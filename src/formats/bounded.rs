//! Resource bounds shared by the archive and package extractors.
//!
//! Every container here is untrusted: a member count, a declared size or a
//! compression ratio is whatever the file says. The helpers below put one
//! bound on each of those and record when it was hit, so a capped walk is a
//! reported limit (`<format>.limits`) rather than a silent short read.

use std::fmt;
use std::io::{self, Read};
use std::string::FromUtf8Error;

use flate2::read::GzDecoder;
use serde_json::{Value as JsonValue, json};

use crate::output::{Errors, Stage, ValueKey, Values};

/// Members an archive walk lists before it stops. Each listed member costs
/// a JSON object and an `ArchiveMember`, and a container's member count is
/// bounded only by its size: 65,536 fits a generous real-world archive (the
/// JDK ships a few thousand classes per jar).
pub(super) const MAX_ARCHIVE_MEMBERS: usize = 65_536;

/// Bytes of member paths one directory-tree walk builds. ISO 9660, UDF and
/// ASAR spell each member's path out from its ancestors' names, so a deep
/// chain of long directory names is repeated in every member beneath it: a
/// few MiB of names expanded into gigabytes of paths. Real archives need a
/// small fraction of this for [`MAX_ARCHIVE_MEMBERS`] paths.
pub(super) const MAX_PATH_BYTES: usize = 64 << 20;

/// Inflated bytes a gzipped-tar manifest search reads before giving up.
/// Package manifests sit near the front of the tarball, so this only
/// bounds the walk past them: a small `.tgz` can inflate a thousandfold.
pub(super) const MAX_TARGZ_SEARCH: u64 = 128 << 20;

/// Append a `{stage, reason}` entry to the `key` limits list, keeping any
/// entries already recorded there.
pub(super) fn push_limit(
    values: &mut Values,
    key: ValueKey,
    stage: &str,
    reason: impl Into<String>,
) {
    let entry = json!({ "stage": stage, "reason": reason.into() });
    let mut list = values
        .get_key(key)
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    list.push(entry);
    values.insert_key(key, JsonValue::Array(list));
}

/// The first bytes of a member, read through a cap.
pub(super) struct MemberPrefix {
    /// At most the cap's worth of the member.
    pub(super) bytes: Vec<u8>,
    /// The member continued past the cap.
    pub(super) truncated: bool,
}

/// Read `reader` to at most `max` bytes, reading one more to tell a member
/// exactly at the cap from one past it. `size_hint` is only a capacity
/// hint: a declared size is the container's claim, not a bound.
pub(super) fn read_prefix(reader: impl Read, max: u64, size_hint: u64) -> io::Result<MemberPrefix> {
    let mut bytes = Vec::with_capacity(usize::try_from(size_hint.min(max)).unwrap_or(0));
    reader.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 > max;
    if truncated {
        bytes.truncate(usize::try_from(max).unwrap_or(usize::MAX));
    }
    Ok(MemberPrefix { bytes, truncated })
}

/// Decode a capped text member as UTF-8. When the cap cut a multi-byte
/// character in two, that partial character is not the member's fault and
/// is dropped; any other invalid byte is an error.
pub(super) fn utf8_prefix(prefix: MemberPrefix) -> Result<String, FromUtf8Error> {
    match String::from_utf8(prefix.bytes) {
        Ok(text) => Ok(text),
        Err(e) if prefix.truncated && e.utf8_error().error_len().is_none() => {
            let valid = e.utf8_error().valid_up_to();
            let mut bytes = e.into_bytes();
            bytes.truncate(valid);
            String::from_utf8(bytes)
        }
        Err(e) => Err(e),
    }
}

/// What a gzipped-tar member search found.
pub(super) enum TarGzSearch {
    /// The first member whose path matched, and its capped bytes.
    Found { path: String, prefix: MemberPrefix },
    /// The tarball holds no matching member.
    Absent,
    /// [`MAX_TARGZ_SEARCH`] inflated bytes went by without a match.
    InflateCapped,
}

/// Why a gzipped-tar member search failed.
#[derive(Debug)]
pub(super) enum TarGzError {
    /// The tarball would not inflate or parse before a match was reached.
    Walk(io::Error),
    /// The matching member itself would not read.
    Member { path: String, source: io::Error },
}

impl TarGzError {
    /// A [`MemberFailure`] in `stage`, naming the member that was sought.
    pub(super) fn into_failure(self, stage: Stage, sought: &str) -> MemberFailure {
        match self {
            Self::Walk(e) => {
                MemberFailure::new(stage, format!("tarball unreadable before {sought}"), e)
            }
            Self::Member { path, source } => MemberFailure::new(stage, path, source),
        }
    }
}

/// A package member that would not read: the stage it failed in, what was
/// being read, and why. Kept typed until it lands in the errors view, where
/// it reads `context: source`.
#[derive(Debug)]
pub(super) struct MemberFailure {
    stage: Stage,
    context: String,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl MemberFailure {
    pub(super) fn new(
        stage: Stage,
        context: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            stage,
            context: context.into(),
            source: source.into(),
        }
    }

    /// Record the failure in the errors view, under its stage.
    pub(super) fn record(self, errors: &mut Errors) {
        errors.record_malformed(self.stage, self.to_string());
    }
}

impl fmt::Display for MemberFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.source)
    }
}

impl std::error::Error for MemberFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

impl fmt::Display for TarGzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Walk(e) => write!(f, "tarball unreadable: {e}"),
            Self::Member { path, source } => write!(f, "{path}: {source}"),
        }
    }
}

impl std::error::Error for TarGzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Walk(e) | Self::Member { source: e, .. } => Some(e),
        }
    }
}

/// Find the first member of the gzipped tar `bytes` whose path satisfies
/// `matches`, and read it through a `max_member` cap. Decompression stops at
/// the match, and never runs past [`MAX_TARGZ_SEARCH`] inflated bytes.
pub(super) fn find_targz_member(
    bytes: &[u8],
    matches: impl Fn(&str) -> bool,
    max_member: u64,
) -> Result<TarGzSearch, TarGzError> {
    find_targz_member_within(bytes, matches, max_member, MAX_TARGZ_SEARCH)
}

/// [`find_targz_member`] with the inflate budget as a parameter, so the
/// budget can be exercised without inflating 128 MiB.
fn find_targz_member_within(
    bytes: &[u8],
    matches: impl Fn(&str) -> bool,
    max_member: u64,
    max_inflate: u64,
) -> Result<TarGzSearch, TarGzError> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes).take(max_inflate));
    let entries = archive.entries().map_err(TarGzError::Walk)?;
    let mut walk_error = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                walk_error = Some(e);
                break;
            }
        };
        let Ok(path) = entry.path().map(|p| p.to_string_lossy().into_owned()) else {
            continue;
        };
        if !matches(&path) {
            continue;
        }
        let size = entry.size();
        return match read_prefix(entry, max_member, size) {
            Ok(prefix) => Ok(TarGzSearch::Found { path, prefix }),
            Err(source) => Err(TarGzError::Member { path, source }),
        };
    }
    // The budget is spent when the `Take` has nothing left: whatever the
    // tar reader made of the cut-off stream, the search ran out, not the
    // tarball.
    if archive.into_inner().limit() == 0 {
        return Ok(TarGzSearch::InflateCapped);
    }
    match walk_error {
        Some(e) => Err(TarGzError::Walk(e)),
        None => Ok(TarGzSearch::Absent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A gzipped tar holding the given members.
    fn targz(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *body).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn finds_the_member_and_caps_it() {
        let bytes = targz(&[("pkg/a", b"skip"), ("pkg/manifest", b"0123456789")]);
        let found = find_targz_member(&bytes, |p| p == "pkg/manifest", 4).unwrap();
        let TarGzSearch::Found { path, prefix } = found else {
            panic!("member not found");
        };
        assert_eq!(path, "pkg/manifest");
        assert_eq!(prefix.bytes, b"0123");
        assert!(prefix.truncated);
    }

    #[test]
    fn absent_member_is_not_an_error() {
        let bytes = targz(&[("pkg/a", b"x")]);
        let found = find_targz_member(&bytes, |p| p == "pkg/manifest", 64).unwrap();
        assert!(matches!(found, TarGzSearch::Absent));
    }

    /// A tarball whose manifest sits behind more inflated bytes than the
    /// budget stops at the budget instead of inflating the whole stream.
    #[test]
    fn search_stops_at_the_inflate_budget() {
        let padding = vec![0_u8; 1 << 20];
        let bytes = targz(&[("pkg/pad", &padding), ("pkg/manifest", b"{}")]);
        let found =
            find_targz_member_within(&bytes, |p| p == "pkg/manifest", 64, 64 << 10).unwrap();
        assert!(matches!(found, TarGzSearch::InflateCapped));
        // With room, the same tarball yields the manifest.
        let found = find_targz_member_within(&bytes, |p| p == "pkg/manifest", 64, 4 << 20).unwrap();
        assert!(matches!(found, TarGzSearch::Found { .. }));
    }

    #[test]
    fn utf8_prefix_drops_a_character_cut_by_the_cap() {
        let cut = MemberPrefix {
            bytes: "aé".as_bytes()[..2].to_vec(),
            truncated: true,
        };
        assert_eq!(utf8_prefix(cut).unwrap(), "a");
        let invalid = MemberPrefix {
            bytes: vec![b'a', 0xff, b'b'],
            truncated: true,
        };
        assert!(utf8_prefix(invalid).is_err());
        let whole_but_cut = MemberPrefix {
            bytes: "aé".as_bytes()[..2].to_vec(),
            truncated: false,
        };
        assert!(utf8_prefix(whole_but_cut).is_err());
    }

    #[test]
    fn push_limit_appends() {
        let mut values = Values::new();
        let key = crate::value_key!("pdf.limits");
        push_limit(&mut values, key, "a", "first");
        push_limit(&mut values, key, "b", "second");
        let list = values.get_key(key).and_then(JsonValue::as_array).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1]["stage"].as_str(), Some("b"));
    }

    /// A tarball that is not gzip fails the walk; the recorded line names
    /// the member sought, and the failure keeps the I/O error as its source.
    #[test]
    fn member_failures_keep_their_source_and_record_one_line() {
        let Err(walk) = find_targz_member(b"not gzip", |_| true, 1024) else {
            panic!("a tarball that is not gzip fails the walk");
        };
        let failure = walk.into_failure(Stage::TarParse, "<root>/PKG-INFO");
        assert!(std::error::Error::source(&failure).is_some());
        let mut errors = Errors::new();
        failure.record(&mut errors);
        let recorded = errors.iter().next().unwrap();
        assert_eq!(recorded.stage, Stage::TarParse);
        assert!(
            recorded
                .message
                .starts_with("tarball unreadable before <root>/PKG-INFO: "),
            "{}",
            recorded.message
        );
    }
}
