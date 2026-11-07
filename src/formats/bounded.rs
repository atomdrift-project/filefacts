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

/// Bytes one directory extent of a disc image (ISO 9660, UDF) is read to.
pub(super) const MAX_DIR_EXTENT: usize = 32 << 20;

/// Directory-extent bytes one disc-image tree walk reads in all. A walk
/// keys the directories it has visited on where they are, so records that
/// name one extent with ever-different lengths, extents a sector apart, or
/// distinct UDF ICBs pointing at one run of identifiers each read up to
/// [`MAX_DIR_EXTENT`] again: a quarter-terabyte from a 32 MiB image. Real
/// trees spend a few hundred bytes per record, far below this for
/// [`MAX_ARCHIVE_MEMBERS`] members.
pub(super) const MAX_DIR_BYTES_TOTAL: usize = 128 << 20;

/// Bytes of a package manifest (`package.json`, `Cargo.toml`, a `.nuspec`,
/// Core Metadata, a `.PKGINFO`, …) read before it is refused as padding.
/// Real manifests are a few KiB; one past this cap is hostile or broken, and
/// is reported as a limit rather than parsed.
pub(super) const MAX_MANIFEST_BYTES: u64 = 1 << 20;

/// Inflated bytes a gzipped-tar manifest search reads before giving up.
/// Package manifests sit near the front of the tarball, so this only
/// bounds the walk past them: a small `.tgz` can inflate a thousandfold.
pub(super) const MAX_TARGZ_SEARCH: u64 = 128 << 20;

/// Largest LZ dictionary (zstd window, xz/LZMA dictionary) a decoder may
/// allocate, as a power of two. The stream header names its own size and
/// the decoder allocates it before producing a byte, so without this a
/// frame of a few bytes asks for gigabytes. 64 MiB is what `xz -9` and
/// `zstd --ultra -22` on large inputs use; real package members need less.
const MAX_DICTIONARY_LOG: u32 = 26;

/// A zstd decoder over `input` that refuses frames whose window exceeds
/// [`MAX_DICTIONARY_LOG`].
pub(super) fn zstd_decoder<R: io::BufRead>(
    input: R,
) -> io::Result<zstd::stream::read::Decoder<'static, R>> {
    let mut decoder = zstd::stream::read::Decoder::with_buffer(input)?;
    decoder.window_log_max(MAX_DICTIONARY_LOG)?;
    Ok(decoder)
}

/// An xz decoder over `input` that refuses streams whose dictionary exceeds
/// [`MAX_DICTIONARY_LOG`]. Concatenated streams are read as one, as `xz`
/// itself does.
pub(super) fn xz_decoder<R: Read>(input: R) -> lzma_rust2::XzReader<R> {
    // The limit is the decoder's whole footprint in KiB: the dictionary
    // plus the coder state, which a few MiB more covers.
    const MEM_LIMIT_KIB: u32 = (1 << (MAX_DICTIONARY_LOG - 10)) + (4 << 10);
    lzma_rust2::XzReader::new_mem_limit(input, true, MEM_LIMIT_KIB)
}

/// One bound a walk hit: the stage it was in, and what was cut short.
#[derive(Debug)]
struct Limit {
    stage: &'static str,
    reason: String,
}

/// The bounds one extractor hit, written once to its `<format>.limits` key
/// as `[{stage, reason}]`, so a capped walk is a reported limit rather than
/// a silent short read.
#[derive(Debug, Default)]
pub(super) struct Limits(Vec<Limit>);

impl Limits {
    pub(super) fn push(&mut self, stage: &'static str, reason: impl Into<String>) {
        let reason = reason.into();
        tracing::debug!(target: "filefacts::bounded", stage, reason = %reason, "limit reached");
        self.0.push(Limit { stage, reason });
    }

    /// Append the list to `key`; nothing is written when no limit was hit.
    /// Appending, not replacing, lets two extractors of one file (an OLE2
    /// container and the VBA project inside it) share `office.limits`.
    pub(super) fn emit(self, values: &mut Values, key: ValueKey) {
        if self.0.is_empty() {
            return;
        }
        let mut list = values
            .lookup(key)
            .and_then(JsonValue::as_array)
            .cloned()
            .unwrap_or_default();
        list.extend(
            self.0
                .into_iter()
                .map(|l| json!({ "stage": l.stage, "reason": l.reason })),
        );
        values.insert_key(key, JsonValue::Array(list));
    }
}

/// The first bytes of a member, read through a cap.
#[derive(Clone)]
pub(crate) struct MemberPrefix {
    /// At most the cap's worth of the member.
    pub(crate) bytes: Vec<u8>,
    /// The member continued past the cap.
    pub(crate) truncated: bool,
}

/// What [`inflate_capped`] does with the bytes a decoder produced before it
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnError {
    /// Drop them and return the error: for a member that is parsed whole
    /// (a manifest, a header block), a cut-off copy would only fail to parse.
    Discard,
    /// Keep them, logging the error: for a stream whose damaged tail does
    /// not touch what came before it (a PDF stream a viewer renders up to
    /// the damage, an Alpine package's control segment ahead of a broken
    /// data segment). The error is returned only when nothing decoded.
    KeepPartial,
}

/// Read (and so, through a decoder, inflate) `reader` to at most `cap`
/// bytes, reading one more to tell a member exactly at the cap from one
/// past it. A read error is handled as `on_error` says.
pub(crate) fn inflate_capped(
    reader: impl Read,
    cap: u64,
    on_error: OnError,
) -> io::Result<MemberPrefix> {
    let mut bytes = Vec::new();
    if let Err(error) = reader.take(cap.saturating_add(1)).read_to_end(&mut bytes) {
        if on_error == OnError::Discard || bytes.is_empty() {
            return Err(error);
        }
        tracing::debug!(target: "filefacts::bounded", stage = "inflate", len = bytes.len(), %error, "stream damaged; keeping what decoded before it");
    }
    let truncated = bytes.len() as u64 > cap;
    if truncated {
        bytes.truncate(crate::bytes::sat_usize(cap));
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
    /// The last member whose path matched, and its capped bytes.
    Found { path: String, prefix: MemberPrefix },
    /// The tarball holds no matching member.
    Absent,
    /// [`MAX_TARGZ_SEARCH`] inflated bytes went by before the tarball's
    /// end, so a match seen so far could still be replaced by a later one.
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

/// Find the last member of the gzipped tar `bytes` whose path satisfies
/// `matches`, and read it through a `max_member` cap. Package managers
/// extract every member, so a later member with the same path replaces an
/// earlier one: the whole tarball is walked, and never past
/// [`MAX_TARGZ_SEARCH`] inflated bytes. A tar error fails the search even
/// after a match, since an extractor that resynchronises past the damage
/// (node-tar does) may find a later member there.
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
    Ok(
        match find_targz_members_within(bytes, [&matches], max_member, max_inflate)? {
            TarGzMembers::InflateCapped => TarGzSearch::InflateCapped,
            TarGzMembers::Read([found]) => found.map_or(TarGzSearch::Absent, |(path, prefix)| {
                TarGzSearch::Found { path, prefix }
            }),
        },
    )
}

/// What a search for several gzipped-tar members found.
pub(super) enum TarGzMembers<const N: usize> {
    /// Per matcher, the last member it accepted, and its capped bytes.
    Read([Option<(String, MemberPrefix)>; N]),
    /// The inflate budget ran out before the tarball's end.
    InflateCapped,
}

/// [`find_targz_member`] for several members in one walk: for each of
/// `matchers`, the last member it accepts. One inflate serves them all, where
/// a search per member would inflate the tarball once each.
pub(super) fn find_targz_members<const N: usize>(
    bytes: &[u8],
    matchers: [&dyn Fn(&str) -> bool; N],
    max_member: u64,
) -> Result<TarGzMembers<N>, TarGzError> {
    find_targz_members_within(bytes, matchers, max_member, MAX_TARGZ_SEARCH)
}

fn find_targz_members_within<const N: usize>(
    bytes: &[u8],
    matchers: [&dyn Fn(&str) -> bool; N],
    max_member: u64,
    max_inflate: u64,
) -> Result<TarGzMembers<N>, TarGzError> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes).take(max_inflate));
    let entries = archive.entries().map_err(TarGzError::Walk)?;
    let mut found: [Option<(String, MemberPrefix)>; N] = std::array::from_fn(|_| None);
    let mut failure = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                failure = Some(TarGzError::Walk(e));
                break;
            }
        };
        let Ok(path) = entry.path().map(|p| p.to_string_lossy().into_owned()) else {
            continue;
        };
        let wanted = matchers.map(|matches| matches(&path));
        if !wanted.contains(&true) {
            continue;
        }
        if found
            .iter()
            .zip(&wanted)
            .any(|(slot, &w)| w && slot.is_some())
        {
            tracing::debug!(target: "filefacts::bounded", stage = "targz-search", path = %path, "member repeated; the later one replaces the earlier");
        }
        match inflate_capped(entry, max_member, OnError::Discard) {
            Ok(prefix) => {
                // Matchers rarely overlap: the last one takes the bytes, any
                // other a copy.
                let last = wanted.iter().rposition(|&w| w);
                let mut member = Some((path, prefix));
                for (i, (slot, &w)) in found.iter_mut().zip(&wanted).enumerate() {
                    if w {
                        *slot = if Some(i) == last {
                            member.take()
                        } else {
                            member.clone()
                        };
                    }
                }
            }
            Err(source) => {
                failure = Some(TarGzError::Member { path, source });
                break;
            }
        }
    }
    // The budget is spent when the `Take` has nothing left: whatever the
    // tar reader made of the cut-off stream, the search ran out, not the
    // tarball.
    if archive.into_inner().limit() == 0 {
        return Ok(TarGzMembers::InflateCapped);
    }
    match failure {
        Some(failure) => Err(failure),
        None => Ok(TarGzMembers::Read(found)),
    }
}

#[cfg(test)]
mod tests;
