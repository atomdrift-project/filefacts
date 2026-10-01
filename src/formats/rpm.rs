//! RPM package extractor.
//!
//! Header-only parse — never touches the payload. Walks the
//! 96-byte lead, the signature header (for cryptographic signing
//! algorithm presence), and the main header (NAME, VERSION,
//! BUILDHOST, PACKAGER, …). The header tag set covers the
//! canonical fields `rpm -qpi` shows.
//!
//! Basic declared scriptlets are also exposed as data. No interpreter, macro
//! expansion or queryformat runs during extraction.
//!
//! Schema:
//!
//! - `rpm.{name, version, release, epoch, summary, license, url,
//!   vendor, packager, buildhost, distribution, group, os, arch,
//!   sourcerpm, rpmversion, cookie, platform, payload_format,
//!   payload_compressor, payload_flags}` — string-typed main-header
//!   fields.
//! - `rpm.buildtime` — unix seconds (numeric).
//! - `rpm.signature.algorithms[]` — Pike-style flag array. Each
//!   entry is one of `rsa`, `dsa`, `pgp`, `gpg`; presence of the
//!   array signals a signed package (no bool needed).
//! - `rpm.limits[]` — `{stage, reason}` for a header left unread because it
//!   exceeds the size cap: a coverage limit, not a parse failure. A header
//!   that is malformed (bad magic, sizes running past the end of the file)
//!   is recorded in `errors` instead.

use crate::metric;
use serde_json::{Value as JsonValue, json};

use crate::error::Error;
use crate::formats::common::bytes_at::u32_be;
use crate::formats::common::{XorScan, extract_binary_strings, put_str};
use crate::output::{Errors, Metrics, Stage, Strings, Values};

const RPM_LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const RPM_HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];
const LEAD_BYTES: usize = 96;

/// Cap per-header size to keep the kv pass cheap on hostile
/// inputs (real headers are typically <1 MB).
const MAX_HEADER_BYTES: usize = 16 * 1024 * 1024;

mod main_tag {
    pub(super) const NAME: u32 = 1000;
    pub(super) const VERSION: u32 = 1001;
    pub(super) const RELEASE: u32 = 1002;
    pub(super) const EPOCH: u32 = 1003;
    pub(super) const SUMMARY: u32 = 1004;
    pub(super) const BUILDTIME: u32 = 1006;
    pub(super) const BUILDHOST: u32 = 1007;
    pub(super) const DISTRIBUTION: u32 = 1010;
    pub(super) const VENDOR: u32 = 1011;
    pub(super) const LICENSE: u32 = 1014;
    pub(super) const PACKAGER: u32 = 1015;
    pub(super) const GROUP: u32 = 1016;
    pub(super) const URL: u32 = 1020;
    pub(super) const OS: u32 = 1021;
    pub(super) const ARCH: u32 = 1022;
    pub(super) const SOURCERPM: u32 = 1044;
    pub(super) const RPMVERSION: u32 = 1064;
    pub(super) const COOKIE: u32 = 1094;
    pub(super) const PAYLOADFORMAT: u32 = 1124;
    pub(super) const PAYLOADCOMPRESSOR: u32 = 1125;
    pub(super) const PAYLOADFLAGS: u32 = 1126;
    pub(super) const PLATFORM: u32 = 1132;
}

mod sig_tag {
    pub(super) const DSA: u32 = 267;
    pub(super) const RSA: u32 = 268;
    pub(super) const PGP: u32 = 1002;
    pub(super) const GPG: u32 = 1005;
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings, XorScan::No);

    if !bytes.starts_with(&RPM_LEAD_MAGIC) {
        return Ok(());
    }
    let mut pos = LEAD_BYTES;

    // Signature header — record which cryptographic algorithms
    // signed the package. Presence of the array is the "signed"
    // signal.
    let (sig_entries, _sig_data, sig_total) =
        match read_header(bytes.get(pos..).unwrap_or_default()) {
            Ok(header) => header,
            Err(e) => {
                e.report("signature-header", values, errors);
                return Ok(());
            }
        };
    let mut algos: Vec<&'static str> = Vec::new();
    for entry in &sig_entries {
        if entry.count == 0 {
            continue;
        }
        let name = match entry.tag {
            sig_tag::RSA => "rsa",
            sig_tag::DSA => "dsa",
            sig_tag::PGP => "pgp",
            sig_tag::GPG => "gpg",
            _ => continue,
        };
        if !algos.contains(&name) {
            algos.push(name);
        }
    }
    if !algos.is_empty() {
        let mut sig = serde_json::Map::new();
        sig.insert(
            "algorithms".into(),
            JsonValue::Array(
                algos
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
        values.insert("rpm.signature", JsonValue::Object(sig));
    }
    // Advance past the signature header and round up to the 8-byte
    // alignment boundary the main header is expected to sit at.
    // `read_header` bounded `sig_total` by the buffer, so neither step
    // can overflow.
    let after_sig = pos + sig_total;
    pos = after_sig + (8 - (after_sig % 8)) % 8;

    // Main header.
    let (main_entries, main_data, _) = match read_header(bytes.get(pos..).unwrap_or_default()) {
        Ok(header) => header,
        Err(e) => {
            e.report("main-header", values, errors);
            return Ok(());
        }
    };
    for entry in &main_entries {
        apply_main_tag(entry, main_data, values, metrics);
    }
    extract_scriptlets(&main_entries, main_data, values)
}

// RPM tag triplets: body, interpreter argv, processing flags. Triggers use
// different array schemas, not these scalar lifecycle scriptlet tags.
const SCRIPTLETS: [(&str, u32, u32, u32); 9] = [
    ("prein", 1023, 1085, 5020),
    ("postin", 1024, 1086, 5021),
    ("preun", 1025, 1087, 5022),
    ("postun", 1026, 1088, 5023),
    ("pretrans", 1151, 1153, 5024),
    ("posttrans", 1152, 1154, 5025),
    ("preuntrans", 5103, 5105, 5107),
    ("postuntrans", 5104, 5106, 5108),
    ("verify", 1079, 1091, 5026),
];
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_PROGRAM_ARGS: u32 = 64;
const MAX_PROGRAM_BYTES: usize = 64 * 1024;

/// The outcome of a header-tag lookup. RPM permits at most one entry per tag,
/// so a duplicate leaves the value ambiguous — a distinct state from absent,
/// which for a scriptlet simply means "take the runtime default".
enum Tag<'a> {
    Absent,
    Duplicated,
    Found(&'a IndexEntry),
}

fn unique_tag(entries: &[IndexEntry], tag: u32) -> Tag<'_> {
    let mut found = entries.iter().filter(|e| e.tag == tag);
    match (found.next(), found.next()) {
        (Some(entry), None) => Tag::Found(entry),
        (Some(_), Some(_)) => Tag::Duplicated,
        (None, _) => Tag::Absent,
    }
}

fn script_body<'a>(entry: &IndexEntry, data: &'a [u8]) -> Option<&'a str> {
    if entry.typ != 6 || entry.count != 1 {
        return None;
    }
    let bytes = data.get(entry.offset as usize..)?;
    let end = bytes
        .iter()
        .take(MAX_SCRIPT_BYTES + 1)
        .position(|&b| b == 0)?;
    std::str::from_utf8(bytes.get(..end)?).ok()
}

fn program_args(entry: &IndexEntry, data: &[u8]) -> Option<Vec<String>> {
    // rpmbuild preserves STRING for a single interpreter for legacy compatibility;
    // STRING_ARRAY is used for interpreter argv. Normalize both to the same view.
    if !matches!(entry.typ, 6 | 8)
        || (entry.typ == 6 && entry.count != 1)
        || entry.count == 0
        || entry.count > MAX_PROGRAM_ARGS
    {
        return None;
    }
    let rest = data.get(entry.offset as usize..)?;
    let mut rest = rest.get(..MAX_PROGRAM_BYTES).unwrap_or(rest);
    let mut result = Vec::with_capacity(entry.count as usize);
    for _ in 0..entry.count {
        let end = rest.iter().position(|&b| b == 0)?;
        result.push(std::str::from_utf8(rest.get(..end)?).ok()?.to_owned());
        rest = rest.get(end + 1..)?;
    }
    Some(result)
}

fn extract_scriptlets(
    entries: &[IndexEntry],
    data: &[u8],
    values: &mut Values,
) -> Result<(), Error> {
    let mut scripts = serde_json::Map::new();
    let mut incomplete = false;
    for (name, body_tag, prog_tag, flags_tag) in SCRIPTLETS {
        let body = match unique_tag(entries, body_tag) {
            Tag::Absent => continue,
            Tag::Found(entry) => script_body(entry, data),
            Tag::Duplicated => None,
        };
        let Some(body) = body else {
            incomplete = true;
            continue;
        };
        let mut script = serde_json::Map::new();
        script.insert("body".into(), JsonValue::String(body.into()));
        // An absent tag is not a defect: the runtime default is /bin/sh with
        // no flags. A tag that is present but duplicated or undecodable
        // records Null — it exists, but its value is not established. No
        // decoded program or flags value is itself Null, so Null is the
        // single mark of incomplete evidence.
        let program = match unique_tag(entries, prog_tag) {
            Tag::Absent => None,
            Tag::Found(e) => Some(program_args(e, data).map_or(JsonValue::Null, |a| json!(a))),
            Tag::Duplicated => Some(JsonValue::Null),
        };
        let flags = match unique_tag(entries, flags_tag) {
            Tag::Absent => None,
            Tag::Found(e) => Some(decode_u32(e, data).map_or(JsonValue::Null, |f| json!(f))),
            Tag::Duplicated => Some(JsonValue::Null),
        };
        for (key, value) in [("program", program), ("flags", flags)] {
            if let Some(value) = value {
                incomplete |= value.is_null();
                script.insert(key.into(), value);
            }
        }
        scripts.insert(name.into(), JsonValue::Object(script));
    }
    if !scripts.is_empty() {
        values.insert("rpm.scriptlets", JsonValue::Object(scripts));
    }
    // Preserve independently valid scripts and metadata before reporting the
    // partial parse. Bounds also cap copied bodies at nine MiB in aggregate.
    if incomplete {
        Err(Error::malformed(
            "rpm",
            "scriptlet evidence incomplete: invalid, duplicate or oversized tag",
        ))
    } else {
        Ok(())
    }
}

fn apply_main_tag(entry: &IndexEntry, data: &[u8], values: &mut Values, metrics: &mut Metrics) {
    match entry.tag {
        main_tag::NAME => set_string(values, "rpm.name", entry, data),
        main_tag::VERSION => set_string(values, "rpm.version", entry, data),
        main_tag::RELEASE => set_string(values, "rpm.release", entry, data),
        main_tag::EPOCH => set_u32(values, metrics, metric!("rpm.epoch"), entry, data),
        main_tag::SUMMARY => set_string(values, "rpm.summary", entry, data),
        main_tag::BUILDTIME => set_u32(values, metrics, metric!("rpm.buildtime"), entry, data),
        main_tag::BUILDHOST => set_string(values, "rpm.buildhost", entry, data),
        main_tag::DISTRIBUTION => set_string(values, "rpm.distribution", entry, data),
        main_tag::VENDOR => set_string(values, "rpm.vendor", entry, data),
        main_tag::LICENSE => set_string(values, "rpm.license", entry, data),
        main_tag::PACKAGER => set_string(values, "rpm.packager", entry, data),
        main_tag::GROUP => set_string(values, "rpm.group", entry, data),
        main_tag::URL => set_string(values, "rpm.url", entry, data),
        main_tag::OS => set_string(values, "rpm.os", entry, data),
        main_tag::ARCH => set_string(values, "rpm.arch", entry, data),
        main_tag::RPMVERSION => set_string(values, "rpm.rpmversion", entry, data),
        main_tag::COOKIE => set_string(values, "rpm.cookie", entry, data),
        main_tag::SOURCERPM => set_string(values, "rpm.sourcerpm", entry, data),
        main_tag::PLATFORM => set_string(values, "rpm.platform", entry, data),
        main_tag::PAYLOADFORMAT => set_string(values, "rpm.payload_format", entry, data),
        main_tag::PAYLOADCOMPRESSOR => set_string(values, "rpm.payload_compressor", entry, data),
        main_tag::PAYLOADFLAGS => set_string(values, "rpm.payload_flags", entry, data),
        _ => {}
    }
}

fn set_string(values: &mut Values, key: &str, entry: &IndexEntry, data: &[u8]) {
    if let Some(v) = decode_string(entry, data) {
        put_str(values, key, v);
    }
}

fn set_u32(
    values: &mut Values,
    metrics: &mut Metrics,
    key: crate::MetricKey,
    entry: &IndexEntry,
    data: &[u8],
) {
    if let Some(v) = decode_u32(entry, data) {
        values.insert(key.as_str(), json!(v));
        metrics.insert(key, f64::from(v));
    }
}

/// STRING (type 6) and I18NSTRING (type 9) decode the same way:
/// NUL-terminated UTF-8 starting at `entry.offset`. Returns `None`
/// on missing / empty / non-UTF-8 values.
fn decode_string(entry: &IndexEntry, data: &[u8]) -> Option<String> {
    if !matches!(entry.typ, 6 | 9) {
        return None;
    }
    let off = entry.offset as usize;
    let rest = data.get(off..)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(rest.get(..nul)?).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

fn decode_u32(entry: &IndexEntry, data: &[u8]) -> Option<u32> {
    if entry.typ != 4 || entry.count != 1 {
        return None;
    }
    u32_be(data, entry.offset as usize)
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    tag: u32,
    typ: u32,
    offset: u32,
    count: u32,
}

/// Why an RPM header could not be read.
#[derive(Debug)]
enum HeaderError {
    /// Bad magic, or a preamble, index or data store running past the end
    /// of the file: the header is malformed or truncated.
    Malformed(String),
    /// The header fits in the file but exceeds [`MAX_HEADER_BYTES`]. It is
    /// left unread as a coverage limit, not reported as a parse failure.
    TooLarge(String),
}

impl HeaderError {
    /// Record a malformed header in `errors`, or a size-capped one in
    /// `rpm.limits`, attributed to `stage` (`signature-header` /
    /// `main-header`).
    fn report(self, stage: &str, values: &mut Values, errors: &mut Errors) {
        match self {
            Self::Malformed(why) => {
                errors.record_malformed(Stage::RpmParse, format!("{stage}: {why}"))
            }
            Self::TooLarge(reason) => {
                values.insert("rpm.limits", json!([{ "stage": stage, "reason": reason }]))
            }
        }
    }
}

/// One parsed RPM header: index entries, data store, and the header's
/// total size in bytes (preamble + index + data store).
type Header<'a> = (Vec<IndexEntry>, &'a [u8], usize);

/// Parse one RPM header (magic + entries + data store).
fn read_header(slice: &[u8]) -> Result<Header<'_>, HeaderError> {
    if !slice.starts_with(&RPM_HEADER_MAGIC) {
        let why = if slice.len() < RPM_HEADER_MAGIC.len() {
            "file ends before the header"
        } else {
            "bad header magic"
        };
        return Err(HeaderError::Malformed(why.into()));
    }
    let (Some(nindex), Some(hsize)) = (u32_be(slice, 8), u32_be(slice, 12)) else {
        return Err(HeaderError::Malformed("truncated 16-byte preamble".into()));
    };
    // Both sizes are attacker-controlled u32s; in u64 the sum cannot
    // overflow. Bounds come first so a lying size reads as malformed, and
    // only a header that really is this large reads as a capped limit.
    let index_size = u64::from(nindex) * 16;
    let total = 16 + index_size + u64::from(hsize);
    if total > slice.len() as u64 {
        return Err(HeaderError::Malformed(format!(
            "{nindex} index entries and {hsize} data bytes run past the end of the file \
             ({} bytes remain)",
            slice.len()
        )));
    }
    if index_size > MAX_HEADER_BYTES as u64 || u64::from(hsize) > MAX_HEADER_BYTES as u64 {
        return Err(HeaderError::TooLarge(format!(
            "{nindex} index entries and {hsize} data bytes exceed the {MAX_HEADER_BYTES}-byte \
             header cap; not read"
        )));
    }
    // Within the slice, so the conversions below are lossless.
    let entries_end = 16 + index_size as usize;
    let data_end = total as usize;
    let mut entries = Vec::with_capacity(nindex as usize);
    for raw in slice
        .get(16..entries_end)
        .unwrap_or_default()
        .as_chunks::<16>()
        .0
    {
        // `raw` is exactly 16 bytes, so every field read succeeds.
        let field = |at| u32_be(raw, at).unwrap_or_default();
        entries.push(IndexEntry {
            tag: field(0),
            typ: field(4),
            offset: field(8),
            count: field(12),
        });
    }
    Ok((
        entries,
        slice.get(entries_end..data_end).unwrap_or_default(),
        data_end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script_rpm(tags: Vec<(u32, u32, u32, Vec<u8>)>) -> Vec<u8> {
        let mut out = vec![0; 96];
        out[..4].copy_from_slice(&RPM_LEAD_MAGIC);
        out.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        let size: usize = tags.iter().map(|t| t.3.len()).sum();
        out.extend_from_slice(&(size as u32).to_be_bytes());
        let mut offset = 0u32;
        for (tag, typ, count, value) in &tags {
            for field in [*tag, *typ, offset, *count] {
                out.extend_from_slice(&field.to_be_bytes());
            }
            offset += value.len() as u32;
        }
        for (_, _, _, value) in tags {
            out.extend(value);
        }
        out
    }

    #[test]
    fn declared_lifecycle_scriptlets_are_separate_units() {
        let mut tags = vec![(1000, 6, 1, b"fixture\0".to_vec())];
        for (_, body, program, _) in SCRIPTLETS {
            tags.push((body, 6, 1, b"echo 'ready'\n\0".to_vec()));
            tags.push((program, 6, 1, b"/bin/sh\0".to_vec()));
        }
        let bytes = script_rpm(tags);
        let parsed = crate::open(&bytes).unwrap();
        let sources: Vec<_> = parsed.embedded_sources().collect();
        assert_eq!(sources.len(), 9);
        for (name, _, _, _) in SCRIPTLETS {
            let pointer = format!("/rpm/scriptlets/{name}/body");
            let source = sources.iter().find(|s| s.pointer == pointer).unwrap();
            assert_eq!(source.source, "echo 'ready'\n");
            assert_eq!(source.file_type, Some(crate::FileType::Shell));
        }
        assert!(parsed.errors().is_empty());
        assert_eq!(
            parsed.values().get("rpm.name").unwrap().as_str(),
            Some("fixture")
        );
    }

    #[test]
    fn declared_interpreters_defaults_and_processing_flags() {
        use crate::FileType;
        for (program, expected) in [
            (None, Some(FileType::Shell)),
            (Some("/usr/bin/python3"), Some(FileType::Python)),
            (Some("/usr/bin/perl"), Some(FileType::Perl)),
            (Some("/usr/bin/ruby"), Some(FileType::Ruby)),
            (Some("<lua>"), Some(FileType::Lua)),
            (Some("/usr/local/bin/custom"), None),
        ] {
            let mut tags = vec![(1024, 6, 1, b"print('ready')\0".to_vec())];
            if let Some(program) = program {
                tags.push((1086, 8, 1, format!("{program}\0").into_bytes()));
            }
            let bytes = script_rpm(tags);
            let parsed = crate::open(&bytes).unwrap();
            assert_eq!(
                parsed.embedded_sources().next().unwrap().file_type,
                expected
            );
        }
        for tag in [
            (5021, 4, 1, 1u32.to_be_bytes().to_vec()),
            (1086, 8, 2, b"/bin/sh\0-c\0".to_vec()),
        ] {
            let bytes = script_rpm(vec![(1024, 6, 1, b"echo 'ready'\0".to_vec()), tag]);
            let parsed = crate::open(&bytes).unwrap();
            assert!(
                parsed
                    .embedded_sources()
                    .next()
                    .unwrap()
                    .file_type
                    .is_none()
            );
            assert!(parsed.errors().is_empty());
        }
    }

    #[test]
    fn invalid_bodies_do_not_hide_later_valid_scriptlets() {
        for bad in [
            (1023, 8, 1, b"echo bad\0".to_vec()),
            (1023, 6, 2, b"echo bad\0".to_vec()),
            (1023, 6, 1, vec![0xff, 0]),
        ] {
            let bytes = script_rpm(vec![bad, (1024, 6, 1, b"echo 'ready'\0".to_vec())]);
            let parsed = crate::open(&bytes).unwrap();
            assert_eq!(parsed.embedded_sources().count(), 1);
            assert!(!parsed.errors().is_empty());
        }
        for bad in [b"unterminated".to_vec(), vec![b'x'; MAX_SCRIPT_BYTES + 1]] {
            let bytes = script_rpm(vec![
                (1024, 6, 1, b"echo 'ready'\0".to_vec()),
                (1023, 6, 1, bad),
            ]);
            let parsed = crate::open(&bytes).unwrap();
            assert_eq!(parsed.embedded_sources().count(), 1);
            assert!(!parsed.errors().is_empty());
        }
    }

    #[test]
    fn duplicate_body_is_ambiguous_and_invalid_program_never_defaults() {
        let bytes = script_rpm(vec![
            (1024, 6, 1, b"echo first\0".to_vec()),
            (1024, 6, 1, b"echo second\0".to_vec()),
            (1026, 6, 1, b"echo third\0".to_vec()),
        ]);
        let parsed = crate::open(&bytes).unwrap();
        assert_eq!(parsed.embedded_sources().count(), 1);
        assert!(!parsed.errors().is_empty());
        for bad in [
            (1086, 6, 2, b"/bin/sh\0-c\0".to_vec()),
            (1086, 7, 1, b"/bin/sh\0".to_vec()),
            (1086, 6, 1, b"/bin/sh".to_vec()),
            (1086, 8, 0, Vec::new()),
            (1086, 8, 1, b"/bin/sh".to_vec()),
            (1086, 8, u32::MAX, Vec::new()),
            (5021, 6, 1, b"0\0".to_vec()),
        ] {
            let bytes = script_rpm(vec![(1024, 6, 1, b"echo 'ready'\0".to_vec()), bad]);
            let parsed = crate::open(&bytes).unwrap();
            assert!(
                parsed
                    .embedded_sources()
                    .next()
                    .unwrap()
                    .file_type
                    .is_none()
            );
            assert!(!parsed.errors().is_empty());
        }
    }

    #[test]
    fn descriptive_header_strings_are_not_scriptlets() {
        let bytes = script_rpm(vec![
            (1000, 6, 1, b"fixture\0".to_vec()),
            (1004, 9, 1, b"echo 'ready'\0".to_vec()),
            (1086, 8, 1, b"/bin/sh\0".to_vec()),
        ]);
        let parsed = crate::open(&bytes).unwrap();
        assert_eq!(parsed.embedded_sources().count(), 0);
        assert!(parsed.errors().is_empty());
    }

    fn build_minimal_rpm() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&RPM_LEAD_MAGIC);
        out.extend_from_slice(&[0u8; 92]);

        // Empty signature header.
        out.extend_from_slice(&RPM_HEADER_MAGIC);
        out.push(1);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());

        // Main header: NAME / VERSION / BUILDHOST / BUILDTIME.
        out.extend_from_slice(&RPM_HEADER_MAGIC);
        out.push(1);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&38u32.to_be_bytes());

        for &(tag, typ, offset, count) in &[
            (main_tag::NAME, 6u32, 0u32, 1u32),
            (main_tag::VERSION, 6, 8, 1),
            (main_tag::BUILDHOST, 6, 14, 1),
            (main_tag::BUILDTIME, 4, 34, 1),
        ] {
            out.extend_from_slice(&tag.to_be_bytes());
            out.extend_from_slice(&typ.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
        }
        out.extend_from_slice(b"openssh\0");
        out.extend_from_slice(b"9.9p1\0");
        out.extend_from_slice(b"build-1.example.org\0");
        out.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        out
    }

    fn run(bytes: &[u8]) -> (Values, Metrics, Errors) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut e = Errors::new();
        extract(bytes, &mut v, &mut s, &mut m, &mut e).unwrap();
        (v, m, e)
    }

    /// The one recorded error's stage, kind and message.
    fn only_error(errors: &Errors) -> (Stage, crate::ErrorKind, &str) {
        assert_eq!(errors.len(), 1, "{errors:?}");
        let e = &errors.as_slice()[0];
        (e.stage, e.kind, e.message.as_str())
    }

    #[test]
    fn rejects_non_rpm() {
        let (v, _, e) = run(b"not an rpm");
        assert!(v.get("rpm.name").is_none());
        assert!(e.is_empty());
    }

    #[test]
    fn surfaces_main_header() {
        let rpm = build_minimal_rpm();
        let (v, m, e) = run(&rpm);
        assert!(e.is_empty(), "{e:?}");
        assert!(v.get("rpm.limits").is_none());
        assert_eq!(v.get("rpm.name").and_then(|x| x.as_str()), Some("openssh"));
        assert_eq!(v.get("rpm.version").and_then(|x| x.as_str()), Some("9.9p1"));
        assert_eq!(
            v.get("rpm.buildhost").and_then(|x| x.as_str()),
            Some("build-1.example.org")
        );
        assert_eq!(m.get("rpm.buildtime"), Some(1_700_000_000.0));
        // No signing tags in minimal sample → no signature subtree.
        assert!(v.get("rpm.signature").is_none());
    }

    #[test]
    fn truncated_lead_is_silent() {
        let (v, _, e) = run(&[0u8; 10]);
        assert!(v.get("rpm.name").is_none());
        assert!(e.is_empty());
    }

    #[test]
    fn wrong_lead_magic_is_silent() {
        let mut bad = vec![0u8; LEAD_BYTES + 16];
        bad[0..4].copy_from_slice(b"NOPE");
        let (v, _, e) = run(&bad);
        assert!(v.get("rpm.name").is_none());
        assert!(e.is_empty());
    }

    #[test]
    fn rpm_cut_inside_the_lead_records_a_malformed_signature_header() {
        let (v, _, e) = run(&build_minimal_rpm()[..LEAD_BYTES - 1]);
        let (stage, kind, message) = only_error(&e);
        assert_eq!(
            (stage, kind),
            (Stage::RpmParse, crate::ErrorKind::Malformed)
        );
        assert!(message.starts_with("signature-header:"), "{message}");
        assert!(v.get("rpm.limits").is_none());
    }

    #[test]
    fn bad_signature_header_magic_records_one_malformed_error() {
        let mut rpm = build_minimal_rpm();
        rpm[LEAD_BYTES] = 0;
        let (v, _, e) = run(&rpm);
        let (stage, kind, message) = only_error(&e);
        assert_eq!(
            (stage, kind),
            (Stage::RpmParse, crate::ErrorKind::Malformed)
        );
        assert_eq!(message, "signature-header: bad header magic");
        assert!(v.get("rpm.name").is_none());
        assert!(v.get("rpm.limits").is_none());
    }

    /// A header that really is larger than the cap is a coverage limit, not
    /// a parse failure: it lands in `rpm.limits` and leaves `errors` empty.
    #[test]
    fn oversized_signature_header_is_a_limit_not_an_error() {
        let hsize = MAX_HEADER_BYTES + 1;
        let mut rpm = build_minimal_rpm();
        rpm[LEAD_BYTES + 12..LEAD_BYTES + 16].copy_from_slice(&(hsize as u32).to_be_bytes());
        rpm.resize(LEAD_BYTES + 16 + hsize, 0);
        let (v, _, e) = run(&rpm);
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("rpm.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits.len(), 1);
        assert_eq!(limits[0]["stage"], "signature-header");
        assert!(limits[0]["reason"].as_str().unwrap().contains("header cap"));
    }

    /// The same oversized claim in a file too short to hold it is a lying
    /// size: malformed, not a limit.
    #[test]
    fn header_size_past_end_of_file_is_malformed_not_a_limit() {
        let mut rpm = build_minimal_rpm();
        rpm[LEAD_BYTES + 12..LEAD_BYTES + 16]
            .copy_from_slice(&(MAX_HEADER_BYTES as u32 + 1).to_be_bytes());
        let (v, _, e) = run(&rpm);
        let (stage, kind, message) = only_error(&e);
        assert_eq!(
            (stage, kind),
            (Stage::RpmParse, crate::ErrorKind::Malformed)
        );
        assert!(message.contains("past the end of the file"), "{message}");
        assert!(v.get("rpm.limits").is_none());
    }

    #[test]
    fn truncated_main_header_doesnt_crash() {
        // Valid lead + valid (empty) sig header + main-header magic
        // claiming 1 entry but truncated before entry bytes.
        let mut out = Vec::new();
        out.extend_from_slice(&RPM_LEAD_MAGIC);
        out.extend_from_slice(&[0u8; 92]);
        out.extend_from_slice(&RPM_HEADER_MAGIC);
        out.push(1);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        // Main header claims 1 entry of 100 bytes but supplies neither.
        out.extend_from_slice(&RPM_HEADER_MAGIC);
        out.push(1);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&100u32.to_be_bytes());
        let (v, _, e) = run(&out);
        assert!(v.get("rpm.name").is_none());
        let (stage, kind, message) = only_error(&e);
        assert_eq!(
            (stage, kind),
            (Stage::RpmParse, crate::ErrorKind::Malformed)
        );
        assert!(message.starts_with("main-header:"), "{message}");
    }

    #[test]
    fn rpm_ending_after_the_signature_header_records_a_missing_main_header() {
        let rpm = build_minimal_rpm();
        let (v, _, e) = run(&rpm[..LEAD_BYTES + 16]);
        assert_eq!(
            only_error(&e),
            (
                Stage::RpmParse,
                crate::ErrorKind::Malformed,
                "main-header: file ends before the header"
            )
        );
        assert!(v.get("rpm.name").is_none());
    }
}
