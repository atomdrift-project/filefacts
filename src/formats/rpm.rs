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
use crate::output::{Errors, Metrics, Stage, Strings, ValueKey, Values};
use crate::value_key;

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
        values.insert_key(value_key!("rpm.signature"), JsonValue::Object(sig));
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
        values.insert_key(value_key!("rpm.scriptlets"), JsonValue::Object(scripts));
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
        main_tag::NAME => set_string(values, value_key!("rpm.name"), entry, data),
        main_tag::VERSION => set_string(values, value_key!("rpm.version"), entry, data),
        main_tag::RELEASE => set_string(values, value_key!("rpm.release"), entry, data),
        main_tag::EPOCH => set_u32(
            values,
            metrics,
            value_key!("rpm.epoch"),
            metric!("rpm.epoch"),
            entry,
            data,
        ),
        main_tag::SUMMARY => set_string(values, value_key!("rpm.summary"), entry, data),
        main_tag::BUILDTIME => set_u32(
            values,
            metrics,
            value_key!("rpm.buildtime"),
            metric!("rpm.buildtime"),
            entry,
            data,
        ),
        main_tag::BUILDHOST => set_string(values, value_key!("rpm.buildhost"), entry, data),
        main_tag::DISTRIBUTION => set_string(values, value_key!("rpm.distribution"), entry, data),
        main_tag::VENDOR => set_string(values, value_key!("rpm.vendor"), entry, data),
        main_tag::LICENSE => set_string(values, value_key!("rpm.license"), entry, data),
        main_tag::PACKAGER => set_string(values, value_key!("rpm.packager"), entry, data),
        main_tag::GROUP => set_string(values, value_key!("rpm.group"), entry, data),
        main_tag::URL => set_string(values, value_key!("rpm.homepage"), entry, data),
        main_tag::OS => set_string(values, value_key!("rpm.os"), entry, data),
        main_tag::ARCH => set_string(values, value_key!("rpm.arch"), entry, data),
        main_tag::RPMVERSION => set_string(values, value_key!("rpm.rpmversion"), entry, data),
        main_tag::COOKIE => set_string(values, value_key!("rpm.cookie"), entry, data),
        main_tag::SOURCERPM => set_string(values, value_key!("rpm.sourcerpm"), entry, data),
        main_tag::PLATFORM => set_string(values, value_key!("rpm.platform"), entry, data),
        main_tag::PAYLOADFORMAT => {
            set_string(values, value_key!("rpm.payload_format"), entry, data)
        }
        main_tag::PAYLOADCOMPRESSOR => {
            set_string(values, value_key!("rpm.payload_compressor"), entry, data)
        }
        main_tag::PAYLOADFLAGS => set_string(values, value_key!("rpm.payload_flags"), entry, data),
        _ => {}
    }
}

fn set_string(values: &mut Values, key: ValueKey, entry: &IndexEntry, data: &[u8]) {
    if let Some(v) = decode_string(entry, data) {
        put_str(values, key, v);
    }
}

/// Record an integer tag as both a value and a metric, under the same name.
fn set_u32(
    values: &mut Values,
    metrics: &mut Metrics,
    value_key: ValueKey,
    metric_key: crate::MetricKey,
    entry: &IndexEntry,
    data: &[u8],
) {
    if let Some(v) = decode_u32(entry, data) {
        values.insert_key(value_key, json!(v));
        metrics.insert(metric_key, f64::from(v));
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
            Self::TooLarge(reason) => values.insert_key(
                value_key!("rpm.limits"),
                json!([{ "stage": stage, "reason": reason }]),
            ),
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
mod tests;
