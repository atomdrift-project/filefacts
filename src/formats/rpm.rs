//! RPM package extractor.
//!
//! Header-only parse — never touches the payload. Walks the
//! 96-byte lead, the signature header (for cryptographic signing
//! algorithm presence), and the main header (NAME, VERSION,
//! BUILDHOST, PACKAGER, …). The header tag set covers the
//! canonical fields `rpm -qpi` shows.
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

use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str};
use crate::output::{Metrics, Strings, Values};

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
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    if bytes.len() < LEAD_BYTES + 16 || bytes[..4] != RPM_LEAD_MAGIC {
        return Ok(());
    }
    let mut pos = LEAD_BYTES;

    // Signature header — record which cryptographic algorithms
    // signed the package. Presence of the array is the "signed"
    // signal.
    let Some((sig_entries, _sig_data, sig_total)) = read_header(&bytes[pos..]) else {
        return Ok(());
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
            JsonValue::Array(algos.into_iter().map(|s| JsonValue::String(s.into())).collect()),
        );
        values.insert("rpm.signature", JsonValue::Object(sig));
    }
    pos += sig_total;
    pos += (8 - (pos % 8)) % 8;

    // Main header.
    let Some((main_entries, main_data, _)) = read_header(&bytes[pos..]) else {
        return Ok(());
    };
    for entry in &main_entries {
        apply_main_tag(entry, main_data, values, metrics);
    }

    Ok(())
}

fn apply_main_tag(entry: &IndexEntry, data: &[u8], values: &mut Values, metrics: &mut Metrics) {
    match entry.tag {
        main_tag::NAME => set_string(values, "rpm.name", entry, data),
        main_tag::VERSION => set_string(values, "rpm.version", entry, data),
        main_tag::RELEASE => set_string(values, "rpm.release", entry, data),
        main_tag::EPOCH => set_u32(values, metrics, "rpm.epoch", entry, data),
        main_tag::SUMMARY => set_string(values, "rpm.summary", entry, data),
        main_tag::BUILDTIME => set_u32(values, metrics, "rpm.buildtime", entry, data),
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

fn set_u32(values: &mut Values, metrics: &mut Metrics, key: &str, entry: &IndexEntry, data: &[u8]) {
    if let Some(v) = decode_u32(entry, data) {
        metrics.insert(key.to_string(), f64::from(v));
        values.insert(key, json!(v));
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
    let s = std::str::from_utf8(&rest[..nul]).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

fn decode_u32(entry: &IndexEntry, data: &[u8]) -> Option<u32> {
    if entry.typ != 4 || entry.count != 1 {
        return None;
    }
    let off = entry.offset as usize;
    let bytes = data.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    tag: u32,
    typ: u32,
    offset: u32,
    count: u32,
}

/// Parse one RPM header (magic + entries + data store). Returns
/// `(entries, data_store, total_header_size)` or `None` on bounds
/// failure.
fn read_header(slice: &[u8]) -> Option<(Vec<IndexEntry>, &[u8], usize)> {
    if slice.len() < 16 || slice[..3] != RPM_HEADER_MAGIC {
        return None;
    }
    let nindex = u32::from_be_bytes(slice[8..12].try_into().ok()?) as usize;
    let hsize = u32::from_be_bytes(slice[12..16].try_into().ok()?) as usize;
    let index_size = nindex.checked_mul(16)?;
    if index_size > MAX_HEADER_BYTES || hsize > MAX_HEADER_BYTES {
        return None;
    }
    let entries_end = 16usize.checked_add(index_size)?;
    let data_end = entries_end.checked_add(hsize)?;
    if data_end > slice.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(nindex);
    for i in 0..nindex {
        let off = 16 + i * 16;
        let tag = u32::from_be_bytes(slice[off..off + 4].try_into().ok()?);
        let typ = u32::from_be_bytes(slice[off + 4..off + 8].try_into().ok()?);
        let offset = u32::from_be_bytes(slice[off + 8..off + 12].try_into().ok()?);
        let count = u32::from_be_bytes(slice[off + 12..off + 16].try_into().ok()?);
        entries.push(IndexEntry { tag, typ, offset, count });
    }
    Some((entries, &slice[entries_end..data_end], data_end))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
    }

    #[test]
    fn rejects_non_rpm() {
        let (v, _) = run(b"not an rpm");
        assert!(v.get("rpm.name").is_none());
    }

    #[test]
    fn surfaces_main_header() {
        let rpm = build_minimal_rpm();
        let (v, m) = run(&rpm);
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
        let (v, _) = run(&[0u8; 10]);
        assert!(v.get("rpm.name").is_none());
    }

    #[test]
    fn wrong_lead_magic_is_silent() {
        let mut bad = vec![0u8; LEAD_BYTES + 16];
        bad[0..4].copy_from_slice(b"NOPE");
        let (v, _) = run(&bad);
        assert!(v.get("rpm.name").is_none());
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
        let (v, _) = run(&out);
        assert!(v.get("rpm.name").is_none());
    }
}
