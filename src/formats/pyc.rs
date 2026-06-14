//! Python compiled bytecode (`.pyc`) extractor.
//!
//! Marshal-format-agnostic: surfaces the fixed 16-byte header
//! (magic + flags + timestamp/hash + source-size) and recovers
//! source-filename strings by scanning the body for ASCII byte
//! runs ending in `.py` / `.pyx` / `.pyw` / `.pyi`. The marshal
//! stream itself isn't decoded — `co_filename` paths land in the
//! body contiguously regardless of marshal opcode, so a substring
//! pass catches them without a version-specific decoder.
//!
//! Schema:
//!
//! - `pyc.magic` — hex of the 4-byte file signature.
//! - `pyc.python_version` — derived from the magic table.
//! - `pyc.is_hash_based` — PEP 552 bit 0; replaces timestamp with
//!   a hash when set.
//! - `pyc.timestamp`, `pyc.source_size` — populated only on the
//!   timestamp-based variant (older / non-PEP-552 default).
//! - `pyc.source_files[]` — recovered source paths from
//!   `co_filename` strings.

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{extract_binary_strings, put_str};
use crate::output::{Metrics, Strings, Values};

/// Cap on body bytes scanned for source-filename strings. Real
/// `co_filename` paths sit very early in the marshal stream; the
/// cap keeps the pass cheap on huge bytecode modules.
const MAX_BODY_SCAN: usize = 256 * 1024;
/// Cap on distinct source filenames surfaced.
const MAX_SOURCE_FILES: usize = 32;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings);

    if bytes.len() < 16 {
        return Ok(());
    }
    // PEP 3147+ magic ends in `0x0d 0x0a`.
    if bytes[2] != 0x0D || bytes[3] != 0x0A {
        return Ok(());
    }

    let magic_word = u16::from_le_bytes([bytes[0], bytes[1]]);
    let flags = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let is_hash_based = (flags & 1) != 0;

    put_str(
        values,
        "pyc.magic",
        format!(
            "{:08x}",
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        ),
    );
    if let Some(ver) = python_version_for_magic(magic_word) {
        put_str(values, "pyc.python_version", ver);
    }
    if is_hash_based {
        // Per the convention, omit the `is_hash_based: true` bool
        // and use a presence-only key instead — `exists:
        // pyc.hash` flags the variant for traits without a bool.
        let hash_hex: String = bytes[8..16].iter().map(|b| format!("{b:02x}")).collect();
        put_str(values, "pyc.hash", hash_hex);
    } else {
        let ts = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let sz = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if ts != 0 {
            metrics.insert("pyc.timestamp", f64::from(ts));
            put_str(values, "pyc.timestamp", ts.to_string());
        }
        if sz != 0 {
            metrics.insert("pyc.source_size", f64::from(sz));
            put_str(values, "pyc.source_size", sz.to_string());
        }
    }

    let body_end = 16 + (bytes.len() - 16).min(MAX_BODY_SCAN);
    let body = &bytes[16..body_end];
    let source_files = scan_source_files(body);
    if !source_files.is_empty() {
        metrics.insert("pyc.source_file_count", source_files.len() as f64);
        values.insert(
            "pyc.source_files",
            JsonValue::Array(source_files.into_iter().map(JsonValue::String).collect()),
        );
    }

    Ok(())
}

/// Map a Python bytecode magic word to its release name. Values
/// from CPython's `importlib._bootstrap_external` (canonical
/// table). Unknown magics omit `pyc.python_version` rather than
/// emit a stale label.
fn python_version_for_magic(magic: u16) -> Option<&'static str> {
    match magic {
        3379 => Some("3.6"),
        3390..=3394 => Some("3.7"),
        3400..=3413 => Some("3.8"),
        3420..=3425 => Some("3.9"),
        3430..=3439 => Some("3.10"),
        3450..=3495 => Some("3.11"),
        3500..=3531 => Some("3.12"),
        3550..=3571 => Some("3.13"),
        _ => None,
    }
}

/// Walk the body looking for ASCII byte runs that end in `.py`
/// (or `.pyx`/`.pyw`/`.pyi`). Bounded by `MAX_SOURCE_FILES` and
/// `MAX_BODY_SCAN`. De-duplicates while preserving first-seen
/// order.
fn scan_source_files(body: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'.' {
            i += 1;
            continue;
        }
        let Some(slice) = body.get(i..i + 3) else {
            break;
        };
        if slice != b".py" {
            i += 1;
            continue;
        }
        let extra = match body.get(i + 3) {
            Some(b) if matches!(*b, b'x' | b'w' | b'i') => 1,
            _ => 0,
        };
        let after = i + 3 + extra;
        // Walk backwards over path bytes to the start of the run.
        let mut start = i;
        while start > 0 && is_path_byte(body[start - 1]) {
            start -= 1;
        }
        if start == i {
            i += 1;
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&body[start..after]) {
            if !s.is_empty() && !found.iter().any(|x| x == s) {
                found.push(s.to_string());
                if found.len() >= MAX_SOURCE_FILES {
                    return found;
                }
            }
        }
        i = after;
    }
    found
}

fn is_path_byte(b: u8) -> bool {
    matches!(b, b'/' | b'\\' | b'.' | b'-' | b'_' | b':' | b'+') || b.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pyc(magic_word: u16, flags: u32, ts: u32, sz: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&magic_word.to_le_bytes());
        out.extend_from_slice(&[0x0D, 0x0A]);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&sz.to_le_bytes());
        out.extend_from_slice(body);
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
    fn surfaces_header_and_filenames() {
        let mut body = vec![0x10];
        body.extend_from_slice(b"/build/foo/bar.py");
        body.push(0);
        let pyc = build_pyc(3413, 0, 1_700_000_000, 1234, &body);
        let (v, m) = run(&pyc);
        assert_eq!(
            v.get("pyc.python_version").and_then(|x| x.as_str()),
            Some("3.8")
        );
        assert_eq!(m.get("pyc.timestamp"), Some(1_700_000_000.0));
        assert_eq!(m.get("pyc.source_size"), Some(1234.0));
        let files = v
            .get("pyc.source_files")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(files[0].as_str(), Some("/build/foo/bar.py"));
    }

    #[test]
    fn hash_based_emits_hash_key_not_timestamp() {
        let body = b"\x10/build/foo.py\x00".to_vec();
        let pyc = build_pyc(3439, 0x01, 0, 0, &body);
        let (v, m) = run(&pyc);
        assert!(v.get("pyc.hash").is_some());
        assert!(m.get("pyc.timestamp").is_none());
    }

    #[test]
    fn rejects_too_short() {
        let (v, _) = run(b"short");
        assert!(v.get("pyc.magic").is_none());
    }

    #[test]
    fn rejects_bad_signature() {
        let (v, _) = run(&[0u8; 32]);
        assert!(v.get("pyc.magic").is_none());
    }

    #[test]
    fn dedupes_filenames() {
        let mut body = Vec::new();
        for _ in 0..40 {
            body.push(0x10);
            body.extend_from_slice(b"/tmp/file.py");
            body.push(0);
        }
        let pyc = build_pyc(3413, 0, 1, 1, &body);
        let (v, _) = run(&pyc);
        let files = v
            .get("pyc.source_files")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn unknown_magic_omits_version() {
        // Magic word not in the version table — header still parses,
        // but `pyc.python_version` is omitted rather than mis-labelled.
        let pyc = build_pyc(9999, 0, 0, 0, b"");
        let (v, _) = run(&pyc);
        assert!(v.get("pyc.magic").is_some());
        assert!(v.get("pyc.python_version").is_none());
    }

    #[test]
    fn recognizes_pyx_pyw_pyi_extensions() {
        let mut body = Vec::new();
        for path in [b"a/b.pyx" as &[u8], b"c/d.pyw", b"e/f.pyi", b"g.py"] {
            body.push(0x10);
            body.extend_from_slice(path);
            body.push(0);
        }
        let pyc = build_pyc(3413, 0, 1, 1, &body);
        let (v, m) = run(&pyc);
        let files = v
            .get("pyc.source_files")
            .and_then(|x| x.as_array())
            .unwrap();
        let paths: Vec<&str> = files.iter().filter_map(|x| x.as_str()).collect();
        assert!(paths.contains(&"a/b.pyx"));
        assert!(paths.contains(&"c/d.pyw"));
        assert!(paths.contains(&"e/f.pyi"));
        assert!(paths.contains(&"g.py"));
        assert_eq!(m.get("pyc.source_file_count"), Some(4.0));
    }

    #[test]
    fn rejects_signature_with_wrong_second_pair() {
        // First two bytes look like a magic word but the next two are
        // not `\r\n` — must reject.
        let mut bytes = vec![0x55, 0x0D, 0x00, 0x00];
        bytes.extend_from_slice(&[0u8; 12]);
        let (v, _) = run(&bytes);
        assert!(v.get("pyc.magic").is_none());
    }

    #[test]
    fn body_scan_caps_filename_count() {
        // Build 40 distinct filenames; should cap at MAX_SOURCE_FILES (32).
        let mut body = Vec::new();
        for i in 0..40 {
            body.push(0x10);
            body.extend_from_slice(format!("/tmp/file{i}.py").as_bytes());
            body.push(0);
        }
        let pyc = build_pyc(3413, 0, 1, 1, &body);
        let (v, _) = run(&pyc);
        let files = v
            .get("pyc.source_files")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(files.len(), MAX_SOURCE_FILES);
    }

    #[test]
    fn empty_input_is_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("pyc.magic").is_none());
    }
}
