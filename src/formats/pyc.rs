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
//! - `pyc.hash` — the 8-byte source hash of a PEP 552 hash-based pyc
//!   (flags bit 0), in hex; its presence marks the variant.
//! - `pyc.timestamp`, `pyc.source_size` — populated only on the
//!   timestamp-based variant (older / non-PEP-552 default).
//! - `pyc.source_files[]` — recovered source paths from
//!   `co_filename` strings.

use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;

use crate::formats::common::{XorScan, extract_binary_strings, hex_encode, put_str};
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
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    // PEP 3147+ magic ends in `0x0d 0x0a`.
    let Some((header, rest)) = bytes
        .split_first_chunk::<16>()
        .filter(|(header, _)| header[2..4] == [0x0D, 0x0A])
    else {
        tracing::debug!(
            target: "filefacts::pyc",
            stage = "header",
            len = bytes.len(),
            "no 16-byte pyc header with a CRLF magic; no pyc facts"
        );
        return;
    };

    let magic_word = u16::from_le_bytes([header[0], header[1]]);
    let flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let is_hash_based = (flags & 1) != 0;

    put_str(
        values,
        value_key!("pyc.magic"),
        format!(
            "{:08x}",
            u32::from_le_bytes([header[0], header[1], header[2], header[3]])
        ),
    );
    if let Some(ver) = python_version_for_magic(magic_word) {
        put_str(values, value_key!("pyc.python_version"), ver);
    }
    if is_hash_based {
        // A presence-only key rather than an `is_hash_based` bool:
        // `exists: pyc.hash` flags the variant.
        put_str(values, value_key!("pyc.hash"), hex_encode(&header[8..16]));
    } else {
        let ts = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let sz = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        if ts != 0 {
            metrics.insert(metric!("pyc.timestamp"), f64::from(ts));
            put_str(values, value_key!("pyc.timestamp"), ts.to_string());
        }
        if sz != 0 {
            metrics.insert(metric!("pyc.source_size"), f64::from(sz));
            put_str(values, value_key!("pyc.source_size"), sz.to_string());
        }
    }

    let body = rest.get(..MAX_BODY_SCAN).unwrap_or(rest);
    let source_files = scan_source_files(body);
    if !source_files.is_empty() {
        metrics.insert(metric!("pyc.source_file_count"), source_files.len() as f64);
        values.insert_key(
            value_key!("pyc.source_files"),
            JsonValue::Array(source_files.into_iter().map(JsonValue::String).collect()),
        );
    }
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
    while let Some(&byte) = body.get(i) {
        if byte != b'.' {
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
        let start = body.get(..i).map_or(i, |before| {
            before
                .iter()
                .rposition(|&b| !is_path_byte(b))
                .map_or(0, |p| p + 1)
        });
        if start == i {
            i += 1;
            continue;
        }
        if let Some(Ok(s)) = body.get(start..after).map(std::str::from_utf8) {
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
mod tests;
