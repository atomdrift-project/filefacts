//! Python compiled bytecode (`.pyc`) extractor.
//!
//! Surfaces the header -- magic and mtime, plus the source size from 3.3 and
//! PEP 552 flags (mtime or source hash) from 3.7 -- and recovers
//! source-filename strings by scanning the body for ASCII byte
//! runs ending in `.py` / `.pyx` / `.pyw` / `.pyi`. The marshal
//! stream also supplies, for CPython 2.7 and 3.0-3.16, bounded code-object
//! identifier tables and string constants: the constants are the module's
//! string literals. Constants never become identifier facts.
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

use crate::formats::ExtractCtx;
use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;

use crate::formats::common::{XorScan, extract_binary_strings, hex_encode, put_str};
use crate::formats::marshal::Version;
use crate::output::Stage;

mod code_objects;

/// Cap on body bytes scanned for source-filename strings. Real
/// `co_filename` paths sit very early in the marshal stream; the
/// cap keeps the pass cheap on huge bytecode modules.
const MAX_BODY_SCAN: usize = 256 * 1024;
/// Cap on distinct source filenames surfaced.
const MAX_SOURCE_FILES: usize = 32;

pub(super) fn extract(bytes: &[u8], ctx: ExtractCtx<'_>) {
    let ExtractCtx {
        values,
        strings,
        metrics,
        symbols,
        errors,
        ..
    } = ctx;
    extract_binary_strings(bytes, strings, XorScan::No);

    // Every CPython magic ends in `0x0d 0x0a`.
    let Some(magic) = bytes
        .first_chunk::<4>()
        .filter(|magic| magic[2..4] == [0x0D, 0x0A])
    else {
        tracing::debug!(
            target: "filefacts::pyc",
            stage = "header",
            len = bytes.len(),
            "no pyc magic ending in CRLF; no pyc facts"
        );
        return;
    };
    let magic_word = u16::from_le_bytes([magic[0], magic[1]]);
    let version = python_version_for_magic(magic_word);
    // The header grew: magic and mtime; source size from 3.3; PEP 552 flags
    // from 3.7. A magic this table does not know is taken as current.
    let header_len = match version {
        Some(v) if v < Version::three(3) => 8,
        Some(v) if v < Version::three(7) => 12,
        _ => 16,
    };
    let Some((header, rest)) = bytes.split_at_checked(header_len) else {
        tracing::debug!(
            target: "filefacts::pyc",
            stage = "header",
            len = bytes.len(),
            header_len,
            "pyc shorter than its header; no pyc facts"
        );
        return;
    };

    put_str(
        values,
        value_key!("pyc.magic"),
        format!("{:08x}", u32::from_le_bytes(*magic)),
    );
    if let Some(version) = version {
        put_str(
            values,
            value_key!("pyc.python_version"),
            format!("{}.{}", version.major, version.minor),
        );
        if version.walkable()
            && let Err(message) =
                code_objects::extract(rest, version, header_len, symbols, &mut strings.literals)
        {
            errors.record_malformed(Stage::FormatExtract, format!("Python marshal: {message}"));
        }
    }
    let word = |at: usize| crate::bytes::u32_le(header, at).unwrap_or(0);
    // PEP 552: flags bit 0 marks a hash-based pyc, whose next 8 bytes are the
    // source hash rather than an mtime and size.
    let (timestamp_at, size_at) = match header_len {
        16 if word(4) & 1 != 0 => {
            // A presence-only key rather than an `is_hash_based` bool:
            // `exists: pyc.hash` flags the variant.
            put_str(
                values,
                value_key!("pyc.hash"),
                hex_encode(header.get(8..16).unwrap_or_default()),
            );
            (None, None)
        }
        16 => (Some(8), Some(12)),
        12 => (Some(4), Some(8)),
        _ => (Some(4), None),
    };
    if let Some(ts) = timestamp_at.map(word).filter(|&ts| ts != 0) {
        metrics.insert(metric!("pyc.timestamp"), f64::from(ts));
        put_str(values, value_key!("pyc.timestamp"), ts.to_string());
    }
    if let Some(sz) = size_at.map(word).filter(|&sz| sz != 0) {
        metrics.insert(metric!("pyc.source_size"), f64::from(sz));
        put_str(values, value_key!("pyc.source_size"), sz.to_string());
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

/// The CPython release a bytecode magic word belongs to. Each release owns
/// the block of words its development used, from CPython's
/// `importlib._bootstrap_external` table; from 3.11 a release reserves a
/// block of fifty, which covers its alphas and betas too. Unknown magics
/// omit `pyc.python_version` rather than emit a stale label.
pub(super) fn python_version_for_magic(magic: u16) -> Option<Version> {
    Some(match magic {
        62171..=62211 => Version { major: 2, minor: 7 },
        3111..=3131 => Version::three(0),
        3141..=3151 => Version::three(1),
        3160..=3180 => Version::three(2),
        3190..=3230 => Version::three(3),
        3250..=3310 => Version::three(4),
        3320..=3351 => Version::three(5),
        3360..=3379 => Version::three(6),
        3390..=3399 => Version::three(7),
        3400..=3419 => Version::three(8),
        3420..=3429 => Version::three(9),
        3430..=3449 => Version::three(10),
        3450..=3499 => Version::three(11),
        3500..=3549 => Version::three(12),
        3550..=3599 => Version::three(13),
        3600..=3649 => Version::three(14),
        3650..=3699 => Version::three(15),
        3700..=3749 => Version::three(16),
        _ => return None,
    })
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
        if let Some(Ok(s)) = body.get(start..after).map(std::str::from_utf8)
            && !s.is_empty()
            && !found.iter().any(|x| x == s)
        {
            found.push(s.to_string());
            if found.len() >= MAX_SOURCE_FILES {
                return found;
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
