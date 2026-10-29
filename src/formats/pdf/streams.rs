//! Per-stream facts: the `pdf.streams[]` inventory and the stream
//! structure metrics.

use serde_json::{Value as JsonValue, json};

use super::filters::{decode_stream, find_filters};
use super::lex::truncate;
use super::objects::{DictRegion, LengthValue, classify_stream_length};
use crate::metric;
use crate::output::Metrics;

/// One entry per object that carries a stream body. Each entry
/// records the carrier `object_id`, the filter chain, a short
/// hex `magic` of the raw stream bytes (8 bytes — enough for the
/// usual file-format signatures), and — when the stream is filtered
/// and its chain decodes — the first ~4 KB of the decoded text.
pub(super) fn scan_streams(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<JsonValue> {
    const MAGIC_BYTES: usize = 8;
    const MAX_DECODED_TEXT: usize = 4096;
    let mut out = Vec::new();
    for region in dict_regions {
        let Some((s, e)) = region.stream_range else {
            continue;
        };
        let Some(raw) = bytes.get(s..e).filter(|raw| !raw.is_empty()) else {
            continue;
        };
        let filters = find_filters(region.dict(bytes)).unwrap_or_default();
        let magic_hex: String = raw
            .iter()
            .take(MAGIC_BYTES)
            .map(|b| format!("{b:02x}"))
            .collect();

        let mut entry = serde_json::Map::new();
        if let Some(id) = region.obj_id {
            entry.insert("object_id".into(), json!(id));
        }
        entry.insert("filters".into(), json!(filters));
        entry.insert("magic_hex".into(), JsonValue::String(magic_hex));

        // An unfiltered body is already in the file's bytes as text; only
        // a decoded one adds anything. Only the first `MAX_DECODED_TEXT`
        // bytes are kept, so decoding more would only burn time on every
        // stream in the file.
        if !filters.is_empty()
            && let Ok(decoded) = decode_stream(raw, &filters, MAX_DECODED_TEXT)
        {
            // Decoded streams are roughly text-shaped (content streams,
            // JavaScript, metadata XML) or binary-shaped (image / font /
            // ICC payloads). `decoded_text` is surfaced only for the first
            // kind, at least half printable ASCII, so trait rules don't
            // have to wade through glyph data.
            let printable = decoded
                .iter()
                .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
                .count();
            let text = String::from_utf8_lossy(&decoded);
            let trimmed = text.trim();
            if printable * 2 >= decoded.len() && !trimmed.is_empty() {
                entry.insert(
                    "decoded_text".into(),
                    JsonValue::String(truncate(trimmed, MAX_DECODED_TEXT)),
                );
            }
        }
        out.push(JsonValue::Object(entry));
    }
    out
}

/// Count objects whose stream filter chain includes a historically
/// exploitable decoder (JBIG2, LZW, Crypt). One match per object —
/// chains with multiple unusual filters still count once, so the
/// metric tracks "number of streams that pull in a risky decoder"
/// rather than the raw filter-name occurrence count.
pub(super) fn streams_with_unusual_filter_count(bytes: &[u8], dict_regions: &[DictRegion]) -> u32 {
    let count = dict_regions
        .iter()
        .filter(|region| region.stream_range.is_some())
        .filter_map(|region| find_filters(region.dict(bytes)))
        .filter(|chain| {
            chain.iter().any(|f| {
                matches!(
                    f.as_str(),
                    "JBIG2Decode" | "JBIG2" | "LZWDecode" | "LZW" | "Crypt"
                )
            })
        })
        .count();
    crate::bytes::sat_u32(count)
}

/// Derive `pdf.stream_*_count` metrics from the dict regions. Each
/// region with a `stream_range` is checked for declared-`/Length`
/// accuracy, missing `endstream`, and a `stream` → newline delimiter
/// (PDF spec requires a CR/LF/CR-LF between `stream` and the body).
pub(super) fn derive_stream_metrics(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    metrics: &mut Metrics,
) {
    let mut missing_length = 0_usize;
    let mut invalid_length = 0_usize;
    let mut missing_endstream = 0_usize;
    let mut length_mismatch = 0_usize;
    let mut bad_delimiter = 0_usize;

    for region in dict_regions {
        let Some((body_start, body_end)) = region.stream_range else {
            continue;
        };
        // `/Length` states:
        //   - key absent → missing_length
        //   - present but non-numeric and not an indirect ref →
        //     invalid_length (malformed value, common in
        //     adversarial PDFs)
        //   - direct numeric → drives length_mismatch detection
        //   - indirect ref (`N N R`) → declared but unresolvable;
        //     skipped for mismatch
        match classify_stream_length(region.dict(bytes)) {
            LengthValue::Missing => missing_length += 1,
            LengthValue::Invalid => invalid_length += 1,
            LengthValue::Indirect => {}
            LengthValue::Direct(declared) => {
                // Allow ±2 bytes for CR/LF tolerance around `endstream`.
                let actual = (body_end - body_start) as u64;
                if actual.abs_diff(declared) > 2 {
                    length_mismatch += 1;
                }
            }
        }
        // `endstream` should follow the body's last byte (the region walk
        // trims a single trailing CR/LF); if the bytes immediately after
        // `body_end` aren't `endstream`, mark it missing.
        let end_window = bytes
            .get(body_end..body_end.saturating_add(16))
            .unwrap_or(&[]);
        if memchr::memmem::find(end_window, b"endstream").is_none() {
            missing_endstream += 1;
        }
        // Bad delimiter: the byte immediately after `stream` should be CR,
        // LF, or CR-LF. The region walk already skipped that, so anything
        // other than the canonical delimiter survived as part of
        // `body_start`'s preceding bytes.
        if let Some(pre) = body_start
            .checked_sub(2)
            .and_then(|from| bytes.get(from..body_start))
            && pre != b"\r\n"
            && pre != b"\n\n"
            && !pre.ends_with(b"\n")
        {
            bad_delimiter += 1;
        }
    }
    for (key, count) in [
        (metric!("pdf.stream_missing_length_count"), missing_length),
        (metric!("pdf.stream_invalid_length_count"), invalid_length),
        (
            metric!("pdf.stream_missing_endstream_count"),
            missing_endstream,
        ),
        (metric!("pdf.stream_length_mismatch_count"), length_mismatch),
        (metric!("pdf.stream_bad_delimiter_count"), bad_delimiter),
    ] {
        metrics.insert(key, count as f64);
    }
}
