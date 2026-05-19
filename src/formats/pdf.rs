//! PDF extractor.
//!
//! Lenient byte-scan parser — no cross-reference resolution, no
//! stream decryption, no object-graph reconstruction. Malicious
//! PDFs routinely break those features to evade strict parsers, so
//! we surface forensic facts (action presence, embedded files,
//! catalog flags) by recognizing the canonical PDF tokens directly
//! in the raw bytes.
//!
//! Schema namespaces under `pdf.*` matching expose's per-format
//! convention:
//!
//! - `pdf.header.{version, header_count}` — first `%PDF-X.Y` plus the
//!   total count (>1 signals a stacked-PDF evasion attempt).
//! - `pdf.info.{title, author, creator, producer, subject, keywords,
//!   creation_date, mod_date, trapped}` — DocumentInfo dict.
//! - `pdf.catalog.{has_openaction, has_additional_actions, has_acroform,
//!   has_xfa, has_names_javascript, has_richmedia, has_3d}` — feature
//!   flags from the catalog dictionary.
//! - `pdf.actions[].{kind, source, snippet}` — action invocation sites.
//! - `pdf.embedded_files[].{filename, size}` — `/Type /Filespec` attachments.
//! - `pdf.filter_chains[]` — dedup'd comma-joined `/Filter` declarations.
//! - `pdf.streams[].{object_id, filters, magic_hex, decoded_text}` —
//!   per-stream metadata, FlateDecode bodies inflated.
//! - `pdf.form_fields[].{object_id, name, field_type, rect, value}` —
//!   AcroForm widget entries.
//! - `pdf.shape.{object_count, eof_count, page_count, annotation_count,
//!   encrypted, linearized, …}` — structural counts and flags.
//!
//! Metric counts live flat under `pdf.*` and parallel the kv view.

use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::extract_ascii_strings;
use crate::output::{Metrics, Strings, Values};

/// Cap on the snippet text we surface per action. Long JavaScript
/// payloads exist in malicious PDFs but the *first* few hundred
/// bytes contain the recognizable invocation patterns analysts
/// want; the rest is obfuscated runtime. Matches cleave's cap.
const SNIPPET_BYTES: usize = 200;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    // Every PDF starts with `%PDF-<major>.<minor>`. Bail (parsable
    // as generic) if the header is missing or unreadable.
    let header_count = count_substring(bytes, b"%PDF-");
    if header_count == 0 {
        return Ok(());
    }
    metrics.insert("pdf.header_count", header_count as f64);
    let mut header = serde_json::Map::new();
    if let Some(version) = parse_first_header(bytes) {
        header.insert("version".into(), JsonValue::String(version));
    }
    header.insert("count".into(), json!(header_count));
    values.insert("pdf.header", JsonValue::Object(header));

    // Structural counts — the cheap byte-level fingerprint.
    let eof_count = count_substring(bytes, b"%%EOF");
    let trailer_count = count_substring(bytes, b"\ntrailer");
    let startxref_count = count_substring(bytes, b"startxref");
    let obj_count = count_token(bytes, b"obj");
    let endobj_count = count_token(bytes, b"endobj");
    let stream_count = count_token(bytes, b"stream");
    metrics.insert("pdf.eof_count", eof_count as f64);
    metrics.insert("pdf.trailer_count", trailer_count as f64);
    metrics.insert("pdf.startxref_count", startxref_count as f64);
    metrics.insert("pdf.object_count", obj_count.min(endobj_count) as f64);
    metrics.insert("pdf.stream_count", stream_count as f64);

    // `pdf.catalog.features[]` — Pike-style flag array (mirrors
    // `pe.dll_characteristics`). Trait authors match `exact: xfa` /
    // `exact: openaction` rather than chase a sprawl of per-flag
    // booleans. Names use the PDF-spec keys analysts already know
    // (AcroForm, XFA, OpenAction) lowercased; `additional_actions`
    // expands the abbreviated `/AA`; `3d` matches the spec name.
    let mut features: Vec<&str> = Vec::new();
    if contains_token(bytes, b"/AcroForm") {
        features.push("acroform");
    }
    if contains_token(bytes, b"/XFA") {
        features.push("xfa");
    }
    if contains_token(bytes, b"/OpenAction") {
        features.push("openaction");
    }
    if contains_keyword(bytes, b"/AA") {
        // `/AA` = Additional Actions. Whole-token match — bare
        // substring would hit `AAAaa` style binary noise.
        features.push("additional_actions");
    }
    if contains_token(bytes, b"/JavaScript") {
        features.push("names_javascript");
    }
    if contains_token(bytes, b"/RichMedia") {
        features.push("richmedia");
    }
    if contains_substring(bytes, b"/Subtype /3D") || contains_substring(bytes, b"/Subtype/3D") {
        features.push("3d");
    }
    if !features.is_empty() {
        let mut catalog = serde_json::Map::new();
        catalog.insert(
            "features".into(),
            JsonValue::Array(
                features.into_iter().map(|s| JsonValue::String(s.into())).collect(),
            ),
        );
        values.insert("pdf.catalog", JsonValue::Object(catalog));
    }

    // `shape.*` — structural counts and flags. Cleave's parser
    // owns the cross-reference-aware counts (visible vs object-stream
    // objects, unreferenced objects, trailing bytes); we contribute
    // the byte-level counts that don't require xref resolution.
    let mut shape = serde_json::Map::new();
    shape.insert("object_count".into(), json!(obj_count.min(endobj_count)));
    shape.insert("eof_count".into(), json!(eof_count));
    if trailer_count > 0 {
        shape.insert("trailer_count".into(), json!(trailer_count));
    }
    if startxref_count > 0 {
        shape.insert("startxref_count".into(), json!(startxref_count));
    }
    let mut shape_flags: Vec<&str> = Vec::new();
    if contains_token(bytes, b"/Encrypt") {
        shape_flags.push("encrypted");
    }
    if contains_token(bytes, b"/Linearized") {
        shape_flags.push("linearized");
    }
    if !shape_flags.is_empty() {
        shape.insert(
            "flags".into(),
            JsonValue::Array(
                shape_flags.into_iter().map(|s| JsonValue::String(s.into())).collect(),
            ),
        );
    }

    // `/Type /Name` style counts — each is the number of object
    // dictionaries whose `/Type` key is the named role. Matches
    // both whitespace-separated and joined-token forms emitted by
    // various PDF producers.
    let counts: &[(&str, &str, Option<&str>)] = &[
        ("page_count", "/Page", Some("pdf.page_count")),
        ("annotation_count", "/Annot", Some("pdf.annotation_count")),
        ("xobject_count", "/XObject", Some("pdf.xobject_count")),
        ("font_count", "/Font", Some("pdf.font_count")),
        ("metadata_count", "/Metadata", None),
        ("objstm_count", "/ObjStm", None),
        ("xref_stream_count", "/XRef", None),
        ("signature_object_count", "/Sig", Some("pdf.signature_object_count")),
    ];
    for (kv_key, name, metric_key) in counts {
        let c = count_type_occurrences(bytes, name.as_bytes());
        if c > 0 {
            shape.insert((*kv_key).into(), json!(c));
            if let Some(mk) = metric_key {
                metrics.insert((*mk).to_string(), c as f64);
            }
        }
    }
    let byte_range_count = count_substring(bytes, b"/ByteRange");
    if byte_range_count > 0 {
        shape.insert("byte_range_count".into(), json!(byte_range_count));
        metrics.insert("pdf.byte_range_count", byte_range_count as f64);
    }
    let jbig2 = count_substring(bytes, b"/JBIG2Decode");
    if jbig2 > 0 {
        shape.insert("jbig2_filter_count".into(), json!(jbig2));
        metrics.insert("pdf.jbig2_filter_count", jbig2 as f64);
    }
    let three_d = count_substring(bytes, b"/Subtype /3D") + count_substring(bytes, b"/Subtype/3D");
    if three_d > 0 {
        shape.insert("three_d_object_count".into(), json!(three_d));
    }
    if !shape.is_empty() {
        values.insert("pdf.shape", JsonValue::Object(shape));
    }

    // `/FlateDecode` count — the bulk of legitimate compressed
    // streams. (`/JBIG2Decode` is emitted alongside `shape.*` below
    // as both a metric and a kv field.)
    metrics.insert(
        "pdf.flate_filter_count",
        count_substring(bytes, b"/FlateDecode") as f64,
    );

    // Info dict — Title / Author / Creator / Producer / etc. live
    // in a dict referenced by `/Info` from the trailer. We don't
    // resolve the indirect reference; instead we scan all `obj`
    // blocks for the standard Info keys and pick up whichever
    // appears first. Malicious PDFs sometimes split Info across
    // multiple incremental updates, in which case the last one
    // wins (we want the document's *final* state).
    info_dict(bytes, values);

    // Action sites with full kv shape — `{kind, source, snippet}` —
    // scanned strictly inside object *dictionaries* (between `obj`
    // and the first `stream`/`endobj`). Source attribution is
    // best-effort: object-id when we can identify the carrier,
    // "openaction" when the catalog dict references the action
    // inline. We don't follow indirect references back to named
    // / annotation / acroform sites, so heavily-staged malicious
    // PDFs may show fewer source labels than cleave's xref-aware
    // parser. The `kind` and `snippet` fields stay accurate.
    let dict_regions = collect_dict_regions(bytes);
    let actions = scan_actions(bytes, &dict_regions);
    if !actions.is_empty() {
        metrics.insert("pdf.action_count", actions.len() as f64);
        values.insert("pdf.actions", JsonValue::Array(actions));
    }

    // Embedded files — `{filename, size}` per `/Type /Filespec`
    // record. `size` is recovered by following the `/EF /F <ref>`
    // reference to the embedded-stream object and reading the
    // (possibly indirect) `/Length` value from its dict.
    let embedded = scan_embedded_files(bytes, &dict_regions);
    if !embedded.is_empty() {
        metrics.insert("pdf.embedded_file_count", embedded.len() as f64);
        values.insert(
            "pdf.embedded_files",
            JsonValue::Array(
                embedded
                    .into_iter()
                    .map(|(name, size)| {
                        let mut obj = serde_json::Map::new();
                        obj.insert("filename".into(), JsonValue::String(name));
                        if let Some(sz) = size {
                            obj.insert("size".into(), JsonValue::Number(sz.into()));
                        }
                        JsonValue::Object(obj)
                    })
                    .collect(),
            ),
        );
    }

    // Filter chains — every `/Filter` declaration surfaces as a
    // comma-joined string (e.g. `"ASCIIHexDecode,FlateDecode"`).
    // Deduplicated since trait rules typically check whether a
    // particular chain *appears* anywhere, not how many times.
    let chains = scan_filter_chains(bytes, &dict_regions);
    if !chains.is_empty() {
        values.insert(
            "pdf.filter_chains",
            JsonValue::Array(chains.into_iter().map(JsonValue::String).collect()),
        );
    }

    // Streams — one entry per object that carries a `stream` body.
    // FlateDecode chains are decompressed; the leading ~16 bytes
    // expose a hex magic for content-sniffing and the first ~4 KB
    // of UTF-8-decodable text fills `decoded_text`. Other filter
    // chains (DCT, JBIG2, …) surface filter info only.
    let streams = scan_streams(bytes, &dict_regions);
    if !streams.is_empty() {
        values.insert("pdf.streams", JsonValue::Array(streams));
    }

    // AcroForm widget fields — `/Subtype /Widget` objects with a
    // field type (`/FT`). Surfaces the field name (`/T`), type
    // (`/FT`), bounding box (`/Rect`), and value (`/V`) when one
    // is set. Used by trait rules detecting staged JavaScript or
    // recognizable form authoring fingerprints.
    let form_fields = scan_form_fields(bytes, &dict_regions);
    if !form_fields.is_empty() {
        values.insert("pdf.form_fields", JsonValue::Array(form_fields));
    }

    Ok(())
}

/// First `%PDF-X.Y` version found. Multiple headers (stacked PDFs)
/// is a known evasion technique; the *first* version is what the
/// loader keys on, so that's what we surface as the canonical
/// document version. The full count is exposed as
/// `pdf.header_count`.
fn parse_first_header(bytes: &[u8]) -> Option<String> {
    let pos = bytes.windows(5).position(|w| w == b"%PDF-")?;
    let start = pos + 5;
    let end = (start + 8).min(bytes.len());
    let tail = &bytes[start..end];
    let mut version = String::new();
    for &b in tail {
        if b.is_ascii_digit() || b == b'.' {
            version.push(b as char);
        } else {
            break;
        }
    }
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Scan every `obj` … `endobj` block for the canonical DocumentInfo
/// keys and surface their *first* value occurrence as
/// `pdf.info.<lowercased>`.
fn info_dict(bytes: &[u8], values: &mut Values) {
    const KEYS: &[(&[u8], &str)] = &[
        (b"/Title", "title"),
        (b"/Author", "author"),
        (b"/Creator", "creator"),
        (b"/Producer", "producer"),
        (b"/Subject", "subject"),
        (b"/Keywords", "keywords"),
        (b"/CreationDate", "creation_date"),
        (b"/ModDate", "mod_date"),
        (b"/Trapped", "trapped"),
    ];
    let mut info = serde_json::Map::new();
    for (needle, key) in KEYS {
        if let Some(value) = find_info_value(bytes, needle) {
            if !value.is_empty() {
                info.insert((*key).to_string(), JsonValue::String(value));
            }
        }
    }
    if !info.is_empty() {
        values.insert("pdf.info", JsonValue::Object(info));
    }
}

/// Locate `/Key` and return its associated string-or-name value.
/// Handles `(…)` literal strings, `<…>` hex strings, and bare names
/// (`/Producer /WatermarkPDF`). Returns `None` when the key isn't
/// followed by a recognizable value within a small window.
///
/// Suffix-collision aware: scanning continues past matches whose
/// trailing byte is a name char (so searching for `/T` skips past
/// `/Type` and `/Title` until it finds a real `/T` boundary).
fn find_info_value(bytes: &[u8], key: &[u8]) -> Option<String> {
    let mut cursor = 0;
    while cursor + key.len() <= bytes.len() {
        let rel = bytes[cursor..].windows(key.len()).position(|w| w == key)?;
        let pos = cursor + rel;
        let after_key = pos + key.len();
        let next = *bytes.get(after_key)?;
        if next.is_ascii_alphabetic() || next == b'_' {
            cursor = after_key;
            continue;
        }
        let mut value_pos = after_key;
        while value_pos < bytes.len()
            && (bytes[value_pos] == b' ' || bytes[value_pos] == b'\t')
        {
            value_pos += 1;
        }
        if value_pos >= bytes.len() {
            return None;
        }
        return match bytes[value_pos] {
            b'(' => read_literal_string(bytes, value_pos + 1),
            b'<' if bytes.get(value_pos + 1) != Some(&b'<') => {
                read_hex_string(bytes, value_pos + 1)
            }
            b'/' => read_name(bytes, value_pos + 1),
            b'0'..=b'9' | b'-' => {
                // Bare numeric value (e.g. `/Length 42`). Capture
                // the digit/sign run.
                let end = bytes[value_pos..]
                    .iter()
                    .position(|&b| !(b.is_ascii_digit() || b == b'-' || b == b'.'))
                    .map_or(bytes.len(), |n| value_pos + n);
                std::str::from_utf8(&bytes[value_pos..end])
                    .ok()
                    .map(str::to_string)
            }
            _ => None,
        };
    }
    None
}

/// PDF literal strings are `(text)` with balanced parens and `\)`
/// escapes. We cap at 1024 bytes and decode lossily to UTF-8.
fn read_literal_string(bytes: &[u8], start: usize) -> Option<String> {
    const CAP: usize = 1024;
    let mut depth = 1_i32;
    let mut out = Vec::new();
    let mut i = start;
    while i < bytes.len() && out.len() < CAP {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            // PDF escape sequences inside literal strings:
            //   \n \r \t \b \f \( \) \\  → single-byte escapes
            //   \NNN                       → 1-3 octal digits
            //   \<eol>                     → line continuation
            let esc = bytes[i + 1];
            match esc {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'b' => out.push(8),
                b'f' => out.push(12),
                b'(' | b')' | b'\\' => out.push(esc),
                b'\n' | b'\r' => { /* line continuation: drop */ }
                b'0'..=b'7' => {
                    let mut j = i + 1;
                    let mut value: u16 = 0;
                    let mut count = 0;
                    while count < 3 && j < bytes.len() && (b'0'..=b'7').contains(&bytes[j]) {
                        value = value * 8 + u16::from(bytes[j] - b'0');
                        j += 1;
                        count += 1;
                    }
                    out.push((value & 0xFF) as u8);
                    i = j;
                    continue;
                }
                _ => out.push(esc),
            }
            i += 2;
            continue;
        }
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        out.push(b);
        i += 1;
    }
    if out.is_empty() {
        return None;
    }
    // Strip UTF-16 BOM (FE FF or FF FE) — PDF Title/Author are
    // frequently UTF-16BE encoded with the BE BOM. Decode it; fall
    // back to lossy ASCII otherwise.
    if out.len() >= 2 && out[0] == 0xFE && out[1] == 0xFF {
        let units: Vec<u16> = out[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return Some(String::from_utf16_lossy(&units).trim().to_string());
    }
    Some(String::from_utf8_lossy(&out).trim().to_string())
}

/// PDF hex strings are `<HH HH …>`. Decode pairs to bytes, then to
/// UTF-8 / UTF-16BE the same way as literal strings.
fn read_hex_string(bytes: &[u8], start: usize) -> Option<String> {
    let end = start + bytes[start..].iter().position(|&b| b == b'>')?;
    let hex_only: Vec<u8> = bytes[start..end]
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect();
    let mut out = Vec::with_capacity(hex_only.len() / 2);
    for chunk in hex_only.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = if chunk.len() == 2 {
            hex_nibble(chunk[1])?
        } else {
            0
        };
        out.push((hi << 4) | lo);
    }
    if out.is_empty() {
        return None;
    }
    if out.len() >= 2 && out[0] == 0xFE && out[1] == 0xFF {
        let units: Vec<u16> = out[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return Some(String::from_utf16_lossy(&units).trim().to_string());
    }
    Some(String::from_utf8_lossy(&out).trim().to_string())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// PDF names start with `/` and continue with regular characters
/// until whitespace or a delimiter.
fn read_name(bytes: &[u8], start: usize) -> Option<String> {
    let end = bytes[start..]
        .iter()
        .position(|&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'<' | b'>' | b'[' | b']' | b'('))
        .map_or(bytes.len(), |n| start + n);
    let name = &bytes[start..end];
    if name.is_empty() {
        return None;
    }
    Some(format!("/{}", String::from_utf8_lossy(name)))
}

/// Object boundaries within the file: dict range plus, when the
/// object carries a `stream` body, the stream byte range and the
/// declared `/Length` (when we recovered it). Action / filter
/// scans use only `dict_start..dict_end` so they never see
/// stream-body bytes (high-entropy binary that false-positives
/// `/JS` and friends).
#[derive(Debug, Clone)]
struct DictRegion {
    start: usize,
    end: usize,
    obj_id: Option<u32>,
    /// Byte range of the stream body (the bytes between `stream\n`
    /// and `\nendstream`) when this object has one.
    stream_range: Option<(usize, usize)>,
}

/// Walk every `<id> <gen> obj` … (`stream`|`endobj`) block. Each
/// returned region carries the dict byte range and, when a stream
/// body was present, the stream byte range too.
fn collect_dict_regions(bytes: &[u8]) -> Vec<DictRegion> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(rel) = bytes[pos..].windows(3).position(|w| w == b"obj") else {
            break;
        };
        let obj_pos = pos + rel;
        // Require whole-token: the byte before `obj` must be
        // whitespace and the byte after must not be a name char
        // (avoids matching `endobj`, `objstm`, etc.).
        let before = if obj_pos == 0 { b' ' } else { bytes[obj_pos - 1] };
        let after = bytes.get(obj_pos + 3).copied().unwrap_or(b' ');
        if !before.is_ascii_whitespace() || is_name_char(after) {
            pos = obj_pos + 3;
            continue;
        }
        let obj_id = parse_obj_id_before(bytes, obj_pos);
        let dict_start = obj_pos + 3;
        // Dict ends at the nearest `stream` or `endobj` token.
        // Both are whole tokens, so accept any non-name char as the
        // delimiter (space, newline, etc.).
        let stream_end_marker = find_token_after(bytes, dict_start, b"stream");
        let endobj_end = find_token_after(bytes, dict_start, b"endobj");
        let dict_end = match (stream_end_marker, endobj_end) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        // If a stream is present (i.e. the `stream` token came
        // before `endobj`), find the matching `endstream` to record
        // the stream byte range.
        let stream_range =
            if let (Some(s), Some(e)) = (stream_end_marker, endobj_end) {
                if s < e {
                    // Skip past `stream` + optional CR/LF.
                    let mut body_start = s + b"stream".len();
                    if bytes.get(body_start) == Some(&b'\r') {
                        body_start += 1;
                    }
                    if bytes.get(body_start) == Some(&b'\n') {
                        body_start += 1;
                    }
                    let endstream =
                        find_token_after(bytes, body_start, b"endstream").unwrap_or(e);
                    // Trim a single trailing CR/LF before `endstream`.
                    let mut body_end = endstream;
                    if body_end > body_start && bytes[body_end - 1] == b'\n' {
                        body_end -= 1;
                    }
                    if body_end > body_start && bytes[body_end - 1] == b'\r' {
                        body_end -= 1;
                    }
                    Some((body_start, body_end))
                } else {
                    None
                }
            } else {
                None
            };
        out.push(DictRegion {
            start: dict_start,
            end: dict_end,
            obj_id,
            stream_range,
        });
        // Skip past the stream body if one was present (the next
        // `endobj` is after `endstream`).
        pos = match (stream_end_marker, endobj_end) {
            (Some(s), Some(e)) if s < e => find_token_after(bytes, s, b"endobj").unwrap_or(e),
            _ => dict_end,
        };
    }
    out
}

/// Recover the `<id>` from a `<id> <gen> obj` preamble immediately
/// before `obj_pos`. Returns `None` when the preamble doesn't parse
/// (object stream entries, malformed inputs).
fn parse_obj_id_before(bytes: &[u8], obj_pos: usize) -> Option<u32> {
    // Walk back over whitespace then digits twice (gen, then id),
    // with whitespace between them.
    let mut i = obj_pos;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    // Skip generation number.
    let mut gen_start = i;
    while gen_start > 0 && bytes[gen_start - 1].is_ascii_digit() {
        gen_start -= 1;
    }
    if gen_start == i {
        return None;
    }
    let mut j = gen_start;
    while j > 0 && bytes[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    let mut id_start = j;
    while id_start > 0 && bytes[id_start - 1].is_ascii_digit() {
        id_start -= 1;
    }
    if id_start == j {
        return None;
    }
    std::str::from_utf8(&bytes[id_start..j]).ok()?.parse().ok()
}

/// Like `find_after` but requires the match to be a whole token:
/// neither the preceding nor following byte may be a name char.
fn find_token_after(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let mut pos = from;
    while pos < bytes.len() {
        let rel = bytes[pos..].windows(needle.len()).position(|w| w == needle)?;
        let abs = pos + rel;
        let before = if abs == 0 { b' ' } else { bytes[abs - 1] };
        let after = bytes.get(abs + needle.len()).copied().unwrap_or(b' ');
        if !is_name_char(before) && !is_name_char(after) {
            return Some(abs);
        }
        pos = abs + needle.len();
    }
    None
}


/// Walk each dictionary region for action invocation patterns and
/// emit one entry per occurrence. We don't deduplicate by source
/// object — each `/JS` site is independently interesting, since
/// malicious PDFs often stage the payload across several actions
/// to evade signature-based scanners that look at any one site.
///
/// The carrier object id is included as `source: "object:<id>"`.
/// When a containing object is also the catalog (i.e. carries
/// `/Type /Catalog`) the source is recorded as `"openaction"`
/// instead — that's the canonical name cleave's parser used.
fn scan_actions(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<JsonValue> {
    const KINDS: &[(&[u8], &str)] = &[
        (b"/JS", "javascript"),
        (b"/Launch", "launch"),
        (b"/URI", "uri"),
        (b"/SubmitForm", "submitform"),
        (b"/GoToR", "gotor"),
        (b"/GoToE", "gotoe"),
        (b"/Movie", "movie"),
        (b"/Sound", "sound"),
        (b"/ImportData", "importdata"),
    ];
    let mut out = Vec::new();
    for region_info in dict_regions {
        let DictRegion { start, end, obj_id, .. } = *region_info;
        if end <= start {
            continue;
        }
        let region = &bytes[start..end];
        let is_catalog = contains_substring(region, b"/Type /Catalog")
            || contains_substring(region, b"/Type/Catalog");
        let source = if is_catalog {
            "openaction".to_string()
        } else {
            match obj_id {
                Some(id) => format!("object:{id}"),
                None => "object:unknown".to_string(),
            }
        };
        for (needle, kind) in KINDS {
            let mut pos = 0;
            while let Some(rel) = region[pos..].windows(needle.len()).position(|w| w == *needle) {
                let abs = pos + rel;
                let next = abs + needle.len();
                // Reject `/JS` matching `/JSON` or `/JavaScript`.
                if next < region.len() && region[next].is_ascii_alphabetic() {
                    pos = next;
                    continue;
                }
                // Only emit when the key has a value-bearing payload
                // — filters out `/S /URI` action-type declarations
                // (where `/URI` is a *name value*, not a key).
                if let Some(snip) = action_snippet(region, next) {
                    let mut entry = serde_json::Map::new();
                    entry.insert("kind".into(), JsonValue::String((*kind).to_string()));
                    entry.insert("source".into(), JsonValue::String(source.clone()));
                    entry.insert("snippet".into(), JsonValue::String(snip));
                    out.push(JsonValue::Object(entry));
                }
                pos = next;
            }
        }
    }
    out
}

/// Deduplicated comma-joined filter chain strings across every
/// `/Filter` declaration inside an object dictionary. A single-name
/// declaration like `/Filter /FlateDecode` becomes `"FlateDecode"`;
/// an array like `/Filter [/ASCIIHexDecode /FlateDecode]` becomes
/// `"ASCIIHexDecode,FlateDecode"`. Order preserves first appearance.
fn scan_filter_chains(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for region_info in dict_regions {
        let DictRegion { start, end, .. } = *region_info;
        if end <= start {
            continue;
        }
        let region = &bytes[start..end];
        let mut pos = 0;
        while let Some(rel) = region[pos..].windows(7).position(|w| w == b"/Filter") {
            let after = pos + rel + 7;
            // Reject `/FilterDecodeParms` style suffix collisions.
            if region.get(after).is_some_and(|b| b.is_ascii_alphabetic()) {
                pos = after;
                continue;
            }
            if let Some(chain) = read_filter_value(region, after) {
                if seen.insert(chain.clone()) {
                    out.push(chain);
                }
            }
            pos = after;
        }
    }
    out
}

/// Read a `/Filter` value: a single `/Name` or a `[/Name /Name …]`
/// array. Returns the chain as a comma-joined string.
fn read_filter_value(bytes: &[u8], start: usize) -> Option<String> {
    let mut cursor = start;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    match *bytes.get(cursor)? {
        b'/' => read_name(bytes, cursor + 1).map(|n| n.trim_start_matches('/').to_string()),
        b'[' => {
            cursor += 1;
            let mut names = Vec::new();
            while cursor < bytes.len() {
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                match bytes.get(cursor) {
                    Some(b']') => break,
                    Some(b'/') => {
                        if let Some(name) = read_name(bytes, cursor + 1) {
                            let trimmed = name.trim_start_matches('/').to_string();
                            cursor += 1 + trimmed.len();
                            names.push(trimmed);
                        } else {
                            return None;
                        }
                    }
                    _ => return None,
                }
            }
            if names.is_empty() {
                None
            } else {
                Some(names.join(","))
            }
        }
        _ => None,
    }
}

/// First ~200 chars of the value following an action key. Returns
/// `None` when the key is *not* used as a value-bearing dict entry
/// (e.g. `/S /URI` declares the action type; the `/URI (...)` entry
/// next to it carries the actual payload — only that second one
/// should produce an action record). Accepts `(literal)`, `<hex>`,
/// or an indirect reference `N N R`.
fn action_snippet(bytes: &[u8], start: usize) -> Option<String> {
    let mut cursor = start;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if cursor >= bytes.len() {
        return None;
    }
    match bytes[cursor] {
        b'(' => read_literal_string(bytes, cursor + 1).map(|s| truncate(&s, SNIPPET_BYTES)),
        b'<' if bytes.get(cursor + 1) != Some(&b'<') => {
            read_hex_string(bytes, cursor + 1).map(|s| truncate(&s, SNIPPET_BYTES))
        }
        b'0'..=b'9' => {
            // Indirect reference `N N R`. Emit the reference token
            // so trait authors know an indirect lookup is in use.
            let end = (cursor + 16).min(bytes.len());
            let token: String = bytes[cursor..end]
                .iter()
                .take_while(|&&b| !matches!(b, b'\n' | b'\r' | b'>' | b'/'))
                .map(|&b| b as char)
                .collect();
            let trimmed = token.trim();
            if trimmed.ends_with('R') {
                Some(trimmed.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Scan for `/Type /Filespec` records and return each
/// `(filename, size?)` pair. `filename` comes from `/UF` (Unicode)
/// when present, falling back to `/F` (legacy). `size` is the
/// `/Length` of the embedded-file stream referenced by `/EF /F
/// <id> <gen> R` — recovered by walking the dict-region index back
/// to the target object.
fn scan_embedded_files(
    bytes: &[u8],
    dict_regions: &[DictRegion],
) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    for region in dict_regions {
        let dict = &bytes[region.start..region.end];
        if !(contains_substring(dict, b"/Type /Filespec")
            || contains_substring(dict, b"/Type/Filespec"))
        {
            continue;
        }
        let name = find_info_value(dict, b"/UF").or_else(|| find_info_value(dict, b"/F"));
        let Some(filename) = name.filter(|n| !n.is_empty()) else {
            continue;
        };
        // `/EF` is an embedded-files dict: `<< /F <ref> /UF <ref> >>`.
        // Find the indirect reference and chase it.
        let size = find_ef_stream_length(dict, dict_regions, bytes);
        out.push((filename, size));
    }
    out
}

/// Pull the `/Length` (file size in bytes) of the embedded-file
/// stream referenced from a `/Filespec` dict's `/EF` entry. Walks
/// `/EF` → indirect ref → target object dict's `/Length`. Resolves
/// `/Length` itself if it's also an indirect ref (rare but legal).
fn find_ef_stream_length(
    filespec_dict: &[u8],
    dict_regions: &[DictRegion],
    bytes: &[u8],
) -> Option<u64> {
    // Locate `/EF` then the inner `/F <id> <gen> R` or
    // `/UF <id> <gen> R` reference.
    let ef_pos = filespec_dict
        .windows(3)
        .position(|w| w == b"/EF")
        .filter(|&p| {
            filespec_dict
                .get(p + 3)
                .is_some_and(|b| !b.is_ascii_alphabetic())
        })?;
    let window_end = (ef_pos + 256).min(filespec_dict.len());
    let window = &filespec_dict[ef_pos..window_end];
    let target_id = parse_indirect_ref_value(window, b"/F")
        .or_else(|| parse_indirect_ref_value(window, b"/UF"))?;
    let target = dict_regions.iter().find(|r| r.obj_id == Some(target_id))?;
    let target_dict = &bytes[target.start..target.end];
    let length_text = find_info_value(target_dict, b"/Length")?;
    if let Ok(direct) = length_text.parse::<u64>() {
        return Some(direct);
    }
    // Indirect length — try `<id> <gen> R` form.
    let length_ref = parse_indirect_ref_value(target_dict, b"/Length")?;
    let length_obj = dict_regions.iter().find(|r| r.obj_id == Some(length_ref))?;
    // The raw_value of a length-only object is the literal number;
    // strip leading whitespace and parse.
    let raw = &bytes[length_obj.start..length_obj.end];
    let digits: String = raw
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    digits.parse().ok()
}

/// Find `/key` then read the immediately-following `N M R` indirect
/// reference, returning the object id `N`. Returns `None` when the
/// key isn't present or its value isn't an indirect reference.
fn parse_indirect_ref_value(bytes: &[u8], key: &[u8]) -> Option<u32> {
    let mut cursor = 0;
    while cursor + key.len() <= bytes.len() {
        let rel = bytes[cursor..].windows(key.len()).position(|w| w == key)?;
        let abs = cursor + rel;
        let after_idx = abs + key.len();
        let after = *bytes.get(after_idx)?;
        if after.is_ascii_alphabetic() || after == b'_' {
            cursor = after_idx;
            continue;
        }
        let mut p = after_idx;
        while p < bytes.len() && bytes[p].is_ascii_whitespace() {
            p += 1;
        }
        // Expect digits, whitespace, digits, whitespace, 'R'.
        let id_start = p;
        while p < bytes.len() && bytes[p].is_ascii_digit() {
            p += 1;
        }
        if p == id_start {
            return None;
        }
        let id_text = std::str::from_utf8(&bytes[id_start..p]).ok()?;
        let id: u32 = id_text.parse().ok()?;
        while p < bytes.len() && bytes[p].is_ascii_whitespace() {
            p += 1;
        }
        let gen_start = p;
        while p < bytes.len() && bytes[p].is_ascii_digit() {
            p += 1;
        }
        if p == gen_start {
            return None;
        }
        while p < bytes.len() && bytes[p].is_ascii_whitespace() {
            p += 1;
        }
        if bytes.get(p) == Some(&b'R') {
            return Some(id);
        }
        return None;
    }
    None
}

/// One entry per object that carries a stream body. Each entry
/// records the carrier `object_id`, the filter chain, a short
/// hex `magic` of the raw stream bytes (8 bytes — enough for the
/// usual file-format signatures), and — when the chain is
/// FlateDecode and decompression succeeds — the first ~4 KB of
/// UTF-8-decodable text. Other filter chains surface filter
/// info only.
fn scan_streams(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<JsonValue> {
    const MAGIC_BYTES: usize = 8;
    const MAX_DECODED_TEXT: usize = 4096;
    let mut out = Vec::new();
    for region in dict_regions {
        let Some((s, e)) = region.stream_range else {
            continue;
        };
        if e <= s || e > bytes.len() {
            continue;
        }
        let dict = &bytes[region.start..region.end];
        let filters: Vec<String> = read_filter_value(dict, 0)
            .or_else(|| {
                // No `/Filter` at offset 0 — try locating it inside the dict.
                let mut p = 0;
                while p + 7 <= dict.len() {
                    let rel = dict[p..].windows(7).position(|w| w == b"/Filter")?;
                    let after = p + rel + 7;
                    if dict.get(after).is_some_and(|b| b.is_ascii_alphabetic()) {
                        p = after;
                        continue;
                    }
                    return read_filter_value(dict, after);
                }
                None
            })
            .map(|s| s.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        let raw = &bytes[s..e];
        let magic_hex = hex_prefix(raw, MAGIC_BYTES);

        let mut entry = serde_json::Map::new();
        if let Some(id) = region.obj_id {
            entry.insert("object_id".into(), JsonValue::Number(u64::from(id).into()));
        }
        entry.insert(
            "filters".into(),
            JsonValue::Array(filters.iter().cloned().map(JsonValue::String).collect()),
        );
        entry.insert("magic_hex".into(), JsonValue::String(magic_hex));

        if filters.len() == 1 && filters[0] == "FlateDecode" {
            if let Some(decoded) = inflate(raw) {
                let text_end = decoded.len().min(MAX_DECODED_TEXT);
                let sample = &decoded[..text_end];
                // PDF Flate streams are split roughly into two
                // kinds: text-shaped (content streams, JavaScript,
                // metadata XML — `>= 50%` printable ASCII) and
                // binary-shaped (image / font / ICC payloads).
                // We surface `decoded_text` only when the sample
                // is text-shaped so trait rules don't have to
                // wade through encoded glyph data.
                if is_mostly_printable(sample) {
                    let text = String::from_utf8_lossy(sample);
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        entry.insert(
                            "decoded_text".into(),
                            JsonValue::String(truncate(trimmed, MAX_DECODED_TEXT)),
                        );
                    }
                }
            }
        }
        out.push(JsonValue::Object(entry));
    }
    out
}

/// True when `data` is at least 50% printable ASCII (including
/// whitespace). Used to gate `decoded_text` emission on Flate
/// streams so image / font / ICC payloads don't bloat the kv
/// tree with mojibake.
fn is_mostly_printable(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| (b >= 0x20 && b < 0x7f) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    (printable * 2) >= data.len()
}

/// First `n` bytes of `data` rendered as lowercase hex with no
/// separator. Used as the `magic_hex` content sniff on stream
/// bodies.
fn hex_prefix(data: &[u8], n: usize) -> String {
    let end = data.len().min(n);
    let mut s = String::with_capacity(end * 2);
    for &b in &data[..end] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Collect AcroForm widget fields. Each entry surfaces the
/// `name` (`/T`), `field_type` (`/FT` — `Tx` for text, `Btn` for
/// button, `Ch` for choice, `Sig` for signature), the bounding
/// `rect` (`/Rect [...]`), and the field's `value` (`/V`) when
/// set. We don't follow indirect `/V` refs through to streams;
/// that's a future xref expansion when needed.
fn scan_form_fields(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for region in dict_regions {
        let dict = &bytes[region.start..region.end];
        let has_widget = contains_substring(dict, b"/Subtype /Widget")
            || contains_substring(dict, b"/Subtype/Widget");
        // Field dicts that aren't direct widgets but carry `/FT`
        // (the parent of a Widget) also count — `/FT` is the
        // canonical indicator that this is a form field record.
        let field_type = find_info_value(dict, b"/FT");
        if !has_widget && field_type.is_none() {
            continue;
        }
        let mut entry = serde_json::Map::new();
        if let Some(id) = region.obj_id {
            entry.insert("object_id".into(), JsonValue::Number(u64::from(id).into()));
        }
        if let Some(name) = find_info_value(dict, b"/T") {
            entry.insert("name".into(), JsonValue::String(name));
        }
        if let Some(ft) = field_type {
            entry.insert(
                "field_type".into(),
                JsonValue::String(ft.trim_start_matches('/').to_string()),
            );
        }
        if let Some(rect) = find_rect_value(dict, b"/Rect") {
            entry.insert("rect".into(), JsonValue::String(rect));
        }
        if let Some(val) = find_info_value(dict, b"/V") {
            entry.insert("value".into(), JsonValue::String(truncate(&val, 200)));
        }
        if !entry.is_empty() {
            out.push(JsonValue::Object(entry));
        }
    }
    out
}

/// Read a `/Rect [a b c d]` array as a single space-joined
/// string. Numbers can be int or float; we don't reformat them.
fn find_rect_value(bytes: &[u8], key: &[u8]) -> Option<String> {
    let pos = bytes.windows(key.len()).position(|w| w == key)?;
    let after_idx = pos + key.len();
    if bytes
        .get(after_idx)
        .is_some_and(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let mut cursor = after_idx;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'[') {
        return None;
    }
    let end = cursor + bytes[cursor..].iter().position(|&b| b == b']')?;
    let inner = std::str::from_utf8(&bytes[cursor + 1..end]).ok()?;
    Some(inner.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Decode a FlateDecode stream into a bounded buffer. Caps the
/// inflated output at 1 MiB so adversarial zip-bombs can't blow
/// memory. Returns `None` on decode failure.
fn inflate(input: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    const MAX_DECODED: usize = 1 << 20;
    let mut decoder = ZlibDecoder::new(input).take(MAX_DECODED as u64);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Substring count using a simple sliding window. Fast enough on
/// the file sizes we care about; replace with `memmem` if profiles
/// flag it.
fn count_substring(bytes: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || bytes.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn contains_substring(bytes: &[u8], needle: &[u8]) -> bool {
    count_substring(bytes, needle) > 0
}

/// Count `/Type /<name>` dictionary tags. The PDF spec allows
/// whitespace between the slash-name keys (`/Type /Page`) but
/// many producers concatenate them (`/Type/Page`); both forms
/// count. Also rejects partial-name false positives (`/Page` vs
/// `/Pages`).
fn count_type_occurrences(bytes: &[u8], name: &[u8]) -> usize {
    let with_space = {
        let mut v = Vec::with_capacity(7 + name.len());
        v.extend_from_slice(b"/Type ");
        v.extend_from_slice(name);
        v
    };
    let joined = {
        let mut v = Vec::with_capacity(5 + name.len());
        v.extend_from_slice(b"/Type");
        v.extend_from_slice(name);
        v
    };
    [with_space.as_slice(), joined.as_slice()]
        .iter()
        .map(|needle| {
            let mut count = 0;
            let mut i = 0;
            while i + needle.len() <= bytes.len() {
                if &bytes[i..i + needle.len()] == *needle {
                    let after = bytes.get(i + needle.len()).copied().unwrap_or(b' ');
                    if !is_name_char(after) {
                        count += 1;
                    }
                    i += needle.len();
                } else {
                    i += 1;
                }
            }
            count
        })
        .sum()
}

/// Whole-token count — requires the match to be followed by a
/// non-name character (whitespace, delimiter, paren, etc.) so
/// `obj` doesn't match `objstm` and `endobj` doesn't double-count.
fn count_token(bytes: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || bytes.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let after_idx = i + needle.len();
            let after = bytes.get(after_idx).copied().unwrap_or(b' ');
            let before = if i == 0 { b' ' } else { bytes[i - 1] };
            if !is_name_char(after) && !is_name_char(before) {
                count += 1;
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn contains_token(bytes: &[u8], needle: &[u8]) -> bool {
    count_token(bytes, needle) > 0
}

/// `/AA` is two letters; raw substring scan would hit `AAAa…`-style
/// random binary. Require both a leading non-name byte and a
/// trailing non-alpha to confirm it's a real `/AA` action key.
fn contains_keyword(bytes: &[u8], needle: &[u8]) -> bool {
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let after = bytes.get(i + needle.len()).copied().unwrap_or(b' ');
            if !after.is_ascii_alphabetic() && after != b'_' {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_pdf(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
    }

    #[test]
    fn parses_version_from_header() {
        let pdf = b"%PDF-1.7\n%%EOF\n";
        let (v, m) = extract_pdf(pdf);
        assert_eq!(
            v.get("pdf.header.version").and_then(|x| x.as_str()),
            Some("1.7")
        );
        assert_eq!(m.get("pdf.header_count"), Some(1.0));
        assert_eq!(m.get("pdf.eof_count"), Some(1.0));
    }

    #[test]
    fn extracts_info_title() {
        let pdf = b"%PDF-1.4\n4 0 obj << /Title (Hello World) /Producer (test) >> endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        assert_eq!(
            v.get("pdf.info.title").and_then(|x| x.as_str()),
            Some("Hello World")
        );
        assert_eq!(
            v.get("pdf.info.producer").and_then(|x| x.as_str()),
            Some("test")
        );
    }

    #[test]
    fn detects_javascript_action_count() {
        let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS (app.alert('hi')) >> endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        // The expose extractor reports the count via metrics —
        // the action-detail array stays with cleave's PDF parser.
        assert_eq!(m.get("pdf.action_count"), Some(1.0));
    }

    #[test]
    fn flags_encrypt_and_linearized() {
        let pdf = b"%PDF-1.7\n<< /Linearized 1 /Encrypt 7 0 R >>\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let flags = v
            .get("pdf.shape.flags")
            .and_then(|x| x.as_array())
            .unwrap();
        let strings: Vec<&str> = flags.iter().filter_map(|x| x.as_str()).collect();
        assert!(strings.contains(&"encrypted"));
        assert!(strings.contains(&"linearized"));
    }

    #[test]
    fn catalog_acroform_xfa() {
        let pdf = b"%PDF-1.4\n<< /AcroForm << /XFA [1 0 R] >> >>\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let features = v
            .get("pdf.catalog.features")
            .and_then(|x| x.as_array())
            .unwrap();
        let strings: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(strings.contains(&"acroform"));
        assert!(strings.contains(&"xfa"));
    }

    #[test]
    fn stacked_pdf_headers_counted() {
        let pdf = b"%PDF-1.4\nfoo\n%PDF-1.7\nbar\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.header_count"), Some(2.0));
    }

    #[test]
    fn extracts_filter_chain() {
        let pdf = b"%PDF-1.4\n7 0 obj << /Filter /FlateDecode /Length 0 >> stream\nendstream endobj\n8 0 obj << /Filter [/ASCIIHexDecode /FlateDecode] /Length 0 >> stream\nendstream endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let chains = v.get("pdf.filter_chains").and_then(|x| x.as_array()).unwrap();
        let strings: Vec<&str> = chains.iter().filter_map(|x| x.as_str()).collect();
        assert!(strings.contains(&"FlateDecode"));
        assert!(strings.contains(&"ASCIIHexDecode,FlateDecode"));
    }

    #[test]
    fn extracts_form_field() {
        let pdf = b"%PDF-1.4\n9 0 obj << /Type /Annot /Subtype /Widget /T (username) /FT /Tx /Rect [10 20 100 40] /V (alice) >> endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let fields = v.get("pdf.form_fields").and_then(|x| x.as_array()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0]["name"].as_str(), Some("username"));
        assert_eq!(fields[0]["field_type"].as_str(), Some("Tx"));
        assert_eq!(fields[0]["rect"].as_str(), Some("10 20 100 40"));
        assert_eq!(fields[0]["value"].as_str(), Some("alice"));
    }

    #[test]
    fn extracts_embedded_file_with_size() {
        // Filespec object references stream object 11; stream object
        // declares `/Length 42`.
        let pdf = b"%PDF-1.4\n10 0 obj << /Type /Filespec /F (attachment.txt) /EF << /F 11 0 R >> >> endobj\n11 0 obj << /Length 42 /Type /EmbeddedFile >> stream\nXXX endstream endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let files = v.get("pdf.embedded_files").and_then(|x| x.as_array()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"].as_str(), Some("attachment.txt"));
        assert_eq!(files[0]["size"].as_u64(), Some(42));
    }

    #[test]
    fn no_header_is_silent() {
        let bytes = b"not a PDF";
        let (v, m) = extract_pdf(bytes);
        assert!(v.get("pdf.header.version").is_none());
        assert!(m.get("pdf.header_count").is_none());
    }
}
