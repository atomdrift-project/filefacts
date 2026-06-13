//! PDF extractor.
//!
//! Lenient byte-scan parser — no cross-reference resolution, no
//! stream decryption, no object-graph reconstruction. Malicious
//! PDFs routinely break those features to evade strict parsers, so
//! we surface forensic facts (action presence, embedded files,
//! catalog flags) by recognizing the canonical PDF tokens directly
//! in the raw bytes.
//!
//! Schema namespaces under `pdf.*` matching filefacts' per-format
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

use serde_json::{Value as JsonValue, json};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, hex_nibble};
use crate::output::{Metrics, Strings, Values};

/// Cap on the snippet text we surface per action. Long JavaScript
/// payloads exist in malicious PDFs but the *first* few hundred
/// bytes contain the recognizable invocation patterns analysts
/// want; the rest is obfuscated runtime. Matches cleave's cap.
const SNIPPET_BYTES: usize = 200;

/// Upper bound on how many `<id> <gen> obj` dict regions we collect
/// from a single PDF. Adversarial inputs can stuff millions of
/// skeleton objects to amplify every downstream pass. Real-world
/// PDFs hold a few thousand objects; cap with comfortable headroom
/// and surface a metric so trait rules can spot truncation.
const MAX_DICT_REGIONS: usize = 50_000;

/// Upper bound on how many form-field rects we run the O(n²)
/// overlap check across. Real PDFs hold a handful per page; with
/// thousands of widgets the pairwise pass dominates parse time.
const MAX_OVERLAP_RECTS: usize = 2_000;

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
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
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
                shape_flags
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    // `/Type /Name` style counts — each is the number of object
    // dictionaries whose `/Type` key is the named role. Matches
    // both whitespace-separated and joined-token forms emitted by
    // various PDF producers. Every count is mirrored into the flat
    // metric map so trait rules resolve `field: pdf.<count>`
    // without a kv round-trip.
    let counts: &[(&str, &str, &str)] = &[
        ("page_count", "/Page", "pdf.page_count"),
        ("annotation_count", "/Annot", "pdf.annotation_count"),
        ("xobject_count", "/XObject", "pdf.xobject_count"),
        ("font_count", "/Font", "pdf.font_count"),
        ("metadata_count", "/Metadata", "pdf.metadata_count"),
        ("objstm_count", "/ObjStm", "pdf.objstm_count"),
        ("xref_stream_count", "/XRef", "pdf.xref_stream_count"),
        (
            "signature_object_count",
            "/Sig",
            "pdf.signature_object_count",
        ),
    ];
    let mut page_count_value: u32 = 0;
    let mut annotation_count_value: u32 = 0;
    for (kv_key, name, metric_key) in counts {
        let c = count_type_occurrences(bytes, name.as_bytes());
        if c > 0 {
            shape.insert((*kv_key).into(), json!(c));
            metrics.insert((*metric_key).to_string(), c as f64);
        }
        if *kv_key == "page_count" {
            page_count_value = c as u32;
        }
        if *kv_key == "annotation_count" {
            annotation_count_value = c as u32;
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
        metrics.insert("pdf.three_d_object_count", three_d as f64);
    }
    // `visible_object_count` — objects recovered from the linear
    // byte scan (not from object-stream expansion). Equal to
    // `pdf.object_count` since this extractor does not yet decode
    // ObjStm entries into the dict-region list. Surfacing both
    // keys keeps the trait field schema stable and lets a future
    // ObjStm expansion bump `object_count` without rewriting rules.
    metrics.insert(
        "pdf.visible_object_count",
        obj_count.min(endobj_count) as f64,
    );
    // Trailing bytes after the *last* `%%EOF` marker — a common
    // padding pattern in malicious PDFs that smuggle a payload past
    // the parser. Counted relative to the last EOF only; multiple
    // EOFs are normal in incrementally-updated documents.
    let trailing_bytes = trailing_bytes_after_last_eof(bytes);
    if trailing_bytes > 0 {
        metrics.insert("pdf.trailing_bytes_after_eof", trailing_bytes as f64);
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
    if dict_regions.len() >= MAX_DICT_REGIONS {
        // Signal to trait rules that the object-graph scan stopped
        // early. The cap is a DoS guard, not a sizing heuristic, so
        // anything that hits it is well outside the real-world range.
        metrics.insert("pdf.dict_region_truncated", 1.0);
    }
    let actions = scan_actions(bytes, &dict_regions);
    let uri_action_count = action_count_by_kind(&actions, "uri");
    let javascript_action_count = action_count_by_kind(&actions, "javascript");
    if !actions.is_empty() {
        metrics.insert("pdf.action_count", actions.len() as f64);
        values.insert("pdf.actions", JsonValue::Array(actions));
    }
    if javascript_action_count > 0 {
        metrics.insert(
            "pdf.javascript_action_count",
            f64::from(javascript_action_count),
        );
    }
    if uri_action_count > 0 {
        metrics.insert("pdf.uri_action_count", f64::from(uri_action_count));
    }

    // Full-content JavaScript payloads — one entry per `/JS` site
    // resolved end-to-end (inline literals, hex strings, and indirect
    // references followed into Flate-compressed streams). Distinct
    // from `pdf.actions[]`, which keeps a short truncated snippet for
    // at-a-glance triage. Downstream consumers (cleave's PDF
    // sub-file analyzer) re-extract each entry as a virtual JS
    // sub-file at depth 1 so JavaScript-specific traits match
    // against the actual code rather than just the metadata count.
    let js_payloads = scan_javascript_payloads(bytes, &dict_regions);
    if !js_payloads.is_empty() {
        let total_bytes: u64 = js_payloads
            .iter()
            .filter_map(|v| v.as_object())
            .filter_map(|o| o.get("content_bytes").and_then(JsonValue::as_u64))
            .sum();
        metrics.insert("pdf.javascript_count", js_payloads.len() as f64);
        metrics.insert("pdf.javascript_total_bytes", total_bytes as f64);
        values.insert("pdf.javascript", JsonValue::Array(js_payloads));
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
        metrics.insert("pdf.form_field_count", form_fields.len() as f64);
    }
    derive_form_field_metrics(&form_fields, metrics);
    if !form_fields.is_empty() {
        values.insert("pdf.form_fields", JsonValue::Array(form_fields));
    }

    // Per-page ratios — number of annotations / URI actions per
    // page. Surfacing these as derived metrics keeps trait rules
    // shape-agnostic: a one-page PDF with 30 URI annotations and a
    // thirty-page PDF with one URI annotation per page produce the
    // same `uri_actions_per_page = 1.0` rather than two unrelated
    // raw counts. Zero pages → zero ratio (rather than NaN).
    if page_count_value > 0 {
        metrics.insert(
            "pdf.annotations_per_page",
            f64::from(annotation_count_value) / f64::from(page_count_value),
        );
        if uri_action_count > 0 {
            metrics.insert(
                "pdf.uri_actions_per_page",
                f64::from(uri_action_count) / f64::from(page_count_value),
            );
        }
    }

    // Object stream inner-object count — the number of indirect
    // objects packed into `/Type /ObjStm` streams. Each ObjStm
    // carries an `/N` count plus a header table of `(id, offset)`
    // pairs; we sum `/N` across every ObjStm we can locate (no
    // decompression needed, the count is a dict field).
    let obj_stream_inner = scan_object_stream_inner_count(bytes, &dict_regions);
    if obj_stream_inner > 0 {
        metrics.insert(
            "pdf.object_stream_inner_object_count",
            f64::from(obj_stream_inner),
        );
    }

    // Unreferenced object count — objects whose id never appears
    // as the target of an `<id> <gen> R` reference. Pure-orphan
    // counts are a structural shape indicator (legitimate PDFs
    // generally reference all their objects through the catalog
    // graph).
    let unreferenced = unreferenced_object_count(bytes, &dict_regions);
    if unreferenced > 0 {
        metrics.insert("pdf.unreferenced_object_count", f64::from(unreferenced));
    }

    // Unusual filters — JBIG2, LZW, and Crypt. Each pulls in a
    // historically exploitable decoder path (CVE-2010-1297 et al).
    // Counts the number of objects with at least one unusual
    // filter in the chain, not the number of filter declarations.
    let unusual = streams_with_unusual_filter_count(bytes, &dict_regions);
    if unusual > 0 {
        metrics.insert("pdf.streams_with_unusual_filter_count", f64::from(unusual));
    }

    // Phase 1B derived metrics — formerly computed by cleave's
    // pdf::parser. Now reachable through the metric-fold adapter
    // (`merge_filefacts_metrics`) so trait rules using `field: pdf.X`
    // resolve against filefacts' flat metric map.
    let leading_bytes = bytes.windows(5).position(|w| w == b"%PDF-").unwrap_or(0);
    metrics.insert("pdf.leading_bytes_before_header", leading_bytes as f64);
    let sig_count = count_type_occurrences(bytes, b"/Sig") + count_substring(bytes, b"/Type /Sig");
    metrics.insert("pdf.signature_object_count", (sig_count / 2) as f64);
    // Signed incremental update: incremental updates leave more than
    // one `%%EOF` marker; pair that with the presence of a signature
    // object to count signed-then-modified PDFs (the classic
    // shadow-attack shape).
    if sig_count > 0 {
        let signed_incremental = if eof_count > 1 {
            eof_count.saturating_sub(1)
        } else {
            0
        };
        metrics.insert(
            "pdf.signed_incremental_update_count",
            signed_incremental as f64,
        );
    }
    derive_stream_metrics(bytes, &dict_regions, metrics);
    derive_risky_feature_score(values, metrics);

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
        while value_pos < bytes.len() && (bytes[value_pos] == b' ' || bytes[value_pos] == b'\t') {
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

/// PDF names start with `/` and continue with regular characters
/// until whitespace or a delimiter.
fn read_name(bytes: &[u8], start: usize) -> Option<String> {
    let end = bytes[start..]
        .iter()
        .position(|&b| {
            matches!(
                b,
                b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'<' | b'>' | b'[' | b']' | b'('
            )
        })
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
/// body was present, the stream byte range too. Output is capped
/// at [`MAX_DICT_REGIONS`] entries — adversarial inputs that stuff
/// millions of skeleton objects would otherwise turn every
/// downstream pass into a quadratic walk.
fn collect_dict_regions(bytes: &[u8]) -> Vec<DictRegion> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if out.len() >= MAX_DICT_REGIONS {
            break;
        }
        let Some(rel) = bytes[pos..].windows(3).position(|w| w == b"obj") else {
            break;
        };
        let obj_pos = pos + rel;
        // Require whole-token: the byte before `obj` must be
        // whitespace and the byte after must not be a name char
        // (avoids matching `endobj`, `objstm`, etc.).
        let before = if obj_pos == 0 {
            b' '
        } else {
            bytes[obj_pos - 1]
        };
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
        let stream_range = if let (Some(s), Some(e)) = (stream_end_marker, endobj_end) {
            if s < e {
                // Skip past `stream` + optional CR/LF.
                let mut body_start = s + b"stream".len();
                if bytes.get(body_start) == Some(&b'\r') {
                    body_start += 1;
                }
                if bytes.get(body_start) == Some(&b'\n') {
                    body_start += 1;
                }
                let dict = &bytes[dict_start..dict_end];
                let body_end = match classify_stream_length(dict) {
                    LengthValue::Direct(n) => declared_stream_end(bytes, body_start, n)
                        .unwrap_or_else(|| fallback_stream_end(bytes, body_start, e)),
                    _ => fallback_stream_end(bytes, body_start, e),
                };
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
        let rel = bytes[pos..]
            .windows(needle.len())
            .position(|w| w == needle)?;
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

/// Return the stream body end implied by a direct `/Length`, but only
/// when `endstream` sits exactly at that boundary. PDF writers
/// normally put an EOL before `endstream`, but real generated PDFs may
/// omit it; in that case compressed body bytes can end with a name
/// character and form raw byte strings such as `sendstream`. A whole
/// token scan misses those valid boundaries, so prefer the declared
/// length when it is self-consistent.
fn declared_stream_end(bytes: &[u8], body_start: usize, declared: u64) -> Option<usize> {
    let declared = usize::try_from(declared).ok()?;
    let body_end = body_start.checked_add(declared)?;
    if body_end > bytes.len() {
        return None;
    }
    let mut marker = body_end;
    if bytes.get(marker) == Some(&b'\r') {
        marker += 1;
    }
    if bytes.get(marker) == Some(&b'\n') {
        marker += 1;
    }
    bytes
        .get(marker..marker.saturating_add(b"endstream".len()))
        .filter(|w| *w == b"endstream")
        .map(|_| body_end)
}

fn fallback_stream_end(bytes: &[u8], body_start: usize, object_end: usize) -> usize {
    let endstream = find_token_after(bytes, body_start, b"endstream").unwrap_or(object_end);
    // Trim a single trailing CR/LF before `endstream`.
    let mut body_end = endstream;
    if body_end > body_start && bytes[body_end - 1] == b'\n' {
        body_end -= 1;
    }
    if body_end > body_start && bytes[body_end - 1] == b'\r' {
        body_end -= 1;
    }
    body_end
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
        let DictRegion {
            start, end, obj_id, ..
        } = *region_info;
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
            while let Some(rel) = region[pos..]
                .windows(needle.len())
                .position(|w| w == *needle)
            {
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

/// Walk every `/JS` site and resolve it to its full byte content —
/// inline literals (`/JS (var x=1;)`), hex strings (`/JS <76617220...>`),
/// and indirect references (`/JS 42 0 R`) that point at a string or
/// stream object. FlateDecode-encoded streams are inflated. Distinct
/// from [`scan_actions`], which records each site with a 200-byte
/// snippet for at-a-glance triage; here we want the *whole* payload so
/// downstream tools can treat each JS blob as a virtual sub-file.
///
/// Returns one entry per site with `{source, target_object_id?,
/// filters?, content, content_bytes}`. `target_object_id` is set when
/// the site referenced another object (so consumers can map the JS
/// payload back to a specific object id); `filters` records the
/// stream's filter chain when the payload was decoded from a stream.
fn scan_javascript_payloads(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<JsonValue> {
    // Lookup table for indirect-ref resolution. PDFs with multiple
    // generations of the same object id are rare in malicious samples
    // and we accept the last-wins behavior here (matches how the rest
    // of the extractor handles incremental updates).
    let mut by_id: std::collections::HashMap<u32, &DictRegion> =
        std::collections::HashMap::with_capacity(dict_regions.len());
    for r in dict_regions {
        if let Some(id) = r.obj_id {
            by_id.insert(id, r);
        }
    }

    let mut out = Vec::new();
    for region in dict_regions {
        let DictRegion {
            start, end, obj_id, ..
        } = *region;
        if end <= start {
            continue;
        }
        let dict = &bytes[start..end];
        let mut pos = 0;
        while let Some(rel) = dict[pos..].windows(3).position(|w| w == b"/JS") {
            let abs = pos + rel;
            let next = abs + 3;
            // Reject /JSON, /JavaScript (the *name*, not the key form).
            if next < dict.len() && dict[next].is_ascii_alphabetic() {
                pos = next;
                continue;
            }
            if let Some(payload) = resolve_js_value(bytes, dict, next, &by_id) {
                let mut entry = serde_json::Map::new();
                entry.insert(
                    "source".into(),
                    JsonValue::String(match obj_id {
                        Some(id) => format!("object:{id}"),
                        None => "object:unknown".to_string(),
                    }),
                );
                if let Some(target) = payload.target_object_id {
                    entry.insert(
                        "target_object_id".into(),
                        JsonValue::Number(u64::from(target).into()),
                    );
                }
                if !payload.filters.is_empty() {
                    entry.insert(
                        "filters".into(),
                        JsonValue::Array(
                            payload.filters.into_iter().map(JsonValue::String).collect(),
                        ),
                    );
                }
                entry.insert(
                    "content_bytes".into(),
                    JsonValue::Number((payload.content.len() as u64).into()),
                );
                entry.insert("content".into(), JsonValue::String(payload.content));
                out.push(JsonValue::Object(entry));
            }
            pos = next;
        }
    }
    out
}

struct JsPayload {
    target_object_id: Option<u32>,
    filters: Vec<String>,
    content: String,
}

/// Resolve the value sitting after a `/JS` key in `dict` (slice
/// relative to the object's dict region). Walks across object
/// boundaries for indirect references — string objects come back
/// inline; stream objects come back inflated (FlateDecode) or raw
/// (no filter).
fn resolve_js_value(
    bytes: &[u8],
    dict: &[u8],
    after_js_key: usize,
    by_id: &std::collections::HashMap<u32, &DictRegion>,
) -> Option<JsPayload> {
    let mut cursor = after_js_key;
    while cursor < dict.len() && dict[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let first = *dict.get(cursor)?;
    match first {
        b'(' => {
            let content = read_literal_string(dict, cursor + 1)?;
            Some(JsPayload {
                target_object_id: None,
                filters: Vec::new(),
                content,
            })
        }
        b'<' if dict.get(cursor + 1) != Some(&b'<') => {
            let content = read_hex_string(dict, cursor + 1)?;
            Some(JsPayload {
                target_object_id: None,
                filters: Vec::new(),
                content,
            })
        }
        b'0'..=b'9' => resolve_indirect_js(bytes, dict, cursor, by_id),
        _ => None,
    }
}

/// Parse an `N G R` indirect reference at `dict[cursor..]` and dereference
/// it through `by_id` to recover the underlying string- or stream-object's
/// content.
fn resolve_indirect_js(
    bytes: &[u8],
    dict: &[u8],
    cursor: usize,
    by_id: &std::collections::HashMap<u32, &DictRegion>,
) -> Option<JsPayload> {
    let end = (cursor + 32).min(dict.len());
    let token: String = dict[cursor..end]
        .iter()
        .take_while(|&&b| !matches!(b, b'\n' | b'\r' | b'>' | b'/' | b'('))
        .map(|&b| b as char)
        .collect();
    let trimmed = token.trim();
    if !trimmed.ends_with('R') {
        return None;
    }
    let mut parts = trimmed[..trimmed.len() - 1].split_whitespace();
    let target_id: u32 = parts.next()?.parse().ok()?;
    let _gen: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let target = by_id.get(&target_id).copied()?;

    // Two shapes — a stream object (most common for /JS, since JS
    // blobs are bigger than a string-literal-friendly size) or a
    // bare string object. Try stream first.
    if let Some((s, e)) = target.stream_range {
        if e > s && e <= bytes.len() {
            let target_dict = &bytes[target.start..target.end];
            let filters = read_object_filters(target_dict);
            let raw = &bytes[s..e];
            let decoded: Option<Vec<u8>> = match filters.as_slice() {
                [] => Some(raw.to_vec()),
                [single] if single == "FlateDecode" => inflate(raw),
                _ => None, // skip unusual filter chains; out of scope for now
            };
            if let Some(decoded) = decoded {
                // Surface as a string. `String::from_utf8_lossy` so
                // any embedded shellcode bytes survive as `U+FFFD`
                // rather than throwing the whole payload away — the
                // downstream JS parser sees the same UTF-8 it would
                // see opening the PDF in a viewer that ignores the
                // odd byte.
                return Some(JsPayload {
                    target_object_id: Some(target_id),
                    filters,
                    content: String::from_utf8_lossy(&decoded).into_owned(),
                });
            }
        }
    }
    // String-object fallback — the target dict region may just be a
    // bare `(literal)` or `<hex>` string instead of an actual dict.
    let target_dict = &bytes[target.start..target.end];
    let mut p = 0;
    while p < target_dict.len() && target_dict[p].is_ascii_whitespace() {
        p += 1;
    }
    match target_dict.get(p) {
        Some(&b'(') => Some(JsPayload {
            target_object_id: Some(target_id),
            filters: Vec::new(),
            content: read_literal_string(target_dict, p + 1)?,
        }),
        Some(&b'<') if target_dict.get(p + 1) != Some(&b'<') => Some(JsPayload {
            target_object_id: Some(target_id),
            filters: Vec::new(),
            content: read_hex_string(target_dict, p + 1)?,
        }),
        _ => None,
    }
}

/// Pull the `/Filter` chain out of an object's dict, returning a
/// `Vec` of name strings (no leading slash). `/FilterDecodeParms` and
/// other name-suffix collisions are rejected via whole-token match.
fn read_object_filters(dict: &[u8]) -> Vec<String> {
    let mut p = 0;
    while p + 7 <= dict.len() {
        let Some(rel) = dict[p..].windows(7).position(|w| w == b"/Filter") else {
            return Vec::new();
        };
        let after = p + rel + 7;
        if dict.get(after).is_some_and(|b| b.is_ascii_alphabetic()) {
            p = after;
            continue;
        }
        return read_filter_value(dict, after)
            .map(|s| s.split(',').map(str::to_string).collect())
            .unwrap_or_default();
    }
    Vec::new()
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

/// Count action entries from `scan_actions` whose `kind` matches.
/// Used to surface `pdf.javascript_action_count` and
/// `pdf.uri_action_count` from the same action table the kv view
/// emits — single source of truth, no separate substring scan.
fn action_count_by_kind(actions: &[JsonValue], kind: &str) -> u32 {
    actions
        .iter()
        .filter(|a| {
            a.as_object()
                .and_then(|o| o.get("kind"))
                .and_then(JsonValue::as_str)
                == Some(kind)
        })
        .count() as u32
}

/// Trailing bytes after the *last* `%%EOF` marker. Malicious PDFs
/// commonly append a payload past the canonical end marker; this
/// surfaces the length of that tail so trait rules can flag it.
fn trailing_bytes_after_last_eof(bytes: &[u8]) -> usize {
    let needle = b"%%EOF";
    let mut last_end = None;
    let mut cursor = 0;
    while cursor + needle.len() <= bytes.len() {
        let Some(rel) = bytes[cursor..]
            .windows(needle.len())
            .position(|w| w == needle)
        else {
            break;
        };
        let abs = cursor + rel;
        last_end = Some(abs + needle.len());
        cursor = abs + needle.len();
    }
    last_end
        .map(|end| bytes.len().saturating_sub(end))
        .unwrap_or(0)
}

/// Sum the declared `/N` count across every `/Type /ObjStm` object
/// stream. An object stream packs multiple indirect objects into a
/// single compressed body; `/N` is the spec-mandated header field
/// stating how many objects live inside. We trust the declared
/// count rather than decompressing because the count is a
/// trait-shape indicator and decompression is expensive.
fn scan_object_stream_inner_count(bytes: &[u8], dict_regions: &[DictRegion]) -> u32 {
    let mut total: u32 = 0;
    for region in dict_regions {
        if region.end <= region.start {
            continue;
        }
        let dict = &bytes[region.start..region.end];
        let is_objstm =
            contains_substring(dict, b"/Type /ObjStm") || contains_substring(dict, b"/Type/ObjStm");
        if !is_objstm {
            continue;
        }
        if let Some(n_text) = find_info_value(dict, b"/N") {
            if let Ok(n) = n_text.trim().parse::<u32>() {
                total = total.saturating_add(n);
            }
        }
    }
    total
}

/// Count object ids that are never referenced from any dict in the
/// document. Walks every dict for `<id> <gen> R` triples and
/// subtracts the reference set from the id set. Pure-orphan objects
/// don't participate in the catalog graph — a structural anomaly.
fn unreferenced_object_count(bytes: &[u8], dict_regions: &[DictRegion]) -> u32 {
    use std::collections::BTreeSet;
    let mut ids: BTreeSet<u32> = BTreeSet::new();
    let mut refs: BTreeSet<u32> = BTreeSet::new();
    for region in dict_regions {
        if let Some(id) = region.obj_id {
            ids.insert(id);
        }
        let dict = &bytes[region.start..region.end];
        collect_indirect_refs(dict, &mut refs);
    }
    if ids.is_empty() {
        return 0;
    }
    ids.difference(&refs).count() as u32
}

/// Scan an arbitrary byte slice for `<id> <gen> R` indirect-ref
/// tokens and record the referenced ids. Array brackets and other
/// delimiters are treated as token separators so `[2 0 R]` and
/// `12 0 R` both contribute.
fn collect_indirect_refs(slice: &[u8], refs: &mut std::collections::BTreeSet<u32>) {
    let text = String::from_utf8_lossy(slice);
    // Treat any non-ASCII-alphanumeric byte as a separator. PDF
    // delimiter characters (`[`, `]`, `<`, `>`, `(`, `)`, `/`) all
    // split tokens, as does whitespace. The `R` ref marker is a
    // single ASCII char that survives this split intact.
    let tokens: Vec<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    for window in tokens.windows(3) {
        if window[2] == "R" {
            if let Ok(id) = window[0].parse::<u32>() {
                refs.insert(id);
            }
        }
    }
}

/// Count objects whose stream filter chain includes a historically
/// exploitable decoder (JBIG2, LZW, Crypt). One match per object —
/// chains with multiple unusual filters still count once, so the
/// metric tracks "number of streams that pull in a risky decoder"
/// rather than the raw filter-name occurrence count.
fn streams_with_unusual_filter_count(bytes: &[u8], dict_regions: &[DictRegion]) -> u32 {
    let mut count: u32 = 0;
    for region in dict_regions {
        if region.stream_range.is_none() {
            continue;
        }
        let dict = &bytes[region.start..region.end];
        let Some(chain) = find_filter_in_dict(dict) else {
            continue;
        };
        if chain
            .split(',')
            .any(|f| matches!(f, "JBIG2Decode" | "JBIG2" | "LZWDecode" | "LZW" | "Crypt"))
        {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Locate the `/Filter` value inside a dict slice. Returns the
/// comma-joined chain (single name or array form). Used by the
/// unusual-filter sweep so we don't repeat `scan_filter_chains`'s
/// dedup-aware walk for this dictionary-local check.
fn find_filter_in_dict(dict: &[u8]) -> Option<String> {
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
}

/// Scan for `/Type /Filespec` records and return each
/// `(filename, size?)` pair. `filename` comes from `/UF` (Unicode)
/// when present, falling back to `/F` (legacy). `size` is the
/// `/Length` of the embedded-file stream referenced by `/EF /F
/// <id> <gen> R` — recovered by walking the dict-region index back
/// to the target object.
fn scan_embedded_files(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<(String, Option<u64>)> {
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

/// Non-overlapping substring count via the `memchr` SIMD-accelerated
/// `memmem` searcher. Roughly an order of magnitude faster than the
/// hand-rolled sliding window we used previously, and the worst-case
/// cost on adversarial inputs (long near-matches that repeatedly
/// reset a naive scan) stays linear.
#[must_use]
fn count_substring(bytes: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || bytes.len() < needle.len() {
        return 0;
    }
    memchr::memmem::find_iter(bytes, needle).count()
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
#[must_use]
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

/// Derive form-field metrics from the already-parsed `pdf.form_fields[]`
/// array: hidden-zero-rect count, duplicate-name / duplicate-rect /
/// duplicate-name-and-rect counts, overlapping-pair count, and
/// max-decoded-value length. These were the cleave-only PDF metrics
/// that previously kept `pdf::parser` alive.
fn derive_form_field_metrics(fields: &[JsonValue], metrics: &mut Metrics) {
    if fields.is_empty() {
        return;
    }
    use std::collections::HashMap;
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut by_rect: HashMap<String, usize> = HashMap::new();
    let mut by_name_rect: HashMap<(String, String), usize> = HashMap::new();
    let mut hidden_zero_rect = 0_u32;
    let mut max_decoded_len = 0_usize;
    let mut rects: Vec<[f64; 4]> = Vec::with_capacity(fields.len());

    for f in fields {
        let obj = f.as_object();
        let name = obj
            .and_then(|o| o.get("name"))
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let rect = obj
            .and_then(|o| o.get("rect"))
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let value = obj
            .and_then(|o| o.get("value"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if !name.is_empty() {
            *by_name.entry(name.clone()).or_insert(0) += 1;
        }
        if !rect.is_empty() {
            *by_rect.entry(rect.clone()).or_insert(0) += 1;
        }
        if !name.is_empty() && !rect.is_empty() {
            *by_name_rect
                .entry((name.clone(), rect.clone()))
                .or_insert(0) += 1;
        }
        if let Some(r) = parse_rect(&rect) {
            if r == [0.0, 0.0, 0.0, 0.0] {
                hidden_zero_rect += 1;
            }
            rects.push(r);
        }
        max_decoded_len = max_decoded_len.max(value.len());
    }

    // Duplicate counts: every key with count > 1 contributes
    // `count - 1` to the "extra occurrences" total.
    let dup = |map: &HashMap<String, usize>| -> u32 {
        map.values()
            .filter(|&&c| c > 1)
            .map(|&c| (c - 1) as u32)
            .sum()
    };
    let dup_pair = |map: &HashMap<(String, String), usize>| -> u32 {
        map.values()
            .filter(|&&c| c > 1)
            .map(|&c| (c - 1) as u32)
            .sum()
    };
    metrics.insert("pdf.duplicate_form_name_count", f64::from(dup(&by_name)));
    metrics.insert("pdf.duplicate_form_rect_count", f64::from(dup(&by_rect)));
    metrics.insert(
        "pdf.duplicate_form_name_rect_count",
        f64::from(dup_pair(&by_name_rect)),
    );
    metrics.insert(
        "pdf.hidden_zero_rect_field_count",
        f64::from(hidden_zero_rect),
    );
    metrics.insert("pdf.decoded_form_value_max_len", max_decoded_len as f64);

    // Overlapping-pair count: O(n²) intersection check. PDF rects
    // are [x_lo, y_lo, x_hi, y_hi] but some producers swap the
    // hi/lo pairs, so normalize before intersecting. Capped at
    // `MAX_OVERLAP_RECTS` widgets so an adversarial AcroForm with
    // hundreds of thousands of fields can't dominate parse time —
    // anything beyond the cap is itself the forensic signal.
    let overlap_window = rects.len().min(MAX_OVERLAP_RECTS);
    let mut overlapping = 0_u32;
    for i in 0..overlap_window {
        let a = normalize_rect(rects[i]);
        for b_raw in rects[i + 1..overlap_window].iter() {
            let b = normalize_rect(*b_raw);
            if rects_overlap(a, b) {
                overlapping = overlapping.saturating_add(1);
            }
        }
    }
    metrics.insert(
        "pdf.overlapping_form_field_pair_count",
        f64::from(overlapping),
    );
    if rects.len() > MAX_OVERLAP_RECTS {
        metrics.insert("pdf.overlap_check_truncated", 1.0);
    }
}

fn parse_rect(s: &str) -> Option<[f64; 4]> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0.0; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

fn normalize_rect(r: [f64; 4]) -> [f64; 4] {
    [
        r[0].min(r[2]),
        r[1].min(r[3]),
        r[0].max(r[2]),
        r[1].max(r[3]),
    ]
}

fn rects_overlap(a: [f64; 4], b: [f64; 4]) -> bool {
    a[0] < b[2] && b[0] < a[2] && a[1] < b[3] && b[1] < a[3]
}

/// Derive `pdf.stream_*_count` metrics from the existing dict
/// regions. Each region with a `stream_range` is checked for
/// declared-`/Length` accuracy, missing `endstream`, and a `stream`
/// → newline delimiter (PDF spec requires a CR/LF/CR-LF between
/// `stream` and the body).
fn derive_stream_metrics(bytes: &[u8], dict_regions: &[DictRegion], metrics: &mut Metrics) {
    let mut missing_length = 0_u32;
    let mut invalid_length = 0_u32;
    let mut missing_endstream = 0_u32;
    let mut length_mismatch = 0_u32;
    let mut bad_delimiter = 0_u32;

    for region in dict_regions {
        let Some((body_start, body_end)) = region.stream_range else {
            continue;
        };
        let dict = &bytes[region.start..region.end];
        // Distinguish three `/Length` states for stream telemetry:
        //   - key absent → missing_length
        //   - present but non-numeric and not an indirect ref →
        //     invalid_length (malformed value, common in
        //     adversarial PDFs)
        //   - direct numeric → drives length_mismatch detection
        //   - indirect ref (`N N R`) → treated as declared but
        //     unresolvable; skipped for mismatch
        let length_classification = classify_stream_length(dict);
        let mut declared: Option<u64> = None;
        match length_classification {
            LengthValue::Missing => missing_length = missing_length.saturating_add(1),
            LengthValue::Invalid => invalid_length = invalid_length.saturating_add(1),
            LengthValue::Indirect => {}
            LengthValue::Direct(n) => declared = Some(n),
        }
        let actual = (body_end - body_start) as u64;
        if let Some(d) = declared {
            // Allow ±2 bytes for CR/LF tolerance around `endstream`.
            let diff = if actual > d { actual - d } else { d - actual };
            if diff > 2 {
                length_mismatch = length_mismatch.saturating_add(1);
            }
        }
        // `endstream` should follow the body's last byte (we trim
        // a single trailing CR/LF in collect_dict_regions); if the
        // bytes immediately after `body_end` aren't `endstream`,
        // mark it missing.
        let end_window = bytes
            .get(body_end..body_end.saturating_add(16))
            .unwrap_or(&[]);
        if !end_window.windows(9).any(|w| w == b"endstream") {
            missing_endstream = missing_endstream.saturating_add(1);
        }
        // Bad delimiter: the byte immediately after `stream` should
        // be CR, LF, or CR-LF. `collect_dict_regions` already
        // skipped that, so anything other than the canonical
        // delimiter survived as part of `body_start`'s preceding
        // bytes.
        if body_start >= 2 {
            let pre = &bytes[body_start.saturating_sub(2)..body_start];
            if pre != b"\r\n" && pre != b"\n\n" && !pre.ends_with(b"\n") {
                bad_delimiter = bad_delimiter.saturating_add(1);
            }
        }
    }
    metrics.insert("pdf.stream_missing_length_count", f64::from(missing_length));
    metrics.insert("pdf.stream_invalid_length_count", f64::from(invalid_length));
    metrics.insert(
        "pdf.stream_missing_endstream_count",
        f64::from(missing_endstream),
    );
    metrics.insert(
        "pdf.stream_length_mismatch_count",
        f64::from(length_mismatch),
    );
    metrics.insert("pdf.stream_bad_delimiter_count", f64::from(bad_delimiter));
}

/// Classification of a stream dictionary's `/Length` value.
///
/// The PDF spec allows three concrete shapes — direct numeric,
/// indirect reference, or absent — and adversarial inputs add a
/// fourth (junk). `derive_stream_metrics` consumes all four to
/// emit the `stream_*_length_count` family without re-walking the
/// dict bytes.
#[derive(Debug)]
enum LengthValue {
    Missing,
    Invalid,
    Indirect,
    Direct(u64),
}

/// Inspect a stream dict for its `/Length` value and classify it.
fn classify_stream_length(dict: &[u8]) -> LengthValue {
    let key = b"/Length";
    let mut cursor = 0;
    while cursor + key.len() <= dict.len() {
        let Some(rel) = dict[cursor..].windows(key.len()).position(|w| w == key) else {
            return LengthValue::Missing;
        };
        let pos = cursor + rel;
        let after = pos + key.len();
        // Reject suffix collisions: `/LengthBytes`, `/Length1` (font
        // subset metadata) — both are valid name characters after the
        // key.
        match dict.get(after).copied() {
            Some(b) if is_name_char(b) => {
                cursor = after;
                continue;
            }
            None => return LengthValue::Missing,
            _ => {}
        }
        // Capture the run of non-delimiter bytes up to the next
        // `/` or `>>` boundary. Whitespace is permitted (indirect
        // refs span three whitespace-separated tokens).
        let mut end = after;
        while end < dict.len() {
            match dict[end] {
                b'/' | b'<' | b'>' | b'[' | b']' => break,
                _ => end += 1,
            }
        }
        let value = std::str::from_utf8(&dict[after..end]).unwrap_or("").trim();
        if value.is_empty() {
            return LengthValue::Missing;
        }
        if let Ok(n) = value.parse::<u64>() {
            return LengthValue::Direct(n);
        }
        // Indirect ref: `<id> <gen> R` — three whitespace tokens.
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() == 3
            && parts[0].parse::<u32>().is_ok()
            && parts[1].parse::<u32>().is_ok()
            && parts[2] == "R"
        {
            return LengthValue::Indirect;
        }
        return LengthValue::Invalid;
    }
    LengthValue::Missing
}

/// Composite "how dangerous does this PDF look?" score, 0-100.
/// Sums weighted signals from `pdf.catalog.features[]`, the action
/// count, embedded files, and JavaScript-style stream content.
/// Calibrated against cleave's prior implementation so existing
/// trait thresholds (`min: 70`) still mean roughly the same thing.
fn derive_risky_feature_score(values: &Values, metrics: &mut Metrics) {
    let mut score: u32 = 0;
    let features = values
        .get("pdf.catalog.features")
        .and_then(serde_json::Value::as_array);
    if let Some(feats) = features {
        for entry in feats {
            let Some(name) = entry.as_str() else { continue };
            score += match name {
                "openaction" => 20,
                "additional_actions" => 15,
                "names_javascript" => 25,
                "richmedia" => 25,
                "3d" => 15,
                "xfa" => 20,
                "acroform" => 5,
                _ => 0,
            };
        }
    }
    let action_count = metrics.get("pdf.action_count").unwrap_or(0.0) as u32;
    if action_count > 0 {
        score += action_count.min(20);
    }
    let embedded = metrics.get("pdf.embedded_file_count").unwrap_or(0.0) as u32;
    if embedded > 0 {
        score += (embedded * 5).min(20);
    }
    metrics.insert("pdf.risky_feature_score", f64::from(score.min(100)));
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
        // The filefacts extractor reports the count via metrics —
        // the action-detail array stays with cleave's PDF parser.
        assert_eq!(m.get("pdf.action_count"), Some(1.0));
    }

    /// Inline-string `/JS (literal)` surfaces in `pdf.javascript[]`
    /// with the literal as its full content — downstream consumers
    /// extract this as a virtual JS sub-file.
    #[test]
    fn javascript_payload_inline_literal() {
        let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS (app.alert('hi')) >> endobj\n%%EOF";
        let (v, m) = extract_pdf(pdf);
        let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
        assert_eq!(js.len(), 1);
        assert_eq!(js[0]["source"].as_str(), Some("object:5"));
        assert_eq!(js[0]["content"].as_str(), Some("app.alert('hi')"));
        assert_eq!(js[0]["content_bytes"].as_u64(), Some(15));
        assert!(js[0].get("target_object_id").is_none());
        assert_eq!(m.get("pdf.javascript_count"), Some(1.0));
        assert_eq!(m.get("pdf.javascript_total_bytes"), Some(15.0));
    }

    /// `/JS <hex>` surfaces with the decoded hex string as its
    /// content. Hex strings are how some authoring tools encode
    /// non-ASCII JS or obfuscate the payload past simple grep scans.
    #[test]
    fn javascript_payload_hex_string() {
        // <6170703D31> = "app=1" — trailing-whitespace trimming in
        // read_hex_string drops the canonical "app " sample, so we
        // pick a no-trailing-space string for the assertion.
        let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS <6170703D31> >> endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
        assert_eq!(js[0]["content"].as_str(), Some("app=1"));
    }

    /// `/JS N N R` follows the indirect reference into a string-
    /// object body and surfaces its content — the target object id
    /// is recorded so analysts can map JS back to a specific obj.
    #[test]
    fn javascript_payload_indirect_string_object() {
        let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS 7 0 R >> endobj\n7 0 obj (var x = 1;) endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
        assert_eq!(js.len(), 1);
        assert_eq!(js[0]["target_object_id"].as_u64(), Some(7));
        assert_eq!(js[0]["content"].as_str(), Some("var x = 1;"));
    }

    /// Bare `/JSON` / `/JavaScript` name tokens (the action-type
    /// declaration, not the key form) must not produce a payload.
    #[test]
    fn javascript_payload_ignores_name_only_tokens() {
        // `/JavaScript` is a name value here, not a `/JS` key.
        let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript >> endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        assert!(v.get("pdf.javascript").is_none());
    }

    #[test]
    fn flags_encrypt_and_linearized() {
        let pdf = b"%PDF-1.7\n<< /Linearized 1 /Encrypt 7 0 R >>\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        let flags = v.get("pdf.shape.flags").and_then(|x| x.as_array()).unwrap();
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
        let chains = v
            .get("pdf.filter_chains")
            .and_then(|x| x.as_array())
            .unwrap();
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
        let files = v
            .get("pdf.embedded_files")
            .and_then(|x| x.as_array())
            .unwrap();
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

    // ------------------------------------------------------------------
    // Phase 1B derived-metric tests
    // ------------------------------------------------------------------

    #[test]
    fn leading_bytes_before_header_counted() {
        let pdf = b"GARBAGE_LEADING_NOISE_%PDF-1.7\n%%EOF\n";
        let (_, m) = extract_pdf(pdf);
        // `GARBAGE_LEADING_NOISE_` is 22 bytes; `%PDF-` starts at 22.
        assert_eq!(m.get("pdf.leading_bytes_before_header"), Some(22.0));
    }

    #[test]
    fn signature_object_counted() {
        let pdf = b"%PDF-1.7\n5 0 obj << /Type /Sig /Filter /Adobe.PPKLite >> endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert!(m.get("pdf.signature_object_count").unwrap() >= 1.0);
    }

    #[test]
    fn signed_incremental_update_counted() {
        // Two %%EOF markers + a signature object → 1 incremental update.
        let pdf =
            b"%PDF-1.7\n5 0 obj << /Type /Sig >> endobj\n%%EOF\n6 0 obj << >> endobj\n%%EOF\n";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.signed_incremental_update_count"), Some(1.0));
    }

    #[test]
    fn duplicate_form_name_counted() {
        let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (name1) /FT /Tx /Rect [0 0 10 10] >> endobj\n\
            11 0 obj << /Subtype /Widget /T (name1) /FT /Tx /Rect [50 50 60 60] >> endobj\n\
            12 0 obj << /Subtype /Widget /T (name2) /FT /Tx /Rect [100 100 110 110] >> endobj\n\
            %%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.duplicate_form_name_count"), Some(1.0));
    }

    #[test]
    fn duplicate_form_rect_counted() {
        let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (a) /FT /Tx /Rect [0 0 10 10] >> endobj\n\
            11 0 obj << /Subtype /Widget /T (b) /FT /Tx /Rect [0 0 10 10] >> endobj\n\
            %%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.duplicate_form_rect_count"), Some(1.0));
    }

    #[test]
    fn hidden_zero_rect_field_counted() {
        let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (hidden) /FT /Tx /Rect [0 0 0 0] /V (secret) >> endobj\n\
            11 0 obj << /Subtype /Widget /T (visible) /FT /Tx /Rect [10 10 100 100] /V (x) >> endobj\n\
            %%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.hidden_zero_rect_field_count"), Some(1.0));
    }

    #[test]
    fn decoded_form_value_max_len_reported() {
        let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (short) /FT /Tx /Rect [0 0 10 10] /V (hi) >> endobj\n\
            11 0 obj << /Subtype /Widget /T (long) /FT /Tx /Rect [0 0 10 10] /V (this is a longer value) >> endobj\n\
            %%EOF";
        let (_, m) = extract_pdf(pdf);
        assert!(m.get("pdf.decoded_form_value_max_len").unwrap() >= 22.0);
    }

    #[test]
    fn overlapping_form_field_pair_counted() {
        // Two rects that overlap, one non-overlapping → 1 pair.
        let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (a) /FT /Tx /Rect [0 0 50 50] >> endobj\n\
            11 0 obj << /Subtype /Widget /T (b) /FT /Tx /Rect [25 25 75 75] >> endobj\n\
            12 0 obj << /Subtype /Widget /T (c) /FT /Tx /Rect [200 200 250 250] >> endobj\n\
            %%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.overlapping_form_field_pair_count"), Some(1.0));
    }

    #[test]
    fn risky_feature_score_aggregates_signals() {
        let pdf = b"%PDF-1.4\n<< /AcroForm << /XFA [1 0 R] >> /OpenAction << /JS (app.alert(1)) >> >>\n5 0 obj << /S /JavaScript /JS (app.alert('x')) >> endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        let score = m.get("pdf.risky_feature_score").unwrap();
        // openaction (20) + xfa (20) + acroform (5) + 1 action (1)
        // — exact arithmetic depends on action attribution; the
        // floor is 40 for the catalog features alone.
        assert!(score >= 40.0, "risky_feature_score = {score}");
    }

    #[test]
    fn stream_metrics_count_anomalies() {
        // Stream with no /Length declared → missing_length.
        let pdf =
            b"%PDF-1.5\n5 0 obj << /Filter /FlateDecode >> stream\nXYZ\nendstream endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.stream_missing_length_count"), Some(1.0));
    }

    #[test]
    fn stream_length_mismatch_detected() {
        // /Length declares 10 bytes but body is 3 bytes.
        let pdf = b"%PDF-1.5\n5 0 obj << /Length 10 /Filter /FlateDecode >> stream\nXYZ\nendstream endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert!(m.get("pdf.stream_length_mismatch_count").unwrap() >= 1.0);
    }

    #[test]
    fn direct_length_allows_adjacent_endstream_marker() {
        // The body ends with `s`, yielding raw bytes `sendstream`.
        // Direct /Length still identifies the stream boundary exactly.
        let pdf = b"%PDF-1.5\n5 0 obj << /Length 4 /Filter /FlateDecode >> stream\nABCsendstream endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.stream_length_mismatch_count"), Some(0.0));
    }

    // ------------------------------------------------------------------
    // Malformed / robustness tests
    // ------------------------------------------------------------------

    #[test]
    fn truncated_header_is_silent() {
        // `%PDF-` truncated mid-version stamp.
        let pdf = b"%PDF-";
        let (v, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.header_count"), Some(1.0));
        // No version parsed, but header_count remains.
        assert!(v.get("pdf.header").and_then(|h| h.get("version")).is_none());
    }

    #[test]
    fn malformed_obj_block_doesnt_crash() {
        let pdf = b"%PDF-1.5\nNNNN 0 obj << bad dict\n%%EOF";
        let (_v, _m) = extract_pdf(pdf);
        // Just confirm we don't panic; correctness of recovery is
        // best-effort.
    }

    // ------------------------------------------------------------------
    // Metrics ported from cleave's pdf_kv module
    // ------------------------------------------------------------------

    #[test]
    fn javascript_and_uri_action_counts_split() {
        let pdf = b"%PDF-1.7\n\
1 0 obj << /S /JavaScript /JS (a) >> endobj\n\
2 0 obj << /S /JavaScript /JS (b) >> endobj\n\
3 0 obj << /S /URI /URI (https://example.invalid) >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.javascript_action_count"), Some(2.0));
        assert_eq!(m.get("pdf.uri_action_count"), Some(1.0));
    }

    #[test]
    fn metadata_and_objstm_counts_emitted() {
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Metadata /Length 0 >> endobj\n\
2 0 obj << /Type /ObjStm /N 3 /First 0 /Length 0 >> stream\nendstream endobj\n\
3 0 obj << /Type /XRef /Length 0 >> stream\nendstream endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.metadata_count"), Some(1.0));
        assert_eq!(m.get("pdf.objstm_count"), Some(1.0));
        assert_eq!(m.get("pdf.xref_stream_count"), Some(1.0));
        assert_eq!(m.get("pdf.object_stream_inner_object_count"), Some(3.0));
    }

    #[test]
    fn three_d_object_count_emitted() {
        let pdf =
            b"%PDF-1.7\n1 0 obj << /Subtype /3D /Type /Annot >> endobj\n2 0 obj << /Subtype/3D >> endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert!(m.get("pdf.three_d_object_count").unwrap() >= 2.0);
    }

    #[test]
    fn trailing_bytes_after_eof_counted() {
        // `\n` + `GARBAGE_TAIL_PAYLOAD` (20 bytes) = 21 trailing bytes.
        let pdf = b"%PDF-1.7\n%%EOF\nGARBAGE_TAIL_PAYLOAD";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.trailing_bytes_after_eof"), Some(21.0));
    }

    #[test]
    fn annotations_per_page_ratio() {
        // 2 pages, 4 annotations → 2.0 annotations/page.
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Page >> endobj\n\
2 0 obj << /Type /Page >> endobj\n\
3 0 obj << /Type /Annot >> endobj\n\
4 0 obj << /Type /Annot >> endobj\n\
5 0 obj << /Type /Annot >> endobj\n\
6 0 obj << /Type /Annot >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.annotations_per_page"), Some(2.0));
    }

    #[test]
    fn uri_actions_per_page_ratio() {
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Page >> endobj\n\
2 0 obj << /S /URI /URI (https://a.invalid) >> endobj\n\
3 0 obj << /S /URI /URI (https://b.invalid) >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.uri_actions_per_page"), Some(2.0));
    }

    #[test]
    fn unreferenced_object_count_reported() {
        // Three objects, none referenced from any other dict.
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Page >> endobj\n\
2 0 obj << /Type /Annot >> endobj\n\
3 0 obj << /Type /Font >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert!(m.get("pdf.unreferenced_object_count").unwrap() >= 3.0);
    }

    #[test]
    fn unreferenced_objects_drop_when_referenced() {
        // Object 2 is referenced from object 1's /Kids array.
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Pages /Kids [2 0 R] >> endobj\n\
2 0 obj << /Type /Page >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        // Only object 1 is unreferenced (no /Root ref scan here).
        assert_eq!(m.get("pdf.unreferenced_object_count"), Some(1.0));
    }

    #[test]
    fn unusual_filter_count_jbig2() {
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Filter /JBIG2Decode /Length 0 >> stream\nendstream endobj\n\
2 0 obj << /Filter /FlateDecode /Length 0 >> stream\nendstream endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.streams_with_unusual_filter_count"), Some(1.0));
    }

    #[test]
    fn stream_invalid_length_counted() {
        // `/Length not_a_number` — neither decimal nor indirect ref.
        let pdf = b"%PDF-1.7\n1 0 obj << /Length junk >> stream\nXYZ\nendstream endobj\n%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.stream_invalid_length_count"), Some(1.0));
    }

    #[test]
    fn form_field_count_reported() {
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Subtype /Widget /T (a) /FT /Tx /Rect [0 0 1 1] >> endobj\n\
2 0 obj << /Subtype /Widget /T (b) /FT /Tx /Rect [0 0 1 1] >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        assert_eq!(m.get("pdf.form_field_count"), Some(2.0));
    }

    #[test]
    fn visible_object_count_mirrors_object_count() {
        let pdf = b"%PDF-1.7\n\
1 0 obj << >> endobj\n\
2 0 obj << >> endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        let oc = m.get("pdf.object_count").unwrap();
        assert_eq!(m.get("pdf.visible_object_count"), Some(oc));
    }

    #[test]
    fn known_fixture_emits_expected_metric_keys() {
        // Lock the per-format metric surface against drift. If a
        // metric is renamed or removed this assertion fires.
        let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Catalog /OpenAction 2 0 R /AcroForm << /XFA 3 0 R >> >> endobj\n\
2 0 obj << /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >> endobj\n\
3 0 obj << /Type /Font >> endobj\n\
4 0 obj << /Type /Page >> endobj\n\
5 0 obj << /Type /Annot /Subtype /Widget /T (n) /FT /Tx /Rect [0 0 1 1] /V (v) >> endobj\n\
6 0 obj << /Type /ObjStm /N 2 /First 0 /Length 0 >> stream\nendstream endobj\n\
%%EOF";
        let (_, m) = extract_pdf(pdf);
        let want: &[&str] = &[
            "pdf.action_count",
            "pdf.annotation_count",
            "pdf.eof_count",
            "pdf.font_count",
            "pdf.form_field_count",
            "pdf.header_count",
            "pdf.javascript_action_count",
            "pdf.object_count",
            "pdf.object_stream_inner_object_count",
            "pdf.objstm_count",
            "pdf.page_count",
            "pdf.risky_feature_score",
            "pdf.stream_count",
            "pdf.visible_object_count",
        ];
        for key in want {
            assert!(m.get(key).is_some(), "missing metric: {key}");
        }
    }

    #[test]
    fn extracts_info_title_utf16_bom() {
        // `<feff>` BOM marks the Title as UTF-16BE encoded — see
        // PDF 1.7 §7.9.2.2 ("Text Strings").
        let pdf = b"%PDF-1.4\n4 0 obj << /Title <FEFF0048006900210020> >> endobj\n%%EOF";
        let (v, _) = extract_pdf(pdf);
        assert_eq!(
            v.get("pdf.info.title").and_then(|x| x.as_str()),
            Some("Hi!")
        );
    }
}
