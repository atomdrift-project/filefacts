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

use crate::metric;
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use serde_json::{Value as JsonValue, json};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::formats::common::{XorScan, extract_binary_strings, hex_nibble};
use crate::output::{Metrics, Strings, Values};
use crate::value_key;

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

/// Cap on one inflated FlateDecode stream.
const MAX_INFLATED: usize = 1 << 20;

/// Cap on the inflated bytes kept across every `/Type /ObjStm` stream. Each
/// is already held to [`MAX_INFLATED`], but every one is kept for the
/// type-count and action scans, so without a running total a file with
/// thousands of object streams pins gigabytes.
const MAX_OBJSTM_TOTAL: usize = 16 << 20;

/// Upper bound on how many form-field rects we run the O(n²)
/// overlap check across. Real PDFs hold a handful per page; with
/// thousands of widgets the pairwise pass dominates parse time.
const MAX_OVERLAP_RECTS: usize = 2_000;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    // Every fixed token and feature key below comes out of this one pass.
    // The walks that parse (object regions, object streams, dictionaries)
    // still read the bytes themselves.
    let scan = TokenScan::run(bytes);

    // Every PDF starts with `%PDF-<major>.<minor>`. Bail (parsable
    // as generic) if the header is missing or unreadable.
    let header_hits = scan.get(Tok::Header);
    let header_count = header_hits.all;
    let Some(header_at) = header_hits.first else {
        return;
    };
    metrics.insert(metric!("pdf.header_count"), header_count as f64);
    let mut header = serde_json::Map::new();
    if let Some(version) = header_version(bytes, header_at) {
        header.insert("version".into(), JsonValue::String(version));
    }
    header.insert("count".into(), json!(header_count));
    values.insert_key(value_key!("pdf.header"), JsonValue::Object(header));

    // Structural counts — the cheap byte-level fingerprint.
    let eof_count = scan.get(Tok::Eof).all;
    let trailer_count = scan.get(Tok::Trailer).all;
    let startxref_count = scan.get(Tok::StartXref).all;
    let obj_count = scan.get(Tok::Obj).accepted;
    let endobj_count = scan.get(Tok::EndObj).accepted;
    let stream_count = scan.get(Tok::Stream).accepted;
    metrics.insert(metric!("pdf.eof_count"), eof_count as f64);
    metrics.insert(metric!("pdf.trailer_count"), trailer_count as f64);
    metrics.insert(metric!("pdf.startxref_count"), startxref_count as f64);
    metrics.insert(
        metric!("pdf.object_count"),
        obj_count.min(endobj_count) as f64,
    );
    metrics.insert(metric!("pdf.stream_count"), stream_count as f64);

    // `pdf.catalog.features[]` — Pike-style flag array (mirrors
    // `pe.dll_characteristics`). Trait authors match `exact: xfa` /
    // `exact: openaction` rather than chase a sprawl of per-flag
    // booleans. Names use the PDF-spec keys analysts already know
    // (AcroForm, XFA, OpenAction) lowercased; `additional_actions`
    // expands the abbreviated `/AA`; `3d` matches the spec name.
    let mut features: Vec<&str> = Vec::new();
    if scan.has(Tok::AcroForm) {
        features.push("acroform");
    }
    if scan.has(Tok::Xfa) {
        features.push("xfa");
    }
    if scan.has(Tok::OpenAction) {
        features.push("openaction");
    }
    if scan.has(Tok::AdditionalActions) {
        // `/AA` = Additional Actions. Whole-token match — bare
        // substring would hit `AAAaa` style binary noise.
        features.push("additional_actions");
    }
    if scan.has(Tok::JavaScript) {
        features.push("names_javascript");
    }
    if scan.has(Tok::RichMedia) {
        features.push("richmedia");
    }
    let three_d = scan.get(Tok::Subtype3dSpaced).all + scan.get(Tok::Subtype3dJoined).all;
    if three_d > 0 {
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
        values.insert_key(value_key!("pdf.catalog"), JsonValue::Object(catalog));
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
    if scan.has(Tok::Encrypt) {
        shape_flags.push("encrypted");
    }
    if scan.has(Tok::Linearized) {
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
    // Objects packed into `/Type /ObjStm` streams never appear in the bytes
    // as written, so a scan of the file alone reports a document with no
    // annotations, no pages and no actions in it. Decode them once here and
    // count against both views.
    let dict_regions = collect_dict_regions(bytes);
    let object_streams = decode_object_streams(bytes, &dict_regions, MAX_OBJSTM_TOTAL);
    // A spent budget is a coverage limit, not a parse failure: it goes in
    // `pdf.limits` like the archive walkers' limits, and stays out of
    // `errors` (which traits read as "the parser failed").
    if object_streams.skipped > 0 {
        push_pdf_limit(
            values,
            "object-stream-budget",
            format!(
                "{} object stream(s) not decoded: the {MAX_OBJSTM_TOTAL}-byte budget was spent",
                object_streams.skipped
            ),
        );
    }
    let objstm_text = object_streams.decoded;
    let objstm_scans: Vec<TokenScan> = objstm_text
        .iter()
        .map(|(_, text)| TokenScan::run(text))
        .collect();

    let counts: &[(&str, TypeName, crate::MetricKey)] = &[
        ("page_count", TypeName::Page, metric!("pdf.page_count")),
        (
            "annotation_count",
            TypeName::Annot,
            metric!("pdf.annotation_count"),
        ),
        (
            "xobject_count",
            TypeName::XObject,
            metric!("pdf.xobject_count"),
        ),
        ("font_count", TypeName::Font, metric!("pdf.font_count")),
        (
            "metadata_count",
            TypeName::Metadata,
            metric!("pdf.metadata_count"),
        ),
        (
            "objstm_count",
            TypeName::ObjStm,
            metric!("pdf.objstm_count"),
        ),
        (
            "xref_stream_count",
            TypeName::XRef,
            metric!("pdf.xref_stream_count"),
        ),
        (
            "signature_object_count",
            TypeName::Sig,
            metric!("pdf.signature_object_count"),
        ),
    ];
    let mut page_count_value: u32 = 0;
    let mut annotation_count_value: u32 = 0;
    for (kv_key, name, metric_key) in counts {
        let c = scan.type_count(*name)
            + objstm_scans
                .iter()
                .map(|s| s.type_count(*name))
                .sum::<usize>();
        if c > 0 {
            shape.insert((*kv_key).into(), json!(c));
            metrics.insert(metric_key.clone(), c as f64);
        }
        if *kv_key == "page_count" {
            page_count_value = crate::bytes::sat_u32(c);
        }
        if *kv_key == "annotation_count" {
            annotation_count_value = crate::bytes::sat_u32(c);
        }
    }
    let byte_range_count = scan.get(Tok::ByteRange).all;
    if byte_range_count > 0 {
        shape.insert("byte_range_count".into(), json!(byte_range_count));
        metrics.insert(metric!("pdf.byte_range_count"), byte_range_count as f64);
    }
    let jbig2 = scan.get(Tok::Jbig2Decode).all;
    if jbig2 > 0 {
        shape.insert("jbig2_filter_count".into(), json!(jbig2));
        metrics.insert(metric!("pdf.jbig2_filter_count"), jbig2 as f64);
    }
    if three_d > 0 {
        shape.insert("three_d_object_count".into(), json!(three_d));
        metrics.insert(metric!("pdf.three_d_object_count"), three_d as f64);
    }
    // `visible_object_count` — objects recovered from the linear
    // byte scan (not from object-stream expansion). Equal to
    // `pdf.object_count` since this extractor does not yet decode
    // ObjStm entries into the dict-region list. Surfacing both
    // keys keeps the trait field schema stable and lets a future
    // ObjStm expansion bump `object_count` without rewriting rules.
    metrics.insert(
        metric!("pdf.visible_object_count"),
        obj_count.min(endobj_count) as f64,
    );
    // Trailing bytes after the *last* `%%EOF` marker — a common
    // padding pattern in malicious PDFs that smuggle a payload past
    // the parser. Counted relative to the last EOF only; multiple
    // EOFs are normal in incrementally-updated documents.
    let trailing_bytes = scan
        .get(Tok::Eof)
        .last
        .map_or(0, |at| bytes.len().saturating_sub(at + b"%%EOF".len()));
    if trailing_bytes > 0 {
        metrics.insert(metric!("pdf.trailing_bytes"), trailing_bytes as f64);
    }
    if !shape.is_empty() {
        values.insert_key(value_key!("pdf.shape"), JsonValue::Object(shape));
    }

    // `/FlateDecode` count — the bulk of legitimate compressed
    // streams. (`/JBIG2Decode` is emitted alongside `shape.*` below
    // as both a metric and a kv field.)
    metrics.insert(
        metric!("pdf.flate_filter_count"),
        scan.get(Tok::FlateDecode).all as f64,
    );

    // Info dict — Title / Author / Creator / Producer / etc. live
    // in a dict referenced by `/Info` from the trailer. We don't
    // resolve the indirect reference; instead we scan all `obj`
    // blocks for the standard Info keys and pick up whichever
    // appears first. Malicious PDFs sometimes split Info across
    // multiple incremental updates, in which case the last one
    // wins (we want the document's *final* state).
    info_dict(bytes, &scan, values);

    // Action sites with full kv shape — `{kind, source, snippet}` —
    // scanned strictly inside object *dictionaries* (between `obj`
    // and the first `stream`/`endobj`). Source attribution is
    // best-effort: object-id when we can identify the carrier,
    // "openaction" when the catalog dict references the action
    // inline. We don't follow indirect references back to named
    // / annotation / acroform sites, so heavily-staged malicious
    // PDFs may show fewer source labels than cleave's xref-aware
    // parser. The `kind` and `snippet` fields stay accurate.
    if dict_regions.len() >= MAX_DICT_REGIONS {
        // Signal to trait rules that the object-graph scan stopped
        // early. The cap is a DoS guard, not a sizing heuristic, so
        // anything that hits it is well outside the real-world range.
        metrics.insert(metric!("pdf.dict_region_truncated"), 1.0);
    }
    let mut actions = scan_actions(bytes, &dict_regions);
    actions.extend(objstm_actions(&objstm_text));
    let uri_action_count = action_count_by_kind(&actions, "uri");
    let javascript_action_count = action_count_by_kind(&actions, "javascript");
    let upload_directory_uri_count = count_upload_directory_uris(&actions);
    if !actions.is_empty() {
        metrics.insert(metric!("pdf.action_count"), actions.len() as f64);
        values.insert_key(value_key!("pdf.actions"), JsonValue::Array(actions));
    }
    if javascript_action_count > 0 {
        metrics.insert(
            metric!("pdf.javascript_action_count"),
            f64::from(javascript_action_count),
        );
    }
    if uri_action_count > 0 {
        metrics.insert(metric!("pdf.uri_action_count"), f64::from(uri_action_count));
    }
    if upload_directory_uri_count > 0 {
        metrics.insert(
            metric!("pdf.upload_directory_uri_count"),
            f64::from(upload_directory_uri_count),
        );
    }

    // Full-content JavaScript payloads — one entry per `/JS` site
    // resolved end-to-end (inline literals, hex strings, and indirect
    // references followed into Flate-compressed streams). Distinct
    // from `pdf.actions[]`, which keeps a short truncated snippet for
    // at-a-glance triage. Downstream consumers (cleave's PDF
    // sub-file analyzer) re-extract each entry as a virtual JS
    // sub-file at depth 1 so JavaScript-specific traits match
    // against the actual code rather than just the metadata count.
    let objects = index_objects(&dict_regions);
    let JsScan {
        payloads: js_payloads,
        limit: js_limit,
    } = scan_javascript_payloads(bytes, &dict_regions, &objects);
    if let Some(reason) = js_limit {
        push_pdf_limit(values, "javascript-budget", reason);
    }
    if !js_payloads.is_empty() {
        // A repeat of an already-decoded target carries no content of its
        // own, so this totals distinct payload bytes.
        let total_bytes: u64 = js_payloads
            .iter()
            .filter_map(|v| v.as_object())
            .filter(|o| o.contains_key("content"))
            .filter_map(|o| o.get("content_bytes").and_then(JsonValue::as_u64))
            .sum();
        metrics.insert(metric!("pdf.javascript_count"), js_payloads.len() as f64);
        metrics.insert(metric!("pdf.javascript_total_bytes"), total_bytes as f64);
        values.insert_key(value_key!("pdf.javascript"), JsonValue::Array(js_payloads));
    }

    // Embedded files — `{filename, size}` per `/Type /Filespec`
    // record. `size` is recovered by following the `/EF /F <ref>`
    // reference to the embedded-stream object and reading the
    // (possibly indirect) `/Length` value from its dict.
    let embedded = scan_embedded_files(bytes, &dict_regions, &objects);
    if !embedded.is_empty() {
        metrics.insert(metric!("pdf.embedded_file_count"), embedded.len() as f64);
        values.insert_key(
            value_key!("pdf.embedded_files"),
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
        values.insert_key(
            value_key!("pdf.filter_chains"),
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
        values.insert_key(value_key!("pdf.streams"), JsonValue::Array(streams));
    }

    // AcroForm widget fields — `/Subtype /Widget` objects with a
    // field type (`/FT`). Surfaces the field name (`/T`), type
    // (`/FT`), bounding box (`/Rect`), and value (`/V`) when one
    // is set. Used by trait rules detecting staged JavaScript or
    // recognizable form authoring fingerprints.
    let form_fields = scan_form_fields(bytes, &dict_regions);
    derive_form_field_metrics(&form_fields, metrics);
    if !form_fields.is_empty() {
        metrics.insert(metric!("pdf.form_field_count"), form_fields.len() as f64);
        values.insert_key(value_key!("pdf.form_fields"), JsonValue::Array(form_fields));
    }

    // Per-page ratios — number of annotations / URI actions per
    // page. Surfacing these as derived metrics keeps trait rules
    // shape-agnostic: a one-page PDF with 30 URI annotations and a
    // thirty-page PDF with one URI annotation per page produce the
    // same `uri_actions_per_page = 1.0` rather than two unrelated
    // raw counts. Zero pages → zero ratio (rather than NaN).
    if page_count_value > 0 {
        metrics.insert(
            metric!("pdf.annotations_per_page"),
            f64::from(annotation_count_value) / f64::from(page_count_value),
        );
        if uri_action_count > 0 {
            metrics.insert(
                metric!("pdf.uri_actions_per_page"),
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
            metric!("pdf.object_stream_inner_object_count"),
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
        metrics.insert(
            metric!("pdf.unreferenced_object_count"),
            f64::from(unreferenced),
        );
    }

    // Unusual filters — JBIG2, LZW, and Crypt. Each pulls in a
    // historically exploitable decoder path (CVE-2010-1297 et al).
    // Counts the number of objects with at least one unusual
    // filter in the chain, not the number of filter declarations.
    let unusual = streams_with_unusual_filter_count(bytes, &dict_regions);
    if unusual > 0 {
        metrics.insert(
            metric!("pdf.streams_with_unusual_filter_count"),
            f64::from(unusual),
        );
    }

    // Phase 1B derived metrics — formerly computed by cleave's
    // pdf::parser. Now reachable through the metric-fold adapter
    // (`merge_filefacts_metrics`) so trait rules using `field: pdf.X`
    // resolve against filefacts' flat metric map.
    metrics.insert(metric!("pdf.leading_bytes"), header_at as f64);
    let sig_count = scan.type_count(TypeName::Sig) + scan.get(Tok::TypeSigSpaced).all;
    metrics.insert(
        metric!("pdf.signature_object_count"),
        (sig_count / 2) as f64,
    );
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
            metric!("pdf.signed_incremental_update_count"),
            signed_incremental as f64,
        );
    }
    derive_stream_metrics(bytes, &dict_regions, metrics);
    derive_risky_feature_score(values, metrics);
}

/// The version after the first `%PDF-` (at `header_at`). Multiple headers
/// (stacked PDFs) is a known evasion technique; the *first* version is
/// what the loader keys on, so that's what we surface as the canonical
/// document version. The full count is exposed as
/// `pdf.header_count`.
fn header_version(bytes: &[u8], header_at: usize) -> Option<String> {
    let start = header_at + b"%PDF-".len();
    let tail = bytes.get(start..)?;
    let tail = tail.get(..8).unwrap_or(tail);
    let version: String = tail
        .iter()
        .take_while(|&&b| b.is_ascii_digit() || b == b'.')
        .map(|&b| b as char)
        .collect();
    (!version.is_empty()).then_some(version)
}

/// Surface the *first* value of each canonical DocumentInfo key
/// anywhere in the file as `pdf.info.<lowercased>`.
fn info_dict(bytes: &[u8], scan: &TokenScan, values: &mut Values) {
    let mut info = serde_json::Map::new();
    for (tok, key) in INFO_KEYS {
        let Some(at) = scan.get(tok).first_accepted else {
            continue;
        };
        if let Some(value) = value_after_key(bytes, at + tok.pattern().0.len()) {
            if !value.is_empty() {
                info.insert(key.to_string(), JsonValue::String(value));
            }
        }
    }
    if !info.is_empty() {
        values.insert_key(value_key!("pdf.info"), JsonValue::Object(info));
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
        let rel = memchr::memmem::find(bytes.get(cursor..)?, key)?;
        let after_key = cursor + rel + key.len();
        let next = *bytes.get(after_key)?;
        if next.is_ascii_alphabetic() || next == b'_' {
            cursor = after_key;
            continue;
        }
        return value_after_key(bytes, after_key);
    }
    None
}

/// The value of a key that ends at `after_key`: a literal or hex string, a
/// name, or a bare number, after optional spaces and tabs.
fn value_after_key(bytes: &[u8], after_key: usize) -> Option<String> {
    let mut value_pos = after_key;
    while bytes
        .get(value_pos)
        .is_some_and(|&b| b == b' ' || b == b'\t')
    {
        value_pos += 1;
    }
    match *bytes.get(value_pos)? {
        b'(' => read_literal_string(bytes, value_pos + 1),
        b'<' if bytes.get(value_pos + 1) != Some(&b'<') => read_hex_string(bytes, value_pos + 1),
        b'/' => read_name(bytes, value_pos + 1),
        b'0'..=b'9' | b'-' => {
            // Bare numeric value (e.g. `/Length 42`). Capture
            // the digit/sign run.
            let run = bytes.get(value_pos..)?;
            let end = run
                .iter()
                .position(|&b| !(b.is_ascii_digit() || b == b'-' || b == b'.'))
                .unwrap_or(run.len());
            std::str::from_utf8(run.get(..end)?)
                .ok()
                .map(str::to_string)
        }
        _ => None,
    }
}

/// PDF literal strings are `(text)` with balanced parens and `\)`
/// escapes. We cap at 1024 bytes and decode lossily to UTF-8.
fn read_literal_string(bytes: &[u8], start: usize) -> Option<String> {
    const CAP: usize = 1024;
    let mut depth = 1_i32;
    let mut out = Vec::new();
    let mut i = start;
    while out.len() < CAP {
        let Some(&b) = bytes.get(i) else {
            break;
        };
        // PDF escape sequences inside literal strings:
        //   \n \r \t \b \f \( \) \\  → single-byte escapes
        //   \NNN                       → 1-3 octal digits
        //   \<eol>                     → line continuation
        if let (b'\\', Some(&esc)) = (b, bytes.get(i + 1)) {
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
                    while count < 3 {
                        let Some(&digit) = bytes.get(j).filter(|d| (b'0'..=b'7').contains(*d))
                        else {
                            break;
                        };
                        value = value * 8 + u16::from(digit - b'0');
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
    Some(decode_text_string(&out))
}

/// A decoded PDF string as text. PDF Title/Author are frequently UTF-16BE
/// with the `FE FF` BOM: decode those; fall back to lossy UTF-8 otherwise.
fn decode_text_string(raw: &[u8]) -> String {
    if let Some(be) = raw.strip_prefix(&[0xFE, 0xFF]) {
        return crate::bytes::utf16_lossy(be, crate::bytes::Endian::Big)
            .trim()
            .to_string();
    }
    String::from_utf8_lossy(raw).trim().to_string()
}

/// PDF hex strings are `<HH HH …>`. Decode pairs to bytes, then to
/// UTF-8 / UTF-16BE the same way as literal strings.
fn read_hex_string(bytes: &[u8], start: usize) -> Option<String> {
    let rest = bytes.get(start..)?;
    let end = rest.iter().position(|&b| b == b'>')?;
    let hex_only: Vec<u8> = rest
        .get(..end)?
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect();
    let mut out = Vec::with_capacity(hex_only.len() / 2);
    for chunk in hex_only.chunks(2) {
        let (&hi, lo) = chunk.split_first()?;
        let hi = hex_nibble(hi)?;
        let lo = match lo.first() {
            Some(&lo) => hex_nibble(lo)?,
            None => 0,
        };
        out.push((hi << 4) | lo);
    }
    if out.is_empty() {
        return None;
    }
    Some(decode_text_string(&out))
}

/// PDF names start with `/` and continue with regular characters
/// until whitespace or a delimiter.
fn read_name(bytes: &[u8], start: usize) -> Option<String> {
    let rest = bytes.get(start..)?;
    let end = rest
        .iter()
        .position(|&b| {
            matches!(
                b,
                b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'<' | b'>' | b'[' | b']' | b'('
            )
        })
        .unwrap_or(rest.len());
    let name = rest.get(..end)?;
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

impl DictRegion {
    /// The dictionary bytes, `start..end` of `bytes`. Regions always lie
    /// inside the bytes they were collected from; anything else reads as
    /// an empty dictionary.
    fn dict<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        bytes.get(self.start..self.end).unwrap_or_default()
    }
}

/// The byte before `at`, or a space at the start of the input.
fn byte_before(bytes: &[u8], at: usize) -> u8 {
    at.checked_sub(1)
        .and_then(|i| bytes.get(i))
        .copied()
        .unwrap_or(b' ')
}

/// The first position at or after `from` whose byte fails `pred`, or the
/// end of `bytes`.
fn skip_while(bytes: &[u8], from: usize, pred: impl Fn(&u8) -> bool) -> usize {
    from + bytes
        .get(from..)
        .map_or(0, |rest| rest.iter().take_while(|b| pred(b)).count())
}

/// `bytes` split before its trailing run of bytes that satisfy `pred`.
fn split_trailing(bytes: &[u8], pred: impl Fn(&u8) -> bool) -> (&[u8], &[u8]) {
    let run = bytes.iter().rev().take_while(|b| pred(b)).count();
    bytes
        .split_at_checked(bytes.len() - run)
        .unwrap_or((bytes, &[]))
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
        let Some(rel) = bytes
            .get(pos..)
            .and_then(|rest| memchr::memmem::find(rest, b"obj"))
        else {
            break;
        };
        let obj_pos = pos + rel;
        // Require whole-token: the byte before `obj` must be
        // whitespace and the byte after must not be a name char
        // (avoids matching `endobj`, `objstm`, etc.).
        let before = byte_before(bytes, obj_pos);
        let after = bytes.get(obj_pos + 3).copied().unwrap_or(b' ');
        if !before.is_ascii_whitespace() || is_name_char(after) {
            pos = obj_pos + 3;
            continue;
        }
        let obj_id = parse_obj_id_before(bytes, obj_pos);
        let dict_start = obj_pos + 3;
        // Dict ends at the nearest `stream` or `endobj` token.
        // Both are whole tokens, so accept any non-name char as the
        // delimiter (space, newline, etc.). `endobj` first, and
        // `stream` only inside this object: an object without a
        // stream used to look for one all the way to the next stream
        // in the file, and a tagged PDF ends with thousands of
        // stream-less structure objects, so each of them scanned to
        // end-of-file — minutes for a 5 MB manual (fleet, 2026-09-06).
        let endobj_end = find_token_after(bytes, dict_start, b"endobj");
        let stream_end_marker = find_token_between(
            bytes,
            dict_start,
            endobj_end.unwrap_or(bytes.len()),
            b"stream",
        );
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
                let dict = bytes.get(dict_start..dict_end).unwrap_or_default();
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
        // Skip past the stream body if one was present: `endobj_end`
        // is the first `endobj` after the dict, so it is the one after
        // `endstream` too.
        pos = match (stream_end_marker, endobj_end) {
            (Some(s), Some(e)) if s < e => e,
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
    let (head, _) = split_trailing(bytes.get(..obj_pos)?, u8::is_ascii_whitespace);
    let (head, generation) = split_trailing(head, u8::is_ascii_digit);
    if generation.is_empty() {
        return None;
    }
    let (head, _) = split_trailing(head, u8::is_ascii_whitespace);
    let (_, id) = split_trailing(head, u8::is_ascii_digit);
    if id.is_empty() {
        return None;
    }
    std::str::from_utf8(id).ok()?.parse().ok()
}

/// Like `find_after` but requires the match to be a whole token:
/// neither the preceding nor following byte may be a name char.
fn find_token_after(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    find_token_between(bytes, from, bytes.len(), needle)
}

/// [`find_token_after`] with the match confined to `from..to`. The
/// bytes on either side of a match are still judged from `bytes`, so
/// a token at the bound is accepted or rejected exactly as an
/// unbounded search would.
fn find_token_between(bytes: &[u8], from: usize, to: usize, needle: &[u8]) -> Option<usize> {
    let to = to.min(bytes.len());
    if from >= to {
        return None;
    }
    memchr::memmem::find_iter(bytes.get(from..to)?, needle)
        .map(|rel| from + rel)
        .find(|&abs| {
            let before = byte_before(bytes, abs);
            let after = bytes.get(abs + needle.len()).copied().unwrap_or(b' ');
            !is_name_char(before) && !is_name_char(after)
        })
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
    if body_end > body_start && byte_before(bytes, body_end) == b'\n' {
        body_end -= 1;
    }
    if body_end > body_start && byte_before(bytes, body_end) == b'\r' {
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
        let region = region_info.dict(bytes);
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
            while let Some(rel) = region
                .get(pos..)
                .and_then(|rest| memchr::memmem::find(rest, needle))
            {
                let abs = pos + rel;
                let next = abs + needle.len();
                // Reject `/JS` matching `/JSON` or `/JavaScript`.
                if region.get(next).is_some_and(u8::is_ascii_alphabetic) {
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

/// Scan actions packed inside `/Type /ObjStm` object streams.
///
/// A cross-reference stream file keeps most of its objects inside compressed
/// object streams, so the annotation that carries the document's only link
/// never appears in the raw bytes at all -- and a scan of the file as written
/// reports a PDF with no actions in it. Malicious documents are routinely
/// built this way, which makes the compressed side the more important one.
///
/// Objects inside an ObjStm have no `obj` framing -- the stream is a table of
/// offsets followed by the dictionaries end to end -- so the decoded buffer is
/// handed to [`scan_actions`] as a single region.
fn objstm_actions(decoded: &[(Option<u32>, Vec<u8>)]) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for (obj_id, text) in decoded {
        let whole = DictRegion {
            start: 0,
            end: text.len(),
            obj_id: *obj_id,
            stream_range: None,
        };
        for mut action in scan_actions(text, std::slice::from_ref(&whole)) {
            // Say where it really came from: inside object stream <id>, not
            // object <id> itself.
            if let (Some(map), Some(id)) = (action.as_object_mut(), *obj_id) {
                map.insert("source".into(), JsonValue::String(format!("objstm:{id}")));
            }
            out.push(action);
        }
    }
    out
}

/// Inflated object streams, each carrier's object id alongside the objects it
/// holds.
struct ObjectStreams {
    decoded: Vec<(Option<u32>, Vec<u8>)>,
    /// Object streams left undecoded once the budget was spent.
    skipped: usize,
}

/// Inflate every `/Type /ObjStm` stream, keeping at most `budget` inflated
/// bytes across all of them ([`MAX_OBJSTM_TOTAL`] outside tests).
fn decode_object_streams(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    mut budget: usize,
) -> ObjectStreams {
    let mut out = ObjectStreams {
        decoded: Vec::new(),
        skipped: 0,
    };
    for region in dict_regions {
        let Some((s, e)) = region.stream_range else {
            continue;
        };
        let dict = region.dict(bytes);
        if !contains_substring(dict, b"/Type /ObjStm") && !contains_substring(dict, b"/Type/ObjStm")
        {
            continue;
        }
        if budget == 0 {
            out.skipped += 1;
            continue;
        }
        let raw = bytes.get(s..e).unwrap_or_default();
        if let Some(decoded) = inflate_capped(raw, budget.min(MAX_INFLATED)) {
            budget -= decoded.len();
            out.decoded.push((region.obj_id, decoded));
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
fn scan_javascript_payloads(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    objects: &ObjectIndex<'_>,
) -> JsScan {
    let mut out = Vec::new();
    // Decoded bytes left for the document. Sites can repeat one target
    // (`/JS 2 0 R` a thousand times over); each target is decoded once,
    // and the budget bounds what distinct targets and inline strings add.
    let mut budget = MAX_JS_TOTAL;
    let mut sites = 0_usize;
    // Every target resolved so far, with its decoded length (`None`: it
    // did not resolve), so a repeat is answered without decoding again.
    let mut seen: HashMap<u32, Option<u64>> = HashMap::new();
    let mut limit = None;
    'regions: for region in dict_regions {
        let DictRegion {
            start, end, obj_id, ..
        } = *region;
        if end <= start {
            continue;
        }
        let dict = region.dict(bytes);
        let mut pos = 0;
        while let Some(rel) = dict
            .get(pos..)
            .and_then(|rest| memchr::memmem::find(rest, b"/JS"))
        {
            let abs = pos + rel;
            let next = abs + 3;
            pos = next;
            // Reject /JSON, /JavaScript (the *name*, not the key form).
            if dict.get(next).is_some_and(u8::is_ascii_alphabetic) {
                continue;
            }
            if sites >= MAX_JS_SITES {
                limit = Some(format!("stopped after {MAX_JS_SITES} /JS sites"));
                break 'regions;
            }
            sites += 1;
            let source = JsonValue::String(match obj_id {
                Some(id) => format!("object:{id}"),
                None => "object:unknown".to_string(),
            });
            let cursor = skip_while(dict, next, u8::is_ascii_whitespace);
            let target = js_reference(dict, cursor);
            if let Some(&known) = target.and_then(|id| seen.get(&id)) {
                // The payload is the earlier entry's with the same
                // `target_object_id`; repeating its content would only
                // multiply the output.
                if let (Some(id), Some(len)) = (target, known) {
                    out.push(json!({
                        "source": source,
                        "target_object_id": id,
                        "content_bytes": len,
                    }));
                }
                continue;
            }
            if budget == 0 {
                limit = Some(format!(
                    "/JS payloads past the {MAX_JS_TOTAL}-byte decode budget not read"
                ));
                break 'regions;
            }
            let payload = match target {
                Some(id) => resolve_indirect_js(bytes, id, objects, budget.min(MAX_INFLATED)),
                None => resolve_inline_js(dict, cursor),
            };
            if let Some(id) = target {
                seen.insert(id, payload.as_ref().map(|p| p.content.len() as u64));
            }
            let Some(payload) = payload else {
                continue;
            };
            budget = budget.saturating_sub(payload.content.len());
            let mut entry = serde_json::Map::new();
            entry.insert("source".into(), source);
            if let Some(target) = payload.target_object_id {
                entry.insert(
                    "target_object_id".into(),
                    JsonValue::Number(u64::from(target).into()),
                );
            }
            if !payload.filters.is_empty() {
                entry.insert(
                    "filters".into(),
                    JsonValue::Array(payload.filters.into_iter().map(JsonValue::String).collect()),
                );
            }
            entry.insert(
                "content_bytes".into(),
                JsonValue::Number((payload.content.len() as u64).into()),
            );
            entry.insert("content".into(), JsonValue::String(payload.content));
            out.push(JsonValue::Object(entry));
        }
    }
    JsScan {
        payloads: out,
        limit,
    }
}

/// Decoded `/JS` content kept per document, across every site.
const MAX_JS_TOTAL: usize = 16 << 20;
/// `/JS` sites resolved per document.
const MAX_JS_SITES: usize = 4096;

/// The `pdf.javascript` entries, and why the scan stopped early if it did.
struct JsScan {
    payloads: Vec<JsonValue>,
    limit: Option<String>,
}

/// Every object with an id, for following indirect references. PDFs with
/// multiple generations of one object id are rare in malicious samples, and
/// the last one wins here, as it does in the rest of the extractor's
/// handling of incremental updates.
type ObjectIndex<'r> = HashMap<u32, &'r DictRegion>;

fn index_objects(dict_regions: &[DictRegion]) -> ObjectIndex<'_> {
    let mut by_id = HashMap::with_capacity(dict_regions.len());
    for r in dict_regions {
        if let Some(id) = r.obj_id {
            by_id.insert(id, r);
        }
    }
    by_id
}

fn push_pdf_limit(values: &mut Values, stage: &str, reason: impl Into<String>) {
    super::bounded::push_limit(values, value_key!("pdf.limits"), stage, reason);
}

struct JsPayload {
    target_object_id: Option<u32>,
    filters: Vec<String>,
    content: String,
}

/// An inline `/JS` value at `dict[cursor..]`: a `(literal)` or a `<hex>`
/// string.
fn resolve_inline_js(dict: &[u8], cursor: usize) -> Option<JsPayload> {
    let content = match dict.get(cursor)? {
        b'(' => read_literal_string(dict, cursor + 1)?,
        b'<' if dict.get(cursor + 1) != Some(&b'<') => read_hex_string(dict, cursor + 1)?,
        _ => return None,
    };
    Some(JsPayload {
        target_object_id: None,
        filters: Vec::new(),
        content,
    })
}

/// The object id of an `N G R` indirect reference at `dict[cursor..]`.
fn js_reference(dict: &[u8], cursor: usize) -> Option<u32> {
    if !dict.get(cursor)?.is_ascii_digit() {
        return None;
    }
    let end = (cursor + 32).min(dict.len());
    let token: String = dict
        .get(cursor..end)?
        .iter()
        .take_while(|&&b| !matches!(b, b'\n' | b'\r' | b'>' | b'/' | b'('))
        .map(|&b| b as char)
        .collect();
    let reference = token.trim().strip_suffix('R')?;
    let mut parts = reference.split_whitespace();
    let target_id: u32 = parts.next()?.parse().ok()?;
    let _gen: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some(target_id)
}

/// Dereference object `target_id` to recover the underlying string- or
/// stream-object's content, decoding at most `cap` bytes of a stream.
fn resolve_indirect_js(
    bytes: &[u8],
    target_id: u32,
    objects: &ObjectIndex<'_>,
    cap: usize,
) -> Option<JsPayload> {
    let target = objects.get(&target_id).copied()?;

    // Two shapes — a stream object (most common for /JS, since JS
    // blobs are bigger than a string-literal-friendly size) or a
    // bare string object. Try stream first.
    if let Some((s, e)) = target.stream_range {
        if let Some(raw) = bytes.get(s..e).filter(|raw| !raw.is_empty()) {
            let filters = read_object_filters(target.dict(bytes));
            let decoded: Option<std::borrow::Cow<'_, [u8]>> = match filters.as_slice() {
                [] => Some(raw.get(..cap).unwrap_or(raw).into()),
                [single] if single == "FlateDecode" => inflate_capped(raw, cap).map(Into::into),
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
    let target_dict = target.dict(bytes);
    let p = skip_while(target_dict, 0, u8::is_ascii_whitespace);
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
    find_filter_in_dict(dict)
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_default()
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
        let region = region_info.dict(bytes);
        let mut pos = 0;
        while let Some(rel) = region
            .get(pos..)
            .and_then(|rest| memchr::memmem::find(rest, b"/Filter"))
        {
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
    let mut cursor = skip_while(bytes, start, u8::is_ascii_whitespace);
    match *bytes.get(cursor)? {
        b'/' => read_name(bytes, cursor + 1).map(|n| n.trim_start_matches('/').to_string()),
        b'[' => {
            cursor += 1;
            let mut names = Vec::new();
            while cursor < bytes.len() {
                cursor = skip_while(bytes, cursor, u8::is_ascii_whitespace);
                match bytes.get(cursor) {
                    Some(b']') => break,
                    Some(b'/') => {
                        let name = read_name(bytes, cursor + 1)?;
                        let trimmed = name.trim_start_matches('/').to_string();
                        cursor += 1 + trimmed.len();
                        names.push(trimmed);
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
    let cursor = skip_while(bytes, start, u8::is_ascii_whitespace);
    match *bytes.get(cursor)? {
        b'(' => read_literal_string(bytes, cursor + 1).map(|s| truncate(&s, SNIPPET_BYTES)),
        b'<' if bytes.get(cursor + 1) != Some(&b'<') => {
            read_hex_string(bytes, cursor + 1).map(|s| truncate(&s, SNIPPET_BYTES))
        }
        b'0'..=b'9' => {
            // Indirect reference `N N R`. Emit the reference token
            // so trait authors know an indirect lookup is in use.
            let end = (cursor + 16).min(bytes.len());
            let token: String = bytes
                .get(cursor..end)?
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

/// URI actions whose path is a CMS upload directory (`/wp-content/uploads/`,
/// `/system/files/webform/`). One such citation is ordinary; a doorway is
/// built out of many of them.
fn count_upload_directory_uris(actions: &[JsonValue]) -> u32 {
    let mut n = 0_u32;
    for action in actions {
        let Some(obj) = action.as_object() else {
            continue;
        };
        if obj.get("kind").and_then(JsonValue::as_str) != Some("uri") {
            continue;
        }
        let Some(snippet) = obj.get("snippet").and_then(JsonValue::as_str) else {
            continue;
        };
        let lower = snippet.to_ascii_lowercase();
        if lower.contains("/wp-content/uploads/") || lower.contains("/system/files/webform/") {
            n = n.saturating_add(1);
        }
    }
    n
}

/// Count action entries from `scan_actions` whose `kind` matches.
/// Used to surface `pdf.javascript_action_count` and
/// `pdf.uri_action_count` from the same action table the kv view
/// emits — single source of truth, no separate substring scan.
fn action_count_by_kind(actions: &[JsonValue], kind: &str) -> u32 {
    let count = actions
        .iter()
        .filter(|a| {
            a.as_object()
                .and_then(|o| o.get("kind"))
                .and_then(JsonValue::as_str)
                == Some(kind)
        })
        .count();
    crate::bytes::sat_u32(count)
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
        let dict = region.dict(bytes);
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
        collect_indirect_refs(region.dict(bytes), &mut refs);
    }
    if ids.is_empty() {
        return 0;
    }
    crate::bytes::sat_u32(ids.difference(&refs).count())
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
        if let [id, _, "R"] = window {
            if let Ok(id) = id.parse::<u32>() {
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
        let Some(chain) = find_filter_in_dict(region.dict(bytes)) else {
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
        let rel = memchr::memmem::find(dict.get(p..)?, b"/Filter")?;
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
fn scan_embedded_files(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    objects: &ObjectIndex<'_>,
) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    for region in dict_regions {
        let dict = region.dict(bytes);
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
        let size = find_ef_stream_length(dict, objects, bytes);
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
    objects: &ObjectIndex<'_>,
    bytes: &[u8],
) -> Option<u64> {
    // Locate `/EF` then the inner `/F <id> <gen> R` or
    // `/UF <id> <gen> R` reference.
    let ef_pos = memchr::memmem::find(filespec_dict, b"/EF").filter(|&p| {
        filespec_dict
            .get(p + 3)
            .is_some_and(|b| !b.is_ascii_alphabetic())
    })?;
    let window_end = (ef_pos + 256).min(filespec_dict.len());
    let window = filespec_dict.get(ef_pos..window_end)?;
    let target_id = parse_indirect_ref_value(window, b"/F")
        .or_else(|| parse_indirect_ref_value(window, b"/UF"))?;
    let target = objects.get(&target_id)?;
    let target_dict = target.dict(bytes);
    let length_text = find_info_value(target_dict, b"/Length")?;
    if let Ok(direct) = length_text.parse::<u64>() {
        return Some(direct);
    }
    // Indirect length — try `<id> <gen> R` form.
    let length_ref = parse_indirect_ref_value(target_dict, b"/Length")?;
    let length_obj = objects.get(&length_ref)?;
    // The raw_value of a length-only object is the literal number;
    // strip leading whitespace and parse.
    let digits: String = length_obj
        .dict(bytes)
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
        let rel = memchr::memmem::find(bytes.get(cursor..)?, key)?;
        let abs = cursor + rel;
        let after_idx = abs + key.len();
        let after = *bytes.get(after_idx)?;
        if after.is_ascii_alphabetic() || after == b'_' {
            cursor = after_idx;
            continue;
        }
        // Expect digits, whitespace, digits, whitespace, 'R'.
        let id_start = skip_while(bytes, after_idx, u8::is_ascii_whitespace);
        let id_end = skip_while(bytes, id_start, u8::is_ascii_digit);
        if id_end == id_start {
            return None;
        }
        let id_text = std::str::from_utf8(bytes.get(id_start..id_end)?).ok()?;
        let id: u32 = id_text.parse().ok()?;
        let gen_start = skip_while(bytes, id_end, u8::is_ascii_whitespace);
        let gen_end = skip_while(bytes, gen_start, u8::is_ascii_digit);
        if gen_end == gen_start {
            return None;
        }
        let p = skip_while(bytes, gen_end, u8::is_ascii_whitespace);
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
        let Some(raw) = bytes.get(s..e).filter(|raw| !raw.is_empty()) else {
            continue;
        };
        let dict = region.dict(bytes);
        // No `/Filter` at offset 0 — try locating it inside the dict.
        let filters: Vec<String> = read_filter_value(dict, 0)
            .or_else(|| find_filter_in_dict(dict))
            .map(|s| s.split(',').map(str::to_string).collect())
            .unwrap_or_default();
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

        if matches!(filters.as_slice(), [only] if only == "FlateDecode") {
            // Only the first `MAX_DECODED_TEXT` bytes are kept, so inflating
            // more would only burn time on every stream in the file.
            if let Some(decoded) = inflate_capped(raw, MAX_DECODED_TEXT) {
                let sample = decoded.as_slice();
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
    for &b in data.iter().take(n) {
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
        let dict = region.dict(bytes);
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
    let pos = memchr::memmem::find(bytes, key)?;
    let after_idx = pos + key.len();
    if bytes
        .get(after_idx)
        .is_some_and(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let cursor = skip_while(bytes, after_idx, u8::is_ascii_whitespace);
    let array = bytes.get(cursor..)?.strip_prefix(b"[")?;
    let end = array.iter().position(|&b| b == b']')?;
    let inner = std::str::from_utf8(array.get(..end)?).ok()?;
    Some(inner.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Decode a FlateDecode stream into a buffer of at most `max` bytes, so an
/// adversarial deflate bomb can't blow memory.
///
/// A truncated stream or one with a bad checksum still yields what decoded
/// before the damage: viewers render that prefix, and malicious PDFs ship
/// such streams on purpose to trip strict parsers. `None` only when nothing
/// decoded at all.
fn inflate_capped(input: &[u8], max: usize) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(input).take(max as u64);
    let mut out = Vec::new();
    // `read_to_end` keeps what it read before an error.
    let complete = decoder.read_to_end(&mut out).is_ok();
    (complete || !out.is_empty()).then_some(out)
}

fn contains_substring(bytes: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(bytes, needle).is_some()
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// PDF whitespace and the delimiters that can sit next to a name key.
fn is_delim(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'/')
}

/// What has to surround an occurrence of a fixed pattern for it to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    /// Every occurrence counts.
    Any,
    /// No name character on either side, so `obj` matches neither `objstm`
    /// nor the tail of `endobj`.
    Token,
    /// A delimiter or whitespace before, and a delimiter, whitespace or digit
    /// after. `/AA` is two letters: checking only the trailing byte let them
    /// through when they fell inside compressed image data, which reported
    /// additional actions on every other scanned document.
    Keyword,
    /// No name character after, so `/Type /Page` does not count `/Pages`.
    NameEnd,
    /// No letter or `_` after, so `/Title` does not match `/Titles`.
    KeyEnd,
}

impl Boundary {
    fn accepts(self, bytes: &[u8], start: usize, end: usize) -> bool {
        let before = byte_before(bytes, start);
        let after = bytes.get(end).copied();
        match self {
            Self::Any => true,
            Self::Token => !is_name_char(before) && !after.is_some_and(is_name_char),
            Self::Keyword => {
                let after = after.unwrap_or(b' ');
                is_delim(before) && (is_delim(after) || after.is_ascii_digit())
            }
            Self::NameEnd => !after.is_some_and(is_name_char),
            Self::KeyEnd => !after.is_some_and(|b| b.is_ascii_alphabetic() || b == b'_'),
        }
    }

    /// Whether every occurrence is a candidate. The other kinds take
    /// occurrences the way `memmem::find_iter` does: one may not start
    /// inside the previous one, whether or not that one counted.
    fn overlapping(self) -> bool {
        self == Self::Keyword
    }
}

/// Every fixed byte pattern the whole-file scan looks for. A variant's
/// position in [`Tok::ALL`] is its pattern id in [`TOKEN_SCANNER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Header,
    Eof,
    Trailer,
    StartXref,
    Obj,
    EndObj,
    Stream,
    AcroForm,
    Xfa,
    OpenAction,
    AdditionalActions,
    JavaScript,
    RichMedia,
    Subtype3dSpaced,
    Subtype3dJoined,
    Encrypt,
    Linearized,
    ByteRange,
    Jbig2Decode,
    FlateDecode,
    TypePageSpaced,
    TypePageJoined,
    TypeAnnotSpaced,
    TypeAnnotJoined,
    TypeXObjectSpaced,
    TypeXObjectJoined,
    TypeFontSpaced,
    TypeFontJoined,
    TypeMetadataSpaced,
    TypeMetadataJoined,
    TypeObjStmSpaced,
    TypeObjStmJoined,
    TypeXRefSpaced,
    TypeXRefJoined,
    TypeSigSpaced,
    TypeSigJoined,
    InfoTitle,
    InfoAuthor,
    InfoCreator,
    InfoProducer,
    InfoSubject,
    InfoKeywords,
    InfoCreationDate,
    InfoModDate,
    InfoTrapped,
}

impl Tok {
    const ALL: [Self; 45] = [
        Self::Header,
        Self::Eof,
        Self::Trailer,
        Self::StartXref,
        Self::Obj,
        Self::EndObj,
        Self::Stream,
        Self::AcroForm,
        Self::Xfa,
        Self::OpenAction,
        Self::AdditionalActions,
        Self::JavaScript,
        Self::RichMedia,
        Self::Subtype3dSpaced,
        Self::Subtype3dJoined,
        Self::Encrypt,
        Self::Linearized,
        Self::ByteRange,
        Self::Jbig2Decode,
        Self::FlateDecode,
        Self::TypePageSpaced,
        Self::TypePageJoined,
        Self::TypeAnnotSpaced,
        Self::TypeAnnotJoined,
        Self::TypeXObjectSpaced,
        Self::TypeXObjectJoined,
        Self::TypeFontSpaced,
        Self::TypeFontJoined,
        Self::TypeMetadataSpaced,
        Self::TypeMetadataJoined,
        Self::TypeObjStmSpaced,
        Self::TypeObjStmJoined,
        Self::TypeXRefSpaced,
        Self::TypeXRefJoined,
        Self::TypeSigSpaced,
        Self::TypeSigJoined,
        Self::InfoTitle,
        Self::InfoAuthor,
        Self::InfoCreator,
        Self::InfoProducer,
        Self::InfoSubject,
        Self::InfoKeywords,
        Self::InfoCreationDate,
        Self::InfoModDate,
        Self::InfoTrapped,
    ];

    /// The bytes to find and what must surround them.
    fn pattern(self) -> (&'static [u8], Boundary) {
        use Boundary::{Any, KeyEnd, Keyword, NameEnd, Token};
        match self {
            Self::Header => (b"%PDF-", Any),
            Self::Eof => (b"%%EOF", Any),
            Self::Trailer => (b"\ntrailer", Any),
            Self::StartXref => (b"startxref", Any),
            Self::Obj => (b"obj", Token),
            Self::EndObj => (b"endobj", Token),
            Self::Stream => (b"stream", Token),
            Self::AcroForm => (b"/AcroForm", Token),
            Self::Xfa => (b"/XFA", Token),
            Self::OpenAction => (b"/OpenAction", Token),
            Self::AdditionalActions => (b"/AA", Keyword),
            Self::JavaScript => (b"/JavaScript", Token),
            Self::RichMedia => (b"/RichMedia", Token),
            Self::Subtype3dSpaced => (b"/Subtype /3D", Any),
            Self::Subtype3dJoined => (b"/Subtype/3D", Any),
            Self::Encrypt => (b"/Encrypt", Token),
            Self::Linearized => (b"/Linearized", Token),
            Self::ByteRange => (b"/ByteRange", Any),
            Self::Jbig2Decode => (b"/JBIG2Decode", Any),
            Self::FlateDecode => (b"/FlateDecode", Any),
            Self::TypePageSpaced => (b"/Type /Page", NameEnd),
            Self::TypePageJoined => (b"/Type/Page", NameEnd),
            Self::TypeAnnotSpaced => (b"/Type /Annot", NameEnd),
            Self::TypeAnnotJoined => (b"/Type/Annot", NameEnd),
            Self::TypeXObjectSpaced => (b"/Type /XObject", NameEnd),
            Self::TypeXObjectJoined => (b"/Type/XObject", NameEnd),
            Self::TypeFontSpaced => (b"/Type /Font", NameEnd),
            Self::TypeFontJoined => (b"/Type/Font", NameEnd),
            Self::TypeMetadataSpaced => (b"/Type /Metadata", NameEnd),
            Self::TypeMetadataJoined => (b"/Type/Metadata", NameEnd),
            Self::TypeObjStmSpaced => (b"/Type /ObjStm", NameEnd),
            Self::TypeObjStmJoined => (b"/Type/ObjStm", NameEnd),
            Self::TypeXRefSpaced => (b"/Type /XRef", NameEnd),
            Self::TypeXRefJoined => (b"/Type/XRef", NameEnd),
            Self::TypeSigSpaced => (b"/Type /Sig", NameEnd),
            Self::TypeSigJoined => (b"/Type/Sig", NameEnd),
            Self::InfoTitle => (b"/Title", KeyEnd),
            Self::InfoAuthor => (b"/Author", KeyEnd),
            Self::InfoCreator => (b"/Creator", KeyEnd),
            Self::InfoProducer => (b"/Producer", KeyEnd),
            Self::InfoSubject => (b"/Subject", KeyEnd),
            Self::InfoKeywords => (b"/Keywords", KeyEnd),
            Self::InfoCreationDate => (b"/CreationDate", KeyEnd),
            Self::InfoModDate => (b"/ModDate", KeyEnd),
            Self::InfoTrapped => (b"/Trapped", KeyEnd),
        }
    }
}

/// DocumentInfo keys, surfaced as `pdf.info.<name>`.
const INFO_KEYS: [(Tok, &str); 9] = [
    (Tok::InfoTitle, "title"),
    (Tok::InfoAuthor, "author"),
    (Tok::InfoCreator, "creator"),
    (Tok::InfoProducer, "producer"),
    (Tok::InfoSubject, "subject"),
    (Tok::InfoKeywords, "keywords"),
    (Tok::InfoCreationDate, "creation_date"),
    (Tok::InfoModDate, "mod_date"),
    (Tok::InfoTrapped, "trapped"),
];

/// A `/Type /<Name>` dictionary role. The PDF spec allows whitespace
/// between the slash-name keys (`/Type /Page`) but many producers
/// concatenate them (`/Type/Page`); both forms count.
#[derive(Clone, Copy, Debug)]
enum TypeName {
    Page,
    Annot,
    XObject,
    Font,
    Metadata,
    ObjStm,
    XRef,
    Sig,
}

impl TypeName {
    fn spellings(self) -> [Tok; 2] {
        match self {
            Self::Page => [Tok::TypePageSpaced, Tok::TypePageJoined],
            Self::Annot => [Tok::TypeAnnotSpaced, Tok::TypeAnnotJoined],
            Self::XObject => [Tok::TypeXObjectSpaced, Tok::TypeXObjectJoined],
            Self::Font => [Tok::TypeFontSpaced, Tok::TypeFontJoined],
            Self::Metadata => [Tok::TypeMetadataSpaced, Tok::TypeMetadataJoined],
            Self::ObjStm => [Tok::TypeObjStmSpaced, Tok::TypeObjStmJoined],
            Self::XRef => [Tok::TypeXRefSpaced, Tok::TypeXRefJoined],
            Self::Sig => [Tok::TypeSigSpaced, Tok::TypeSigJoined],
        }
    }
}

/// One automaton over every [`Tok`] pattern, and what it cannot see.
///
/// [`TokenScan`] needs every occurrence of every pattern, however they
/// overlap one another: each pattern used to be searched on its own, so
/// `obj` was found inside `endobj`, and the `endobj` that shares its `e`
/// with a preceding `/FlateDecode`. Standard semantics with overlapping
/// iteration reports all of them, but walks the input a byte at a time and
/// ran slower than the per-token `memmem` passes it replaced. A
/// leftmost-first search takes the SIMD prefilter path instead; it resumes
/// after each match, so the occurrences that start inside a match are
/// recovered from [`Self::starts_inside`].
struct TokenScanner {
    automaton: AhoCorasick,
    /// For each pattern id, the `(pattern id, offset)` pairs that can start
    /// inside an occurrence of it: the patterns whose bytes agree with it
    /// from that offset on (offset 0 for a different pattern that shares its
    /// start). Every occurrence either is a match of the search or starts
    /// inside one, so checking these after each match finds exactly the
    /// occurrences the search stepped over.
    starts_inside: Vec<Vec<(usize, usize)>>,
}

impl TokenScanner {
    fn new() -> Self {
        let patterns = Tok::ALL.map(|t| t.pattern().0);
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build(patterns)
            .expect("fixed PDF token patterns build");
        let starts_inside = patterns
            .iter()
            .enumerate()
            .map(|(outer, outer_bytes)| {
                let mut inside = Vec::new();
                for offset in 0..outer_bytes.len() {
                    let tail = outer_bytes.get(offset..).unwrap_or_default();
                    for (inner, inner_bytes) in patterns.iter().enumerate() {
                        if inner == outer && offset == 0 {
                            continue;
                        }
                        let n = tail.len().min(inner_bytes.len());
                        if tail.get(..n) == inner_bytes.get(..n) {
                            inside.push((inner, offset));
                        }
                    }
                }
                inside
            })
            .collect();
        Self {
            automaton,
            starts_inside,
        }
    }
}

static TOKEN_SCANNER: LazyLock<TokenScanner> = LazyLock::new(TokenScanner::new);

/// What the scan saw of one pattern.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Hits {
    /// Occurrences, counted the way `memmem::find_iter` counts them (or
    /// every one, for an overlapping [`Boundary`]).
    all: usize,
    /// Those that pass the pattern's [`Boundary`].
    accepted: usize,
    /// Start of the first occurrence.
    first: Option<usize>,
    /// Start of the last occurrence.
    last: Option<usize>,
    /// Start of the first occurrence that passes the boundary test.
    first_accepted: Option<usize>,
}

/// Counts and positions of every fixed token, from one pass over the bytes.
struct TokenScan([Hits; Tok::ALL.len()]);

impl TokenScan {
    fn run(bytes: &[u8]) -> Self {
        let mut scan = Self([Hits::default(); Tok::ALL.len()]);
        // Where each pattern's next counted occurrence may start.
        let mut resume = [0usize; Tok::ALL.len()];
        let scanner = &*TOKEN_SCANNER;
        for m in scanner.automaton.find_iter(bytes) {
            let (id, start) = (m.pattern().as_usize(), m.start());
            scan.record(bytes, &mut resume, id, start);
            // Occurrences inside this match, in offset order, so each
            // pattern still sees its occurrences in input order: the next
            // match starts at or after this one's end.
            for &(inner, offset) in scanner.starts_inside.get(id).into_iter().flatten() {
                let at = start + offset;
                let Some(inner_bytes) = Tok::ALL.get(inner).map(|t| t.pattern().0) else {
                    continue;
                };
                if bytes.get(at..at + inner_bytes.len()) == Some(inner_bytes) {
                    scan.record(bytes, &mut resume, inner, at);
                }
            }
        }
        scan
    }

    /// Count one occurrence of pattern `id` at `start`. Occurrences of one
    /// pattern arrive in input order.
    fn record(&mut self, bytes: &[u8], resume: &mut [usize], id: usize, start: usize) {
        let (Some(tok), Some(h), Some(resume)) =
            (Tok::ALL.get(id), self.0.get_mut(id), resume.get_mut(id))
        else {
            return;
        };
        let (pattern, boundary) = tok.pattern();
        let end = start + pattern.len();
        h.first.get_or_insert(start);
        h.last = Some(start);
        if !boundary.overlapping() {
            if start < *resume {
                return;
            }
            *resume = end;
        }
        h.all += 1;
        if boundary.accepts(bytes, start, end) {
            h.accepted += 1;
            h.first_accepted.get_or_insert(start);
        }
    }

    fn get(&self, tok: Tok) -> Hits {
        self.0.get(tok as usize).copied().unwrap_or_default()
    }

    /// Whether `tok` occurs at least once with its boundary satisfied.
    fn has(&self, tok: Tok) -> bool {
        self.get(tok).accepted > 0
    }

    /// Dictionaries tagged `/Type /<name>`, in either spelling.
    fn type_count(&self, name: TypeName) -> usize {
        name.spellings().iter().map(|&t| self.get(t).accepted).sum()
    }
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
        let field_type = obj
            .and_then(|o| o.get("field_type"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
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
            // A signature widget with no appearance box is how an invisible
            // certification is stored. It is not a hidden payload field.
            if r == [0.0, 0.0, 0.0, 0.0] && !field_type.eq_ignore_ascii_case("Sig") {
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
            .map(|&c| crate::bytes::sat_u32(c - 1))
            .fold(0, u32::saturating_add)
    };
    let dup_pair = |map: &HashMap<(String, String), usize>| -> u32 {
        map.values()
            .filter(|&&c| c > 1)
            .map(|&c| crate::bytes::sat_u32(c - 1))
            .fold(0, u32::saturating_add)
    };
    metrics.insert(
        metric!("pdf.duplicate_form_name_count"),
        f64::from(dup(&by_name)),
    );
    metrics.insert(
        metric!("pdf.duplicate_form_rect_count"),
        f64::from(dup(&by_rect)),
    );
    metrics.insert(
        metric!("pdf.duplicate_form_name_rect_count"),
        f64::from(dup_pair(&by_name_rect)),
    );
    metrics.insert(
        metric!("pdf.hidden_zero_rect_field_count"),
        f64::from(hidden_zero_rect),
    );
    metrics.insert(
        metric!("pdf.decoded_form_value_max_length"),
        max_decoded_len as f64,
    );

    // Overlapping-pair count: O(n²) intersection check. PDF rects
    // are [x_lo, y_lo, x_hi, y_hi] but some producers swap the
    // hi/lo pairs, so normalize before intersecting. Capped at
    // `MAX_OVERLAP_RECTS` widgets so an adversarial AcroForm with
    // hundreds of thousands of fields can't dominate parse time —
    // anything beyond the cap is itself the forensic signal.
    let overlap_window = rects.get(..MAX_OVERLAP_RECTS).unwrap_or(&rects);
    let mut overlapping = 0_u32;
    for (i, a_raw) in overlap_window.iter().enumerate() {
        let a = normalize_rect(*a_raw);
        for b_raw in overlap_window.iter().skip(i + 1) {
            let b = normalize_rect(*b_raw);
            if rects_overlap(a, b) {
                overlapping = overlapping.saturating_add(1);
            }
        }
    }
    metrics.insert(
        metric!("pdf.overlapping_form_field_pair_count"),
        f64::from(overlapping),
    );
    if rects.len() > MAX_OVERLAP_RECTS {
        metrics.insert(metric!("pdf.overlap_check_truncated"), 1.0);
    }
}

fn parse_rect(s: &str) -> Option<[f64; 4]> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0.0; 4];
    for (slot, p) in out.iter_mut().zip(&parts) {
        *slot = p.parse().ok()?;
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
        let dict = region.dict(bytes);
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
        if memchr::memmem::find(end_window, b"endstream").is_none() {
            missing_endstream = missing_endstream.saturating_add(1);
        }
        // Bad delimiter: the byte immediately after `stream` should
        // be CR, LF, or CR-LF. `collect_dict_regions` already
        // skipped that, so anything other than the canonical
        // delimiter survived as part of `body_start`'s preceding
        // bytes.
        if let Some(pre) = body_start
            .checked_sub(2)
            .and_then(|from| bytes.get(from..body_start))
        {
            if pre != b"\r\n" && pre != b"\n\n" && !pre.ends_with(b"\n") {
                bad_delimiter = bad_delimiter.saturating_add(1);
            }
        }
    }
    metrics.insert(
        metric!("pdf.stream_missing_length_count"),
        f64::from(missing_length),
    );
    metrics.insert(
        metric!("pdf.stream_invalid_length_count"),
        f64::from(invalid_length),
    );
    metrics.insert(
        metric!("pdf.stream_missing_endstream_count"),
        f64::from(missing_endstream),
    );
    metrics.insert(
        metric!("pdf.stream_length_mismatch_count"),
        f64::from(length_mismatch),
    );
    metrics.insert(
        metric!("pdf.stream_bad_delimiter_count"),
        f64::from(bad_delimiter),
    );
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
        let Some(rel) = dict
            .get(cursor..)
            .and_then(|rest| memchr::memmem::find(rest, key))
        else {
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
        let end = skip_while(dict, after, |b| {
            !matches!(b, b'/' | b'<' | b'>' | b'[' | b']')
        });
        let value = dict
            .get(after..end)
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("")
            .trim();
        if value.is_empty() {
            return LengthValue::Missing;
        }
        if let Ok(n) = value.parse::<u64>() {
            return LengthValue::Direct(n);
        }
        // Indirect ref: `<id> <gen> R` — three whitespace tokens.
        let parts: Vec<&str> = value.split_whitespace().collect();
        if let [id, generation, "R"] = parts.as_slice() {
            if id.parse::<u32>().is_ok() && generation.parse::<u32>().is_ok() {
                return LengthValue::Indirect;
            }
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
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int `as` saturates (NaN is 0); the metrics read here are non-negative counts"
)]
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
    metrics.insert(
        metric!("pdf.risky_feature_score"),
        f64::from(score.min(100)),
    );
}

#[cfg(test)]
mod tests;
