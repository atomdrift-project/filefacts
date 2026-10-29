//! PDF extractor.
//!
//! Lenient byte-scan parser — no cross-reference resolution, no
//! stream decryption, no object-graph reconstruction. Malicious
//! PDFs routinely break those features to evade strict parsers, so
//! we surface forensic facts (action presence, embedded files,
//! catalog flags) by recognizing the canonical PDF tokens directly
//! in the raw bytes, and in the objects packed into object streams.
//!
//! Schema namespaces under `pdf.*` matching filefacts' per-format
//! convention:
//!
//! - `pdf.header.{version, count}` — first `%PDF-X.Y` plus the
//!   total count (>1 signals a stacked-PDF evasion attempt).
//! - `pdf.info.{title, author, creator, producer, subject, keywords,
//!   creation_date, mod_date, trapped}` — DocumentInfo dict.
//! - `pdf.catalog.features[]` — `acroform`, `xfa`, `openaction`,
//!   `additional_actions`, `names_javascript`, `richmedia`, `3d`.
//! - `pdf.actions[].{kind, source, snippet}` — action invocation sites.
//! - `pdf.javascript[]` — every `/JS` payload, decoded in full.
//! - `pdf.embedded_files[].{filename, size}` — `/Type /Filespec` attachments.
//! - `pdf.filter_chains[]` — dedup'd comma-joined `/Filter` declarations.
//! - `pdf.streams[].{object_id, filters, magic_hex, decoded_text}` —
//!   per-stream metadata, filtered bodies decoded.
//! - `pdf.form_fields[].{object_id, name, field_type, rect, value}` —
//!   AcroForm widget entries.
//! - `pdf.shape.{object_count, eof_count, page_count, annotation_count,
//!   flags, …}` — structural counts and flags.
//! - `pdf.limits[]` — coverage the caps cut short.
//!
//! Metric counts live flat under `pdf.*` and parallel the kv view.
//!
//! The extractor runs in phases over shared inputs: one token scan of the
//! whole file ([`tokens`]), one walk of its object regions ([`objects`]),
//! and the object streams those regions hold, decoded once ([`filters`]).

use serde_json::{Value as JsonValue, json};

use crate::formats::bounded::Limits;
use crate::formats::common::{XorScan, extract_binary_strings};
use crate::output::{Metrics, Strings, Values};
use crate::{MetricKey, metric, value_key};

mod actions;
mod filters;
mod forms;
mod lex;
mod objects;
mod streams;
mod tokens;

use actions::{Action, JsScan};
use lex::value_after_key;
use objects::{DictRegion, MAX_DICT_REGIONS, ObjectIndex, ObjectStreams, TypeCounts};
use tokens::{INFO_KEYS, Tok, TokenScan};

/// Cap on one decoded stream.
const MAX_INFLATED: usize = 1 << 20;

/// Cap on the decoded bytes kept across every `/Type /ObjStm` stream. Each
/// is already held to [`MAX_INFLATED`], but every one is kept for the
/// type-count and action scans, so without a running total a file with
/// thousands of object streams pins gigabytes.
const MAX_OBJSTM_TOTAL: usize = 16 << 20;

/// Action sites recorded per document. Each becomes a JSON entry of up to
/// a kilobyte from as little as six input bytes; a dictionary packed with
/// `/URI(` would otherwise grow the values tree a hundredfold. Link-heavy
/// real documents carry a few thousand.
const MAX_ACTIONS: usize = 65_536;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    // Every fixed token and feature key comes out of this one pass. The
    // walks that parse (object regions, object streams, dictionaries)
    // read the bytes themselves.
    let scan = TokenScan::run(bytes);
    let Some(header_at) = header(bytes, &scan, values, metrics) else {
        tracing::debug!(
            target: "filefacts::pdf",
            stage = "header",
            len = bytes.len(),
            "no %PDF- header; not parsed as PDF"
        );
        return;
    };
    let features = catalog_features(&scan);
    if !features.is_empty() {
        values.insert_key(value_key!("pdf.catalog"), json!({ "features": features }));
    }

    let walk = objects::collect_dict_regions(bytes);
    let regions = walk.regions.as_slice();
    tracing::debug!(
        target: "filefacts::pdf",
        stage = "objects",
        len = bytes.len(),
        regions = regions.len(),
        searched = walk.searched,
        "object regions collected"
    );
    if regions.len() >= MAX_DICT_REGIONS {
        // Signal to trait rules that the object-graph scan stopped
        // early. The cap is a DoS guard, not a sizing heuristic, so
        // anything that hits it is well outside the real-world range.
        tracing::debug!(
            target: "filefacts::pdf",
            stage = "objects",
            cap = MAX_DICT_REGIONS,
            "object region walk stopped at the cap"
        );
        metrics.insert(metric!("pdf.dict_region_truncated"), 1.0);
    }

    // Objects packed into `/Type /ObjStm` streams never appear in the bytes
    // as written, so a scan of the file alone reports a document with no
    // annotations, no pages and no actions in it. Decode them once here and
    // count against both views.
    let mut limits = Limits::default();
    let object_streams = objects::decode_object_streams(bytes, regions, MAX_OBJSTM_TOTAL);
    object_stream_limits(&object_streams, &mut limits);
    let mut types = TypeCounts::default();
    for region in regions {
        types.add(region.dict(bytes));
    }
    for (_, text) in &object_streams.decoded {
        types.add(text);
    }

    shape(bytes, &scan, &types, values, metrics);
    info_dict(bytes, &scan, values);
    let actions = action_sites(
        bytes,
        regions,
        &object_streams,
        &mut limits,
        values,
        metrics,
    );
    let object_index: ObjectIndex<'_> = regions
        .iter()
        .filter_map(|r| Some((r.obj_id?, r)))
        .collect();
    javascript(bytes, regions, &object_index, &mut limits, values, metrics);
    let embedded = embedded_files(bytes, regions, &object_index, values, metrics);
    stream_inventory(bytes, regions, values, metrics);

    // Per-page ratios — number of annotations / URI actions per
    // page. Surfacing these as derived metrics keeps trait rules
    // shape-agnostic: a one-page PDF with 30 URI annotations and a
    // thirty-page PDF with one URI annotation per page produce the
    // same `uri_actions_per_page = 1.0` rather than two unrelated
    // raw counts. Zero pages → no ratio (rather than NaN).
    let uri_actions = actions.iter().filter(|a| a.kind == "uri").count();
    if types.page > 0 {
        let pages = types.page as f64;
        metrics.insert(
            metric!("pdf.annotations_per_page"),
            types.annot as f64 / pages,
        );
        if uri_actions > 0 {
            metrics.insert(
                metric!("pdf.uri_actions_per_page"),
                uri_actions as f64 / pages,
            );
        }
    }

    object_metrics(bytes, regions, metrics);
    metrics.insert(metric!("pdf.leading_bytes"), header_at as f64);
    // Signed incremental update: incremental updates leave more than
    // one `%%EOF` marker; pair that with the presence of a signature
    // object to count signed-then-modified PDFs (the classic
    // shadow-attack shape).
    if types.sig > 0 {
        let updates = scan.get(Tok::Eof).all.saturating_sub(1);
        metrics.insert(
            metric!("pdf.signed_incremental_update_count"),
            updates as f64,
        );
    }
    metrics.insert(
        metric!("pdf.risky_feature_score"),
        f64::from(risky_feature_score(&features, actions.len(), embedded)),
    );
    limits.emit(values, value_key!("pdf.limits"));
}

/// `pdf.header` and `pdf.header_count`; the offset of the first `%PDF-`,
/// or `None` when there is none.
fn header(
    bytes: &[u8],
    scan: &TokenScan,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Option<usize> {
    let hits = scan.get(Tok::Header);
    let header_at = hits.first?;
    metrics.insert(metric!("pdf.header_count"), hits.all as f64);
    let mut header = serde_json::Map::new();
    if let Some(version) = header_version(bytes, header_at) {
        header.insert("version".into(), JsonValue::String(version));
    }
    header.insert("count".into(), json!(hits.all));
    values.insert_key(value_key!("pdf.header"), JsonValue::Object(header));
    Some(header_at)
}

/// The version after the first `%PDF-` (at `header_at`). Multiple headers
/// (stacked PDFs) is a known evasion technique; the *first* version is
/// what the loader keys on, so that's what we surface as the canonical
/// document version. The full count is exposed as
/// `pdf.header_count`.
fn header_version(bytes: &[u8], header_at: usize) -> Option<String> {
    let start = header_at + Tok::Header.bytes().len();
    let tail = bytes.get(start..)?;
    let tail = tail.get(..8).unwrap_or(tail);
    let version: String = tail
        .iter()
        .take_while(|&&b| b.is_ascii_digit() || b == b'.')
        .map(|&b| b as char)
        .collect();
    (!version.is_empty()).then_some(version)
}

/// `pdf.catalog.features[]` — a flag array (as `pe.dll_characteristics`
/// is), so trait authors match `exact: xfa` rather than chase per-flag
/// booleans. Names use the PDF-spec keys analysts already know (AcroForm,
/// XFA, OpenAction) lowercased; `additional_actions` expands the
/// abbreviated `/AA`; `3d` matches the spec name.
fn catalog_features(scan: &TokenScan) -> Vec<&'static str> {
    let three_d = scan.get(Tok::Subtype3dSpaced).all + scan.get(Tok::Subtype3dJoined).all;
    [
        (scan.has(Tok::AcroForm), "acroform"),
        (scan.has(Tok::Xfa), "xfa"),
        (scan.has(Tok::OpenAction), "openaction"),
        (scan.has(Tok::AdditionalActions), "additional_actions"),
        (scan.has(Tok::JavaScript), "names_javascript"),
        (scan.has(Tok::RichMedia), "richmedia"),
        (three_d > 0, "3d"),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect()
}

/// `pdf.limits` entries for the object streams left undecoded. A spent
/// budget or an unsupported filter is a coverage limit, not a parse
/// failure: it goes in `pdf.limits` like the archive walkers' limits, and
/// stays out of `errors` (which traits read as "the parser failed").
fn object_stream_limits(streams: &ObjectStreams, limits: &mut Limits) {
    if streams.over_budget > 0 {
        tracing::debug!(
            target: "filefacts::pdf",
            stage = "object-stream",
            skipped = streams.over_budget,
            cap = MAX_OBJSTM_TOTAL,
            "object streams past the decode budget"
        );
        limits.push(
            "object-stream-budget",
            format!(
                "{} object stream(s) not decoded: the {MAX_OBJSTM_TOTAL}-byte budget was spent",
                streams.over_budget
            ),
        );
    }
    if let Some(why) = &streams.first_failure {
        limits.push(
            "object-stream-decode",
            format!(
                "{} object stream(s) not decoded; first: {why}",
                streams.undecodable
            ),
        );
    }
}

/// `pdf.shape` and its flat metric mirrors: the byte-level structural
/// counts and flags. Counts that need cross-reference resolution (objects
/// reachable from the trailer, free entries) are out of reach of a byte
/// scan; these are the ones that are not.
fn shape(
    bytes: &[u8],
    scan: &TokenScan,
    types: &TypeCounts,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let eof = scan.get(Tok::Eof);
    let trailer_count = scan.get(Tok::Trailer).all;
    let startxref_count = scan.get(Tok::StartXref).all;
    let object_count = scan
        .get(Tok::Obj)
        .accepted
        .min(scan.get(Tok::EndObj).accepted);
    metrics.insert(metric!("pdf.eof_count"), eof.all as f64);
    metrics.insert(metric!("pdf.trailer_count"), trailer_count as f64);
    metrics.insert(metric!("pdf.startxref_count"), startxref_count as f64);
    metrics.insert(metric!("pdf.object_count"), object_count as f64);
    // Objects as written in the file's bytes; those packed in object
    // streams are `pdf.object_stream_inner_object_count`.
    metrics.insert(metric!("pdf.visible_object_count"), object_count as f64);
    metrics.insert(
        metric!("pdf.stream_count"),
        scan.get(Tok::Stream).accepted as f64,
    );
    // `/FlateDecode` count — the bulk of legitimate compressed streams.
    metrics.insert(
        metric!("pdf.flate_filter_count"),
        scan.get(Tok::FlateDecode).all as f64,
    );

    let mut shape = serde_json::Map::new();
    shape.insert("object_count".into(), json!(object_count));
    shape.insert("eof_count".into(), json!(eof.all));
    if trailer_count > 0 {
        shape.insert("trailer_count".into(), json!(trailer_count));
    }
    if startxref_count > 0 {
        shape.insert("startxref_count".into(), json!(startxref_count));
    }
    let flags: Vec<&str> = [
        (scan.has(Tok::Encrypt), "encrypted"),
        (scan.has(Tok::Linearized), "linearized"),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect();
    if !flags.is_empty() {
        shape.insert("flags".into(), json!(flags));
    }

    // Each count is the number of dictionaries whose `/Type` is the named
    // role, in the file's objects and inside its object streams.
    let three_d = scan.get(Tok::Subtype3dSpaced).all + scan.get(Tok::Subtype3dJoined).all;
    let counts: [(&str, MetricKey, usize); 11] = [
        ("page_count", metric!("pdf.page_count"), types.page),
        (
            "annotation_count",
            metric!("pdf.annotation_count"),
            types.annot,
        ),
        ("xobject_count", metric!("pdf.xobject_count"), types.xobject),
        ("font_count", metric!("pdf.font_count"), types.font),
        (
            "metadata_count",
            metric!("pdf.metadata_count"),
            types.metadata,
        ),
        ("objstm_count", metric!("pdf.objstm_count"), types.objstm),
        (
            "xref_stream_count",
            metric!("pdf.xref_stream_count"),
            types.xref,
        ),
        (
            "signature_object_count",
            metric!("pdf.signature_object_count"),
            types.sig,
        ),
        (
            "byte_range_count",
            metric!("pdf.byte_range_count"),
            scan.get(Tok::ByteRange).all,
        ),
        (
            "jbig2_filter_count",
            metric!("pdf.jbig2_filter_count"),
            scan.get(Tok::Jbig2Decode).all,
        ),
        (
            "three_d_object_count",
            metric!("pdf.three_d_object_count"),
            three_d,
        ),
    ];
    for (key, metric_key, count) in counts {
        if count > 0 {
            shape.insert(key.into(), json!(count));
            metrics.insert(metric_key, count as f64);
        }
    }
    values.insert_key(value_key!("pdf.shape"), JsonValue::Object(shape));

    // Trailing bytes after the *last* `%%EOF` marker — a common
    // padding pattern in malicious PDFs that smuggle a payload past
    // the parser. Counted relative to the last EOF only; multiple
    // EOFs are normal in incrementally-updated documents.
    let trailing = eof.last.map_or(0, |at| {
        bytes.len().saturating_sub(at + Tok::Eof.bytes().len())
    });
    if trailing > 0 {
        metrics.insert(metric!("pdf.trailing_bytes"), trailing as f64);
    }
}

/// Info dict — Title / Author / Creator / Producer / etc. live in a dict
/// referenced by `/Info` from the trailer. The indirect reference is not
/// resolved; the first occurrence of each standard key anywhere in the
/// file is surfaced as `pdf.info.<lowercased>`.
fn info_dict(bytes: &[u8], scan: &TokenScan, values: &mut Values) {
    let mut info = serde_json::Map::new();
    for (tok, key) in INFO_KEYS {
        let Some(at) = scan.get(tok).first_accepted else {
            continue;
        };
        if let Some(value) = value_after_key(bytes, at + tok.bytes().len())
            && !value.is_empty()
        {
            info.insert(key.to_string(), JsonValue::String(value));
        }
    }
    if !info.is_empty() {
        values.insert_key(value_key!("pdf.info"), JsonValue::Object(info));
    }
}

/// `pdf.actions[]` and its counts: action sites scanned strictly inside
/// object *dictionaries* (between `obj` and the first `stream`/`endobj`)
/// and inside object streams. Source attribution is best-effort: indirect
/// references are not followed back to named / annotation / acroform
/// sites, so heavily-staged PDFs may show fewer source labels than an
/// xref-aware parser would give. The `kind` and `snippet` fields stay
/// accurate.
fn action_sites(
    bytes: &[u8],
    regions: &[DictRegion],
    object_streams: &ObjectStreams,
    limits: &mut Limits,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Vec<Action> {
    // One site past the cap is read to tell a document that reaches it
    // from one that runs over.
    let mut actions = actions::scan_actions(bytes, regions, MAX_ACTIONS + 1);
    actions.extend(actions::objstm_actions(
        &object_streams.decoded,
        (MAX_ACTIONS + 1).saturating_sub(actions.len()),
    ));
    if actions.len() > MAX_ACTIONS {
        actions.truncate(MAX_ACTIONS);
        tracing::debug!(
            target: "filefacts::pdf",
            stage = "actions",
            cap = MAX_ACTIONS,
            "action sites past the cap not recorded"
        );
        limits.push(
            "action-cap",
            format!("action sites past the first {MAX_ACTIONS} not recorded"),
        );
    }
    if actions.is_empty() {
        return actions;
    }
    let of_kind = |kind: &str| actions.iter().filter(|a| a.kind == kind).count();
    let counts = [
        (
            metric!("pdf.javascript_action_count"),
            of_kind("javascript"),
        ),
        (metric!("pdf.uri_action_count"), of_kind("uri")),
        // URI actions whose path is a CMS upload directory. One such
        // citation is ordinary; a doorway is built out of many of them.
        (
            metric!("pdf.upload_directory_uri_count"),
            actions
                .iter()
                .filter(|a| a.kind == "uri")
                .filter(|a| {
                    let lower = a.snippet.to_ascii_lowercase();
                    lower.contains("/wp-content/uploads/")
                        || lower.contains("/system/files/webform/")
                })
                .count(),
        ),
    ];
    for (key, count) in counts {
        if count > 0 {
            metrics.insert(key, count as f64);
        }
    }
    metrics.insert(metric!("pdf.action_count"), actions.len() as f64);
    values.insert_key(
        value_key!("pdf.actions"),
        JsonValue::Array(
            actions
                .iter()
                .map(|a| json!({"kind": a.kind, "source": a.source, "snippet": a.snippet}))
                .collect(),
        ),
    );
    actions
}

/// `pdf.javascript[]` — one entry per `/JS` site resolved end-to-end
/// (inline literals, hex strings, and indirect references followed into
/// decoded streams). Distinct from `pdf.actions[]`, which keeps a short
/// truncated snippet for at-a-glance triage.
fn javascript(
    bytes: &[u8],
    regions: &[DictRegion],
    objects: &ObjectIndex<'_>,
    limits: &mut Limits,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let JsScan { payloads, limit } = actions::scan_javascript_payloads(bytes, regions, objects);
    if let Some(reason) = limit {
        limits.push("javascript-budget", reason);
    }
    if payloads.is_empty() {
        return;
    }
    // A repeat of an already-decoded target carries no content of its
    // own, so this totals distinct payload bytes.
    let total_bytes: u64 = payloads
        .iter()
        .filter(|v| v.get("content").is_some())
        .filter_map(|v| v.get("content_bytes").and_then(JsonValue::as_u64))
        .sum();
    metrics.insert(metric!("pdf.javascript_count"), payloads.len() as f64);
    metrics.insert(metric!("pdf.javascript_total_bytes"), total_bytes as f64);
    values.insert_key(value_key!("pdf.javascript"), JsonValue::Array(payloads));
}

/// `pdf.embedded_files[]` — `{filename, size}` per `/Type /Filespec`
/// record, `size` read by following `/EF /F <ref>` to the embedded-stream
/// object's `/Length`. Returns how many there are.
fn embedded_files(
    bytes: &[u8],
    regions: &[DictRegion],
    objects: &ObjectIndex<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
) -> usize {
    let embedded = actions::scan_embedded_files(bytes, regions, objects);
    if embedded.is_empty() {
        return 0;
    }
    metrics.insert(metric!("pdf.embedded_file_count"), embedded.len() as f64);
    let entries: Vec<JsonValue> = embedded
        .iter()
        .map(|(name, size)| match size {
            Some(size) => json!({"filename": name, "size": size}),
            None => json!({"filename": name}),
        })
        .collect();
    values.insert_key(value_key!("pdf.embedded_files"), JsonValue::Array(entries));
    embedded.len()
}

/// `pdf.filter_chains[]`, `pdf.streams[]` and `pdf.form_fields[]`: the
/// per-object inventories.
fn stream_inventory(
    bytes: &[u8],
    regions: &[DictRegion],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    // Deduplicated, since trait rules check whether a chain *appears*
    // anywhere, not how many times.
    let chains = filters::scan_filter_chains(bytes, regions);
    if !chains.is_empty() {
        values.insert_key(value_key!("pdf.filter_chains"), json!(chains));
    }
    let streams = streams::scan_streams(bytes, regions);
    if !streams.is_empty() {
        values.insert_key(value_key!("pdf.streams"), JsonValue::Array(streams));
    }
    let fields = forms::scan_form_fields(bytes, regions);
    forms::derive_form_field_metrics(&fields, metrics);
    if !fields.is_empty() {
        metrics.insert(metric!("pdf.form_field_count"), fields.len() as f64);
        values.insert_key(
            value_key!("pdf.form_fields"),
            JsonValue::Array(fields.iter().map(forms::FormField::to_json).collect()),
        );
    }
}

/// Structural metrics over the object regions: object-stream inner counts,
/// unreferenced objects, risky filters and stream framing.
fn object_metrics(bytes: &[u8], regions: &[DictRegion], metrics: &mut Metrics) {
    let inner = objects::object_stream_inner_count(bytes, regions);
    if inner > 0 {
        metrics.insert(
            metric!("pdf.object_stream_inner_object_count"),
            f64::from(inner),
        );
    }
    // Objects whose id never appears as the target of an `<id> <gen> R`
    // reference. Legitimate PDFs generally reference all their objects
    // through the catalog graph.
    let unreferenced = objects::unreferenced_object_count(bytes, regions);
    if unreferenced > 0 {
        metrics.insert(
            metric!("pdf.unreferenced_object_count"),
            f64::from(unreferenced),
        );
    }
    // Unusual filters — JBIG2, LZW, and Crypt. Each pulls in a
    // historically exploitable decoder path (CVE-2010-1297 et al).
    let unusual = streams::streams_with_unusual_filter_count(bytes, regions);
    if unusual > 0 {
        metrics.insert(
            metric!("pdf.streams_with_unusual_filter_count"),
            f64::from(unusual),
        );
    }
    streams::derive_stream_metrics(bytes, regions, metrics);
}

/// Composite "how dangerous does this PDF look?" score, 0-100: weighted
/// catalog features, plus one per action site (up to 20) and five per
/// embedded file (up to 20). The weights are part of the output contract;
/// rules set thresholds against them (`min: 70`).
fn risky_feature_score(features: &[&str], actions: usize, embedded: usize) -> u32 {
    let feature_score: u32 = features
        .iter()
        .map(|&name| match name {
            "openaction" | "xfa" => 20,
            "additional_actions" | "3d" => 15,
            "names_javascript" | "richmedia" => 25,
            "acroform" => 5,
            _ => 0,
        })
        .sum();
    let usage = crate::bytes::sat_u32(actions.min(20) + embedded.saturating_mul(5).min(20));
    (feature_score + usage).min(100)
}

#[cfg(test)]
mod tests;
