//! OOXML (`.docx`/`.xlsx`/`.pptx`/`.docm`/…) extractor.
//!
//! OOXML files are ZIP archives with a fixed internal layout: a top-level
//! `[Content_Types].xml` manifests every content stream by MIME type,
//! `docProps/core.xml` carries the Dublin Core metadata pane, and
//! `docProps/app.xml` carries the originating application info. Macros
//! live under `*/vbaProject.bin` and the `[Content_Types].xml` MIME
//! string distinguishes the document variant (Word / Excel /
//! PowerPoint, with-macros vs without).
//!
//! Layered on the same ZIP handle used by the generic archive walk,
//! after it has emitted `archive.members[]` and `archive.compression.*`.
//! This module reads a small number of named streams and surfaces an `office.*`
//! schema for trait rules:
//!
//! - `office.kind` — `"docx" | "xlsx" | "pptx" | "ooxml"` from the
//!   `[Content_Types].xml` document-type declaration.
//! - `office.{title, creator, last_modified_by, created, modified,
//!   subject, description, keywords, category}` — Dublin Core fields
//!   from `docProps/core.xml`.
//! - `office.application`, `office.company` — from `docProps/app.xml`.
//! - `office.features[]` — Pike-style array of structural features
//!   (`"macros"`, `"external_template"`, `"ole_objects"`, …).
//! - `office.macros[]` — paths of `vbaProject.bin` streams when
//!   present (one per OOXML application; usually a single entry).

use crate::metric;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use crate::bytes::ends_with_ci;
use crate::formats::bounded::Limits;
use crate::formats::common::{embedded_kind, put_str};
use crate::output::{DiagnosticKind, Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// Read cap for the named parts the `office.*` layer is built from.
/// `[Content_Types].xml` and the `.rels` parts grow with the part count, so
/// an ordinary large package runs to hundreds of KiB, and a cut-off XML part
/// only fails to parse, taking everything derived from it along. The cap
/// sits with the crate's other manifest caps rather than at a typical size.
const MAX_PART_BYTES: u64 = 4 << 20;

/// Read cap for each `.xml` part in the DDE / customUI scan, which visits
/// every part rather than a named few.
const MAX_SCAN_PART_BYTES: u64 = 1 << 20;

/// Inflated bytes the DDE / customUI scan reads across every part, a part
/// refused at its cap counting as the cap.
const MAX_SCAN_TOTAL_BYTES: u64 = 32 << 20;

/// Inflated `.rels` bytes read across the package, a part refused at its
/// cap counting as the cap. Every relationship part is read, and each may
/// be a 4 MiB deflate bomb: thousands of them took minutes to inflate and
/// parse.
const MAX_RELS_TOTAL_BYTES: u64 = 16 << 20;

/// Relationships kept per package. A 4 MiB part holds 150,000 of them, each
/// a few hundred bytes once parsed, so a package of such parts built tens of
/// gigabytes. Real packages carry a few thousand.
const MAX_RELATIONSHIPS: usize = 65_536;

/// Element names the DDE and customUI scans match on. A part naming none of
/// them has nothing for either, and is not parsed.
const SCAN_MARKERS: [&str; 4] = ["fldSimple", "instrText", "ddeLink", "customUI"];

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // Part names straight from the central directory. Opening each entry
    // would set up a decompressor per member just to read its name, and
    // silently drop the names of entries it cannot open (an encrypted
    // `vbaProject.bin`). Capped like the archive walk's member listing:
    // every later pass is per name.
    let names: Vec<String> = zip
        .file_names()
        .filter_map(Result::ok)
        .take(super::bounded::MAX_ARCHIVE_MEMBERS)
        .map(std::borrow::Cow::into_owned)
        .collect();
    let Some(index) = build_ooxml_index(zip, &names, errors) else {
        return;
    };

    let Some(kind) = detect_kind(&index) else {
        return;
    };
    put_str(values, value_key!("office.kind"), kind);

    if let Some(core) = parse_core_props(zip, errors) {
        for (key, value) in core {
            values.insert_key(key, value);
        }
    }

    let (app, company) = parse_app_props(zip, errors).unwrap_or_default();
    if let Some(app) = app {
        put_str(values, value_key!("office.application"), app);
    }
    if let Some(company) = company {
        put_str(values, value_key!("office.company"), company);
    }

    let mut features: Vec<&'static str> = Vec::new();
    let mut macros_seen = BTreeSet::new();
    let mut macros: Vec<JsonValue> = Vec::new();
    let mut embedded_seen = HashMap::new();
    let mut embedded: Vec<JsonValue> = Vec::new();
    let mut controls_seen = HashSet::new();
    let mut controls: Vec<JsonValue> = Vec::new();

    // The package's own pointer to its VBA project is a `vbaProject`
    // relationship, so those targets come first: VBA extraction reads the
    // first entry. A content type that only comes from a `Default` extension
    // mapping is weaker evidence. Word writes `bin` -> vbaProject in every
    // macro-enabled document, and that mapping also covers any other `.bin`
    // part without an override: an embedded OLE object, printer settings.
    for rel in &index.relationships {
        if is_macro_relationship(&rel.short_type) {
            let target = rel.target_part.as_deref().unwrap_or(&rel.target);
            push_unique_string(&mut macros_seen, &mut macros, target);
        }
    }
    let has_macro_relationship = !macros.is_empty();
    let other_targets: HashSet<&str> = index
        .relationships
        .iter()
        .filter(|rel| !is_macro_relationship(&rel.short_type))
        .filter_map(|rel| rel.target_part.as_deref())
        .collect();
    for name in &names {
        let content_type = index.content_type_for(name).unwrap_or_default();
        let declared_macro = match index.override_for(name) {
            Some(content_type) => is_macro_content_type(content_type),
            // Only by `Default`: trust it when nothing names the project
            // and nothing says this part is something else.
            None => {
                !has_macro_relationship
                    && !other_targets.contains(name.as_str())
                    && is_macro_content_type(content_type)
            }
        };
        if declared_macro || name.ends_with("/vbaProject.bin") || name == "vbaProject.bin" {
            push_unique_string(&mut macros_seen, &mut macros, name);
        }
        if content_type.contains("vnd.ms-office.activeX") {
            push_control(&mut controls_seen, &mut controls, name, "active_x", None);
        }
        if name.contains("/embeddings/") {
            push_feature(&mut features, "ole_objects");
            push_embedded(zip, &mut embedded_seen, &mut embedded, name, None, None);
        }
        if name.starts_with("xl/externalLinks/") {
            push_feature(&mut features, "external_links");
        }
    }

    package_stats(zip, &names, metrics);

    for rel in &index.relationships {
        match rel.short_type.as_str() {
            short_type @ ("oleObject" | "package") => {
                let feature = if short_type == "package" {
                    "embedded_packages"
                } else {
                    "ole_objects"
                };
                push_feature(&mut features, feature);
                if let Some(target) = rel.target_part.as_deref() {
                    push_embedded(
                        zip,
                        &mut embedded_seen,
                        &mut embedded,
                        target,
                        Some(short_type),
                        Some(&rel.source),
                    );
                }
            }
            "control" => {
                push_feature(&mut features, "active_x");
                if let Some(target) = rel.target_part.as_deref() {
                    push_control(
                        &mut controls_seen,
                        &mut controls,
                        target,
                        "active_x",
                        Some(&rel.source),
                    );
                }
            }
            "externalLink" => push_feature(&mut features, "external_links"),
            _ => {}
        }
    }

    if !embedded.is_empty() {
        let count = embedded.len() as f64;
        let exec_count = embedded
            .iter()
            .filter(|e| {
                e.get("kind")
                    .and_then(|x| x.as_str())
                    .is_some_and(|k| matches!(k, "pe" | "elf" | "macho"))
            })
            .count() as f64;
        values.insert_key(value_key!("office.embedded"), JsonValue::Array(embedded));
        metrics.insert(metric!("office.embedded_count"), count);
        if exec_count > 0.0 {
            metrics.insert(metric!("office.embedded_executable_count"), exec_count);
            push_feature(&mut features, "embedded_executable");
        }
    }

    if !controls.is_empty() {
        let count = controls.len() as f64;
        values.insert_key(value_key!("office.controls"), JsonValue::Array(controls));
        metrics.insert(metric!("office.control_count"), count);
        push_feature(&mut features, "active_x");
    }

    let external_relationships: Vec<JsonValue> = index
        .relationships
        .iter()
        .filter(|rel| rel.mode.as_deref() == Some("External") || is_external_target(&rel.target))
        .map(external_relationship_value)
        .collect();
    // The injection vectors (CVE-2017-0199 and kin) load a remote object,
    // frame or sub-document; a local target or a hyperlink is no vector.
    let remote = |types: &[&str]| {
        index
            .relationships
            .iter()
            .filter(|rel| types.contains(&rel.short_type.as_str()))
            .filter(|rel| workbook::is_remote_target(&rel.target))
            .count()
    };
    for (key, count) in [
        (
            metric!("office.external_oleobject_count"),
            remote(&["oleObject"]),
        ),
        (
            metric!("office.external_frame_count"),
            remote(&["frame", "subDocument"]),
        ),
    ] {
        if count > 0 {
            metrics.insert(key, count as f64);
        }
    }
    if !external_relationships.is_empty() {
        let count = external_relationships.len() as f64;
        values.insert_key(
            value_key!("office.external_relationships"),
            JsonValue::Array(external_relationships),
        );
        metrics.insert(metric!("office.external_relationship_count"), count);
        push_feature(&mut features, "external_relationships");
    }

    if !macros.is_empty() {
        push_feature(&mut features, "macros");
        let count = macros.len() as f64;
        // Uncompressed bytes of the VBA project. A project someone wrote is
        // tens of kilobytes; the padding that hides a payload, or defeats a
        // scanner's size limit, shows up here and nowhere else -- the
        // document itself stays small because the padding compresses away.
        let vba_bytes: u64 = macros
            .iter()
            .filter_map(|m| m.as_str())
            .filter_map(|name| zip.by_name(name).ok().map(|e| e.size()))
            .sum();
        if vba_bytes > 0 {
            metrics.insert(metric!("office.vba.project_size"), vba_bytes as f64);
        }
        values.insert_key(value_key!("office.macros"), JsonValue::Array(macros));
        metrics.insert(metric!("office.macro_count"), count);
    }

    let mut dde_links: Vec<JsonValue> = Vec::new();
    let mut custom_ui_onload: Vec<JsonValue> = Vec::new();
    let mut xlm_calls = workbook::XlmCalls::default();
    let mut book: Option<workbook::Workbook> = None;
    // Oversized parts are routine (a long document, a big sheet). They are a
    // coverage limit, not a parse failure, so they land in `office.limits`
    // like the other archive walkers' limits and stay out of `errors` (which
    // traits read as "the parser failed").
    let mut oversized_parts = 0usize;
    // Every `.xml` part is a candidate, so the scan as a whole needs a bound
    // too: thousands of 1 MiB parts would each be inflated and parsed.
    let mut scan_budget = MAX_SCAN_TOTAL_BYTES;
    let mut unscanned_parts = 0usize;
    for name in &names {
        // OPC part names compare case-insensitively (ECMA-376 Part 2 §9.1.1.1):
        // Office opens `word/document.XML` like `word/document.xml`.
        if !ends_with_ci(name, ".xml") || ends_with_ci(name, ".rels") {
            continue;
        }
        if scan_budget == 0 {
            unscanned_parts += 1;
            continue;
        }
        let text = match read_part(zip, name, MAX_SCAN_PART_BYTES) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(e) => {
                // A refused part may have been inflated up to the cap first.
                scan_budget = scan_budget.saturating_sub(MAX_SCAN_PART_BYTES);
                match e {
                    PartError::TooLarge => oversized_parts += 1,
                    PartError::Unreadable(why) => {
                        errors.record_malformed(Stage::OoxmlParse, format!("{name}: {why}"));
                    }
                }
                continue;
            }
        };
        scan_budget = scan_budget.saturating_sub(text.len() as u64);
        if workbook::is_macrosheet(name) {
            xlm_calls.add(&text);
        }
        if index
            .content_type_for(name)
            .is_some_and(is_workbook_content_type)
        {
            match roxmltree::Document::parse(&text) {
                Ok(doc) => book = Some(workbook::parse(&doc)),
                Err(e) => errors.record_malformed(Stage::OoxmlParse, format!("{name}: {e}")),
            }
        }
        // Most parts carry neither: skip the parse unless an element either
        // scan looks for is named. Element names cannot be written as
        // character references, so a plain search finds every candidate.
        if !SCAN_MARKERS.iter().any(|m| text.contains(m)) {
            continue;
        }
        let doc = match roxmltree::Document::parse(&text) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::debug!(
                    target: "filefacts::ooxml",
                    stage = "part-scan",
                    part = name.as_str(),
                    error = %e,
                    "part names a DDE or customUI element but does not parse"
                );
                continue;
            }
        };
        dde_links.extend(extract_dde_links(&doc, name));
        custom_ui_onload.extend(extract_custom_ui_onload(&doc, name));
    }
    let mut limits = Limits::default();
    if index.unread_rels > 0 {
        limits.push(
            "rels-budget",
            format!(
                "{} relationship part(s) not read in full: past the {MAX_RELS_TOTAL_BYTES}-byte \
                 or {MAX_RELATIONSHIPS}-relationship budget",
                index.unread_rels
            ),
        );
    }
    if oversized_parts > 0 {
        limits.push(
            "part-scan",
            format!(
                "{oversized_parts} XML part(s) over the {MAX_SCAN_PART_BYTES}-byte scan cap \
                 not searched for DDE links or customUI onLoad"
            ),
        );
    }
    if unscanned_parts > 0 {
        limits.push(
            "part-scan-budget",
            format!(
                "{unscanned_parts} XML part(s) past the {MAX_SCAN_TOTAL_BYTES}-byte scan budget \
                 not searched for DDE links or customUI onLoad"
            ),
        );
    }
    limits.emit(values, value_key!("office.limits"));
    xlm_calls.emit(metrics);
    if let Some(book) = book {
        workbook::emit(book, values, metrics, &mut features);
    }
    if !dde_links.is_empty() {
        let count = dde_links.len() as f64;
        values.insert_key(value_key!("office.dde_links"), JsonValue::Array(dde_links));
        metrics.insert(metric!("office.dde_link_count"), count);
        push_feature(&mut features, "dde_links");
    }
    if !custom_ui_onload.is_empty() {
        let count = custom_ui_onload.len() as f64;
        values.insert_key(
            value_key!("office.custom_ui_onload"),
            JsonValue::Array(custom_ui_onload),
        );
        metrics.insert(metric!("office.custom_ui_onload_count"), count);
        push_feature(&mut features, "custom_ui_onload");
    }

    if !features.is_empty() {
        values.insert_key(
            value_key!("office.features"),
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
}

#[derive(Debug, Default)]
struct OoxmlIndex {
    defaults: HashMap<String, String>,
    overrides: HashMap<String, String>,
    relationships: Vec<RelationshipInfo>,
    /// `.rels` parts skipped or cut short by the relationship budgets.
    unread_rels: usize,
}

#[derive(Debug)]
struct RelationshipInfo {
    source: String,
    rels_source: String,
    target: String,
    target_part: Option<String>,
    rel_type: String,
    short_type: String,
    mode: Option<String>,
}

impl OoxmlIndex {
    /// The content type an `Override` gives this part, if any.
    fn override_for(&self, name: &str) -> Option<&str> {
        self.overrides
            .get(name.trim_start_matches('/'))
            .map(String::as_str)
    }

    /// The content type of this part: its `Override`, else the `Default`
    /// for its extension.
    fn content_type_for(&self, name: &str) -> Option<&str> {
        if let Some(content_type) = self.override_for(name) {
            return Some(content_type);
        }
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        self.defaults.get(&ext).map(String::as_str)
    }
}

/// Content types plus every relationship. `None` means no OOXML layer at all,
/// so a `[Content_Types].xml` that is present but unusable is recorded first.
fn build_ooxml_index<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    names: &[String],
    errors: &mut Errors,
) -> Option<OoxmlIndex> {
    const CONTENT_TYPES: &str = "[Content_Types].xml";
    let content_types = read_named_part(zip, CONTENT_TYPES, errors)?;
    let mut index = parse_content_types(&content_types)
        .map_err(|e| errors.record_malformed(Stage::OoxmlParse, format!("{CONTENT_TYPES}: {e}")))
        .ok()?;
    let mut budget = MAX_RELS_TOTAL_BYTES;
    for name in names {
        if !ends_with_ci(name, ".rels") {
            continue;
        }
        if budget == 0 || index.relationships.len() >= MAX_RELATIONSHIPS {
            index.unread_rels += 1;
            continue;
        }
        let text = match read_part(zip, name, MAX_PART_BYTES) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(e) => {
                // A refused part may have been inflated up to the cap first.
                budget = budget.saturating_sub(MAX_PART_BYTES);
                record_part_error(errors, name, e);
                continue;
            }
        };
        budget = budget.saturating_sub(text.len() as u64);
        match parse_relationships(&text, name) {
            Ok(rels) => {
                let room = MAX_RELATIONSHIPS - index.relationships.len();
                if rels.len() > room {
                    index.unread_rels += 1;
                }
                index.relationships.extend(rels.into_iter().take(room));
            }
            Err(e) => errors.record_malformed(Stage::OoxmlParse, format!("{name}: {e}")),
        }
    }
    Some(index)
}

fn parse_content_types(xml: &str) -> Result<OoxmlIndex, roxmltree::Error> {
    let doc = roxmltree::Document::parse(xml)?;
    let mut index = OoxmlIndex::default();
    for node in doc.descendants() {
        match node.tag_name().name() {
            "Default" => {
                let Some(ext) = node.attribute("Extension") else {
                    continue;
                };
                let Some(content_type) = node.attribute("ContentType") else {
                    continue;
                };
                index
                    .defaults
                    .insert(ext.to_ascii_lowercase(), content_type.to_string());
            }
            "Override" => {
                let Some(part) = node.attribute("PartName") else {
                    continue;
                };
                let Some(content_type) = node.attribute("ContentType") else {
                    continue;
                };
                index.overrides.insert(
                    part.trim_start_matches('/').to_string(),
                    content_type.to_string(),
                );
            }
            _ => {}
        }
    }
    Ok(index)
}

fn parse_relationships(
    xml: &str,
    rels_source: &str,
) -> Result<Vec<RelationshipInfo>, roxmltree::Error> {
    let doc = roxmltree::Document::parse(xml)?;
    let source = relationship_source_part(rels_source);
    let mut out = Vec::new();
    for node in doc.descendants() {
        if node.tag_name().name() != "Relationship" {
            continue;
        }
        let Some(target) = node.attribute("Target") else {
            continue;
        };
        let rel_type = node.attribute("Type").unwrap_or_default().to_string();
        let short_type = rel_type
            .rsplit('/')
            .next()
            .unwrap_or(rel_type.as_str())
            .to_string();
        let mode = node.attribute("TargetMode").map(str::to_string);
        let target_part = if mode.as_deref() == Some("External") || is_external_target(target) {
            None
        } else {
            resolve_relationship_target(&source, target)
        };
        out.push(RelationshipInfo {
            source: source.clone(),
            rels_source: rels_source.to_string(),
            target: target.to_string(),
            target_part,
            rel_type,
            short_type,
            mode,
        });
    }
    Ok(out)
}

fn relationship_source_part(rels_source: &str) -> String {
    if rels_source == "_rels/.rels" {
        return String::new();
    }
    let Some((prefix, file)) = rels_source.rsplit_once("/_rels/") else {
        return String::new();
    };
    let source_name = file.strip_suffix(".rels").unwrap_or(file);
    if prefix.is_empty() {
        source_name.to_string()
    } else {
        format!("{prefix}/{source_name}")
    }
}

fn resolve_relationship_target(source: &str, target: &str) -> Option<String> {
    let target = target.trim();
    if target.is_empty() || target.eq_ignore_ascii_case("NULL") {
        return None;
    }
    let joined = if target.starts_with('/') {
        target.trim_start_matches('/').to_string()
    } else if let Some((dir, _)) = source.rsplit_once('/') {
        format!("{dir}/{target}")
    } else {
        target.to_string()
    };
    normalize_part_name(&joined)
}

fn normalize_part_name(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn push_feature(features: &mut Vec<&'static str>, feature: &'static str) {
    if !features.contains(&feature) {
        features.push(feature);
    }
}

fn push_unique_string(seen: &mut BTreeSet<String>, out: &mut Vec<JsonValue>, value: &str) {
    if seen.insert(value.to_string()) {
        out.push(JsonValue::String(value.to_string()));
    }
}

fn push_control(
    seen: &mut HashSet<String>,
    out: &mut Vec<JsonValue>,
    filename: &str,
    kind: &str,
    source: Option<&str>,
) {
    if !seen.insert(filename.to_string()) {
        return;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("filename".into(), JsonValue::String(filename.to_string()));
    obj.insert("kind".into(), JsonValue::String(kind.to_string()));
    if let Some(source) = source {
        obj.insert("source".into(), JsonValue::String(source.to_string()));
    }
    out.push(JsonValue::Object(obj));
}

/// Record an embedded part once, keyed in `seen` by filename to its entry
/// in `out`; a later relationship naming the same part updates that entry.
/// The lookup is by key: a scan of `out` per repeated relationship made a
/// package of them quadratic.
fn push_embedded<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    seen: &mut HashMap<String, usize>,
    out: &mut Vec<JsonValue>,
    filename: &str,
    relationship_type: Option<&str>,
    source: Option<&str>,
) {
    let at = match seen.get(filename) {
        Some(&at) => at,
        None => {
            let mut obj = serde_json::Map::new();
            obj.insert("filename".into(), JsonValue::String(filename.to_string()));
            if let Ok(mut entry) = zip.by_name(filename) {
                obj.insert("size_bytes".into(), JsonValue::Number(entry.size().into()));
                let mut header = [0u8; 8];
                let n = entry.read(&mut header).unwrap_or_else(|e| {
                    tracing::debug!(
                        target: "filefacts::ooxml",
                        stage = "embedded",
                        part = filename,
                        error = %e,
                        "embedded part unreadable; kind not classified"
                    );
                    0
                });
                if let Some(kind) = embedded_kind(header.get(..n).unwrap_or_default()) {
                    obj.insert("kind".into(), JsonValue::String(kind.into()));
                }
            }
            seen.insert(filename.to_string(), out.len());
            out.push(JsonValue::Object(obj));
            out.len() - 1
        }
    };
    let Some(obj) = out.get_mut(at).and_then(JsonValue::as_object_mut) else {
        return;
    };
    if let Some(relationship_type) = relationship_type {
        obj.insert(
            "relationship_type".into(),
            JsonValue::String(relationship_type.to_string()),
        );
    }
    if let Some(source) = source {
        obj.insert("source".into(), JsonValue::String(source.to_string()));
    }
}

/// Whether `content_type` is a SpreadsheetML workbook's main part (`.xlsx`,
/// `.xlsm`, templates and add-ins).
fn is_workbook_content_type(content_type: &str) -> bool {
    content_type.ends_with(".main+xml")
        && (content_type.contains("spreadsheetml") || content_type.contains("ms-excel"))
}

/// Package-level part statistics: the largest part (the padding that
/// inflates a payload past a scanner's size limit compresses away, so it
/// shows only uncompressed), the image parts a lure is built from, and the
/// parts named like something to run.
fn package_stats<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    names: &[String],
    metrics: &mut Metrics,
) {
    const RUNNABLE: [&str; 8] = ["exe", "dll", "hta", "lnk", "bat", "js", "scr", "vbs"];
    let max_entry_size = (0..zip.len().min(names.len()))
        .filter_map(|i| zip.by_index_raw(i).ok().map(|entry| entry.size()))
        .max()
        .unwrap_or(0);
    let image_parts = names
        .iter()
        .filter(|n| {
            ["word/media/", "xl/media/", "ppt/media/"]
                .iter()
                .any(|p| n.starts_with(p))
        })
        .count();
    let runnable_parts = names
        .iter()
        .filter(|n| {
            n.rsplit_once('.')
                .is_some_and(|(_, ext)| RUNNABLE.iter().any(|r| ext.eq_ignore_ascii_case(r)))
        })
        .count();
    metrics.insert(
        metric!("office.ooxml.max_entry_size"),
        max_entry_size as f64,
    );
    for (key, count) in [
        (metric!("office.ooxml.image_part_count"), image_parts),
        (
            metric!("office.ooxml.suspicious_extension_count"),
            runnable_parts,
        ),
    ] {
        if count > 0 {
            metrics.insert(key, count as f64);
        }
    }
}

fn is_macro_relationship(short_type: &str) -> bool {
    matches!(short_type, "vbaProject" | "xlIntlMacrosheet")
}

fn is_macro_content_type(content_type: &str) -> bool {
    content_type.contains("vbaProject") || content_type.contains("intlmacrosheet")
}

fn external_relationship_value(rel: &RelationshipInfo) -> JsonValue {
    let mut obj = serde_json::Map::new();
    obj.insert("type".into(), JsonValue::String(rel.short_type.clone()));
    obj.insert("target".into(), JsonValue::String(rel.target.clone()));
    obj.insert("source".into(), JsonValue::String(rel.rels_source.clone()));
    if !rel.source.is_empty() {
        obj.insert("part".into(), JsonValue::String(rel.source.clone()));
    }
    if !rel.rel_type.is_empty() {
        obj.insert(
            "relationship".into(),
            JsonValue::String(rel.rel_type.clone()),
        );
    }
    if let Some(mode) = &rel.mode {
        obj.insert("mode".into(), JsonValue::String(mode.clone()));
    }
    JsonValue::Object(obj)
}

/// Read `[Content_Types].xml` and map its primary content type onto a
/// short OOXML variant label. Falls back to `"ooxml"` for OOXML files
/// we don't have a more specific label for (Visio, custom packages, …).
fn detect_kind(index: &OoxmlIndex) -> Option<&'static str> {
    let all_types = index
        .overrides
        .values()
        .chain(index.defaults.values())
        .map(String::as_str);
    let mut saw_ooxml_type = false;
    for content_type in all_types {
        saw_ooxml_type = true;
        if content_type.contains("wordprocessingml.document")
            || content_type.contains("wordprocessingml.template")
            || content_type.contains("ms-word.document")
            || content_type.contains("ms-word.template")
        {
            return Some("docx");
        }
        if content_type.contains("spreadsheetml.sheet")
            || content_type.contains("spreadsheetml.template")
            || content_type.contains("ms-excel.sheet")
            || content_type.contains("ms-excel.template")
            || content_type.contains("ms-excel.addin")
        {
            return Some("xlsx");
        }
        if content_type.contains("presentationml.presentation")
            || content_type.contains("presentationml.template")
            || content_type.contains("presentationml.slideshow")
            || content_type.contains("ms-powerpoint.presentation")
            || content_type.contains("ms-powerpoint.template")
            || content_type.contains("ms-powerpoint.slideshow")
        {
            return Some("pptx");
        }
    }
    saw_ooxml_type.then_some("ooxml")
}

/// Parse `docProps/core.xml` into a Map of canonical Dublin Core
/// fields. Empty values are dropped so a trait `exists:` check is
/// meaningful.
fn parse_core_props<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    errors: &mut Errors,
) -> Option<BTreeMap<ValueKey, JsonValue>> {
    const CORE: &str = "docProps/core.xml";
    let text = read_named_part(zip, CORE, errors)?;
    let doc = roxmltree::Document::parse(&text)
        .map_err(|e| errors.record_malformed(Stage::OoxmlParse, format!("{CORE}: {e}")))
        .ok()?;
    let mut out = BTreeMap::new();
    for node in doc.descendants() {
        let name = node.tag_name().name();
        // Dublin Core elements live in two namespaces (`dc:` and
        // `cp:`); `tag_name().name()` strips the prefix so we match
        // by local-name alone.
        let key = match name {
            "title" => value_key!("office.title"),
            "creator" => value_key!("office.creator"),
            "subject" => value_key!("office.subject"),
            "description" => value_key!("office.description"),
            "keywords" => value_key!("office.keywords"),
            "lastModifiedBy" => value_key!("office.last_modified_by"),
            "created" => value_key!("office.created"),
            "modified" => value_key!("office.modified"),
            "category" => value_key!("office.category"),
            "contentStatus" => value_key!("office.content_status"),
            "revision" => value_key!("office.revision"),
            _ => continue,
        };
        let Some(text) = node.text() else {
            continue;
        };
        let trimmed = text.trim();
        if !trimmed.is_empty() && !out.contains_key(&key) {
            out.insert(key, JsonValue::String(trimmed.to_string()));
        }
    }
    Some(out)
}

/// Parse `docProps/app.xml` for the `Application` (e.g. "Microsoft
/// Macintosh Word") and `Company` strings. Optional both —
/// hand-rolled OOXML packages (LibreOffice exports, GitHub Actions
/// generators, …) often skip `app.xml` entirely.
fn parse_app_props<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    errors: &mut Errors,
) -> Option<(Option<String>, Option<String>)> {
    const APP: &str = "docProps/app.xml";
    let text = read_named_part(zip, APP, errors)?;
    let doc = roxmltree::Document::parse(&text)
        .map_err(|e| errors.record_malformed(Stage::OoxmlParse, format!("{APP}: {e}")))
        .ok()?;
    let mut application: Option<String> = None;
    let mut company: Option<String> = None;
    for node in doc.descendants() {
        match node.tag_name().name() {
            "Application" => application = node.text().map(|s| s.trim().to_string()),
            "Company" => company = node.text().map(|s| s.trim().to_string()),
            _ => {}
        }
    }
    Some((
        application.filter(|s| !s.is_empty()),
        company.filter(|s| !s.is_empty()),
    ))
}

/// True when a relationship target points at something outside the archive.
fn is_external_target(target: &str) -> bool {
    let t = target.trim();
    if t.is_empty() {
        return false;
    }
    if t.starts_with("\\\\") || t.starts_with("//") {
        return true;
    }
    let Some(colon) = t.find(':') else {
        return false;
    };
    if colon == 1 && t.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    t[..colon].bytes().enumerate().all(|(i, b)| {
        b.is_ascii_alphabetic()
            || (i > 0 && (b.is_ascii_digit() || b == b'+' || b == b'.' || b == b'-'))
    })
}

fn extract_dde_links(doc: &roxmltree::Document<'_>, source: &str) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for node in doc.descendants() {
        match node.tag_name().name() {
            "fldSimple" => {
                for attr in node.attributes() {
                    if attr.name() == "instr" {
                        push_dde_field(&mut out, source, attr.value());
                    }
                }
            }
            "instrText" => {
                if let Some(text) = node.text() {
                    push_dde_field(&mut out, source, text);
                }
            }
            "ddeLink" => {
                let mut obj = serde_json::Map::new();
                obj.insert("source".into(), JsonValue::String(source.to_string()));
                obj.insert("kind".into(), JsonValue::String("excel".into()));
                for attr in node.attributes() {
                    match attr.name() {
                        "ddeService" => {
                            obj.insert(
                                "service".into(),
                                JsonValue::String(attr.value().to_string()),
                            );
                        }
                        "ddeTopic" => {
                            obj.insert("topic".into(), JsonValue::String(attr.value().to_string()));
                        }
                        _ => {}
                    }
                }
                out.push(JsonValue::Object(obj));
            }
            _ => {}
        }
    }
    out
}

fn push_dde_field(out: &mut Vec<JsonValue>, source: &str, text: &str) {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("dde ")
        || lower.starts_with("ddeauto ")
        || lower == "dde"
        || lower == "ddeauto")
    {
        return;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("source".into(), JsonValue::String(source.to_string()));
    obj.insert("kind".into(), JsonValue::String("field".into()));
    obj.insert("text".into(), JsonValue::String(trimmed.to_string()));
    out.push(JsonValue::Object(obj));
}

fn extract_custom_ui_onload(doc: &roxmltree::Document<'_>, source: &str) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for node in doc.descendants() {
        if node.tag_name().name() != "customUI" {
            continue;
        }
        let Some(on_load) = node.attribute("onLoad") else {
            continue;
        };
        let trimmed = on_load.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut obj = serde_json::Map::new();
        obj.insert("source".into(), JsonValue::String(source.to_string()));
        obj.insert("on_load".into(), JsonValue::String(trimmed.to_string()));
        out.push(JsonValue::Object(obj));
    }
    out
}

/// Why a part that is present could not be handed to the XML parser.
enum PartError {
    /// Over the read cap. A cut-off XML part only fails to parse, so an
    /// oversized one is not read at all.
    TooLarge,
    /// Unreadable (a corrupt or encrypted entry) or not UTF-8/UTF-16 text.
    Unreadable(String),
}

/// Read a part as text, up to `max_bytes`. `Ok(None)` is a part that is not
/// in the package, which is normal: most parts are optional.
fn read_part<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Result<Option<String>, PartError> {
    let buf = match super::zip::read_member(zip, name, max_bytes) {
        Ok(Some(buf)) => buf,
        Ok(None) => return Ok(None),
        Err(super::zip::MemberError::TooLarge { .. }) => return Err(PartError::TooLarge),
        Err(e) => return Err(PartError::Unreadable(e.to_string())),
    };
    decode_xml_bytes(buf)
        .map(Some)
        .ok_or_else(|| PartError::Unreadable("not UTF-8 or UTF-16 text".into()))
}

/// [`read_part`] for a named part whose loss empties part of the `office.*`
/// layer, so a failure is recorded rather than dropped.
fn read_named_part<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
    errors: &mut Errors,
) -> Option<String> {
    read_part(zip, name, MAX_PART_BYTES)
        .map_err(|e| record_part_error(errors, name, e))
        .ok()
        .flatten()
}

/// Record why the named part `name` was not read.
fn record_part_error(errors: &mut Errors, name: &str, e: PartError) {
    match e {
        PartError::TooLarge => errors.record(
            DiagnosticKind::Truncated,
            Stage::OoxmlParse,
            format!("{name}: over the {MAX_PART_BYTES}-byte read cap; not parsed"),
        ),
        PartError::Unreadable(why) => {
            errors.record_malformed(Stage::OoxmlParse, format!("{name}: {why}"));
        }
    }
}

fn decode_xml_bytes(buf: Vec<u8>) -> Option<String> {
    if let Some(rest) = buf.strip_prefix(&[0xFF, 0xFE]) {
        return crate::bytes::utf16_strict(rest, crate::bytes::Endian::Little);
    }
    if let Some(rest) = buf.strip_prefix(&[0xFE, 0xFF]) {
        return crate::bytes::utf16_strict(rest, crate::bytes::Endian::Big);
    }
    // No BOM: an XML declaration spelled in UTF-16 still gives it away.
    if buf.len() >= 8 && buf.starts_with(&[b'<', 0, b'?', 0]) {
        return crate::bytes::utf16_strict(&buf, crate::bytes::Endian::Little);
    }
    if buf.len() >= 8 && buf.starts_with(&[0, b'<', 0, b'?']) {
        return crate::bytes::utf16_strict(&buf, crate::bytes::Endian::Big);
    }
    String::from_utf8(buf).ok()
}

mod workbook;

#[cfg(test)]
mod tests;
