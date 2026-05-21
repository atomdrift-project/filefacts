//! End-to-end tests against synthetic and real fixtures.
//!
//! Every test here asserts the no-duplicate-work guarantee
//! (`parse_count() == 1` after exercising all views) so the contract
//! holds for downstream embedders.

use expose::{open, open_with_path, FileType};

#[test]
fn json_manifest_parses_once_through_all_views() {
    let bytes = br#"{"name":"sample","version":"1.0.0","scripts":{"preinstall":"echo hi"}}"#;
    let parsed = open_with_path(std::path::Path::new("package.json"), bytes).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::PackageJson);

    let values = parsed.values();
    let strings = parsed.strings();
    let metrics = parsed.metrics();

    assert_eq!(values.get("name").and_then(|v| v.as_str()), Some("sample"));
    assert_eq!(
        values.get("scripts.preinstall").and_then(|v| v.as_str()),
        Some("echo hi")
    );
    assert_eq!(
        strings.len(),
        0,
        "JSON manifests do not emit ASCII runs in v1"
    );
    assert!(metrics.get("file.size_bytes").unwrap() > 0.0);

    assert_eq!(
        parsed.parse_count(),
        1,
        "all three views must share a single extraction pass"
    );
}

#[test]
fn zip_archive_emits_member_listing_and_aggregates() {
    // Hand-build a minimal ZIP with three regular-file entries so we
    // don't depend on an external fixture for an integration test.
    let bytes = build_minimal_zip();
    let parsed = open(&bytes).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::Zip);

    let values = parsed.values();
    let metrics = parsed.metrics();

    let members = values
        .get("archive.members")
        .and_then(|v| v.as_array())
        .expect("archive.members should be present");
    assert_eq!(members.len(), 3);

    assert_eq!(metrics.get("archive.member_count"), Some(3.0));
    assert!(metrics.get("file.entropy").is_some());

    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn empty_input_classifies_and_exposes_metrics() {
    let parsed = open(&[]).unwrap();
    // An empty byte slice has no meaningful format; we still expose
    // file.size_bytes and file.entropy so downstream consumers can
    // observe the degenerate case uniformly.
    assert_eq!(parsed.metrics().get("file.size_bytes"), Some(0.0));
    assert_eq!(parsed.metrics().get("file.entropy"), Some(0.0));
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn javascript_ast_projection_is_complete() {
    let source = br#"
        const fs = require('fs');
        chrome.cookies.getAll({ url: 'https://example.com' }, (c) => {});
        fetch('https://api.example.com/data');
        const decoded = atob("aGVsbG8=");
    "#;
    let parsed = open_with_path(std::path::Path::new("sample.js"), source).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::JavaScript);

    let ast = parsed.ast();
    assert!(
        ast.call_targets
            .contains(&"chrome.cookies.getAll".to_string()),
        "expected dotted target in call_targets, got {:?}",
        ast.call_targets
    );
    assert!(
        ast.call_string_args
            .get("fetch")
            .is_some_and(|args| args.contains(&"https://api.example.com/data".to_string())),
        "fetch's string-literal arg should be recorded"
    );
    assert!(
        ast.call_string_args
            .get("atob")
            .is_some_and(|args| args.contains(&"aGVsbG8=".to_string())),
        "atob's literal should be recorded"
    );

    // Parse count must stay at 1 after exercising all five views.
    let _ = parsed.values();
    let _ = parsed.strings();
    let _ = parsed.metrics();
    let _ = parsed.ast();
    let _ = parsed.fileid();
    assert_eq!(
        parsed.parse_count(),
        1,
        "all five views must share a single extraction pass"
    );
}

#[test]
fn ast_metrics_mirror_ast_paths() {
    // Verify the metric-naming convention: AST-derived metrics use
    // the `ast.` prefix and mirror the view's path shape.
    let source = b"const a = [1,2,3,4,5,6,7,8,9,10,11,12]; const u = 'a'+'b'+'c'+'d';";
    let parsed = open_with_path(std::path::Path::new("x.js"), source).unwrap();
    let m = parsed.metrics();
    assert!(m.get("ast.node_count").unwrap_or(0.0) > 0.0);
    assert_eq!(m.get("ast.array_literal_max_length"), Some(12.0));
    assert_eq!(m.get("ast.string_concat_chain_max_length"), Some(4.0));
}

#[test]
fn non_source_file_yields_empty_ast() {
    let parsed = open(b"{\"name\":\"x\"}").unwrap();
    // No view has been requested yet — parse_count is still 0.
    assert_eq!(parsed.parse_count(), 0);
    // The first view access (any of them) bumps parse_count to 1.
    assert!(parsed.ast().is_empty());
    assert_eq!(parsed.parse_count(), 1);
    // Subsequent view accesses share the same cached extraction.
    let _ = parsed.values();
    let _ = parsed.strings();
    let _ = parsed.metrics();
    assert_eq!(
        parsed.parse_count(),
        1,
        "non-source files still honour the single-parse contract"
    );
}

#[test]
fn unrecognised_bytes_still_extract_generic_metrics() {
    let bytes = vec![0xaa_u8; 4096];
    let parsed = open(&bytes).unwrap();
    let m = parsed.metrics();
    assert_eq!(m.get("file.size_bytes"), Some(4096.0));
    // A single repeated byte has zero entropy.
    assert!(m.get("file.entropy").unwrap().abs() < 1e-9);
    assert_eq!(parsed.parse_count(), 1);
}

/// Build a minimal ZIP containing three regular-file entries with
/// distinct paths. Pure-Rust, no external test fixture required.
fn build_minimal_zip() -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let mut buf = Vec::new();
    let cursor = std::io::Cursor::new(&mut buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    writer.start_file("a.txt", options).unwrap();
    writer.write_all(b"alpha\n").unwrap();
    writer.start_file("dir/b.txt", options).unwrap();
    writer.write_all(b"beta\n").unwrap();
    writer.start_file("dir/c.txt", options).unwrap();
    writer.write_all(b"gamma\n").unwrap();
    writer.finish().unwrap();
    buf
}
