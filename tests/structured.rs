//! End-to-end tests of structured documents and generic inputs: JSON
//! manifests, empty and unrecognised bytes, and the path-derived values.
//!
//! Tests that read more than one view assert the no-duplicate-work
//! guarantee (`parse_count() == 1` once those views have been read).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::float_cmp,
    reason = "fixtures build binary layouts from literals and compare exact expected values"
)]

mod common;

use common::{open, options};
use filefacts::FileType;

#[test]
fn json_manifest_parses_once_through_all_views() {
    let bytes = br#"{"name":"sample","version":"1.0.0","scripts":{"preinstall":"echo hi"}}"#;
    let parsed = options()
        .path(std::path::Path::new("package.json"))
        .open(bytes);
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
    let parsed = options()
        .path(std::path::Path::new("payload.json"))
        .open(br#"{"cookie":"alert(1)"}"#);
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

    let parsed = options()
        .path(std::path::Path::new("payload.json"))
        .open(&bytes);
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
fn empty_input_classifies_and_exposes_metrics() {
    let parsed = open(&[]);
    // An empty byte slice has no meaningful format; we still expose
    // file.size and file.entropy so downstream consumers can
    // observe the degenerate case uniformly.
    assert_eq!(parsed.metrics().get("file.size"), Some(0.0));
    assert_eq!(parsed.metrics().get("file.entropy"), Some(0.0));
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn non_source_file_yields_empty_ast() {
    let parsed = open(b"{\"name\":\"x\"}");
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
    let parsed = open(&bytes);
    let m = parsed.metrics();
    assert_eq!(m.get("file.size"), Some(4096.0));
    // A single repeated byte has zero entropy.
    assert!(m.get("file.entropy").unwrap().abs() < 1e-9);
    assert_eq!(parsed.parse_count(), 1);
}

/// `OpenOptions::path` should populate file.basename and file.stem in the
/// values tree so traits can match on them via
/// `type: value, path: file.basename`.
#[test]
fn path_option_populates_file_basename_and_stem() {
    let bytes = b"# Hello\n";
    let parsed = options()
        .path(std::path::Path::new("/tmp/README.md"))
        .open(bytes);
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
    let parsed = open(bytes);
    let values = parsed.values();
    assert!(values.get("file.basename").is_none());
    assert!(values.get("file.stem").is_none());
}

/// Stem-vs-extension semantics: a dotfile keeps its leading dot in
/// the stem (matches Python pathlib).
#[test]
fn file_stem_handles_dotfiles() {
    let parsed = options()
        .path(std::path::Path::new("/p/.gitignore"))
        .open(b"");
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
