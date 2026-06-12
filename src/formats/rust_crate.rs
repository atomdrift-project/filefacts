//! Rust crate (`.crate`) `Cargo.toml` identity extractor.
//!
//! A `.crate` is a gzipped tar whose `{name}-{version}/Cargo.toml`
//! carries the `[package]` identity — name, version, authors, and the
//! repository/homepage URLs. The generic [`super::tar`] walker lists the
//! members; this reads the manifest for the publisher identity.
//!
//! Decompression stops at the first `Cargo.toml`, so a large crate is
//! never fully inflated to read one manifest.

use std::io::Read;

use flate2::read::GzDecoder;
use serde_json::Value as JsonValue;
use tar::Archive;

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Metrics, Values};

/// Manifests above this are not legitimate — stop rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    if let Some(manifest) = cargo_toml(bytes) {
        emit(&manifest, values);
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read and parse `{name}-{version}/Cargo.toml` from the gzipped crate.
fn cargo_toml(bytes: &[u8]) -> Option<toml::Value> {
    let mut archive = Archive::new(GzDecoder::new(bytes));
    for entry in archive.entries().ok()? {
        let Ok(entry) = entry else { break };
        // Exactly `…/Cargo.toml` — not the vendored `Cargo.toml.orig`.
        let is_manifest = entry
            .path()
            .map(|p| p.to_string_lossy().ends_with("/Cargo.toml"))
            .unwrap_or(false);
        if !is_manifest {
            continue;
        }
        let mut text = String::new();
        if entry.take(MAX_MANIFEST).read_to_string(&mut text).is_err() {
            return None;
        }
        return toml::from_str(&text).ok();
    }
    None
}

/// Emit `crate.*` identity from a parsed `Cargo.toml`'s `[package]`.
fn emit(manifest: &toml::Value, values: &mut Values) {
    let Some(pkg) = manifest.get("package") else {
        return;
    };
    let mut put = |key: &str, field: &str| {
        if let Some(v) = pkg.get(field).and_then(toml::Value::as_str) {
            if !v.is_empty() {
                values.insert(key, JsonValue::String(v.to_string()));
            }
        }
    };
    put("crate.name", "name");
    put("crate.version", "version");
    put("crate.repository", "repository");
    put("crate.homepage", "homepage");
    if let Some(authors) = pkg.get("authors").and_then(toml::Value::as_array) {
        let list: Vec<JsonValue> = authors
            .iter()
            .filter_map(toml::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| JsonValue::String(s.to_string()))
            .collect();
        if !list.is_empty() {
            values.insert("crate.authors", JsonValue::Array(list));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_toml_package_identity_extracted() {
        let toml = r#"
            [package]
            name = "widget"
            version = "0.3.1"
            authors = ["Jane Dev <jane@example.test>"]
            repository = "https://example.test/widget"
        "#;
        let manifest: toml::Value = toml::from_str(toml).unwrap();
        let mut v = Values::new();
        emit(&manifest, &mut v);
        assert_eq!(v.get("crate.name").and_then(|x| x.as_str()), Some("widget"));
        assert_eq!(
            v.get("crate.version").and_then(|x| x.as_str()),
            Some("0.3.1")
        );
        assert_eq!(
            v.get("crate.repository").and_then(|x| x.as_str()),
            Some("https://example.test/widget")
        );
        assert_eq!(
            v.get("crate.authors")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_str()),
            Some("Jane Dev <jane@example.test>")
        );
    }
}
