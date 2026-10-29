//! Rust crate (`.crate`) `Cargo.toml` identity extractor.
//!
//! A `.crate` is a gzipped tar whose `{name}-{version}/Cargo.toml`
//! carries the `[package]` identity — name, version, authors, and the
//! repository/homepage URLs. The generic [`super::tar`] walker lists the
//! members; this reads the manifest for the publisher identity.
//!
//! Decompression stops at the first `Cargo.toml`, so a large crate is
//! never fully inflated to read one manifest.

use serde_json::Value as JsonValue;

use super::bounded::{Limits, MAX_TARGZ_SEARCH, TarGzSearch, find_targz_member};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// Manifests above this are not legitimate — stop rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<(), Error> {
    if let Some(manifest) = cargo_toml(bytes, values, errors) {
        emit(&manifest, values);
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read and parse `{name}-{version}/Cargo.toml` from the gzipped crate.
/// `None` when the crate has none (silently), when it is over the size cap
/// or past the inflate budget (a `crate.limits` entry), or when the crate or
/// manifest is unreadable or not TOML (an error). Decompression stops at
/// the manifest.
fn cargo_toml(bytes: &[u8], values: &mut Values, errors: &mut Errors) -> Option<toml::Value> {
    const SOUGHT: &str = "<root>/Cargo.toml";
    // Exactly `<root>/Cargo.toml` — not the vendored `Cargo.toml.orig`,
    // nor a nested workspace member or test fixture.
    let is_manifest = |path: &str| path.ends_with("/Cargo.toml") && path.split('/').count() == 2;
    let (path, prefix) = match find_targz_member(bytes, is_manifest, MAX_MANIFEST) {
        Ok(TarGzSearch::Found { path, prefix }) => (path, prefix),
        Ok(TarGzSearch::Absent) => return None,
        Ok(TarGzSearch::InflateCapped) => {
            let mut limits = Limits::default();
            limits.push(
                "manifest-search",
                format!("no {SOUGHT} in the first {MAX_TARGZ_SEARCH} inflated bytes"),
            );
            limits.emit(values, value_key!("crate.limits"));
            return None;
        }
        Err(e) => {
            e.into_failure(Stage::TarParse, SOUGHT).record(errors);
            return None;
        }
    };
    if prefix.truncated {
        let mut limits = Limits::default();
        limits.push(
            "manifest",
            format!("{path} over the {MAX_MANIFEST}-byte cap; not parsed"),
        );
        limits.emit(values, value_key!("crate.limits"));
        return None;
    }
    let parsed = String::from_utf8(prefix.bytes)
        .map_err(|e| format!("not UTF-8: {e}"))
        .and_then(|text| {
            toml::from_str::<toml::Value>(&text).map_err(|e| {
                // toml's message can span lines; keep the record on one.
                let message = e.message().lines().collect::<Vec<_>>().join("; ");
                match e.span() {
                    Some(span) => format!("{message} at byte {}", span.start),
                    None => message,
                }
            })
        });
    parsed
        .map_err(|why| errors.record_malformed(Stage::FormatExtract, format!("{path}: {why}")))
        .ok()
}

/// Emit `crate.*` identity from a parsed `Cargo.toml`'s `[package]`.
fn emit(manifest: &toml::Value, values: &mut Values) {
    let Some(pkg) = manifest.get("package") else {
        return;
    };
    let mut put = |key: ValueKey, field: &str| {
        if let Some(v) = pkg.get(field).and_then(toml::Value::as_str) {
            if !v.is_empty() {
                values.insert_key(key, JsonValue::String(v.to_string()));
            }
        }
    };
    put(value_key!("crate.name"), "name");
    put(value_key!("crate.version"), "version");
    put(value_key!("crate.description"), "description");
    put(value_key!("crate.repository"), "repository");
    put(value_key!("crate.homepage"), "homepage");
    // Cargo writes each author as a `"Name <email>"` string.
    super::people::put(
        values,
        value_key!("crate.authors"),
        pkg.get("authors")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(super::people::Person::parse),
    );
}

#[cfg(test)]
mod tests;
