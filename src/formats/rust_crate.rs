//! Rust crate (`.crate`) `Cargo.toml` identity extractor.
//!
//! A `.crate` is a gzipped tar whose `{name}-{version}/Cargo.toml`
//! carries the `[package]` identity — name, version, authors, and the
//! repository/homepage URLs. The generic [`super::tar`] walker lists the
//! members; this reads the manifest for the publisher identity.
//!
//! Cargo extracts every member, so a later `Cargo.toml` replaces an
//! earlier one: the manifest is the last one in the crate.

use crate::formats::ExtractCtx;
use serde_json::Value as JsonValue;

use super::bounded::{
    Limits, MAX_MANIFEST_BYTES, MAX_TARGZ_SEARCH, TarGzSearch, find_targz_member,
};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{Errors, Stage, ValueKey, Values};
use crate::value_key;

pub(super) fn extract(bytes: &[u8], ctx: ExtractCtx<'_>) -> Result<(), Error> {
    let ExtractCtx {
        values,
        metrics,
        archive_members,
        errors,
        ..
    } = ctx;
    if let Some(manifest) = cargo_toml(bytes, values, errors) {
        emit(&manifest, values);
    }
    super::tar::extract(bytes, FileType::Crate, values, metrics, archive_members)
}

/// Read and parse `{name}-{version}/Cargo.toml` from the gzipped crate.
/// `None` when the crate has none (silently), when it is over the size cap
/// or past the inflate budget (a `crate.limits` entry), or when the crate or
/// manifest is unreadable or not TOML (an error). The last manifest in the
/// crate is the one read.
fn cargo_toml(bytes: &[u8], values: &mut Values, errors: &mut Errors) -> Option<toml::Value> {
    const SOUGHT: &str = "<root>/Cargo.toml";
    // Exactly `<root>/Cargo.toml` — not the vendored `Cargo.toml.orig`,
    // nor a nested workspace member or test fixture.
    let is_manifest = |path: &str| path.ends_with("/Cargo.toml") && path.split('/').count() == 2;
    let (path, prefix) = match find_targz_member(bytes, is_manifest, MAX_MANIFEST_BYTES) {
        Ok(TarGzSearch::Found { path, prefix }) => (path, prefix),
        Ok(TarGzSearch::Absent) => return None,
        Ok(TarGzSearch::InflateCapped) => {
            let mut limits = Limits::default();
            limits.push(
                "manifest-search",
                format!(
                    "tarball inflates past {MAX_TARGZ_SEARCH} bytes before its end; {SOUGHT} not read"
                ),
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
            format!("{path} over the {MAX_MANIFEST_BYTES}-byte cap; not parsed"),
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
        if let Some(v) = pkg
            .get(field)
            .and_then(toml::Value::as_str)
            .filter(|v| !v.is_empty())
        {
            values.insert_key(key, JsonValue::String(v.to_string()));
        }
    };
    put(value_key!("crate.name"), "name");
    put(value_key!("crate.version"), "version");
    put(value_key!("crate.description"), "description");
    put(value_key!("crate.repository"), "repository");
    put(value_key!("crate.homepage"), "homepage");
    // Cargo writes each author as a `"Name <email>"` string.
    super::people::put_list(
        values,
        value_key!("crate.authors"),
        pkg.get("authors")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(super::people::Person::parse),
        value_key!("crate.limits"),
    );
}

#[cfg(test)]
mod tests;
