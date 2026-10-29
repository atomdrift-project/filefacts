//! RubyGems package (`.gem`) metadata extractor.
//!
//! A gem is an uncompressed `ustar` tar holding three members:
//! `metadata.gz` (a gzipped `Gem::Specification` YAML), `data.tar.gz` (the
//! installed files), and `checksums.yaml.gz`. The package's *identity* —
//! name, version, dependencies, authors — lives only in `metadata.gz`; it
//! never appears in the installed file tree. This extractor reads that one
//! member (gunzipping just it, no other decompression) and surfaces the
//! identity as `gem.*` facts.
//!
//! Emitted keys:
//!
//! - `gem.name`, `gem.version`, `gem.platform` — core identity. `platform`
//!   is `"ruby"` for pure-Ruby gems, otherwise a native target triple.
//! - `gem.description`, `gem.homepage` — provenance / impersonation signals.
//! - `gem.license` — the SPDX licenses, any of which applies, joined with
//!   ` OR `; `gem.authors[]` — author names.
//! - `gem.dependencies[]` — runtime dependency names (bounded).
//! - `gem.dependency_count`, `gem.runtime_dependency_count`,
//!   `gem.development_dependency_count` — dependency-shape metrics.

use crate::metric;
use std::io::Read;

use serde_json::Value as JsonValue;

use crate::output::{Errors, Metrics, Stage, Values};
use crate::value_key;

use super::bounded::{MemberFailure, inflate_capped};
use super::structured::parse_yaml;

/// The outer-tar member holding the gzipped `Gem::Specification`.
const METADATA: &str = "metadata.gz";
/// Cap on the compressed `metadata.gz` we read from the outer tar. Real gem
/// specifications are a few KiB; anything larger is malformed or hostile.
const MAX_METADATA_GZ: u64 = 1 << 20; // 1 MiB
/// Cap on the decompressed YAML, guarding against a gzip bomb in `metadata.gz`.
const MAX_METADATA_YAML: u64 = 8 << 20; // 8 MiB
/// Cap on the number of list entries (authors, licenses, dependency names)
/// retained — a gem with tens of thousands of deps shouldn't bloat the facts.
const MAX_LIST: usize = 256;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // A gem whose `metadata.gz` is absent or unparseable still gets the generic
    // archive.* surface from the tar walker — just no gem.* identity. An
    // unreadable one is recorded rather than failing the whole extraction.
    let spec = match read_metadata(bytes) {
        Ok(Some(spec)) => spec,
        Ok(None) => return,
        Err(failure) => {
            failure.record(errors);
            return;
        }
    };

    if let Some(name) = field_str(&spec, "name") {
        values.insert_key(value_key!("gem.name"), JsonValue::String(name.to_string()));
    }
    // `version` is a nested `!ruby/object:Gem::Version` mapping: { version: x }.
    if let Some(version) = spec.get("version").and_then(|v| field_str(v, "version")) {
        values.insert_key(
            value_key!("gem.version"),
            JsonValue::String(version.to_string()),
        );
    }
    if let Some(platform) = field_str(&spec, "platform") {
        values.insert_key(
            value_key!("gem.platform"),
            JsonValue::String(platform.to_string()),
        );
    }
    if let Some(summary) = field_str(&spec, "summary") {
        values.insert_key(
            value_key!("gem.description"),
            JsonValue::String(summary.to_string()),
        );
    }
    if let Some(homepage) = field_str(&spec, "homepage") {
        values.insert_key(
            value_key!("gem.homepage"),
            JsonValue::String(homepage.to_string()),
        );
    }

    // `licenses` (plural, a sequence) is current; `license` (singular) is the
    // legacy single-value form. Prefer the sequence, fall back to the scalar.
    let mut licenses = collect_strings(spec.get("licenses"));
    if licenses.is_empty() {
        if let Some(l) = field_str(&spec, "license") {
            licenses.push(l.to_string());
        }
    }
    // Several licenses mean the user may pick any of them.
    if !licenses.is_empty() {
        values.insert_key(
            value_key!("gem.license"),
            JsonValue::String(licenses.join(" OR ")),
        );
    }

    // Same plural/singular split for authors (`authors` seq vs `author` scalar).
    let mut authors = collect_strings(spec.get("authors"));
    if authors.is_empty() {
        if let Some(a) = field_str(&spec, "author") {
            authors.push(a.to_string());
        }
    }
    super::people::put(
        values,
        value_key!("gem.authors"),
        authors
            .iter()
            .map(|name| super::people::Person::from_fields(Some(name), None)),
    );

    extract_dependencies(&spec, values, metrics);
}

/// Walk the outer (uncompressed) tar, gunzip `metadata.gz` straight from the
/// member, and parse the `Gem::Specification` YAML. Its Ruby tags are
/// dropped, leaving plain mappings. `Ok(None)` when the gem has no
/// `metadata.gz`; `Err` names the stage and step that failed.
fn read_metadata(bytes: &[u8]) -> Result<Option<JsonValue>, MemberFailure> {
    let walk = |e: std::io::Error| {
        MemberFailure::new(
            Stage::TarParse,
            format!("gem unreadable before {METADATA}"),
            e,
        )
    };
    let mut archive = tar::Archive::new(bytes);
    for entry in archive.entries().map_err(walk)? {
        let mut entry = entry.map_err(walk)?;
        if *entry.path_bytes() != *METADATA.as_bytes() {
            continue;
        }
        // An over-cap `metadata.gz` ends mid-stream and fails to gunzip; an
        // over-cap YAML is refused rather than parsed short. Either lands
        // below as an error naming the step.
        let yaml = inflate_capped(
            flate2::read::GzDecoder::new(entry.by_ref().take(MAX_METADATA_GZ)),
            MAX_METADATA_YAML,
        )
        .map_err(|e| {
            MemberFailure::new(
                Stage::FormatExtract,
                format!("{METADATA}: gunzip failed"),
                e,
            )
        })?;
        if yaml.truncated {
            return Err(MemberFailure::new(
                Stage::FormatExtract,
                METADATA,
                format!("YAML over the {MAX_METADATA_YAML}-byte cap"),
            ));
        }
        return parse_yaml(&yaml.bytes)
            .map(Some)
            .map_err(|e| MemberFailure::new(Stage::FormatExtract, METADATA, e));
    }
    Ok(None)
}

/// Surface the dependency shape. Each dependency is a
/// `!ruby/object:Gem::Dependency` mapping with a `name` and a `type` symbol
/// (`:runtime` or `:development`).
fn extract_dependencies(spec: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    let Some(deps) = spec.get("dependencies").and_then(JsonValue::as_array) else {
        return;
    };
    let mut runtime: Vec<String> = Vec::new();
    let mut runtime_count: u64 = 0;
    let mut development_count: u64 = 0;
    for dep in deps {
        let Some(name) = field_str(dep, "name") else {
            continue;
        };
        // YAML symbols (`:runtime`) parse as the string `":runtime"`; tolerate
        // both the symbol and bare forms.
        let is_dev =
            field_str(dep, "type").is_some_and(|t| t == ":development" || t == "development");
        if is_dev {
            development_count += 1;
        } else {
            runtime_count += 1;
            if runtime.len() < MAX_LIST {
                runtime.push(name.to_string());
            }
        }
    }
    metrics.insert(metric!("gem.dependency_count"), deps.len() as f64);
    metrics.insert(
        metric!("gem.runtime_dependency_count"),
        runtime_count as f64,
    );
    metrics.insert(
        metric!("gem.development_dependency_count"),
        development_count as f64,
    );
    if !runtime.is_empty() {
        values.insert_key(value_key!("gem.dependencies"), string_array(&runtime));
    }
}

/// Convenience: the string value of `key` within a mapping.
fn field_str<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    v.get(key).and_then(JsonValue::as_str)
}

/// Collect the string entries of a sequence, bounded.
fn collect_strings(v: Option<&JsonValue>) -> Vec<String> {
    v.and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .take(MAX_LIST)
        .filter_map(JsonValue::as_str)
        .map(str::to_string)
        .collect()
}

fn string_array(items: &[String]) -> JsonValue {
    JsonValue::Array(items.iter().cloned().map(JsonValue::String).collect())
}

#[cfg(test)]
mod tests;
