//! RubyGems package (`.gem`) metadata extractor.
//!
//! A gem is an uncompressed `ustar` tar holding three members:
//! `metadata.gz` (a gzipped `Gem::Specification` YAML), `data.tar.gz` (the
//! installed files), and `checksums.yaml.gz`. The package's *identity* —
//! name, version, dependencies, authors — lives only in `metadata.gz` (or
//! an uncompressed `metadata`, which RubyGems also reads); it never appears
//! in the installed file tree. This extractor reads that member (gunzipping
//! just it, no other decompression) and surfaces the identity as `gem.*`
//! facts.
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

use super::bounded::{MAX_MANIFEST_BYTES, MemberFailure, OnError, inflate_capped};
use super::common::put_str;
use super::structured::parse_yaml;

/// The outer-tar member holding the gzipped `Gem::Specification`.
const METADATA: &str = "metadata.gz";
/// The member holding it uncompressed, which RubyGems reads as well.
const METADATA_PLAIN: &str = "metadata";
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

    // `version` is a nested `!ruby/object:Gem::Version` mapping: { version: x }.
    let version = spec.get("version").and_then(|v| field_str(v, "version"));
    for (key, value) in [
        (value_key!("gem.name"), field_str(&spec, "name")),
        (value_key!("gem.version"), version),
        (value_key!("gem.platform"), field_str(&spec, "platform")),
        (value_key!("gem.description"), field_str(&spec, "summary")),
        (value_key!("gem.homepage"), field_str(&spec, "homepage")),
    ] {
        if let Some(value) = value {
            put_str(values, key, value);
        }
    }

    // `licenses` and `authors` (sequences) are current; `license` and
    // `author` (scalars) are the legacy single-value forms. Prefer the
    // sequence, fall back to the scalar. Sequences are bounded.
    let strings = |plural: &str, singular: &str| -> Vec<&str> {
        let listed: Vec<&str> = spec
            .get(plural)
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .take(MAX_LIST)
            .filter_map(JsonValue::as_str)
            .collect();
        if listed.is_empty() {
            field_str(&spec, singular).into_iter().collect()
        } else {
            listed
        }
    };
    // Several licenses mean the user may pick any of them.
    let licenses = strings("licenses", "license");
    if !licenses.is_empty() {
        put_str(values, value_key!("gem.license"), licenses.join(" OR "));
    }
    let authors = strings("authors", "author");
    super::people::put(
        values,
        value_key!("gem.authors"),
        authors
            .iter()
            .map(|&name| super::people::Person::from_fields(Some(name), None)),
    );

    extract_dependencies(&spec, values, metrics);
}

/// Walk the outer (uncompressed) tar, read its `Gem::Specification` YAML --
/// gunzipped from `metadata.gz`, or as stored in `metadata` -- and parse it.
/// Its Ruby tags are dropped, leaving plain mappings. RubyGems loads every
/// such member in turn, so the last one is the gem's specification: an
/// earlier one is a decoy. `Ok(None)` when the gem has neither; `Err` names
/// the stage and step that failed.
fn read_metadata(bytes: &[u8]) -> Result<Option<JsonValue>, MemberFailure> {
    let walk = |e: std::io::Error| {
        MemberFailure::new(
            Stage::TarParse,
            format!("gem unreadable before {METADATA}"),
            e,
        )
    };
    let mut archive = tar::Archive::new(bytes);
    let mut spec = Ok(None);
    for entry in archive.entries().map_err(walk)? {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(e) if matches!(spec, Ok(None)) => return Err(walk(e)),
            // RubyGems refuses a gem whose tar breaks off; what was read
            // before the break is kept.
            Err(e) => {
                tracing::debug!(target: "filefacts::gem", stage = "tar", error = %e, "gem unreadable past its metadata");
                break;
            }
        };
        let member = match &*entry.path_bytes() {
            b"metadata.gz" => METADATA,
            b"metadata" => METADATA_PLAIN,
            _ => continue,
        };
        spec = read_spec(&mut entry, member).map(Some);
    }
    spec
}

/// Read and parse one specification member, `metadata.gz` or `metadata`.
fn read_spec(entry: &mut impl Read, member: &str) -> Result<JsonValue, MemberFailure> {
    // An over-cap `metadata.gz` ends mid-stream and fails to gunzip; an
    // over-cap YAML is refused rather than parsed short. Either lands
    // below as an error naming the step.
    let yaml = if member == METADATA {
        inflate_capped(
            flate2::read::GzDecoder::new(entry.take(MAX_MANIFEST_BYTES)),
            MAX_METADATA_YAML,
            OnError::Discard,
        )
        .map_err(|e| {
            MemberFailure::new(
                Stage::FormatExtract,
                format!("{METADATA}: gunzip failed"),
                e,
            )
        })?
    } else {
        inflate_capped(entry, MAX_METADATA_YAML, OnError::Discard)
            .map_err(|e| MemberFailure::new(Stage::TarParse, member, e))?
    };
    if yaml.truncated {
        return Err(MemberFailure::new(
            Stage::FormatExtract,
            member,
            format!("YAML over the {MAX_METADATA_YAML}-byte cap"),
        ));
    }
    parse_yaml(&yaml.bytes).map_err(|e| MemberFailure::new(Stage::FormatExtract, member, e))
}

/// Surface the dependency shape. Each dependency is a
/// `!ruby/object:Gem::Dependency` mapping with a `name` and a `type` symbol
/// (`:runtime` or `:development`).
fn extract_dependencies(spec: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    let Some(deps) = spec.get("dependencies").and_then(JsonValue::as_array) else {
        return;
    };
    let mut runtime: Vec<&str> = Vec::new();
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
                runtime.push(name);
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
        values.insert_key(value_key!("gem.dependencies"), JsonValue::from(runtime));
    }
}

/// Convenience: the string value of `key` within a mapping.
fn field_str<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    v.get(key).and_then(JsonValue::as_str)
}

#[cfg(test)]
mod tests;
