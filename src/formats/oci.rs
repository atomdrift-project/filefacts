//! OCI / Docker container-image identity extractor.
//!
//! The member listing comes from the generic [`super::tar`] walker; this
//! module adds the image identity that lives in the bundle's top-level
//! manifest. Two on-disk shapes are handled:
//!
//! * **OCI image layout** — an `index.json` (the
//!   [image index](https://github.com/opencontainers/image-spec)) listing
//!   manifest descriptors by digest, with the human-readable tag in the
//!   `org.opencontainers.image.ref.name` annotation.
//! * **`docker save` bundle** — a `manifest.json` array, each element naming
//!   a config blob, the `RepoTags` it was saved under, and its layer blobs.
//!
//! The image refs and the config/manifest digests are the strongest
//! cross-image identifiers, so they are surfaced as `oci.*` for the identity
//! normalizer. The tarball is uncompressed, so reading one small JSON member
//! is cheap.

use crate::metric;
use std::collections::BTreeSet;
use std::io::Cursor;

use serde_json::Value as JsonValue;

use super::bounded::{Limits, MemberPrefix, inflate_capped};
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// Manifests larger than this are not the small index/manifest JSON we want;
/// stop reading rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // `index.json` (OCI) takes precedence over `manifest.json` (docker save)
    // when a bundle carries both, since the OCI index is the authoritative
    // top-level descriptor. One that does not parse still falls through to
    // the other, but is recorded.
    let mut limits = Limits::default();
    if let Some(json) = manifest(bytes, "index.json", &mut limits, errors) {
        emit_oci_index(&json, values, metrics);
    } else if let Some(json) = manifest(bytes, "manifest.json", &mut limits, errors) {
        emit_docker_manifest(&json, values, metrics);
    }
    limits.emit(values, value_key!("oci.limits"));
}

/// Read and parse a top-level JSON manifest. `None` when the bundle has no
/// such member (silently), when it is over the size cap (a `limits` entry),
/// or when it is unreadable or not JSON (an error).
fn manifest(
    bytes: &[u8],
    name: &str,
    limits: &mut Limits,
    errors: &mut Errors,
) -> Option<JsonValue> {
    let raw = match member(bytes, name) {
        Ok(Some(raw)) => raw,
        Ok(None) => return None,
        Err(e) => {
            errors.record_malformed(Stage::TarParse, format!("{name}: {e}"));
            return None;
        }
    };
    if raw.truncated {
        limits.push(
            "manifest",
            format!("{name} over the {MAX_MANIFEST}-byte cap; not parsed"),
        );
        return None;
    }
    serde_json::from_slice(&raw.bytes)
        .map_err(|e| errors.record_malformed(Stage::FormatExtract, format!("{name}: {e}")))
        .ok()
}

/// Read a top-level tar member by name (tolerating a `./` prefix) through
/// the manifest cap. `Ok(None)` when the bundle holds no such member.
fn member(bytes: &[u8], name: &str) -> std::io::Result<Option<MemberPrefix>> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    for entry in archive.entries()? {
        let entry = entry?;
        let matches = entry
            .path()
            .is_ok_and(|p| p.to_string_lossy().trim_start_matches("./") == name);
        if !matches {
            continue;
        }
        return inflate_capped(entry, MAX_MANIFEST).map(Some);
    }
    Ok(None)
}

/// Emit `oci.*` facts from an OCI image index.
fn emit_oci_index(index: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    values.insert_key(value_key!("oci.kind"), JsonValue::String("oci".into()));
    let manifests = index.get("manifests").and_then(JsonValue::as_array);
    let Some(manifests) = manifests else { return };
    metrics.insert(metric!("oci.manifest_count"), manifests.len() as f64);

    let mut digests = BTreeSet::new();
    let mut refs = BTreeSet::new();
    for m in manifests {
        if let Some(d) = m.get("digest").and_then(JsonValue::as_str) {
            digests.insert(d.to_string());
        }
        if let Some(r) = m
            .get("annotations")
            .and_then(|a| a.get("org.opencontainers.image.ref.name"))
            .and_then(JsonValue::as_str)
        {
            refs.insert(r.to_string());
        }
    }
    insert_set(values, value_key!("oci.manifest.digest"), digests);
    insert_set(values, value_key!("oci.ref"), refs);
}

/// Emit `oci.*` facts from a `docker save` `manifest.json` array.
fn emit_docker_manifest(manifest: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    values.insert_key(value_key!("oci.kind"), JsonValue::String("docker".into()));
    let images = manifest.as_array();
    let Some(images) = images else { return };
    metrics.insert(metric!("oci.image_count"), images.len() as f64);

    let mut refs = BTreeSet::new();
    let mut configs = BTreeSet::new();
    let mut layers = 0u64;
    for image in images {
        for tag in image
            .get("RepoTags")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .filter_map(JsonValue::as_str)
        {
            refs.insert(tag.to_string());
        }
        if let Some(cfg) = image.get("Config").and_then(JsonValue::as_str) {
            configs.insert(normalize_digest(cfg));
        }
        layers += image
            .get("Layers")
            .and_then(JsonValue::as_array)
            .map_or(0, Vec::len) as u64;
    }
    insert_set(values, value_key!("oci.ref"), refs);
    insert_set(values, value_key!("oci.config.digest"), configs);
    metrics.insert(metric!("oci.layer_count"), layers as f64);
}

/// Normalize a `docker save` config reference to a `sha256:<hex>` digest.
/// Classic bundles name it `<hex>.json`; containerd-era bundles already use
/// `blobs/sha256/<hex>`. Anything else is passed through unchanged.
fn normalize_digest(config: &str) -> String {
    let stem = config
        .rsplit('/')
        .next()
        .unwrap_or(config)
        .strip_suffix(".json")
        .unwrap_or_else(|| config.rsplit('/').next().unwrap_or(config));
    if stem.len() == 64 && stem.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("sha256:{stem}")
    } else {
        config.to_string()
    }
}

/// Insert a set of strings as a JSON array value, skipping the key when empty.
fn insert_set(values: &mut Values, key: ValueKey, set: BTreeSet<String>) {
    if set.is_empty() {
        return;
    }
    let arr = set.into_iter().map(JsonValue::String).collect();
    values.insert_key(key, JsonValue::Array(arr));
}

#[cfg(test)]
mod tests;
