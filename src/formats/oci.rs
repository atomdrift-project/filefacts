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
use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::output::{Metrics, Values};

/// Manifests larger than this are not the small index/manifest JSON we want;
/// stop reading rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    // `index.json` (OCI) takes precedence over `manifest.json` (docker save)
    // when a bundle carries both, since the OCI index is the authoritative
    // top-level descriptor.
    if let Some(raw) = member(bytes, "index.json") {
        if let Ok(json) = serde_json::from_slice::<JsonValue>(&raw) {
            emit_oci_index(&json, values, metrics);
            return Ok(());
        }
    }
    if let Some(raw) = member(bytes, "manifest.json") {
        if let Ok(json) = serde_json::from_slice::<JsonValue>(&raw) {
            emit_docker_manifest(&json, values, metrics);
        }
    }
    Ok(())
}

/// Read a top-level tar member by name (tolerating a `./` prefix).
fn member(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    for entry in archive.entries().ok()? {
        let Ok(mut entry) = entry else { break };
        let matches = entry
            .path()
            .map(|p| p.to_string_lossy().trim_start_matches("./") == name)
            .unwrap_or(false);
        if !matches {
            continue;
        }
        let mut buf = Vec::new();
        (&mut entry).take(MAX_MANIFEST).read_to_end(&mut buf).ok()?;
        return Some(buf);
    }
    None
}

/// Emit `oci.*` facts from an OCI image index.
fn emit_oci_index(index: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    values.insert("oci.kind", JsonValue::String("oci".into()));
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
    insert_set(values, "oci.manifest.digest", digests);
    insert_set(values, "oci.ref", refs);
}

/// Emit `oci.*` facts from a `docker save` `manifest.json` array.
fn emit_docker_manifest(manifest: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    values.insert("oci.kind", JsonValue::String("docker".into()));
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
    insert_set(values, "oci.ref", refs);
    insert_set(values, "oci.config.digest", configs);
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
fn insert_set(values: &mut Values, key: &str, set: BTreeSet<String>) {
    if set.is_empty() {
        return;
    }
    let arr = set.into_iter().map(JsonValue::String).collect();
    values.insert(key, JsonValue::Array(arr));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_manifest_emits_refs_and_config() {
        let json = serde_json::json!([{
            "Config": "ab".repeat(32) + ".json",
            "RepoTags": ["nginx:1.27", "nginx:latest"],
            "Layers": ["a/layer.tar", "b/layer.tar"]
        }]);
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        emit_docker_manifest(&json, &mut values, &mut metrics);
        assert_eq!(
            values.get("oci.kind").and_then(JsonValue::as_str),
            Some("docker")
        );
        let refs = values.get("oci.ref").and_then(JsonValue::as_array).unwrap();
        assert_eq!(refs.len(), 2);
        let configs = values
            .get("oci.config.digest")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(
            configs[0].as_str().unwrap(),
            format!("sha256:{}", "ab".repeat(32))
        );
        assert_eq!(metrics.get("oci.layer_count"), Some(2.0));
    }

    #[test]
    fn oci_index_emits_digest_and_ref() {
        let json = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:".to_string() + &"cd".repeat(32),
                "annotations": { "org.opencontainers.image.ref.name": "v1.0.0" }
            }]
        });
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        emit_oci_index(&json, &mut values, &mut metrics);
        assert_eq!(
            values.get("oci.kind").and_then(JsonValue::as_str),
            Some("oci")
        );
        assert_eq!(metrics.get("oci.manifest_count"), Some(1.0));
        let refs = values.get("oci.ref").and_then(JsonValue::as_array).unwrap();
        assert_eq!(refs[0].as_str(), Some("v1.0.0"));
    }
}
