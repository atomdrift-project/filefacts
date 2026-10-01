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
) -> Result<(), Error> {
    // `index.json` (OCI) takes precedence over `manifest.json` (docker save)
    // when a bundle carries both, since the OCI index is the authoritative
    // top-level descriptor. One that does not parse still falls through to
    // the other, but is recorded.
    let mut limits = Vec::new();
    if let Some(json) = manifest(bytes, "index.json", &mut limits, errors) {
        emit_oci_index(&json, values, metrics);
    } else if let Some(json) = manifest(bytes, "manifest.json", &mut limits, errors) {
        emit_docker_manifest(&json, values, metrics);
    }
    if !limits.is_empty() {
        values.insert_key(value_key!("oci.limits"), JsonValue::Array(limits));
    }
    Ok(())
}

/// Read and parse a top-level JSON manifest. `None` when the bundle has no
/// such member (silently), when it is over the size cap (a `limits` entry),
/// or when it is unreadable or not JSON (an error).
fn manifest(
    bytes: &[u8],
    name: &str,
    limits: &mut Vec<JsonValue>,
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
    if raw.len() as u64 > MAX_MANIFEST {
        limits.push(serde_json::json!({
            "stage": "manifest",
            "reason": format!("{name} over the {MAX_MANIFEST}-byte cap; not parsed"),
        }));
        return None;
    }
    serde_json::from_slice(&raw)
        .map_err(|e| errors.record_malformed(Stage::FormatExtract, format!("{name}: {e}")))
        .ok()
}

/// Read a top-level tar member by name (tolerating a `./` prefix), to one
/// byte past the cap so an oversized one is recognisable. `Ok(None)` when
/// the bundle holds no such member.
fn member(bytes: &[u8], name: &str) -> std::io::Result<Option<Vec<u8>>> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let matches = entry
            .path()
            .is_ok_and(|p| p.to_string_lossy().trim_start_matches("./") == name);
        if !matches {
            continue;
        }
        let mut buf = Vec::new();
        (&mut entry).take(MAX_MANIFEST + 1).read_to_end(&mut buf)?;
        return Ok(Some(buf));
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
mod tests {
    use super::*;

    /// An uncompressed tar holding the given members.
    fn bundle(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, body) in members {
            let mut h = tar::Header::new_ustar();
            h.set_path(path).unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append(&h, *body).unwrap();
        }
        tar.into_inner().unwrap()
    }

    fn run(bytes: &[u8]) -> (Values, Errors) {
        let mut v = Values::new();
        let mut e = Errors::new();
        extract(bytes, &mut v, &mut Metrics::new(), &mut e).unwrap();
        (v, e)
    }

    #[test]
    fn well_formed_or_absent_manifests_record_nothing() {
        let (v, e) = run(&bundle(&[("index.json", br#"{"manifests": []}"#)]));
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(v.get("oci.kind").and_then(JsonValue::as_str), Some("oci"));
        let (v, e) = run(&bundle(&[("blobs/sha256/x", b"{}")]));
        assert!(e.is_empty(), "{e:?}");
        assert!(v.get("oci.kind").is_none());
    }

    #[test]
    fn index_that_is_not_json_records_one_error_and_falls_through() {
        let (v, e) = run(&bundle(&[
            ("index.json", b"{\"manifests\": ["),
            ("manifest.json", br#"[{"RepoTags": ["a:1"]}]"#),
        ]));
        assert_eq!(e.len(), 1, "{e:?}");
        let err = &e.as_slice()[0];
        assert_eq!(
            (err.stage, err.kind),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
        assert!(err.message.starts_with("index.json:"), "{}", err.message);
        assert_eq!(
            v.get("oci.kind").and_then(JsonValue::as_str),
            Some("docker")
        );
        assert!(v.get("oci.limits").is_none());
    }

    #[test]
    fn oversized_manifest_is_a_limit_not_an_error() {
        let big = vec![b' '; MAX_MANIFEST as usize + 1];
        let (v, e) = run(&bundle(&[("manifest.json", &big)]));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("oci.limits").and_then(JsonValue::as_array).unwrap();
        assert_eq!(limits.len(), 1);
        assert_eq!(limits[0]["stage"], "manifest");
    }

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
