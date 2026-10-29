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
    extract(bytes, &mut v, &mut Metrics::new(), &mut e);
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
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
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
