use super::*;
use std::io::Write;

/// A gzipped tar holding the given members.
fn crate_with(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, body) in members {
        let mut h = tar::Header::new_ustar();
        h.set_path(path).unwrap();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append(&h, *body).unwrap();
    }
    let tar = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

fn run(bytes: &[u8]) -> (Values, Errors) {
    let mut v = Values::new();
    let mut e = Errors::new();
    extract(
        bytes,
        FileType::Crate,
        &mut v,
        &mut Metrics::new(),
        &mut Vec::new(),
        &mut e,
    )
    .unwrap();
    (v, e)
}

/// The one recorded error's stage and kind.
fn only_error(errors: &Errors) -> (Stage, crate::DiagnosticKind) {
    assert_eq!(errors.len(), 1, "{errors:?}");
    (errors.as_slice()[0].stage, errors.as_slice()[0].kind)
}

#[test]
fn root_manifest_is_read_and_records_nothing() {
    // A nested fixture manifest that does not parse is not the crate's.
    let (v, e) = run(&crate_with(&[
        ("w-0.1.0/Cargo.toml", b"[package]\nname = \"w\"\n"),
        ("w-0.1.0/tests/bad/Cargo.toml", b"[package"),
    ]));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(v.get("crate.name").and_then(|x| x.as_str()), Some("w"));
    let (_, e) = run(&crate_with(&[("w-0.1.0/src/lib.rs", b"")]));
    assert!(e.is_empty(), "{e:?}");
}

#[test]
fn manifest_that_is_not_toml_records_one_error() {
    let (v, e) = run(&crate_with(&[("w-0.1.0/Cargo.toml", b"[package")]));
    assert_eq!(
        only_error(&e),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    let message = &e.as_slice()[0].message;
    assert!(message.starts_with("w-0.1.0/Cargo.toml:"), "{message}");
    assert!(!message.contains('\n'), "{message}");
    assert!(v.get("crate.name").is_none());
}

#[test]
fn corrupt_gzip_stream_records_one_tar_parse_error() {
    let mut bytes = crate_with(&[("w-0.1.0/Cargo.toml", b"[package]\nname = \"w\"\n")]);
    for b in &mut bytes[10..] {
        *b ^= 0x5a;
    }
    let (_, e) = run(&bytes);
    assert_eq!(
        only_error(&e),
        (Stage::TarParse, crate::DiagnosticKind::Malformed)
    );
}

#[test]
fn oversized_manifest_is_a_limit_not_an_error() {
    let big = vec![b'#'; MAX_MANIFEST as usize + 1];
    let (v, e) = run(&crate_with(&[("w-0.1.0/Cargo.toml", &big)]));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("crate.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits[0]["stage"], "manifest");
}

#[test]
fn cargo_toml_package_identity_extracted() {
    let toml = r#"
            [package]
            name = "widget"
            version = "0.3.1"
            description = "Widgets for gadgets"
            authors = ["Jane Dev <jane@example.test>"]
            repository = "https://example.test/widget"
        "#;
    let manifest: toml::Value = toml::from_str(toml).unwrap();
    let mut v = Values::new();
    emit(&manifest, &mut v);
    assert_eq!(v.get("crate.name").and_then(|x| x.as_str()), Some("widget"));
    assert_eq!(
        v.get("crate.description").and_then(|x| x.as_str()),
        Some("Widgets for gadgets")
    );
    assert_eq!(
        v.get("crate.version").and_then(|x| x.as_str()),
        Some("0.3.1")
    );
    assert_eq!(
        v.get("crate.repository").and_then(|x| x.as_str()),
        Some("https://example.test/widget")
    );
    assert_eq!(
        v.get("crate.authors"),
        Some(&serde_json::json!([{"name": "Jane Dev", "email": "jane@example.test"}]))
    );
}
