#![allow(clippy::unwrap_used)]
use super::*;

fn facts(bytes: &[u8]) -> (Option<Manifest>, Values, Metrics) {
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    let manifest = parse(bytes);
    if let Some(m) = &manifest {
        emit(m, bytes, &mut values, &mut metrics);
    }
    (manifest, values, metrics)
}

#[test]
fn strict_manifest() {
    let (m, values, metrics) = facts(br#"{"name":"demo","version":"1.0.0"}"#);
    let m = m.unwrap();
    assert_eq!(m.stage, Stage::Strict);
    assert_eq!(
        values.get("npm.manifest.parse"),
        Some(&JsonValue::from("strict"))
    );
    assert!(values.get("npm.manifest.parse_error").is_none());
    assert!(metrics.get("npm.manifest.trailing_size").is_none());
}

#[test]
fn a_bom_is_not_trailing_content_or_an_error() {
    let (m, values, _) = facts(b"\xEF\xBB\xBF{\"name\":\"demo\"}\n");
    assert_eq!(m.unwrap().stage, Stage::Strict);
    assert!(values.get("npm.manifest.trailing_offset").is_none());
}

#[test]
fn comments_and_trailing_commas_read_leniently() {
    let doc = b"{\n  // hand edited\n  \"name\": \"demo\",\n  \"scripts\": {\"test\": \"x\",},\n}";
    let (m, values, _) = facts(doc);
    let m = m.unwrap();
    assert_eq!(m.stage, Stage::Lenient);
    assert_eq!(m.doc["scripts"]["test"], "x");
    assert_eq!(
        values.get("npm.manifest.parse"),
        Some(&JsonValue::from("lenient"))
    );
    assert!(values.get("npm.manifest.parse_error").is_some());
}

#[test]
fn broken_json_is_salvaged() {
    let doc = br#"{"name": "demo", "scripts": {"postinstall": "node x.js"}, "dependencies": {"a": "1"} oops"#;
    let (m, values, _) = facts(doc);
    let m = m.unwrap();
    assert_eq!(m.stage, Stage::Salvaged);
    assert_eq!(m.doc["name"], "demo");
    assert_eq!(m.doc["scripts"]["postinstall"], "node x.js");
    assert_eq!(m.doc["dependencies"]["a"], "1");
    assert_eq!(
        values.get("npm.manifest.parse"),
        Some(&JsonValue::from("salvaged"))
    );
    assert!(parse(b"not json at all").is_none());
}

#[test]
fn trailing_code_and_steganography() {
    let json = br#"{"name":"demo"}"#;
    let mut doc = json.to_vec();
    doc.extend_from_slice("\neval(Buffer.from('x\u{FE01}\u{200B}', 'base64'))".as_bytes());
    let (m, values, metrics) = facts(&doc);
    assert_eq!(m.unwrap().end, json.len());
    assert_eq!(
        values.get("npm.manifest.trailing_offset"),
        Some(&JsonValue::from(json.len()))
    );
    assert!(metrics.get("npm.manifest.trailing_size").unwrap() > 0.0);
    assert_eq!(metrics.get("npm.manifest.trailing_code"), Some(1.0));
    assert_eq!(
        metrics.get("npm.manifest.trailing_variation_selectors"),
        Some(1.0)
    );
    assert_eq!(metrics.get("npm.manifest.trailing_zero_width"), Some(1.0));
}

#[test]
fn trailing_prose_is_not_code() {
    let (_, _, metrics) = facts(b"{\"name\":\"demo\"}\nhello there");
    assert!(metrics.get("npm.manifest.trailing_size").is_some());
    assert!(metrics.get("npm.manifest.trailing_code").is_none());
}
