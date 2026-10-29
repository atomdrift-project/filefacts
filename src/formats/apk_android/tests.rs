use super::*;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

fn apk_with(manifest: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    w.start_file("AndroidManifest.xml", opts).unwrap();
    w.write_all(manifest).unwrap();
    for (name, body) in extra {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn run(bytes: &[u8]) -> (Values, Metrics, Errors) {
    let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    let mut errors = Errors::new();
    extract_from_archive(&mut zip, &mut values, &mut metrics, &mut errors);
    (values, metrics, errors)
}

/// Deflate every member, then flip a byte inside the named member's
/// compressed data so it fails to inflate (or fails its CRC).
fn apk_with_corrupt(corrupt: &str, members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(::zip::CompressionMethod::Deflated);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    let mut bytes = w.finish().unwrap().into_inner();
    let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let entry = zip.by_name(corrupt).unwrap();
    let start = entry.data_start().unwrap() as usize;
    let len = entry.compressed_size() as usize;
    drop(entry);
    for b in &mut bytes[start..start + len] {
        *b ^= 0xa5;
    }
    bytes
}

fn only_error(errors: &Errors) -> &crate::Diagnostic {
    assert_eq!(errors.len(), 1, "{errors:?}");
    &errors.as_slice()[0]
}

#[test]
fn an_unreadable_manifest_is_reported_rather_than_passed_over() {
    let (_, metrics, errors) = run(&apk_with(b"not binary xml", &[]));
    assert_eq!(metrics.get("android.manifest_unreadable"), Some(1.0));
    // Present and readable, just not walkable: the metric says so, and
    // no read failure is recorded.
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn a_manifest_that_fails_to_inflate_records_one_zip_parse_error() {
    let body = vec![b'A'; 4096];
    let (values, _, errors) = run(&apk_with_corrupt(
        "AndroidManifest.xml",
        &[("AndroidManifest.xml", &body)],
    ));
    let e = only_error(&errors);
    assert_eq!(
        (e.stage, e.kind),
        (Stage::ZipParse, crate::DiagnosticKind::Malformed)
    );
    assert!(
        e.message.starts_with("AndroidManifest.xml:"),
        "{}",
        e.message
    );
    assert!(values.get("android.package").is_none());
}

#[test]
fn unreadable_signature_blocks_record_one_aggregate_error() {
    let body = vec![0x30; 4096];
    let (_, metrics, errors) = run(&apk_with_corrupt(
        "META-INF/CERT.RSA",
        &[
            ("AndroidManifest.xml", b"x"),
            ("META-INF/CERT.RSA", &body),
            ("META-INF/OTHER.RSA", b"not der"),
        ],
    ));
    let e = only_error(&errors);
    assert_eq!(
        (e.stage, e.kind),
        (Stage::ZipParse, crate::DiagnosticKind::Malformed)
    );
    assert!(
        e.message
            .starts_with("1 of 2 v1 signature blocks unreadable; first: META-INF/CERT.RSA:"),
        "{}",
        e.message
    );
    assert_eq!(metrics.get("android.v1_signature_count"), Some(2.0));
}

#[test]
fn v1_signature_members_are_counted_by_extension_and_case() {
    let (_, metrics, errors) = run(&apk_with(
        b"x",
        &[
            ("META-INF/CERT.RSA", b"not der"),
            ("META-INF/cert.dsa", b"not der"),
            ("META-INF/MANIFEST.MF", b"irrelevant"),
            ("classes.dex", b"irrelevant"),
        ],
    ));
    assert_eq!(metrics.get("android.v1_signature_count"), Some(2.0));
    // Readable blocks that are not DER: no signer, and no read failure.
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn an_apk_without_a_manifest_yields_no_android_fields() {
    let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("classes.dex", SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"x").unwrap();
    let bytes = w.finish().unwrap().into_inner();
    let (values, metrics, errors) = run(&bytes);
    assert!(values.get("android.package").is_none());
    assert!(metrics.get("android.manifest_unreadable").is_none());
    assert!(errors.is_empty(), "{errors:?}");
}

/// An APK whose first local header lost its signature still reaches the
/// APK layer: Android reads the central directory, and so does the
/// recovery in `zip::open_and_walk`.
#[test]
fn apk_with_a_corrupted_local_header_still_reaches_the_apk_layer() {
    let mut bytes = apk_with(b"not axml", &[("META-INF/CERT.RSA", b"\x30\x00")]);
    bytes[0..2].copy_from_slice(b"XX");
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    let mut errors = Errors::new();
    let mut members = Vec::new();
    let mut archive = super::super::zip::open_and_walk(
        &bytes,
        &mut values,
        &mut metrics,
        &mut members,
        &mut errors,
    )
    .unwrap()
    .expect("repaired archive");
    extract_from_archive(&mut archive, &mut values, &mut metrics, &mut errors);
    assert_eq!(members.len(), 2);
    assert_eq!(metrics.get("android.v1_signature_count"), Some(1.0));
    assert_eq!(
        metrics.get("archive.local_header_mismatch_count"),
        Some(1.0)
    );
}

/// Signature blocks past the cap are counted but not read: each would
/// otherwise cost a member read and a CMS parse.
#[test]
fn signature_blocks_past_the_cap_are_counted_not_read() {
    let names: Vec<String> = (0..MAX_SIGNATURE_BLOCKS + 4)
        .map(|i| format!("META-INF/S{i}.RSA"))
        .collect();
    let members: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), b"\x30\x00".as_slice()))
        .collect();
    let (values, metrics, _) = run(&apk_with(b"x", &members));
    assert_eq!(
        metrics.get("android.v1_signature_count"),
        Some((MAX_SIGNATURE_BLOCKS + 4) as f64)
    );
    let limits = values
        .get("android.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("signature-blocks"));
}

/// A manifest past the cap is refused and recorded, not parsed from its
/// first 8 MiB.
#[test]
fn oversized_manifest_is_a_limit() {
    let big = vec![0_u8; MAX_MANIFEST_BYTES as usize + 1];
    let (values, metrics, errors) = run(&apk_with(&big, &[]));
    let limits = values
        .get("android.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("manifest"));
    assert!(metrics.get("android.manifest_unreadable").is_none());
    assert!(errors.is_empty(), "{errors:?}");
}

const V1_SF: &[u8] = include_bytes!("../../../tests/fixtures/apk/CERT.SF");
const V1_RSA: &[u8] = include_bytes!("../../../tests/fixtures/apk/CERT.RSA");

fn v1_signature(values: &Values) -> &serde_json::Map<String, JsonValue> {
    values
        .get_key(value_key!("android.signatures"))
        .and_then(JsonValue::as_array)
        .and_then(|sigs| sigs.first())
        .and_then(JsonValue::as_object)
        .expect("one v1 signature")
}

/// A v1 block is detached: it verifies over the `.SF` of the same base
/// name, matched without regard to case.
#[test]
fn v1_signature_verifies_over_its_signature_file() {
    let bytes = apk_with(
        b"not axml",
        &[("META-INF/cert.sf", V1_SF), ("META-INF/CERT.RSA", V1_RSA)],
    );
    let (values, _, errors) = run(&bytes);
    let sig = v1_signature(&values);
    assert_eq!(sig.get("verified"), Some(&JsonValue::Bool(true)), "{sig:?}");
    assert_eq!(
        sig.get("signed_member").and_then(JsonValue::as_str),
        Some("META-INF/cert.sf")
    );
    assert!(errors.is_empty());
}

/// A signature file edited after signing no longer matches the block.
#[test]
fn v1_signature_over_an_edited_signature_file_fails() {
    let mut sf = V1_SF.to_vec();
    sf.extend_from_slice(b"Name: classes.dex\r\nSHA-256-Digest: AAAA\r\n\r\n");
    let bytes = apk_with(
        b"not axml",
        &[("META-INF/CERT.SF", &sf), ("META-INF/CERT.RSA", V1_RSA)],
    );
    let (values, _, _) = run(&bytes);
    assert_eq!(
        v1_signature(&values).get("verified"),
        Some(&JsonValue::Bool(false))
    );
}

/// Without its signature file the signer is still named, but nothing
/// was verified.
#[test]
fn v1_signature_without_its_signature_file_is_unverified() {
    let bytes = apk_with(b"not axml", &[("META-INF/CERT.RSA", V1_RSA)]);
    let (values, _, _) = run(&bytes);
    let sig = v1_signature(&values);
    assert_ne!(sig.get("verified"), Some(&JsonValue::Bool(true)));
    assert!(sig.get("signed_member").is_none());
}
