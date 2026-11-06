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
const BOUND_MF: &[u8] = include_bytes!("../../../tests/fixtures/apk/BOUND.MF");
const BOUND_SF: &[u8] = include_bytes!("../../../tests/fixtures/apk/BOUND.SF");
const BOUND_RSA: &[u8] = include_bytes!("../../../tests/fixtures/apk/BOUND.RSA");
/// `classes.dex` as `BOUND.MF` digests it; `AndroidManifest.xml` is
/// `not axml`.
const BOUND_DEX: &[u8] = b"dex\n035\0";

/// The APK `generate.sh` signed as `BOUND`, with `replace` members put in
/// place of (or beside) its own, in order.
fn bound_apk(replace: &[(&str, &[u8])]) -> Vec<u8> {
    let mut members: Vec<(&str, &[u8])> = vec![
        ("classes.dex", BOUND_DEX),
        ("META-INF/MANIFEST.MF", BOUND_MF),
        ("META-INF/BOUND.SF", BOUND_SF),
        ("META-INF/BOUND.RSA", BOUND_RSA),
    ];
    for &(name, body) in replace {
        match members
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            Some(member) => *member = (name, body),
            None => members.push((name, body)),
        }
    }
    apk_with(b"not axml", &members)
}

fn v1_signature(values: &Values) -> &serde_json::Map<String, JsonValue> {
    values
        .lookup(value_key!("android.signatures"))
        .and_then(JsonValue::as_array)
        .and_then(|sigs| sigs.first())
        .and_then(JsonValue::as_object)
        .expect("one v1 signature")
}

/// A v1 block is detached: it verifies over the `.SF` of the same base
/// name, matched without regard to case. Verified means the whole chain
/// holds: the block signs the `.SF`, the `.SF` digests the manifest, and
/// the manifest digests every member.
#[test]
fn v1_signature_verifies_over_its_signature_file() {
    let (values, _, errors) = run(&bound_apk(&[("META-INF/bound.sf", BOUND_SF)]));
    let sig = v1_signature(&values);
    assert_eq!(sig.get("verified"), Some(&JsonValue::Bool(true)), "{sig:?}");
    assert_eq!(sig.get("digest_matches"), Some(&JsonValue::Bool(true)));
    assert_eq!(
        sig.get("signed_member").and_then(JsonValue::as_str),
        Some("META-INF/bound.sf")
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

fn v1_verdict(bytes: &[u8]) -> (Option<JsonValue>, Option<JsonValue>) {
    let (values, _, _) = run(bytes);
    let sig = v1_signature(&values);
    (
        sig.get("verified").cloned(),
        sig.get("digest_matches").cloned(),
    )
}

const BROKEN: (Option<JsonValue>, Option<JsonValue>) =
    (Some(JsonValue::Bool(false)), Some(JsonValue::Bool(false)));

/// A genuine block and `.SF` lifted out of another app verify perfectly
/// over that `.SF`, which says nothing about this archive: its manifest
/// digest is of another manifest, or there is no manifest, and the members
/// here are not the ones it signed.
#[test]
fn a_grafted_v1_signature_is_not_verified() {
    let payload: &[u8] = b"attacker dex";
    // CERT.SF digests an empty manifest, so with one the `.SF` binds the
    // manifest, but nothing binds the members.
    for manifest in [None, Some(&b""[..]), Some(BOUND_MF)] {
        let mut members: Vec<(&str, &[u8])> = vec![
            ("classes.dex", payload),
            ("META-INF/CERT.SF", V1_SF),
            ("META-INF/CERT.RSA", V1_RSA),
        ];
        if let Some(manifest) = manifest {
            members.push(("META-INF/MANIFEST.MF", manifest));
        }
        let verdict = v1_verdict(&apk_with(b"not axml", &members));
        assert_eq!(verdict, BROKEN, "manifest {manifest:?}");
    }
}

/// Each member must be the one the manifest digests, and listed in it and
/// in the `.SF`.
#[test]
fn a_v1_signature_over_other_members_is_not_verified() {
    // A member replaced after signing.
    assert_eq!(
        v1_verdict(&bound_apk(&[("classes.dex", b"attacker dex")])),
        BROKEN
    );
    // A member added after signing, in no manifest at all.
    assert_eq!(
        v1_verdict(&bound_apk(&[("assets/payload.bin", b"x")])),
        BROKEN
    );
    // A member added with a manifest section the `.SF` does not list: the
    // manifest no longer matches the `.SF`'s whole-manifest digest, and its
    // sections bind only the members that were signed.
    let mut manifest = BOUND_MF.to_vec();
    manifest.extend_from_slice(
        b"Name: assets/payload.bin\r\n\
          SHA-256-Digest: LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=\r\n\r\n",
    );
    assert_eq!(
        v1_verdict(&bound_apk(&[
            ("META-INF/MANIFEST.MF", &manifest),
            ("assets/payload.bin", b"x"),
        ])),
        BROKEN
    );
    // The manifest missing.
    let bytes = apk_with(
        b"not axml",
        &[
            ("classes.dex", BOUND_DEX),
            ("META-INF/BOUND.SF", BOUND_SF),
            ("META-INF/BOUND.RSA", BOUND_RSA),
        ],
    );
    assert_eq!(v1_verdict(&bytes), BROKEN);
}

/// When the manifest's whole digest no longer matches, the `.SF`'s
/// per-section digests still bind each section, as Android and apksig
/// fall back to: an edit outside the signed sections does not break the
/// signature.
#[test]
fn v1_section_digests_bind_a_manifest_whose_main_section_changed() {
    let manifest = String::from_utf8(BOUND_MF.to_vec())
        .unwrap()
        .replace("Created-By: filefacts fixture", "Created-By: someone else");
    let bytes = bound_apk(&[("META-INF/MANIFEST.MF", manifest.as_bytes())]);
    assert_eq!(
        v1_verdict(&bytes),
        (Some(JsonValue::Bool(true)), Some(JsonValue::Bool(true)))
    );
}

/// Android refuses an archive whose central directory names a member
/// twice, and a reader keeping one copy may keep the other one: the
/// signature cannot be said to cover what the platform loads.
#[test]
fn a_v1_signature_over_duplicate_members_is_not_verified() {
    // The attacker's copy is written as `classes.dey`, then renamed
    // `classes.dex` in its local and central headers, ahead of the signed one.
    let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    for (name, body) in [
        ("AndroidManifest.xml", &b"not axml"[..]),
        ("classes.dey", b"attacker dex"),
        ("classes.dex", BOUND_DEX),
        ("META-INF/MANIFEST.MF", BOUND_MF),
        ("META-INF/BOUND.SF", BOUND_SF),
        ("META-INF/BOUND.RSA", BOUND_RSA),
    ] {
        w.start_file(name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    let mut bytes = w.finish().unwrap().into_inner();
    let at: Vec<usize> = bytes
        .windows(11)
        .enumerate()
        .filter(|(_, w)| *w == b"classes.dey")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 2, "local and central names");
    for i in at {
        bytes[i + 10] = b'x';
    }
    let zip = ::zip::ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
    assert!(zip.has_duplicate_names());
    assert_ne!(v1_verdict(&bytes).0, Some(JsonValue::Bool(true)));
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

/// A binary-XML manifest of one `<manifest>` element whose attributes are
/// `(namespace, name, value)` string-pool indices into `strings`; a
/// namespace of `u32::MAX` is none.
fn manifest_axml(strings: &[&str], attrs: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        data.extend_from_slice(&[s.len() as u8, s.len() as u8]);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let header = 28 + offsets.len() * 4;
    let mut pool = Vec::new();
    pool.extend_from_slice(&1u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&((header + data.len()) as u32).to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&(1u32 << 8).to_le_bytes());
    pool.extend_from_slice(&(header as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);
    let mut el = Vec::new();
    el.extend_from_slice(&0x0102u16.to_le_bytes());
    el.extend_from_slice(&16u16.to_le_bytes());
    el.extend_from_slice(&((36 + attrs.len() * 20) as u32).to_le_bytes());
    el.extend_from_slice(&1u32.to_le_bytes());
    el.extend_from_slice(&u32::MAX.to_le_bytes());
    el.extend_from_slice(&u32::MAX.to_le_bytes());
    el.extend_from_slice(&0u32.to_le_bytes()); // "manifest"
    el.extend_from_slice(&20u16.to_le_bytes());
    el.extend_from_slice(&20u16.to_le_bytes());
    el.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    el.extend_from_slice(&[0; 6]);
    for &(ns, name, value) in attrs {
        el.extend_from_slice(&ns.to_le_bytes());
        el.extend_from_slice(&name.to_le_bytes());
        el.extend_from_slice(&value.to_le_bytes());
        el.extend_from_slice(&8u16.to_le_bytes());
        el.extend_from_slice(&[0, 0x03]);
        el.extend_from_slice(&value.to_le_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&0x0003u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&((8 + pool.len() + el.len()) as u32).to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&el);
    out
}

/// Android reads `package` in no namespace; an `android:package` placed
/// ahead of it must not stand in for the package name.
#[test]
fn a_namespaced_package_attribute_is_not_the_package() {
    let strings = [
        "manifest",
        "package",
        "com.google.android.gms",
        "com.evil.app",
        "http://schemas.android.com/apk/res/android",
    ];
    let manifest = manifest_axml(&strings, &[(4, 1, 2), (u32::MAX, 1, 3)]);
    let (values, _, _) = run(&apk_with(&manifest, &[]));
    assert_eq!(
        values.get("android.package").and_then(|v| v.as_str()),
        Some("com.evil.app")
    );
    // Alone, the unqualified attribute is still the package.
    let manifest = manifest_axml(&strings, &[(u32::MAX, 1, 3)]);
    let (values, _, _) = run(&apk_with(&manifest, &[]));
    assert_eq!(
        values.get("android.package").and_then(|v| v.as_str()),
        Some("com.evil.app")
    );
}
