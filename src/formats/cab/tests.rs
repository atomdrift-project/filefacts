use super::*;

/// Build a one-file cabinet in memory and read it back through the same
/// path a scan takes.
fn cabinet_with(name: &str, body: &[u8]) -> Vec<u8> {
    let mut builder = cab::CabinetBuilder::new();
    builder
        .add_folder(cab::CompressionType::None)
        .add_file(name.to_string());
    let mut writer = builder.build(Cursor::new(Vec::new())).unwrap();
    while let Some(mut w) = writer.next_file().unwrap() {
        std::io::Write::write_all(&mut w, body).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn run(bytes: &[u8]) -> (Values, Metrics, Vec<ArchiveMember>) {
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    let mut typed = Vec::new();
    extract(bytes, &mut values, &mut metrics, &mut typed).unwrap();
    (values, metrics, typed)
}

#[test]
fn header_walk_emits_members_and_counts_executables() {
    let bytes = cabinet_with("payload\\setup.exe", b"not an executable");
    let (values, metrics, typed) = run(&bytes);

    let members = values.get("archive.members").unwrap().as_array().unwrap();
    assert_eq!(members.len(), 1);
    // Backslashes are normalized so member rules match a cabinet the same
    // way they match a zip.
    assert_eq!(members[0]["path"].as_str(), Some("payload/setup.exe"));
    assert_eq!(members[0]["size_bytes"].as_u64(), Some(17));
    assert_eq!(metrics.get("archive.file_count"), Some(1.0));
    assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
    assert_eq!(metrics.get("cab.folder_count"), Some(1.0));
    assert_eq!(metrics.get("cab.file_count_mismatch"), Some(0.0));
    assert_eq!(typed.len(), 1);
    assert_eq!(
        values
            .get("archive.format.kind")
            .and_then(serde_json::Value::as_str),
        Some("cab")
    );
    assert_eq!(
        values.get("cab.version").and_then(JsonValue::as_str),
        Some("1.3")
    );
}

#[test]
fn appended_bytes_are_reported_as_trailing() {
    let mut bytes = cabinet_with("a.txt", b"hi");
    let clean = run(&bytes).1.get("archive.trailing_bytes");
    assert_eq!(clean, Some(0.0));

    bytes.extend_from_slice(&[0x41; 512]);
    let (_, metrics, _) = run(&bytes);
    // The cabinet still parses; the appended block is what gets reported.
    assert_eq!(metrics.get("archive.trailing_bytes"), Some(512.0));
}

#[test]
fn header_facts_survive_an_unreadable_member_table() {
    // Truncate past the fixed header so the member table cannot be walked
    // but the CFHEADER is intact.
    let bytes = cabinet_with("a.txt", b"hi");
    let cut = &bytes[..CFHEADER_FIXED_LEN + 2];
    let (values, metrics, typed) = run(cut);

    assert!(typed.is_empty());
    assert!(values.get("cab.limits").is_some(), "limitation recorded");
    // The identifying header fields are still reported.
    assert_eq!(
        values.get("cab.version").and_then(JsonValue::as_str),
        Some("1.3")
    );
    assert!(metrics.get("cab.declared_total_size").unwrap() > 0.0);
}

/// A cabinet signature commits to a digest of the cabinet, which nothing
/// here recomputes: a genuine SignedData appended to any cabinet verifies as
/// CMS, so it must read as unverifiable rather than verified.
#[test]
fn appended_signature_is_not_verified_over_the_cabinet() {
    const SIGNED_DATA: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode-digicert-tencent.p7b"
    ));
    let mut bytes = cabinet_with("a.txt", b"hi");
    let cabinet_len = bytes.len();
    let blob = crate::formats::cms::der_element(SIGNED_DATA).unwrap();
    bytes.extend_from_slice(blob);
    bytes.extend_from_slice(&[0; 32]);
    let (values, metrics, _) = run(&bytes);
    let sig = values.get("cab.signatures[0]").expect("signature parsed");
    assert_eq!(sig["verified"], JsonValue::Null);
    assert_eq!(sig["verification_unsupported"], true);
    assert!(sig["subject"].as_str().is_some());
    assert_eq!(metrics.get("cab.signature_bytes"), Some(blob.len() as f64));
    assert_eq!(metrics.get("cab.post_signature_bytes"), Some(32.0));
    assert_eq!(
        metrics.get("archive.trailing_bytes"),
        Some((bytes.len() - cabinet_len) as f64)
    );
}

#[test]
fn signature_guard_requires_the_signed_data_oid() {
    let signed_data = [
        0x30, 0x82, 0x3d, 0x4b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        0xa0, 0x00,
    ];
    assert!(is_pkcs7_signed_data(&signed_data));
    // A DER sequence that is not SignedData, and plain appended bytes,
    // must not be handed to the ASN.1 decoder.
    let other = [
        0x30, 0x82, 0x3d, 0x4b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        0xa0, 0x00,
    ];
    assert!(!is_pkcs7_signed_data(&other));
    assert!(!is_pkcs7_signed_data(&[0x41; 64]));
}

#[test]
fn appended_payload_is_not_mistaken_for_a_signature() {
    let mut bytes = cabinet_with("a.txt", b"hi");
    bytes.extend_from_slice(&[0x41; 512]);
    let (values, metrics, _) = run(&bytes);
    assert_eq!(metrics.get("archive.trailing_bytes"), Some(512.0));
    assert!(values.get("cab.signatures").is_none());
    assert!(metrics.get("cab.signature_bytes").is_none());
}

#[test]
fn non_cabinet_bytes_are_rejected() {
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    let mut typed = Vec::new();
    assert!(extract(b"not a cab at all", &mut values, &mut metrics, &mut typed).is_err());
}
