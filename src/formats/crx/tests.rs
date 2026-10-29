#[test]
fn browser_manifest_bom_and_comments_are_accepted() {
    let raw = "\u{feff}{\n  // the extension\n  \"name\": \"x\", /* block */\n  \"homepage_url\": \"https://example.invalid/a//b\",\n  \"q\": \"say \\\"//hi\\\"\"\n}";
    let parsed: serde_json::Value =
        serde_json::from_slice(&super::browser_manifest_json(raw.as_bytes())).unwrap();
    assert_eq!(parsed["name"], "x");
    assert_eq!(parsed["homepage_url"], "https://example.invalid/a//b");
    assert_eq!(parsed["q"], "say \"//hi\"");
}

use super::*;

#[test]
fn manifest_description_extracted_unless_localized() {
    let mut v = Values::new();
    emit_web_extension_identity(
        &serde_json::json!({"description": "Blocks trackers"}),
        &CRX_KEYS,
        &mut v,
    );
    assert_eq!(
        v.get("crx.description").and_then(JsonValue::as_str),
        Some("Blocks trackers")
    );
    let mut v = Values::new();
    emit_web_extension_identity(
        &serde_json::json!({"description": "__MSG_desc__"}),
        &CRX_KEYS,
        &mut v,
    );
    assert!(v.get("crx.description").is_none());
}

#[test]
fn extension_id_maps_nibbles_to_a_through_p() {
    // 0x00 → "aa", 0x0f → "ap", 0xf0 → "pa", 0xff → "pp".
    let digest = [0x00, 0x0f, 0xf0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(&extension_id(&digest)[..8], "aaappapp");
}

#[test]
fn crx3_uses_signed_id_and_matching_developer_proof() {
    let publisher_key = b"shared publisher key";
    let developer_key = b"extension developer key";
    let digest = Sha256::digest(developer_key);
    let crx_id = &digest[..16];

    let mut header = Vec::new();
    for key in [publisher_key.as_slice(), developer_key.as_slice()] {
        let mut proof = vec![0x0a, key.len() as u8];
        proof.extend_from_slice(key);
        proof.extend_from_slice(&[0x12, 0x01, 0x01]);
        header.extend_from_slice(&[0x12, proof.len() as u8]);
        header.extend_from_slice(&proof);
    }
    let mut signed_data = vec![0x0a, 16];
    signed_data.extend_from_slice(crx_id);
    // field 10000, wire type 2
    header.extend_from_slice(&[0x82, 0xf1, 0x04, signed_data.len() as u8]);
    header.extend_from_slice(&signed_data);

    let mut bytes = b"Cr24".to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&header);

    let mut values = Values::new();
    super::header(&bytes, &mut values);
    assert_eq!(
        values.get("crx.extension_id").and_then(JsonValue::as_str),
        Some(extension_id(crx_id).as_str())
    );
    assert_eq!(
        values
            .get("crx.public_key_sha256")
            .and_then(JsonValue::as_str),
        Some(hex_encode(&digest).as_str())
    );
    // The keys are not real and nothing is signed: a claim.
    assert_eq!(
        values
            .get("crx.signature_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

/// A length-delimited protobuf field.
fn pb(field: u64, data: &[u8]) -> Vec<u8> {
    fn varint(mut n: u64, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut out = Vec::new();
    varint((field << 3) | 2, &mut out);
    varint(data.len() as u64, &mut out);
    out.extend_from_slice(data);
    out
}

/// The SHA-256 a CRX3 proof signs, spelled out independently of
/// [`crx3_verified`].
fn crx3_message_digest(signed_data: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut message = b"CRX3 SignedData\x00".to_vec();
    message.extend_from_slice(&(signed_data.len() as u32).to_le_bytes());
    message.extend_from_slice(signed_data);
    message.extend_from_slice(archive);
    Sha256::digest(&message).to_vec()
}

/// A CRX3 file: `proofs` as `(field, key, signature)`, then the signed
/// data naming `crx_id`, then `archive`.
fn crx3(proofs: &[(u64, &[u8], &[u8])], signed_data: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    for (field, key, signature) in proofs {
        let mut proof = pb(1, key);
        proof.extend(pb(2, signature));
        header.extend(pb(*field, &proof));
    }
    header.extend(pb(10_000, signed_data));
    let mut bytes = b"Cr24".to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(archive);
    bytes
}

fn test_rsa_key() -> rsa::RsaPrivateKey {
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_der(include_bytes!(
        "../../../tests/fixtures/crx/test-rsa1024.pk8.der"
    ))
    .unwrap()
}

fn rsa_spki(key: &rsa::RsaPrivateKey) -> Vec<u8> {
    use rsa::pkcs8::EncodePublicKey;
    key.to_public_key().to_public_key_der().unwrap().into_vec()
}

fn verified(bytes: &[u8]) -> Option<bool> {
    let mut values = Values::new();
    header(bytes, &mut values);
    values
        .get("crx.signature_verified")
        .and_then(JsonValue::as_bool)
}

/// An ECDSA developer proof over the real message verifies the id; the
/// same file with one archive byte changed does not.
#[test]
fn crx3_ecdsa_developer_proof_is_verified() {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let spki = key.verifying_key().to_public_key_der().unwrap().into_vec();
    let crx_id = Sha256::digest(&spki)[..16].to_vec();
    let signed_data = pb(1, &crx_id);
    let archive = b"PK\x05\x06 archive bytes";
    let digest = crx3_message_digest(&signed_data, archive);
    let signature: Signature = key.sign_prehash(&digest).unwrap();
    let der = signature.to_der();

    let bytes = crx3(&[(3, &spki, der.as_bytes())], &signed_data, archive);
    let mut values = Values::new();
    header(&bytes, &mut values);
    assert_eq!(
        values.get("crx.extension_id").and_then(JsonValue::as_str),
        Some(extension_id(&crx_id).as_str())
    );
    assert_eq!(
        values
            .get("crx.signature_verified")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(verified(&tampered), Some(false));
}

/// RSA developer proofs verify under SHA-256, as Chrome signs them.
#[test]
fn crx3_rsa_developer_proof_is_verified() {
    let key = test_rsa_key();
    let spki = rsa_spki(&key);
    let crx_id = Sha256::digest(&spki)[..16].to_vec();
    let signed_data = pb(1, &crx_id);
    let archive = b"PK\x05\x06 archive bytes";
    let digest = crx3_message_digest(&signed_data, archive);
    let signature = key
        .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
        .unwrap();
    let bytes = crx3(&[(2, &spki, &signature)], &signed_data, archive);
    assert_eq!(verified(&bytes), Some(true));
}

/// Anyone can write another extension's id and public key into the
/// header. Without that key's signature the id is emitted as a claim,
/// flagged unverified: here the attacker signs with their own key, and
/// separately pastes the victim's key beside a junk signature.
#[test]
fn crx3_claimed_id_without_its_signature_is_unverified() {
    let attacker = test_rsa_key();
    let attacker_spki = rsa_spki(&attacker);
    let victim_key = b"victim developer key";
    let victim_id = Sha256::digest(victim_key)[..16].to_vec();
    let signed_data = pb(1, &victim_id);
    let archive = b"PK\x05\x06 malicious";
    let digest = crx3_message_digest(&signed_data, archive);
    let signature = attacker
        .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
        .unwrap();
    let bytes = crx3(
        &[(2, &attacker_spki, &signature), (2, victim_key, b"junk")],
        &signed_data,
        archive,
    );
    let mut values = Values::new();
    header(&bytes, &mut values);
    assert_eq!(
        values.get("crx.extension_id").and_then(JsonValue::as_str),
        Some(extension_id(&victim_id).as_str())
    );
    assert_eq!(
        values
            .get("crx.signature_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

/// Chrome reads the last `signed_header_data`, as protobuf does; a decoy
/// before it does not change which id is reported.
#[test]
fn crx3_last_signed_header_data_wins() {
    let decoy = pb(1, &[0xaa; 16]);
    let real = pb(1, &[0x11; 16]);
    let mut header = pb(10_000, &decoy);
    header.extend(pb(10_000, &real));
    assert_eq!(signed_header_data(&header), Some(real.as_slice()));
    assert_eq!(signed_crx_id(&real), Some([0x11; 16].as_slice()));
}

/// CRX2 signs the archive with RSA-SHA1 under the header's key.
#[test]
fn crx2_signature_is_verified() {
    let key = test_rsa_key();
    let spki = rsa_spki(&key);
    let archive = b"PK\x05\x06 archive bytes";
    let digest = sha1::Sha1::digest(archive);
    let signature = key
        .sign(rsa::Pkcs1v15Sign::new::<sha1::Sha1>(), &digest)
        .unwrap();
    let mut bytes = b"Cr24".to_vec();
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&(spki.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&spki);
    bytes.extend_from_slice(&signature);
    bytes.extend_from_slice(archive);
    assert_eq!(verified(&bytes), Some(true));

    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(verified(&bytes), Some(false));
}

/// A CRX3 shell around a stored-member zip.
fn crx_with(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = ::zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = ::zip::write::SimpleFileOptions::default()
        .compression_method(::zip::CompressionMethod::Stored);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    let mut bytes = b"Cr24".to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&w.finish().unwrap().into_inner());
    bytes
}

fn run(bytes: &[u8]) -> (Values, Errors) {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut members = Vec::new();
    let mut errors = Errors::new();
    extract(bytes, &mut values, &mut metrics, &mut members, &mut errors).unwrap();
    (values, errors)
}

#[test]
fn manifest_that_is_not_json_records_one_error() {
    let (values, errors) = run(&crx_with(&[("manifest.json", b"{\"author\": ")]));
    assert_eq!(errors.len(), 1, "{errors:?}");
    let e = &errors.as_slice()[0];
    assert_eq!(
        (e.stage, e.kind),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    assert!(e.message.starts_with("manifest.json:"), "{}", e.message);
    assert!(values.get("crx.limits").is_none());
}

#[test]
fn well_formed_or_absent_manifest_records_nothing() {
    let (values, errors) = run(&crx_with(&[("manifest.json", br#"{"author": "Jo"}"#)]));
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        values
            .get("crx.authors[0].name")
            .and_then(JsonValue::as_str),
        Some("Jo")
    );
    let (_, errors) = run(&crx_with(&[("background.js", b"//")]));
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn oversized_manifest_is_a_limit_not_an_error() {
    let mut big = b"{\"description\": \"".to_vec();
    big.resize(600 * 1024, b'a');
    big.extend_from_slice(b"\"}");
    let (values, errors) = run(&crx_with(&[("manifest.json", &big)]));
    assert!(errors.is_empty(), "{errors:?}");
    let limits = values
        .get("crx.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits[0]["stage"], "manifest");
}

#[test]
fn non_crx_bytes_emit_nothing() {
    let mut values = Values::new();
    header(b"PK\x03\x04not a crx", &mut values);
    assert!(values.get("crx.format_version").is_none());
}
