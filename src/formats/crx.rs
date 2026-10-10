//! Chrome extension (`.crx`) header parser.
//!
//! A CRX file is a ZIP with a signed header prepended. The ZIP body is
//! walked by the generic [`super::zip`] extractor (the `zip` crate
//! tolerates the prefix); this module decodes the header to recover the
//! identity that ZIP can't carry: the developer proof key and canonical
//! **extension id**.
//!
//! The extension id is the first 16 bytes of a SHA-256 digest, each nibble
//! mapped `0..15` → `a..p`. CRX2 derives it directly from its public key.
//! CRX3 declares it in the signed-header `SignedData`; Web Store packages can
//! carry a publisher proof before the developer proof, so hashing the first
//! proof key produces the wrong extension id.
//!
//! Two on-disk layouts:
//! - **CRX2**: `Cr24`, version, key length, signature length, then the
//!   DER `SubjectPublicKeyInfo` directly.
//! - **CRX3**: `Cr24`, version, header length, then a protobuf
//!   `CrxFileHeader`. Field 10000 contains the canonical signed id; RSA/ECDSA
//!   proofs are searched for a developer key whose hash agrees with that id.
//!
//! Every header field is a claim until a signature backs it: anyone can
//! write another extension's id into `SignedData`, or paste its public key
//! into a CRX2 header. `crx.signature_verified` is `true` only when the
//! developer key's signature checks out over the header and archive bytes
//! (CRX3: RSA-PKCS#1 v1.5 or ECDSA P-256 over SHA-256 of
//! `"CRX3 SignedData\0" ‖ le32(len) ‖ signed_header_data ‖ archive`;
//! CRX2: RSA-PKCS#1 v1.5 over SHA-1 of the archive), and `false` otherwise.

use std::io::Read;

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::formats::common::bytes_at::u32_le;
use crate::formats::common::hex_encode;
use crate::output::{ArchiveMember, Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// Proofs carrying the developer key whose signatures are checked. A real
/// CRX3 has one; each check is a public-key operation, and a header can
/// repeat the same proof as often as its length allows.
const MAX_PROOF_CHECKS: usize = 4;

/// The context string CRX3 signs ahead of the signed header data.
const CRX3_SIGNATURE_CONTEXT: &[u8] = b"CRX3 SignedData\x00";

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<(), Error> {
    // Header decode is best-effort identity enrichment; a malformed
    // header must not stop the ZIP walk.
    header(bytes, values);
    let Some(mut archive) =
        super::zip::open_and_walk(bytes, values, metrics, archive_members, errors)?
    else {
        return Ok(());
    };
    // The extension's `manifest.json` carries the developer-declared
    // author and homepage — the human identity behind the signing key.
    if let Some(manifest) = read_manifest(&mut archive, values, errors) {
        emit_manifest_identity(&manifest, values);
    }
    Ok(())
}

/// Read and parse the root `manifest.json` of an opened CRX archive.
fn read_manifest<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    errors: &mut Errors,
) -> Option<JsonValue> {
    read_browser_manifest(zip, values, errors, value_key!("crx.limits"))
}

/// Read and parse the root `manifest.json` of an opened browser-extension
/// archive (CRX or XPI). `None` when it is absent (silently), over the size
/// cap (a `limits` entry), or unreadable or not JSON (an error).
pub(super) fn read_browser_manifest<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    errors: &mut Errors,
    limits: ValueKey,
) -> Option<JsonValue> {
    const NAME: &str = "manifest.json";
    const MAX: u64 = 512 * 1024;
    let buf = match super::zip::read_member(zip, NAME, MAX) {
        Ok(buf) => buf?,
        Err(super::zip::MemberError::TooLarge { max }) => {
            super::bounded::push_limit(
                values,
                limits,
                "manifest",
                format!("{NAME} over the {max}-byte cap; not parsed"),
            );
            return None;
        }
        Err(e) => {
            errors.record_malformed(Stage::ZipParse, format!("{NAME}: {e}"));
            return None;
        }
    };
    serde_json::from_slice(&browser_manifest_json(&buf))
        .map_err(|e| errors.record_malformed(Stage::FormatExtract, format!("{NAME}: {e}")))
        .ok()
}

/// `manifest.json` as strict JSON. Chrome and Firefox both accept a UTF-8 BOM
/// and `//` / `/* */` comments in it, so a manifest using either is valid,
/// not malformed; drop them (outside strings) before parsing.
pub(super) fn browser_manifest_json(raw: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    if !raw.contains(&b'/') {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    let mut in_string = false;
    while let Some((&b, tail)) = rest.split_first() {
        if in_string {
            out.push(b);
            match (b, tail.first()) {
                (b'\\', Some(&next)) => {
                    out.push(next);
                    rest = tail.get(1..).unwrap_or_default();
                    continue;
                }
                (b'"', _) => in_string = false,
                _ => {}
            }
            rest = tail;
            continue;
        }
        match (b, tail.first()) {
            (b'"', _) => {
                in_string = true;
                out.push(b);
                rest = tail;
            }
            (b'/', Some(b'/')) => {
                let end = memchr::memchr(b'\n', tail).unwrap_or(tail.len());
                rest = tail.get(end..).unwrap_or_default();
            }
            (b'/', Some(b'*')) => {
                let body = tail.get(1..).unwrap_or_default();
                rest = memchr::memmem::find(body, b"*/")
                    .and_then(|end| body.get(end + 2..))
                    .unwrap_or_default();
                out.push(b' ');
            }
            _ => {
                out.push(b);
                rest = tail;
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Emit `crx.author` / `crx.author_email` / `crx.homepage` /
/// `crx.description` from a parsed Chrome `manifest.json`. `author` may be a
/// bare string or an `{ "email": … }` object (MV3).
fn emit_manifest_identity(manifest: &JsonValue, values: &mut Values) {
    match manifest.get("author") {
        Some(JsonValue::String(s)) if !s.is_empty() => {
            values.insert_key(value_key!("crx.author"), JsonValue::String(s.clone()));
        }
        Some(JsonValue::Object(o)) => {
            if let Some(email) = o.get("email").and_then(JsonValue::as_str) {
                values.insert_key(
                    value_key!("crx.author_email"),
                    JsonValue::String(email.to_string()),
                );
            }
        }
        _ => {}
    }
    if let Some(url) = manifest.get("homepage_url").and_then(JsonValue::as_str) {
        values.insert_key(
            value_key!("crx.homepage"),
            JsonValue::String(url.to_string()),
        );
    }
    // `__MSG_*__` is a localization placeholder, not the extension's words.
    if let Some(description) = manifest
        .get("description")
        .and_then(JsonValue::as_str)
        .filter(|d| !d.is_empty() && !d.starts_with("__MSG_"))
    {
        values.insert_key(
            value_key!("crx.description"),
            JsonValue::String(description.to_string()),
        );
    }
}

fn header(bytes: &[u8], values: &mut Values) {
    if !bytes.starts_with(b"Cr24") || bytes.len() < 12 {
        return;
    }
    let Some(version) = u32_le(bytes, 4) else {
        return;
    };
    values.insert_key(value_key!("crx.version"), JsonValue::from(version));

    let verified = match version {
        2 => {
            let Some(public_key) = crx2_public_key(bytes) else {
                return;
            };
            let digest = Sha256::digest(public_key);
            values.insert_key(
                value_key!("crx.public_key_sha256"),
                JsonValue::String(hex_encode(&digest)),
            );
            values.insert_key(
                value_key!("crx.extension_id"),
                JsonValue::String(extension_id(&digest)),
            );
            crx2_verified(bytes, public_key)
        }
        3 => {
            let Some((header, archive)) = crx3_parts(bytes) else {
                return;
            };
            let Some(signed_data) = signed_header_data(header) else {
                return;
            };
            let Some(crx_id) = signed_crx_id(signed_data) else {
                return;
            };
            values.insert_key(
                value_key!("crx.extension_id"),
                JsonValue::String(extension_id(crx_id)),
            );
            if let Some(public_key) = matching_developer_public_key(header, crx_id) {
                let digest = Sha256::digest(public_key);
                values.insert_key(
                    value_key!("crx.public_key_sha256"),
                    JsonValue::String(hex_encode(&digest)),
                );
            }
            crx3_verified(header, signed_data, crx_id, archive)
        }
        _ => return,
    };
    values.insert_key(
        value_key!("crx.signature_verified"),
        JsonValue::Bool(verified),
    );
}

fn crx2_public_key(bytes: &[u8]) -> Option<&[u8]> {
    let key_len = u32_le(bytes, 8)? as usize;
    let start = 16usize;
    bytes.get(start..start.checked_add(key_len)?)
}

/// Whether the CRX2 signature, which follows the key, is the key's RSA
/// PKCS#1 v1.5 SHA-1 signature over the archive that follows it.
fn crx2_verified(bytes: &[u8], public_key: &[u8]) -> bool {
    let Some(sig_len) = u32_le(bytes, 12) else {
        return false;
    };
    let sig_start = 16 + public_key.len();
    let Some(archive_start) = sig_start.checked_add(sig_len as usize) else {
        return false;
    };
    let (Some(signature), Some(archive)) = (
        bytes.get(sig_start..archive_start),
        bytes.get(archive_start..),
    ) else {
        return false;
    };
    let digest = sha1::Sha1::digest(archive);
    verify_rsa(
        public_key,
        rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
        &digest,
        signature,
    )
}

/// The CRX3 protobuf header and the archive after it.
fn crx3_parts(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let header_len = u32_le(bytes, 8)? as usize;
    let end = 12usize.checked_add(header_len)?;
    Some((bytes.get(12..end)?, bytes.get(end..)?))
}

/// Whether a proof carrying the key that hashes to `crx_id` signs this
/// header's `signed_data` and `archive`. Proofs under other keys (the Web
/// Store's publisher proof) cannot establish the id and are not checked.
fn crx3_verified(header: &[u8], signed_data: &[u8], crx_id: &[u8], archive: &[u8]) -> bool {
    let Ok(signed_len) = u32::try_from(signed_data.len()) else {
        return false;
    };
    // The signed message is the whole file past the header; hash it once,
    // and only if a candidate proof exists.
    let mut digest = None;
    let mut checks = 0;
    let mut pos = 0;
    while let Some((field, proof)) = next_field(header, &mut pos) {
        if field != 2 && field != 3 {
            continue;
        }
        let Some((public_key, signature)) = proof_parts(proof) else {
            continue;
        };
        if Sha256::digest(public_key).get(..16) != Some(crx_id) {
            continue;
        }
        if checks == MAX_PROOF_CHECKS {
            return false;
        }
        checks += 1;
        let digest = digest.get_or_insert_with(|| {
            Sha256::new()
                .chain_update(CRX3_SIGNATURE_CONTEXT)
                .chain_update(signed_len.to_le_bytes())
                .chain_update(signed_data)
                .chain_update(archive)
                .finalize()
        });
        let ok = if field == 2 {
            verify_rsa(
                public_key,
                rsa::Pkcs1v15Sign::new::<Sha256>(),
                digest,
                signature,
            )
        } else {
            verify_p256(public_key, digest, signature)
        };
        if ok {
            return true;
        }
    }
    false
}

/// RSA PKCS#1 v1.5 over a precomputed digest, with the key as a DER
/// `SubjectPublicKeyInfo`.
fn verify_rsa(spki: &[u8], scheme: rsa::Pkcs1v15Sign, digest: &[u8], signature: &[u8]) -> bool {
    use rsa::pkcs8::DecodePublicKey;
    rsa::RsaPublicKey::from_public_key_der(spki)
        .is_ok_and(|key| key.verify(scheme, digest, signature).is_ok())
}

/// ECDSA P-256 over a precomputed SHA-256 digest, with the key as a DER
/// `SubjectPublicKeyInfo` and the signature DER-encoded, as Chrome writes
/// them.
fn verify_p256(spki: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_public_key_der(spki),
        Signature::from_der(signature),
    ) else {
        return false;
    };
    key.verify_prehash(digest, &signature).is_ok()
}

/// Map a SHA-256 digest to the 32-character `a..p` Chrome extension id.
fn extension_id(digest: &[u8]) -> String {
    digest
        .iter()
        .take(16)
        .flat_map(|&b| [b'a' + (b >> 4), b'a' + (b & 0x0f)])
        .map(char::from)
        .collect()
}

// --- Minimal protobuf reader for the CRX3 `CrxFileHeader` -------------
//
// We need only a few length-delimited fields: the proofs (fields 2 and 3
// of the header) with their `public_key` (1) and `signature` (2), and
// `signed_header_data` (10000) with its `crx_id` (1). A full protobuf
// library would be a heavy dependency for those nested reads, so we walk
// the wire format directly.

/// Read a base-128 varint, advancing `pos`.
fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    while let Some(&byte) = buf.get(*pos) {
        *pos += 1;
        value |= u64::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Return the bytes of a length-delimited field, advancing `pos`; skip
/// other wire types. Returns `(field_number, payload)`.
fn next_field<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u64, &'a [u8])> {
    while *pos < buf.len() {
        let tag = varint(buf, pos)?;
        let field = tag >> 3;
        match tag & 0x07 {
            0 => {
                varint(buf, pos)?;
            }
            1 => *pos = pos.checked_add(8)?,
            5 => *pos = pos.checked_add(4)?,
            2 => {
                let len = usize::try_from(varint(buf, pos)?).ok()?;
                let end = pos.checked_add(len)?;
                let data = buf.get(*pos..end)?;
                *pos = end;
                return Some((field, data));
            }
            _ => return None,
        }
    }
    None
}

/// The last length-delimited `field` in `buf`. Protobuf keeps the last
/// occurrence of a repeated scalar field, and so does Chrome: reading the
/// first would let a decoy field name an id Chrome never sees.
fn last_field(buf: &[u8], field: u64) -> Option<&[u8]> {
    let mut pos = 0;
    let mut last = None;
    while let Some((number, data)) = next_field(buf, &mut pos) {
        if number == field {
            last = Some(data);
        }
    }
    last
}

/// `CrxFileHeader.signed_header_data` (field 10000): the bytes the proofs
/// sign.
fn signed_header_data(header: &[u8]) -> Option<&[u8]> {
    last_field(header, 10_000)
}

/// `SignedData.crx_id` (field 1). A valid Chrome extension id is 16 bytes.
fn signed_crx_id(signed_data: &[u8]) -> Option<&[u8]> {
    last_field(signed_data, 1).filter(|id| id.len() == 16)
}

/// An `AsymmetricKeyProof`'s public key (field 1) and non-empty signature
/// (field 2).
fn proof_parts(proof: &[u8]) -> Option<(&[u8], &[u8])> {
    let public_key = last_field(proof, 1)?;
    let signature = last_field(proof, 2).filter(|s| !s.is_empty())?;
    Some((public_key, signature))
}

/// Return the RSA or ECDSA proof key whose SHA-256 prefix equals the signed
/// CRX id. Publisher proofs (notably the shared Chrome Web Store key) do not
/// satisfy this relation and are intentionally ignored. The key is a claim
/// until [`crx3_verified`] checks its signature.
fn matching_developer_public_key<'a>(header: &'a [u8], crx_id: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0;
    while let Some((field, proof)) = next_field(header, &mut pos) {
        if field != 2 && field != 3 {
            continue;
        }
        if let Some((public_key, _)) = proof_parts(proof)
            && Sha256::digest(public_key).get(..16) == Some(crx_id)
        {
            return Some(public_key);
        }
    }
    None
}

#[cfg(test)]
mod tests {
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
        emit_manifest_identity(
            &serde_json::json!({"description": "Blocks trackers"}),
            &mut v,
        );
        assert_eq!(
            v.get("crx.description").and_then(JsonValue::as_str),
            Some("Blocks trackers")
        );
        let mut v = Values::new();
        emit_manifest_identity(&serde_json::json!({"description": "__MSG_desc__"}), &mut v);
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
            "../../tests/fixtures/crx/test-rsa1024.pk8.der"
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
            values.get("crx.author").and_then(JsonValue::as_str),
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
        assert!(values.get("crx.version").is_none());
    }
}
