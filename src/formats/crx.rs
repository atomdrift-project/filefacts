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

use std::io::Read;

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::output::{ArchiveMember, Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    // Header decode is best-effort identity enrichment; a malformed
    // header must not stop the ZIP walk.
    header(bytes, values);
    let mut archive = super::zip::open_archive(bytes)?;
    super::zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
    // The extension's `manifest.json` carries the developer-declared
    // author and homepage — the human identity behind the signing key.
    if let Some(manifest) = read_manifest(&mut archive) {
        emit_manifest_identity(&manifest, values);
    }
    Ok(())
}

/// Read and parse the root `manifest.json` of an opened CRX archive.
fn read_manifest<R: Read + std::io::Seek>(zip: &mut ::zip::ZipArchive<R>) -> Option<JsonValue> {
    const MAX: u64 = 512 * 1024;
    let member = zip.by_name("manifest.json").ok()?;
    let mut buf = Vec::new();
    member.take(MAX).read_to_end(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// Emit `crx.author` / `crx.author_email` / `crx.homepage_url` from a
/// parsed Chrome `manifest.json`. `author` may be a bare string or an
/// `{ "email": … }` object (MV3).
fn emit_manifest_identity(manifest: &JsonValue, values: &mut Values) {
    match manifest.get("author") {
        Some(JsonValue::String(s)) if !s.is_empty() => {
            values.insert("crx.author", JsonValue::String(s.clone()));
        }
        Some(JsonValue::Object(o)) => {
            if let Some(email) = o.get("email").and_then(JsonValue::as_str) {
                values.insert("crx.author_email", JsonValue::String(email.to_string()));
            }
        }
        _ => {}
    }
    if let Some(url) = manifest.get("homepage_url").and_then(JsonValue::as_str) {
        values.insert("crx.homepage_url", JsonValue::String(url.to_string()));
    }
}

fn header(bytes: &[u8], values: &mut Values) {
    if !bytes.starts_with(b"Cr24") || bytes.len() < 12 {
        return;
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    values.insert("crx.version", JsonValue::from(version));

    match version {
        2 => {
            let Some(public_key) = crx2_public_key(bytes) else {
                return;
            };
            let digest = Sha256::digest(public_key);
            values.insert(
                "crx.public_key_sha256",
                JsonValue::String(hex_lower(&digest)),
            );
            values.insert("crx.extension_id", JsonValue::String(extension_id(&digest)));
        }
        3 => {
            let Some(header) = crx3_header(bytes) else {
                return;
            };
            let Some(crx_id) = signed_crx_id(header) else {
                return;
            };
            values.insert("crx.extension_id", JsonValue::String(extension_id(crx_id)));
            if let Some(public_key) = matching_developer_public_key(header, crx_id) {
                let digest = Sha256::digest(public_key);
                values.insert(
                    "crx.public_key_sha256",
                    JsonValue::String(hex_lower(&digest)),
                );
            }
        }
        _ => {}
    }
}

fn crx2_public_key(bytes: &[u8]) -> Option<&[u8]> {
    let key_len = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
    let start = 16usize;
    bytes.get(start..start.checked_add(key_len)?)
}

fn crx3_header(bytes: &[u8]) -> Option<&[u8]> {
    let header_len = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
    bytes.get(12..12usize.checked_add(header_len)?)
}

/// Map a SHA-256 digest to the 32-character `a..p` Chrome extension id.
fn extension_id(digest: &[u8]) -> String {
    digest[..16]
        .iter()
        .flat_map(|&b| [b'a' + (b >> 4), b'a' + (b & 0x0f)])
        .map(char::from)
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    out
}

// --- Minimal protobuf reader for the CRX3 `CrxFileHeader` -------------
//
// We only need one field: the `public_key` (field 1) of the first
// `sha256_with_rsa` proof (field 2 of the header). A full protobuf
// library would be a heavy dependency for two nested length-delimited
// reads, so we walk the wire format directly.

/// Read a base-128 varint, advancing `pos`.
fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    while *pos < buf.len() {
        let byte = buf[*pos];
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

/// Decode `CrxFileHeader.signed_header_data` (field 10000), then return
/// `SignedData.crx_id` (field 1). A valid Chrome extension id is 16 bytes.
fn signed_crx_id(header: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    while let Some((field, data)) = next_field(header, &mut pos) {
        if field == 10_000 {
            let mut inner = 0;
            while let Some((signed_field, signed_data)) = next_field(data, &mut inner) {
                if signed_field == 1 && signed_data.len() == 16 {
                    return Some(signed_data);
                }
            }
        }
    }
    None
}

/// Return the RSA or ECDSA proof key whose SHA-256 prefix equals the signed
/// CRX id. Publisher proofs (notably the shared Chrome Web Store key) do not
/// satisfy this relation and are intentionally ignored.
fn matching_developer_public_key<'a>(header: &'a [u8], crx_id: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0;
    while let Some((field, proof)) = next_field(header, &mut pos) {
        if field != 2 && field != 3 {
            continue;
        }
        let mut inner = 0;
        let mut public_key = None;
        let mut has_signature = false;
        while let Some((proof_field, data)) = next_field(proof, &mut inner) {
            match proof_field {
                1 => public_key = Some(data),
                2 => has_signature = !data.is_empty(),
                _ => {}
            }
        }
        if has_signature
            && let Some(public_key) = public_key
            && Sha256::digest(public_key).get(..16) == Some(crx_id)
        {
            return Some(public_key);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Some(hex_lower(&digest).as_str())
        );
    }

    #[test]
    fn non_crx_bytes_emit_nothing() {
        let mut values = Values::new();
        header(b"PK\x03\x04not a crx", &mut values);
        assert!(values.get("crx.version").is_none());
    }
}
