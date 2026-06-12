//! Chrome extension (`.crx`) header parser.
//!
//! A CRX file is a ZIP with a signed header prepended. The ZIP body is
//! walked by the generic [`super::zip`] extractor (the `zip` crate
//! tolerates the prefix); this module decodes the header to recover the
//! identity that ZIP can't carry: the packager's public key and the
//! **extension id** derived from it.
//!
//! The extension id is the canonical Chrome identifier — the first 16
//! bytes of `SHA-256(DER public key)`, each nibble mapped `0..15` →
//! `a..p`. Because it is a hash of the signing key, it is forgery-proof
//! in a way a manifest name is not.
//!
//! Two on-disk layouts:
//! - **CRX2**: `Cr24`, version, key length, signature length, then the
//!   DER `SubjectPublicKeyInfo` directly.
//! - **CRX3**: `Cr24`, version, header length, then a protobuf
//!   `CrxFileHeader` whose first `sha256_with_rsa` proof carries the
//!   public key.

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

    let Some(public_key) = public_key(bytes, version) else {
        return;
    };
    let digest = Sha256::digest(public_key);
    values.insert(
        "crx.public_key_sha256",
        JsonValue::String(hex_lower(&digest)),
    );
    values.insert("crx.extension_id", JsonValue::String(extension_id(&digest)));
}

/// Locate the DER public key for either CRX version.
fn public_key(bytes: &[u8], version: u32) -> Option<&[u8]> {
    match version {
        2 => {
            let key_len = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
            let start = 16usize;
            bytes.get(start..start.checked_add(key_len)?)
        }
        3 => {
            let header_len = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
            let header = bytes.get(12..12usize.checked_add(header_len)?)?;
            first_rsa_public_key(header)
        }
        _ => None,
    }
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

fn first_rsa_public_key(header: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    while let Some((field, data)) = next_field(header, &mut pos) {
        // Field 2 = repeated AsymmetricKeyProof sha256_with_rsa.
        if field == 2 {
            let mut inner = 0;
            while let Some((proof_field, proof_data)) = next_field(data, &mut inner) {
                // Field 1 = public_key.
                if proof_field == 1 {
                    return Some(proof_data);
                }
            }
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
    fn crx3_public_key_round_trips_through_protobuf() {
        // CrxFileHeader { sha256_with_rsa: [ { public_key: "KEY" } ] }
        // field 2 (LEN) -> { field 1 (LEN) -> "KEY" }
        let proof = [0x0a, 0x03, b'K', b'E', b'Y']; // field 1, len 3
        let mut header = vec![0x12, proof.len() as u8]; // field 2, len
        header.extend_from_slice(&proof);
        assert_eq!(first_rsa_public_key(&header), Some(&b"KEY"[..]));
    }

    #[test]
    fn non_crx_bytes_emit_nothing() {
        let mut values = Values::new();
        header(b"PK\x03\x04not a crx", &mut values);
        assert!(values.get("crx.version").is_none());
    }
}
