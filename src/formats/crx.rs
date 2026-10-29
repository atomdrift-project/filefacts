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

use super::people::{self, Person};
use std::io::Read;

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use super::bounded::Limits;
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
    let mut limits = Limits::default();
    let manifest = read_browser_manifest(&mut archive, &mut limits, errors);
    limits.emit(values, value_key!("crx.limits"));
    if let Some(manifest) = manifest {
        emit_web_extension_identity(&manifest, &CRX_KEYS, values);
    }
    Ok(())
}

/// Read and parse the root `manifest.json` of an opened browser-extension
/// archive (CRX or XPI). `None` when it is absent (silently), over the size
/// cap (a `limits` entry), or unreadable or not JSON (an error).
pub(super) fn read_browser_manifest<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    limits: &mut Limits,
    errors: &mut Errors,
) -> Option<JsonValue> {
    const NAME: &str = "manifest.json";
    const MAX: u64 = 512 * 1024;
    let buf = super::zip::read_manifest_member(zip, NAME, MAX, limits, "manifest", errors)?;
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

/// Where one browser's `manifest.json` identity fields land.
pub(super) struct WebExtensionKeys {
    authors: ValueKey,
    homepage: ValueKey,
    description: ValueKey,
    name: ValueKey,
    version: ValueKey,
}

const CRX_KEYS: WebExtensionKeys = WebExtensionKeys {
    authors: value_key!("crx.authors"),
    homepage: value_key!("crx.homepage"),
    description: value_key!("crx.description"),
    name: value_key!("crx.name"),
    version: value_key!("crx.version"),
};

pub(super) const XPI_KEYS: WebExtensionKeys = WebExtensionKeys {
    authors: value_key!("xpi.authors"),
    homepage: value_key!("xpi.homepage"),
    description: value_key!("xpi.description"),
    name: value_key!("xpi.name"),
    version: value_key!("xpi.version"),
};

/// Emit the identity a WebExtension `manifest.json` declares, for Chrome and
/// Firefox alike. `author` may be a bare string or an `{ "email": … }`
/// object (Chrome MV3). `name` and `description` are skipped when they are
/// `__MSG_*__` localization placeholders, which are not the extension's
/// words.
pub(super) fn emit_web_extension_identity(
    manifest: &JsonValue,
    keys: &WebExtensionKeys,
    values: &mut Values,
) {
    let text = |field: &str| {
        manifest
            .get(field)
            .and_then(JsonValue::as_str)
            .filter(|s| !s.is_empty())
    };
    let words = |field: &str| text(field).filter(|s| !s.starts_with("__MSG_"));
    let mut put = |key: ValueKey, value: Option<&str>| {
        if let Some(value) = value {
            values.insert_key(key, JsonValue::String(value.to_string()));
        }
    };
    put(keys.homepage, text("homepage_url"));
    put(keys.description, words("description"));
    put(keys.name, words("name"));
    put(keys.version, text("version"));
    // A string `author` is a name; Chrome MV3's object form carries an email.
    let author = match manifest.get("author") {
        Some(object @ JsonValue::Object(_)) => Person::from_json(object),
        _ => Person::from_fields(text("author"), None),
    };
    people::put(values, keys.authors, [author]);
}

fn header(bytes: &[u8], values: &mut Values) {
    if !bytes.starts_with(b"Cr24") || bytes.len() < 12 {
        return;
    }
    let Some(version) = u32_le(bytes, 4) else {
        return;
    };
    values.insert_key(value_key!("crx.format_version"), JsonValue::from(version));

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
mod tests;
