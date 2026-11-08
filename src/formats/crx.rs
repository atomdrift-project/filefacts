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
//! As in Chrome, a CRX3 verifies only when every proof in its header does.

use super::people::{self, Person};
use crate::formats::ExtractCtx;
use std::io::Read;

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use super::bounded::Limits;
use crate::bytes::{sat_usize, u32_le};
use crate::error::Error;
use crate::formats::common::hex_encode;
use crate::output::{Errors, Stage, ValueKey, Values};
use crate::value_key;

/// Proofs whose signatures are checked. A real CRX3 has one or two (the
/// developer's, and the Web Store's); each check is a public-key operation,
/// and a header can repeat a proof as often as its length allows. A header
/// with more proofs than this does not verify, since Chrome checks them all.
const MAX_PROOF_CHECKS: usize = 4;

/// `CrxFileHeader` field numbers: the RSA and ECDSA `AsymmetricKeyProof`s,
/// and the `SignedData` the proofs sign.
const RSA_PROOF: u64 = 2;
const ECDSA_PROOF: u64 = 3;
const SIGNED_HEADER_DATA: u64 = 10_000;

/// The context string CRX3 signs ahead of the signed header data.
const CRX3_SIGNATURE_CONTEXT: &[u8] = b"CRX3 SignedData\x00";

pub(super) fn extract(bytes: &[u8], ctx: ExtractCtx<'_>) -> Result<(), Error> {
    let ExtractCtx {
        values,
        metrics,
        archive_members,
        errors,
        ..
    } = ctx;
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
    if let Some(offset) = archive_offset(bytes, version) {
        values.insert_key(value_key!("crx.archive_offset"), JsonValue::from(offset));
    }

    let verified = match version {
        2 => {
            // The DER key follows the 16-byte fixed header.
            let Some(public_key) =
                u32_le(bytes, 8).and_then(|key_len| bytes.get(16..)?.get(..sat_usize(key_len)))
            else {
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
            // The protobuf header follows the 12-byte fixed header, and the
            // archive follows it.
            let Some((header, archive)) = u32_le(bytes, 8)
                .and_then(|header_len| bytes.get(12..)?.split_at_checked(sat_usize(header_len)))
            else {
                return;
            };
            let Some(signed_data) = signed_header_data(header) else {
                return;
            };
            // `SignedData.crx_id` (field 1); a valid extension id is 16 bytes.
            let Some(crx_id) = last_field(signed_data, 1).filter(|id| id.len() == 16) else {
                return;
            };
            values.insert_key(
                value_key!("crx.extension_id"),
                JsonValue::String(extension_id(crx_id)),
            );
            // The developer key is a claim until `crx3_verified` checks it.
            if let Some((_, public_key, _)) = proofs(header)
                .flatten()
                .find(|&(_, key, _)| is_developer_key(key, crx_id))
            {
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

/// Where the ZIP archive begins: after CRX2's 16-byte header, key and
/// signature, or CRX3's 12-byte header and protobuf header. `None` when the
/// declared lengths run past the file.
fn archive_offset(bytes: &[u8], version: u32) -> Option<usize> {
    let offset = match version {
        2 => 16usize
            .checked_add(sat_usize(u32_le(bytes, 8)?))?
            .checked_add(sat_usize(u32_le(bytes, 12)?))?,
        3 => 12usize.checked_add(sat_usize(u32_le(bytes, 8)?))?,
        _ => return None,
    };
    (offset <= bytes.len()).then_some(offset)
}

/// Whether the CRX2 signature, which follows the key, is the key's RSA
/// PKCS#1 v1.5 SHA-1 signature over the archive that follows it.
fn crx2_verified(bytes: &[u8], public_key: &[u8]) -> bool {
    let Some(sig_len) = u32_le(bytes, 12) else {
        return false;
    };
    let sig_start = 16 + public_key.len();
    let Some(archive_start) = sig_start.checked_add(sat_usize(sig_len)) else {
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

/// Whether the header parses in full, every proof signs this header's
/// `signed_data` and `archive`, and one of them is by the key that hashes to
/// `crx_id`. Chrome refuses a file with a malformed header or any proof that
/// does not verify, the Web Store's publisher proof included, and only a key
/// hashing to the id establishes it.
fn crx3_verified(header: &[u8], signed_data: &[u8], crx_id: &[u8], archive: &[u8]) -> bool {
    let Ok(signed_len) = u32::try_from(signed_data.len()) else {
        return false;
    };
    let proof_messages = || {
        fields(header)
            .filter(|&(field, _)| matches!(field, RSA_PROOF | ECDSA_PROOF))
            .map(|(_, proof)| proof)
    };
    if !well_formed(header) || !well_formed(signed_data) || !proof_messages().all(well_formed) {
        tracing::debug!(
            target: "filefacts::crx",
            stage = "header",
            len = header.len(),
            "CRX3 header is not well-formed protobuf; signature not verified"
        );
        return false;
    }
    let Some(proofs) = proofs(header)
        .take(MAX_PROOF_CHECKS + 1)
        .collect::<Option<Vec<_>>>()
        .filter(|proofs| proofs.len() <= MAX_PROOF_CHECKS)
    else {
        return false;
    };
    if !proofs
        .iter()
        .any(|&(_, public_key, _)| is_developer_key(public_key, crx_id))
    {
        return false;
    }
    // The signed message is the whole file past the header; hash it once.
    let digest = Sha256::new()
        .chain_update(CRX3_SIGNATURE_CONTEXT)
        .chain_update(signed_len.to_le_bytes())
        .chain_update(signed_data)
        .chain_update(archive)
        .finalize();
    proofs.iter().all(|&(field, public_key, signature)| {
        if field == RSA_PROOF {
            verify_rsa(
                public_key,
                rsa::Pkcs1v15Sign::new::<Sha256>(),
                &digest,
                signature,
            )
        } else {
            verify_p256(public_key, &digest, signature)
        }
    })
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

/// The next field of any wire type, advancing `pos`: its number, and its
/// payload when it is length-delimited. `None` at the end of `buf` and at a
/// malformed field: field number zero, a group or unknown wire type, or a
/// value running past the end.
fn next_field<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u64, Option<&'a [u8]>)> {
    if *pos >= buf.len() {
        return None;
    }
    let tag = varint(buf, pos)?;
    let field = tag >> 3;
    if field == 0 {
        return None;
    }
    let fixed = |pos: &mut usize, len: usize| {
        let end = pos.checked_add(len).filter(|&end| end <= buf.len())?;
        *pos = end;
        Some((field, None))
    };
    match tag & 0x07 {
        0 => varint(buf, pos).map(|_| (field, None)),
        1 => fixed(pos, 8),
        5 => fixed(pos, 4),
        2 => {
            let len = usize::try_from(varint(buf, pos)?).ok()?;
            let end = pos.checked_add(len)?;
            let data = buf.get(*pos..end)?;
            *pos = end;
            Some((field, Some(data)))
        }
        _ => None,
    }
}

/// Whether `buf` parses to its end as protobuf wire format. Chrome parses
/// the header, each proof and the signed data in full and refuses the file
/// when any of them does not, so a malformed field cannot hide the fields
/// after it.
fn well_formed(buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        if next_field(buf, &mut pos).is_none() {
            return false;
        }
    }
    true
}

/// The last length-delimited `field` in `buf`. Protobuf keeps the last
/// occurrence of a repeated scalar field, and so does Chrome: reading the
/// first would let a decoy field name an id Chrome never sees.
fn last_field(buf: &[u8], field: u64) -> Option<&[u8]> {
    fields(buf)
        .filter(|&(number, _)| number == field)
        .last()
        .map(|(_, data)| data)
}

/// `CrxFileHeader.signed_header_data` (field 10000): the bytes the proofs
/// sign.
fn signed_header_data(header: &[u8]) -> Option<&[u8]> {
    last_field(header, SIGNED_HEADER_DATA)
}

/// The length-delimited fields of `buf` in order, up to the first malformed
/// one; [`well_formed`] says whether there was one.
fn fields(buf: &[u8]) -> impl Iterator<Item = (u64, &[u8])> {
    let mut pos = 0;
    std::iter::from_fn(move || next_field(buf, &mut pos))
        .filter_map(|(field, data)| Some((field, data?)))
}

/// The RSA (field 2) and ECDSA (field 3) proofs, as `(field, public_key,
/// signature)`: `None` for a proof without a key or a non-empty signature,
/// which no verifier accepts.
fn proofs(header: &[u8]) -> impl Iterator<Item = Option<(u64, &[u8], &[u8])>> {
    fields(header)
        .filter(|&(field, _)| matches!(field, RSA_PROOF | ECDSA_PROOF))
        .map(|(field, proof)| {
            // An `AsymmetricKeyProof`: public key (field 1) and signature
            // (field 2).
            let public_key = last_field(proof, 1)?;
            let signature = last_field(proof, 2).filter(|s| !s.is_empty())?;
            Some((field, public_key, signature))
        })
}

/// Whether `public_key`'s SHA-256 prefix is the signed CRX id. Publisher
/// proofs (notably the shared Chrome Web Store key) do not satisfy this.
fn is_developer_key(public_key: &[u8], crx_id: &[u8]) -> bool {
    Sha256::digest(public_key).get(..16) == Some(crx_id)
}

#[cfg(test)]
mod tests;
