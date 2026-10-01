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
use crate::formats::common::bytes_at::u32_le;
use crate::formats::common::hex_encode;
use crate::output::{ArchiveMember, Errors, Metrics, Stage, Values};

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
    let mut archive = super::zip::open_archive(bytes)?;
    super::zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
    // The extension's `manifest.json` carries the developer-declared
    // author and homepage — the human identity behind the signing key.
    if let Some(manifest) = read_manifest(&mut archive, values, errors) {
        emit_manifest_identity(&manifest, values);
    }
    Ok(())
}

/// Read and parse the root `manifest.json` of an opened CRX archive.
/// `None` when it is absent (silently), over the size cap (a `crx.limits`
/// entry), or unreadable or not JSON (an error).
fn read_manifest<R: Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    errors: &mut Errors,
) -> Option<JsonValue> {
    const NAME: &str = "manifest.json";
    const MAX: u64 = 512 * 1024;
    let member = match zip.by_name(NAME) {
        Ok(member) => member,
        Err(::zip::result::ZipError::FileNotFound) => return None,
        Err(e) => {
            errors.record_malformed(Stage::ZipParse, format!("{NAME}: {e}"));
            return None;
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = member.take(MAX + 1).read_to_end(&mut buf) {
        errors.record_malformed(Stage::ZipParse, format!("{NAME}: {e}"));
        return None;
    }
    if buf.len() as u64 > MAX {
        values.insert(
            "crx.limits",
            serde_json::json!([{
                "stage": "manifest",
                "reason": format!("{NAME} over the {MAX}-byte cap; not parsed"),
            }]),
        );
        return None;
    }
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

/// Emit `crx.author` / `crx.author_email` / `crx.homepage_url` /
/// `crx.description` from a parsed Chrome `manifest.json`. `author` may be a
/// bare string or an `{ "email": … }` object (MV3).
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
    // `__MSG_*__` is a localization placeholder, not the extension's words.
    if let Some(description) = manifest
        .get("description")
        .and_then(JsonValue::as_str)
        .filter(|d| !d.is_empty() && !d.starts_with("__MSG_"))
    {
        values.insert(
            "crx.description",
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
    values.insert("crx.version", JsonValue::from(version));

    match version {
        2 => {
            let Some(public_key) = crx2_public_key(bytes) else {
                return;
            };
            let digest = Sha256::digest(public_key);
            values.insert(
                "crx.public_key_sha256",
                JsonValue::String(hex_encode(&digest)),
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
                    JsonValue::String(hex_encode(&digest)),
                );
            }
        }
        _ => {}
    }
}

fn crx2_public_key(bytes: &[u8]) -> Option<&[u8]> {
    let key_len = u32_le(bytes, 8)? as usize;
    let start = 16usize;
    bytes.get(start..start.checked_add(key_len)?)
}

fn crx3_header(bytes: &[u8]) -> Option<&[u8]> {
    let header_len = u32_le(bytes, 8)? as usize;
    bytes.get(12..12usize.checked_add(header_len)?)
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
// We only need one field: the `public_key` (field 1) of the first
// `sha256_with_rsa` proof (field 2 of the header). A full protobuf
// library would be a heavy dependency for two nested length-delimited
// reads, so we walk the wire format directly.

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
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
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
