//! Authenticode PKCS#7 SignedData parser for PE files.
//!
//! The PE optional header's Certificate Table directory entry points to
//! a sequence of `WIN_CERTIFICATE` records. For Authenticode signatures,
//! each record carries a DER-encoded PKCS#7 `SignedData` blob whose
//! `encapContentInfo` is an `SpcIndirectDataContent` covering the PE
//! image digest, and whose `signerInfo` references a signing certificate
//! whose subject, issuer, validity, and serial number are the bits a
//! forensic analyst wants to see.
//!
//! We expose the *primary signer*'s certificate fields plus the
//! signature's digest algorithm. RFC 3161 countersignatures and full
//! certificate chains are parked for a richer extractor later — what we
//! emit here is enough to answer "who claims to have signed this, and
//! when did the cert expire?".

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::output::Values;

/// Parse the Certificate Table contents `cert_table_bytes` (the bytes
/// the PE optional header's directory entry points at) and write
/// signature facts into `values` under `pe.authenticode.*`.
///
/// On parse failure, leaves the values untouched and returns silently —
/// `pe.signed` (set by the caller) is the only marker
/// consumers should rely on to know whether a signature *exists*.
pub(super) fn parse(cert_table_bytes: &[u8], values: &mut Values) {
    // The certificate table is a sequence of WIN_CERTIFICATE records:
    //   DWORD dwLength      (total length, including this header)
    //   WORD  wRevision     (0x0200 = revision 2)
    //   WORD  wCertificateType  (0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    //   BYTE  bCertificate[]
    // Each record is padded to an 8-byte boundary.
    let mut pos = 0;
    let mut signatures: Vec<JsonValue> = Vec::new();
    while pos + 8 <= cert_table_bytes.len() {
        let length = u32::from_le_bytes([
            cert_table_bytes[pos],
            cert_table_bytes[pos + 1],
            cert_table_bytes[pos + 2],
            cert_table_bytes[pos + 3],
        ]) as usize;
        if length < 8 || pos + length > cert_table_bytes.len() {
            break;
        }
        let cert_type = u16::from_le_bytes([
            cert_table_bytes[pos + 6],
            cert_table_bytes[pos + 7],
        ]);
        // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA. Other types
        // (x.509 cert wrapper, reserved, TS_STACK_SIGNED) are not
        // currently parsed.
        if cert_type == 0x0002 {
            let blob = &cert_table_bytes[pos + 8..pos + length];
            // `dwLength` rounds the PKCS#7 blob up to an 8-byte
            // boundary with null padding; the DER decoder rejects that
            // padding as trailing garbage. Trim to the SEQUENCE's
            // own declared length.
            let trimmed = trim_to_der_object(blob).unwrap_or(blob);
            if let Some(sig) = parse_pkcs7(trimmed) {
                signatures.push(sig);
            }
        }
        // Align to 8 bytes.
        pos += (length + 7) & !7;
    }
    if !signatures.is_empty() {
        values.insert(
            "pe.signatures",
            JsonValue::Array(signatures),
        );
    }
}

/// Parse a CMS / PKCS#7 SignedData blob and return the same signer-cert
/// JSON object the PE Authenticode path emits. Exposed to the Mach-O
/// code-signature module so it can hand off the embedded CMS blob
/// found inside `CSMAGIC_BLOBWRAPPER` and get the same forensic
/// fields back.
pub(super) fn parse_cms_blob(der_bytes: &[u8]) -> Option<JsonValue> {
    parse_pkcs7(der_bytes)
}

fn parse_pkcs7(der_bytes: &[u8]) -> Option<JsonValue> {
    let ci = ContentInfo::from_der(der_bytes)
        .inspect_err(|e| crate::debug::log(format_args!("pe.authenticode ContentInfo::from_der failed: {e}")))
        .ok()?;
    // For Authenticode the outer ContentInfo wraps a SignedData.
    let signed_data: SignedData = ci
        .content
        .decode_as()
        .inspect_err(|e| crate::debug::log(format_args!("pe.authenticode SignedData decode_as failed: {e}")))
        .ok()?;

    let signer = signed_data.signer_infos.0.as_slice().first()?;
    let digest_algorithm = oid_to_label(&signer.digest_alg.oid);

    // Resolve the signer's certificate from the SignedData.certificates
    // bag by matching on issuer + serial number.
    let signer_cert = find_signer_cert(&signed_data, signer);

    let mut obj = serde_json::Map::new();
    obj.insert(
        "digest_algorithm".into(),
        JsonValue::String(digest_algorithm.into()),
    );

    if let Some(cert) = signer_cert {
        let tbs = &cert.tbs_certificate;
        // The signer cert's fields land directly on the signature
        // object — every PE signature has exactly one signer, so the
        // `.signer.` namespace would just stutter. Subject / issuer /
        // serial / validity / thumbprints are properties OF the signer
        // and read more naturally without the extra path segment.
        obj.insert("subject".into(), JsonValue::String(tbs.subject.to_string()));
        obj.insert("issuer".into(), JsonValue::String(tbs.issuer.to_string()));
        obj.insert(
            "serial".into(),
            JsonValue::String(hex_encode(tbs.serial_number.as_bytes())),
        );
        obj.insert(
            "not_before".into(),
            JsonValue::String(time_to_string(tbs.validity.not_before)),
        );
        obj.insert(
            "not_after".into(),
            JsonValue::String(time_to_string(tbs.validity.not_after)),
        );

        // Thumbprints are computed over the entire DER encoding of the
        // certificate — the most stable per-certificate fingerprint.
        // The `thumbprint_` prefix is canonical (sigcheck, signtool,
        // and PowerShell's `Get-AuthenticodeSignature` all use it)
        // and disambiguates from the signature's own digest_algorithm
        // and the PE image hash.
        if let Ok(cert_der) = cert.to_der() {
            obj.insert(
                "thumbprint_sha1".into(),
                JsonValue::String(hex_encode(&Sha1::digest(&cert_der))),
            );
            obj.insert(
                "thumbprint_sha256".into(),
                JsonValue::String(hex_encode(&Sha256::digest(&cert_der))),
            );
        }
    }

    // Pull signing-time from the signed-attributes bag if present
    // (OID 1.2.840.113549.1.9.5).
    if let Some(signing_time) = extract_signing_time(signer) {
        obj.insert("signing_time".into(), JsonValue::String(signing_time));
    }

    Some(JsonValue::Object(obj))
}

fn find_signer_cert<'a>(
    signed_data: &'a SignedData,
    signer: &cms::signed_data::SignerInfo,
) -> Option<&'a x509_cert::Certificate> {
    let bag = signed_data.certificates.as_ref()?;
    for entry in bag.0.iter() {
        let cms::cert::CertificateChoices::Certificate(ref cert) = entry else {
            continue;
        };
        let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ref isn) = signer.sid else {
            // SubjectKeyIdentifier matching for `subject_key_identifier`
            // variant is uncommon in Authenticode; skip.
            continue;
        };
        if cert.tbs_certificate.issuer == isn.issuer
            && cert.tbs_certificate.serial_number == isn.serial_number
        {
            return Some(cert);
        }
    }
    None
}

/// PKCS#9 signing-time OID.
const SIGNING_TIME_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

fn extract_signing_time(signer: &cms::signed_data::SignerInfo) -> Option<String> {
    let attrs = signer.signed_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != SIGNING_TIME_OID {
            continue;
        }
        let any = attr.values.as_slice().first()?;
        // CHOICE { UTCTime, GeneralizedTime }. Try both — `decode_as`
        // succeeds for whichever the ANY actually contains.
        if let Ok(t) = any.decode_as::<der::asn1::UtcTime>() {
            return Some(t.to_date_time().to_string());
        }
        if let Ok(t) = any.decode_as::<der::asn1::GeneralizedTime>() {
            return Some(t.to_date_time().to_string());
        }
    }
    None
}

/// Return the prefix of `bytes` that is exactly one DER-encoded object,
/// or `None` if the bytes don't start with a recognisable
/// definite-length DER header.
///
/// DER lengths come in two encodings:
/// - **Short form** (length byte `0x00..=0x7F`): the next `N` bytes are
///   the object's contents.
/// - **Long form** (first byte `0x81..=0x88`): the low 7 bits give the
///   number of subsequent length bytes (big-endian), which in turn give
///   the content length. We refuse lengths beyond 8 bytes — Authenticode
///   blobs never reach those scales and longer encodings are typically
///   malformed.
fn trim_to_der_object(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 2 {
        return None;
    }
    // The leading tag byte: we don't constrain it (Authenticode wraps a
    // SEQUENCE `0x30`, but the helper is intentionally tag-agnostic).
    let len_byte = bytes[1];
    let (header_size, content_len) = if len_byte & 0x80 == 0 {
        (2_usize, len_byte as usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 8 || bytes.len() < 2 + n {
            return None;
        }
        let mut content_len = 0_usize;
        for &b in &bytes[2..2 + n] {
            content_len = (content_len << 8) | (b as usize);
        }
        (2 + n, content_len)
    };
    let total = header_size.checked_add(content_len)?;
    if total > bytes.len() {
        return None;
    }
    Some(&bytes[..total])
}

fn time_to_string(t: x509_cert::time::Time) -> String {
    use x509_cert::time::Time;
    match t {
        Time::UtcTime(v) => v.to_date_time().to_string(),
        Time::GeneralTime(v) => v.to_date_time().to_string(),
    }
}

fn oid_to_label(oid: &ObjectIdentifier) -> &'static str {
    // Common digest-algorithm OIDs. Anything we don't recognise falls
    // back to the dotted OID string via the caller (we return "other"
    // here and the caller can choose to surface the OID separately —
    // for v1 we just label).
    match oid.to_string().as_str() {
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.113549.2.5" => "md5",
        _ => "other",
    }
}

use crate::formats::common::hex_encode;

#[cfg(test)]
mod tests {
    use super::{oid_to_label, trim_to_der_object};
    use der::oid::ObjectIdentifier;

    #[test]
    fn known_digest_oids() {
        let sha256 = ObjectIdentifier::new("2.16.840.1.101.3.4.2.1").unwrap();
        assert_eq!(oid_to_label(&sha256), "sha256");
        let sha1 = ObjectIdentifier::new("1.3.14.3.2.26").unwrap();
        assert_eq!(oid_to_label(&sha1), "sha1");
    }

    #[test]
    fn trim_strips_short_form_trailing_padding() {
        // SEQUENCE of 3 bytes content, then 4 padding bytes.
        let bytes = [0x30, 0x03, b'a', b'b', b'c', 0, 0, 0, 0];
        let out = trim_to_der_object(&bytes).expect("short-form length");
        assert_eq!(out, &[0x30, 0x03, b'a', b'b', b'c']);
    }

    #[test]
    fn trim_strips_long_form_trailing_padding() {
        // SEQUENCE with `0x82` two-byte length = 0x0003 = 3, then pad.
        let bytes = [0x30, 0x82, 0x00, 0x03, b'x', b'y', b'z', 0, 0, 0, 0];
        let out = trim_to_der_object(&bytes).expect("long-form length");
        assert_eq!(out, &[0x30, 0x82, 0x00, 0x03, b'x', b'y', b'z']);
    }

    #[test]
    fn trim_handles_zero_padded_authenticode_shape() {
        // The exact failure mode that broke Microsoft-signed DLLs: the
        // PE certificate-table record's `dwLength` rounded the PKCS#7
        // blob up to an 8-byte boundary, leaving three null padding
        // bytes after the SEQUENCE.
        let header = [0x30, 0x82, 0x00, 0x05];
        let content = [1, 2, 3, 4, 5];
        let mut padded = Vec::new();
        padded.extend_from_slice(&header);
        padded.extend_from_slice(&content);
        padded.extend_from_slice(&[0, 0, 0]); // 3 bytes of pad
        let out = trim_to_der_object(&padded).expect("trimmed");
        assert_eq!(out.len(), header.len() + content.len());
    }

    #[test]
    fn trim_rejects_truncated_length() {
        // Long-form length declares 4 length bytes but only 2 follow.
        let bytes = [0x30, 0x84, 0x00, 0x00];
        assert!(trim_to_der_object(&bytes).is_none());
    }

    #[test]
    fn trim_rejects_oversized_length() {
        // Claims 1000-byte content but only 4 bytes are present.
        let bytes = [0x30, 0x82, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00];
        assert!(trim_to_der_object(&bytes).is_none());
    }
}
