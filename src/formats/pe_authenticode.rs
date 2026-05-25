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
        let cert_type = u16::from_le_bytes([cert_table_bytes[pos + 6], cert_table_bytes[pos + 7]]);
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
        values.insert("pe.signatures", JsonValue::Array(signatures));
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
        .inspect_err(|e| {
            crate::debug::log(format_args!(
                "pe.authenticode ContentInfo::from_der failed: {e}"
            ))
        })
        .ok()?;
    // For Authenticode the outer ContentInfo wraps a SignedData.
    let signed_data: SignedData = ci
        .content
        .decode_as()
        .inspect_err(|e| {
            crate::debug::log(format_args!(
                "pe.authenticode SignedData decode_as failed: {e}"
            ))
        })
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

    // Count of certificates carried alongside the signature — proxy
    // for chain depth. A signing cert + intermediate + (sometimes)
    // root is typical; a bag with only the leaf is suspicious.
    if let Some(bag) = signed_data.certificates.as_ref() {
        let count = bag
            .0
            .iter()
            .filter(|e| matches!(e, cms::cert::CertificateChoices::Certificate(_)))
            .count();
        if count > 0 {
            obj.insert("cert_chain_depth".into(), JsonValue::Number(count.into()));
        }
    }

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
        // Friendly name for the cert's signature algorithm
        // (`sha256WithRSAEncryption` / `ecdsa-with-SHA256` / …). Maps
        // a stable set of OIDs; unknown algorithms surface as their
        // dotted-OID string for forward compatibility.
        obj.insert(
            "signature_algorithm".into(),
            JsonValue::String(signature_algorithm_name(&cert.signature_algorithm.oid)),
        );

        // Extended Key Usage — the leaf's claimed-purpose set. A
        // self-signed dropper rarely bothers to set `code_signing`
        // (1.3.6.1.5.5.7.3.3), so absence on a non-system signer is a
        // soft tampering signal. Self-issued = subject == issuer.
        if let Some(eku) = parse_extended_key_usage(cert) {
            obj.insert("eku_code_signing".into(), JsonValue::Bool(eku.code_signing));
        }
        let self_issued = tbs.subject == tbs.issuer;
        if self_issued {
            obj.insert("self_issued".into(), JsonValue::Bool(true));
        }

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
    // (OID 1.2.840.113549.1.9.5). Emitted in two forms: the canonical
    // ISO-8601 string for display, plus a Unix timestamp for downstream
    // arithmetic (sign-time-before-build checks, age windows, etc.).
    if let Some((s, unix)) = extract_signing_time(signer) {
        obj.insert("signing_time".into(), JsonValue::String(s));
        obj.insert("signing_time_unix".into(), JsonValue::Number(unix.into()));
    }

    // SpcIndirectDataContent — the structure inside the SignedData's
    // encapContentInfo carrying the algorithm + digest the signature
    // was made over. The digest is what consumers compare against the
    // recomputed Authentihash to detect post-signing tampering.
    if let Some((alg, digest_hex)) = extract_spc_indirect_data(&signed_data) {
        obj.insert(
            "signature_digest_algorithm".into(),
            JsonValue::String(alg.into()),
        );
        obj.insert("signature_digest".into(), JsonValue::String(digest_hex));
    }

    // Cryptographic verification of the SignerInfo signature against
    // the signer cert's public key. Verifies that whoever holds the
    // private key matching the certificate signed *exactly* this set
    // of signed-attributes (one of which carries the
    // SpcIndirectDataContent that claims the PE image hash).
    if let Some(cert) = signer_cert {
        match verify_signer_signature(signer, cert) {
            VerifyOutcome::Verified => {
                obj.insert("verified".into(), JsonValue::Bool(true));
            }
            VerifyOutcome::Failed => {
                obj.insert("verified".into(), JsonValue::Bool(false));
            }
            VerifyOutcome::Unsupported => {
                // Off-pair curve, exotic OID, or missing parts —
                // record the gap rather than guess at "valid".
                obj.insert("verified".into(), JsonValue::Null);
                obj.insert("verification_unsupported".into(), JsonValue::Bool(true));
            }
        }
    }

    // Nested signature (Microsoft `ms-counter-sign` /
    // `nested-signature`). Carrier for SHA-256 signatures on dual-
    // signed legacy binaries; the inner PKCS#7 has its own SignerInfo
    // and certificate chain. Emit it recursively so consumers see the
    // same shape as the outer signature.
    if let Some(nested) = extract_nested_signature(signer) {
        obj.insert("nested".into(), nested);
    }

    Some(JsonValue::Object(obj))
}

/// Result of cryptographically verifying a SignerInfo signature.
enum VerifyOutcome {
    /// Public-key verification succeeded — the holder of the private
    /// key matching the signer certificate signed these exact signed-
    /// attributes.
    Verified,
    /// The signature was structurally well-formed but verification
    /// against the cert's public key produced a mismatch. Either the
    /// signed bytes were tampered with or the cert doesn't match the
    /// signer.
    Failed,
    /// We couldn't even attempt verification — exotic curve, off-pair
    /// algorithm (e.g. ECDSA P-256 + SHA-384), or a malformed public
    /// key. Distinguished from `Failed` so consumers don't treat
    /// "we don't know how to check this" as "tampered".
    Unsupported,
}

/// Verify the SignerInfo's encrypted-digest field against the signer
/// certificate's public key. Re-encodes `signed_attrs` from its
/// in-message `[0] IMPLICIT` form to the canonical `SET OF Attribute`
/// shape the spec requires before hashing.
fn verify_signer_signature(
    signer: &cms::signed_data::SignerInfo,
    cert: &x509_cert::Certificate,
) -> VerifyOutcome {
    let Some(signed_attrs_der) = encode_signed_attrs(signer) else {
        return VerifyOutcome::Unsupported;
    };
    let sig_alg = signer.signature_algorithm.oid.to_string();
    let digest_alg = signer.digest_alg.oid.to_string();
    let signature = signer.signature.as_bytes();

    // RSA-PKCS1v15. The signature algorithm's OID may be the
    // hash-specific `sha256WithRSAEncryption` form or the generic
    // `rsaEncryption` (1.2.840.113549.1.1.1) — both occur in
    // Authenticode SignerInfos. When generic, the digest algorithm
    // tells us which hash to use.
    if is_rsa_oid(&sig_alg) {
        return verify_rsa(cert, &digest_alg, &signed_attrs_der, signature);
    }
    // ECDSA: OIDs are hash-specific and the curve comes from the
    // cert's SPKI parameters.
    if is_ecdsa_oid(&sig_alg) {
        return verify_ecdsa(cert, &digest_alg, &signed_attrs_der, signature);
    }
    VerifyOutcome::Unsupported
}

fn is_rsa_oid(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.1"   // rsaEncryption
            | "1.2.840.113549.1.1.4"   // md5WithRSA
            | "1.2.840.113549.1.1.5"   // sha1WithRSA
            | "1.2.840.113549.1.1.11"  // sha256WithRSA
            | "1.2.840.113549.1.1.12"  // sha384WithRSA
            | "1.2.840.113549.1.1.13" // sha512WithRSA
    )
}

fn is_ecdsa_oid(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.10045.4.1"     // ecdsa-with-SHA1
            | "1.2.840.10045.4.3.2" // ecdsa-with-SHA256
            | "1.2.840.10045.4.3.3" // ecdsa-with-SHA384
            | "1.2.840.10045.4.3.4" // ecdsa-with-SHA512
    )
}

/// Re-encode the SignerInfo's signed-attributes for verification.
/// In the wire SignerInfo the attribute bag is tagged `[0] IMPLICIT`
/// (0xA0); the cryptographic signing input replaces that with the
/// universal `SET OF Attribute` tag (0x31). Everything else (length,
/// contents) stays the same.
fn encode_signed_attrs(signer: &cms::signed_data::SignerInfo) -> Option<Vec<u8>> {
    let attrs = signer.signed_attrs.as_ref()?;
    let mut der = attrs.to_der().ok()?;
    if der.is_empty() {
        return None;
    }
    // Re-tag from [0] IMPLICIT (0xA0) to SET OF (0x31).
    der[0] = 0x31;
    Some(der)
}

fn verify_rsa(
    cert: &x509_cert::Certificate,
    digest_oid: &str,
    signed_message: &[u8],
    signature: &[u8],
) -> VerifyOutcome {
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    // SubjectPublicKeyInfo carries the RSA modulus + exponent as an
    // RSAPublicKey (PKCS#1) inside the BIT STRING.
    let spk_bits = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let public_key = match RsaPublicKey::from_pkcs1_der(spk_bits) {
        Ok(k) => k,
        Err(_) => return VerifyOutcome::Unsupported,
    };
    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return VerifyOutcome::Failed,
    };
    let verified = match digest_oid {
        "1.3.14.3.2.26" => VerifyingKey::<Sha1>::new(public_key)
            .verify(signed_message, &sig)
            .is_ok(),
        "2.16.840.1.101.3.4.2.1" => VerifyingKey::<Sha256>::new(public_key)
            .verify(signed_message, &sig)
            .is_ok(),
        "2.16.840.1.101.3.4.2.2" => VerifyingKey::<Sha384>::new(public_key)
            .verify(signed_message, &sig)
            .is_ok(),
        "2.16.840.1.101.3.4.2.3" => VerifyingKey::<Sha512>::new(public_key)
            .verify(signed_message, &sig)
            .is_ok(),
        _ => return VerifyOutcome::Unsupported,
    };
    if verified {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed
    }
}

/// Curve identifier — we only support P-256 and P-384, which cover
/// every real-world Authenticode + Mach-O CMS payload encountered.
enum NamedCurve {
    P256,
    P384,
}

fn verify_ecdsa(
    cert: &x509_cert::Certificate,
    digest_oid: &str,
    signed_message: &[u8],
    signature: &[u8],
) -> VerifyOutcome {
    // Curve OID lives in the SubjectPublicKeyInfo's algorithm
    // parameters; the SEC1-encoded public point lives in the BIT
    // STRING.
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let curve_oid = match spki.algorithm.parameters.as_ref() {
        Some(p) => match p.decode_as::<ObjectIdentifier>() {
            Ok(o) => o.to_string(),
            Err(_) => return VerifyOutcome::Unsupported,
        },
        None => return VerifyOutcome::Unsupported,
    };
    let curve = match curve_oid.as_str() {
        "1.2.840.10045.3.1.7" => NamedCurve::P256, // secp256r1 / prime256v1
        "1.3.132.0.34" => NamedCurve::P384,        // secp384r1
        _ => return VerifyOutcome::Unsupported,
    };
    let pubkey_sec1 = spki.subject_public_key.raw_bytes();

    match (&curve, digest_oid) {
        (NamedCurve::P256, "2.16.840.1.101.3.4.2.1") => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_sec1) else {
                return VerifyOutcome::Unsupported;
            };
            let Ok(sig) = Signature::from_der(signature) else {
                return VerifyOutcome::Failed;
            };
            if vk.verify(signed_message, &sig).is_ok() {
                VerifyOutcome::Verified
            } else {
                VerifyOutcome::Failed
            }
        }
        (NamedCurve::P384, "2.16.840.1.101.3.4.2.2") => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_sec1) else {
                return VerifyOutcome::Unsupported;
            };
            let Ok(sig) = Signature::from_der(signature) else {
                return VerifyOutcome::Failed;
            };
            if vk.verify(signed_message, &sig).is_ok() {
                VerifyOutcome::Verified
            } else {
                VerifyOutcome::Failed
            }
        }
        // Off-pair (P-256 + SHA-384 etc.) — extremely rare; record as
        // unsupported rather than producing a misleading mismatch.
        _ => VerifyOutcome::Unsupported,
    }
}

/// Walk the SignerInfo's `unsigned_attrs` for the Microsoft nested-
/// signature attribute (OID 1.3.6.1.4.1.311.2.4.1). When present, the
/// attribute value is itself a PKCS#7 SignedData blob; we recursively
/// parse it through the same pipeline so the consumer reads the same
/// fields on both layers.
fn extract_nested_signature(signer: &cms::signed_data::SignerInfo) -> Option<JsonValue> {
    const MS_NESTED_SIGNATURE_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");
    let attrs = signer.unsigned_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != MS_NESTED_SIGNATURE_OID {
            continue;
        }
        let any = attr.values.as_slice().first()?;
        // `any.to_der()` returns the full TLV; the nested blob is the
        // ContentInfo SEQUENCE itself.
        let nested_der = any.to_der().ok()?;
        if let Some(nested) = parse_pkcs7(&nested_der) {
            return Some(nested);
        }
    }
    None
}

/// Minimal Extended Key Usage parse — we only care about the
/// `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3) OID for code-signing
/// attribution. Other EKU OIDs are not currently surfaced.
struct ParsedEku {
    code_signing: bool,
}

fn parse_extended_key_usage(cert: &x509_cert::Certificate) -> Option<ParsedEku> {
    const EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
    const CODE_SIGNING_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id != EKU_OID {
            continue;
        }
        // EKU extension value is `SEQUENCE OF OBJECT IDENTIFIER`.
        // Decode the SEQUENCE manually — x509-cert doesn't expose a
        // typed accessor for arbitrary extensions.
        let bytes = ext.extn_value.as_bytes();
        if let Ok(seq) = der::asn1::SequenceOf::<ObjectIdentifier, 32>::from_der(bytes) {
            let mut code_signing = false;
            for oid in seq.iter() {
                if *oid == CODE_SIGNING_OID {
                    code_signing = true;
                }
            }
            return Some(ParsedEku { code_signing });
        }
        return Some(ParsedEku {
            code_signing: false,
        });
    }
    None
}

/// Map a signature-algorithm OID to its canonical friendly name. The
/// set covers what real-world Authenticode + Mach-O CMS payloads use;
/// unknown OIDs surface as the dotted-OID string so consumers can
/// match on them as data.
/// Canonical RFC name for a signature-algorithm OID, or the dotted
/// OID itself when the algorithm is outside our friendly-name table.
/// Returning the raw OID (rather than a useless `"other"`) lets a
/// forensic consumer look up exotic / new algorithms directly.
fn signature_algorithm_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption".into(),
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        other => other.to_string(),
    }
}

fn find_signer_cert<'a>(
    signed_data: &'a SignedData,
    signer: &cms::signed_data::SignerInfo,
) -> Option<&'a x509_cert::Certificate> {
    let bag = signed_data.certificates.as_ref()?;
    for entry in bag.0.iter() {
        let cms::cert::CertificateChoices::Certificate(cert) = entry else {
            continue;
        };
        let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(isn) = &signer.sid else {
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
const SIGNING_TIME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Recover the signing time from the SignerInfo signed-attributes
/// bag. Returns the ISO-8601 string alongside its Unix-epoch seconds
/// so consumers don't have to reparse the string for arithmetic.
fn extract_signing_time(signer: &cms::signed_data::SignerInfo) -> Option<(String, i64)> {
    let attrs = signer.signed_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != SIGNING_TIME_OID {
            continue;
        }
        let any = attr.values.as_slice().first()?;
        // CHOICE { UTCTime, GeneralizedTime }. Try both — `decode_as`
        // succeeds for whichever the ANY actually contains.
        if let Ok(t) = any.decode_as::<der::asn1::UtcTime>() {
            let dt = t.to_date_time();
            return Some((dt.to_string(), dt.unix_duration().as_secs() as i64));
        }
        if let Ok(t) = any.decode_as::<der::asn1::GeneralizedTime>() {
            let dt = t.to_date_time();
            return Some((dt.to_string(), dt.unix_duration().as_secs() as i64));
        }
    }
    None
}

/// Authenticode `SpcIndirectDataContent` OID — what the SignedData's
/// `encapContentInfo.eContentType` is set to for a PE signature.
const SPC_INDIRECT_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

/// Extract the algorithm + digest the signature was made over from the
/// SignedData's `encapContentInfo`. The eContent is a
/// `SpcIndirectDataContent` whose nested `messageDigest.digestAlgorithm`
/// + `messageDigest.digest` carry exactly the claim "this signature
/// authenticates a PE image whose Authentihash equals these bytes
/// under this hash".
///
/// Returns `(algorithm_label, hex_digest)` on success. The OID-to-label
/// mapping uses the same `oid_to_label` helper as the SignerInfo digest
/// so consumers see consistent shorthand ("sha256", "sha1", …).
fn extract_spc_indirect_data(
    signed_data: &cms::signed_data::SignedData,
) -> Option<(&'static str, String)> {
    let encap = &signed_data.encap_content_info;
    if encap.econtent_type != SPC_INDIRECT_DATA_OID {
        return None;
    }
    let econtent_any = encap.econtent.as_ref()?;
    // Round-trip the Any through full DER encoding so we get the
    // SpcIndirectDataContent SEQUENCE's tag + length back, then parse
    // it as a regular SEQUENCE. `Any::value()` strips the outer wrapper
    // which makes structural parsing fragile across the
    // [0]-EXPLICIT-OCTET-STRING / [0]-EXPLICIT-SpcIndirect variants
    // Microsoft uses in practice.
    let full_der = econtent_any.to_der().ok()?;
    parse_spc_indirect_inner(&full_der)
}

/// Walk the DER bytes of the SpcIndirectDataContent SEQUENCE and pull
/// out the `messageDigest` (DigestInfo) component. Matches the spec
/// layout: `SEQUENCE { data SpcAttributeTypeAndOptionalValue,
///                     messageDigest DigestInfo }`.
fn parse_spc_indirect_inner(der: &[u8]) -> Option<(&'static str, String)> {
    use der::Reader as _;
    let mut reader = der::SliceReader::new(der).ok()?;
    // The bytes we're handed may be either the bare SpcIndirectDataContent
    // SEQUENCE or that SEQUENCE wrapped in an OCTET STRING (the
    // RFC-5652-strict form). Peek the tag and unwrap if needed.
    let header = reader.peek_header().ok()?;
    let body_bytes: Vec<u8> = if header.tag == der::Tag::OctetString {
        // OCTET STRING containing the SEQUENCE — decode and use the
        // inner bytes directly.
        let os = der::asn1::OctetString::decode(&mut reader).ok()?;
        os.as_bytes().to_vec()
    } else {
        der.to_vec()
    };
    let mut reader = der::SliceReader::new(&body_bytes).ok()?;
    let body = reader.sequence(|r| {
        // Skip `data SpcAttributeTypeAndOptionalValue`.
        let _ = r.tlv_bytes()?;
        // `messageDigest DigestInfo ::= SEQUENCE { digestAlgorithm
        // AlgorithmIdentifier, digest OCTET STRING }`.
        let msg_digest = r.sequence(|m| {
            let alg = m.decode::<x509_cert::spki::AlgorithmIdentifierOwned>()?;
            let digest = m.decode::<der::asn1::OctetString>()?;
            Ok((alg, digest))
        })?;
        Ok(msg_digest)
    });
    let (alg, digest) = body.ok()?;
    let label = oid_to_label(&alg.oid);
    Some((label, hex_encode(digest.as_bytes())))
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
    use super::{
        is_ecdsa_oid, is_rsa_oid, oid_to_label, signature_algorithm_name, trim_to_der_object,
    };
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

    /// `is_rsa_oid` must accept every RSA OID Authenticode emitters
    /// have been observed to put on PE signatures — the bare
    /// `rsaEncryption` plus the hash-specific composites. Unknown
    /// OIDs must NOT match, otherwise `verify_signer_signature`
    /// would dispatch RSA verification on an ECDSA cert (or worse).
    #[test]
    fn is_rsa_oid_covers_known_authenticode_oids() {
        // Bare rsaEncryption + every hash-specific composite shipped
        // in Windows Authenticode signatures.
        for oid in [
            "1.2.840.113549.1.1.1",  // rsaEncryption
            "1.2.840.113549.1.1.4",  // md5WithRSA
            "1.2.840.113549.1.1.5",  // sha1WithRSA
            "1.2.840.113549.1.1.11", // sha256WithRSA
            "1.2.840.113549.1.1.12", // sha384WithRSA
            "1.2.840.113549.1.1.13", // sha512WithRSA
        ] {
            assert!(is_rsa_oid(oid), "should classify {oid} as RSA");
        }
        // ECDSA OIDs must NOT match — they go through verify_ecdsa.
        assert!(!is_rsa_oid("1.2.840.10045.4.3.2"));
        // Garbage / Ed25519 / dsa-with-sha256 OIDs are unsupported.
        assert!(!is_rsa_oid("1.3.101.112"));
        assert!(!is_rsa_oid(""));
    }

    #[test]
    fn is_ecdsa_oid_covers_known_authenticode_oids() {
        for oid in [
            "1.2.840.10045.4.1",   // ecdsa-with-SHA1
            "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
            "1.2.840.10045.4.3.3", // ecdsa-with-SHA384
            "1.2.840.10045.4.3.4", // ecdsa-with-SHA512
        ] {
            assert!(is_ecdsa_oid(oid), "should classify {oid} as ECDSA");
        }
        // RSA OIDs must NOT match.
        assert!(!is_ecdsa_oid("1.2.840.113549.1.1.11"));
        // Curve OIDs (subject_public_key_info parameters) must NOT
        // be mistaken for signature algorithms.
        assert!(!is_ecdsa_oid("1.2.840.10045.3.1.7")); // P-256
        assert!(!is_ecdsa_oid(""));
    }

    /// `signature_algorithm_name` returns the canonical RFC label for
    /// every signature-algorithm OID we recognise, and the dotted-OID
    /// fallback for the long tail. Trait authors match against these
    /// strings.
    #[test]
    fn signature_algorithm_name_maps_known_oids() {
        let oid = ObjectIdentifier::new("1.2.840.113549.1.1.11").unwrap();
        assert_eq!(signature_algorithm_name(&oid), "sha256WithRSAEncryption");
        let oid = ObjectIdentifier::new("1.2.840.10045.4.3.2").unwrap();
        assert_eq!(signature_algorithm_name(&oid), "ecdsa-with-SHA256");
    }

    /// Unknown / exotic OIDs fall through to the dotted-OID string
    /// itself. The legacy `"other"` fallback threw away the only
    /// piece of forensically useful information; the dotted form lets
    /// an analyst look the algorithm up directly.
    #[test]
    fn signature_algorithm_name_falls_back_to_dotted_oid() {
        let oid = ObjectIdentifier::new("1.3.6.1.4.1.99999").unwrap();
        assert_eq!(signature_algorithm_name(&oid), "1.3.6.1.4.1.99999");
        // RSASSA-PSS (1.2.840.113549.1.1.10) — not in our friendly
        // table yet but still emitted as a usable identifier.
        let oid = ObjectIdentifier::new("1.2.840.113549.1.1.10").unwrap();
        assert_eq!(signature_algorithm_name(&oid), "1.2.840.113549.1.1.10");
    }
}
