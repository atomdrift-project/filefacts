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
//! signature's digest algorithm, enough to answer "who claims to have
//! signed this, and when did the cert expire?". `chain_sha256` answers
//! "who vouches for that claim": the thumbprints of the certificates whose
//! keys verifiably signed the signer's certificate and each other. Names in
//! it prove nothing; thumbprints do, and pinning them is left to consumers.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::output::Values;
use crate::value_key;

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
        let Some(length) = u32_le(cert_table_bytes, pos) else {
            break;
        };
        let length = length as usize;
        if length < 8 || pos + length > cert_table_bytes.len() {
            break;
        }
        let Some(cert_type) = u16_le(cert_table_bytes, pos + 6) else {
            break;
        };
        // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA. Other types
        // (x.509 cert wrapper, reserved, TS_STACK_SIGNED) are not
        // currently parsed.
        if cert_type == 0x0002 {
            let Some(blob) = cert_table_bytes.get(pos + 8..pos + length) else {
                break;
            };
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
        values.insert_key(value_key!("pe.signatures"), JsonValue::Array(signatures));
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
        // Unix forms of the same two instants. The string forms are for
        // display; these are what a consumer needs to answer "was this
        // signature made while the certificate was valid?" and "has the
        // certificate since expired?" without parsing dates. Those are
        // different questions with different answers: an old but honestly
        // signed binary fails the second and passes the first, whereas a
        // backdated or forged one fails the first.
        obj.insert(
            "not_before_unix".into(),
            JsonValue::Number(time_to_unix(tbs.validity.not_before).into()),
        );
        obj.insert(
            "not_after_unix".into(),
            JsonValue::Number(time_to_unix(tbs.validity.not_after).into()),
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
        }
        if let Some(thumbprint) = thumbprint_sha256(cert) {
            obj.insert("thumbprint_sha256".into(), JsonValue::String(thumbprint));
        }
    }

    // Pull signing-time from the signed-attributes bag if present
    // (OID 1.2.840.113549.1.9.5). Emitted in two forms: the canonical
    // ISO-8601 string for display, plus a Unix timestamp for downstream
    // arithmetic (sign-time-before-build checks, age windows, etc.).
    // The signer's own attribute first, then the countersignature — the
    // timestamping authority is where Authenticode actually records signing
    // time, so most binaries only answer on the second lookup. `signing_time`
    // means the same thing either way; `signing_time_source` says which
    // attested it, because a self-asserted time is the signer's word and a
    // countersigned one is a third party's.
    let timed = extract_signing_time(signer)
        .map(|t| (t, "signer"))
        .or_else(|| extract_countersignature_time(signer).map(|t| (t, "countersignature")))
        .or_else(|| extract_rfc3161_gen_time(signer).map(|t| (t, "rfc3161")));
    if let Some(((s, unix), source)) = timed {
        obj.insert("signing_time".into(), JsonValue::String(s));
        obj.insert("signing_time_unix".into(), JsonValue::Number(unix.into()));
        obj.insert(
            "signing_time_source".into(),
            JsonValue::String(source.into()),
        );
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
        let chain = verified_chain(&signed_data, cert)
            .into_iter()
            .map(JsonValue::String)
            .collect();
        obj.insert("chain_sha256".into(), JsonValue::Array(chain));
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
    // Re-tag from [0] IMPLICIT (0xA0) to SET OF (0x31).
    *der.first_mut()? = 0x31;
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

/// The signer certificate, then each certificate in the SignedData bag whose
/// public key verifiably signed the one before it, as SHA-256 thumbprints.
///
/// Names prove nothing: anyone can mint a certificate whose subject reads
/// "Microsoft Code Signing PCA 2011". A link is added only when the issuer's
/// key verifies the child's signature over its TBSCertificate, so a real CA's
/// thumbprint appears here only if that CA's private key signed the chain
/// below it. Which CAs to trust is policy and stays with the consumer, which
/// pins thumbprints; this reports only what the cryptography proves.
///
/// The walk stops at a self-issued certificate, at the first link that does
/// not verify or uses an algorithm we cannot check, or at `MAX_CHAIN`. Every
/// failure shortens the chain; none can add a certificate to it.
fn verified_chain(signed_data: &SignedData, signer: &x509_cert::Certificate) -> Vec<String> {
    const MAX_CHAIN: usize = 8;
    let bag: Vec<&x509_cert::Certificate> = signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|entry| match entry {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            _ => None,
        })
        .collect();
    let mut chain = Vec::new();
    let mut cert = signer;
    while let Some(thumbprint) = thumbprint_sha256(cert) {
        if chain.contains(&thumbprint) {
            break;
        }
        chain.push(thumbprint);
        let tbs = &cert.tbs_certificate;
        if chain.len() == MAX_CHAIN || tbs.issuer == tbs.subject {
            break;
        }
        let Some(issuer) = bag
            .iter()
            .copied()
            .find(|c| c.tbs_certificate.subject == tbs.issuer && signs(c, cert))
        else {
            break;
        };
        cert = issuer;
    }
    chain
}

/// Whether `issuer`'s public key verifies `child`'s certificate signature.
fn signs(issuer: &x509_cert::Certificate, child: &x509_cert::Certificate) -> bool {
    let alg = child.signature_algorithm.oid.to_string();
    let digest = match alg.as_str() {
        "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => "1.3.14.3.2.26",
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => "2.16.840.1.101.3.4.2.2",
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => "2.16.840.1.101.3.4.2.3",
        _ => return false,
    };
    let (Ok(tbs), Some(signature)) = (child.tbs_certificate.to_der(), child.signature.as_bytes())
    else {
        return false;
    };
    let outcome = if is_rsa_oid(&alg) {
        verify_rsa(issuer, digest, &tbs, signature)
    } else {
        verify_ecdsa(issuer, digest, &tbs, signature)
    };
    matches!(outcome, VerifyOutcome::Verified)
}

fn thumbprint_sha256(cert: &x509_cert::Certificate) -> Option<String> {
    cert.to_der()
        .ok()
        .map(|der| hex_encode(&Sha256::digest(&der)))
}

/// Signing time from a countersignature, for the common case where the signer
/// left no `signingTime` of its own.
///
/// Authenticode records *when* a signature was made in a countersignature made
/// by a timestamping authority, not in the signer's own attributes — which is
/// why reading only the signer leaves the signing time unknown for most real
/// binaries, Microsoft's included. Two forms exist and both appear in the wild:
/// the legacy PKCS#9 `counterSignature`, whose value is a SignerInfo carrying
/// an ordinary `signingTime`, and the RFC 3161 token used by modern signing.
/// This handles the legacy form; the token form is read by
/// `extract_rfc3161_gen_time`.
fn extract_countersignature_time(signer: &cms::signed_data::SignerInfo) -> Option<(String, i64)> {
    const COUNTERSIGNATURE_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
    let attrs = signer.unsigned_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != COUNTERSIGNATURE_OID {
            continue;
        }
        let any = attr.values.as_slice().first()?;
        let der = any.to_der().ok()?;
        // The countersignature value is a SignerInfo in its own right, so the
        // existing signed-attribute walk applies unchanged.
        if let Ok(counter) = der::Decode::from_der(&der) {
            let counter: cms::signed_data::SignerInfo = counter;
            if let Some(found) = extract_signing_time(&counter) {
                return Some(found);
            }
        }
    }
    None
}

/// Signing time from an RFC 3161 timestamp token.
///
/// Modern Authenticode timestamps with a token rather than a PKCS#9
/// countersignature: the unsigned attribute (OID 1.3.6.1.4.1.311.3.3.1) holds a
/// ContentInfo wrapping SignedData whose encapsulated content is a TSTInfo, and
/// the authority's attested instant is TSTInfo's `genTime`. Every
/// Microsoft-signed binary checked here uses this form, so without it the
/// signing time — and any judgement about whether a signature was made while
/// its certificate was valid — is unavailable for most signed software.
///
/// The token is navigated by hand rather than through `cms::SignedData`:
/// these tokens carry the optional `crls [1]` field, which that model rejects
/// (`unexpected ASN.1 DER tag: got CONTEXT-SPECIFIC [1]`). Only one value is
/// wanted, and it sits at a fixed place relative to the `id-ct-TSTInfo`
/// content-type OID, so the search anchors there and reads forward.
fn extract_rfc3161_gen_time(signer: &cms::signed_data::SignerInfo) -> Option<(String, i64)> {
    const MS_TIMESTAMP_TOKEN_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
    let attrs = signer.unsigned_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != MS_TIMESTAMP_TOKEN_OID {
            continue;
        }
        let Some(any) = attr.values.as_slice().first() else {
            continue;
        };
        let Ok(der_bytes) = any.to_der() else {
            continue;
        };
        if let Some(found) = gen_time_from_token(&der_bytes) {
            return Some(found);
        }
    }
    None
}

/// DER encoding of the `id-ct-TSTInfo` OID (1.2.840.113549.1.9.16.1.4), which
/// appears exactly once in a token — as `encapContentInfo.eContentType`.
const TST_INFO_OID_DER: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// Locate the TSTInfo inside a timestamp token and read its `genTime`.
///
/// After the content-type OID comes `eContent [0] EXPLICIT OCTET STRING`, whose
/// bytes are the TSTInfo. Some producers wrap the TSTInfo in a further OCTET
/// STRING, so one extra layer is unwrapped when present.
fn gen_time_from_token(token_der: &[u8]) -> Option<(String, i64)> {
    let at = token_der
        .windows(TST_INFO_OID_DER.len())
        .position(|w| w == TST_INFO_OID_DER)?;
    let after_oid = token_der.get(at + TST_INFO_OID_DER.len()..)?;

    let (tag, explicit, _) = read_tlv(after_oid)?;
    // [0] EXPLICIT, constructed.
    if tag != 0xA0 {
        return None;
    }
    let (tag, mut body, _) = read_tlv(explicit)?;
    if tag != 0x04 {
        return None;
    }
    // Unwrap a redundant OCTET STRING layer if one is present.
    if let Some((0x04, inner, _)) = read_tlv(body) {
        if inner.len() + 2 <= body.len() {
            body = inner;
        }
    }
    gen_time_from_tst_info(body)
}

/// Read one DER TLV, returning `(tag, contents, remainder)`.
///
/// Deliberately minimal: definite-length only, which is all DER permits.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first_len = *bytes.get(1)? as usize;
    let (len, header) = if first_len < 0x80 {
        (first_len, 2)
    } else {
        // Long form: the low seven bits give the number of length bytes.
        let n = first_len & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *bytes.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    Some((tag, bytes.get(header..end)?, bytes.get(end..)?))
}

/// Pull `genTime` out of a TSTInfo body.
///
/// TSTInfo ::= SEQUENCE {
///     version, policy, messageImprint, serialNumber, genTime, ... }
///
/// Only `genTime` is wanted, so the SEQUENCE is walked positionally to its
/// fifth element rather than modelling the whole structure.
fn gen_time_from_tst_info(tst_der: &[u8]) -> Option<(String, i64)> {
    let (tag, mut rest, _) = read_tlv(tst_der)?;
    if tag != 0x30 {
        return None;
    }
    // version, policy, messageImprint, serialNumber.
    for _ in 0..4 {
        let (_, _, next) = read_tlv(rest)?;
        rest = next;
    }
    let (tag, gen_time, _) = read_tlv(rest)?;
    // GeneralizedTime.
    if tag != 0x18 {
        return None;
    }
    let text = std::str::from_utf8(gen_time).ok()?;
    parse_generalized_time(text)
}

/// Parse `YYYYMMDDHHMMSS[.fff]Z` into a display string and Unix seconds.
fn parse_generalized_time(text: &str) -> Option<(String, i64)> {
    let digits = &text[..text.find(['.', 'Z'])?];
    if digits.len() < 14 {
        return None;
    }
    // `str::get`: the text is only known to be UTF-8, so a multi-byte char
    // can put a field edge off a char boundary.
    let num = |a: usize, b: usize| digits.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, sec) = (num(8, 10)?, num(10, 12)?, num(12, 14)?);
    // Days since epoch via the civil-from-days algorithm (Howard Hinnant).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix = days * 86_400 + h * 3_600 + mi * 60 + sec;
    Some((
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{sec:02} UTC"),
        unix,
    ))
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
    // The leading tag byte: we don't constrain it (Authenticode wraps a
    // SEQUENCE `0x30`, but the helper is intentionally tag-agnostic).
    let len_byte = *bytes.get(1)?;
    let (header_size, content_len) = if len_byte & 0x80 == 0 {
        (2_usize, len_byte as usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 8 {
            return None;
        }
        let mut content_len = 0_usize;
        for &b in bytes.get(2..2 + n)? {
            content_len = (content_len << 8) | (b as usize);
        }
        (2 + n, content_len)
    };
    let total = header_size.checked_add(content_len)?;
    bytes.get(..total)
}

/// Seconds since the Unix epoch for an X.509 validity instant.
fn time_to_unix(t: x509_cert::time::Time) -> i64 {
    use x509_cert::time::Time;
    match t {
        Time::UtcTime(v) => v.to_date_time().unix_duration().as_secs() as i64,
        Time::GeneralTime(v) => v.to_date_time().unix_duration().as_secs() as i64,
    }
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
mod tests;
