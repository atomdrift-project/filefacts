//! CMS / PKCS#7 `SignedData` signatures: PE Authenticode, cabinets, Mach-O
//! code signatures and APK v1 signature blocks all carry one.
//!
//! Each signature is reported as a [`Signature`]: the *primary signer*'s
//! certificate fields plus the digest algorithms, enough to answer "who
//! claims to have signed this, and when did the cert expire?". `chain_sha256`
//! answers "who vouches for that claim": the thumbprints of the certificates
//! whose keys verifiably signed the signer's certificate and each other.
//! Names in it prove nothing; thumbprints do, and pinning them is left to
//! consumers. The one exception is `chain_anchor`, set when the chain ends at
//! one of the few platform roots filefacts carries (Microsoft's and Apple's
//! code-signing roots), so "signed by the platform vendor" is a cryptographic
//! fact rather than a name match.
//!
//! `verified` is true only when both halves of a CMS signature hold: the
//! signer's key signed the signed attributes, and those attributes bind the
//! signed content (`messageDigest` equals the content's hash, `contentType`
//! names it). Checking the first half alone would accept a SignerInfo lifted
//! from a genuine file and grafted onto content of the attacker's choosing.
//!
//! Weak cryptography is reported, never silently accepted or rejected:
//! `weak_algorithms` names every MD5 or SHA-1 digest the signature relies on,
//! and `weak_key` marks a signer key below 2048-bit RSA or 256-bit ECC.

mod ber;

use std::sync::LazyLock;

use ::cms::content_info::ContentInfo;
use ::cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::oid::{AssociatedOid, ObjectIdentifier};
use der::{Decode, Encode, Reader as _};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::formats::common::hex_encode;

/// Most signatures parsed from one certificate table or CMS blob, nested
/// signatures included. Real binaries carry one to three; the cap bounds the
/// public-key work a crafted table full of small SignedData records can force.
const MAX_SIGNATURES: u16 = 16;
/// Signature levels parsed, the outer signature included. Dual- and
/// triple-signed binaries nest one level; each level re-decodes its blob, so
/// depth is also a memory bound.
const MAX_NESTING: u8 = 4;
/// Countersignature attribute values examined per signer.
const MAX_COUNTERSIGNATURES: usize = 4;
/// Smallest signer key not reported as `weak_key`, per scheme.
const MIN_RSA_BITS: u32 = 2048;
const MIN_EC_BITS: u32 = 256;

/// One parsed signature, as published under `pe.signatures[]`,
/// `cab.signatures[]`, `macho.code_signature.cms` and `android.signatures[]`.
///
/// Fields absent from the blob are absent from the output. The PE-only
/// fields (`unsigned_trailing_bytes`, `digest_matches`,
/// `signed_within_validity`) are filled in by the PE extractor, which alone
/// can compare a signature with the image it claims to cover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Signature {
    /// The SignerInfo's digest algorithm (`sha256`, `sha1`, …, or `other`).
    pub(crate) digest_algorithm: String,
    /// SignerInfos in the SignedData. Only the first is examined; Authenticode
    /// requires exactly one, so any other count is itself a finding.
    pub(crate) signer_count: usize,
    /// Certificates carried in the SignedData's certificate bag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cert_bag_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<String>,
    /// Signer certificate serial number, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_after: Option<String>,
    /// Unix forms of the validity window. The string forms are for display;
    /// these answer "was this signed while the certificate was valid?" and
    /// "has the certificate since expired?" without parsing dates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_before_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_after_unix: Option<i64>,
    /// The signer certificate's signature algorithm, by RFC name or dotted OID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature_algorithm: Option<String>,
    /// Size of the signer's public key in bits, when the scheme is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_bits: Option<u32>,
    /// The signer key is smaller than [`MIN_RSA_BITS`] / [`MIN_EC_BITS`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) weak_key: bool,
    /// MD5 / SHA-1 digests the signature relies on: the SignerInfo's, the
    /// signed image digest's, and the signer certificate's own signature.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) weak_algorithms: Vec<String>,
    /// The signer certificate's Extended Key Usage purposes, dotted OIDs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) extended_key_usage: Vec<String>,
    /// Whether the EKU, when present, names `id-kp-codeSigning`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) eku_code_signing: Option<bool>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) self_issued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) thumbprint_sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) thumbprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signing_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signing_time_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signing_time_source: Option<TimeSource>,
    /// `chain_sha256` of the timestamping authority; empty unless the
    /// timestamp verified.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) timestamp_chain_sha256: Vec<String>,
    /// Algorithm of the image digest an `SpcIndirectDataContent` commits to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature_digest_algorithm: Option<String>,
    /// The committed image digest, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chain_sha256: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chain_anchor: Option<Vendor>,
    /// Absent when no signer certificate was found.
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) verified: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) verification_failure: Option<Failure>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) verification_unsupported: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) nested: Vec<Signature>,
    /// Certificate-table bytes past this signature that nothing signs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unsigned_trailing_bytes: Option<u64>,
    /// The committed image digest equals the recomputed Authentihash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) digest_matches: Option<bool>,
    /// The attested signing time fell inside the validity window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signed_within_validity: Option<bool>,
}

/// Distinguishes a `null` field from an absent one: absent stays `None`
/// through `#[serde(default)]`, a present value (null included) is `Some`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// The CMS verdict, published as `verified`: `true`, `false`, or `null` when
/// verification could not be attempted (with `verification_unsupported`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Verified,
    Failed,
    Unsupported,
}

impl Serialize for Verdict {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Verified => serializer.serialize_bool(true),
            Self::Failed => serializer.serialize_bool(false),
            Self::Unsupported => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for Verdict {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<bool>::deserialize(deserializer)? {
            Some(true) => Self::Verified,
            Some(false) => Self::Failed,
            None => Self::Unsupported,
        })
    }
}

impl Signature {
    /// The signature as a published value.
    pub(crate) fn to_json(&self) -> JsonValue {
        // A struct of strings, numbers and vectors always serializes.
        serde_json::to_value(self).unwrap_or(JsonValue::Null)
    }

    /// Whether the CMS signature itself verified over its content.
    pub(crate) fn is_verified(&self) -> bool {
        self.verified == Some(Verdict::Verified)
    }

    fn record(&mut self, outcome: VerifyOutcome) {
        match outcome {
            VerifyOutcome::Verified => self.verified = Some(Verdict::Verified),
            VerifyOutcome::Failed(why) => {
                self.verified = Some(Verdict::Failed);
                self.verification_failure = Some(why);
            }
            VerifyOutcome::Unsupported => {
                self.verified = Some(Verdict::Unsupported);
                self.verification_unsupported = true;
            }
        }
    }

    fn note_weak(&mut self, alg: DigestAlg) {
        if alg.is_weak() && !self.weak_algorithms.iter().any(|w| w == alg.label()) {
            self.weak_algorithms.push(alg.label().to_string());
        }
    }
}

/// Parse the PE Certificate Table (the bytes the optional header's directory
/// entry points at) into its Authenticode signatures.
///
/// The image hash skips the whole table, so whatever it holds besides the
/// signatures rides along unsigned: data appended inside a WIN_CERTIFICATE
/// past its signature, or past the last record, with the lengths stretched to
/// cover it (the MS13-098 / CVE-2013-3900 padding, which Windows still
/// accepts by default). A signature records those bytes, beyond its own
/// 8-byte alignment, as `unsigned_trailing_bytes` — the last one also counts
/// the table's tail. Installers tag themselves this way too, so it is a fact
/// rather than a verdict; without it the payload would be invisible, since
/// the overlay view stops where the table starts.
pub(crate) fn certificate_table(table: &[u8]) -> Vec<Signature> {
    // The certificate table is a sequence of WIN_CERTIFICATE records:
    //   DWORD dwLength      (total length, including this header)
    //   WORD  wRevision     (0x0200 = revision 2)
    //   WORD  wCertificateType  (0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    //   BYTE  bCertificate[]
    // Each record is padded to an 8-byte boundary.
    let mut pos = 0;
    let mut signatures = Vec::new();
    let mut budget = Budget::new();
    while pos + 8 <= table.len() {
        let Some(length) = u32_le(table, pos) else {
            break;
        };
        let length = length as usize;
        // `pos + 8 <= len` above, so the subtraction cannot underflow; the
        // sum `pos + length` could wrap on a 32-bit target.
        if length < 8 || length > table.len() - pos {
            tracing::debug!(
                target: "filefacts::cms",
                format = "pe",
                stage = "certificate-table",
                offset = pos,
                len = length,
                "WIN_CERTIFICATE length out of range; table walk stopped"
            );
            break;
        }
        let Some(cert_type) = u16_le(table, pos + 6) else {
            break;
        };
        // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA. The other types (X.509
        // wrapper, TS_STACK_SIGNED) carry no Authenticode signature.
        if cert_type == 0x0002 {
            let Some(blob) = table.get(pos + 8..pos + length) else {
                break;
            };
            // `dwLength` rounds the PKCS#7 blob up to an 8-byte boundary with
            // null padding, which a DER decoder rejects as trailing data.
            let trimmed = der_element(blob).unwrap_or(blob);
            if let Some(mut sig) = decode_content_info(trimmed)
                .and_then(|ci| parse_content_info(&ci, Signs::PeImage, &mut budget, 0))
            {
                let signed = (8 + trimmed.len()).next_multiple_of(8);
                add_unsigned_bytes(&mut sig, length.next_multiple_of(8) - signed);
                signatures.push(sig);
            }
        } else {
            tracing::debug!(
                target: "filefacts::cms",
                format = "pe",
                stage = "certificate-table",
                offset = pos,
                cert_type,
                "WIN_CERTIFICATE type carries no Authenticode signature"
            );
        }
        pos += length.next_multiple_of(8);
    }
    if let Some(last) = signatures.last_mut() {
        add_unsigned_bytes(last, table.len().saturating_sub(pos));
    }
    signatures
}

/// Add `bytes` to a signature's `unsigned_trailing_bytes`, which is present
/// only when non-zero.
fn add_unsigned_bytes(sig: &mut Signature, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    let total = sig
        .unsigned_trailing_bytes
        .unwrap_or(0)
        .saturating_add(bytes);
    sig.unsigned_trailing_bytes = Some(total);
}

/// Parse a CMS / PKCS#7 SignedData blob into its published value, for the
/// formats that carry one beside their content (APK v1 signature blocks). A
/// detached signature parsed this way has no content to bind and reads as
/// unverifiable; see [`parse_detached_cms_blob`].
pub(crate) fn parse_cms_blob(der_bytes: &[u8]) -> Option<JsonValue> {
    parse_pkcs7(der_bytes, Signs::Encapsulated).map(|sig| sig.to_json())
}

/// [`parse_cms_blob`] for a detached signature over `content`. The Mach-O
/// code-signature module hands over the CMS blob found inside
/// `CSMAGIC_BLOBWRAPPER` with the CodeDirectory it signs, which lives beside
/// the signature rather than inside it.
pub(crate) fn parse_detached_cms_blob(der_bytes: &[u8], content: &[u8]) -> Option<JsonValue> {
    parse_pkcs7(der_bytes, Signs::Detached(content)).map(|sig| sig.to_json())
}

/// Parse a signature whose content is a digest of an object the caller does
/// not recompute (a cabinet's Authenticode signature). The blob's own
/// cryptography is still checked, so a broken signature reads `verified:
/// false`; a sound one reads `verified: null` with `verification_unsupported`,
/// since nothing shows it was made over this file.
pub(crate) fn parse_unbound_cms_blob(der_bytes: &[u8]) -> Option<Signature> {
    parse_pkcs7(der_bytes, Signs::Unbound)
}

/// Signatures left to parse for one certificate table or blob.
struct Budget {
    remaining: u16,
}

impl Budget {
    fn new() -> Self {
        Self {
            remaining: MAX_SIGNATURES,
        }
    }

    fn take(&mut self) -> bool {
        let Some(left) = self.remaining.checked_sub(1) else {
            return false;
        };
        self.remaining = left;
        true
    }
}

/// What the signatures in one parse must sign.
#[derive(Clone, Copy)]
enum Signs<'a> {
    /// Their own encapsulated content, whatever its type.
    Encapsulated,
    /// Content carried beside the signature rather than inside it.
    Detached(&'a [u8]),
    /// A PE image. Authenticode reaches the image only through the digest an
    /// `SpcIndirectDataContent` names, so any other content type proves
    /// nothing about the file it was found in: a Microsoft-signed catalog
    /// lifted into a PE verifies, with a Microsoft chain, all the same.
    PeImage,
    /// A digest of an object nobody recomputes; see
    /// [`parse_unbound_cms_blob`].
    Unbound,
}

fn parse_pkcs7(der_bytes: &[u8], signs: Signs<'_>) -> Option<Signature> {
    let ci = decode_content_info(der_bytes)?;
    parse_content_info(&ci, signs, &mut Budget::new(), 0)
}

/// Decode a ContentInfo, normalizing BER to DER first when the strict decode
/// fails. Apple's Mach-O signatures are BER; Authenticode is DER.
fn decode_content_info(der_bytes: &[u8]) -> Option<ContentInfo> {
    let strict = match ContentInfo::from_der(der_bytes) {
        Ok(ci) => return Some(ci),
        Err(e) => e,
    };
    let Some(normalized) = ber::to_der(der_bytes) else {
        tracing::debug!(
            target: "filefacts::cms",
            stage = "content-info",
            len = der_bytes.len(),
            error = %strict,
            "ContentInfo is neither DER nor well-formed BER"
        );
        return None;
    };
    ContentInfo::from_der(&normalized)
        .inspect_err(|e| {
            tracing::debug!(
                target: "filefacts::cms",
                stage = "content-info",
                len = der_bytes.len(),
                error = %e,
                strict_error = %strict,
                "ContentInfo decode failed after BER normalization"
            );
        })
        .ok()
}

fn parse_content_info(
    ci: &ContentInfo,
    signs: Signs<'_>,
    budget: &mut Budget,
    depth: u8,
) -> Option<Signature> {
    if !budget.take() {
        tracing::debug!(
            target: "filefacts::cms",
            stage = "signed-data",
            limit = MAX_SIGNATURES,
            "signature budget spent; remaining signatures skipped"
        );
        return None;
    }
    let signed_data: SignedData = ci
        .content
        .decode_as()
        .inspect_err(|e| {
            tracing::debug!(
                target: "filefacts::cms",
                stage = "signed-data",
                error = %e,
                "SignedData decode failed"
            );
        })
        .ok()?;

    let signers = signed_data.signer_infos.0.as_slice();
    let signer = signers.first()?;
    let bag = cert_bag(&signed_data);
    let signer_cert = find_signer_cert(&bag, signer);

    let mut sig = Signature {
        digest_algorithm: oid_to_label(&signer.digest_alg.oid).to_string(),
        signer_count: signers.len(),
        cert_bag_size: (!bag.is_empty()).then_some(bag.len()),
        ..Signature::default()
    };
    if let Some(alg) = DigestAlg::from_oid(&signer.digest_alg.oid) {
        sig.note_weak(alg);
    }
    if let Some(cert) = signer_cert {
        certificate_fields(cert, &mut sig);
    }

    // Signing time, in two forms: the canonical string for display, plus a
    // Unix timestamp for arithmetic. The signer's own `signingTime`
    // attribute first — it sits under the signer's signature, so it is the
    // signer's verified word — then a timestamp. Authenticode records signing
    // time in a timestamp made by a timestamping authority, so most binaries
    // only answer on the second lookup. A timestamp whose own signature or
    // imprint does not check out is reported as `unverified_<kind>` so
    // nothing downstream mistakes it for an attested time; its chain
    // thumbprints are `timestamp_chain_sha256`, so a consumer can decide
    // whether it trusts the authority.
    if let Some(time) = signing_time(signer, &bag) {
        sig.signing_time = Some(time.text);
        sig.signing_time_unix = Some(time.unix);
        sig.signing_time_source = Some(time.source);
        sig.timestamp_chain_sha256 = time.chain;
    }

    // SpcIndirectDataContent carries the algorithm + digest the signature
    // was made over: what the PE extractor compares against the recomputed
    // Authentihash to detect post-signing tampering.
    let image_digest = extract_spc_indirect_data(&signed_data);
    if let Some((alg, digest_hex)) = &image_digest {
        sig.signature_digest_algorithm = Some(oid_to_label(alg).to_string());
        sig.signature_digest = Some(digest_hex.clone());
        if let Some(alg) = DigestAlg::from_oid(alg) {
            sig.note_weak(alg);
        }
    }

    // Cryptographic verification: the signer's key over the signed
    // attributes, and the attributes' binding to the encapsulated content
    // (or, for a detached signature, the content the caller supplied).
    if let Some(cert) = signer_cert {
        let chain = verified_chain(&bag, cert);
        sig.chain_sha256 = Some(chain.thumbprints);
        sig.chain_anchor = chain.anchor;
        let content = SignedContent {
            content_type: Some(signed_data.encap_content_info.econtent_type),
            bytes: signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .map(der::Any::value)
                .or(match signs {
                    Signs::Detached(bytes) => Some(bytes),
                    Signs::Encapsulated | Signs::PeImage | Signs::Unbound => None,
                }),
        };
        let outcome = match (verify_signer(signer, cert, &content), signs) {
            // Whatever the key signed, it was not this image.
            (VerifyOutcome::Verified | VerifyOutcome::Unsupported, Signs::PeImage)
                if image_digest.is_none() =>
            {
                VerifyOutcome::Failed(Failure::ImageDigestMissing)
            }
            // Sound, but over a digest of the file nothing here recomputes.
            (VerifyOutcome::Verified, Signs::Unbound) => VerifyOutcome::Unsupported,
            (outcome, _) => outcome,
        };
        if let VerifyOutcome::Failed(why) = outcome {
            tracing::debug!(
                target: "filefacts::cms",
                stage = "verify",
                failure = why.label(),
                "signature did not verify"
            );
        }
        sig.record(outcome);
    }

    // Nested signatures (Microsoft `nested-signature`). Carrier for SHA-256
    // signatures on dual-signed SHA-1 binaries; each inner PKCS#7 has its
    // own SignerInfo and certificate chain and covers the same image. Every
    // value is parsed through the same pipeline, so consumers see the same
    // shape at each level.
    sig.nested = extract_nested_signatures(signer, signs, budget, depth);
    Some(sig)
}

/// The signer certificate's identity, validity, key and purpose facts.
fn certificate_fields(cert: &Certificate, sig: &mut Signature) {
    let tbs = &cert.tbs_certificate;
    sig.subject = Some(tbs.subject.to_string());
    sig.issuer = Some(tbs.issuer.to_string());
    sig.serial = Some(hex_encode(tbs.serial_number.as_bytes()));
    sig.not_before = Some(time_to_string(tbs.validity.not_before));
    sig.not_after = Some(time_to_string(tbs.validity.not_after));
    sig.not_before_unix = Some(time_to_unix(tbs.validity.not_before));
    sig.not_after_unix = Some(time_to_unix(tbs.validity.not_after));
    sig.signature_algorithm = Some(signature_algorithm_name(&cert.signature_algorithm.oid));
    if let Some(alg) = signature_algorithm(&cert.signature_algorithm.oid).and_then(|a| a.digest) {
        sig.note_weak(alg);
    }
    sig.key_bits = public_key_bits(cert);
    sig.weak_key = sig.key_bits.is_some_and(|bits| {
        let floor = match key_scheme(cert) {
            Some(Scheme::Rsa) => MIN_RSA_BITS,
            Some(Scheme::Ecdsa) => MIN_EC_BITS,
            None => 0,
        };
        bits < floor
    });

    // Extended Key Usage — the leaf's claimed-purpose set. A self-signed
    // dropper rarely bothers to set `codeSigning`, so absence on a non-system
    // signer is a soft tampering signal.
    if let Some(eku) = extension::<x509_cert::ext::pkix::ExtendedKeyUsage>(cert) {
        sig.eku_code_signing = Some(eku.0.contains(&CODE_SIGNING_OID));
        sig.extended_key_usage = eku.0.iter().map(ToString::to_string).collect();
    }
    sig.self_issued = tbs.subject == tbs.issuer;

    // Thumbprints are computed over the entire DER encoding of the
    // certificate — the most stable per-certificate fingerprint. The
    // `thumbprint_` prefix is the one sigcheck, signtool and PowerShell use.
    if let Ok(cert_der) = cert.to_der() {
        sig.thumbprint_sha1 = Some(hex_encode(&Sha1::digest(&cert_der)));
    }
    sig.thumbprint_sha256 = thumbprint_sha256(cert);
}

/// `id-kp-codeSigning`.
const CODE_SIGNING_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Decode the certificate extension of type `T`. `None` when absent or
/// undecodable; a malformed extension claims nothing.
fn extension<T: AssociatedOid + for<'a> Decode<'a>>(cert: &Certificate) -> Option<T> {
    let ext = cert
        .tbs_certificate
        .extensions
        .as_deref()?
        .iter()
        .find(|ext| ext.extn_id == T::OID)?;
    T::from_der(ext.extn_value.as_bytes())
        .inspect_err(|e| {
            tracing::debug!(
                target: "filefacts::cms",
                stage = "certificate",
                oid = %T::OID,
                error = %e,
                "certificate extension undecodable"
            );
        })
        .ok()
}

// ---------------------------------------------------------------------
// Algorithms.
// ---------------------------------------------------------------------

/// A digest algorithm a SignerInfo, a certificate signature, or an
/// Authenticode structure can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DigestAlg {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

const DIGEST_ALGORITHMS: &[(ObjectIdentifier, DigestAlg)] = &[
    (
        ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
        DigestAlg::Md5,
    ),
    (
        ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
        DigestAlg::Sha1,
    ),
    (
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
        DigestAlg::Sha256,
    ),
    (
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
        DigestAlg::Sha384,
    ),
    (
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
        DigestAlg::Sha512,
    ),
];

impl DigestAlg {
    fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        DIGEST_ALGORITHMS
            .iter()
            .find(|(known, _)| known == oid)
            .map(|&(_, alg)| alg)
    }

    /// Shorthand consumers see (`sha256`, `sha1`, …).
    fn label(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// MD5 and SHA-1 have practical collision attacks.
    fn is_weak(self) -> bool {
        matches!(self, Self::Md5 | Self::Sha1)
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => md5::Md5::digest(data).to_vec(),
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// Public-key scheme of a signature algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Rsa,
    Ecdsa,
}

/// A signature-algorithm OID: its RFC name, its scheme, and the digest it
/// fixes when the OID is hash-specific. Generic `rsaEncryption` fixes none;
/// the SignerInfo's digest algorithm says which hash to use.
struct SignatureAlgorithm {
    oid: ObjectIdentifier,
    name: &'static str,
    scheme: Scheme,
    digest: Option<DigestAlg>,
}

const SIGNATURE_ALGORITHMS: &[SignatureAlgorithm] = &[
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
        name: "rsaEncryption",
        scheme: Scheme::Rsa,
        digest: None,
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4"),
        name: "md5WithRSAEncryption",
        scheme: Scheme::Rsa,
        digest: Some(DigestAlg::Md5),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"),
        name: "sha1WithRSAEncryption",
        scheme: Scheme::Rsa,
        digest: Some(DigestAlg::Sha1),
    },
    // The OIW arc's SHA-1 with RSA, older than PKCS #1's: the 1997 Microsoft
    // Root Authority signed its Code Signing and Timestamping PCAs with it.
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.3.14.3.2.29"),
        name: "sha1WithRSASignature",
        scheme: Scheme::Rsa,
        digest: Some(DigestAlg::Sha1),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        name: "sha256WithRSAEncryption",
        scheme: Scheme::Rsa,
        digest: Some(DigestAlg::Sha256),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
        name: "sha384WithRSAEncryption",
        scheme: Scheme::Rsa,
        digest: Some(DigestAlg::Sha384),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
        name: "sha512WithRSAEncryption",
        scheme: Scheme::Rsa,
        digest: Some(DigestAlg::Sha512),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.1"),
        name: "ecdsa-with-SHA1",
        scheme: Scheme::Ecdsa,
        digest: Some(DigestAlg::Sha1),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        name: "ecdsa-with-SHA256",
        scheme: Scheme::Ecdsa,
        digest: Some(DigestAlg::Sha256),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        name: "ecdsa-with-SHA384",
        scheme: Scheme::Ecdsa,
        digest: Some(DigestAlg::Sha384),
    },
    SignatureAlgorithm {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"),
        name: "ecdsa-with-SHA512",
        scheme: Scheme::Ecdsa,
        digest: Some(DigestAlg::Sha512),
    },
];

fn signature_algorithm(oid: &ObjectIdentifier) -> Option<&'static SignatureAlgorithm> {
    SIGNATURE_ALGORITHMS.iter().find(|alg| alg.oid == *oid)
}

/// Curve identifiers — P-256 and P-384 cover the Authenticode and Mach-O CMS
/// payloads in circulation.
const CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// SubjectPublicKeyInfo algorithms.
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The scheme of a certificate's own public key.
fn key_scheme(cert: &Certificate) -> Option<Scheme> {
    match cert.tbs_certificate.subject_public_key_info.algorithm.oid {
        RSA_ENCRYPTION_OID => Some(Scheme::Rsa),
        EC_PUBLIC_KEY_OID => Some(Scheme::Ecdsa),
        _ => None,
    }
}

/// Bits in a certificate's public key: the RSA modulus, or the curve order.
fn public_key_bits(cert: &Certificate) -> Option<u32> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    match key_scheme(cert)? {
        Scheme::Rsa => {
            let key =
                rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes()).ok()?;
            u32::try_from(key.n().bits()).ok()
        }
        Scheme::Ecdsa => match spki.algorithm.parameters.as_ref()?.decode_as().ok()? {
            CURVE_P256 => Some(256),
            CURVE_P384 => Some(384),
            _ => None,
        },
    }
}

// ---------------------------------------------------------------------
// Signer verification.
// ---------------------------------------------------------------------

/// PKCS#9 attributes a signature binds its content with.
const CONTENT_TYPE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// What a SignerInfo signs: the content bytes its `messageDigest` must hash
/// to, and the content type its `contentType` attribute must name. A
/// countersignature has no content type (RFC 5652 §11.1 forbids the
/// attribute there), so it carries `None`.
struct SignedContent<'a> {
    content_type: Option<ObjectIdentifier>,
    bytes: Option<&'a [u8]>,
}

/// Result of cryptographically verifying a SignerInfo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyOutcome {
    /// The holder of the private key matching the signer certificate signed
    /// these exact signed attributes, and they bind the signed content.
    Verified,
    /// Verification ran and failed; the reason says which half.
    Failed(Failure),
    /// We couldn't even attempt verification — exotic curve, off-pair
    /// algorithm (e.g. ECDSA P-256 + SHA-384), a malformed public key, or
    /// a detached signature with no content to bind it to. Distinguished
    /// from `Failed` so consumers don't treat "we don't know how to check
    /// this" as "tampered".
    Unsupported,
}

/// Why a SignerInfo failed verification, published as
/// `verification_failure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Failure {
    /// The public key does not verify the signature value.
    Signature,
    /// No `messageDigest` attribute, so nothing binds the content.
    MessageDigestMissing,
    /// `messageDigest` repeated, multi-valued, or not an OCTET STRING.
    MessageDigestMalformed,
    /// `messageDigest` does not equal the content's hash: the signed
    /// attributes belong to other content.
    MessageDigestMismatch,
    /// `contentType` absent, repeated, or naming a different content type.
    ContentTypeMismatch,
    /// A PE signature whose content is not an `SpcIndirectDataContent`
    /// naming an image digest, so it authenticates no PE image.
    ImageDigestMissing,
}

impl Failure {
    fn label(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::MessageDigestMissing => "message_digest_missing",
            Self::MessageDigestMalformed => "message_digest_malformed",
            Self::MessageDigestMismatch => "message_digest_mismatch",
            Self::ContentTypeMismatch => "content_type_mismatch",
            Self::ImageDigestMissing => "image_digest_missing",
        }
    }
}

/// Verify a SignerInfo against its certificate and the content it claims to
/// sign (RFC 5652 §5.4, §5.6).
///
/// With signed attributes, the signature covers their DER `SET OF` encoding,
/// and the attributes must bind the content: exactly one `messageDigest`
/// equal to the content's hash under the signer's digest algorithm, and
/// (outside countersignatures) exactly one `contentType` naming the
/// encapsulated type. Without signed attributes the signature covers the
/// content directly.
fn verify_signer(
    signer: &SignerInfo,
    cert: &Certificate,
    content: &SignedContent<'_>,
) -> VerifyOutcome {
    let Some(digest) = DigestAlg::from_oid(&signer.digest_alg.oid) else {
        return VerifyOutcome::Unsupported;
    };
    let Some(bytes) = content.bytes else {
        // A detached signature with no content to hash: the signature
        // might verify, but it would prove nothing about any file.
        return VerifyOutcome::Unsupported;
    };
    let (message, binding) = match &signer.signed_attrs {
        Some(attrs) => {
            let Some(der) = encode_signed_attrs(signer) else {
                return VerifyOutcome::Unsupported;
            };
            (
                der,
                check_binding(attrs.as_slice(), digest, content.content_type, bytes),
            )
        }
        None => (bytes.to_vec(), Ok(())),
    };
    let signature = signer.signature.as_bytes();
    match verify_signature(
        cert,
        &signer.signature_algorithm.oid,
        digest,
        &message,
        signature,
    ) {
        // The signature itself failing is the more basic finding.
        VerifyOutcome::Failed(why) => VerifyOutcome::Failed(why),
        // A broken binding is tampering whether or not we could check the
        // signature over it.
        outcome => match binding {
            Err(why) => VerifyOutcome::Failed(why),
            Ok(()) => outcome,
        },
    }
}

/// One attribute's lookup: absent, exactly one value, or anything else.
enum AttrValue<'a> {
    Absent,
    One(&'a der::Any),
    Malformed,
}

fn single_value<'a>(
    attrs: &'a [x509_cert::attr::Attribute],
    oid: &ObjectIdentifier,
) -> AttrValue<'a> {
    let mut found = None;
    for attr in attrs.iter().filter(|a| a.oid == *oid) {
        let [value] = attr.values.as_slice() else {
            return AttrValue::Malformed;
        };
        if found.replace(value).is_some() {
            return AttrValue::Malformed;
        }
    }
    found.map_or(AttrValue::Absent, AttrValue::One)
}

/// Check that the signed attributes bind `content`.
fn check_binding(
    attrs: &[x509_cert::attr::Attribute],
    digest: DigestAlg,
    content_type: Option<ObjectIdentifier>,
    content: &[u8],
) -> Result<(), Failure> {
    if let Some(expected) = content_type {
        let named = match single_value(attrs, &CONTENT_TYPE_OID) {
            AttrValue::One(any) => any.decode_as::<ObjectIdentifier>().ok(),
            AttrValue::Absent | AttrValue::Malformed => None,
        };
        if named != Some(expected) {
            return Err(Failure::ContentTypeMismatch);
        }
    }
    let claimed = match single_value(attrs, &MESSAGE_DIGEST_OID) {
        AttrValue::Absent => return Err(Failure::MessageDigestMissing),
        AttrValue::Malformed => return Err(Failure::MessageDigestMalformed),
        AttrValue::One(any) => any
            .decode_as::<OctetString>()
            .map_err(|_| Failure::MessageDigestMalformed)?,
    };
    if claimed.as_bytes() == digest.digest(content).as_slice() {
        Ok(())
    } else {
        Err(Failure::MessageDigestMismatch)
    }
}

/// Re-encode the SignerInfo's signed-attributes for verification.
/// In the wire SignerInfo the attribute bag is tagged `[0] IMPLICIT`
/// (0xA0); the cryptographic signing input replaces that with the
/// universal `SET OF Attribute` tag (0x31). Everything else (length,
/// contents) stays the same.
fn encode_signed_attrs(signer: &SignerInfo) -> Option<Vec<u8>> {
    let attrs = signer.signed_attrs.as_ref()?;
    let mut der = attrs.to_der().ok()?;
    *der.first_mut()? = 0x31;
    Some(der)
}

/// Verify `signature` over `message` with `cert`'s public key, under the
/// scheme `sig_alg` names and the `digest` the caller resolved.
fn verify_signature(
    cert: &Certificate,
    sig_alg: &ObjectIdentifier,
    digest: DigestAlg,
    message: &[u8],
    signature: &[u8],
) -> VerifyOutcome {
    match signature_algorithm(sig_alg).map(|alg| alg.scheme) {
        Some(Scheme::Rsa) => verify_rsa(cert, digest, message, signature),
        Some(Scheme::Ecdsa) => verify_ecdsa(cert, digest, message, signature),
        None => VerifyOutcome::Unsupported,
    }
}

fn verify_rsa(
    cert: &Certificate,
    digest: DigestAlg,
    message: &[u8],
    signature: &[u8],
) -> VerifyOutcome {
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::{Sha384, Sha512};

    // SubjectPublicKeyInfo carries the RSA modulus + exponent as an
    // RSAPublicKey (PKCS#1) inside the BIT STRING.
    let spk_bits = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let Ok(public_key) = RsaPublicKey::from_pkcs1_der(spk_bits) else {
        return VerifyOutcome::Unsupported;
    };
    let Ok(sig) = Signature::try_from(signature) else {
        return VerifyOutcome::Failed(Failure::Signature);
    };
    let verified = match digest {
        DigestAlg::Sha1 => VerifyingKey::<Sha1>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestAlg::Sha256 => VerifyingKey::<Sha256>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestAlg::Sha384 => VerifyingKey::<Sha384>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestAlg::Sha512 => VerifyingKey::<Sha512>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestAlg::Md5 => return VerifyOutcome::Unsupported,
    };
    if verified {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed(Failure::Signature)
    }
}

fn verify_ecdsa(
    cert: &Certificate,
    digest: DigestAlg,
    message: &[u8],
    signature: &[u8],
) -> VerifyOutcome {
    // Curve OID lives in the SubjectPublicKeyInfo's algorithm
    // parameters; the SEC1-encoded public point lives in the BIT
    // STRING.
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let Some(Ok(curve)) = spki
        .algorithm
        .parameters
        .as_ref()
        .map(|p| p.decode_as::<ObjectIdentifier>())
    else {
        return VerifyOutcome::Unsupported;
    };
    let pubkey_sec1 = spki.subject_public_key.raw_bytes();

    let verified = if curve == CURVE_P256 && digest == DigestAlg::Sha256 {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_sec1) else {
            return VerifyOutcome::Unsupported;
        };
        let Ok(sig) = Signature::from_der(signature) else {
            return VerifyOutcome::Failed(Failure::Signature);
        };
        vk.verify(message, &sig).is_ok()
    } else if curve == CURVE_P384 && digest == DigestAlg::Sha384 {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_sec1) else {
            return VerifyOutcome::Unsupported;
        };
        let Ok(sig) = Signature::from_der(signature) else {
            return VerifyOutcome::Failed(Failure::Signature);
        };
        vk.verify(message, &sig).is_ok()
    } else {
        // Off-pair (P-256 + SHA-384 etc.) or another curve: record as
        // unsupported rather than producing a misleading mismatch.
        return VerifyOutcome::Unsupported;
    };
    if verified {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed(Failure::Signature)
    }
}

// ---------------------------------------------------------------------
// Certificate chains.
// ---------------------------------------------------------------------

/// The certificates a SignedData carries.
fn cert_bag(signed_data: &SignedData) -> Vec<&Certificate> {
    signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|entry| match entry {
            ::cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            ::cms::cert::CertificateChoices::Other(_) => None,
        })
        .collect()
}

/// A platform vendor whose code-signing roots filefacts carries, published
/// as `chain_anchor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Vendor {
    Microsoft,
    Apple,
}

/// A root certificate whose key can end a chain as `chain_anchor`.
struct PinnedRoot {
    vendor: Vendor,
    cert: Certificate,
    thumbprint: String,
}

/// Microsoft's and Apple's code-signing roots, as published by each vendor
/// (microsoft.com/pki/certs, apple.com/appleca). A chain reaching one of
/// these keys was signed by that vendor's PKI; any other chain proves only
/// that some CA signed it, and pinning is left to the consumer.
static PINNED_ROOTS: LazyLock<Vec<PinnedRoot>> = LazyLock::new(|| {
    const ROOTS: &[(Vendor, &[u8])] = &[
        // The 1997 "Microsoft Root Authority": the SHA-1-era root above the
        // original Code Signing and Timestamping PCAs, so the VC++ 2005–2010
        // runtimes and other pre-2011 Microsoft binaries anchor here. A v3
        // certificate with no extensions, which is why anchors skip
        // `may_issue` in `walk_chain`.
        (
            Vendor::Microsoft,
            include_bytes!("cms/roots/microsoft-root-authority-1997.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("cms/roots/microsoft-root-2001.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("cms/roots/microsoft-root-2010.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("cms/roots/microsoft-root-2011.cer"),
        ),
        (Vendor::Apple, include_bytes!("cms/roots/apple-root.cer")),
        (Vendor::Apple, include_bytes!("cms/roots/apple-root-g3.cer")),
    ];
    ROOTS
        .iter()
        .filter_map(|&(vendor, der)| {
            let cert = Certificate::from_der(der).ok()?;
            let thumbprint = thumbprint_sha256(&cert)?;
            Some(PinnedRoot {
                vendor,
                cert,
                thumbprint,
            })
        })
        .collect()
});

/// A verified chain: thumbprints from the signer upward, and the platform
/// root it ends at, when it ends at one.
struct Chain {
    thumbprints: Vec<String>,
    anchor: Option<Vendor>,
}

/// The signer certificate, then each certificate in the SignedData bag whose
/// public key verifiably signed the one before it, as SHA-256 thumbprints.
///
/// Names prove nothing: anyone can mint a certificate whose subject reads
/// "Microsoft Code Signing PCA 2011". A link is added only when the issuer's
/// key verifies the child's signature over its TBSCertificate, and the
/// issuer's own certificate permits issuing: BasicConstraints `cA`, a
/// keyUsage (when present) with `keyCertSign`, and a path length covering
/// the intermediates below it. A real CA's thumbprint therefore appears here
/// only if that CA's private key signed the chain below it, and a leaf
/// certificate cannot pose as a CA by signing another leaf.
///
/// When the walk reaches a [`PINNED_ROOTS`] key — in the bag or not — that
/// root closes the chain and names `anchor`. A pinned root is a trust
/// anchor, so its own certificate is not held to the issuing constraints
/// (RFC 5280 §6.1.1): its authority comes from being pinned, and the 1997
/// Microsoft root predates BasicConstraints. Its key must still verify the
/// child. Which other CAs to trust is policy and stays with the consumer,
/// which pins thumbprints.
///
/// The walk stops at a self-issued certificate, at the first link that does
/// not verify, is not permitted, or uses an algorithm we cannot check, at
/// `MAX_CHAIN`, or once it has tried [`MAX_LINK_ATTEMPTS`] candidate issuers.
/// Every failure shortens the chain; none can add a certificate to it.
fn verified_chain(bag: &[&Certificate], signer: &Certificate) -> Chain {
    walk_chain(bag, signer, &PINNED_ROOTS)
}

/// Candidate issuers one chain walk checks a signature against. Every
/// candidate carrying the right name costs a public-key verification, and a
/// signature walks its bag once for the signer and again for each
/// countersigner. A bag of thousands of same-named decoys, each taking up to
/// eight tries along an alternating-name chain, would otherwise cost minutes
/// per megabyte. A real chain tries one or two candidates per link.
const MAX_LINK_ATTEMPTS: usize = 32;

fn walk_chain(bag: &[&Certificate], signer: &Certificate, roots: &[PinnedRoot]) -> Chain {
    const MAX_CHAIN: usize = 8;
    let mut chain = Chain {
        thumbprints: Vec::new(),
        anchor: None,
    };
    let mut attempts = 0;
    let mut cert = signer;
    while let Some(thumbprint) = thumbprint_sha256(cert) {
        if chain.thumbprints.contains(&thumbprint) {
            break;
        }
        let root = roots.iter().find(|r| r.thumbprint == thumbprint);
        chain.thumbprints.push(thumbprint);
        if let Some(root) = root {
            chain.anchor = Some(root.vendor);
            break;
        }
        let tbs = &cert.tbs_certificate;
        if chain.thumbprints.len() == MAX_CHAIN || tbs.issuer == tbs.subject {
            break;
        }
        // CA certificates between the next issuer and the leaf.
        let intermediates_below = chain.thumbprints.len() - 1;
        let child = cert;
        let Some((issuer, _)) = bag
            .iter()
            .map(|&c| (c, false))
            .chain(roots.iter().map(|r| (&r.cert, true)))
            .find(|&(c, anchor)| {
                c.tbs_certificate.subject == tbs.issuer
                    && (anchor || may_issue(c, intermediates_below))
                    && {
                        attempts += 1;
                        attempts <= MAX_LINK_ATTEMPTS && signs(c, child)
                    }
            })
        else {
            break;
        };
        cert = issuer;
    }
    chain
}

/// Whether `issuer`'s certificate permits it to sign certificates with
/// `intermediates_below` CA certificates between it and the leaf
/// (RFC 5280 §4.2.1.3, §4.2.1.9). BasicConstraints is required: a
/// certificate without it is not a CA.
fn may_issue(issuer: &Certificate, intermediates_below: usize) -> bool {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let Some(constraints) = extension::<BasicConstraints>(issuer) else {
        return false;
    };
    if !constraints.ca
        || constraints
            .path_len_constraint
            .is_some_and(|max| intermediates_below > usize::from(max))
    {
        return false;
    }
    let has_key_usage = issuer
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|ext| ext.extn_id == KeyUsage::OID);
    // Absent keyUsage permits every use; a present one that does not decode
    // permits none.
    !has_key_usage || extension::<KeyUsage>(issuer).is_some_and(|usage| usage.key_cert_sign())
}

/// Whether `issuer`'s public key verifies `child`'s certificate signature.
fn signs(issuer: &Certificate, child: &Certificate) -> bool {
    let Some(digest) = signature_algorithm(&child.signature_algorithm.oid).and_then(|a| a.digest)
    else {
        return false;
    };
    let (Ok(tbs), Some(signature)) = (child.tbs_certificate.to_der(), child.signature.as_bytes())
    else {
        return false;
    };
    verify_signature(
        issuer,
        &child.signature_algorithm.oid,
        digest,
        &tbs,
        signature,
    ) == VerifyOutcome::Verified
}

fn thumbprint_sha256(cert: &Certificate) -> Option<String> {
    cert.to_der()
        .ok()
        .map(|der| hex_encode(&Sha256::digest(&der)))
}

fn find_signer_cert<'a>(bag: &[&'a Certificate], signer: &SignerInfo) -> Option<&'a Certificate> {
    // SubjectKeyIdentifier matching for the `subject_key_identifier`
    // variant is uncommon in Authenticode; it is not resolved.
    let ::cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(isn) = &signer.sid else {
        tracing::debug!(
            target: "filefacts::cms",
            stage = "signer",
            "signer identified by subject key identifier; certificate not resolved"
        );
        return None;
    };
    bag.iter().copied().find(|cert| {
        cert.tbs_certificate.issuer == isn.issuer
            && cert.tbs_certificate.serial_number == isn.serial_number
    })
}

// ---------------------------------------------------------------------
// Signing time and timestamps.
// ---------------------------------------------------------------------

/// Who attested a signing time, published as `signing_time_source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TimeSource {
    /// The signer's own signed `signingTime` attribute.
    Signer,
    /// A PKCS#9 countersignature that verified over this signature.
    Countersignature,
    UnverifiedCountersignature,
    /// An RFC 3161 timestamp token that verified over this signature.
    Rfc3161,
    UnverifiedRfc3161,
}

impl TimeSource {
    /// Whether the time came from a timestamp that did not check out, so the
    /// file alone chose it.
    pub(crate) fn is_unverified(self) -> bool {
        matches!(
            self,
            Self::UnverifiedCountersignature | Self::UnverifiedRfc3161
        )
    }
}

/// A signing time and who attested it.
struct SigningTime {
    text: String,
    unix: i64,
    source: TimeSource,
    /// `chain_sha256` of the timestamping authority; empty unless the
    /// timestamp verified.
    chain: Vec<String>,
}

impl SigningTime {
    /// A timestamp's time, labelled `verified` or `unverified` by whether its
    /// signature and binding checked out; `chain` is the authority's verified
    /// chain, or `None` when they did not.
    fn timestamp(
        (text, unix): (String, i64),
        (verified, unverified): (TimeSource, TimeSource),
        chain: Option<Vec<String>>,
    ) -> Self {
        let source = if chain.is_some() {
            verified
        } else {
            unverified
        };
        Self {
            text,
            unix,
            source,
            chain: chain.unwrap_or_default(),
        }
    }
}

/// The signing time in precedence order: the signer's own attribute, then a
/// verified timestamp, then an unverified one (labelled as such).
fn signing_time(signer: &SignerInfo, bag: &[&Certificate]) -> Option<SigningTime> {
    if let Some((text, unix)) = extract_signing_time(signer) {
        return Some(SigningTime {
            text,
            unix,
            source: TimeSource::Signer,
            chain: Vec::new(),
        });
    }
    let mut unverified = None;
    for found in countersignature_times(signer, bag).chain(rfc3161_times(signer)) {
        if !found.source.is_unverified() {
            return Some(found);
        }
        unverified.get_or_insert(found);
    }
    unverified
}

/// PKCS#9 counterSignature attribute.
const COUNTERSIGNATURE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");

/// Signing times from PKCS#9 countersignatures, the older Authenticode
/// timestamp: a SignerInfo whose `messageDigest` covers the outer signer's
/// signature value, carrying an ordinary `signingTime`. The countersigner's
/// certificate sits in the outer SignedData's bag.
///
/// Verified means the countersigner's key signed its attributes and their
/// `messageDigest` equals the hash of the outer signature, i.e. this time
/// was attested over this signature and not lifted from another one.
fn countersignature_times<'a>(
    signer: &'a SignerInfo,
    bag: &'a [&'a Certificate],
) -> impl Iterator<Item = SigningTime> + 'a {
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == COUNTERSIGNATURE_OID)
        .flat_map(|attr| attr.values.iter())
        .take(MAX_COUNTERSIGNATURES)
        .filter_map(move |any| {
            let counter: SignerInfo = any.decode_as().ok()?;
            let time = extract_signing_time(&counter)?;
            let content = SignedContent {
                content_type: None,
                bytes: Some(signer.signature.as_bytes()),
            };
            let chain = find_signer_cert(bag, &counter)
                .filter(|cert| verify_signer(&counter, cert, &content) == VerifyOutcome::Verified)
                .map(|cert| verified_chain(bag, cert).thumbprints);
            Some(SigningTime::timestamp(
                time,
                (
                    TimeSource::Countersignature,
                    TimeSource::UnverifiedCountersignature,
                ),
                chain,
            ))
        })
}

/// Microsoft's RFC 3161 timestamp-token attribute.
const MS_TIMESTAMP_TOKEN_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
/// `id-ct-TSTInfo`, the encapsulated content type of a timestamp token.
const TST_INFO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Signing times from RFC 3161 timestamp tokens.
///
/// Modern Authenticode timestamps with a token rather than a PKCS#9
/// countersignature: the unsigned attribute (OID 1.3.6.1.4.1.311.3.3.1) holds a
/// ContentInfo wrapping SignedData whose encapsulated content is a TSTInfo, and
/// the authority's attested instant is TSTInfo's `genTime`. Microsoft signs
/// its binaries this way, so without it the signing time — and any judgement
/// about whether a signature was made while its certificate was valid — is
/// unavailable for most signed software.
///
/// Verified means the token's own SignerInfo verifies over the TSTInfo (with
/// the content binding [`verify_signer`] checks) and the TSTInfo's
/// `messageImprint` is the hash of the outer signer's signature value — the
/// authority stamped this signature, not some other one. A verified time is
/// read from that same TSTInfo: the byte search [`gen_time_from_token`] does
/// would find a TSTInfo-shaped forgery planted in front of the real one (in an
/// unsigned `digestAlgorithms` parameter, say) and pass its time off under the
/// authority's signature.
fn rfc3161_times(signer: &SignerInfo) -> impl Iterator<Item = SigningTime> + '_ {
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == MS_TIMESTAMP_TOKEN_OID)
        .flat_map(|attr| attr.values.iter())
        .take(MAX_COUNTERSIGNATURES)
        .filter_map(|any| {
            let token_der = any.to_der().ok()?;
            let labels = (TimeSource::Rfc3161, TimeSource::UnverifiedRfc3161);
            Some(
                match verify_token(&token_der, signer.signature.as_bytes()) {
                    Some(token) => SigningTime::timestamp(token.time, labels, Some(token.chain)),
                    None => SigningTime::timestamp(gen_time_from_token(&token_der)?, labels, None),
                },
            )
        })
}

/// A timestamp token that verified: the time its signed TSTInfo attests and
/// the authority's verified chain.
struct VerifiedToken {
    time: (String, i64),
    chain: Vec<String>,
}

/// Verify a timestamp token over `stamped` (the outer signature value).
/// `None` when anything fails, the signed TSTInfo's `genTime` included.
fn verify_token(token_der: &[u8], stamped: &[u8]) -> Option<VerifiedToken> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    let signed_data = decode_signed_data_lenient(&ci.content)?;
    let encap = &signed_data.encap_content_info;
    if encap.econtent_type != TST_INFO_OID {
        return None;
    }
    // The eContent is an OCTET STRING whose value is the TSTInfo DER.
    let tst_info = encap.econtent.as_ref()?.decode_as::<OctetString>().ok()?;
    let tst = TstInfo::decode(tst_info.as_bytes())?;
    if tst.imprint_alg.digest(stamped) != tst.imprint {
        return None;
    }
    let bag = cert_bag(&signed_data);
    let token_signer = signed_data.signer_infos.0.as_slice().first()?;
    let cert = find_signer_cert(&bag, token_signer)?;
    let content = SignedContent {
        content_type: Some(TST_INFO_OID),
        bytes: Some(tst_info.as_bytes()),
    };
    if verify_signer(token_signer, cert, &content) != VerifyOutcome::Verified {
        return None;
    }
    Some(VerifiedToken {
        time: tst.gen_time?,
        chain: verified_chain(&bag, cert).thumbprints,
    })
}

/// Decode a SignedData, dropping its `crls [1]` field first if the strict
/// model rejects it. Timestamp tokens carry CRL forms the `cms` crate does
/// not model (`unexpected ASN.1 DER tag: got CONTEXT-SPECIFIC [1]`); no check
/// here reads them, and nothing a signature covers lives there.
fn decode_signed_data_lenient(content: &der::Any) -> Option<SignedData> {
    if let Ok(sd) = content.decode_as::<SignedData>() {
        return Some(sd);
    }
    let mut body = Vec::with_capacity(content.value().len());
    let mut rest = content.value();
    while !rest.is_empty() {
        let (tag, _, next) = read_tlv(rest)?;
        let element = rest.get(..rest.len() - next.len())?;
        if tag != 0xA1 {
            body.extend_from_slice(element);
        }
        rest = next;
    }
    let der = der::asn1::AnyRef::new(der::Tag::Sequence, &body)
        .ok()?
        .to_der()
        .ok()?;
    SignedData::from_der(&der).ok()
}

/// The TSTInfo fields a timestamp is checked and dated by (RFC 3161 §2.4.2):
///
/// ```text
/// TSTInfo ::= SEQUENCE {
///     version INTEGER, policy OBJECT IDENTIFIER,
///     messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier,
///                               hashedMessage OCTET STRING },
///     serialNumber INTEGER, genTime GeneralizedTime,
///     accuracy, ordering, nonce, tsa, extensions -- optional, not read }
/// ```
struct TstInfo {
    imprint_alg: DigestAlg,
    imprint: Vec<u8>,
    /// `None` when `genTime` is not a valid GeneralizedTime.
    gen_time: Option<(String, i64)>,
}

impl TstInfo {
    /// Decode the fields up to `genTime`, each checked against its ASN.1
    /// type. `der`'s own `GeneralizedTime` refuses fractional seconds, which
    /// RFC 3161 permits and timestamping authorities emit, so `genTime` is
    /// taken as its raw value and read by [`parse_generalized_time`].
    fn decode(tst_der: &[u8]) -> Option<Self> {
        use der::Tagged as _;
        use der::asn1::{AnyRef, IntRef, OctetStringRef};
        let mut reader = der::SliceReader::new(tst_der).ok()?;
        let (alg, imprint, gen_time) = reader
            .sequence(|seq| {
                let _version = u8::decode(seq)?;
                // The policy is not read, only checked to be an OID.
                AnyRef::decode(seq)?
                    .tag()
                    .assert_eq(der::Tag::ObjectIdentifier)?;
                let (alg, imprint) = seq.sequence(|message_imprint| {
                    let alg = message_imprint.sequence(|alg_id| {
                        let oid = ObjectIdentifier::decode(alg_id)?;
                        // Digest parameters are NULL or absent; neither matters.
                        alg_id.read_slice(alg_id.remaining_len())?;
                        Ok(oid)
                    })?;
                    let imprint = OctetStringRef::decode(message_imprint)?;
                    Ok((alg, imprint.as_bytes().to_vec()))
                })?;
                let _serial = IntRef::decode(seq)?;
                let gen_time = AnyRef::decode(seq)?;
                seq.read_slice(seq.remaining_len())?;
                Ok((alg, imprint, gen_time))
            })
            .ok()?;
        let gen_time = (gen_time.tag() == der::Tag::GeneralizedTime)
            .then(|| parse_generalized_time(std::str::from_utf8(gen_time.value()).ok()?))
            .flatten();
        Some(Self {
            imprint_alg: DigestAlg::from_oid(&alg)?,
            imprint,
            gen_time,
        })
    }
}

/// DER encoding of the `id-ct-TSTInfo` OID (1.2.840.113549.1.9.16.1.4), which
/// appears exactly once in a token — as `encapContentInfo.eContentType`.
const TST_INFO_OID_DER: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// Locate the TSTInfo inside a timestamp token and read its `genTime`.
///
/// The fallback for a token that does not verify, so its time is reported as
/// unverified: such tokens carry the optional `crls [1]` field or other
/// damage the `cms::SignedData` model rejects. Only one value is wanted, and
/// it sits at a fixed place relative to the `id-ct-TSTInfo` content-type OID,
/// so the search anchors there and reads forward. After the content-type OID
/// comes `eContent [0] EXPLICIT OCTET STRING`, whose bytes are the TSTInfo.
/// Some producers wrap the TSTInfo in a further OCTET STRING, so one extra
/// layer is unwrapped when present.
fn gen_time_from_token(token_der: &[u8]) -> Option<(String, i64)> {
    let at = memchr::memmem::find(token_der, TST_INFO_OID_DER)?;
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
    if let Some((0x04, inner, _)) = read_tlv(body)
        && inner.len() + 2 <= body.len()
    {
        body = inner;
    }
    TstInfo::decode(body)?.gen_time
}

/// A DER header is at most a tag byte and a five-byte length.
const MAX_DER_HEADER_LEN: usize = 6;

/// The header of the DER element at the start of `bytes`, and how many bytes
/// it occupies. Only the header's own bytes are handed to the decoder, so the
/// rest of the input may be any size.
fn der_header(bytes: &[u8]) -> Option<(der::Header, usize)> {
    let prefix = bytes.get(..bytes.len().min(MAX_DER_HEADER_LEN))?;
    let mut reader = der::SliceReader::new(prefix).ok()?;
    let header = der::Header::decode(&mut reader).ok()?;
    Some((header, usize::try_from(reader.position()).ok()?))
}

/// The DER element at the start of `bytes`, without whatever follows it:
/// DER decoders reject trailing data, and signature carriers pad theirs.
/// `None` when the bytes do not open with a DER header whose element they
/// hold in full.
pub(crate) fn der_element(bytes: &[u8]) -> Option<&[u8]> {
    let (header, header_len) = der_header(bytes)?;
    let end = header_len.checked_add(usize::try_from(header.length).ok()?)?;
    bytes.get(..end)
}

/// Read one DER element, returning `(tag, contents, remainder)`.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (header, header_len) = der_header(bytes)?;
    let end = header_len.checked_add(usize::try_from(header.length).ok()?)?;
    Some((
        header.tag.into(),
        bytes.get(header_len..end)?,
        bytes.get(end..)?,
    ))
}

/// Parse `YYYYMMDDHHMMSS[.fff]Z` into a display string and Unix seconds. The
/// calendar fields are checked by [`der::DateTime::new`], so a thirteenth
/// month or a 30 February is refused rather than rolled into another date.
fn parse_generalized_time(text: &str) -> Option<(String, i64)> {
    let digits = text.get(..text.find(['.', 'Z'])?)?;
    if digits.len() < 14 {
        return None;
    }
    // `str::get`: the text is only known to be UTF-8, so a multi-byte char
    // can put a field edge off a char boundary.
    let field = |a: usize, b: usize| digits.get(a..b)?.parse::<u8>().ok();
    let year = digits.get(0..4)?.parse::<u16>().ok()?;
    let dt = der::DateTime::new(
        year,
        field(4, 6)?,
        field(6, 8)?,
        field(8, 10)?,
        field(10, 12)?,
        field(12, 14)?,
    )
    .ok()?;
    Some((dt.to_string(), unix_secs(dt.unix_duration())))
}

/// PKCS#9 signing-time OID.
const SIGNING_TIME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Recover the signing time from the SignerInfo signed-attributes
/// bag. Returns the ISO-8601 string alongside its Unix-epoch seconds
/// so consumers don't have to reparse the string for arithmetic.
fn extract_signing_time(signer: &SignerInfo) -> Option<(String, i64)> {
    use x509_cert::time::Time;
    let attrs = signer.signed_attrs.as_ref()?;
    let attr = attrs.iter().find(|attr| attr.oid == SIGNING_TIME_OID)?;
    // CHOICE { UTCTime, GeneralizedTime }.
    let any = attr.values.as_slice().first()?;
    let time = any
        .decode_as()
        .map(Time::UtcTime)
        .or_else(|_| any.decode_as().map(Time::GeneralTime))
        .ok()?;
    Some((time_to_string(time), time_to_unix(time)))
}

// ---------------------------------------------------------------------
// Nested signatures.
// ---------------------------------------------------------------------

/// Microsoft nested-signature attribute.
const MS_NESTED_SIGNATURE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

/// Every value of the SignerInfo's nested-signature attributes, each a
/// PKCS#7 SignedData parsed through the same pipeline. Bounded by
/// [`MAX_NESTING`] levels and the shared signature budget. Each value is
/// decoded straight from its attribute rather than re-encoded first. A nested
/// signature signs its own content, which for a PE is the same image.
fn extract_nested_signatures(
    signer: &SignerInfo,
    signs: Signs<'_>,
    budget: &mut Budget,
    depth: u8,
) -> Vec<Signature> {
    if depth + 1 >= MAX_NESTING {
        return Vec::new();
    }
    let signs = match signs {
        Signs::PeImage => Signs::PeImage,
        Signs::Unbound => Signs::Unbound,
        Signs::Encapsulated | Signs::Detached(_) => Signs::Encapsulated,
    };
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == MS_NESTED_SIGNATURE_OID)
        .flat_map(|attr| attr.values.iter())
        .filter_map(|any| any.decode_as::<ContentInfo>().ok())
        .filter_map(|ci| parse_content_info(&ci, signs, budget, depth + 1))
        .collect()
}

// ---------------------------------------------------------------------
// Certificate and content fields.
// ---------------------------------------------------------------------

/// Canonical RFC name for a signature-algorithm OID, or the dotted
/// OID itself when the algorithm is outside our friendly-name table.
/// Returning the raw OID (rather than a useless `"other"`) lets a
/// forensic consumer look up exotic / new algorithms directly.
fn signature_algorithm_name(oid: &ObjectIdentifier) -> String {
    signature_algorithm(oid).map_or_else(|| oid.to_string(), |alg| alg.name.to_string())
}

/// Authenticode `SpcIndirectDataContent` OID — what the SignedData's
/// `encapContentInfo.eContentType` is set to for a PE signature.
const SPC_INDIRECT_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

/// The algorithm OID and hex digest the signature was made over, from the
/// SignedData's `encapContentInfo`. The eContent is a
/// `SpcIndirectDataContent` whose nested `messageDigest.digestAlgorithm`
/// and `messageDigest.digest` carry exactly the claim "this signature
/// authenticates an image whose Authentihash equals these bytes under
/// this hash".
fn extract_spc_indirect_data(signed_data: &SignedData) -> Option<(ObjectIdentifier, String)> {
    let encap = &signed_data.encap_content_info;
    if encap.econtent_type != SPC_INDIRECT_DATA_OID {
        return None;
    }
    // Round-trip the Any through full DER encoding so we get the
    // SpcIndirectDataContent SEQUENCE's tag + length back, then parse
    // it as a regular SEQUENCE. `Any::value()` strips the outer wrapper
    // which makes structural parsing fragile across the
    // [0]-EXPLICIT-OCTET-STRING / [0]-EXPLICIT-SpcIndirect variants
    // Microsoft uses in practice.
    let full_der = encap.econtent.as_ref()?.to_der().ok()?;
    parse_spc_indirect_inner(&full_der)
}

/// Walk the DER bytes of the SpcIndirectDataContent SEQUENCE and pull
/// out the `messageDigest` (DigestInfo) component. Matches the spec
/// layout: `SEQUENCE { data SpcAttributeTypeAndOptionalValue,
///                     messageDigest DigestInfo }`.
fn parse_spc_indirect_inner(der: &[u8]) -> Option<(ObjectIdentifier, String)> {
    let mut reader = der::SliceReader::new(der).ok()?;
    // The bytes we're handed may be either the bare SpcIndirectDataContent
    // SEQUENCE or that SEQUENCE wrapped in an OCTET STRING (the
    // RFC-5652-strict form). Peek the tag and unwrap if needed.
    let unwrapped;
    let body = if reader.peek_header().ok()?.tag == der::Tag::OctetString {
        unwrapped = OctetString::decode(&mut reader).ok()?;
        unwrapped.as_bytes()
    } else {
        der
    };
    let mut reader = der::SliceReader::new(body).ok()?;
    let (alg, digest) = reader
        .sequence(|r| {
            // Skip `data SpcAttributeTypeAndOptionalValue`.
            r.tlv_bytes()?;
            // `messageDigest DigestInfo ::= SEQUENCE { digestAlgorithm
            // AlgorithmIdentifier, digest OCTET STRING }`.
            r.sequence(|m| {
                let alg = m.decode::<x509_cert::spki::AlgorithmIdentifierOwned>()?;
                let digest = m.decode::<OctetString>()?;
                Ok((alg, digest))
            })
        })
        .ok()?;
    Some((alg.oid, hex_encode(digest.as_bytes())))
}

/// Seconds since the Unix epoch for an X.509 validity instant.
fn time_to_unix(t: x509_cert::time::Time) -> i64 {
    unix_secs(t.to_unix_duration())
}

fn time_to_string(t: x509_cert::time::Time) -> String {
    t.to_date_time().to_string()
}

/// Shorthand for a digest-algorithm OID (`sha256`, `sha1`, …), or `other`.
fn oid_to_label(oid: &ObjectIdentifier) -> &'static str {
    DigestAlg::from_oid(oid).map_or("other", DigestAlg::label)
}

/// Seconds since the Unix epoch as an `i64`. X.509 times end at 9999-12-31,
/// so the saturation never fires on a decodable certificate.
fn unix_secs(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
