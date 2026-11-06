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
mod chain;
mod timestamp;
mod verify;

use ::cms::content_info::ContentInfo;
use ::cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::oid::{AssociatedOid, ObjectIdentifier};
use der::{Decode, Encode, Reader as _};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::Digest;
use x509_cert::Certificate;

use crate::bytes::{u16_le, u32_le};
use crate::formats::common::hex_encode;
pub(crate) use chain::Vendor;
use chain::{cert_bag, find_signer_cert, thumbprint_sha256, verified_chain};
pub(crate) use timestamp::TimeSource;
use timestamp::signing_time;
use verify::{
    DigestAlg, Scheme, SignedContent, key_scheme, public_key_bits, signature_algorithm,
    verify_signer,
};
pub(crate) use verify::{Failure, Verdict};

/// Most signatures parsed from one certificate table or CMS blob, nested
/// signatures included. Real binaries carry one to three; the cap bounds the
/// public-key work a crafted table full of small SignedData records can force.
const MAX_SIGNATURES: u16 = 16;
/// Signature levels parsed, the outer signature included. Dual- and
/// triple-signed binaries nest one level; each level re-decodes its blob, so
/// depth is also a memory bound.
const MAX_NESTING: u8 = 4;
/// Smallest signer key not reported as `weak_key`, per scheme.
const MIN_RSA_BITS: u32 = 2048;
const MIN_EC_BITS: u32 = 256;

/// One parsed signature, as published under `pe.signatures[]`,
/// `cab.signatures[]`, `macho.code_signature.cms` and `android.signatures[]`.
///
/// Fields absent from the blob are absent from the output. The PE-only
/// fields (`unsigned_trailing_bytes`, `signed_within_validity`) are filled
/// in by the PE extractor, which alone can compare a signature with the image
/// it claims to cover; `digest_matches` by the PE and APK extractors.
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
    /// Published as `verified`, `verification_failure` and
    /// `verification_unsupported`; absent when no signer certificate was
    /// found.
    #[serde(flatten, with = "verdict_fields")]
    pub(crate) verified: Option<Verdict>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) nested: Vec<Signature>,
    /// Certificate-table bytes past this signature that nothing signs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unsigned_trailing_bytes: Option<u64>,
    /// The committed image digest equals the recomputed Authentihash; for
    /// an APK v1 signature, the `.SF` digests match the manifest and the
    /// manifest's digests match every member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) digest_matches: Option<bool>,
    /// The signing time a verified timestamp attests fell inside the
    /// validity window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signed_within_validity: Option<bool>,
}

/// The published form of [`Signature::verified`]: `verified` itself
/// (`true`, `false`, or `null` when verification could not be attempted),
/// with `verification_failure` beside a `false` and
/// `verification_unsupported` beside a `null`.
mod verdict_fields {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Failure, Verdict};

    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct Fields {
        /// `Some(None)` is a published `null`, which an absent field is not.
        #[expect(
            clippy::option_option,
            reason = "absent and `null` publish differently"
        )]
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        verified: Option<Option<bool>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        verification_failure: Option<Failure>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        verification_unsupported: bool,
    }

    /// A present field, `null` included, is `Some`; an absent one stays
    /// `None` through `#[serde(default)]`.
    #[expect(
        clippy::option_option,
        reason = "absent and `null` publish differently"
    )]
    fn present<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Option<bool>>, D::Error> {
        Option::<bool>::deserialize(deserializer).map(Some)
    }

    #[expect(
        clippy::ref_option,
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature serde's `with` calls"
    )]
    pub(super) fn serialize<S: Serializer>(
        verdict: &Option<Verdict>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let fields = match *verdict {
            None => Fields::default(),
            Some(Verdict::Verified) => Fields {
                verified: Some(Some(true)),
                ..Fields::default()
            },
            Some(Verdict::Failed(why)) => Fields {
                verified: Some(Some(false)),
                verification_failure: Some(why),
                ..Fields::default()
            },
            Some(Verdict::Unsupported) => Fields {
                verified: Some(None),
                verification_unsupported: true,
                ..Fields::default()
            },
        };
        fields.serialize(serializer)
    }

    /// `verified` decides the verdict. A `false` published without a reason
    /// reads as the signature itself failing, the most basic one.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Verdict>, D::Error> {
        let fields = Fields::deserialize(deserializer)?;
        Ok(fields.verified.map(|verified| match verified {
            Some(true) => Verdict::Verified,
            Some(false) => {
                Verdict::Failed(fields.verification_failure.unwrap_or(Failure::Signature))
            }
            None => Verdict::Unsupported,
        }))
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

    fn note_weak(&mut self, alg: DigestAlg) {
        // MD5 and SHA-1 have practical collision attacks.
        let weak = matches!(alg, DigestAlg::Md5 | DigestAlg::Sha1);
        if weak && !self.weak_algorithms.iter().any(|w| w == alg.label()) {
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

/// Parse a CMS / PKCS#7 SignedData blob into its published value, for a
/// format that carries the signature beside its content when that content
/// is missing (an APK v1 block without its `.SF`, a Mach-O signature
/// without a primary CodeDirectory). Nothing binds it to the file, so a
/// sound one reads as unverifiable, like [`parse_unbound_cms_blob`]: any
/// content it encapsulates is its own, not the file's.
pub(crate) fn parse_cms_blob(der_bytes: &[u8]) -> Option<JsonValue> {
    parse_pkcs7(der_bytes, Signs::Unbound).map(|sig| sig.to_json())
}

/// Recover a property list carried as CMS SignedData's encapsulated data.
/// Apple provisioning profiles use this envelope. Follow the ASN.1 fields,
/// never an XML substring elsewhere in the certificate or signature material.
/// This validates framing and plist structure, not a signature or trust chain;
/// forged signatures must still expose their content to normal analysis.
pub(crate) fn encapsulated_plist(bytes: &[u8]) -> Option<::plist::Value> {
    // Profiles are normally tens of KiB. Bound allocations before DER/BER
    // decoding; plist_guard independently bounds nesting and DAG expansion.
    if bytes.first() != Some(&0x30) || bytes.len() > 16 * 1024 * 1024 {
        return None;
    }
    let ci = ContentInfo::from_der(bytes).ok().or_else(|| {
        // A standalone object, unlike an embedded signature blob, must
        // not carry trailing bytes.
        let (der, rest) = ber::normalize(bytes)?;
        if !rest.is_empty() {
            return None;
        }
        ContentInfo::from_der(&der).ok()
    })?;
    if ci.content_type != ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2") {
        return None;
    }
    let signed_data: SignedData = ci.content.decode_as().ok()?;
    let encap = signed_data.encap_content_info;
    if encap.econtent_type != ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1") {
        return None;
    }
    let content: OctetString = encap.econtent?.decode_as().ok()?;
    let raw = content.as_bytes().trim_ascii_start();
    if !(raw.starts_with(b"bplist00")
        || raw.starts_with(b"<?xml")
        || raw.starts_with(b"<plist")
        || raw.starts_with(b"<!DOCTYPE plist"))
    {
        return None;
    }
    super::plist_guard::parse(content.as_bytes())
        .ok()
        .filter(|v| matches!(v, ::plist::Value::Dictionary(_)))
}

/// [`parse_cms_blob`] for a detached signature over `content`. The Mach-O
/// code-signature module hands over the CMS blob found inside
/// `CSMAGIC_BLOBWRAPPER` with the CodeDirectory it signs, which lives beside
/// the signature rather than inside it.
pub(crate) fn parse_detached_cms_blob(der_bytes: &[u8], content: &[u8]) -> Option<JsonValue> {
    parse_detached_cms(der_bytes, content).map(|sig| sig.to_json())
}

/// [`parse_detached_cms_blob`] as a [`Signature`], for a caller that goes on
/// to check what `content` itself binds (an APK v1 `.SF` and its manifest).
pub(crate) fn parse_detached_cms(der_bytes: &[u8], content: &[u8]) -> Option<Signature> {
    parse_pkcs7(der_bytes, Signs::Detached(content))
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
    /// Content carried beside the signature rather than inside it. Content
    /// the signature encapsulates is ignored: a genuine signed document
    /// lifted into the format's signature slot would otherwise verify over
    /// itself.
    Detached(&'a [u8]),
    /// A PE image. Authenticode reaches the image only through the digest an
    /// `SpcIndirectDataContent` names, so any other content type proves
    /// nothing about the file it was found in: a Microsoft-signed catalog
    /// lifted into a PE verifies, with a Microsoft chain, all the same.
    PeImage,
    /// Nothing the file can be checked against: a digest of an object nobody
    /// recomputes, or a detached signature whose content is missing; see
    /// [`parse_unbound_cms_blob`] and [`parse_cms_blob`].
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
    // Unix timestamp for arithmetic. A timestamp a timestamping authority
    // verifiably made over this signature comes first, with its chain
    // thumbprints in `timestamp_chain_sha256` so a consumer can decide
    // whether it trusts the authority. The signer's own `signingTime`
    // attribute comes next: it sits under the signer's signature, but it is
    // only the key holder's word, so it is labelled `signer` and attests
    // nothing. A timestamp whose own signature or imprint does not check out
    // comes last, as `unverified_<kind>`.
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
            bytes: match signs {
                Signs::Detached(bytes) => Some(bytes),
                Signs::PeImage | Signs::Unbound => signed_data
                    .encap_content_info
                    .econtent
                    .as_ref()
                    .map(der::Any::value),
            },
        };
        let verdict = match (verify_signer(signer, cert, &content), signs) {
            // Whatever the key signed, it was not this image.
            (Verdict::Verified | Verdict::Unsupported, Signs::PeImage)
                if image_digest.is_none() =>
            {
                Verdict::Failed(Failure::ImageDigestMissing)
            }
            // Sound, but over a digest of the file nothing here recomputes.
            (Verdict::Verified, Signs::Unbound) => Verdict::Unsupported,
            (verdict, _) => verdict,
        };
        if let Verdict::Failed(why) = verdict {
            tracing::debug!(
                target: "filefacts::cms",
                stage = "verify",
                failure = why.label(),
                "signature did not verify"
            );
        }
        sig.verified = Some(verdict);
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
    // The RFC name, or the dotted OID for an algorithm outside the table, so
    // a consumer can still look an exotic algorithm up.
    let oid = &cert.signature_algorithm.oid;
    let alg = signature_algorithm(oid);
    sig.signature_algorithm = Some(alg.map_or_else(|| oid.to_string(), |alg| alg.name.to_string()));
    if let Some(digest) = alg.and_then(|a| a.digest) {
        sig.note_weak(digest);
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
// Nested signatures.
// ---------------------------------------------------------------------

/// Microsoft nested-signature attribute.
const MS_NESTED_SIGNATURE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

/// Every value of the SignerInfo's nested-signature attributes, each a
/// PKCS#7 SignedData parsed through the same pipeline. Bounded by
/// [`MAX_NESTING`] levels and the shared signature budget. Each value is
/// decoded straight from its attribute rather than re-encoded first. A nested
/// signature signs the same object as the one carrying it.
fn extract_nested_signatures(
    signer: &SignerInfo,
    signs: Signs<'_>,
    budget: &mut Budget,
    depth: u8,
) -> Vec<Signature> {
    if depth + 1 >= MAX_NESTING {
        return Vec::new();
    }
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

/// A DER header is at most a tag byte and a five-byte length.
const MAX_DER_HEADER_LEN: usize = 6;

/// The DER element at the start of `bytes`, without whatever follows it:
/// DER decoders reject trailing data, and signature carriers pad theirs.
/// `None` when the bytes do not open with a DER header whose element they
/// hold in full. Only the header's own bytes are handed to the decoder, so
/// the rest of the input may be any size.
pub(crate) fn der_element(bytes: &[u8]) -> Option<&[u8]> {
    let prefix = bytes.get(..bytes.len().min(MAX_DER_HEADER_LEN))?;
    let mut reader = der::SliceReader::new(prefix).ok()?;
    let header = der::Header::decode(&mut reader).ok()?;
    let header_len = usize::try_from(reader.position()).ok()?;
    let end = header_len.checked_add(usize::try_from(header.length).ok()?)?;
    bytes.get(..end)
}

#[cfg(test)]
mod tests;
