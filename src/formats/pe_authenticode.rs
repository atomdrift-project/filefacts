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
//! The one exception is `chain_anchor`, set when the chain ends at one of the
//! few platform roots filefacts carries (Microsoft's and Apple's code-signing
//! roots), so "signed by the platform vendor" is a cryptographic fact rather
//! than a name match.
//!
//! `verified` is true only when both halves of a CMS signature hold: the
//! signer's key signed the signed attributes, and those attributes bind the
//! signed content (`messageDigest` equals the content's hash, `contentType`
//! names it). Checking the first half alone would accept a SignerInfo lifted
//! from a genuine file and grafted onto content of the attacker's choosing.

mod ber;

use std::sync::LazyLock;

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::output::Values;
use crate::value_key;

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
    let mut budget = Budget::new();
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
            if let Some(sig) = parse_pkcs7(trimmed, None, &mut budget) {
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
/// JSON object the PE Authenticode path emits, for the other formats that
/// carry one (cabinets, APK v1 signature blocks). A detached signature
/// parsed this way has no content to bind and reads as unverifiable; see
/// [`parse_detached_cms_blob`].
pub(super) fn parse_cms_blob(der_bytes: &[u8]) -> Option<JsonValue> {
    parse_pkcs7(der_bytes, None, &mut Budget::new())
}

/// [`parse_cms_blob`] for a detached signature over `content`. The Mach-O
/// code-signature module hands over the CMS blob found inside
/// `CSMAGIC_BLOBWRAPPER` with the CodeDirectory it signs, which lives beside
/// the signature rather than inside it.
pub(super) fn parse_detached_cms_blob(der_bytes: &[u8], content: &[u8]) -> Option<JsonValue> {
    parse_pkcs7(der_bytes, Some(content), &mut Budget::new())
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

fn parse_pkcs7(
    der_bytes: &[u8],
    detached: Option<&[u8]>,
    budget: &mut Budget,
) -> Option<JsonValue> {
    let ci = decode_content_info(der_bytes)?;
    parse_content_info(&ci, detached, budget, 0)
}

/// Decode a ContentInfo, normalizing BER to DER first when the strict decode
/// fails. Apple's Mach-O signatures are BER; Authenticode is DER.
fn decode_content_info(der_bytes: &[u8]) -> Option<ContentInfo> {
    match ContentInfo::from_der(der_bytes) {
        Ok(ci) => Some(ci),
        Err(strict) => {
            let normalized = ber::to_der(der_bytes)?;
            ContentInfo::from_der(&normalized)
                .inspect_err(|e| {
                    crate::debug::log(format_args!(
                        "pe.authenticode ContentInfo::from_der failed: {strict}; after BER normalization: {e}"
                    ));
                })
                .ok()
        }
    }
}

fn parse_content_info(
    ci: &ContentInfo,
    detached: Option<&[u8]>,
    budget: &mut Budget,
    depth: u8,
) -> Option<JsonValue> {
    if !budget.take() {
        return None;
    }
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
    let bag = cert_bag(&signed_data);

    // Resolve the signer's certificate from the SignedData.certificates
    // bag by matching on issuer + serial number.
    let signer_cert = find_signer_cert(&bag, signer);

    let mut obj = serde_json::Map::new();
    obj.insert(
        "digest_algorithm".into(),
        JsonValue::String(digest_algorithm.into()),
    );

    // Count of certificates carried alongside the signature — proxy
    // for chain depth. A signing cert + intermediate + (sometimes)
    // root is typical; a bag with only the leaf is suspicious.
    if !bag.is_empty() {
        obj.insert(
            "cert_chain_depth".into(),
            JsonValue::Number(bag.len().into()),
        );
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

    // Signing time, in two forms: the canonical string for display, plus a
    // Unix timestamp for downstream arithmetic (sign-time-before-build checks,
    // age windows, etc.). The signer's own `signingTime` attribute first — it
    // sits under the signer's signature, so it is the signer's verified word —
    // then a timestamp. Authenticode records signing time in a timestamp made
    // by a timestamping authority, so most binaries only answer on the second
    // lookup. `signing_time_source` says which attested it. A timestamp whose
    // own signature or imprint does not check out is reported as
    // `unverified_<kind>` so nothing downstream mistakes it for an attested
    // time; its chain thumbprints are `timestamp_chain_sha256`, so a consumer
    // can decide whether it trusts the authority.
    if let Some(time) = signing_time(signer, &bag) {
        obj.insert("signing_time".into(), JsonValue::String(time.text));
        obj.insert(
            "signing_time_unix".into(),
            JsonValue::Number(time.unix.into()),
        );
        obj.insert(
            "signing_time_source".into(),
            JsonValue::String(time.source.into()),
        );
        if !time.chain.is_empty() {
            obj.insert(
                "timestamp_chain_sha256".into(),
                JsonValue::Array(time.chain.into_iter().map(JsonValue::String).collect()),
            );
        }
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

    // Cryptographic verification: the signer's key over the signed
    // attributes, and the attributes' binding to the encapsulated content
    // (or, for a detached signature, the content the caller supplied).
    if let Some(cert) = signer_cert {
        let chain = verified_chain(&bag, cert);
        obj.insert(
            "chain_sha256".into(),
            JsonValue::Array(
                chain
                    .thumbprints
                    .into_iter()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
        if let Some(anchor) = chain.anchor {
            obj.insert(
                "chain_anchor".into(),
                JsonValue::String(anchor.label().into()),
            );
        }
        let content = SignedContent {
            content_type: Some(signed_data.encap_content_info.econtent_type),
            bytes: signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .map(der::Any::value)
                .or(detached),
        };
        match verify_signer(signer, cert, &content) {
            VerifyOutcome::Verified => {
                obj.insert("verified".into(), JsonValue::Bool(true));
            }
            VerifyOutcome::Failed(why) => {
                obj.insert("verified".into(), JsonValue::Bool(false));
                obj.insert(
                    "verification_failure".into(),
                    JsonValue::String(why.label().into()),
                );
            }
            VerifyOutcome::Unsupported => {
                // Off-pair curve, exotic OID, or missing parts —
                // record the gap rather than guess at "valid".
                obj.insert("verified".into(), JsonValue::Null);
                obj.insert("verification_unsupported".into(), JsonValue::Bool(true));
            }
        }
    }

    // Nested signatures (Microsoft `nested-signature`). Carrier for SHA-256
    // signatures on dual-signed legacy binaries; each inner PKCS#7 has its
    // own SignerInfo and certificate chain and covers the same image. Every
    // value is parsed through the same pipeline, so consumers see the same
    // shape at each level.
    let nested = extract_nested_signatures(signer, budget, depth);
    if !nested.is_empty() {
        obj.insert("nested".into(), JsonValue::Array(nested));
    }

    Some(JsonValue::Object(obj))
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

/// Curve identifiers — P-256 and P-384 cover every real-world Authenticode
/// and Mach-O CMS payload encountered.
const CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

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
#[derive(Debug, PartialEq, Eq)]
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

/// Why a SignerInfo failed verification. The label lands in
/// `verification_failure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
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
}

impl Failure {
    fn label(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::MessageDigestMissing => "message_digest_missing",
            Self::MessageDigestMalformed => "message_digest_malformed",
            Self::MessageDigestMismatch => "message_digest_mismatch",
            Self::ContentTypeMismatch => "content_type_mismatch",
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
    // Re-tag from [0] IMPLICIT (0xA0) to SET OF (0x31).
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
        // Off-pair (P-256 + SHA-384 etc.) or another curve — extremely
        // rare; record as unsupported rather than producing a misleading
        // mismatch.
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
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            cms::cert::CertificateChoices::Other(_) => None,
        })
        .collect()
}

/// A platform vendor whose code-signing roots filefacts carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Vendor {
    Microsoft,
    Apple,
}

impl Vendor {
    fn label(self) -> &'static str {
        match self {
            Self::Microsoft => "microsoft",
            Self::Apple => "apple",
        }
    }
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
        (
            Vendor::Microsoft,
            include_bytes!("pe_authenticode/roots/microsoft-root-2001.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("pe_authenticode/roots/microsoft-root-2010.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("pe_authenticode/roots/microsoft-root-2011.cer"),
        ),
        (
            Vendor::Apple,
            include_bytes!("pe_authenticode/roots/apple-root.cer"),
        ),
        (
            Vendor::Apple,
            include_bytes!("pe_authenticode/roots/apple-root-g3.cer"),
        ),
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
/// root closes the chain and names `anchor`. Which other CAs to trust is
/// policy and stays with the consumer, which pins thumbprints.
///
/// The walk stops at a self-issued certificate, at the first link that does
/// not verify, is not permitted, or uses an algorithm we cannot check, or at
/// `MAX_CHAIN`. Every failure shortens the chain; none can add a certificate
/// to it.
fn verified_chain(bag: &[&Certificate], signer: &Certificate) -> Chain {
    walk_chain(bag, signer, &PINNED_ROOTS)
}

fn walk_chain(bag: &[&Certificate], signer: &Certificate, roots: &[PinnedRoot]) -> Chain {
    const MAX_CHAIN: usize = 8;
    let mut chain = Chain {
        thumbprints: Vec::new(),
        anchor: None,
    };
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
        let Some(issuer) = bag
            .iter()
            .copied()
            .chain(roots.iter().map(|r| &r.cert))
            .find(|c| {
                c.tbs_certificate.subject == tbs.issuer
                    && may_issue(c, intermediates_below)
                    && signs(c, child)
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
    const BASIC_CONSTRAINTS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const KEY_USAGE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

    let extensions = issuer
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();
    let extension = |oid: ObjectIdentifier| {
        extensions
            .iter()
            .find(|ext| ext.extn_id == oid)
            .map(|ext| ext.extn_value.as_bytes())
    };
    let Some(Ok(constraints)) = extension(BASIC_CONSTRAINTS_OID).map(BasicConstraints::from_der)
    else {
        return false;
    };
    if !constraints.ca {
        return false;
    }
    if constraints
        .path_len_constraint
        .is_some_and(|max| intermediates_below > usize::from(max))
    {
        return false;
    }
    match extension(KEY_USAGE_OID).map(KeyUsage::from_der) {
        None => true,
        Some(Ok(usage)) => usage.key_cert_sign(),
        Some(Err(_)) => false,
    }
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
    let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(isn) = &signer.sid else {
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

/// A signing time and who attested it.
struct SigningTime {
    text: String,
    unix: i64,
    source: &'static str,
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
        (verified, unverified): (&'static str, &'static str),
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

    fn verified(&self) -> bool {
        !self.source.starts_with("unverified_")
    }
}

/// The signing time in precedence order: the signer's own attribute, then a
/// verified timestamp, then an unverified one (labelled as such).
fn signing_time(signer: &SignerInfo, bag: &[&Certificate]) -> Option<SigningTime> {
    if let Some((text, unix)) = extract_signing_time(signer) {
        return Some(SigningTime {
            text,
            unix,
            source: "signer",
            chain: Vec::new(),
        });
    }
    let mut unverified = None;
    for found in countersignature_times(signer, bag).chain(rfc3161_times(signer)) {
        if found.verified() {
            return Some(found);
        }
        unverified.get_or_insert(found);
    }
    unverified
}

/// PKCS#9 counterSignature attribute.
const COUNTERSIGNATURE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");

/// Signing times from PKCS#9 countersignatures, the legacy Authenticode
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
                ("countersignature", "unverified_countersignature"),
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
/// the authority's attested instant is TSTInfo's `genTime`. Every
/// Microsoft-signed binary checked here uses this form, so without it the
/// signing time — and any judgement about whether a signature was made while
/// its certificate was valid — is unavailable for most signed software.
///
/// Verified means the token's own SignerInfo verifies over the TSTInfo (with
/// the content binding [`verify_signer`] checks) and the TSTInfo's
/// `messageImprint` is the hash of the outer signer's signature value — the
/// authority stamped this signature, not some other one.
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
            let time = gen_time_from_token(&token_der)?;
            Some(SigningTime::timestamp(
                time,
                ("rfc3161", "unverified_rfc3161"),
                verify_token(&token_der, signer.signature.as_bytes()),
            ))
        })
}

/// Verify a timestamp token over `stamped` (the outer signature value).
/// Returns the authority's verified chain, or `None` when anything fails.
fn verify_token(token_der: &[u8], stamped: &[u8]) -> Option<Vec<String>> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    let signed_data = decode_signed_data_lenient(&ci.content)?;
    let encap = &signed_data.encap_content_info;
    if encap.econtent_type != TST_INFO_OID {
        return None;
    }
    // The eContent is an OCTET STRING whose value is the TSTInfo DER.
    let tst_info = encap.econtent.as_ref()?.decode_as::<OctetString>().ok()?;
    let (imprint_alg, imprint) = message_imprint(tst_info.as_bytes())?;
    if imprint_alg.digest(stamped) != imprint {
        return None;
    }
    let bag = cert_bag(&signed_data);
    let token_signer = signed_data.signer_infos.0.as_slice().first()?;
    let cert = find_signer_cert(&bag, token_signer)?;
    let content = SignedContent {
        content_type: Some(TST_INFO_OID),
        bytes: Some(tst_info.as_bytes()),
    };
    (verify_signer(token_signer, cert, &content) == VerifyOutcome::Verified)
        .then(|| verified_chain(&bag, cert).thumbprints)
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
    u32::try_from(body.len()).ok()?;
    let mut der = vec![0x30];
    ber::push_length(body.len(), &mut der);
    der.extend_from_slice(&body);
    SignedData::from_der(&der).ok()
}

/// `messageImprint` from a TSTInfo: its hash algorithm and hashed message.
///
/// TSTInfo ::= SEQUENCE { version, policy, messageImprint, ... }
/// MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
///                               hashedMessage OCTET STRING }
fn message_imprint(tst_der: &[u8]) -> Option<(DigestAlg, Vec<u8>)> {
    let (tag, body, _) = read_tlv(tst_der)?;
    if tag != 0x30 {
        return None;
    }
    // version, policy.
    let (_, _, rest) = read_tlv(body)?;
    let (_, _, rest) = read_tlv(rest)?;
    let (tag, imprint, _) = read_tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, alg_id, rest) = read_tlv(imprint)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, oid, _) = read_tlv(alg_id)?;
    if tag != 0x06 {
        return None;
    }
    let alg = DigestAlg::from_oid(&ObjectIdentifier::from_bytes(oid).ok()?)?;
    let (tag, hashed, _) = read_tlv(rest)?;
    if tag != 0x04 {
        return None;
    }
    Some((alg, hashed.to_vec()))
}

/// DER encoding of the `id-ct-TSTInfo` OID (1.2.840.113549.1.9.16.1.4), which
/// appears exactly once in a token — as `encapContentInfo.eContentType`.
const TST_INFO_OID_DER: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// Locate the TSTInfo inside a timestamp token and read its `genTime`.
///
/// The token is navigated by hand rather than through `cms::SignedData`:
/// these tokens carry the optional `crls [1]` field, which that model rejects.
/// Only one value is wanted, and it sits at a fixed place relative to the
/// `id-ct-TSTInfo` content-type OID, so the search anchors there and reads
/// forward. After the content-type OID comes `eContent [0] EXPLICIT OCTET
/// STRING`, whose bytes are the TSTInfo. Some producers wrap the TSTInfo in a
/// further OCTET STRING, so one extra layer is unwrapped when present.
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

/// PKCS#9 signing-time OID.
const SIGNING_TIME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Recover the signing time from the SignerInfo signed-attributes
/// bag. Returns the ISO-8601 string alongside its Unix-epoch seconds
/// so consumers don't have to reparse the string for arithmetic.
fn extract_signing_time(signer: &SignerInfo) -> Option<(String, i64)> {
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
            return Some((dt.to_string(), unix_secs(dt.unix_duration())));
        }
        if let Ok(t) = any.decode_as::<der::asn1::GeneralizedTime>() {
            let dt = t.to_date_time();
            return Some((dt.to_string(), unix_secs(dt.unix_duration())));
        }
    }
    None
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
/// decoded straight from its attribute rather than re-encoded first.
fn extract_nested_signatures(
    signer: &SignerInfo,
    budget: &mut Budget,
    depth: u8,
) -> Vec<JsonValue> {
    if depth + 1 >= MAX_NESTING {
        return Vec::new();
    }
    let mut nested = Vec::new();
    let values = signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == MS_NESTED_SIGNATURE_OID)
        .flat_map(|attr| attr.values.iter());
    for any in values {
        let Ok(ci) = any.decode_as::<ContentInfo>() else {
            continue;
        };
        if let Some(sig) = parse_content_info(&ci, None, budget, depth + 1) {
            nested.push(sig);
        }
    }
    nested
}

// ---------------------------------------------------------------------
// Certificate and content fields.
// ---------------------------------------------------------------------

/// Minimal Extended Key Usage parse — we only care about the
/// `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3) OID for code-signing
/// attribution. Other EKU OIDs are not currently surfaced.
struct ParsedEku {
    code_signing: bool,
}

fn parse_extended_key_usage(cert: &Certificate) -> Option<ParsedEku> {
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

/// Extract the algorithm + digest the signature was made over from the
/// SignedData's `encapContentInfo`. The eContent is a
/// `SpcIndirectDataContent` whose nested `messageDigest.digestAlgorithm`
/// and `messageDigest.digest` carry exactly the claim "this signature
/// authenticates a PE image whose Authentihash equals these bytes under
/// this hash".
///
/// Returns `(algorithm_label, hex_digest)` on success. The OID-to-label
/// mapping uses the same `oid_to_label` helper as the SignerInfo digest
/// so consumers see consistent shorthand ("sha256", "sha1", …).
fn extract_spc_indirect_data(signed_data: &SignedData) -> Option<(&'static str, String)> {
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
        let os = OctetString::decode(&mut reader).ok()?;
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
            let digest = m.decode::<OctetString>()?;
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
        Time::UtcTime(v) => unix_secs(v.to_date_time().unix_duration()),
        Time::GeneralTime(v) => unix_secs(v.to_date_time().unix_duration()),
    }
}

fn time_to_string(t: x509_cert::time::Time) -> String {
    use x509_cert::time::Time;
    match t {
        Time::UtcTime(v) => v.to_date_time().to_string(),
        Time::GeneralTime(v) => v.to_date_time().to_string(),
    }
}

/// Shorthand for a digest-algorithm OID (`sha256`, `sha1`, …), or `other`.
fn oid_to_label(oid: &ObjectIdentifier) -> &'static str {
    DigestAlg::from_oid(oid).map_or("other", DigestAlg::label)
}

use crate::formats::common::hex_encode;

/// Seconds since the Unix epoch as an `i64`. X.509 times end at 9999-12-31,
/// so the saturation never fires on a decodable certificate.
fn unix_secs(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
