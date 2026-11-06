//! Signature algorithms and SignerInfo verification: RSA and ECDSA over
//! the signed attributes, and the attributes' binding to the content.

use ::cms::signed_data::SignerInfo;
use der::Encode;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// A digest algorithm a SignerInfo, a certificate signature, or an
/// Authenticode structure can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DigestAlg {
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
    pub(super) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        DIGEST_ALGORITHMS
            .iter()
            .find(|(known, _)| known == oid)
            .map(|&(_, alg)| alg)
    }

    /// Shorthand consumers see (`sha256`, `sha1`, …).
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    pub(super) fn digest(self, data: &[u8]) -> Vec<u8> {
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
pub(super) enum Scheme {
    Rsa,
    Ecdsa,
}

/// A signature-algorithm OID: its RFC name, its scheme, and the digest it
/// fixes when the OID is hash-specific. Generic `rsaEncryption` fixes none;
/// the SignerInfo's digest algorithm says which hash to use.
pub(super) struct SignatureAlgorithm {
    oid: ObjectIdentifier,
    pub(super) name: &'static str,
    pub(super) scheme: Scheme,
    pub(super) digest: Option<DigestAlg>,
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

pub(super) fn signature_algorithm(oid: &ObjectIdentifier) -> Option<&'static SignatureAlgorithm> {
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
pub(super) fn key_scheme(cert: &Certificate) -> Option<Scheme> {
    match cert.tbs_certificate.subject_public_key_info.algorithm.oid {
        RSA_ENCRYPTION_OID => Some(Scheme::Rsa),
        EC_PUBLIC_KEY_OID => Some(Scheme::Ecdsa),
        _ => None,
    }
}

/// Bits in a certificate's public key: the RSA modulus, or the curve order.
pub(super) fn public_key_bits(cert: &Certificate) -> Option<u32> {
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

/// PKCS#9 attributes a signature binds its content with.
pub(super) const CONTENT_TYPE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub(super) const MESSAGE_DIGEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// What a SignerInfo signs: the content bytes its `messageDigest` must hash
/// to, and the content type its `contentType` attribute must name. A
/// countersignature has no content type (RFC 5652 §11.1 forbids the
/// attribute there), so it carries `None`.
pub(super) struct SignedContent<'a> {
    pub(super) content_type: Option<ObjectIdentifier>,
    pub(super) bytes: Option<&'a [u8]>,
}

/// Result of cryptographically verifying a SignerInfo, published as
/// `verified` (`true`, `false` or `null`) beside `verification_failure` or
/// `verification_unsupported`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
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
    /// A JAR or APK v1 signature file that does not bind the archive's
    /// manifest: no manifest, or digests that do not match it.
    JarManifestMismatch,
    /// A JAR or APK v1 manifest that does not bind every member: one it or
    /// the signature file leaves out, one whose digest differs, or a name
    /// the archive holds twice.
    JarMemberMismatch,
}

impl Failure {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::MessageDigestMissing => "message_digest_missing",
            Self::MessageDigestMalformed => "message_digest_malformed",
            Self::MessageDigestMismatch => "message_digest_mismatch",
            Self::ContentTypeMismatch => "content_type_mismatch",
            Self::ImageDigestMissing => "image_digest_missing",
            Self::JarManifestMismatch => "jar_manifest_mismatch",
            Self::JarMemberMismatch => "jar_member_mismatch",
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
pub(super) fn verify_signer(
    signer: &SignerInfo,
    cert: &Certificate,
    content: &SignedContent<'_>,
) -> Verdict {
    let Some(digest) = DigestAlg::from_oid(&signer.digest_alg.oid) else {
        return Verdict::Unsupported;
    };
    let Some(bytes) = content.bytes else {
        // A detached signature with no content to hash: the signature
        // might verify, but it would prove nothing about any file.
        return Verdict::Unsupported;
    };
    let (message, binding) = match &signer.signed_attrs {
        Some(attrs) => {
            // The signing input is the signed-attributes bag re-encoded with
            // the universal `SET OF Attribute` tag (0x31) in place of the
            // wire's `[0] IMPLICIT` (0xA0); length and contents stay the same.
            let Ok(mut der) = attrs.to_der() else {
                return Verdict::Unsupported;
            };
            let Some(tag) = der.first_mut() else {
                return Verdict::Unsupported;
            };
            *tag = 0x31;
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
        Verdict::Failed(why) => Verdict::Failed(why),
        // A broken binding is tampering whether or not we could check the
        // signature over it.
        outcome => match binding {
            Err(why) => Verdict::Failed(why),
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
pub(super) fn check_binding(
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

/// Verify `signature` over `message` with `cert`'s public key, under the
/// scheme `sig_alg` names and the `digest` the caller resolved.
pub(super) fn verify_signature(
    cert: &Certificate,
    sig_alg: &ObjectIdentifier,
    digest: DigestAlg,
    message: &[u8],
    signature: &[u8],
) -> Verdict {
    match signature_algorithm(sig_alg).map(|alg| alg.scheme) {
        Some(Scheme::Rsa) => verify_rsa(cert, digest, message, signature),
        Some(Scheme::Ecdsa) => verify_ecdsa(cert, digest, message, signature),
        None => Verdict::Unsupported,
    }
}

fn verify_rsa(cert: &Certificate, digest: DigestAlg, message: &[u8], signature: &[u8]) -> Verdict {
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
        return Verdict::Unsupported;
    };
    let Ok(sig) = Signature::try_from(signature) else {
        return Verdict::Failed(Failure::Signature);
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
        DigestAlg::Md5 => return Verdict::Unsupported,
    };
    if verified {
        Verdict::Verified
    } else {
        Verdict::Failed(Failure::Signature)
    }
}

fn verify_ecdsa(
    cert: &Certificate,
    digest: DigestAlg,
    message: &[u8],
    signature: &[u8],
) -> Verdict {
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
        return Verdict::Unsupported;
    };
    let pubkey_sec1 = spki.subject_public_key.raw_bytes();

    let verified = if curve == CURVE_P256 && digest == DigestAlg::Sha256 {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_sec1) else {
            return Verdict::Unsupported;
        };
        let Ok(sig) = Signature::from_der(signature) else {
            return Verdict::Failed(Failure::Signature);
        };
        vk.verify(message, &sig).is_ok()
    } else if curve == CURVE_P384 && digest == DigestAlg::Sha384 {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_sec1) else {
            return Verdict::Unsupported;
        };
        let Ok(sig) = Signature::from_der(signature) else {
            return Verdict::Failed(Failure::Signature);
        };
        vk.verify(message, &sig).is_ok()
    } else {
        // Off-pair (P-256 + SHA-384 etc.) or another curve: record as
        // unsupported rather than producing a misleading mismatch.
        return Verdict::Unsupported;
    };
    if verified {
        Verdict::Verified
    } else {
        Verdict::Failed(Failure::Signature)
    }
}
