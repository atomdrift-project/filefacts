//! Certificate chains: the issuers whose keys verifiably signed the signer's
//! certificate, and the platform roots a chain can end at.

use std::sync::LazyLock;

use ::cms::signed_data::{SignedData, SignerInfo};
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use super::extension;
use super::verify::{Verdict, signature_algorithm, verify_signature};
use crate::formats::common::hex_encode;

/// The certificates a SignedData carries.
pub(super) fn cert_bag(signed_data: &SignedData) -> Vec<&Certificate> {
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
pub(super) struct PinnedRoot {
    pub(super) vendor: Vendor,
    pub(super) cert: Certificate,
    pub(super) thumbprint: String,
}

/// Microsoft's and Apple's code-signing roots, as published by each vendor
/// (microsoft.com/pki/certs, apple.com/appleca). A chain reaching one of
/// these keys was signed by that vendor's PKI; any other chain proves only
/// that some CA signed it, and pinning is left to the consumer.
pub(super) static PINNED_ROOTS: LazyLock<Vec<PinnedRoot>> = LazyLock::new(|| {
    const ROOTS: &[(Vendor, &[u8])] = &[
        // The 1997 "Microsoft Root Authority": the SHA-1-era root above the
        // original Code Signing and Timestamping PCAs, so the VC++ 2005–2010
        // runtimes and other pre-2011 Microsoft binaries anchor here. A v3
        // certificate with no extensions, which is why anchors skip
        // `may_issue` in `walk_chain`.
        (
            Vendor::Microsoft,
            include_bytes!("roots/microsoft-root-authority-1997.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("roots/microsoft-root-2001.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("roots/microsoft-root-2010.cer"),
        ),
        (
            Vendor::Microsoft,
            include_bytes!("roots/microsoft-root-2011.cer"),
        ),
        (Vendor::Apple, include_bytes!("roots/apple-root.cer")),
        (Vendor::Apple, include_bytes!("roots/apple-root-g3.cer")),
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
pub(super) struct Chain {
    pub(super) thumbprints: Vec<String>,
    pub(super) anchor: Option<Vendor>,
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
pub(super) fn verified_chain(bag: &[&Certificate], signer: &Certificate) -> Chain {
    walk_chain(bag, signer, &PINNED_ROOTS)
}

/// Candidate issuers one chain walk checks a signature against. Every
/// candidate carrying the right name costs a public-key verification, and a
/// signature walks its bag once for the signer and again for each
/// countersigner. A bag of thousands of same-named decoys, each taking up to
/// eight tries along an alternating-name chain, would otherwise cost minutes
/// per megabyte. A real chain tries one or two candidates per link.
pub(super) const MAX_LINK_ATTEMPTS: usize = 32;

pub(super) fn walk_chain(
    bag: &[&Certificate],
    signer: &Certificate,
    roots: &[PinnedRoot],
) -> Chain {
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
    ) == Verdict::Verified
}

pub(super) fn thumbprint_sha256(cert: &Certificate) -> Option<String> {
    cert.to_der()
        .ok()
        .map(|der| hex_encode(&Sha256::digest(&der)))
}

pub(super) fn find_signer_cert<'a>(
    bag: &[&'a Certificate],
    signer: &SignerInfo,
) -> Option<&'a Certificate> {
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
