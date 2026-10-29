//! Separates a signature that has *aged* from one that is *wrong*.
//!
//! `pe.signatures[].verified` answers one narrow question: did the holder of
//! the private key matching the signer certificate sign these exact
//! signed-attributes? That is a statement about the PKCS#7 blob alone. It stays
//! true for a decade-old binary whose certificate expired long ago, and it also
//! stays true for a file whose bytes were rewritten after signing — because the
//! attacker never touched the blob, only the image it claims to describe.
//!
//! Those two look identical to a consumer reading `verified` and are opposite
//! findings. Old software with an expired certificate is the overwhelmingly
//! common benign case; a signature whose digest no longer matches the file is
//! one of the strongest tamper signals a PE can carry. This brings the digest
//! a signature commits to and the recomputed Authentihash together:
//!
//! - `pe.signatures[].digest_matches` — the signature's claimed image digest
//!   equals the recomputed Authentihash. False means the bytes changed after
//!   signing.
//! - `pe.signatures[].signed_within_validity` — the signing timestamp fell
//!   inside the certificate's validity window. False means backdating or a
//!   certificate issued after the fact.
//! - `pe.signature_integrity` — the worst state across the signatures present,
//!   nested ones included.
//!
//! Every judgement compares values inside the file, so it is stable forever.
//! Whether a certificate has since expired depends on the reader's clock, not
//! the file; `not_after_unix` on each signature answers it for a consumer
//! that knows the time.

use super::image_hash::ImageHashes;
use crate::formats::cms::{Signature, TimeSource, Verdict};

/// The integrity of a PE's signatures, ordered by severity so the summary is
/// the maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Integrity {
    /// The blob verifies and its image digest matches the file.
    Intact,
    /// The verdict cannot be reached: an algorithm we cannot check, or an
    /// image digest with nothing recomputed to compare it against.
    Unverifiable,
    /// The blob's own cryptography fails.
    Invalid,
    /// The image digest does not match the file: rewritten after signing.
    Tampered,
}

impl Integrity {
    /// The published `pe.signature_integrity` value.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Intact => "intact",
            Self::Unverifiable => "unverifiable",
            Self::Invalid => "invalid",
            Self::Tampered => "tampered",
        }
    }
}

/// Annotate every signature, nested ones included, with `digest_matches` and
/// `signed_within_validity`, and return the worst integrity among them;
/// `None` when there are no signatures.
///
/// Nested signatures are judged like the outer one. Each claims to cover the
/// same image, so a nested signature lifted from another file is tampering
/// even under an outer signature that matches.
pub(super) fn judge(signatures: &mut [Signature], hashes: &ImageHashes) -> Option<Integrity> {
    signatures.iter_mut().map(|sig| annotate(sig, hashes)).max()
}

fn annotate(sig: &mut Signature, hashes: &ImageHashes) -> Integrity {
    sig.signed_within_validity = signed_within_validity(sig);
    // The recomputed Authentihash is keyed by the algorithm the signature
    // committed to, so a signature over SHA-256 is compared against the
    // SHA-256 image hash and never against a digest of another width. An
    // unknown answer must not read as a failed one.
    sig.digest_matches = sig
        .signature_digest
        .as_deref()
        .zip(sig.signature_digest_algorithm.as_deref())
        .and_then(|(claimed, alg)| Some(claimed.eq_ignore_ascii_case(hashes.get(alg)?)));

    let state = match (sig.verified, sig.digest_matches) {
        // A digest mismatch is reported even when the blob itself verifies —
        // that combination *is* the post-signing tamper case.
        (_, Some(false)) => Integrity::Tampered,
        (Some(Verdict::Failed), _) => Integrity::Invalid,
        (Some(Verdict::Unsupported) | None, _) => Integrity::Unverifiable,
        // The signature names an image digest that could not be recomputed
        // (an algorithm not hashed, a layout the image hash refuses, or no
        // section table at all). A verified blob says nothing about this file
        // until that comparison is made, and a genuine blob grafted onto a
        // file whose sections run past its end would otherwise read as
        // intact.
        (_, None) if sig.signature_digest.is_some() => Integrity::Unverifiable,
        _ => Integrity::Intact,
    };
    sig.nested
        .iter_mut()
        .map(|nested| annotate(nested, hashes))
        .fold(state, Integrity::max)
}

/// Was the signing timestamp inside the certificate's validity window?
/// `None` when the signature carries no signing time — plenty do not, and
/// their absence is not evidence either way — and when the time came from a
/// timestamp that did not verify (`signing_time_source` `unverified_*`):
/// such a time is whatever the file says, so judging the window by it would
/// let the file choose the answer.
fn signed_within_validity(sig: &Signature) -> Option<bool> {
    if sig
        .signing_time_source
        .is_some_and(TimeSource::is_unverified)
    {
        return None;
    }
    let signed = sig.signing_time_unix?;
    Some(signed >= sig.not_before_unix? && signed <= sig.not_after_unix?)
}

#[cfg(test)]
mod tests;
