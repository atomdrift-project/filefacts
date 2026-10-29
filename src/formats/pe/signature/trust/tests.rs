use super::super::image_hash::{HashAlg, ImageHashes};
use super::*;
use serde_json::{Value as JsonValue, json};

const HASH: &str = "1b3049f7372192e1f05497e9fb3a441c84d1aaa11d29c755975cb4fc197f7446";

/// Judge `signatures` (as published JSON) against the recomputed
/// `hashes`, returning the annotated signatures and the summary.
fn run(hashes: &[(HashAlg, &str)], signatures: JsonValue) -> (JsonValue, Option<Integrity>) {
    let hashes = ImageHashes(
        hashes
            .iter()
            .map(|&(alg, digest)| (alg, digest.to_string()))
            .collect(),
    );
    let mut sigs: Vec<Signature> = serde_json::from_value(signatures).unwrap();
    let integrity = judge(&mut sigs, &hashes);
    (serde_json::to_value(&sigs).unwrap(), integrity)
}

/// The case the whole module exists for: the PKCS#7 blob still verifies
/// because the attacker never touched it, but the image it commits to has
/// been rewritten. `verified` alone cannot tell this from a genuine file.
#[test]
fn rewritten_image_is_tampered_even_though_blob_verifies() {
    let (sigs, integrity) = run(
        &[(HashAlg::Sha256, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": "0".repeat(64),
        }]),
    );
    assert_eq!(integrity, Some(Integrity::Tampered));
    assert_eq!(sigs[0]["digest_matches"], false);
}

/// An honestly signed file whose certificate has since expired is intact
/// here; ageing is the consumer's question, answered against not_after_unix.
#[test]
fn aged_signature_stays_intact_and_reports_its_validity_window() {
    let (sigs, integrity) = run(
        &[(HashAlg::Sha256, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
            "signing_time_unix": 1_500_000_000,
            "not_before_unix": 1_400_000_000,
            "not_after_unix": 1_600_000_000,
        }]),
    );
    assert_eq!(integrity, Some(Integrity::Intact));
    assert_eq!(sigs[0]["signed_within_validity"], true);
}

/// Signed outside the certificate's window — backdating or a cert minted
/// after the fact. The digest still matches, so this is not tampering, but
/// it is not an honest age either.
#[test]
fn signing_time_outside_window_is_reported() {
    let (sigs, integrity) = run(
        &[(HashAlg::Sha256, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
            "signing_time_unix": 1_300_000_000,
            "not_before_unix": 1_400_000_000,
            "not_after_unix": 1_600_000_000,
        }]),
    );
    assert_eq!(sigs[0]["signed_within_validity"], false);
    // Still intact: a bad timestamp is not a modified image.
    assert_eq!(integrity, Some(Integrity::Intact));
}

#[test]
fn failed_crypto_verification_is_invalid() {
    let (_, integrity) = run(
        &[(HashAlg::Sha256, HASH)],
        json!([{
            "verified": false,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
        }]),
    );
    assert_eq!(integrity, Some(Integrity::Invalid));
}

/// An algorithm we could not verify must not masquerade as either a pass
/// or a failure.
#[test]
fn unsupported_verification_is_its_own_state() {
    let (_, integrity) = run(&[(HashAlg::Sha256, HASH)], json!([{"verified": null}]));
    assert_eq!(integrity, Some(Integrity::Unverifiable));
}

/// A missing digest on either side is unknown, not false — absence of
/// evidence must not read as a tampered file.
#[test]
fn absent_digest_is_unknown_not_failure() {
    let (sigs, integrity) = run(&[], json!([{"verified": true}]));
    assert!(sigs[0].get("digest_matches").is_none());
    assert_eq!(integrity, Some(Integrity::Intact));
}

/// A timestamp whose signature or imprint did not verify supplies a time
/// the file chose; it must not decide whether the signature was made
/// inside the certificate's window.
#[test]
fn unverified_timestamp_does_not_judge_the_validity_window() {
    let (sigs, _) = run(
        &[(HashAlg::Sha256, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
            "signing_time_unix": 1_300_000_000,
            "signing_time_source": "unverified_rfc3161",
            "not_before_unix": 1_400_000_000,
            "not_after_unix": 1_600_000_000,
        }]),
    );
    assert!(sigs[0].get("signed_within_validity").is_none());
}

/// Dual-signed images are routine; the summary takes the worst state.
#[test]
fn summary_takes_the_worst_of_several_signatures() {
    let (_, integrity) = run(
        &[(HashAlg::Sha1, "aa"), (HashAlg::Sha256, HASH)],
        json!([
            {"verified": true, "signature_digest_algorithm": "sha256", "signature_digest": HASH},
            {"verified": true, "signature_digest_algorithm": "sha1", "signature_digest": "bb"},
        ]),
    );
    assert_eq!(integrity, Some(Integrity::Tampered));
}

/// Comparison is per-algorithm: a SHA-256 signature is never checked
/// against a SHA-1 Authentihash.
#[test]
fn digest_compared_against_matching_algorithm_only() {
    let (sigs, _) = run(
        &[(HashAlg::Sha1, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
        }]),
    );
    assert!(sigs[0].get("digest_matches").is_none());
}

/// Expiry never turns a sound signature into a finding: the judgement reads
/// nothing but the file.
#[test]
fn expiry_does_not_affect_integrity() {
    let (_, integrity) = run(
        &[(HashAlg::Sha256, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
            "not_after_unix": 0,
        }]),
    );
    assert_eq!(integrity, Some(Integrity::Intact));
}

/// A verified blob whose claimed image digest has nothing to be compared
/// against — the image hash was refused, as for a genuine signature
/// grafted onto a file with a section running past its end — is not
/// intact.
#[test]
fn claimed_digest_without_a_recomputed_hash_is_unverifiable() {
    let (sigs, integrity) = run(
        &[],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
        }]),
    );
    assert!(sigs[0].get("digest_matches").is_none());
    assert_eq!(integrity, Some(Integrity::Unverifiable));
}

/// A nested signature claims the same image as the outer one; one lifted
/// from another file is tampering even when the outer signature matches.
#[test]
fn nested_signatures_are_judged_too() {
    let (sigs, integrity) = run(
        &[(HashAlg::Sha1, "aa"), (HashAlg::Sha256, HASH)],
        json!([{
            "verified": true,
            "signature_digest_algorithm": "sha256",
            "signature_digest": HASH,
            "nested": [{
                "verified": true,
                "signature_digest_algorithm": "sha1",
                "signature_digest": "bb",
            }],
        }]),
    );
    assert_eq!(sigs[0]["nested"][0]["digest_matches"], false);
    assert_eq!(integrity, Some(Integrity::Tampered));
}

/// No signatures, no summary.
#[test]
fn no_signatures_yield_no_integrity() {
    let (_, integrity) = run(&[(HashAlg::Sha256, HASH)], json!([]));
    assert_eq!(integrity, None);
}

/// A genuine SignerInfo grafted around a forged Authentihash must not read
/// as intact even when the forged digest matches the file: the binding
/// check fails the blob, and the summary reports it invalid.
#[test]
fn grafted_signature_is_not_intact() {
    const DIGICERT_TENCENT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode-digicert-tencent.p7b"
    ));
    let blob = crate::formats::cms::der_element(DIGICERT_TENCENT).unwrap();
    let parse = |blob: &[u8]| -> Signature {
        serde_json::from_value(crate::formats::cms::parse_cms_blob(blob).unwrap()).unwrap()
    };
    let genuine = parse(blob);
    let claimed = genuine.signature_digest.clone().unwrap();
    let claimed: Vec<u8> = (0..claimed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&claimed[i..i + 2], 16).unwrap())
        .collect();
    // Flip the last byte of the claimed digest inside the signed content.
    let at = blob
        .windows(claimed.len())
        .position(|w| w == claimed.as_slice())
        .unwrap();
    let mut forged_blob = blob.to_vec();
    forged_blob[at + claimed.len() - 1] ^= 0x01;
    let forged = parse(&forged_blob);
    let forged_digest = forged.signature_digest.clone().unwrap();

    let hashes = ImageHashes(vec![(HashAlg::Sha256, forged_digest)]);
    let mut sigs = vec![forged];
    assert_eq!(judge(&mut sigs, &hashes), Some(Integrity::Invalid));
    assert_eq!(sigs[0].digest_matches, Some(true));
}
