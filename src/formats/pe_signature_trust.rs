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
//! one of the strongest tamper signals a PE can carry.
//!
//! Both halves of the comparison already exist — `pe_authenticode` records the
//! digest the signature commits to, and `pe_image_hash` recomputes the
//! Authentihash over the file — but nothing brought them together. This does,
//! and emits:
//!
//! - `pe.signatures[].digest_matches` — the signature's claimed image digest
//!   equals the recomputed Authentihash. False means the bytes changed after
//!   signing.
//! - `pe.signatures[].signed_within_validity` — the signing timestamp fell
//!   inside the certificate's validity window. False means backdating or a
//!   certificate issued after the fact.
//! - `pe.signature_integrity` — the worst state across the signatures present.
//!
//! Expiry is handled separately and deliberately does **not** feed
//! `signature_integrity`. An expired certificate is the normal condition of old
//! software that was signed honestly, and the clock the comparison depends on
//! is not the file's — a skewed host, a restored VM or a CI box with a bad NTP
//! peer would otherwise turn correct binaries into findings. Everything above
//! compares values that live inside the file and is stable forever; expiry is
//! offered alongside as one opt-in metric:
//!
//! - `pe.signature_expired_days` — days between the certificate's `not_after`
//!   and now. Negative while the certificate is still current.
//!
//! A count rather than a flag, because that is what makes the skew tolerable: a
//! boolean flips on a one-second disagreement, whereas an author writing
//! `min: 30` is saying "expired by a margin no clock error explains". Authors
//! who want expiry ignored need do nothing, which is the default.
//!
//! It is the only clock-dependent fact this module emits, so a consumer caching
//! by content hash knows exactly which one field to recompute or drop.

use serde_json::{Map, Value as JsonValue};

use crate::Values;
use crate::output::Metrics;

/// Worst-case integrity across a PE's signatures, in descending severity.
const TAMPERED: &str = "tampered";
const INVALID: &str = "invalid";
const UNVERIFIABLE: &str = "unverifiable";
const INTACT: &str = "intact";

/// Rank for picking the worst state when a binary carries several signatures
/// (dual-signed SHA-1 + SHA-256 images are routine).
fn severity(state: &str) -> u8 {
    match state {
        TAMPERED => 3,
        INVALID => 2,
        UNVERIFIABLE => 1,
        _ => 0,
    }
}

/// Read back the signatures and image hashes both already emitted, annotate
/// each signature, and record the summary.
///
/// `now` is Unix seconds, supplied by the caller rather than read here so the
/// derivation stays a pure function — the same convention `registry::with_age`
/// uses for its wall-clock-relative fields.
pub(super) fn derive(values: &mut Values, metrics: &mut Metrics, now: i64) {
    let Some(JsonValue::Array(signatures)) = values.get("pe.signatures") else {
        return;
    };
    let signatures = signatures.clone();
    if signatures.is_empty() {
        return;
    }

    let mut worst = INTACT;
    let annotated: Vec<JsonValue> = signatures
        .into_iter()
        .map(|sig| {
            let JsonValue::Object(mut obj) = sig else {
                return sig;
            };
            let state = annotate(&mut obj, values);
            if severity(state) > severity(worst) {
                worst = state;
            }
            JsonValue::Object(obj)
        })
        .collect();

    values.insert("pe.signatures", JsonValue::Array(annotated.clone()));
    values.insert(
        "pe.signature_integrity",
        JsonValue::String(worst.to_string()),
    );
    if let Some(days) = expired_days(&annotated, now) {
        metrics.insert("pe.signature_expired_days", days);
    }
}

/// Days past `not_after`, negative while the certificate is still current.
///
/// A dual-signed image is judged by its longest-lived certificate: the file is
/// only really expired once every signature on it has lapsed.
fn expired_days(signatures: &[JsonValue], now: i64) -> Option<f64> {
    let latest = signatures
        .iter()
        .filter_map(|s| s.get("not_after_unix")?.as_i64())
        .max()?;
    Some((now - latest) as f64 / 86_400.0)
}

/// Annotate one signature object in place; returns its integrity state.
fn annotate(obj: &mut Map<String, JsonValue>, values: &Values) -> &'static str {
    if let Some(within) = signed_within_validity(obj) {
        obj.insert("signed_within_validity".into(), JsonValue::Bool(within));
    }

    // The recomputed Authentihash is keyed by the algorithm the signature
    // committed to, so a signature over SHA-256 is compared against
    // `pe.image_hash.sha256` and never against a digest of another width.
    let matches = digest_matches(obj, values);
    if let Some(m) = matches {
        obj.insert("digest_matches".into(), JsonValue::Bool(m));
    }

    match (obj.get("verified"), matches) {
        // A digest mismatch is reported even when the blob itself verifies —
        // that combination *is* the post-signing tamper case.
        (_, Some(false)) => TAMPERED,
        (Some(JsonValue::Bool(false)), _) => INVALID,
        (Some(JsonValue::Null) | None, _) => UNVERIFIABLE,
        _ => INTACT,
    }
}

/// Compare the signature's claimed image digest with the recomputed
/// Authentihash of the same algorithm. `None` when either side is absent —
/// an unknown answer must not read as a failed one.
fn digest_matches(obj: &Map<String, JsonValue>, values: &Values) -> Option<bool> {
    let claimed = obj.get("signature_digest")?.as_str()?;
    let alg = obj.get("signature_digest_algorithm")?.as_str()?;
    let recomputed = values.get(&format!("pe.image_hash.{alg}"))?.as_str()?;
    Some(claimed.eq_ignore_ascii_case(recomputed))
}

/// Was the signing timestamp inside the certificate's validity window?
/// `None` when the signature carries no signing time — plenty do not, and
/// their absence is not evidence either way.
fn signed_within_validity(obj: &Map<String, JsonValue>) -> Option<bool> {
    let signed = obj.get("signing_time_unix")?.as_i64()?;
    let not_before = obj.get("not_before_unix")?.as_i64()?;
    let not_after = obj.get("not_after_unix")?.as_i64()?;
    Some(signed >= not_before && signed <= not_after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn values_with(image_hash: JsonValue, signatures: JsonValue) -> Values {
        let mut v = Values::new();
        v.insert("pe.image_hash", image_hash);
        v.insert("pe.signatures", signatures);
        v
    }

    /// Fixed instant so the wall clock never enters a test.
    const NOW: i64 = 1_700_000_000;

    fn run(v: &mut Values) -> Metrics {
        let mut m = Metrics::new();
        derive(v, &mut m, NOW);
        m
    }

    const HASH: &str = "1b3049f7372192e1f05497e9fb3a441c84d1aaa11d29c755975cb4fc197f7446";

    /// The case the whole module exists for: the PKCS#7 blob still verifies
    /// because the attacker never touched it, but the image it commits to has
    /// been rewritten. `verified` alone cannot tell this from a genuine file.
    #[test]
    fn rewritten_image_is_tampered_even_though_blob_verifies() {
        let mut v = values_with(
            json!({"sha256": HASH}),
            json!([{
                "verified": true,
                "signature_digest_algorithm": "sha256",
                "signature_digest": "0".repeat(64),
            }]),
        );
        run(&mut v);
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(TAMPERED)
        );
        assert_eq!(
            v.get("pe.signatures[0].digest_matches").unwrap().as_bool(),
            Some(false)
        );
    }

    /// An honestly signed file whose certificate has since expired is intact
    /// here; ageing is the consumer's question, answered against not_after_unix.
    #[test]
    fn aged_signature_stays_intact_and_reports_its_validity_window() {
        let mut v = values_with(
            json!({"sha256": HASH}),
            json!([{
                "verified": true,
                "signature_digest_algorithm": "sha256",
                "signature_digest": HASH,
                "signing_time_unix": 1_500_000_000,
                "not_before_unix": 1_400_000_000,
                "not_after_unix": 1_600_000_000,
            }]),
        );
        run(&mut v);
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(INTACT)
        );
        assert_eq!(
            v.get("pe.signatures[0].signed_within_validity")
                .unwrap()
                .as_bool(),
            Some(true)
        );
    }

    /// Signed outside the certificate's window — backdating or a cert minted
    /// after the fact. The digest still matches, so this is not tampering, but
    /// it is not an honest age either.
    #[test]
    fn signing_time_outside_window_is_reported() {
        let mut v = values_with(
            json!({"sha256": HASH}),
            json!([{
                "verified": true,
                "signature_digest_algorithm": "sha256",
                "signature_digest": HASH,
                "signing_time_unix": 1_300_000_000,
                "not_before_unix": 1_400_000_000,
                "not_after_unix": 1_600_000_000,
            }]),
        );
        run(&mut v);
        assert_eq!(
            v.get("pe.signatures[0].signed_within_validity")
                .unwrap()
                .as_bool(),
            Some(false)
        );
        // Still intact: a bad timestamp is not a modified image.
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(INTACT)
        );
    }

    #[test]
    fn failed_crypto_verification_is_invalid() {
        let mut v = values_with(
            json!({"sha256": HASH}),
            json!([{
                "verified": false,
                "signature_digest_algorithm": "sha256",
                "signature_digest": HASH,
            }]),
        );
        run(&mut v);
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(INVALID)
        );
    }

    /// An algorithm we could not verify must not masquerade as either a pass
    /// or a failure.
    #[test]
    fn unsupported_verification_is_its_own_state() {
        let mut v = values_with(json!({"sha256": HASH}), json!([{"verified": null}]));
        run(&mut v);
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(UNVERIFIABLE)
        );
    }

    /// A missing digest on either side is unknown, not false — absence of
    /// evidence must not read as a tampered file.
    #[test]
    fn absent_digest_is_unknown_not_failure() {
        let mut v = values_with(json!({}), json!([{"verified": true}]));
        run(&mut v);
        assert!(v.get("pe.signatures[0].digest_matches").is_none());
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(INTACT)
        );
    }

    /// Dual-signed images are routine; the summary takes the worst state.
    #[test]
    fn summary_takes_the_worst_of_several_signatures() {
        let mut v = values_with(
            json!({"sha1": "aa", "sha256": HASH}),
            json!([
                {"verified": true, "signature_digest_algorithm": "sha256", "signature_digest": HASH},
                {"verified": true, "signature_digest_algorithm": "sha1", "signature_digest": "bb"},
            ]),
        );
        run(&mut v);
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(TAMPERED)
        );
    }

    /// Comparison is per-algorithm: a SHA-256 signature is never checked
    /// against a SHA-1 Authentihash.
    #[test]
    fn digest_compared_against_matching_algorithm_only() {
        let mut v = values_with(
            json!({"sha1": HASH}),
            json!([{
                "verified": true,
                "signature_digest_algorithm": "sha256",
                "signature_digest": HASH,
            }]),
        );
        run(&mut v);
        assert!(v.get("pe.signatures[0].digest_matches").is_none());
    }

    /// Expiry must never turn a sound signature into a finding — that is the
    /// default the metric exists to leave alone.
    #[test]
    fn expiry_does_not_affect_integrity() {
        let mut v = values_with(
            json!({"sha256": HASH}),
            json!([{
                "verified": true,
                "signature_digest_algorithm": "sha256",
                "signature_digest": HASH,
                "not_after_unix": NOW - 400 * 86_400,
            }]),
        );
        let m = run(&mut v);
        assert_eq!(
            v.get("pe.signature_integrity").unwrap().as_str(),
            Some(INTACT)
        );
        assert_eq!(m.get("pe.signature_expired_days").unwrap().round(), 400.0);
    }

    /// Negative while current, so an author thresholding on `min:` never
    /// matches a live certificate.
    #[test]
    fn current_certificate_reports_negative_days() {
        let mut v = values_with(
            json!({}),
            json!([{"verified": true, "not_after_unix": NOW + 30 * 86_400}]),
        );
        let m = run(&mut v);
        assert_eq!(m.get("pe.signature_expired_days").unwrap().round(), -30.0);
    }

    /// A dual-signed image is only expired once every signature has lapsed, so
    /// the longest-lived certificate decides.
    #[test]
    fn dual_signed_uses_longest_lived_certificate() {
        let mut v = values_with(
            json!({}),
            json!([
                {"verified": true, "not_after_unix": NOW - 500 * 86_400},
                {"verified": true, "not_after_unix": NOW + 10 * 86_400},
            ]),
        );
        let m = run(&mut v);
        assert_eq!(m.get("pe.signature_expired_days").unwrap().round(), -10.0);
    }

    /// No validity information means no metric, rather than a zero that would
    /// read as "expired today".
    #[test]
    fn absent_validity_emits_no_metric() {
        let mut v = values_with(json!({}), json!([{"verified": true}]));
        let m = run(&mut v);
        assert!(m.get("pe.signature_expired_days").is_none());
    }
}
