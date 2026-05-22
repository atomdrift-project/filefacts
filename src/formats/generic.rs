//! Format-agnostic extractor.
//!
//! Records facts that hold for any blob of bytes: total size and
//! Shannon entropy. Runs before every format-specific extractor so the
//! metric exists even for unrecognised inputs.

use crate::output::{Metrics, Strings, Values};
use crate::scan::entropy;

/// Run the generic byte-level pass. Always succeeds.
pub(super) fn extract(
    bytes: &[u8],
    _values: &mut Values,
    _strings: &mut Strings,
    metrics: &mut Metrics,
) {
    metrics.insert("file.size_bytes", bytes.len() as f64);
    metrics.insert("file.entropy", entropy::shannon(bytes));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> Metrics {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m);
        m
    }

    /// Empty input still records `file.size_bytes = 0` and a zero
    /// entropy. The "always-succeeds" contract is what downstream
    /// consumers rely on for the universal `file.*` metrics.
    #[test]
    fn empty_input_records_zero_size_and_entropy() {
        let m = run(&[]);
        assert_eq!(m.get("file.size_bytes"), Some(0.0));
        assert_eq!(m.get("file.entropy"), Some(0.0));
    }

    /// A single byte is uniformly-distributed by definition — Shannon
    /// entropy over a single-byte alphabet is 0. The size metric is
    /// the byte count, not 1.0.
    #[test]
    fn single_byte_input_has_zero_entropy() {
        let m = run(&[0x42]);
        assert_eq!(m.get("file.size_bytes"), Some(1.0));
        assert_eq!(m.get("file.entropy"), Some(0.0));
    }

    /// Two distinct bytes occurring once each → maximum 1-bit entropy.
    /// Pins the unit convention (bits, not nats) and the math.
    #[test]
    fn two_balanced_bytes_have_one_bit_entropy() {
        let m = run(&[0x00, 0xff]);
        assert_eq!(m.get("file.size_bytes"), Some(2.0));
        let h = m.get("file.entropy").unwrap();
        assert!((h - 1.0).abs() < 1e-9, "expected ~1 bit, got {h}",);
    }

    /// Uniform random over the full byte alphabet → entropy ≈ 8.0
    /// (the theoretical maximum for an 8-bit alphabet). We construct
    /// a perfectly uniform distribution (each byte once) so the math
    /// is exact, not approximate.
    #[test]
    fn uniform_byte_distribution_approaches_eight_bits() {
        let bytes: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
        let m = run(&bytes);
        assert_eq!(m.get("file.size_bytes"), Some(256.0));
        let h = m.get("file.entropy").unwrap();
        assert!(
            (h - 8.0).abs() < 1e-9,
            "expected exactly 8 bits for uniform 256-byte alphabet, got {h}",
        );
    }

    /// `extract` is the very first pass in filefacts' pipeline — any
    /// panic here would abort the whole extraction. Adversarial
    /// inputs (extreme sizes, weird byte patterns) must be handled
    /// without crashing.
    #[test]
    fn extract_never_panics_on_pathological_inputs() {
        // All zeros: low entropy.
        let m = run(&vec![0u8; 4096]);
        assert_eq!(m.get("file.entropy"), Some(0.0));
        // All 0xff: also zero entropy (single-symbol alphabet).
        let m = run(&vec![0xffu8; 4096]);
        assert_eq!(m.get("file.entropy"), Some(0.0));
    }
}
