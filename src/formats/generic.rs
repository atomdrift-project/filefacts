//! Format-agnostic extractor.
//!
//! Records facts that hold for any blob of bytes: total size and
//! Shannon entropy. Runs before every format-specific extractor so the
//! metric exists even for unrecognised inputs.

use crate::output::{Metrics, Span, Strings, Values};
use crate::scan::entropy;

/// Run the generic byte-level pass. Always succeeds.
pub(super) fn extract(
    bytes: &[u8],
    _values: &mut Values,
    _strings: &mut Strings,
    metrics: &mut Metrics,
) {
    // One windowed pass yields both the whole-file entropy and the
    // concealed-region signals below, so the file is read only once.
    let scan = entropy::windowed(bytes);
    metrics.insert("file.size_bytes", bytes.len() as f64);
    // Whole-file Shannon entropy.
    // unqualified default; specializations qualify (`binary.code_entropy`,
    // `binary.data_entropy`, `sections.entropy_*`). Historically this was
    // `binary.overall_entropy` (+ a `file.entropy` twin, dropped first);
    // renamed 2026-08-22 with rules/model vocab migrated in lockstep.
    metrics.insert("file.entropy", scan.overall);

    // Peak concentrated region. Whole-file and section entropy both average a
    // small encrypted stage into its surroundings; this surfaces and locates
    // the single most concentrated region for any file type. Pure measurement
    // — the detection policy ("how high, how big, against what baseline") lives
    // in the rules. The canonical tell is `peak_region_entropy` high while
    // `overall_entropy` stays low (a blob concealed in low-entropy padding, or
    // a base64 region inside readable source). The high-entropy runs travel
    // with `peak_region_entropy` as its spans, so a finding can point an
    // analyst straight at the bytes — no offset scalar to join against.
    if scan.peak_bytes > 0 {
        let spans = scan.spans.iter().map(|&(offset, len)| Span { offset, len });
        metrics.insert_located("binary.peak_region_entropy", scan.peak_entropy, spans);
        metrics.insert("binary.peak_region_bytes", scan.peak_bytes as f64);
    }
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

    /// `file.entropy` is emitted universally (not just by png/jpeg),
    /// so entropy rules apply to every file type.
    #[test]
    fn binary_overall_entropy_mirrors_file_entropy() {
        let m = run(&[0x00, 0xff]);
        assert_eq!(m.get("file.entropy"), m.get("file.entropy"));
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

    /// A low-entropy file still reports a peak region (the metric is pure
    /// measurement), but `peak_region_entropy` is ~0 so no detection rule
    /// keying on a high peak can fire.
    #[test]
    fn low_entropy_file_reports_low_peak() {
        let m = run(&vec![0u8; 8192]);
        assert!(m.get("binary.peak_region_entropy").unwrap() < 1.0);
    }

    /// The headline case: a cipher blob buried in zero padding stays
    /// low-entropy whole-file, yet the peak-region metrics surface and
    /// locate it — `peak_region_entropy` high while `overall_entropy` is low.
    #[test]
    fn concealed_blob_surfaces_peak_region_but_not_overall() {
        let mut bytes = vec![0u8; 4096];
        bytes.extend((0..4096).map(|i| (i % 256) as u8)); // uniform → 8.0
        bytes.extend(vec![0u8; 4096]);
        let m = run(&bytes);
        assert!(m.get("file.entropy").unwrap() < 5.0);
        assert!(m.get("binary.peak_region_entropy").unwrap() >= 7.5);
        assert_eq!(m.get("binary.peak_region_bytes"), Some(4096.0));
        // The blob's location travels with the fact, not as a separate metric.
        assert_eq!(
            m.fact("binary.peak_region_entropy").unwrap().spans,
            vec![Span::new(4096, 4096)]
        );
    }

    /// Same mechanism on script-shaped input: a base64 region (~6.0) inside
    /// readable text (~4.32) is located even though it never reaches 7.5.
    #[test]
    fn concealed_base64_region_in_script_text_is_located() {
        let mut bytes: Vec<u8> = (0..4096).map(|i| (i % 20) as u8).collect(); // text
        bytes.extend((0..2048).map(|i| (i % 64) as u8)); // base64 blob
        bytes.extend((0..4096).map(|i| (i % 20) as u8)); // more text
        let m = run(&bytes);
        let peak = m.get("binary.peak_region_entropy").unwrap();
        assert!((peak - 6.0).abs() < 0.1, "peak = {peak}");
        assert_eq!(m.get("binary.peak_region_bytes"), Some(2048.0));
        assert_eq!(
            m.fact("binary.peak_region_entropy").unwrap().spans,
            vec![Span::new(4096, 2048)]
        );
    }
}
