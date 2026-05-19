//! Shannon entropy and byte-histogram helpers.
//!
//! Used by metric extractors to characterise compressed/encrypted regions
//! and as a generic file-wide signal. Computed lazily and once — the
//! histogram pass is `O(n)` over the input, then entropy is `O(256)`.

/// Build a 256-entry byte-frequency histogram of `bytes`.
#[must_use]
pub(crate) fn histogram(bytes: &[u8]) -> [u64; 256] {
    let mut h = [0u64; 256];
    for &b in bytes {
        h[b as usize] += 1;
    }
    h
}

/// Shannon entropy in bits-per-byte (`[0.0, 8.0]`).
///
/// Returns `0.0` for empty input. The histogram pass is exposed
/// separately so callers that already computed a histogram for other
/// reasons can skip the work.
#[must_use]
pub(crate) fn shannon_from_histogram(histogram: &[u64; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let mut entropy = 0.0;
    for &count in histogram {
        if count == 0 {
            continue;
        }
        let p = count as f64 / n;
        entropy -= p * p.log2();
    }
    entropy
}

/// Convenience wrapper that builds the histogram and computes entropy in
/// one call. Use this when callers don't need the histogram for anything
/// else.
#[must_use]
pub(crate) fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let h = histogram(bytes);
    shannon_from_histogram(&h, bytes.len())
}

#[cfg(test)]
mod tests {
    use super::{histogram, shannon, shannon_from_histogram};

    #[test]
    fn empty_input_is_zero() {
        assert!(shannon(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn uniform_input_approaches_eight() {
        // 256 distinct bytes → entropy exactly 8.0.
        let bytes: Vec<u8> = (0..=255).collect();
        let e = shannon(&bytes);
        assert!((e - 8.0).abs() < 1e-9, "expected ~8.0, got {e}");
    }

    #[test]
    fn single_byte_repeated_is_zero() {
        let bytes = vec![0x42u8; 1024];
        let e = shannon(&bytes);
        assert!(e.abs() < 1e-9, "expected ~0.0, got {e}");
    }

    #[test]
    fn two_distinct_bytes_is_one() {
        // 50/50 split between two byte values → entropy = 1.0 bit/byte.
        let mut bytes = vec![0u8; 500];
        bytes.extend(vec![1u8; 500]);
        let e = shannon(&bytes);
        assert!((e - 1.0).abs() < 1e-9, "expected ~1.0, got {e}");
    }

    #[test]
    fn histogram_counts_correctly() {
        let bytes = b"aabbcc";
        let h = histogram(bytes);
        assert_eq!(h[b'a' as usize], 2);
        assert_eq!(h[b'b' as usize], 2);
        assert_eq!(h[b'c' as usize], 2);
        assert_eq!(h[0], 0);
    }

    #[test]
    fn precomputed_histogram_matches_shannon() {
        let bytes = b"hello world";
        let h = histogram(bytes);
        let from_hist = shannon_from_histogram(&h, bytes.len());
        let direct = shannon(bytes);
        assert!((from_hist - direct).abs() < 1e-12);
    }
}
