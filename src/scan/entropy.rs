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

/// Fixed analysis window for [`windowed`]. 1 KiB is the smallest size at
/// which an entropy reading still reflects real structure rather than a
/// short run of varied bytes: truly random 1 KiB measures ~7.8 bits/byte
/// (you see ~251 of 256 distinct values). It is also the smallest concealed
/// region we aim to localise. Applies to any byte stream — a script's
/// embedded blob is found the same way as a binary's.
pub(crate) const WINDOW_BYTES: usize = 1024;

/// Windows within this many bits/byte of the file's peak window belong to
/// the same region. This is a *structural* smoothing constant for bounding
/// a contiguous run — deliberately not a detection threshold (rules decide
/// how high `peak_entropy` must be to matter). Small enough that readable
/// text (~4.5) is never absorbed into an encoded region (~6.0) and machine
/// code (~6.2) never absorbs an adjacent cipher block (~8.0).
const PEAK_TOLERANCE: f64 = 0.5;

/// Cap on the number of run spans reported. The aggregate `peak_bytes` is
/// always the full mass; `spans` is a bounded sample of the largest runs for
/// localisation, so a pathologically fragmented file can't bloat the result.
const MAX_SPANS: usize = 64;

/// Per-file result of a single-pass windowed entropy scan.
///
/// Whole-file and section-level entropy both average a small encrypted
/// stage into its surroundings (a 52 KiB blob at 8.0 inside 76 MiB of zeros
/// reads as ~3.1), hiding it. Scanning fixed windows surfaces the single
/// most concentrated region — measurement only, no verdict — while a shared
/// accumulated histogram still yields the whole-file entropy. One pass over
/// the bytes, no re-reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct WindowedEntropy {
    /// Shannon entropy of the whole file, folded from the same pass.
    pub overall: f64,
    /// Entropy of the most concentrated (peak) window.
    pub peak_entropy: f64,
    /// Total bytes across all windows within [`PEAK_TOLERANCE`] of the peak
    /// — the amount of data at the file's peak entropy level. A *mass*, not a
    /// contiguous run: real ciphertext dips below a strict floor every few KiB,
    /// so requiring contiguity would undercount a single payload severalfold.
    pub peak_bytes: u64,
    /// File offset where the largest *contiguous* block of peak-level windows
    /// begins — the best single pointer at the concealed payload for triage.
    pub peak_offset: u64,
    /// The contiguous peak-level runs as `(offset, len)` byte spans, largest
    /// first, capped at [`MAX_SPANS`]. The provenance of the measurement —
    /// where the high-entropy data physically is.
    pub spans: Vec<(u64, u64)>,
}

/// Scan `bytes` in fixed [`WINDOW_BYTES`] windows, returning the whole-file
/// entropy alongside the peak concentrated region. Single `O(n)` byte pass
/// (each byte counted once into a per-window and a shared global histogram),
/// then `O(windows)` to locate and bound the peak region. The transient
/// per-window vector is the natural structure for the relative region
/// search and is dropped on return — it is never part of the result.
#[must_use]
pub(crate) fn windowed(bytes: &[u8]) -> WindowedEntropy {
    let mut out = WindowedEntropy::default();
    if bytes.is_empty() {
        return out;
    }
    let mut global = [0u64; 256];
    let mut windows: Vec<f64> = Vec::with_capacity(bytes.len() / WINDOW_BYTES + 1);
    for window in bytes.chunks(WINDOW_BYTES) {
        let mut hist = [0u64; 256];
        for &b in window {
            let bi = b as usize;
            hist[bi] += 1;
            global[bi] += 1;
        }
        windows.push(shannon_from_histogram(&hist, window.len()));
    }
    out.overall = shannon_from_histogram(&global, bytes.len());

    // Peak level is relative to the file's own peak window, so the same code
    // characterises an 8.0 cipher block in a binary and a 6.0 base64 blob in a
    // script. `peak_bytes` sums every window within tolerance of the peak (the
    // total payload mass, robust to ciphertext's per-window dips); `peak_offset`
    // points at the largest contiguous block of such windows.
    let peak_entropy = windows.iter().copied().fold(0.0f64, f64::max);
    out.peak_entropy = peak_entropy;
    let floor = peak_entropy - PEAK_TOLERANCE;

    // Collect the contiguous runs of peak-level windows as byte spans. Each
    // run's byte length is bounded by the file end so a short trailing window
    // contributes its actual size, not a padded window.
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut start: Option<usize> = None;
    let close = |s: usize, end_idx: usize, runs: &mut Vec<(u64, u64)>| {
        let off = (s * WINDOW_BYTES) as u64;
        let end = (end_idx * WINDOW_BYTES).min(bytes.len()) as u64;
        runs.push((off, end - off));
    };
    for (i, &e) in windows.iter().enumerate() {
        if e >= floor {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            close(s, i, &mut runs);
        }
    }
    if let Some(s) = start.take() {
        close(s, windows.len(), &mut runs);
    }

    out.peak_bytes = runs.iter().map(|&(_, len)| len).sum();
    // Largest run, ties broken toward the earliest offset.
    let mut best_len = 0u64;
    for &(off, len) in &runs {
        if len > best_len {
            best_len = len;
            out.peak_offset = off;
        }
    }
    // Report the largest runs first, bounded — the aggregate above is exact.
    runs.sort_by_key(|&(_, len)| std::cmp::Reverse(len));
    runs.truncate(MAX_SPANS);
    out.spans = runs;
    out
}

#[cfg(test)]
mod tests {
    use super::{WINDOW_BYTES, histogram, shannon, shannon_from_histogram, windowed};

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

    /// `len` bytes cycling over `symbols` distinct values in equal counts:
    /// a deterministic block of entropy `log2(symbols)`. `symbols = 256`
    /// gives ~8.0 (cipher/compressed), 64 gives 6.0 (base64), 20 gives
    /// ~4.32 (readable text/code).
    fn block(len: usize, symbols: usize) -> Vec<u8> {
        (0..len).map(|i| (i % symbols) as u8).collect()
    }

    #[test]
    fn windowed_empty_is_default() {
        assert_eq!(windowed(&[]), super::WindowedEntropy::default());
    }

    #[test]
    fn windowed_overall_matches_whole_file_shannon() {
        // The folded global histogram must equal a direct whole-file pass.
        let bytes = block(4096, 256);
        assert!((windowed(&bytes).overall - shannon(&bytes)).abs() < 1e-12);
    }

    #[test]
    fn windowed_flat_file_has_zero_peak_entropy() {
        // 8 KiB of one byte: no concentration anywhere. peak_entropy ~0 so
        // no detection rule fires, even though a peak region is still named.
        let w = windowed(&vec![0x41u8; 8 * WINDOW_BYTES]);
        assert!(w.peak_entropy.abs() < 1e-9, "peak = {}", w.peak_entropy);
        assert!(w.overall.abs() < 1e-9);
    }

    #[test]
    fn windowed_locates_blob_concealed_in_low_entropy_padding() {
        // 4 KiB zeros | 4 KiB cipher | 4 KiB zeros — the section-average
        // case that hides a stage. Whole-file entropy stays low, but the
        // scan pins the blob to its offset and size.
        let mut bytes = vec![0u8; 4 * WINDOW_BYTES];
        bytes.extend(block(4 * WINDOW_BYTES, 256));
        bytes.extend(vec![0u8; 4 * WINDOW_BYTES]);
        let w = windowed(&bytes);
        assert!(w.peak_entropy > 7.9, "peak = {}", w.peak_entropy);
        assert_eq!(w.peak_bytes, (4 * WINDOW_BYTES) as u64);
        assert_eq!(w.peak_offset, (4 * WINDOW_BYTES) as u64);
        // Concealment is real: the file as a whole is not high-entropy.
        assert!(w.overall < 5.0, "overall = {}", w.overall);
    }

    #[test]
    fn windowed_locates_base64_blob_in_script_text() {
        // Readable code (~4.32) | base64 blob (6.0). The relative region
        // finds the 6.0 peak even though it never reaches a binary's 7.5 —
        // the script case, same code path.
        let mut bytes = block(2 * WINDOW_BYTES, 20);
        bytes.extend(block(2 * WINDOW_BYTES, 64));
        let w = windowed(&bytes);
        assert!(
            (w.peak_entropy - 6.0).abs() < 0.05,
            "peak = {}",
            w.peak_entropy
        );
        assert_eq!(w.peak_offset, (2 * WINDOW_BYTES) as u64);
        assert_eq!(w.peak_bytes, (2 * WINDOW_BYTES) as u64);
    }

    #[test]
    fn windowed_region_stops_at_lower_entropy_neighbor() {
        // cipher (8.0) | base64 (6.0): the 6.0 window is outside tolerance
        // of the 8.0 peak, so the region is the single peak window only.
        let mut bytes = block(WINDOW_BYTES, 256);
        bytes.extend(block(WINDOW_BYTES, 64));
        let w = windowed(&bytes);
        assert!(w.peak_entropy > 7.9, "peak = {}", w.peak_entropy);
        assert_eq!(w.peak_offset, 0);
        assert_eq!(w.peak_bytes, WINDOW_BYTES as u64);
    }

    #[test]
    fn windowed_region_includes_within_tolerance_neighbors() {
        // 8.0 | ~7.64 | 6.0: the 7.64 window is within 0.5 of the peak and
        // joins the region; the 6.0 window does not.
        let mut bytes = block(WINDOW_BYTES, 256); // 8.0
        bytes.extend(block(WINDOW_BYTES, 200)); // log2(200) ~= 7.64
        bytes.extend(block(WINDOW_BYTES, 64)); // 6.0
        let w = windowed(&bytes);
        assert_eq!(w.peak_offset, 0);
        assert_eq!(w.peak_bytes, (2 * WINDOW_BYTES) as u64);
    }

    #[test]
    fn windowed_peak_bytes_counts_mass_across_dips() {
        // cipher | dip | cipher | dip | cipher — ciphertext fragmented by
        // sub-floor windows. peak_bytes is the *total* high-entropy mass
        // (3 windows), not the largest contiguous run (1 window); peak_offset
        // points at the first block.
        let mut bytes = Vec::new();
        for i in 0..5 {
            bytes.extend(block(WINDOW_BYTES, if i % 2 == 0 { 256 } else { 64 }));
        }
        let w = windowed(&bytes);
        assert!(w.peak_entropy > 7.9, "peak = {}", w.peak_entropy);
        assert_eq!(w.peak_bytes, (3 * WINDOW_BYTES) as u64);
        assert_eq!(w.peak_offset, 0);
        // Each cipher window is its own run; spans localise all three.
        assert_eq!(
            w.spans,
            vec![
                (0, WINDOW_BYTES as u64),
                (2 * WINDOW_BYTES as u64, WINDOW_BYTES as u64),
                (4 * WINDOW_BYTES as u64, WINDOW_BYTES as u64),
            ]
        );
    }

    #[test]
    fn windowed_spans_are_largest_first_and_capped() {
        // One big run then a one-window run: spans are ordered by size, and a
        // single contiguous block is reported as a single span.
        let mut bytes = block(3 * WINDOW_BYTES, 256); // 3-window run
        bytes.extend(vec![0u8; WINDOW_BYTES]); // gap
        bytes.extend(block(WINDOW_BYTES, 256)); // 1-window run
        let w = windowed(&bytes);
        assert_eq!(
            w.spans,
            vec![
                (0, 3 * WINDOW_BYTES as u64),
                (4 * WINDOW_BYTES as u64, WINDOW_BYTES as u64),
            ]
        );
        assert_eq!(w.peak_offset, 0);
        assert_eq!(w.peak_bytes, (4 * WINDOW_BYTES) as u64);
    }

    #[test]
    fn windowed_short_trailing_window_is_measured() {
        // A high-entropy tail shorter than a full window: the region length
        // is the actual byte coverage, not a padded window.
        let mut bytes = vec![0u8; WINDOW_BYTES];
        bytes.extend(block(512, 256));
        let w = windowed(&bytes);
        assert!(w.peak_entropy > 7.9, "peak = {}", w.peak_entropy);
        assert_eq!(w.peak_offset, WINDOW_BYTES as u64);
        assert_eq!(w.peak_bytes, 512);
    }
}
