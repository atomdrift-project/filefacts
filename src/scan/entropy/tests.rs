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

/// The folded whole-file histogram is exact, so `overall` is bit-for-bit
/// a direct `shannon` pass, and each window matches its own direct pass,
/// on pseudo-random data whose length is not a window multiple.
#[test]
fn windowed_matches_a_naive_reference_on_random_data() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let bytes: Vec<u8> = (0..10 * WINDOW_BYTES + 333)
        .map(|i| {
            // xorshift64*, with low-entropy stretches mixed in.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let r = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
            if (i / WINDOW_BYTES) % 3 == 1 {
                r & 0x0F
            } else {
                r
            }
        })
        .collect();
    let w = windowed(&bytes);
    assert_eq!(w.overall.to_bits(), shannon(&bytes).to_bits());
    let peak = bytes
        .chunks(WINDOW_BYTES)
        .map(shannon)
        .fold(0.0f64, f64::max);
    assert_eq!(w.peak_entropy.to_bits(), peak.to_bits());
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
