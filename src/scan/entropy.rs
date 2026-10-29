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
        if let Some(count) = h.get_mut(usize::from(b)) {
            *count += 1;
        }
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
/// (each byte counted once into its window's histogram, which is then folded
/// into the whole-file one), then `O(windows)` to locate and bound the peak
/// region. The transient
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
        let hist = histogram(window);
        // Fold each window into the whole-file histogram once, 256 adds per
        // window, rather than counting every byte into both.
        for (total, local) in global.iter_mut().zip(hist) {
            *total += local;
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
mod tests;
