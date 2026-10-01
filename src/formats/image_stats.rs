//! Pixel-statistic helpers shared by the JPEG and PNG extractors.
//!
//! Steganography-relevant facts derived from decoded pixel buffers:
//! per-channel Shannon entropy, histogram flatness, and simple
//! gradient-based edge density. Kept in one place because both image
//! formats want the same numerical surface — only the decode front
//! end differs.

/// Shannon entropy in bits-per-byte for a 256-bin byte histogram.
/// Returns `0.0` for an empty population.
#[must_use]
pub(super) fn entropy_from_histogram(freq: &[u32; 256], total: u32) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f32;
    freq.iter().filter(|&&c| c > 0).fold(0.0f32, |e, &c| {
        let p = c as f32 / total;
        e - p * p.log2()
    })
}

/// Per-channel Shannon entropy of an interleaved RGB(A) pixel buffer.
/// Returns `(r, g, b, a)`; `a` is `0.0` when fewer than four channels
/// are present. Returns all zeros when `channels < 3`.
#[must_use]
pub(super) fn channel_entropy(pixels: &[u8], channels: usize) -> (f32, f32, f32, f32) {
    if channels < 3 {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let mut hr = [0u32; 256];
    let mut hg = [0u32; 256];
    let mut hb = [0u32; 256];
    let mut ha = [0u32; 256];
    let mut rgb_count: u32 = 0;
    let mut a_count: u32 = 0;
    for pixel in pixels.chunks_exact(channels) {
        // `channels >= 3`, so every pixel has red, green and blue.
        let [r, g, b, rest @ ..] = pixel else {
            continue;
        };
        tally(&mut hr, *r);
        tally(&mut hg, *g);
        tally(&mut hb, *b);
        rgb_count += 1;
        if let Some(&a) = rest.first() {
            tally(&mut ha, a);
            a_count += 1;
        }
    }
    let r = entropy_from_histogram(&hr, rgb_count);
    let g = entropy_from_histogram(&hg, rgb_count);
    let b = entropy_from_histogram(&hb, rgb_count);
    let a = if a_count > 0 {
        entropy_from_histogram(&ha, a_count)
    } else {
        0.0
    };
    (r, g, b, a)
}

/// Count one occurrence of `value` in a byte histogram. A `u8` always lands
/// inside the 256 bins.
fn tally(histogram: &mut [u32; 256], value: u8) {
    if let Some(bin) = histogram.get_mut(usize::from(value)) {
        *bin += 1;
    }
}

/// Fraction of adjacent-pixel pairs (horizontal + vertical) whose
/// first-channel value differs by more than the edge threshold. Real
/// imagery shows structured edges; random/encrypted payloads stuffed
/// into image bytes have very low edge density.
#[must_use]
pub(super) fn edge_density(pixels: &[u8], width: usize, height: usize, channels: usize) -> f32 {
    const EDGE_THRESHOLD: i32 = 30;
    if width < 2 || height < 2 || pixels.is_empty() || channels == 0 {
        return 0.0;
    }
    let row_stride = width.saturating_mul(channels);
    // First-channel value of the pixel at (`x`, `y`), when the whole pixel is
    // in the buffer. Dimensions come from the file, so the offset saturates
    // rather than wrapping; a saturated offset is simply out of the buffer.
    let first_channel = |x: usize, y: usize| {
        let at = y
            .saturating_mul(row_stride)
            .saturating_add(x.saturating_mul(channels));
        pixels
            .get(at..at.saturating_add(channels))
            .and_then(<[u8]>::first)
            .map(|&v| i32::from(v))
    };
    let mut edge_count = 0u64;
    let mut total_pairs = 0u64;
    // A pair counts when its second pixel is in the buffer; the first one
    // precedes it, so it is too.
    let mut tally_pair = |a: Option<i32>, b: Option<i32>| {
        if let (Some(a), Some(b)) = (a, b) {
            if (a - b).abs() > EDGE_THRESHOLD {
                edge_count += 1;
            }
            total_pairs += 1;
        }
    };

    for y in 0..height {
        for x in 0..(width - 1) {
            tally_pair(first_channel(x, y), first_channel(x + 1, y));
        }
    }
    for y in 0..(height - 1) {
        for x in 0..width {
            tally_pair(first_channel(x, y), first_channel(x, y + 1));
        }
    }
    if total_pairs == 0 {
        return 0.0;
    }
    edge_count as f32 / total_pairs as f32
}

/// Cap (in bytes) on decoded pixel buffer size before we skip the
/// entropy pass. A pathological 16K × 16K RGBA image would otherwise
/// allocate ~1 GiB per worker just so we can compute Shannon entropy
/// on the result — structural metadata is preserved without the
/// decode, so the trade-off is favorable.
pub(super) const MAX_DECODE_BYTES: usize = 32 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_from_histogram_zero_total_is_zero() {
        let h = [0u32; 256];
        assert_eq!(entropy_from_histogram(&h, 0), 0.0);
    }

    #[test]
    fn channel_entropy_uniform_rgb() {
        // 256 unique RGB triples — each channel sees every value once,
        // so per-channel entropy is exactly 8.0 bits.
        let mut pixels = Vec::with_capacity(256 * 3);
        for i in 0..=255u8 {
            pixels.extend_from_slice(&[i, i, i]);
        }
        let (r, g, b, a) = channel_entropy(&pixels, 3);
        assert!((r - 8.0).abs() < 1e-5);
        assert!((g - 8.0).abs() < 1e-5);
        assert!((b - 8.0).abs() < 1e-5);
        assert_eq!(a, 0.0);
    }

    #[test]
    fn edge_density_constant_image_is_zero() {
        let pixels = vec![128u8; 100 * 100 * 3];
        let d = edge_density(&pixels, 100, 100, 3);
        assert!(
            d < 0.01,
            "constant image should have near-zero edge density, got {d}"
        );
    }

    #[test]
    fn edge_density_small_image_is_zero() {
        let pixels = vec![0u8; 4];
        assert_eq!(edge_density(&pixels, 1, 1, 1), 0.0);
    }
}
