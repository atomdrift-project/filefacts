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
