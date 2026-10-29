use super::*;

fn run(bytes: &[u8]) -> Metrics {
    let mut m = Metrics::new();
    extract(bytes, &mut m);
    m
}

/// Empty input still records `file.size = 0` and a zero
/// entropy. The "always-succeeds" contract is what downstream
/// consumers rely on for the universal `file.*` metrics.
#[test]
fn empty_input_records_zero_size_and_entropy() {
    let m = run(&[]);
    assert_eq!(m.get("file.size"), Some(0.0));
    assert_eq!(m.get("file.entropy"), Some(0.0));
}

/// A single byte is uniformly-distributed by definition — Shannon
/// entropy over a single-byte alphabet is 0. The size metric is
/// the byte count, not 1.0.
#[test]
fn single_byte_input_has_zero_entropy() {
    let m = run(&[0x42]);
    assert_eq!(m.get("file.size"), Some(1.0));
    assert_eq!(m.get("file.entropy"), Some(0.0));
}

/// Two distinct bytes occurring once each → maximum 1-bit entropy.
/// Pins the unit convention (bits, not nats) and the math.
#[test]
fn two_balanced_bytes_have_one_bit_entropy() {
    let m = run(&[0x00, 0xff]);
    assert_eq!(m.get("file.size"), Some(2.0));
    let h = m.get("file.entropy").unwrap();
    assert!((h - 1.0).abs() < 1e-9, "expected ~1 bit, got {h}",);
}

/// `file.entropy` is emitted universally (not just by png/jpeg),
/// so entropy rules apply to every file type. It is the one whole-file
/// entropy: the retired `binary.overall_entropy` twin stays retired.
#[test]
fn file_entropy_is_universal_and_has_no_twin() {
    let bytes = b"#!/bin/sh\necho hello\n";
    let m = run(bytes);
    assert_eq!(
        m.get("file.entropy"),
        Some(entropy::windowed(bytes).overall)
    );
    assert!(m.get("binary.overall_entropy").is_none());
}

/// Uniform random over the full byte alphabet → entropy ≈ 8.0
/// (the theoretical maximum for an 8-bit alphabet). We construct
/// a perfectly uniform distribution (each byte once) so the math
/// is exact, not approximate.
#[test]
fn uniform_byte_distribution_approaches_eight_bits() {
    let bytes: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    let m = run(&bytes);
    assert_eq!(m.get("file.size"), Some(256.0));
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

/// An XOR-encoded PE opened through the full pipeline is typed Data and
/// carries the key; a plaintext PE and random bytes carry nothing.
#[test]
fn xor_encoded_pe_emits_key_facts() {
    let pe = include_bytes!("../../../tests/fixtures/test.exe");
    let key = [0x0f, 0x1e, 0x2d, 0x3c];
    let enc: Vec<u8> = pe
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect();
    for name in ["hvnc.enc", "payload.bin"] {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new(name))
            .open(&enc);
        assert_eq!(parsed.fileid().file_type(), crate::FileType::Data);
        assert_eq!(parsed.metrics().get("xor.has_embedded_pe"), Some(1.0));
        assert_eq!(parsed.metrics().get("xor.pe_key_length"), Some(4.0));
        assert_eq!(
            parsed.values().get("xor.pe_key"),
            Some(&serde_json::json!("0f1e2d3c"))
        );
    }

    let plain = crate::OpenOptions::new()
        .path(std::path::Path::new("a.exe"))
        .open(pe);
    assert_eq!(plain.metrics().get("xor.pe_key_length"), None);
    let noise: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let blob = crate::OpenOptions::new()
        .path(std::path::Path::new("blob.bin"))
        .open(&noise);
    assert_eq!(blob.metrics().get("xor.pe_key_length"), None);
    assert!(blob.values().get("xor.pe_key").is_none());
}
