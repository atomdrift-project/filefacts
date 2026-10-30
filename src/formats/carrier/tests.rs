use super::*;

fn run(coverage: &Coverage, bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    emit(bytes, coverage, &mut v, &mut m);
    (v, m)
}

fn stow(v: &Values) -> Vec<String> {
    v.get("media.stowaway")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn fake_pe(body: usize) -> Vec<u8> {
    let mut out = vec![0u8; 0x40];
    out[0] = b'M';
    out[1] = b'Z';
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out.extend_from_slice(b"PE\0\0");
    out.extend(std::iter::repeat_n(0x41u8, body));
    out
}

#[test]
fn fully_claimed_container_is_valid_and_quiet() {
    let bytes = vec![0u8; 512];
    let mut c = Coverage::new("test", 8);
    c.claim(8, 512);
    let (v, m) = run(&c, &bytes);
    assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));
    assert!(stow(&v).is_empty());
    assert_eq!(m.get("media.trailing_bytes"), Some(0.0));
    assert_eq!(m.get("media.gap_bytes"), Some(0.0));
    assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));
}

#[test]
fn appended_executable_is_named() {
    let mut bytes = vec![0u8; 256];
    bytes.extend_from_slice(&fake_pe(2048));
    let mut c = Coverage::new("test", 8);
    c.claim(8, 256);
    let (v, m) = run(&c, &bytes);
    assert_eq!(stow(&v), vec!["pe"]);
    assert!(m.get("media.trailing_bytes").unwrap() > 2000.0);
    assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(false));
}

#[test]
fn interior_hole_is_measured_and_classified() {
    let mut bytes = vec![0u8; 128];
    bytes.extend_from_slice(b"PK\x03\x04payload riding in the hole");
    bytes.resize(1024, 0);
    let mut c = Coverage::new("test", 8);
    c.claim(8, 128);
    c.claim(600, 1024);
    let (v, m) = run(&c, &bytes);
    assert!(stow(&v).contains(&"zip".to_string()));
    assert!(m.get("media.gap_bytes").unwrap() > 400.0);
}

/// A freeform region (an ID3 comment, a PNG `tEXt`) legitimately holds
/// text, so text there is not concealment and its size is not concealed
/// space — but an executable signature in it still is.
#[test]
fn freeform_region_allows_text_but_not_executables() {
    let mut bytes = vec![0u8; 64];
    bytes.extend_from_slice(b"Copyright 2026 Example. All rights reserved. Comment field.");
    bytes.resize(512, 0);
    let mut c = Coverage::new("test", 8);
    c.claim(8, 64);
    c.claim_freeform(64, 200);
    c.claim(200, 512);
    let (v, m) = run(&c, &bytes);
    assert!(stow(&v).is_empty());
    assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));

    let mut bytes = vec![0u8; 64];
    bytes.extend_from_slice(&fake_pe(64));
    bytes.resize(512, 0);
    let mut c = Coverage::new("test", 8);
    c.claim(8, 64);
    c.claim_freeform(64, 300);
    c.claim(300, 512);
    let (v, _) = run(&c, &bytes);
    assert_eq!(stow(&v), vec!["pe"]);
}

#[test]
fn unrecognized_container_reports_content_kind() {
    let mut blob = Vec::new();
    let mut x: u32 = 0x1234_5678;
    while blob.len() < 4096 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        blob.extend_from_slice(&x.to_le_bytes());
    }
    let (v, _) = run(&Coverage::unrecognized(), &blob);
    assert_eq!(
        v.get("media.content_kind").and_then(|x| x.as_str()),
        Some("high_entropy")
    );
    assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(false));
}

#[test]
fn mz_without_pe_signature_is_not_an_executable() {
    let mut bytes = vec![0u8; 64];
    let mut noise = vec![0u8; 2048];
    noise[100] = b'M';
    noise[101] = b'Z';
    bytes.extend_from_slice(&noise);
    let mut c = Coverage::new("test", 8);
    c.claim(8, 64);
    let (v, _) = run(&c, &bytes);
    assert!(!stow(&v).contains(&"pe".to_string()));
}

#[test]
fn declared_length_shorter_than_file_hides_the_remainder() {
    let mut bytes = vec![0u8; 256];
    bytes.extend_from_slice(&fake_pe(1024));
    let mut c = Coverage::new("test", 8);
    c.claim(8, 256);
    c.declared_len = Some(256);
    let (v, m) = run(&c, &bytes);
    assert_eq!(stow(&v), vec!["pe"]);
    assert!(m.get("media.trailing_bytes").unwrap() > 1000.0);
}

#[test]
fn alignment_padding_is_not_a_hole() {
    let bytes = vec![0u8; 512];
    let mut c = Coverage::new("test", 8);
    c.claim(8, 100);
    c.claim(102, 512); // two bytes of pad-to-even between regions
    let (_, m) = run(&c, &bytes);
    assert_eq!(m.get("media.gap_bytes"), Some(0.0));
}

fn compressed_gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::GzBuilder::new()
        .filename("payload.txt")
        .comment("carrier regression")
        .write(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn invalid_gzip_header_in_claimed_metadata_is_not_an_archive() {
    // Bytes observed inside the valid zTXt stream of ws-about-codecs.png.
    // 0x8e sets reserved gzip flags, so this is not a gzip header.
    let mut bytes = vec![0u8; 64];
    bytes.extend_from_slice(b"\x1f\x8b\x08\x8e\x9f\xd4\x9b\x17\x23\x39\x83\xa4");
    bytes.resize(512, 0);
    let mut coverage = Coverage::new("test", 8);
    coverage.claim(8, 64);
    coverage.claim_freeform(64, 512);
    let (values, metrics) = run(&coverage, &bytes);
    assert!(!stow(&values).contains(&"gzip".to_string()));
    assert_eq!(metrics.get("media.stowaway_bytes"), Some(0.0));
}

#[test]
fn gzip_stowaway_survives_padding_optional_headers_and_bad_magic() {
    let gzip = compressed_gzip(b"printf 'carrier regression\\n'; id; uname -s\n");
    let mut region = b"padding\x1f\x8b\x08\x8e invalid candidate; ".to_vec();
    region.extend_from_slice(&gzip);
    assert_eq!(classify_region(&region), Some("gzip"));
    let mut bytes = vec![0u8; 64];
    bytes.extend_from_slice(&region);
    let mut coverage = Coverage::new("test", 8);
    coverage.claim_freeform(8, bytes.len() as u64);
    assert!(stow(&run(&coverage, &bytes).0).contains(&"gzip".to_string()));
}

#[test]
fn gzip_magic_requires_a_valid_stream_and_small_member_checksum() {
    assert_ne!(classify_region(b"prefix\x1f\x8b\x08"), Some("gzip"));
    let mut gzip = compressed_gzip(b"ordinary compressed data");
    assert_eq!(classify_region(&gzip), Some("gzip"));
    let checksum = gzip.len() - 8;
    *gzip.get_mut(checksum).unwrap() ^= 1;
    assert_ne!(classify_region(&gzip), Some("gzip"));
}

#[test]
fn large_gzip_is_probed_with_bounded_output() {
    let gzip = compressed_gzip(&vec![b'A'; 1024 * 1024]);
    assert_eq!(classify_region(&gzip), Some("gzip"));
}

#[test]
fn cab_ascii_inside_diagram_metadata_is_not_an_archive() {
    let region = b"diagram=MSCF%2BsrsQL1eNarNwQrSK3R%2B7j3Vch%2BMhE";
    assert!(!find_cab(region));
    assert_ne!(classify_region(region), Some("cab"));
}

#[test]
fn cabinet_candidate_requires_bounded_header_and_searches_past_false_magic() {
    let mut cab = vec![0u8; 36];
    cab[..4].copy_from_slice(b"MSCF");
    cab[8..12].copy_from_slice(&36u32.to_le_bytes());
    cab[16..20].copy_from_slice(&36u32.to_le_bytes());
    cab[24..26].copy_from_slice(&[3, 1]);
    assert_eq!(classify_region(&cab), Some("cab"));
    let mut padded = b"MSCF not a cabinet; padding ".to_vec();
    padded.extend_from_slice(&cab);
    assert_eq!(classify_region(&padded), Some("cab"));
    cab[8..12].copy_from_slice(&37u32.to_le_bytes());
    assert!(!find_cab(&cab));
    cab[8..12].copy_from_slice(&36u32.to_le_bytes());
    cab[16..20].copy_from_slice(&37u32.to_le_bytes());
    assert!(!find_cab(&cab));
    assert!(!find_cab(b"MSCF"));
}

#[test]
fn trailer_kind_is_distinct_from_claimed_metadata_and_interior_holes() {
    let pe = fake_pe(1024);
    let mut bytes = vec![0; 64];
    bytes.extend_from_slice(&pe);
    let end = bytes.len();
    bytes.extend_from_slice(b"ordinary unframed trailing text without an executable");
    bytes.extend_from_slice(b" and sufficient length to exceed the coverage floor");
    let mut coverage = Coverage::new("test", 8);
    coverage.claim(8, 64);
    coverage.claim_freeform(64, end as u64);
    let (values, _) = run(&coverage, &bytes);
    assert!(stow(&values).contains(&"pe".to_string()));
    assert_eq!(
        values.get("media.trailing_content_kind"),
        Some(&serde_json::json!("text"))
    );

    // A program in an interior hole is likewise not a program in the tail.
    coverage.claims.clear();
    coverage.claim(end as u64 - 16, end as u64);
    let (values, _) = run(&coverage, &bytes);
    assert!(stow(&values).contains(&"pe".to_string()));
    assert_eq!(
        values.get("media.trailing_content_kind"),
        Some(&serde_json::json!("text"))
    );
}

#[test]
fn executable_trailer_retains_location_when_metadata_is_ordinary() {
    let mut bytes = vec![0; 64];
    bytes.extend_from_slice(&fake_pe(1024));
    let mut coverage = Coverage::new("test", 8);
    coverage.claim(8, 64);
    let (values, _) = run(&coverage, &bytes);
    assert_eq!(
        values.get("media.trailing_content_kind"),
        Some(&serde_json::json!("pe"))
    );
}

#[test]
fn no_trailer_kind_is_invented_for_covered_or_opaque_unrecognized_data() {
    let bytes = vec![0; 512];
    let mut coverage = Coverage::new("test", 8);
    coverage.claim(8, bytes.len() as u64);
    assert!(
        run(&coverage, &bytes)
            .0
            .get("media.trailing_content_kind")
            .is_none()
    );
    assert!(
        run(&Coverage::unrecognized(), &bytes)
            .0
            .get("media.trailing_content_kind")
            .is_none()
    );
    let mut high = vec![0; 64];
    high.extend((0..=255u8).cycle().take(2048));
    coverage.claims.clear();
    coverage.claim(8, 64);
    assert_eq!(
        run(&coverage, &high).0.get("media.trailing_content_kind"),
        Some(&serde_json::json!("high_entropy"))
    );
}
