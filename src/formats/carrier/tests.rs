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
