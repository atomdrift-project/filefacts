use super::*;
use crate::fileid::{FileType, detect};
use std::path::Path;

const SAMPLE: &[u8] = include_bytes!("../testdata/tiny-image4-trustcache.im4p");

#[test]
fn full_trca_table_identification_is_independent_of_collected_name() {
    let parsed = parse(SAMPLE).unwrap();
    assert_eq!(parsed.description, "1");
    assert_eq!(parsed.entries.len() / 24, 83);
    for name in ["", "hash", "firmware.trustcache", "firmware.im4p"] {
        let detected = detect(Path::new(name), SAMPLE).unwrap();
        assert_eq!(detected.file_type, FileType::Image4TrustCache);
        assert!(!detected.extension_mismatch());
    }
    assert!(
        detect(Path::new("program.exe"), SAMPLE)
            .unwrap()
            .extension_mismatch()
    );
}

#[test]
fn framing_count_version_order_and_reserved_bytes_are_required() {
    for cut in 0..SAMPLE.len() {
        assert!(parse(&SAMPLE[..cut]).is_none(), "cut {cut}");
    }
    for (offset, value) in [(8, b'X'), (15, b'i'), (23, 3), (43, 84), (70, 1)] {
        let mut corrupt = SAMPLE.to_vec();
        corrupt[offset] = value;
        assert!(parse(&corrupt).is_none(), "offset {offset}");
    }
    let mut trailing = SAMPLE.to_vec();
    trailing.push(0);
    assert!(parse(&trailing).is_none());
    let mut unordered = SAMPLE.to_vec();
    unordered[47..67].fill(255);
    assert!(parse(&unordered).is_none());
    let mut bad_der = SAMPLE.to_vec();
    bad_der[1] = 0x80;
    assert!(parse(&bad_der).is_none());
}
