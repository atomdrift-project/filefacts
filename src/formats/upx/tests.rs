use super::*;

#[test]
fn detects_banner_in_the_stub_window() {
    let mut buf = vec![0u8; 1000];
    buf.extend_from_slice(b"$Info: This file is packed with the UPX executable packer\0");
    assert!(has_upx_signature(&buf));
}

#[test]
fn detects_magic_in_stub_window() {
    let mut buf = vec![0u8; 1000];
    buf[300..304].copy_from_slice(b"UPX!");
    assert!(has_upx_signature(&buf));
}

#[test]
fn ignores_magic_in_middle_of_file() {
    // UPX! a few hundred KB into the file is more likely random
    // content (esp. inside a UPX-compressed payload that's
    // *itself* embedded in something) than a packer marker.
    let mut buf = vec![0u8; 1_000_000];
    buf[500_000..500_004].copy_from_slice(b"UPX!");
    assert!(!has_upx_signature(&buf));
}

#[test]
fn version_extracts_token() {
    let buf = b"$Id: UPX 5.11 Copyright (C) 1996-2026 the UPX Team. All Rights Reserved. $";
    assert_eq!(extract_version(buf), Some("5.11".to_string()));
}

/// A UPX-packed payload embedded deep in a host carries the banner, but the
/// host is not what UPX packed.
#[test]
fn ignores_a_banner_deep_in_the_file() {
    let mut buf = vec![0u8; 1_000_000];
    let banner = b"$Info: This file is packed with the UPX executable packer";
    buf[500_000..500_000 + banner.len()].copy_from_slice(banner);
    assert!(!has_upx_signature(&buf));
}

/// The version is a short dotted token; anything longer is not one.
#[test]
fn version_token_is_bounded() {
    let mut long = b"$Id: UPX ".to_vec();
    long.extend(std::iter::repeat_n(b'9', 100_000));
    long.extend_from_slice(b" Copyright");
    assert_eq!(extract_version(&long), None);
    assert_eq!(
        extract_version(b"$Id: UPX 3.96w Copyright"),
        Some("3.96w".to_string())
    );
    assert_eq!(extract_version(b"$Id: UPX \x01\x02 Copyright"), None);
}
