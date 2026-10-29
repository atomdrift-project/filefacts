use super::*;

#[test]
fn detects_banner_anywhere_in_file() {
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
