use std::path::Path;

use super::*;
use crate::FileType;
use crate::fileid::detect;

fn c64_loader() -> Vec<u8> {
    let mut b = b"\x01\x08\x0b\x08\xc8\x07\x9e2059\0".to_vec();
    b.extend([0xa9, 1, 0x8d, 0x20, 0xd0, 0x4c, 0x0b, 8]);
    b
}

fn prodos_system() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..3].copy_from_slice(&[0x4c, 0x30, 0x20]);
    b[24..42].copy_from_slice(&[
        0x20, 0x00, 0xbf, 0xc8, 0x00, 0x30, 0x20, 0x00, 0xbf, 0xca, 0x10, 0x30, 0x20, 0x00, 0xbf,
        0xcc, 0x20, 0x30,
    ]);
    b
}

fn prodos_boot() -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    data[..7].copy_from_slice(&[0x01, 0x38, 0xb0, 0x03, 0x4c, 0x1c, 0x09]);
    data[100..106].copy_from_slice(b"PRODOS");
    data[110..120].copy_from_slice(b"SOS.KERNEL");
    data[120..126].copy_from_slice(&[0xa5, 0x60, 0x85, 0x44, 0xa5, 0x61]);
    data
}

fn sign_of_misery() -> Vec<u8> {
    let mut bytes = b"\x0a\x01\0\0\x49\0\0\0Program: \0Protection: \0Cracker: \0Group: \0Released: \0Title\0\xff\x93\x01\0\0\0\x7e\0\0\0\0".to_vec();
    bytes.extend_from_slice(b"\x81sample command\0");
    bytes
}

fn aout16() -> Vec<u8> {
    let mut b = vec![0u8; 48];
    for (at, val) in [
        (0, 0o407u16),
        (2, 16),
        (4, 8),
        (6, 4),
        (8, 8),
        (10, 0),
        (14, 1),
    ] {
        b[at..at + 2].copy_from_slice(&val.to_le_bytes());
    }
    b
}

/// What every shape prevents: an unnamed copy is Data, which generic binary
/// analysis reads, rather than Unknown, which nothing reads. Each shape is
/// the only thing that recognises its sample.
#[test]
fn each_shape_routes_an_unnamed_copy_to_data_rather_than_unknown() {
    for (name, sample) in [
        ("c64_basic_sys_loader", c64_loader()),
        ("prodos_system_code", prodos_system()),
        ("prodos_boot_code", prodos_boot()),
        ("sign_of_misery_script", sign_of_misery()),
        ("unix_aout16_image", aout16()),
    ] {
        assert_eq!(shape_of(&sample), Some(name));
        for path in ["unnamed", "renamed.bin"] {
            let detected = detect(Path::new(path), &sample).map(|d| d.file_type);
            assert_eq!(detected, Some(FileType::Data), "{name} as {path}");
        }
    }
}

#[test]
fn c64_loader_rejects_inconsistent_or_truncated_headers() {
    let s = c64_loader();
    assert!(!has_basic_sys_loader(&s[..12]));
    for (at, value) in [(0, 2), (2, 0), (6, 0x80), (7, b'9'), (11, b'!')] {
        let mut b = s.clone();
        b[at] = value;
        assert!(!has_basic_sys_loader(&b), "offset {at}");
    }
    let mut b = s;
    b.resize(65538, 0);
    assert!(!has_basic_sys_loader(&b));
}

#[test]
fn prodos_boot_needs_every_part() {
    let data = prodos_boot();
    for offset in [0, 6, 100, 110, 120] {
        let mut changed = data.clone();
        changed[offset] ^= 0xff;
        assert!(!has_prodos_boot_code(&changed), "offset {offset}");
    }
    assert!(!has_prodos_boot_code(&data[..512]));
}

#[test]
fn prodos_system_rejects_missing_calls_invalid_entry_and_truncation() {
    let data = prodos_system();
    for (at, value) in [
        (0, 0xea),
        (2, 0x40),
        (27, 0xc7),
        (33, 0xc9),
        (39, 0xcd),
        (29, 0x00),
    ] {
        let mut changed = data.clone();
        changed[at] = value;
        assert!(!has_prodos_system_code(&changed), "offset {at}");
    }
    assert!(!has_prodos_system_code(&data[..100]));
}

#[test]
fn sign_of_misery_keeps_its_own_name_and_rejects_damage() {
    let bytes = sign_of_misery();
    assert_eq!(
        detect(Path::new("demo.s0m"), &bytes).map(|d| d.file_type),
        Some(FileType::Data)
    );
    assert!(!looks_like_sign_of_misery_script(&bytes[..50]));
    for (at, value) in [(0, 0), (8, b'X'), (58, b'X')] {
        let mut altered = bytes.clone();
        altered[at] = value;
        assert!(!looks_like_sign_of_misery_script(&altered), "offset {at}");
    }
}

#[test]
fn aout16_rejects_truncation_and_inconsistent_geometry() {
    let b = aout16();
    assert!(!looks_like_aout16_image(&b[..47]));
    for (at, value) in [(0, 0), (2, 15), (4, 80), (10, 16), (14, 0)] {
        let mut changed = b.clone();
        changed[at] = value;
        assert!(!looks_like_aout16_image(&changed), "offset {at}");
    }
}
