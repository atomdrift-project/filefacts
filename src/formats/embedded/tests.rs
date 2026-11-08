#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
use super::*;

#[test]
fn physical_child_does_not_consume_neighbor_from_virtual_image_size() {
    let mut data = Vec::new();
    make_synthetic_pe(&mut data, 0);
    make_synthetic_pe(&mut data, 1024);
    data[0x80 + 80..0x80 + 84].copy_from_slice(&0x100000u32.to_le_bytes());
    let first = validate_pe(&data, 0).unwrap();
    assert_eq!(first.size, 1024);
    assert_eq!(validate_pe(&data, 1024).unwrap().size, 1024);
}

#[test]
fn physical_child_keeps_its_file_offset_certificate() {
    let mut data = Vec::new();
    make_synthetic_pe(&mut data, 0);
    let security = 0x80 + 24 + 96 + 4 * 8;
    data[security..security + 4].copy_from_slice(&1024u32.to_le_bytes());
    data[security + 4..security + 8].copy_from_slice(&128u32.to_le_bytes());
    assert_eq!(validate_pe(&data, 0).unwrap().size, 1152);
    data[security + 4..security + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(validate_pe(&data, 0).unwrap().size, 1024);
}

/// Build a minimal but structurally valid PE32 blob at the given offset within a buffer.
fn make_synthetic_pe(buf: &mut Vec<u8>, offset: usize) {
    while buf.len() < offset + 4096 {
        buf.push(0u8);
    }
    // MZ header
    buf[offset] = 0x4D; // M
    buf[offset + 1] = 0x5A; // Z
    // e_lfanew at offset + 0x3C = 0x80 (128) — typical for real PEs
    let e_lfanew: u32 = 0x80;
    buf[offset + 0x3C..offset + 0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    let pe_base = offset + 0x80;
    // PE\0\0 signature
    buf[pe_base] = 0x50;
    buf[pe_base + 1] = 0x45;
    buf[pe_base + 2] = 0x00;
    buf[pe_base + 3] = 0x00;
    // COFF header (20 bytes at pe_base + 4)
    // Machine: x86 (0x014C)
    buf[pe_base + 4..pe_base + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    // NumberOfSections: 1
    buf[pe_base + 6..pe_base + 8].copy_from_slice(&1u16.to_le_bytes());
    // SizeOfOptionalHeader: 0xE0 (224) — standard PE32
    buf[pe_base + 20..pe_base + 22].copy_from_slice(&0x00E0u16.to_le_bytes());

    // Optional header (starts at pe_base + 24)
    // Magic: PE32 (0x010B)
    buf[pe_base + 24..pe_base + 26].copy_from_slice(&0x010Bu16.to_le_bytes());
    // SizeOfImage at optional header offset 56
    buf[pe_base + 80..pe_base + 84].copy_from_slice(&(4096u32).to_le_bytes());

    // Section table (starts at pe_base + 24 + 0xE0 = pe_base + 248)
    let section_base = pe_base + 24 + 0xE0;
    // SizeOfRawData at section header offset 16
    buf[section_base + 16..section_base + 20].copy_from_slice(&512u32.to_le_bytes());
    // PointerToRawData at section header offset 20
    buf[section_base + 20..section_base + 24].copy_from_slice(&512u32.to_le_bytes());
}

/// Build a minimal ELF64 LE blob at the given offset within a buffer.
fn make_synthetic_elf(buf: &mut Vec<u8>, offset: usize) {
    let elf_size = 0x3000usize;
    while buf.len() < offset + elf_size {
        buf.push(0u8);
    }
    buf[offset] = 0x7F;
    buf[offset + 1] = 0x45; // E
    buf[offset + 2] = 0x4C; // L
    buf[offset + 3] = 0x46; // F
    buf[offset + 4] = 2; // 64-bit
    buf[offset + 5] = 1; // LE
    buf[offset + 6] = 1; // version
    // e_type = EXEC (2)
    buf[offset + 16..offset + 18].copy_from_slice(&2u16.to_le_bytes());
    // e_machine = x86-64 (0x3E)
    buf[offset + 18..offset + 20].copy_from_slice(&0x3Eu16.to_le_bytes());
    // e_version
    buf[offset + 20..offset + 24].copy_from_slice(&1u32.to_le_bytes());
    // e_phoff = 64, e_shoff = 0x2000
    buf[offset + 32..offset + 40].copy_from_slice(&64u64.to_le_bytes());
    buf[offset + 40..offset + 48].copy_from_slice(&0x2000u64.to_le_bytes());
    // e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    buf[offset + 52..offset + 54].copy_from_slice(&64u16.to_le_bytes());
    buf[offset + 54..offset + 56].copy_from_slice(&56u16.to_le_bytes());
    buf[offset + 56..offset + 58].copy_from_slice(&1u16.to_le_bytes());
    buf[offset + 58..offset + 60].copy_from_slice(&64u16.to_le_bytes());
    buf[offset + 60..offset + 62].copy_from_slice(&1u16.to_le_bytes());
    buf[offset + 62..offset + 64].copy_from_slice(&0u16.to_le_bytes());

    // One PT_LOAD segment covering the whole synthetic ELF.
    let ph = offset + 64;
    buf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    buf[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    buf[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    buf[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    buf[ph + 32..ph + 40].copy_from_slice(&(elf_size as u64).to_le_bytes());
    buf[ph + 40..ph + 48].copy_from_slice(&(elf_size as u64).to_le_bytes());
    buf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
}

#[test]
fn test_scan_empty() {
    assert!(scan(&[]).is_empty());
}

#[test]
fn test_scan_finds_embedded_pe() {
    let mut buf = vec![0u8; 8192];
    // Host PE header at offset 0 (just needs MZ so our scan starts at 2)
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    // Embedded PE at offset 512
    make_synthetic_pe(&mut buf, 512);

    let found = scan(&buf);
    assert!(!found.is_empty(), "should detect embedded PE");
    assert_eq!(found[0].offset, 512);
    assert!(matches!(found[0].kind, EmbeddedKind::Pe32));
}

#[test]
fn test_scan_finds_embedded_elf() {
    let mut buf = vec![0u8; 2048];
    // Host ELF at offset 0
    buf[0] = 0x7F;
    buf[1] = 0x45;
    buf[2] = 0x4C;
    buf[3] = 0x46;
    // Embedded ELF at offset 512
    make_synthetic_elf(&mut buf, 512);

    let found = scan(&buf);
    assert!(!found.is_empty(), "should detect embedded ELF");
    assert_eq!(found[0].offset, 512);
    assert!(matches!(found[0].kind, EmbeddedKind::Elf64Le));
}

#[test]
fn test_scan_finds_base64_encoded_embedded_elf() {
    // Build a real synthetic ELF, base64-encode it, splice into a
    // host buffer's data region — exact shape of the Kong-ingress-
    // controller 2024 dropper.
    let mut payload = Vec::new();
    make_synthetic_elf(&mut payload, 0);
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload);
    let mut host = vec![0u8; 4096];
    host[0] = 0x7F;
    host[1] = 0x45;
    host[2] = 0x4C;
    host[3] = 0x46;
    let splice_off = 1024;
    host.extend_from_slice(&[0u8; 1024]);
    let needed = splice_off + encoded.len() + 256;
    host.resize(needed, 0);
    host[splice_off..splice_off + encoded.len()].copy_from_slice(encoded.as_bytes());

    let found = scan(&host);
    let base64_hit = found.iter().find(|f| f.offset == splice_off);
    assert!(
        base64_hit.is_some(),
        "should detect base64-encoded ELF at offset {splice_off}; found {:?}",
        found.iter().map(|f| (f.offset, f.kind)).collect::<Vec<_>>()
    );
    assert!(matches!(
        base64_hit.expect("base64 hit present").kind,
        EmbeddedKind::Elf64Le
    ));
}

#[test]
fn test_scan_rejects_random_base64_run() {
    // 16 KB of base64-shaped bytes that don't decode to ELF/PE.
    let mut host = vec![0u8; 4096];
    host[0] = 0x7F;
    host[1] = 0x45;
    host[2] = 0x4C;
    host[3] = 0x46;
    // Junk encoded — not a real binary.
    let junk = "A".repeat(20_000);
    host.extend_from_slice(junk.as_bytes());

    let found = scan(&host);
    assert!(
        !found.iter().any(|f| f.offset >= 4096),
        "must not flag random base64 runs as embedded payloads"
    );
}

#[test]
fn test_rejects_bad_e_lfanew_zero() {
    let mut data = vec![0u8; 256];
    data[0] = 0x4D;
    data[1] = 0x5A;
    // e_lfanew = 0 (invalid)
    data[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
    assert!(validate_pe(&data, 0).is_none());
}

#[test]
fn test_rejects_bad_e_lfanew_too_large() {
    let mut data = vec![0u8; 256];
    data[0] = 0x4D;
    data[1] = 0x5A;
    // e_lfanew = 2048 (> 1024, invalid)
    data[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes());
    assert!(validate_pe(&data, 0).is_none());
}

#[test]
fn test_rejects_bad_e_lfanew_misaligned() {
    let mut data = vec![0u8; 256];
    data[0] = 0x4D;
    data[1] = 0x5A;
    // e_lfanew = 65 (not 4-byte aligned)
    data[0x3C..0x40].copy_from_slice(&65u32.to_le_bytes());
    assert!(validate_pe(&data, 0).is_none());
}

#[test]
fn test_rejects_bad_machine_type() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 0);
    // Overwrite machine with unknown value 0xFFFF
    buf[0x80 + 4..0x80 + 6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert!(validate_pe(&buf, 0).is_none());
}

#[test]
fn test_rejects_zero_sections() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 0);
    // NumberOfSections = 0
    buf[0x80 + 6..0x80 + 8].copy_from_slice(&0u16.to_le_bytes());
    assert!(validate_pe(&buf, 0).is_none());
}

#[test]
fn test_rejects_too_many_sections() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 0);
    // NumberOfSections = 200 (> 96)
    buf[0x80 + 6..0x80 + 8].copy_from_slice(&200u16.to_le_bytes());
    assert!(validate_pe(&buf, 0).is_none());
}

#[test]
fn test_rejects_unknown_opt_magic() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 0);
    // Optional header magic = 0xDEAD (neither PE32 nor PE32+)
    buf[0x80 + 24..0x80 + 26].copy_from_slice(&0xDEADu16.to_le_bytes());
    assert!(validate_pe(&buf, 0).is_none());
}

#[test]
fn test_rejects_sections_outside_embedded_slice() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 0);
    // First section header points far beyond SizeOfImage.
    // Section table is at 0x80 + 24 + 0xE0 (pe_base + COFF header + optional header)
    let section_table = 0x80 + 24 + 0xE0;
    buf[section_table + 16..section_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section_table + 20..section_table + 24].copy_from_slice(&0x9000u32.to_le_bytes());
    assert!(validate_pe(&buf, 0).is_none());
}

#[test]
fn test_elf_rejects_bad_class() {
    let mut data = vec![0u8; 64];
    make_synthetic_elf(&mut data, 0);
    data[4] = 3; // invalid class
    assert!(validate_elf(&data, 0).is_none());
}

#[test]
fn test_elf_rejects_bad_encoding() {
    let mut data = vec![0u8; 64];
    make_synthetic_elf(&mut data, 0);
    data[5] = 3; // invalid encoding
    assert!(validate_elf(&data, 0).is_none());
}

#[test]
fn test_elf_rejects_header_only_stub() {
    let mut data = vec![0u8; 512];
    data[0] = 0x7F;
    data[1] = 0x45;
    data[2] = 0x4C;
    data[3] = 0x46;
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    data[32..40].copy_from_slice(&64u64.to_le_bytes());
    data[52..54].copy_from_slice(&64u16.to_le_bytes());
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    data[56..58].copy_from_slice(&1u16.to_le_bytes());
    assert!(validate_elf(&data, 0).is_none());
}

#[test]
fn test_elf_rejects_bad_machine() {
    let mut data = vec![0u8; 64];
    make_synthetic_elf(&mut data, 0);
    // e_machine = 0xDEAD (unknown)
    data[18..20].copy_from_slice(&0xDEADu16.to_le_bytes());
    assert!(validate_elf(&data, 0).is_none());
}

#[test]
fn test_max_candidates_enforced() {
    // Build a buffer with many valid ELF headers
    let elf_size = 64;
    let n = MAX_EMBEDDED + 5;
    let mut buf = vec![0u8; 4 + n * (elf_size + 4)];
    for i in 0..n {
        make_synthetic_elf(&mut buf, 4 + i * (elf_size + 4));
    }
    let found = scan(&buf);
    assert!(found.len() <= MAX_EMBEDDED);
}

#[test]
fn test_duplicate_prefix_does_not_hide_unique_tail_pe() {
    let count = MAX_EMBEDDED + 6;
    let stride = 4096;
    let mut buf = vec![0u8; stride];
    buf[0] = b'M';
    buf[1] = b'Z';
    for i in 0..count {
        make_synthetic_pe(&mut buf, stride * (i + 1));
    }

    // All earlier images are byte-identical. Make only the final image
    // distinct at a byte covered by the content fingerprint.
    let tail_offset = stride * count;
    buf[tail_offset + 700] = 0xA5;

    let found = scan(&buf);
    assert_eq!(found.len(), MAX_EMBEDDED);
    assert!(
        found
            .iter()
            .any(|candidate| candidate.offset == tail_offset),
        "a distinct late stage must survive a duplicate-heavy prefix"
    );
}

#[test]
fn test_no_false_positive_on_null_bytes() {
    let data = vec![0u8; 4096];
    assert!(scan(&data).is_empty());
}

#[test]
fn test_no_false_positive_on_text() {
    let data = b"This is just plain ASCII text with no binary content whatsoever. \
                     It repeats a few times to be sure. \
                     This is just plain ASCII text with no binary content whatsoever."
        .to_vec();
    assert!(scan(&data).is_empty());
}

#[test]
fn emits_entries_and_count() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 1024);
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    emit(&buf, None, &mut values, &mut metrics);
    assert_eq!(metrics.get("binary.embedded_binaries"), Some(1.0));
    let entry = &values
        .get("binary.embedded")
        .and_then(|v| v.as_array())
        .unwrap()[0];
    assert_eq!(entry["offset"], 1024);
    assert_eq!(entry["kind"], "pe");
    assert_eq!(entry["variant"], "pe32");
    assert!(entry.get("encoding").is_none());
}

#[test]
fn images_inside_the_signature_are_not_payloads() {
    let mut buf = vec![0u8; 4096];
    make_synthetic_pe(&mut buf, 1024);
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    emit(&buf, Some(1000..2000), &mut values, &mut metrics);
    assert!(values.get("binary.embedded").is_none());
    assert_eq!(metrics.get("binary.embedded_binaries"), None);
}
