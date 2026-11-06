use super::*;

/// Whether `data`, under no name, reads as a DOS COM program.
fn is_com(data: &[u8]) -> bool {
    looks_like_dos_com(&Sniff::new(std::path::Path::new(""), data))
}

#[test]
fn headerless_bios_disk_bootstrap_uses_the_existing_entry_decoder() {
    // Argument setup separates AX from the BIOS call. No DOS syscall or
    // filename extension is needed to recognize this real-mode program.
    let program = [
        0xB8, 0x01, 0x03, 0xB9, 0x01, 0x00, 0xBA, 0x80, 0x00, 0xBB, 0x00, 0x38, 0x8E, 0xC3, 0xBB,
        0x00, 0x00, 0xCD, 0x13, 0xCD, 0x19,
    ];
    for selector in [0x02, 0x03] {
        let mut code = program;
        code[2] = selector;
        assert!(is_com(&code));
        for name in ["program", "program.32", "program.com"] {
            assert_eq!(
                super::super::detect(std::path::Path::new(name), &code)
                    .unwrap()
                    .file_type,
                crate::FileType::DosCom
            );
        }
    }

    let mut unknown_selector = program;
    unknown_selector[2] = 0xFF;
    assert!(!is_com(&unknown_selector));
    let mut no_bootstrap = program;
    no_bootstrap[20] = 0x18;
    assert!(!is_com(&no_bootstrap));
    // An intervening AX write invalidates the known selector.
    let mut clobbered = program[..17].to_vec();
    clobbered.extend_from_slice(&[0x31, 0xC0]);
    clobbered.extend_from_slice(&program[17..]);
    assert!(!is_com(&clobbered));
    // Valid-looking bytes behind an unconditional return are not entry code.
    let mut unreachable = vec![0xC3];
    unreachable.extend_from_slice(&program);
    assert!(!is_com(&unreachable));
    assert!(!is_com(&[0xCD, 0x13, 0xCD, 0x19]));
}

fn fat12_boot_sector() -> [u8; 512] {
    let mut data = [0u8; 512];
    data[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    data[3..11].copy_from_slice(b"MSDOS5.0");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 1;
    data[14..16].copy_from_slice(&1u16.to_le_bytes());
    data[16] = 2;
    data[17..19].copy_from_slice(&224u16.to_le_bytes());
    data[19..21].copy_from_slice(&2880u16.to_le_bytes());
    data[21] = 0xF0;
    data[22..24].copy_from_slice(&9u16.to_le_bytes());
    data[24..26].copy_from_slice(&18u16.to_le_bytes());
    data[26..28].copy_from_slice(&2u16.to_le_bytes());
    data[510..].copy_from_slice(&[0x55, 0xAA]);
    data
}

fn fat32_boot_sector() -> [u8; 512] {
    let mut data = [0u8; 512];
    data[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    data[3..11].copy_from_slice(b"MSWIN4.1");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 8;
    data[14..16].copy_from_slice(&32u16.to_le_bytes());
    data[16] = 2;
    data[21] = 0xF8;
    data[24..26].copy_from_slice(&63u16.to_le_bytes());
    data[26..28].copy_from_slice(&255u16.to_le_bytes());
    data[32..36].copy_from_slice(&1_000_000u32.to_le_bytes());
    data[36..40].copy_from_slice(&976u32.to_le_bytes());
    data[510..].copy_from_slice(&[0x55, 0xAA]);
    data
}

#[test]
fn padded_dos_com_overwriter_is_recognized_without_loose_interrupt_matches() {
    let anton =
        &crate::fileid::testutil::unzstd(include_bytes!("../../../testdata/dos-com/anton-97.zst"));
    assert!(looks_like_dos_com_overwriter(anton));

    let mut one_interrupt = vec![0u8; 5120];
    one_interrupt[0..6].copy_from_slice(b"*.COM\0");
    one_interrupt[16..18].copy_from_slice(&[0xCD, 0x21]);
    one_interrupt[32..34].copy_from_slice(&[0xCD, 0x20]);
    assert!(!looks_like_dos_com_overwriter(&one_interrupt));

    let mut no_wildcard = one_interrupt.clone();
    no_wildcard[24..26].copy_from_slice(&[0xCD, 0x21]);
    no_wildcard[0..6].copy_from_slice(b"plain\0");
    assert!(!looks_like_dos_com_overwriter(&no_wildcard));

    let text = b"uses INT 21 and INT 20 while searching *.COM\n";
    assert!(!looks_like_dos_com_overwriter(text));
}

#[test]
fn fat_boot_sector_accepts_valid_fat12_and_fat32_bpbs() {
    let sector = fat12_boot_sector();
    assert!(looks_like_fat_boot_sector(&sector));
    assert!(looks_like_fat_boot_sector(&fat32_boot_sector()));
}

#[test]
fn fat_boot_sector_rejects_each_required_bpb_field_when_invalid() {
    let sector = fat12_boot_sector();
    let mut mutations: Vec<(&str, Box<dyn Fn(&mut [u8; 512])>)> = vec![
        (
            "bytes per sector",
            Box::new(|b| b[11..13].copy_from_slice(&513u16.to_le_bytes())),
        ),
        ("cluster size", Box::new(|b| b[13] = 3)),
        ("reserved sectors", Box::new(|b| b[14..16].fill(0))),
        ("fat count", Box::new(|b| b[16] = 0)),
        ("media descriptor", Box::new(|b| b[21] = 0)),
        (
            "fat size",
            Box::new(|b| {
                b[22..24].fill(0);
                b[36..40].fill(0);
            }),
        ),
        (
            "volume size",
            Box::new(|b| {
                b[19..21].fill(0);
                b[32..36].fill(0);
            }),
        ),
        ("sectors per track", Box::new(|b| b[24..26].fill(0))),
        ("head count", Box::new(|b| b[26..28].fill(0))),
        ("jump opcode", Box::new(|b| b[0] = 0x90)),
        ("short jump NOP", Box::new(|b| b[2] = 0x91)),
        ("boot signature", Box::new(|b| b[511] = 0)),
    ];
    for (name, mutate) in mutations.drain(..) {
        let mut invalid = sector;
        mutate(&mut invalid);
        assert!(
            !looks_like_fat_boot_sector(&invalid),
            "accepted invalid {name}"
        );
    }

    let mut signature_only = [0x41u8; 512];
    signature_only[510..].copy_from_slice(&[0x55, 0xAA]);
    assert!(!looks_like_fat_boot_sector(&signature_only));
    assert!(!looks_like_fat_boot_sector(&sector[..511]));
}

/// Anything larger than a COM image is ruled out by its size alone, before a
/// byte of it is classified: every text file of any size passes through here.
#[test]
fn dos_com_size_gate_comes_before_reading_the_body() {
    let large = vec![b'a'; DOS_COM_MAX_SIZE + 1];
    let sniff = Sniff::new(std::path::Path::new(""), &large);
    assert!(!looks_like_dos_com(&sniff));
    assert!(!sniff.classified_binary());
}

/// A coherent 16-bit DOS MZ header.
fn mz_example() -> Vec<u8> {
    let mut b = vec![0u8; 96];
    b[..2].copy_from_slice(b"MZ");
    b[2..4].copy_from_slice(&96u16.to_le_bytes());
    b[4..6].copy_from_slice(&1u16.to_le_bytes());
    b[8..10].copy_from_slice(&2u16.to_le_bytes());
    b[24..26].copy_from_slice(&28u16.to_le_bytes());
    b[32..34].copy_from_slice(&[0xcd, 0x20]);
    b
}

#[test]
fn mz_valid_header_and_nonzero_entry() {
    let mut b = mz_example();
    assert!(looks_like_dos_mz(&b));
    b[20..22].copy_from_slice(&20u16.to_le_bytes());
    assert!(looks_like_dos_mz(&b));
}

#[test]
fn mz_identification_preserves_extended_formats() {
    let mut b = mz_example();
    let path = std::path::Path::new("legacy.exe");
    assert_eq!(
        crate::fileid::detect(path, &b).unwrap().file_type,
        crate::FileType::Data
    );
    b[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
    b[64..68].copy_from_slice(b"PE\0\0");
    assert_eq!(
        crate::fileid::detect(path, &b).unwrap().file_type,
        crate::FileType::Pe
    );
}

#[test]
fn mz_rejects_incoherent_geometry() {
    let b = mz_example();
    assert!(!looks_like_dos_mz(&b[..31]));
    for (at, value) in [(0, 0), (4, 0), (8, 0), (20, 255), (22, 255)] {
        let mut changed = b.clone();
        changed[at] = value;
        assert!(!looks_like_dos_mz(&changed), "offset {at}");
    }
    let mut changed = b.clone();
    changed[2..4].copy_from_slice(&512u16.to_le_bytes());
    assert!(!looks_like_dos_mz(&changed));
    let mut changed = b;
    changed[6..8].copy_from_slice(&2u16.to_le_bytes());
    assert!(!looks_like_dos_mz(&changed));
}
