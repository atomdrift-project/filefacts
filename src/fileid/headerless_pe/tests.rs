use super::*;

const NT: usize = 0x80;

/// A small, well-formed file-layout PE: two stored sections (`.text` with a
/// `ret` at the entry point, `.data` holding an empty base-relocation
/// block), linker-default alignments and sixteen data directories.
fn intact(layout: Layout) -> Vec<u8> {
    let mut pe = vec![0u8; 0x800];
    let put = |pe: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        pe[at..at + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut pe, 0, b"MZ");
    put(&mut pe, 0x3C, &u32::try_from(NT).unwrap().to_le_bytes());
    put(&mut pe, NT, b"PE\0\0");
    let coff = NT + 4;
    put(&mut pe, coff, &layout.default_machine().to_le_bytes());
    put(&mut pe, coff + 2, &2u16.to_le_bytes());
    put(
        &mut pe,
        coff + 16,
        &layout.optional_header_size().to_le_bytes(),
    );
    put(&mut pe, coff + 18, &0x0102u16.to_le_bytes());
    let opt = coff + 20;
    put(&mut pe, opt, &layout.magic().to_le_bytes());
    put(&mut pe, opt + 16, &0x1000u32.to_le_bytes()); // entry
    match layout {
        Layout::Pe32 => put(&mut pe, opt + 28, &0x1000_0000u32.to_le_bytes()),
        Layout::Pe64 => put(&mut pe, opt + 24, &0x1_4000_0000u64.to_le_bytes()),
    }
    put(&mut pe, opt + 32, &0x1000u32.to_le_bytes());
    put(&mut pe, opt + 36, &0x200u32.to_le_bytes());
    put(&mut pe, opt + 56, &0x3000u32.to_le_bytes()); // SizeOfImage
    put(&mut pe, opt + 60, &0x400u32.to_le_bytes()); // SizeOfHeaders
    put(&mut pe, opt + 68, &2u16.to_le_bytes()); // GUI subsystem
    let count = opt + layout.directory_count_offset();
    put(&mut pe, count, &16u32.to_le_bytes());
    // Base relocations (directory 5): one empty block at the start of .data.
    put(&mut pe, count + 4 + 5 * 8, &0x2000u32.to_le_bytes());
    put(&mut pe, count + 4 + 5 * 8 + 4, &8u32.to_le_bytes());
    let table = opt + usize::from(layout.optional_header_size());
    for (i, (name, va, vsize, raw, flags)) in [
        (
            b".text\0\0\0",
            0x1000u32,
            0x1A0u32,
            0x400u32,
            0x6000_0020u32,
        ),
        (b".data\0\0\0", 0x2000, 0x10, 0x600, 0xC000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let s = table + i * SECTION_HEADER;
        put(&mut pe, s, name);
        put(&mut pe, s + 8, &vsize.to_le_bytes());
        put(&mut pe, s + 12, &va.to_le_bytes());
        put(&mut pe, s + 16, &0x200u32.to_le_bytes());
        put(&mut pe, s + 20, &raw.to_le_bytes());
        put(&mut pe, s + 36, &flags.to_le_bytes());
    }
    pe[0x400] = 0xC3;
    put(&mut pe, 0x600, &0x1000u32.to_le_bytes());
    put(&mut pe, 0x604, &8u32.to_le_bytes());
    pe
}

/// What Smoke Loader leaves of a mapped bot image: `e_lfanew` moved into the
/// first dword, and the magics, machine, optional-header size and magic,
/// alignments and directory count all zeroed.
fn smoke_wiped(layout: Layout) -> Vec<u8> {
    let mut pe = intact(layout);
    let opt = NT + 24;
    pe[..0x40].fill(0);
    pe[..4].copy_from_slice(&u32::try_from(NT).unwrap().to_le_bytes());
    pe[NT..NT + 4].fill(0);
    pe[NT + 4..NT + 6].fill(0);
    pe[NT + 20..NT + 22].fill(0);
    pe[opt..opt + 2].fill(0);
    pe[opt + 32..opt + 40].fill(0);
    let count = opt + layout.directory_count_offset();
    pe[count..count + 4].fill(0);
    pe
}

fn names(header: &Header) -> Vec<&'static str> {
    header.fields().iter().map(|f| f.name()).collect()
}

#[test]
fn smoke_style_wiped_pe32_is_located_and_restored_exactly() {
    let wiped = smoke_wiped(Layout::Pe32);
    let header = locate(&wiped).expect("wiped header located");
    assert_eq!(header.nt_offset(), NT);
    assert_eq!(header.layout, Layout::Pe32);
    assert_eq!(
        names(&header),
        [
            "dos_magic",
            "nt_offset",
            "nt_signature",
            "machine",
            "optional_header_size",
            "optional_magic",
            "section_alignment",
            "file_alignment",
            "data_directory_count",
        ]
    );
    let repaired = repair(&wiped).expect("repairable");
    assert_eq!(repaired.image, intact(Layout::Pe32));
    assert_eq!(repaired.image.len(), wiped.len());
}

#[test]
fn smoke_style_wiped_pe32_plus_restores_the_64_bit_layout() {
    let wiped = smoke_wiped(Layout::Pe64);
    let repaired = repair(&wiped).expect("repairable");
    assert_eq!(repaired.header.layout, Layout::Pe64);
    assert_eq!(repaired.image, intact(Layout::Pe64));
}

#[test]
fn only_the_missing_magics_are_rewritten() {
    // MZ zeroed, everything else intact.
    let mut no_mz = intact(Layout::Pe32);
    no_mz[..2].fill(0);
    let repaired = repair(&no_mz).expect("repairable");
    assert_eq!(names(&repaired.header), ["dos_magic"]);
    assert_eq!(repaired.image, intact(Layout::Pe32));

    // Both magics zeroed; e_lfanew survives at 0x3C.
    let mut no_magics = no_mz.clone();
    no_magics[NT..NT + 4].fill(0);
    let header = locate(&no_magics).expect("located");
    assert_eq!(names(&header), ["dos_magic", "nt_signature"]);

    // MZ and e_lfanew gone, PE\0\0 intact: found by its signature.
    let mut no_dos_header = intact(Layout::Pe32);
    no_dos_header[..0x40].fill(0);
    let header = locate(&no_dos_header).expect("located by signature");
    assert_eq!(names(&header), ["dos_magic", "nt_offset"]);
    assert_eq!(repair(&no_dos_header).unwrap().image, intact(Layout::Pe32));

    // MZ intact, signature zeroed.
    let mut no_signature = intact(Layout::Pe32);
    no_signature[NT..NT + 4].fill(0);
    assert_eq!(names(&locate(&no_signature).unwrap()), ["nt_signature"]);
}

/// Smoke's bot image also zeroes every section's name, flags and
/// `VirtualSize`, leaving its uninitialized-data section with no extent but
/// its address. The survivors still fit; what the wiper took from the
/// section table stays taken.
#[test]
fn wiped_section_names_flags_and_virtual_sizes_still_fit() {
    let mut wiped = smoke_wiped(Layout::Pe32);
    let opt = NT + 24;
    let table = opt + 0xE0;
    wiped[NT + 6..NT + 8].copy_from_slice(&3u16.to_le_bytes());
    wiped[opt + 56..opt + 60].copy_from_slice(&0x5000u32.to_le_bytes());
    // A third section: no virtual size, no raw data, at 0x3000.
    let bss = table + 2 * SECTION_HEADER;
    wiped[bss + 12..bss + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    for i in 0..3 {
        let s = table + i * SECTION_HEADER;
        wiped[s..s + 12].fill(0); // name and VirtualSize
        wiped[s + 36..s + 40].fill(0); // characteristics
    }
    let repaired = repair(&wiped).expect("still a program");
    assert_eq!(repaired.header.fields().len(), 9);
    assert_eq!(&repaired.image[table..table + 8], &[0; 8]);

    // Two sections at one address are not a section table.
    let mut duplicate = wiped.clone();
    duplicate[bss + 12..bss + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    assert_eq!(locate(&duplicate), None);
}

#[test]
fn an_intact_pe_is_not_a_wiped_one() {
    assert_eq!(locate(&intact(Layout::Pe32)), None);
    assert_eq!(locate(&intact(Layout::Pe64)), None);
    assert_eq!(repair(&intact(Layout::Pe32)), None);
}

#[test]
fn surviving_fields_must_agree_with_one_layout() {
    // A PE32+ machine beside a PE32 optional-header magic.
    let mut mixed = intact(Layout::Pe32);
    mixed[..2].fill(0);
    mixed[NT + 4..NT + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    assert_eq!(locate(&mixed), None);

    // An unknown machine.
    let mut unknown = smoke_wiped(Layout::Pe32);
    unknown[NT + 4..NT + 6].copy_from_slice(&0x1234u16.to_le_bytes());
    assert_eq!(locate(&unknown), None);

    // A signature overwritten with something other than zeros.
    let mut overwritten = smoke_wiped(Layout::Pe32);
    overwritten[NT..NT + 4].copy_from_slice(b"XX\0\0");
    assert_eq!(locate(&overwritten), None);
}

#[test]
fn implausible_structure_is_rejected() {
    let cases: [(&str, fn(&mut Vec<u8>)); 9] = [
        ("unaligned image base", |pe| {
            pe[NT + 24 + 28..NT + 24 + 32].copy_from_slice(&0x1000_1234u32.to_le_bytes());
        }),
        ("no sections", |pe| pe[NT + 6..NT + 8].fill(0)),
        ("too many sections", |pe| {
            pe[NT + 6..NT + 8].copy_from_slice(&97u16.to_le_bytes());
        }),
        ("zero SizeOfImage", |pe| {
            pe[NT + 24 + 56..NT + 24 + 60].fill(0);
        }),
        ("section past the file", |pe| {
            let s = NT + 24 + 0xE0 + SECTION_HEADER;
            pe[s + 20..s + 24].copy_from_slice(&0x800u32.to_le_bytes());
        }),
        ("section past SizeOfImage", |pe| {
            let s = NT + 24 + 0xE0 + SECTION_HEADER;
            pe[s + 12..s + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        }),
        ("overlapping sections", |pe| {
            let s = NT + 24 + 0xE0;
            pe[s + 8..s + 12].copy_from_slice(&0x1800u32.to_le_bytes());
        }),
        ("entry outside every section", |pe| {
            pe[NT + 24 + 16..NT + 24 + 20].copy_from_slice(&0x2F00u32.to_le_bytes());
        }),
        ("directory past the image", |pe| {
            let dir = NT + 24 + 96 + 8;
            pe[dir..dir + 4].copy_from_slice(&0x2FF0u32.to_le_bytes());
            pe[dir + 4..dir + 8].copy_from_slice(&0x100u32.to_le_bytes());
        }),
    ];
    for (what, damage) in cases {
        let mut pe = smoke_wiped(Layout::Pe32);
        damage(&mut pe);
        assert_eq!(locate(&pe), None, "{what}");
    }
}

#[test]
fn truncated_headers_are_rejected() {
    let wiped = smoke_wiped(Layout::Pe32);
    // Cut inside the section table, then before the first section's data.
    for len in [NT + 24 + 0xE0 + 20, 0x300, 0x500] {
        assert_eq!(locate(&wiped[..len]), None, "cut at {len:#x}");
    }
}

#[test]
fn random_text_and_zero_data_are_not_pe() {
    // xorshift64: deterministic noise, with the first dword forced to a
    // plausible e_lfanew so the structural checks are what reject it.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..2_000 {
        let mut noise = vec![0u8; 0x800];
        for chunk in noise.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        noise[..4].copy_from_slice(&0x80u32.to_le_bytes());
        noise[0x80..0x84].fill(0);
        assert_eq!(locate(&noise), None);
    }

    let text = b"Dear reviewer,\n\nPE headers are described in the PE/COFF spec. \
                 MZ is the DOS magic.\n"
        .repeat(64);
    assert_eq!(locate(&text), None);

    let mut zeros = vec![0u8; 0x4000];
    zeros[..4].copy_from_slice(&0xD0u32.to_le_bytes());
    assert_eq!(locate(&zeros), None);
    assert_eq!(locate(&[]), None);
}

#[test]
fn identification_types_a_wiped_pe_as_pe() {
    use crate::FileType;
    let wiped = smoke_wiped(Layout::Pe32);
    for name in ["", "layer3.bin", "payload.dll"] {
        let id = crate::FileId::from_path_and_bytes(std::path::Path::new(name), &wiped);
        assert_eq!(id.file_type(), FileType::Pe, "{name:?}");
    }
    let mut zeros = vec![0u8; 0x4000];
    zeros[..4].copy_from_slice(&0xD0u32.to_le_bytes());
    assert_ne!(crate::FileId::from_bytes(&zeros).file_type(), FileType::Pe);
    let text = b"PE is not here; this is prose about MZ headers.\n".repeat(32);
    assert_ne!(crate::FileId::from_bytes(&text).file_type(), FileType::Pe);
}

#[test]
fn extraction_reads_the_restored_header_and_reports_the_repair() {
    let wiped = smoke_wiped(Layout::Pe32);
    let parsed = crate::open(&wiped);
    let values = parsed.values();
    assert_eq!(
        values.get("pe.header.repaired"),
        Some(&serde_json::json!([
            "dos_magic",
            "nt_offset",
            "nt_signature",
            "machine",
            "optional_header_size",
            "optional_magic",
            "section_alignment",
            "file_alignment",
            "data_directory_count",
        ]))
    );
    assert_eq!(
        values.get("pe.image_base"),
        Some(&serde_json::json!(0x1000_0000u64))
    );
    assert_eq!(
        values.get("pe.entry_section"),
        Some(&serde_json::json!(".text"))
    );
    // The caller's bytes are untouched; only extraction saw the copy.
    assert_eq!(parsed.bytes(), wiped.as_slice());

    // An ordinary PE carries no repair fact.
    let intact = intact(Layout::Pe32);
    assert!(
        crate::open(&intact)
            .values()
            .get("pe.header.repaired")
            .is_none()
    );
}
