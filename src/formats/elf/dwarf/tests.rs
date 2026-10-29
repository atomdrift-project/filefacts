use super::*;

#[test]
fn language_name_known_constants() {
    assert_eq!(language_name(gimli::DW_LANG_C99), "c");
    assert_eq!(language_name(gimli::DW_LANG_Rust), "rust");
    assert_eq!(language_name(gimli::DW_LANG_Go), "go");
    assert_eq!(language_name(gimli::DW_LANG_C_plus_plus_14), "cpp");
}

#[test]
fn language_name_unknown_falls_through() {
    assert_eq!(language_name(DwLang(0xC000)), "unknown");
}

/// Units all share one abbreviation whose root declares 50 000
/// zero-width attributes after a `.debug_str` producer that runs 64 KiB
/// without a NUL. Re-parsing the table, walking every attribute and
/// scanning the string per unit was `units × (table + run)`; each is now
/// paid once or capped, and the facts survive.
#[test]
fn shared_abbreviation_and_string_cost_once_per_file() {
    const UNITS: usize = 5000;
    let mut abbrev = vec![1, 0x11, 0]; // code 1: DW_TAG_compile_unit, no children
    abbrev.extend([0x25, 0x0e]); // DW_AT_producer, DW_FORM_strp
    for _ in 0..50_000 {
        abbrev.extend([0x80, 0x40, 0x19]); // DW_AT 0x2000, DW_FORM_flag_present
    }
    abbrev.extend([0, 0, 0]);
    let mut info = Vec::new();
    for _ in 0..UNITS {
        info.extend(12u32.to_le_bytes()); // unit_length
        info.extend(4u16.to_le_bytes()); // DWARF 4
        info.extend(0u32.to_le_bytes()); // debug_abbrev_offset
        info.push(8); // address size
        info.push(1); // root DIE, abbreviation 1
        info.extend(0u32.to_le_bytes()); // DW_AT_producer strp
    }
    let strs = vec![b'p'; 64 * 1024];
    let sections = DwarfSections {
        endian: RunTimeEndian::Little,
        info: &info,
        abbrev: &abbrev,
        str: &strs,
        line_str: &[],
    };
    let mut values = Values::new();
    let mut metrics = Metrics::default();
    emit_units(&sections, &mut values, &mut metrics);
    assert_eq!(metrics.get("elf.dwarf.cu_count"), Some(UNITS as f64));
    let producers = values
        .get("elf.dwarf.producers")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(producers.len(), 1);
    assert_eq!(producers[0].as_str().unwrap().len(), MAX_ATTR_STRING);
}

/// Each unit's table is parsed from a slice ending where the next unit's
/// table starts, so units at successive offsets into one unterminated
/// table do not each parse the rest of it; honest tables parse the same.
#[test]
fn abbreviation_tables_end_at_the_next_table() {
    // Table A at 0: code 1 = compile_unit with DW_AT_name/DW_FORM_string,
    // terminated. Table B follows: code 1 = compile_unit with
    // DW_AT_comp_dir/DW_FORM_string.
    let mut abbrev = vec![1, 0x11, 0, 0x03, 0x08, 0, 0, 0];
    let b_start = abbrev.len() as u32;
    abbrev.extend([1, 0x11, 0, 0x1b, 0x08, 0, 0, 0]);
    let mut info = Vec::new();
    for (table, text) in [(0, b"main.c\0"), (b_start, b"/build\0")] {
        info.extend((7 + text.len() as u32 + 1).to_le_bytes());
        info.extend(4u16.to_le_bytes());
        info.extend(table.to_le_bytes());
        info.push(8);
        info.push(1);
        info.extend_from_slice(text);
    }
    let sections = DwarfSections {
        endian: RunTimeEndian::Little,
        info: &info,
        abbrev: &abbrev,
        str: &[],
        line_str: &[],
    };
    let mut values = Values::new();
    let mut metrics = Metrics::default();
    emit_units(&sections, &mut values, &mut metrics);
    assert_eq!(
        values.get("elf.dwarf.source_files"),
        Some(&serde_json::json!(["main.c"]))
    );
    assert_eq!(
        values.get("elf.dwarf.comp_dirs"),
        Some(&serde_json::json!(["/build"]))
    );
}

/// A big-endian ELF's DWARF is read in its own byte order rather than
/// skipped.
#[test]
fn big_endian_units_are_read() {
    let abbrev = [1u8, 0x11, 0, 0x03, 0x08, 0, 0, 0];
    let mut info = Vec::new();
    info.extend(15u32.to_be_bytes()); // unit_length
    info.extend(4u16.to_be_bytes()); // DWARF 4
    info.extend(0u32.to_be_bytes()); // debug_abbrev_offset
    info.push(4); // address size
    info.push(1); // root DIE, abbreviation 1
    info.extend_from_slice(b"main.c\0");
    let sections = DwarfSections {
        endian: RunTimeEndian::Big,
        info: &info,
        abbrev: &abbrev,
        str: &[],
        line_str: &[],
    };
    let mut values = Values::new();
    let mut metrics = Metrics::default();
    emit_units(&sections, &mut values, &mut metrics);
    assert_eq!(metrics.get("elf.dwarf.cu_count"), Some(1.0));
    assert_eq!(
        values.get("elf.dwarf.source_files"),
        Some(&serde_json::json!(["main.c"]))
    );
}

/// A compressed stream that does not decode is recorded, not parsed.
#[test]
fn undecodable_compressed_section_is_recorded() {
    let mut errors = Errors::new();
    assert_eq!(
        inflate(
            ".debug_info",
            ELFCOMPRESS_ZLIB,
            b"not zlib",
            64,
            &mut errors
        ),
        None
    );
    assert_eq!(errors.len(), 1);
    assert_eq!(inflate(".debug_info", 99, b"", 0, &mut errors), None);
    assert_eq!(
        errors.len(),
        1,
        "an unknown compression is skipped, not an error"
    );
}
