use super::*;
use std::borrow::Cow;

pub(crate) fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

/// Offsets into `test.exe` (PE32+): the section table and the import
/// data directory. Returned rather than hardcoded so the helpers below
/// keep working if the fixture is regenerated.
fn pe_layout(bytes: &[u8]) -> (usize, usize, usize) {
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_offset + 4;
    let sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_optional = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap());
    let optional = coff + 20;
    assert_eq!(
        u16::from_le_bytes(bytes[optional..optional + 2].try_into().unwrap()),
        0x20b,
        "fixture is expected to be PE32+"
    );
    let section_table = optional + size_of_optional as usize;
    // Data directory 1 is the import table; PE32+ puts the array at +112.
    let import_dir = optional + 112 + 8;
    (section_table, sections, import_dir)
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Build a PE whose import directory is a forgery.
///
/// The last section is grown to 3 MiB and filled with `0x11` bytes, which
/// is exactly the shape that drives goblin's permissive lookup-table walk:
/// non-zero (so the walk does not terminate), top bit clear (so the entry
/// is a name RVA rather than a cheap ordinal), and pointing at an RVA that
/// resolves to nothing (so each iteration takes the "bad RVA, skip entry"
/// branch — a `warn!` and a `continue`, with no allocation). That is the
/// loop the production worker was found spinning in.
///
/// `descriptors` 20-byte import descriptors are written at the section
/// start, followed by a null terminator. Each points its lookup table at
/// the `0x11` region when `long_lookup_tables`, giving the descriptor
/// count times ~390k entries of work; otherwise the lookup RVAs resolve to
/// nothing and each descriptor is individually cheap.
fn pe_with_forged_import_directory(descriptors: usize, long_lookup_tables: bool) -> Vec<u8> {
    const SECTION_SIZE: usize = 3 * 1024 * 1024;
    let mut bytes = read_fixture("test.exe");
    let (section_table, count, import_dir) = pe_layout(&bytes);
    let last = section_table + (count - 1) * 40;
    let virtual_address = u32::from_le_bytes(bytes[last + 12..last + 16].try_into().unwrap());
    let pointer = u32::from_le_bytes(bytes[last + 20..last + 24].try_into().unwrap()) as usize;

    bytes.resize(pointer + SECTION_SIZE, 0x11);
    bytes[pointer..pointer + SECTION_SIZE].fill(0x11);
    put_u32(&mut bytes, last + 8, SECTION_SIZE as u32); // virtual_size
    put_u32(&mut bytes, last + 16, SECTION_SIZE as u32); // size_of_raw_data

    // Lookup tables live past the descriptor array, in the 0x11 fill.
    let lookup_offset = (descriptors + 1) * 20;
    let lookup_rva = if long_lookup_tables {
        virtual_address + lookup_offset as u32
    } else {
        // Resolves to nothing, so goblin abandons this descriptor at once.
        0x1111_1111
    };
    for i in 0..descriptors {
        let at = pointer + i * 20;
        put_u32(&mut bytes, at, lookup_rva); // import_lookup_table_rva
        put_u32(&mut bytes, at + 4, 0); // time_date_stamp
        put_u32(&mut bytes, at + 8, 0); // forwarder_chain
        put_u32(&mut bytes, at + 12, 1); // name_rva: non-zero, unresolvable
        put_u32(&mut bytes, at + 16, 1); // import_address_table_rva
    }
    bytes[pointer + descriptors * 20..pointer + (descriptors + 1) * 20].fill(0);

    put_u32(&mut bytes, import_dir, virtual_address);
    put_u32(&mut bytes, import_dir + 4, 20); // declared size stays sane
    bytes
}

/// goblin never walks the import table: a real one costs nothing, and a
/// forged one, quadratic in the file size to walk, is not read at all. The
/// rest of the image parses, and the certificate table is not parsed either.
#[test]
fn parse_pe_skips_the_import_walk() {
    let bytes = read_fixture("test.exe");
    let prepared = prepare_pe(&bytes);
    assert!(
        matches!(prepared.bytes, Cow::Borrowed(_)),
        "a clean PE costs no copy"
    );
    let pe = parse_pe(&prepared).ok().expect("fixture parses");
    assert!(pe.imports.is_empty() && pe.libraries.is_empty() && pe.import_data.is_none());
    assert!(!pe.sections.is_empty());

    for forged in [
        pe_with_forged_import_directory(MAX_FORGED_DESCRIPTORS, true),
        pe_with_shared_ordinal_lookup_table(512, 64 * 1024),
    ] {
        let prepared = prepare_pe(&forged);
        let pe = parse_pe(&prepared)
            .ok()
            .expect("headers and sections parse");
        assert!(pe.imports.is_empty());
        assert!(!pe.sections.is_empty());
        assert!(pe.header.optional_header.is_some());
    }
}

/// Descriptors in the forged import directory: past any real table.
const MAX_FORGED_DESCRIPTORS: usize = 300;

/// A PE whose import directory is well formed enough for *strict* mode:
/// `descriptors` valid descriptors (a real name string, a resolvable
/// lookup table) that all share one lookup table of `entries` ordinal
/// imports. goblin's strict parse accepts it and materialises
/// `descriptors * entries` imports, so the budget has to run first.
pub(crate) fn pe_with_shared_ordinal_lookup_table(descriptors: usize, entries: usize) -> Vec<u8> {
    let mut bytes = read_fixture("test.exe");
    let (section_table, count, import_dir) = pe_layout(&bytes);
    let last = section_table + (count - 1) * 40;
    let virtual_address = u32::from_le_bytes(bytes[last + 12..last + 16].try_into().unwrap());
    let pointer = u32::from_le_bytes(bytes[last + 20..last + 24].try_into().unwrap()) as usize;
    let name_at = (descriptors + 1) * 20;
    let table_at = name_at + 16;
    let size = table_at + (entries + 1) * 8;
    bytes.resize(pointer + size, 0);
    bytes[pointer..pointer + size].fill(0);
    put_u32(&mut bytes, last + 8, size as u32); // virtual_size
    put_u32(&mut bytes, last + 16, size as u32); // size_of_raw_data
    bytes[pointer + name_at..pointer + name_at + 6].copy_from_slice(b"a.dll\0");
    for i in 0..entries {
        // PE32+ ordinal import: top bit set, ordinal in the low 16 bits.
        let at = pointer + table_at + i * 8;
        bytes[at..at + 8].copy_from_slice(&(0x8000_0000_0000_0001_u64).to_le_bytes());
    }
    let table_rva = virtual_address + table_at as u32;
    for i in 0..descriptors {
        let at = pointer + i * 20;
        put_u32(&mut bytes, at, table_rva); // import_lookup_table_rva
        put_u32(&mut bytes, at + 12, virtual_address + name_at as u32); // name_rva
        put_u32(&mut bytes, at + 16, table_rva); // import_address_table_rva
    }
    put_u32(&mut bytes, import_dir, virtual_address);
    put_u32(&mut bytes, import_dir + 4, ((descriptors + 1) * 20) as u32);
    bytes
}

#[test]
fn validate_rejects_oversized_section_count() {
    let mut data = vec![0u8; 1024];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x40;
    data[0x40] = b'P';
    data[0x41] = b'E';
    // n_sections = 0x00FF = 255 (>192 threshold).
    data[0x46] = 0xFF;
    assert_eq!(
        validate_pe_header(&data),
        Err(Rejection::TooManySections(255))
    );
}

/// A forged resource size skips goblin's resource walk but keeps the rest of
/// the parse (Enigma-protected images declare one); an import size is
/// ignored, since goblin no longer walks the import table.
#[test]
fn oversized_resource_table_skips_resources_only() {
    let header = |directory: usize| {
        let mut data = vec![0u8; 1024];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x46] = 1; // n_sections = 1
        data[0x58] = 0x0B;
        data[0x59] = 0x01; // PE32 magic
        data[0x40 + 24 + 92] = 16; // n_dirs = 16
        let size_ptr = 0x40 + 24 + 96 + 8 * directory + 4;
        data[size_ptr + 3] = 0x01; // size = 16 MiB (>10 MiB cap)
        data
    };
    assert_eq!(validate_pe_header(&header(RESOURCE_DIRECTORY)), Ok(()));
    assert_eq!(
        oversized_resource_directory(&header(RESOURCE_DIRECTORY)),
        Some(Rejection::OversizedDirectory {
            table: "resource",
            size: 16 << 20,
        })
    );
    assert_eq!(oversized_resource_directory(&header(1)), None);
}

/// The reasons land verbatim in the structured errors view, so the typed
/// enum must render exactly the text the old `String` reasons carried.
#[test]
fn rejection_messages_are_unchanged() {
    for (reason, text) in [
        (Rejection::TooManySections(255), "too many sections (255)"),
        (
            Rejection::TooManyDataDirectories(17),
            "too many data directories (17)",
        ),
        (
            Rejection::OversizedDirectory {
                table: "resource",
                size: 16 << 20,
            },
            "malformed resource table size (16777216 bytes)",
        ),
        (
            Rejection::OversizedExportNames,
            "export names exceed 33554432 bytes",
        ),
        (
            Rejection::DeepResourceTree,
            "resource directories nested past 8 levels",
        ),
    ] {
        assert_eq!(reason.to_string(), text);
    }
}

/// The last section of `test.exe` grown to `size` zeroed bytes. Returns the
/// bytes with the section's RVA and file offset.
pub(crate) fn pe_with_last_section(size: usize) -> (Vec<u8>, u32, usize) {
    let mut bytes = read_fixture("test.exe");
    let (section_table, count, _) = pe_layout(&bytes);
    let last = section_table + (count - 1) * 40;
    let virtual_address = u32::from_le_bytes(bytes[last + 12..last + 16].try_into().unwrap());
    let pointer = u32::from_le_bytes(bytes[last + 20..last + 24].try_into().unwrap()) as usize;
    bytes.resize(pointer + size, 0);
    bytes[pointer..pointer + size].fill(0);
    put_u32(&mut bytes, last + 8, size as u32); // virtual_size
    put_u32(&mut bytes, last + 16, size as u32); // size_of_raw_data
    (bytes, virtual_address, pointer)
}

/// An export table of `pointers` name pointers. With `forwarded`, every
/// name is short and every entry forwards through one `long`-byte string
/// inside the export directory; otherwise every pointer names that string.
fn pe_with_export_table(pointers: usize, long: usize, forwarded: bool) -> Vec<u8> {
    pe_with_exports(1, pointers, long, forwarded)
}

/// [`pe_with_export_table`] with `functions` address-table entries, all at
/// one address: every export aliases the first.
pub(crate) fn pe_with_exports(
    functions: usize,
    pointers: usize,
    long: usize,
    forwarded: bool,
) -> Vec<u8> {
    let eat_at = 40;
    let names_at = eat_at + 4 * functions;
    let ordinals_at = names_at + 4 * pointers;
    let short_at = ordinals_at + 2 * pointers;
    let long_at = short_at + 4;
    let size = long_at + long + 1;
    let (mut bytes, va, pointer) = pe_with_last_section(size);
    let (_, _, import_dir) = pe_layout(&bytes);
    let export_dir = import_dir - 8;
    let rva = |at: usize| va + at as u32;
    put_u32(&mut bytes, pointer + 20, functions as u32); // address_table_entries
    put_u32(&mut bytes, pointer + 24, pointers as u32); // number_of_name_pointers
    put_u32(&mut bytes, pointer + 28, rva(eat_at));
    put_u32(&mut bytes, pointer + 32, rva(names_at));
    put_u32(&mut bytes, pointer + 36, rva(ordinals_at));
    let (target, name) = if forwarded {
        (rva(long_at), rva(short_at))
    } else {
        (rva(short_at), rva(long_at))
    };
    for i in 0..functions {
        put_u32(&mut bytes, pointer + eat_at + 4 * i, target);
    }
    for i in 0..pointers {
        put_u32(&mut bytes, pointer + names_at + 4 * i, name);
    }
    bytes[pointer + short_at..pointer + short_at + 2].copy_from_slice(b"f\0");
    bytes[pointer + long_at..pointer + long_at + long].fill(b'x');
    bytes[pointer + long_at + 1] = b'.';
    put_u32(&mut bytes, export_dir, va);
    put_u32(
        &mut bytes,
        export_dir + 4,
        if forwarded { size as u32 } else { 40 },
    );
    bytes
}

/// goblin reads every export's name and forwarder string from scratch and
/// cannot be told to skip exports, so a table whose strings sum past the
/// budget is kept from it on a copy with the export directory cleared.
#[test]
fn oversized_export_names_are_kept_from_goblin() {
    for forwarded in [false, true] {
        let small = pe_with_export_table(4, 1 << 20, forwarded);
        let prepared = prepare_pe(&small);
        assert!(prepared.exports_skipped.is_none());
        let pe = parse_pe(&prepared).ok().expect("parses");
        assert_eq!(pe.exports.len(), 4);

        // 64 pointers x 1 MiB: 64 MiB of strings from a 1 MiB file.
        let big = pe_with_export_table(64, 1 << 20, forwarded);
        let prepared = prepare_pe(&big);
        assert_eq!(
            prepared.exports_skipped,
            Some(Rejection::OversizedExportNames),
            "export budget must trip"
        );
        assert_eq!(prepared.bytes.len(), big.len());
        let pe = parse_pe(&prepared).ok().expect("parses");
        assert!(pe.exports.is_empty());
        assert!(!pe.sections.is_empty(), "everything else still parses");
    }
    assert!(
        prepare_pe(&read_fixture("test.exe"))
            .exports_skipped
            .is_none()
    );
    assert!(prepare_pe(b"not a PE").exports_skipped.is_none());
}

#[test]
fn parse_pe_header_handles_garbage_and_real_headers() {
    assert!(matches!(
        parse_pe_header(b"not a PE file at all"),
        GoblinOutcome::Failed(_)
    ));
    let bytes = read_fixture("test.exe");
    let header = parse_pe_header(&bytes).ok().expect("fixture headers parse");
    assert!(header.optional_header.is_some());
}

#[test]
fn parse_macho_slice_handles_garbage_and_real_slices() {
    assert!(matches!(
        parse_macho_slice(b"not a Mach-O"),
        GoblinOutcome::Failed(_)
    ));
    let bytes = read_fixture("test.macho");
    let macho = parse_macho_slice(&bytes).ok().expect("thin fixture parses");
    assert!(!macho.load_commands.is_empty());
}

#[test]
fn drain_runs_a_lazy_walk_to_completion() {
    let bytes = read_fixture("test.elf");
    let elf = Elf::parse(&bytes).expect("fixture ELF");
    let notes = drain(
        elf.iter_note_headers(&bytes)
            .into_iter()
            .flatten()
            .flatten(),
    )
    .expect("note walk completes");
    // The fixture's single PT_NOTE carries its GNU build-id.
    assert_eq!(notes.len(), 1);
    assert_eq!((notes[0].name, notes[0].n_type), ("GNU", 3));
}

#[test]
fn drain_or_record_reports_a_walk_that_panics() {
    let walk = (0..4).map(|i| if i == 2 { panic!("walker tripped") } else { i });
    let mut errors = Errors::new();
    assert!(drain_or_record(walk, &mut errors, Stage::PeParse).is_empty());
    let recorded = errors.as_slice();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].stage, Stage::PeParse);
    assert!(recorded[0].message.contains("walker tripped"));

    let mut errors = Errors::new();
    assert_eq!(
        drain_or_record(0..3, &mut errors, Stage::PeParse),
        vec![0, 1, 2]
    );
    assert!(errors.as_slice().is_empty());
}

#[test]
fn validate_accepts_too_short_to_be_pe() {
    // Anything below 64 bytes can't possibly be a parseable PE;
    // hand the bytes to goblin without flagging.
    assert!(validate_pe_header(&[]).is_ok());
    assert!(validate_pe_header(&[0u8; 16]).is_ok());
}

#[test]
fn validate_accepts_non_pe_bytes() {
    // Bytes that don't start with MZ get through — the caller's
    // strict parse will report a clean error.
    let data = vec![0u8; 256];
    assert!(validate_pe_header(&data).is_ok());
}

#[test]
fn catch_returns_ok_for_passing_call() {
    let result: GoblinOutcome<i32> = catch(|| Ok(42));
    assert!(matches!(result, GoblinOutcome::Ok(42)));
}

#[test]
fn catch_returns_failed_on_error() {
    let result: GoblinOutcome<i32> = catch(|| Err(GoblinError::Malformed("nope".into())));
    assert!(matches!(result, GoblinOutcome::Failed(_)));
}

#[test]
fn catch_converts_panic_to_outcome() {
    let result: GoblinOutcome<i32> = catch(|| -> Result<i32, GoblinError> { panic!("boom") });
    match result {
        GoblinOutcome::Panicked(msg) => assert!(msg.contains("boom")),
        other => panic!("expected Panicked, got {other:?}"),
    }
}

#[test]
fn parse_pe_rejects_garbage() {
    let prepared = prepare_pe(b"not a PE file at all");
    let result = parse_pe(&prepared);
    match result {
        GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_) => {}
        other => panic!("expected failure, got {other:?}"),
    }
}

#[test]
fn parse_pe_short_input_falls_through_to_goblin() {
    // Below the 64-byte gate, validate_pe_header returns Ok and
    // we hand the bytes straight to goblin, which fails cleanly.
    let prepared = prepare_pe(&[0u8; 16]);
    let result = parse_pe(&prepared);
    assert!(matches!(
        result,
        GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_)
    ));
}

#[test]
fn parse_elf_handles_garbage() {
    let result = parse_elf(b"not an ELF");
    assert!(matches!(
        result,
        GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_)
    ));
}

#[test]
fn parse_mach_handles_garbage() {
    let result = parse_mach(b"not a Mach-O");
    assert!(matches!(
        result,
        GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_)
    ));
}

/// A header cut off inside `e_shstrndx`, the last field zeroed, must not
/// panic slicing the patched copy: every field the helper reads is in
/// bounds, but the one it then writes is not.
#[test]
fn elf_detach_rejects_header_truncated_in_shstrndx() {
    // (EI_CLASS, e_shoff, e_shentsize, e_shnum, e_shstrndx) offsets.
    for (class, shoff_at, shentsize_at, shnum_at, shstrndx_at) in
        [(2u8, 0x28, 0x3A, 0x3C, 0x3E), (1, 0x20, 0x2E, 0x30, 0x32)]
    {
        let mut header = vec![0u8; shstrndx_at + 2];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = class;
        header[5] = 1; // little-endian
        header[shoff_at] = 0x10;
        header[shentsize_at] = 0x40;
        header[shnum_at] = 5;
        header[shstrndx_at] = 3;
        // Section table at 0x10 + 5 * 0x40 ends past EOF: detach it.
        let detached = elf_without_truncated_section_headers(&header).expect("detached");
        assert_eq!((detached.shoff, detached.shstrndx), (0x10, 3));
        let patched = detached.bytes;
        assert_eq!(
            [patched[shoff_at], patched[shnum_at], patched[shstrndx_at]],
            [0, 0, 0]
        );
        assert_eq!(patched[shentsize_at], 0x40);
        for len in [shstrndx_at, shstrndx_at + 1] {
            assert_eq!(elf_without_truncated_section_headers(&header[..len]), None);
        }
    }
}

/// A PE whose `RT_VERSION` resource sits `levels` directories deep, each
/// directory claiming at least 32768 entries. The directories overlap at an
/// 8-byte stride: each one's entry count is the next one's first entry, and
/// its first entry leads on to the next. The last leads to an empty data
/// entry, so the tree is well formed and only its depth is forged.
fn pe_with_deep_resource_tree(levels: usize) -> Vec<u8> {
    const CHAIN: usize = 24;
    let slots = levels + 2;
    let data_entry = (CHAIN + 8 * slots + 16 + 8 * 65536).next_multiple_of(8);
    let size = data_entry + 16;
    let (mut bytes, va, pointer) = pe_with_last_section(size);
    let (_, _, import_dir) = pe_layout(&bytes);
    let resource_dir = import_dir + 8;
    // Root: one id entry, RT_VERSION, leading to the first chain directory.
    bytes[pointer + 14..pointer + 16].copy_from_slice(&1u16.to_le_bytes());
    put_u32(&mut bytes, pointer + 16, 16);
    put_u32(&mut bytes, pointer + 20, 0x8000_0000 | CHAIN as u32);
    for j in 1..slots {
        let target = if j == slots - 1 {
            data_entry as u32
        } else {
            0x8000_0000 | (CHAIN + 8 * (j - 1)) as u32
        };
        put_u32(&mut bytes, pointer + CHAIN + 8 * j + 4, target);
    }
    put_u32(&mut bytes, pointer + data_entry, va); // an empty RT_VERSION blob
    put_u32(&mut bytes, resource_dir, va);
    put_u32(&mut bytes, resource_dir + 4, size as u32);
    bytes
}

/// goblin follows each resource directory's first entry for as long as it
/// is a directory, collecting every entry of each on the way: a chain of
/// overlapping directories makes that walk quadratic in the resource size.
/// A tree deeper than the walk budget is kept from goblin; the rest of the
/// image parses.
#[test]
fn deep_resource_tree_is_kept_from_goblin() {
    let shallow = pe_with_deep_resource_tree(2);
    let prepared = prepare_pe(&shallow);
    let pe = parse_pe(&prepared).ok().expect("parses");
    assert!(pe.resource_data.is_some(), "a shallow tree is goblin's");

    let deep = pe_with_deep_resource_tree(4096);
    let prepared = prepare_pe(&deep);
    let pe = parse_pe(&prepared).ok().expect("parses");
    assert!(pe.resource_data.is_none(), "a deep tree is not walked");
    assert!(!pe.sections.is_empty(), "everything else still parses");
}

/// goblin decodes the *first* `Rich` marker in the DOS stub and fails the
/// whole parse, header-only included, when no `DanS` decodes under its key;
/// the loader never reads the stub. A decoy marker ahead of a genuine Rich
/// header must not cost the image its goblin facts.
#[test]
fn decoy_rich_marker_does_not_fail_the_parse() {
    let mut bytes = read_fixture("test.exe");
    assert!(
        matches!(parse_pe(&prepare_pe(&bytes)), GoblinOutcome::Ok(_)),
        "the fixture parses"
    );
    // `Rich` with a key no word of the stub decodes to `DanS` under.
    bytes[0x40..0x48].copy_from_slice(b"Rich\x11\x11\x11\x11");
    assert!(matches!(
        catch(|| goblin::pe::header::RichHeader::parse(&bytes)),
        GoblinOutcome::Failed(_)
    ));
    let prepared = prepare_pe(&bytes);
    assert!(matches!(parse_pe(&prepared), GoblinOutcome::Ok(_)));
    assert!(matches!(
        parse_pe_header(&prepared.bytes),
        GoblinOutcome::Ok(_)
    ));
}
