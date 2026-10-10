use super::*;

fn read_fixture(name: &str) -> Vec<u8> {
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

#[test]
fn import_walk_budget_accepts_a_real_pe() {
    let bytes = read_fixture("test.exe");
    let pe = PE::parse(&bytes).expect("fixture PE");
    assert!(!pe.imports.is_empty());
    assert!(
        import_walk_budget_from_headers(&bytes).is_ok(),
        "a linker-produced import table must stay within budget"
    );
    let parse = parse_pe(&bytes);
    assert_eq!(parse.imports_skipped, None);
    assert_eq!(
        parse.outcome.ok().expect("fixture parses").imports.len(),
        pe.imports.len()
    );
}

#[test]
fn import_walk_budget_rejects_too_many_descriptors() {
    let bytes = pe_with_forged_import_directory(MAX_IMPORT_DESCRIPTORS + 1, false);
    let err = import_walk_budget_from_headers(&bytes).expect_err("descriptor cap must trip");
    assert_eq!(err, Rejection::UnterminatedImportDirectory);
}

/// The quadratic the bound exists for: a descriptor count a cap on
/// descriptors alone would wave through, each re-walking a lookup table
/// hundreds of thousands of entries long.
#[test]
fn import_walk_budget_rejects_oversized_lookup_tables() {
    let bytes = pe_with_forged_import_directory(8, true);
    let err = import_walk_budget_from_headers(&bytes).expect_err("entry budget must trip");
    assert_eq!(err, Rejection::OversizedImportLookupTables);
}

/// A PE whose import directory is well formed enough for *strict* mode:
/// `descriptors` valid descriptors (a real name string, a resolvable
/// lookup table) that all share one lookup table of `entries` ordinal
/// imports. goblin's strict parse accepts it and materialises
/// `descriptors * entries` imports, so the budget has to run first.
fn pe_with_shared_ordinal_lookup_table(descriptors: usize, entries: usize) -> Vec<u8> {
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
fn parse_pe_budgets_imports_before_the_strict_parse() {
    // Within budget, the shared-table shape still reaches strict goblin.
    let small = pe_with_shared_ordinal_lookup_table(4, 8);
    let parse = parse_pe(&small);
    assert_eq!(parse.imports_skipped, None);
    let pe = parse
        .outcome
        .ok()
        .expect("strict parse of the small fixture");
    assert_eq!(pe.imports.len(), 32, "4 descriptors x 8 entries");

    // 200 x 2000 = 400k imports from 16 KiB of table: refused up front.
    let big = pe_with_shared_ordinal_lookup_table(200, 2000);
    let parse = parse_pe(&big);
    assert_eq!(
        parse.imports_skipped,
        Some(Rejection::OversizedImportLookupTables)
    );
    let pe = parse
        .outcome
        .ok()
        .expect("headers and sections still parse");
    assert!(pe.imports.is_empty());
}

/// The bound has to be wired into `parse_pe`, not merely available: a
/// forged table must cost the imports and nothing else.
#[test]
fn parse_pe_drops_a_forged_import_table_and_keeps_the_rest() {
    let bytes = pe_with_forged_import_directory(8, true);
    let parse = parse_pe(&bytes);
    assert_eq!(
        parse.imports_skipped,
        Some(Rejection::OversizedImportLookupTables),
        "parse_pe must report the abandoned import table"
    );
    let pe = parse
        .outcome
        .ok()
        .expect("headers and sections still parse");
    assert!(
        pe.imports.is_empty(),
        "the forged import table must not be synthesized"
    );
    assert!(
        !pe.sections.is_empty(),
        "dropping imports must not cost us the section table"
    );
    assert!(
        pe.header.optional_header.is_some(),
        "dropping imports must not cost us the optional header"
    );
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

#[test]
fn validate_rejects_oversized_import_table() {
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
    let import_size_ptr = 0x40 + 24 + 96 + 8 + 4;
    data[import_size_ptr + 3] = 0x01; // size = 16 MiB (>10 MiB cap)
    assert_eq!(
        validate_pe_header(&data),
        Err(Rejection::OversizedDirectory {
            table: "import",
            size: 16 << 20,
        })
    );
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
            Rejection::UnterminatedImportDirectory,
            "import directory exceeds 256 descriptors without terminating",
        ),
        (
            Rejection::OversizedImportLookupTables,
            "import lookup tables exceed 262144 entries",
        ),
        (
            Rejection::OversizedImportNames,
            "import names exceed 33554432 bytes",
        ),
        (
            Rejection::OversizedExportNames,
            "export names exceed 33554432 bytes",
        ),
        (
            Rejection::ExportTrieLoop {
                node: 0x20,
                start: 0x10,
                end: 0x40,
            },
            "export trie loops back to node 0x20 (trie 0x10..0x40)",
        ),
        (
            Rejection::ExportTrieBranches {
                node: 0,
                branches: 100,
                available: 4,
            },
            "export trie node 0x0 claims 100 branches in 4 bytes",
        ),
        (
            Rejection::ExportTrieTooDeep {
                node: 0x380,
                depth: 129,
            },
            "export trie reaches node 0x380 at depth 129, past 128",
        ),
        (
            Rejection::OversizedBindStream {
                stream: "lazy",
                imports: 262_145,
            },
            "lazy bind opcodes declare at least 262145 imports, past 262144",
        ),
    ] {
        assert_eq!(reason.to_string(), text);
    }
}

/// The last section of `test.exe` grown to `size` zeroed bytes. Returns the
/// bytes with the section's RVA and file offset.
fn pe_with_last_section(size: usize) -> (Vec<u8>, u32, usize) {
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

/// One import descriptor whose `entries` lookup entries all name the same
/// hint/name entry, a name `name_len` bytes long. Every entry is well formed,
/// so the entry budget alone waves it through.
fn pe_with_long_import_names(entries: usize, name_len: usize) -> Vec<u8> {
    let dll_at = 2 * 20;
    let table_at = dll_at + 8;
    let hint_at = table_at + (entries + 1) * 8;
    let (mut bytes, va, pointer) = pe_with_last_section(hint_at + 2 + name_len + 1);
    let (_, _, import_dir) = pe_layout(&bytes);
    bytes[pointer + dll_at..pointer + dll_at + 6].copy_from_slice(b"a.dll\0");
    for i in 0..entries {
        let at = pointer + table_at + i * 8;
        bytes[at..at + 8].copy_from_slice(&u64::from(va + hint_at as u32).to_le_bytes());
    }
    bytes[pointer + hint_at + 2..pointer + hint_at + 2 + name_len].fill(b'x');
    let table_rva = va + table_at as u32;
    put_u32(&mut bytes, pointer, table_rva); // import_lookup_table_rva
    put_u32(&mut bytes, pointer + 12, va + dll_at as u32); // name_rva
    put_u32(&mut bytes, pointer + 16, table_rva); // import_address_table_rva
    put_u32(&mut bytes, import_dir, va);
    put_u32(&mut bytes, import_dir + 4, 40);
    bytes
}

/// A quarter-million lookup entries are within the entry budget, but each
/// makes goblin scan its name afresh and filefacts copy it: entries times
/// name length, quadratic in the file size. The names are budgeted too.
#[test]
fn import_walk_budget_rejects_oversized_names() {
    let small = pe_with_long_import_names(4, 1 << 20);
    assert_eq!(import_walk_budget_from_headers(&small), Ok(()));
    let parse = parse_pe(&small);
    assert_eq!(parse.imports_skipped, None);
    assert_eq!(parse.outcome.ok().expect("parses").imports.len(), 4);

    // 64 entries x 1 MiB of name: 64 MiB to scan and copy from a 1 MiB file.
    let big = pe_with_long_import_names(64, 1 << 20);
    assert_eq!(
        import_walk_budget_from_headers(&big),
        Err(Rejection::OversizedImportNames)
    );
    let parse = parse_pe(&big);
    assert_eq!(parse.imports_skipped, Some(Rejection::OversizedImportNames));
    assert!(parse.outcome.ok().expect("parses").imports.is_empty());
}

/// An export table of `pointers` name pointers. With `forwarded`, every
/// name is short and every entry forwards through one `long`-byte string
/// inside the export directory; otherwise every pointer names that string.
fn pe_with_export_table(pointers: usize, long: usize, forwarded: bool) -> Vec<u8> {
    let eat_at = 40;
    let names_at = eat_at + 4;
    let ordinals_at = names_at + 4 * pointers;
    let short_at = ordinals_at + 2 * pointers;
    let long_at = short_at + 4;
    let size = long_at + long + 1;
    let (mut bytes, va, pointer) = pe_with_last_section(size);
    let (_, _, import_dir) = pe_layout(&bytes);
    let export_dir = import_dir - 8;
    let rva = |at: usize| va + at as u32;
    put_u32(&mut bytes, pointer + 20, 1); // address_table_entries
    put_u32(&mut bytes, pointer + 24, pointers as u32); // number_of_name_pointers
    put_u32(&mut bytes, pointer + 28, rva(eat_at));
    put_u32(&mut bytes, pointer + 32, rva(names_at));
    put_u32(&mut bytes, pointer + 36, rva(ordinals_at));
    let (target, name) = if forwarded {
        (rva(long_at), rva(short_at))
    } else {
        (rva(short_at), rva(long_at))
    };
    put_u32(&mut bytes, pointer + eat_at, target);
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
        assert!(neutralize_oversized_export_directory(&small).is_none());
        let pe = parse_pe(&small).outcome.ok().expect("parses");
        assert_eq!(pe.exports.len(), 4);

        // 64 pointers x 1 MiB: 64 MiB of strings from a 1 MiB file.
        let big = pe_with_export_table(64, 1 << 20, forwarded);
        let (patched, reason) =
            neutralize_oversized_export_directory(&big).expect("export budget must trip");
        assert_eq!(reason, Rejection::OversizedExportNames);
        assert_eq!(patched.len(), big.len());
        let pe = parse_pe(&patched).outcome.ok().expect("parses");
        assert!(pe.exports.is_empty());
        assert!(!pe.sections.is_empty(), "everything else still parses");
    }
    assert!(neutralize_oversized_export_directory(&read_fixture("test.exe")).is_none());
    assert!(neutralize_oversized_export_directory(b"not a PE").is_none());
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
    .ok()
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
fn catch_infallible_handles_clean_value() {
    let result: GoblinOutcome<&str> = catch_infallible(|| "ok");
    assert!(matches!(result, GoblinOutcome::Ok("ok")));
}

#[test]
fn catch_infallible_catches_lazy_walker_panic() {
    let result: GoblinOutcome<()> = catch_infallible(|| panic!("walker tripped"));
    match result {
        GoblinOutcome::Panicked(msg) => assert!(msg.contains("walker tripped")),
        other => panic!("expected Panicked, got {other:?}"),
    }
}

/// A guard nested inside another must hand suppression back to the outer
/// one: resetting the flag to `false` used to let the outer closure's later
/// panics reach the user's hook.
#[test]
fn nested_guards_restore_the_outer_suppression() {
    let flag = || SUPPRESS_PANIC_OUTPUT.with(Cell::get);
    assert!(!flag());
    let outer = catch_infallible(|| {
        let inner: GoblinOutcome<()> = catch_infallible(|| panic!("inner"));
        assert!(matches!(inner, GoblinOutcome::Panicked(_)));
        flag()
    });
    assert!(matches!(outer, GoblinOutcome::Ok(true)));
    assert!(!flag(), "the outermost guard clears it again");
}

#[test]
fn parse_pe_rejects_garbage() {
    let result = parse_pe(b"not a PE file at all").outcome;
    match result {
        GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_) => {}
        other => panic!("expected failure, got {other:?}"),
    }
}

#[test]
fn parse_pe_short_input_falls_through_to_goblin() {
    // Below the 64-byte gate, validate_pe_header returns Ok and
    // we hand the bytes straight to goblin, which fails cleanly.
    let result = parse_pe(&[0u8; 16]).outcome;
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

/// A two-node trie as a linker emits it: a non-terminal root with one
/// edge `_a` to a terminal leaf (flags 0, address 0x10, no children).
const WELL_FORMED_TRIE: &[u8] = &[
    0x00, 0x01, b'_', b'a', 0x00, 0x06, // root @0: 1 branch, child @6
    0x02, 0x00, 0x10, 0x00, // leaf @6: terminal, no children
];

#[test]
fn export_trie_accepts_well_formed() {
    assert!(validate_export_trie_bytes(WELL_FORMED_TRIE, 0, WELL_FORMED_TRIE.len()).is_ok());
    // Embedded past a header, as in a real file.
    let mut file = vec![0xAAu8; 64];
    file.extend_from_slice(WELL_FORMED_TRIE);
    assert!(validate_export_trie_bytes(&file, 64, WELL_FORMED_TRIE.len()).is_ok());
}

/// The leptris shape: the root's only edge points back at the root, so
/// goblin's walk never ends. llvm-objdump: "loop in children in export
/// trie data at node: 0x0 back to node: 0x0".
#[test]
fn export_trie_rejects_root_self_loop() {
    let trie = [0x00, 0x01, b'_', b'a', 0x00, 0x00];
    let err = validate_export_trie_bytes(&trie, 0, trie.len()).expect_err("loop must trip");
    assert!(
        matches!(err, Rejection::ExportTrieLoop { node: 0, .. }),
        "unexpected reason: {err}"
    );
}

#[test]
fn export_trie_rejects_deep_cycle() {
    // root -> leaf, and the leaf (terminal with one child) points at root.
    let trie = [
        0x00, 0x01, b'_', b'a', 0x00, 0x06, // root @0 -> @6
        0x02, 0x00, 0x10, 0x01, b'b', 0x00, 0x00, // leaf @6, 1 child -> @0
    ];
    assert!(validate_export_trie_bytes(&trie, 0, trie.len()).is_err());
}

#[test]
fn export_trie_rejects_forged_branch_count() {
    // Root claims 100 branches in a 6-byte trie.
    let trie = [0x00, 0x64, b'_', b'a', 0x00, 0x06];
    let err = validate_export_trie_bytes(&trie, 0, trie.len()).expect_err("count must trip");
    assert!(
        matches!(err, Rejection::ExportTrieBranches { branches: 100, .. }),
        "unexpected reason: {err}"
    );
}

#[test]
fn export_trie_waves_through_what_goblin_rejects() {
    // Range past the file: goblin treats it as an empty trie.
    assert!(validate_export_trie_bytes(WELL_FORMED_TRIE, 4, 100).is_ok());
    assert!(validate_export_trie_bytes(&[], 0, 0).is_ok());
    // Truncated ULEB / label: goblin's own Err is the report.
    assert!(validate_export_trie_bytes(&[0x00, 0x01, b'_'], 0, 3).is_ok());
    assert!(validate_export_trie_bytes(&[0x80], 0, 1).is_ok());
}

/// A straight chain of `depth` non-terminal nodes, each with one edge `a`, and
/// a terminal leaf at the bottom. Acyclic, so only a depth bound catches it.
pub(crate) fn chain_trie(depth: usize) -> Vec<u8> {
    let mut trie = Vec::new();
    for _ in 0..depth {
        // Three-byte child ULEB so every node is the same seven bytes.
        let child = trie.len() + 7;
        assert!(child < 1 << 21);
        trie.extend_from_slice(&[0x00, 0x01, b'a', 0x00]);
        trie.extend_from_slice(&[
            (child as u8 & 0x7f) | 0x80,
            ((child >> 7) as u8 & 0x7f) | 0x80,
            (child >> 14) as u8,
        ]);
    }
    trie.extend_from_slice(&[0x02, 0x00, 0x10, 0x00]);
    trie
}

/// A minimal 64-bit Mach-O executable whose only load command is an
/// `LC_DYLD_INFO_ONLY` pointing at `bind` and `export` in the file.
pub(crate) fn macho_with_dyld_info(bind: &[u8], export: &[u8]) -> Vec<u8> {
    const HEADER: usize = 32;
    const DYLD_INFO: usize = 48;
    let bind_off = HEADER + DYLD_INFO;
    let export_off = bind_off + bind.len();
    let mut file = Vec::new();
    for word in [
        0xfeed_facf_u32,
        0x0100_0007,
        3,
        2,
        1,
        DYLD_INFO as u32,
        0,
        0,
    ] {
        file.extend_from_slice(&word.to_le_bytes());
    }
    let fields = [
        0x8000_0022_u32, // LC_DYLD_INFO_ONLY
        DYLD_INFO as u32,
        0,
        0, // rebase
        bind_off as u32,
        bind.len() as u32,
        0,
        0, // weak bind
        0,
        0, // lazy bind
        export_off as u32,
        export.len() as u32,
    ];
    for word in fields {
        file.extend_from_slice(&word.to_le_bytes());
    }
    file.extend_from_slice(bind);
    file.extend_from_slice(export);
    file
}

/// Run `f` on a thread with a 2 MiB stack, the size of a Rayon worker's.
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("join")
}

#[test]
fn export_trie_rejects_a_chain_past_the_depth_limit() {
    let trie = chain_trie(MAX_EXPORT_TRIE_DEPTH);
    let err = validate_export_trie_bytes(&trie, 0, trie.len()).expect_err("depth must trip");
    assert!(
        matches!(err, Rejection::ExportTrieTooDeep { depth, .. } if depth == MAX_EXPORT_TRIE_DEPTH + 1),
        "unexpected reason: {err}"
    );
    // A chain 5000 deep overflows goblin's recursive walk on a 2 MiB stack;
    // the validator refuses it before goblin ever sees it.
    let deep = macho_with_dyld_info(&[], &chain_trie(5000));
    on_small_stack(move || {
        let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&deep) else {
            panic!("fixture must parse");
        };
        assert!(matches!(
            validate_export_trie(&macho, &deep),
            Err(Rejection::ExportTrieTooDeep { .. })
        ));
    });
}

#[test]
fn export_trie_at_the_depth_limit_is_walkable_on_a_worker_stack() {
    let file = macho_with_dyld_info(&[], &chain_trie(MAX_EXPORT_TRIE_DEPTH - 1));
    let exports = on_small_stack(move || {
        let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&file) else {
            panic!("fixture must parse");
        };
        validate_export_trie(&macho, &file).expect("within the limit");
        match catch(|| macho.exports()) {
            GoblinOutcome::Ok(exports) => exports.len(),
            other => panic!("goblin walk failed: {:?}", other.ok().map(|e| e.len())),
        }
    });
    assert_eq!(exports, 1);
}

#[test]
fn bind_opcodes_with_a_forged_repeat_count_are_refused() {
    // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, count 2^32 - 1, skip 0.
    let bind = [0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00];
    let file = macho_with_bind_tables(&bind);
    let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&file) else {
        panic!("fixture must parse");
    };
    let err = validate_bind_opcodes(&macho, &file).expect_err("count must trip");
    assert!(
        matches!(err, Rejection::OversizedBindStream { stream: "bind", imports } if imports == u64::from(u32::MAX)),
        "unexpected reason: {err}"
    );
}

#[test]
fn bind_opcodes_within_budget_reach_goblin_unchanged() {
    // Set symbol `_a`, ordinal 1, segment 0 offset 0, then bind it three
    // times: DO_BIND, DO_BIND_ADD_ADDR_IMM_SCALED, and a ULEB repeat of 1.
    let bind = [
        0x11, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0xB1, 0xC0, 0x01, 0x00, 0x00,
    ];
    let file = macho_with_bind_tables(&bind);
    let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&file) else {
        panic!("fixture must parse");
    };
    assert_eq!(count_bind_imports(&file, 192, 192 + bind.len(), 0), 3);
    assert!(validate_bind_opcodes(&macho, &file).is_ok());
    assert_eq!(macho.imports().expect("goblin binds them").len(), 3);
    // Truncated operands are goblin's to reject: the count stops there.
    assert_eq!(count_bind_imports(&[0x90, 0xA0, 0x80], 0, 3, 0), 2);
    assert_eq!(count_bind_imports(&[0xC0, 0x05], 0, 2, 0), 0);
}

/// goblin indexes `libs[ordinal]` and `segments[segment]` for every import
/// it builds, unchecked: a bind through a dylib ordinal or segment past the
/// binary's tables panicked inside it (found by fuzzing). The walk refuses
/// such a stream before goblin runs it.
#[test]
fn bind_opcodes_past_the_dylib_or_segment_tables_are_refused() {
    // Symbol `_a`, then ordinal 2 (only `self` and one dylib exist).
    let ordinal = [0x12, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00];
    // Ordinal 1, but segment 3 of the one segment.
    let segment = [0x11, 0x40, b'_', b'a', 0x00, 0x73, 0x00, 0x90, 0x00];
    // A ULEB ordinal goblin truncates to its low byte: 0x102 is ordinal 2.
    let wrapped = [
        0x20, 0x82, 0x02, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00,
    ];
    for (bind, table, index, len) in [
        (&ordinal[..], "dylib ordinal", 2, 2),
        (&segment[..], "segment", 3, 1),
        (&wrapped[..], "dylib ordinal", 2, 2),
    ] {
        let file = macho_with_bind_tables(bind);
        let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&file) else {
            panic!("fixture must parse");
        };
        let err = validate_bind_opcodes(&macho, &file).expect_err("index must trip");
        assert!(
            matches!(err, Rejection::BindIndexOutOfRange { stream: "bind", table: t, index: i, len: l }
                if t == table && i == index && l == len),
            "unexpected reason: {err}"
        );
        // goblin itself panics on it.
        assert!(matches!(
            catch(|| macho.imports()),
            GoblinOutcome::Panicked(_)
        ));
    }
    // A `DONE` resets the ordinal; a zero repeat count binds nothing.
    let reset = [0x12, 0x00, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00];
    let empty_repeat = [
        0x12, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0xC0, 0x00, 0x00, 0x00,
    ];
    for bind in [&reset[..], &empty_repeat[..]] {
        let file = macho_with_bind_tables(bind);
        let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&file) else {
            panic!("fixture must parse");
        };
        assert!(validate_bind_opcodes(&macho, &file).is_ok(), "{bind:x?}");
    }
    // The table-less fixture has no segment at all.
    let file = macho_with_dyld_info(&ordinal, &[]);
    let GoblinOutcome::Ok(Mach::Binary(macho)) = parse_mach(&file) else {
        panic!("fixture must parse");
    };
    assert!(validate_bind_opcodes(&macho, &file).is_err());
}

/// A 64-bit Mach-O with one `__DATA` segment, one `LC_LOAD_DYLIB`
/// (`libx.dylib`, ordinal 1 after goblin's `self`), and `bind` as its bind
/// stream at file offset 192.
pub(crate) fn macho_with_bind_tables(bind: &[u8]) -> Vec<u8> {
    const SEGMENT: u32 = 72;
    const DYLIB: u32 = 40;
    const DYLD_INFO: u32 = 48;
    let bind_off = 32 + SEGMENT + DYLIB + DYLD_INFO;
    let mut file = Vec::new();
    let words = |file: &mut Vec<u8>, ws: &[u32]| {
        for w in ws {
            file.extend_from_slice(&w.to_le_bytes());
        }
    };
    words(
        &mut file,
        &[
            0xfeed_facf,
            0x0100_0007,
            3,
            2,
            3,
            SEGMENT + DYLIB + DYLD_INFO,
            0,
            0,
        ],
    );
    words(&mut file, &[0x19, SEGMENT]);
    file.extend_from_slice(b"__DATA\0\0\0\0\0\0\0\0\0\0");
    // vmaddr, vmsize, fileoff, filesize: no file bytes, so any file fits.
    for q in [0x1000_u64, 0x1000, 0, 0] {
        file.extend_from_slice(&q.to_le_bytes());
    }
    words(&mut file, &[3, 3, 0, 0]);
    words(&mut file, &[0x0c, DYLIB, 24, 0, 0, 0]);
    file.extend_from_slice(b"libx.dylib\0\0\0\0\0\0");
    words(
        &mut file,
        &[
            0x8000_0022,
            DYLD_INFO,
            0,
            0,
            bind_off,
            bind.len() as u32,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    assert_eq!(file.len(), bind_off as usize);
    file.extend_from_slice(bind);
    file
}

/// A header cut off inside `e_shstrndx`, the last field zeroed, used to
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
        let patched = elf_without_truncated_section_headers(&header).expect("detached");
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

#[test]
fn uleb128_matches_scroll() {
    let mut off = 0;
    assert_eq!(read_uleb128(&[0xE5, 0x8E, 0x26], &mut off), Some(624_485));
    assert_eq!(off, 3);
    let mut off = 0;
    assert_eq!(read_uleb128(&[0x80], &mut off), None);
    let mut off = 0;
    assert_eq!(read_uleb128(&[0xff; 11], &mut off), None);
}
