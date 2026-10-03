use super::*;
use crate::output::Strings;

#[test]
fn cpu_type_string_known() {
    assert_eq!(cpu_type_string(0x0100_0007), "x86_64");
    assert_eq!(cpu_type_string(0x0100_000c), "arm64");
    assert_eq!(cpu_type_string(0xffff_ffff), "unknown");
}

#[test]
fn macho_go_pclntab_magic_is_validated() {
    let pclntab = [0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08];
    assert!(crate::formats::go_buildinfo::has_pclntab_magic(&pclntab));
}

#[test]
fn macho_spoofed_pclntab_is_not_treated_as_go() {
    assert!(!crate::formats::go_buildinfo::has_pclntab_magic(
        b"not a real pclntab"
    ));
}

#[test]
fn file_type_string_known() {
    assert_eq!(file_type_string(0x2), "executable");
    assert_eq!(file_type_string(0x6), "dylib");
    assert_eq!(file_type_string(0xb), "kext_bundle");
}

#[test]
fn strip_darwin_symbol_variant_recovers_base() {
    // Darwin libc variant suffixes are stripped to the base symbol.
    assert_eq!(strip_darwin_symbol_variant("popen$DARWIN_EXTSN"), "popen");
    assert_eq!(strip_darwin_symbol_variant("write$UNIX2003"), "write");
    assert_eq!(strip_darwin_symbol_variant("stat$INODE64"), "stat");
    assert_eq!(strip_darwin_symbol_variant("open$NOCANCEL"), "open");
    assert_eq!(strip_darwin_symbol_variant("time$1050"), "time");
    // Chained variants collapse to the single base symbol.
    assert_eq!(
        strip_darwin_symbol_variant("close$NOCANCEL$UNIX2003"),
        "close"
    );
    // Plain symbols are untouched.
    assert_eq!(strip_darwin_symbol_variant("popen"), "popen");
    assert_eq!(
        strip_darwin_symbol_variant("_objc_msgSend"),
        "_objc_msgSend"
    );
    // Objective-C class/metaclass references (imported and exported) also
    // use `$`; they must survive, even when the class name is entirely
    // upper-case and so looks variant-shaped — the case a naive shape
    // heuristic truncates to `_OBJC_CLASS_`.
    assert_eq!(
        strip_darwin_symbol_variant("_OBJC_CLASS_$_NSURL"),
        "_OBJC_CLASS_$_NSURL"
    );
    assert_eq!(
        strip_darwin_symbol_variant("_OBJC_CLASS_$_ABC"),
        "_OBJC_CLASS_$_ABC"
    );
    assert_eq!(
        strip_darwin_symbol_variant("_OBJC_METACLASS_$_ABC"),
        "_OBJC_METACLASS_$_ABC"
    );
    // Linker directives (leading `$`) and unknown `$` tails are preserved.
    assert_eq!(
        strip_darwin_symbol_variant("$ld$hide$os10.4$_foo"),
        "$ld$hide$os10.4$_foo"
    );
    assert_eq!(strip_darwin_symbol_variant("foo$bar"), "foo$bar");
}

#[test]
fn load_command_name_strips_required_bit() {
    // LC_LOAD_DYLIB with `LC_REQ_DYLD` bit set
    assert_eq!(load_command_name(0x8000_000c), "LC_LOAD_DYLIB");
}

/// End-to-end coverage of the variant-suffix normalization through the
/// full `open()` pipeline, on a real Mach-O whose `LC_SYMTAB` records
/// libc calls under Darwin's `$`-variant spelling. The fixture is a live
/// (already-public) malware sample, so it is stored zstd-compressed — both
/// to keep it small and to keep an executable backdoor from sitting
/// unpacked in the tree where on-access scanners would quarantine it.
#[test]
fn open_normalizes_darwin_variant_import_names() {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/macho-darwin-variant-symbols.dylib.zst"
    ))
    .expect("fixture present");
    let bytes = zstd::decode_all(compressed.as_slice()).expect("fixture decompresses");

    let parsed = crate::open(&bytes);
    let imports: Vec<&str> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(!imports.is_empty(), "dylib imports should populate");

    // Variant suffixes are stripped to the base symbol.
    assert!(
        imports.contains(&"_popen"),
        "popen$DARWIN_EXTSN should normalize to _popen; got {imports:?}"
    );
    assert!(
        imports.contains(&"_fopen") && imports.contains(&"_fdopen"),
        "fopen/fdopen variants should normalize to their base names"
    );
    // No import retains a Darwin variant suffix.
    assert!(
        !imports.iter().any(|n| n.contains("$DARWIN_EXTSN")
            || n.contains("$UNIX2003")
            || n.contains("$INODE64")
            || n.contains("$NOCANCEL")),
        "no import should retain a Darwin variant suffix; got {imports:?}"
    );
    // Objective-C class references also contain `$` and must survive intact,
    // never truncated at the `$` to a bare `_OBJC_CLASS_`.
    assert!(
        imports.contains(&"_OBJC_CLASS_$_NSURL"),
        "ObjC class import must survive normalization intact"
    );
    assert!(
        !imports.contains(&"_OBJC_CLASS_") && !imports.contains(&"_OBJC_METACLASS_"),
        "ObjC class reference must not be truncated at its `$`"
    );
}

/// Regression test for a panic seen in the field: a small file
/// whose CAFEBABE prefix made goblin parse a fat header with
/// implausible arch offsets. The old slicing path computed
/// `&bytes[start..end]` where `start > bytes.len()` and panicked
/// with `range start index N out of range`. We now bail before
/// the slice and `extract` returns cleanly.
#[test]
fn fat_header_with_out_of_range_arch_offset_does_not_panic() {
    // CAFEBABE + nfat_arch=2 + two arch entries each claiming a
    // multi-gigabyte offset/size. Mirrors junk Java `.class` files
    // misclassified as Mach-O fat via the magic check.
    let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
    // arch 0: cputype=7, subtype=3, offset=0xFFFFFFF0, size=0x1000, align=12
    bytes.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x0C,
    ]);
    // arch 1: cputype=0x0100_000C, subtype=0, offset=0x4D11ABD4, size=0x800, align=12
    bytes.extend_from_slice(&[
        0x01, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x11, 0xAB, 0xD4, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x0C,
    ]);
    // Pad to a plausible class-file size so the body slicing path
    // still operates against bounded input.
    bytes.resize(1024, 0);

    // The point of the test is non-panicking completion.
    extract(&bytes, crate::formats::Sinks::default().ctx());
}

#[test]
fn fat_table_must_fit_the_file() {
    // 50 entries of 20 bytes after the 8-byte header fill 1008 bytes.
    assert!(fat_table_fits(50, 1008));
    assert!(!fat_table_fits(51, 1008));
    assert!(!fat_table_fits(u32::MAX as usize, 1024));
    assert!(fat_table_fits(0, 0));
}

#[test]
fn fat_header_arch_count_is_bounded_by_the_buffer() {
    // nfat_arch = u32::MAX over a 1 KiB file. goblin's `iter_arches`
    // does not check the count against the buffer, so the walk must.
    // Rizin and stng's object walk both trust the count and would run for
    // minutes; `fat_table_fits` keeps this input away from them. (stng
    // caches strings on disk, so a warm cache can hide a regression here;
    // `fat_table_must_fit_the_file` pins the guard itself.)
    let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF];
    bytes.resize(1024, 0);
    let (_, _, metrics) = run(&bytes);
    assert!(
        metrics
            .get("macho.slice_count")
            .is_none_or(|n| n <= MAX_FAT_ARCHES as f64)
    );
}

fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
    let (v, s, m, _) = run_with_symbols(bytes);
    (v, s, m)
}

fn run_with_symbols(bytes: &[u8]) -> (Values, Strings, Metrics, crate::Symbols) {
    let mut out = crate::formats::Sinks::default();
    extract(bytes, out.ctx());
    let crate::formats::Sinks {
        values: v,
        strings: s,
        metrics: m,
        symbols,
        ..
    } = out;
    (v, s, m, symbols)
}

/// Every Mach-O import offset must anchor at the symbol *name* in the
/// `LC_SYMTAB` string table — the bytes at that offset spell the name
/// (NUL-terminated), human-readable and consistent with ELF `.dynstr`.
/// Regression guard for the universal-binary hex view, which rendered
/// `__got` bind-slot pointer bytes (pure binary) before this anchor was
/// introduced.
#[test]
fn import_offsets_anchor_at_name_string() {
    use crate::output::Symbol;
    let bytes = read_fixture("test.macho");
    let (_, _, _, symbols) = run_with_symbols(&bytes);

    let mut checked = 0;
    for sym in symbols.iter() {
        let Symbol::Import {
            name,
            offset: Some(off),
            ..
        } = sym
        else {
            continue;
        };
        let off = *off as usize;
        // The string-table entry is the name followed by a NUL.
        let end = off + name.len();
        assert!(
            bytes.get(off..end) == Some(name.as_bytes()) && bytes.get(end) == Some(&0u8),
            "import {name:?} offset {off:#x} should point at its NUL-terminated \
                 name in LC_SYMTAB, found {:?}",
            bytes
                .get(off..end.min(bytes.len()))
                .map(String::from_utf8_lossy)
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "fixture should expose at least one import with an offset"
    );
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

#[test]
fn cpu_type_string_arm32_and_x86() {
    assert_eq!(cpu_type_string(0x0000_0007), "x86");
    assert_eq!(cpu_type_string(0x0000_000c), "arm");
    assert_eq!(cpu_type_string(0x0200_000c), "arm64_32");
}

#[test]
fn file_type_string_object_and_core() {
    assert_eq!(file_type_string(0x1), "object");
    assert_eq!(file_type_string(0x4), "core");
    assert_eq!(file_type_string(0x99), "unknown");
}

#[test]
fn load_command_name_known_set() {
    // LC_SEGMENT_64 = 0x19, LC_UUID = 0x1b, LC_CODE_SIGNATURE = 0x1d
    assert_eq!(load_command_name(0x19), "LC_SEGMENT_64");
    assert_eq!(load_command_name(0x1b), "LC_UUID");
    assert_eq!(load_command_name(0x1d), "LC_CODE_SIGNATURE");
}

#[test]
fn empty_input_doesnt_crash() {
    let (_, _, _) = run(&[]);
}

#[test]
fn non_macho_input_is_silent() {
    let (v, _, m) = run(b"\x00\x00\x00 not macho");
    assert!(v.is_empty() || v.get("macho").is_none());
    assert!(m.get("binary.is_pie").is_none());
}

#[test]
fn truncated_macho_doesnt_crash() {
    // Mach-O magic but no real payload.
    let bytes = vec![0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
    let (_, _, _) = run(&bytes);
}

#[test]
fn end_to_end_parses_real_macho_fixture() {
    let bytes = read_fixture("test.macho");
    let (v, _, m) = run(&bytes);
    // Flat schema: macho.{cpu_type, file_type, …} live directly
    // under the namespace.
    assert!(v.get("macho.cpu_type").is_some());
    assert!(v.get("macho.file_type").is_some());
    // PIE / stripped metrics emitted for every Mach-O.
    assert!(m.get("binary.is_pie").is_some());
    assert!(m.get("binary.is_stripped").is_some());
}

/// Pin the `_raw` header fields and class_bits / entry / load
/// command size values that downstream typed consumers
/// (`cleave::MachoMetrics`) deserialise. test.macho is an x86_64
/// (cputype `0x01000007`) thin executable (`MH_EXECUTE = 0x2`).
#[test]
fn raw_header_fields_pinned() {
    let bytes = read_fixture("test.macho");
    let (v, _, _) = run(&bytes);
    assert_eq!(
        v.get("macho.cpu_type_raw").and_then(|x| x.as_u64()),
        Some(0x0100_0007),
    );
    assert_eq!(
        v.get("macho.file_type_raw").and_then(|x| x.as_u64()),
        Some(0x2),
    );
    // Flags must be non-zero for any real Mach-O — at minimum
    // MH_DYLDLINK | MH_TWOLEVEL.
    assert!(
        v.get("macho.flags_raw")
            .and_then(|x| x.as_u64())
            .is_some_and(|f| f != 0),
    );
    // class_bits is 64 for an arm64 executable.
    assert_eq!(v.get("macho.class_bits").and_then(|x| x.as_u64()), Some(64));
    // Entry point must be set on an executable (LC_MAIN.entryoff).
    assert!(v.get("macho.entry").and_then(|x| x.as_u64()).unwrap_or(0) > 0);
    // sizeofcmds is always non-zero for a valid Mach-O.
    assert!(
        v.get("macho.load_commands_size")
            .and_then(|x| x.as_u64())
            .is_some_and(|n| n > 0)
    );
}

/// Pin per-segment raw initprot/maxprot fields used by cleave's
/// `MachoSegmentEntry::{initprot_hex, maxprot_hex}`.
#[test]
fn segment_raw_protections_emitted() {
    let bytes = read_fixture("test.macho");
    let (v, _, _) = run(&bytes);
    let segs = v
        .get("macho.segments")
        .and_then(|s| s.as_array())
        .expect("segments emitted");
    assert!(!segs.is_empty());
    // __TEXT segment has initprot r-x (5) and maxprot rwx (7) on
    // every Apple-shipped binary; the trivial test fixture matches.
    let text = segs
        .iter()
        .find(|s| s.get("name").and_then(|n| n.as_str()) == Some("__TEXT"))
        .expect("__TEXT segment present");
    assert_eq!(text.get("initprot_raw").and_then(|x| x.as_u64()), Some(5));
    assert_eq!(text.get("maxprot_raw").and_then(|x| x.as_u64()), Some(5));
}

/// Pin per-dylib raw current/compat versions used by cleave's
/// typed `MachoDylibEntry`.
#[test]
fn load_dylibs_raw_versions_emitted() {
    let bytes = read_fixture("test.macho");
    let (v, _, _) = run(&bytes);
    let dylibs = v
        .get("macho.load_dylibs")
        .and_then(|d| d.as_array())
        .expect("load_dylibs emitted");
    assert!(!dylibs.is_empty());
    for entry in dylibs {
        assert!(entry.get("current_version_raw").is_some());
        assert!(entry.get("compatibility_version_raw").is_some());
    }
}

#[test]
fn normalize_dylib_path_strips_dir_and_suffix() {
    assert_eq!(
        normalize_dylib_path("/usr/lib/libSystem.B.dylib"),
        "libsystem.b"
    );
    assert_eq!(normalize_dylib_path("libobjc.A.tbd"), "libobjc.a");
    // Bare names without prefix or suffix are lowercased.
    assert_eq!(normalize_dylib_path("Foo"), "foo");
}

/// Verifies the unified Symbols view is populated for Mach-O
/// imports/exports and that library names come back normalised.
#[test]
fn typed_imports_and_exports_populated_for_macho() {
    let bytes = read_fixture("test.macho");
    let mut out = crate::formats::Sinks::default();
    extract(&bytes, out.ctx());
    let symbols = out.symbols;
    // The trivial test.macho fixture might have no exports but
    // any real binary has bind imports for libSystem.
    for sym in symbols.iter_kind(crate::SymbolKind::Import) {
        let crate::Symbol::Import { library, .. } = sym else {
            unreachable!();
        };
        let lib = library
            .as_deref()
            .expect("Mach-O bind imports carry library");
        assert_eq!(lib, &lib.to_ascii_lowercase());
        assert!(!lib.ends_with(".dylib") && !lib.ends_with(".tbd"));
    }
    for sym in symbols.iter_kind(crate::SymbolKind::Export) {
        assert!(matches!(sym, crate::Symbol::Export { .. }));
    }
}

#[test]
fn mh_flag_names_decompose_canonical_set() {
    // dyld_link | two_level | pie
    let names = mh_flag_names(0x4 | 0x80 | 0x0020_0000);
    assert!(names.contains(&"dyld_link"));
    assert!(names.contains(&"two_level"));
    assert!(names.contains(&"pie"));
    // No spurious flags.
    assert_eq!(names.len(), 3);
}

#[test]
fn mh_flag_names_empty_when_zero() {
    assert!(mh_flag_names(0).is_empty());
}

/// The Mach-O entry-anomaly parity metrics (mirroring ELF/PE) emit on a
/// real binary and stay clean on a benign one: exactly one executable
/// segment (__TEXT), and no nonstandard-entry-section anomaly.
#[test]
fn macho_entry_parity_metrics_clean_on_fixture() {
    let bytes = read_fixture("test.macho");
    let (_v, _, m) = run(&bytes);
    assert_eq!(m.get("macho.executable_segment_count"), Some(1.0));
    assert!(m.get("macho.entry_in_nonstandard_section").is_none());
}

/// The chained-fixups fallback must not fire on a binary that has bind
/// opcodes, or every such import would be emitted twice.
///
/// `test.macho` carries `LC_DYLD_INFO_ONLY`, so `macho.imports()` returns
/// its imports and the symtab fallback must stay out of the way. The
/// fallback exists for `LC_DYLD_CHAINED_FIXUPS` binaries -- macOS 12 and
/// later -- where `macho.imports()` returns nothing at all and the
/// undefined externals in `LC_SYMTAB` are the only record of what the
/// binary imports.
#[test]
fn bind_imports_are_not_duplicated_by_the_symtab_fallback() {
    use std::collections::HashMap;
    let bytes = read_fixture("test.macho");
    let parsed = crate::open(&bytes);
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut total = 0usize;
    for sym in parsed.symbols().iter_kind(crate::SymbolKind::Import) {
        if let crate::Symbol::Import { name, library, .. } = sym {
            total += 1;
            *counts.entry(name.as_str()).or_default() += 1;
            // The bind path always attributes a dylib; the fallback never
            // does. Every import here must have come from the bind path.
            assert!(
                library.is_some(),
                "{name} has no library: emitted by the chained-fixups \
                     fallback on a binary that has bind opcodes"
            );
        }
    }
    assert!(total > 0, "fixture should have imports");
    let dupes: Vec<_> = counts.iter().filter(|(_, n)| **n > 1).collect();
    assert!(dupes.is_empty(), "duplicated imports: {dupes:?}");
}

/// `LC_FUNCTION_STARTS` deltas are read with the shared ULEB128 decoder: the
/// zero terminator ends the table, and so does a truncated delta.
#[test]
fn function_starts_count_stops_at_the_terminator_or_a_truncated_delta() {
    fn count(data: &[u8]) -> Option<f64> {
        let mut file = Vec::new();
        for word in [0xfeed_facf_u32, 0x0100_0007, 3, 2, 1, 16, 0, 0] {
            file.extend_from_slice(&word.to_le_bytes());
        }
        // LC_FUNCTION_STARTS, cmdsize 16, data right after the command.
        for word in [0x26_u32, 16, 48, data.len() as u32] {
            file.extend_from_slice(&word.to_le_bytes());
        }
        file.extend_from_slice(data);
        let macho = MachO::parse(&file, 0).expect("minimal Mach-O");
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        function_starts(&macho, &file, &mut values, &mut metrics);
        metrics.get("macho.function_starts_count")
    }
    // Deltas 0x10, 0x80, 0x4, then the terminator and padding.
    assert_eq!(count(&[0x10, 0x80, 0x01, 0x04, 0x00, 0x05]), Some(3.0));
    // A delta cut off mid-encoding is not a function start.
    assert_eq!(count(&[0x10, 0x80]), Some(1.0));
}

/// Run [`extract`] on a 2 MiB thread — a Rayon worker's stack — and return
/// what it recorded in the errors view.
fn errors_on_worker_stack(bytes: Vec<u8>) -> Errors {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            let mut out = crate::formats::Sinks::default();
            extract(&bytes, out.ctx());
            out.errors
        })
        .expect("spawn")
        .join()
        .expect("join")
}

/// A forged bind repeat count is refused before goblin allocates for it, and
/// the refusal is visible in the errors view rather than only in debug logs.
#[test]
fn oversized_bind_stream_is_recorded_as_malformed() {
    // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, count 2^32 - 1, skip 0,
    // through the fixture's real dylib ordinal and segment so the count is
    // what trips.
    let bind = [0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00];
    let file = crate::formats::goblin_safe::tests::macho_with_bind_tables(&bind);
    let errors = errors_on_worker_stack(file);
    assert!(
        errors
            .iter()
            .any(|e| e.kind == crate::output::DiagnosticKind::Malformed
                && e.stage == crate::Stage::MachoParse
                && e.message.contains("bind opcodes declare")),
        "{errors:?}"
    );
}

/// An export trie too deep for goblin's recursive walk is refused, and the
/// refusal is recorded.
#[test]
fn deep_export_trie_is_recorded_as_malformed() {
    let file = crate::formats::goblin_safe::tests::macho_with_dyld_info(
        &[],
        &crate::formats::goblin_safe::tests::chain_trie(5000),
    );
    let errors = errors_on_worker_stack(file);
    assert!(
        errors
            .iter()
            .any(|e| e.kind == crate::output::DiagnosticKind::Malformed
                && e.stage == crate::Stage::MachoParse
                && e.message.contains("export trie")),
        "{errors:?}"
    );
}
