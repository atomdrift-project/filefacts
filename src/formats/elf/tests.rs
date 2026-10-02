use super::*;
use crate::output::{Metrics, Strings, Values};

fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
    let mut out = crate::formats::Sinks::default();
    // Ignore the Result — most negative-path tests pass malformed
    // bytes and we only care that extract returns without panic.
    extract(bytes, out.ctx());
    (out.values, out.strings, out.metrics)
}

/// Build a minimal, goblin-parseable ELF64 (little-endian) carrying a
/// single named section with the given contents, plus the `.shstrtab`
/// goblin needs to resolve section names. Pure-Rust — no committed binary
/// fixture, no toolchain — so the Go fast-path stays covered everywhere.
fn elf_with_section(name: &str, data: &[u8]) -> Vec<u8> {
    const EH: usize = 64; // ELF64 header size
    const SH: usize = 64; // ELF64 section header size

    // Section-name string table; index 0 is the empty name.
    let mut shstr = vec![0u8];
    let name_off = shstr.len() as u32;
    shstr.extend_from_slice(name.as_bytes());
    shstr.push(0);
    let shstrtab_name_off = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab");
    shstr.push(0);

    let data_off = EH;
    let shstr_off = data_off + data.len();
    let shtab_off = shstr_off + shstr.len();
    let mut buf = vec![0u8; shtab_off + 3 * SH];

    // ELF header.
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    buf[40..48].copy_from_slice(&(shtab_off as u64).to_le_bytes()); // e_shoff
    buf[52..54].copy_from_slice(&(EH as u16).to_le_bytes()); // e_ehsize
    buf[58..60].copy_from_slice(&(SH as u16).to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
    buf[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx

    // Section contents.
    buf[data_off..data_off + data.len()].copy_from_slice(data);
    buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(&shstr);

    // Section headers: [0] null (already zeroed), [1] named, [2] shstrtab.
    fn put_sh(buf: &mut [u8], base: usize, name: u32, ty: u32, off: u64, size: u64) {
        buf[base..base + 4].copy_from_slice(&name.to_le_bytes()); // sh_name
        buf[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes()); // sh_type
        buf[base + 24..base + 32].copy_from_slice(&off.to_le_bytes()); // sh_offset
        buf[base + 32..base + 40].copy_from_slice(&size.to_le_bytes()); // sh_size
    }
    put_sh(
        &mut buf,
        shtab_off + SH,
        name_off,
        1, // SHT_PROGBITS
        data_off as u64,
        data.len() as u64,
    );
    put_sh(
        &mut buf,
        shtab_off + 2 * SH,
        shstrtab_name_off,
        3, // SHT_STRTAB
        shstr_off as u64,
        shstr.len() as u64,
    );
    buf
}

#[test]
fn synthetic_elf_builder_parses_and_names_sections() {
    // Guards the test harness itself: if goblin can't parse what
    // `elf_with_section` emits, the Go-path tests below are meaningless.
    let bytes = elf_with_section(".gopclntab", &[0xf0, 0xff, 0xff, 0xff]);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");
    assert!(
        elf.section_headers
            .iter()
            .any(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".gopclntab")),
        "named section must be resolvable"
    );
}

#[test]
fn go_pclntab_magic_is_detected() {
    // Go 1.18 pclntab magic (0xfffffff0, little-endian) + a plausible tail.
    let pclntab = [0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08];
    let bytes = elf_with_section(".gopclntab", &pclntab);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");
    assert!(
        has_go_pclntab(&elf, &bytes),
        "a valid Go pclntab must be detected"
    );
}

#[test]
fn go_pclntab_big_endian_magic_is_detected() {
    // s390x/ppc64 Go binaries lay the magic out big-endian (0xfffffff1).
    let pclntab = [0xff, 0xff, 0xff, 0xf1, 0x00, 0x00, 0x01, 0x08];
    let bytes = elf_with_section(".gopclntab", &pclntab);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");
    assert!(has_go_pclntab(&elf, &bytes));
}

#[test]
fn spoofed_gopclntab_without_magic_is_not_go() {
    // A section *named* `.gopclntab` but carrying no valid magic is an
    // evasion attempt to dodge deep function discovery. It MUST stay on
    // `aaa` so hidden functions are still recovered.
    let bytes = elf_with_section(".gopclntab", b"not a real pclntab header");
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");
    assert!(!has_go_pclntab(&elf, &bytes));
}

#[test]
fn non_go_binary_has_no_pclntab() {
    let bytes = elf_with_section(".text", &[0x55, 0x48, 0x89, 0xe5]);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");
    assert!(!has_go_pclntab(&elf, &bytes));
}

#[test]
fn machine_string_handles_known() {
    assert_eq!(machine_string(header::EM_X86_64), "x86_64");
    assert_eq!(machine_string(header::EM_AARCH64), "aarch64");
    assert_eq!(machine_string(header::EM_ARM), "arm");
    assert_eq!(machine_string(header::EM_386), "i386");
    assert_eq!(machine_string(header::EM_RISCV), "riscv");
    assert_eq!(machine_string(header::EM_PPC64), "powerpc64");
    assert_eq!(machine_string(header::EM_S390), "s390");
    assert_eq!(machine_string(header::EM_LOONGARCH), "loongarch");
    assert_eq!(machine_string(header::EM_VIDEOCORE3), "videocore3");
    assert_eq!(machine_string(header::EM_QDSP6), "qdsp6");
    assert_eq!(machine_string(header::EM_XTENSA), "xtensa");
    assert_eq!(machine_string(0xeeee), "unknown");
}

#[test]
fn elf_type_string_covers_canonical_set() {
    assert_eq!(elf_type_string(header::ET_NONE), "none");
    assert_eq!(elf_type_string(header::ET_REL), "relocatable");
    assert_eq!(elf_type_string(header::ET_EXEC), "executable");
    assert_eq!(elf_type_string(header::ET_DYN), "dynamic");
    assert_eq!(elf_type_string(header::ET_CORE), "core");
    assert_eq!(elf_type_string(0x9999), "unknown");
}

#[test]
fn section_flags_decompose_each_bit() {
    // SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR
    let f = section_flags(0x1 | 0x2 | 0x4);
    assert_eq!(
        f,
        vec![
            SectionFlag::Writable,
            SectionFlag::Alloc,
            SectionFlag::Executable
        ]
    );
}

#[test]
fn section_flags_picks_up_strings_and_merge() {
    // SHF_MERGE | SHF_STRINGS — `.rodata.str` section uses these.
    let f = section_flags(0x10 | 0x20);
    assert_eq!(f, vec![SectionFlag::Merge, SectionFlag::Strings]);
}

#[test]
fn section_flags_tls_bit() {
    let f = section_flags(0x100);
    assert_eq!(f, vec![SectionFlag::Tls]);
}

#[test]
fn section_flags_empty_when_zero() {
    assert!(section_flags(0).is_empty());
}

#[test]
fn gnu_property_name_handles_x86_features() {
    // GNU_PROPERTY_X86_FEATURE_1_AND (0xc0000002) carries IBT/SHSTK
    // markers on hardened x86 builds.
    assert!(gnu_property_name(0xc0000002, false).is_some());
}

#[test]
fn gnu_property_name_handles_aarch64_pauth() {
    // BTI / PAC properties are aarch64-only.
    let bti = gnu_property_name(0xc0000000, true);
    assert!(bti.is_some());
}

#[test]
fn pauth_platform_name_known_vendors() {
    // Apple = 1, LLVM = 2; vendor IDs come from the AArch64 ABI
    // supplement.
    assert!(!pauth_platform_name(1).is_empty());
    assert!(!pauth_platform_name(2).is_empty());
}

#[test]
fn rejects_non_elf_bytes() {
    let (v, _, m) = run(b"not an elf");
    assert!(v.is_empty());
    // file.size is emitted by the dispatcher, not extract; nothing
    // from elf.* should be present here.
    assert!(m.get("binary.is_pie").is_none());
}

#[test]
fn empty_input_doesnt_crash() {
    let (_, _, _) = run(&[]);
}

#[test]
fn truncated_elf_header_doesnt_crash() {
    let mut bytes = vec![0u8; 32];
    bytes[..4].copy_from_slice(b"\x7fELF");
    let (_, _, _) = run(&bytes);
}

/// Read a real binary fixture from the cleave repo. Lets tests
/// exercise the full extractor against a non-trivial ELF without
/// shipping our own corpus.
fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

/// Extract and return the typed symbols (the `run` helper drops them).
fn run_symbols(bytes: &[u8]) -> crate::Symbols {
    let mut out = crate::formats::Sinks::default();
    extract(bytes, out.ctx());
    out.symbols
}

/// Zero the section-header table in an ELF64 image, simulating a
/// release/packed binary that ships only program headers. goblin still
/// resolves dynamic symbols through `PT_DYNAMIC`, so the names survive — the
/// only thing lost is the `.dynstr` *section*.
fn strip_section_headers(bytes: &mut [u8]) {
    bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes[0x3c..0x3e].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx
}

/// Section-header-stripped binaries must still anchor every import at its
/// name's file offset. The `.dynstr` section is gone, but `DT_STRTAB` in the
/// dynamic segment locates the same string table — without the fallback,
/// downstream consumers see offset-less import matches and (in cleave) log
/// them as "content match has no file offset".
#[test]
fn stripped_section_headers_still_anchor_import_names() {
    use crate::output::{Symbol, SymbolKind};
    let bytes = read_fixture("test.elf");
    let with_shdrs = run_symbols(&bytes);
    let baseline: std::collections::HashMap<String, Option<u64>> = with_shdrs
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, offset, .. } => Some((name.clone(), *offset)),
            _ => None,
        })
        .collect();
    assert!(!baseline.is_empty(), "fixture should carry dynamic imports");
    assert!(
        baseline.values().all(Option::is_some),
        "baseline imports already anchored via .dynstr section"
    );

    let mut stripped = bytes.clone();
    strip_section_headers(&mut stripped);
    let recovered = run_symbols(&stripped);
    let mut import_count = 0;
    for sym in recovered.iter_kind(SymbolKind::Import) {
        let Symbol::Import { name, offset, .. } = sym else {
            continue;
        };
        import_count += 1;
        // Every import keeps an offset, and it matches the section-based one:
        // both point at the name string in `.dynstr`.
        assert_eq!(
            *offset,
            baseline.get(name).copied().flatten(),
            "import {name} lost or changed its offset when section headers were stripped"
        );
    }
    assert_eq!(
        import_count,
        baseline.len(),
        "same imports recovered without section headers"
    );
}

#[test]
fn end_to_end_parses_real_elf_fixture() {
    let bytes = read_fixture("test.elf");
    let (v, _, m) = run(&bytes);
    // Pike-style flat schema: header fields live under `elf.<name>`
    // directly, not nested in `elf.header.*`.
    assert!(v.get("elf.class").is_some());
    assert!(v.get("elf.endian").is_some());
    assert!(v.get("elf.entry").is_some());
    // PIE / stripped flags are present (0 or 1) for any ELF.
    assert!(m.get("binary.is_pie").is_some());
    assert!(m.get("binary.is_stripped").is_some());
}

/// Pin every cleave-consumed emission added to support the
/// ctx-only ELF analyzer migration. If filefacts stops emitting any
/// of these, the analyzer's typed-metric path silently regresses
/// to defaults — catch the loss here.
#[test]
fn pinned_elf_metrics_for_cleave_consumers() {
    let bytes = read_fixture("test.elf");
    let (v, _, m) = run(&bytes);
    // Header / section / segment counts.
    assert!(m.get("elf.bits").unwrap() == 64.0 || m.get("elf.bits").unwrap() == 32.0);
    assert!(m.get("elf.program_header_count").unwrap() > 0.0);
    // Section count flows through cross-format `sections.count`
    // emitted from `lib.rs::extract_all`. The per-format `extract`
    // call this test exercises populates the `sections` Vec
    // directly — the aggregate metric is asserted in the
    // top-level pipeline tests.
    assert!(m.get("dependencies.count").is_some());
    // Anomaly metrics are emitted as zero only when set; their
    // absence on a healthy binary is expected. We verify the
    // dependency-loaded metrics are present.
    assert!(v.get("elf.machine").is_some());
    assert!(v.get("elf.type").is_some());
    // segments[] entries now carry `flags_hex` for cleave's
    // segment_entries carrier.
    let segs = v.get("elf.segments").and_then(|j| j.as_array()).unwrap();
    let first = segs.first().unwrap().as_object().unwrap();
    assert!(first.contains_key("flags_hex"));
    assert!(first.contains_key("perms"));
    assert!(first.contains_key("type"));
    // Completeness: every program-header field is carried, including
    // the previously-missing paddr/align.
    for key in [
        "vaddr",
        "paddr",
        "file_offset",
        "file_size",
        "memory_size",
        "align",
    ] {
        assert!(first.contains_key(key), "segment missing {key}");
    }

    // The full ELF header is surfaced — table offsets and entity
    // sizes included — so no header field can change unnoticed.
    for key in [
        "elf.phoff",
        "elf.shoff",
        "elf.shstrndx",
        "elf.ehsize",
        "elf.phentsize",
        "elf.shentsize",
        "elf.osabi",
        "elf.abi_version",
        "elf.ident_version",
    ] {
        assert!(v.get(key).is_some(), "header fact missing {key}");
    }

    // elf.sections[] carries every Elf64_Shdr field, including the
    // ELF-only fields the cross-format Section list cannot hold.
    let section_headers = v.get("elf.sections").and_then(|j| j.as_array()).unwrap();
    assert!(!section_headers.is_empty());
    let first_header = section_headers.first().unwrap().as_object().unwrap();
    for key in [
        "name",
        "name_offset",
        "type",
        "type_raw",
        "flags",
        "flags_hex",
        "addr",
        "file_offset",
        "size",
        "link",
        "info",
        "addralign",
        "entsize",
    ] {
        assert!(
            first_header.contains_key(key),
            "section header missing {key}"
        );
    }

    // Executable PT_LOAD segments are counted for the grafted-segment
    // (note-cavity) tell.
    assert!(m.get("elf.executable_segment_count").unwrap() >= 1.0);
}

#[test]
fn osabi_string_decodes_known_and_falls_back() {
    assert_eq!(osabi_string(0), "sysv");
    assert_eq!(osabi_string(3), "linux");
    assert_eq!(osabi_string(9), "freebsd");
    // Unknown values keep the raw byte so a change still diffs.
    assert_eq!(osabi_string(200), "osabi:200");
}

#[test]
fn shdr_type_name_covers_common_and_falls_back() {
    assert_eq!(shdr_type_name(1), "progbits"); // SHT_PROGBITS
    assert_eq!(shdr_type_name(7), "note"); // SHT_NOTE
    assert_eq!(shdr_type_name(8), "nobits"); // SHT_NOBITS
    // 0x4242 is unassigned (above the base SHT_* set, below SHT_LOOS).
    assert_eq!(shdr_type_name(0x4242), "other");
}

/// Build a minimal, goblin-parseable ELF64 exercising the note-cavity
/// signals. `infected` selects the post-infection shape: the build-id
/// note's PT_NOTE program header is replaced by a second executable
/// PT_LOAD (the grafted `.attack` segment) and the entry is redirected
/// into `.attack`. The clean shape keeps a PT_NOTE over the build-id
/// note and the entry in `.text`. Virtual addresses equal file offsets
/// to keep the layout easy to reason about.
fn note_cavity_elf(infected: bool) -> Vec<u8> {
    const EH: usize = 64;
    const PH: usize = 56;
    const SH: usize = 64;
    const PHOFF: u64 = 64;
    const TEXT_OFF: u64 = 0x200;
    const NOTE_OFF: u64 = 0x300;
    const ATTACK_OFF: u64 = 0x400;
    const SHSTR_OFF: u64 = 0x500;
    const SHT_OFF: u64 = 0x600;

    fn w16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn put_ph(b: &mut [u8], base: usize, ty: u32, flags: u32, off: u64, va: u64, size: u64) {
        w32(b, base, ty);
        w32(b, base + 4, flags);
        w64(b, base + 8, off);
        w64(b, base + 16, va);
        w64(b, base + 24, va); // p_paddr
        w64(b, base + 32, size); // p_filesz
        w64(b, base + 40, size); // p_memsz
        w64(b, base + 48, 0x1000); // p_align
    }
    fn put_sh(b: &mut [u8], base: usize, name: u32, ty: u32, flags: u64, addr: u64, size: u64) {
        w32(b, base, name);
        w32(b, base + 4, ty);
        w64(b, base + 8, flags);
        w64(b, base + 16, addr);
        w64(b, base + 24, addr); // sh_offset == addr in this layout
        w64(b, base + 32, size);
        w64(b, base + 48, 4); // sh_addralign
    }

    // Section-name string table.
    let mut shstr = vec![0u8];
    let text_name = shstr.len() as u32;
    shstr.extend_from_slice(b".text\0");
    let note_name = shstr.len() as u32;
    shstr.extend_from_slice(b".note.gnu.build-id\0");
    let attack_name = shstr.len() as u32;
    shstr.extend_from_slice(b".attack\0");
    let shstrtab_name = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab\0");

    let mut buf = vec![0u8; 0x800];

    // ELF header.
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    w16(&mut buf, 16, 2); // e_type = ET_EXEC
    w16(&mut buf, 18, 62); // e_machine = EM_X86_64
    w32(&mut buf, 20, 1); // e_version
    let entry = if infected { ATTACK_OFF } else { TEXT_OFF };
    w64(&mut buf, 24, entry); // e_entry
    w64(&mut buf, 32, PHOFF); // e_phoff
    w64(&mut buf, 40, SHT_OFF); // e_shoff
    w16(&mut buf, 52, EH as u16); // e_ehsize
    w16(&mut buf, 54, PH as u16); // e_phentsize
    w16(&mut buf, 56, 2); // e_phnum
    w16(&mut buf, 58, SH as u16); // e_shentsize
    w16(&mut buf, 60, 5); // e_shnum
    w16(&mut buf, 62, 4); // e_shstrndx (.shstrtab)

    // Program headers. PT_LOAD=1, PT_NOTE=4; PF_X=1, PF_R=4.
    put_ph(&mut buf, PHOFF as usize, 1, 4 | 1, 0, 0, 0x210); // r-x LOAD over header+.text
    if infected {
        // Grafted r-x LOAD over .attack — highest vaddr, so last.
        put_ph(
            &mut buf,
            PHOFF as usize + PH,
            1,
            4 | 1,
            ATTACK_OFF,
            ATTACK_OFF,
            0x10,
        );
    } else {
        // PT_NOTE covering the build-id note.
        put_ph(
            &mut buf,
            PHOFF as usize + PH,
            4,
            4,
            NOTE_OFF,
            NOTE_OFF,
            0x20,
        );
    }

    // .text / .attack dummy code (nop; nop; nop; ret).
    buf[TEXT_OFF as usize..TEXT_OFF as usize + 4].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    buf[ATTACK_OFF as usize..ATTACK_OFF as usize + 4].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);

    // GNU build-id note: namesz=4, descsz=16, type=NT_GNU_BUILD_ID(3),
    // name "GNU\0", 16-byte descriptor.
    let n = NOTE_OFF as usize;
    w32(&mut buf, n, 4);
    w32(&mut buf, n + 4, 16);
    w32(&mut buf, n + 8, 3);
    buf[n + 12..n + 16].copy_from_slice(b"GNU\0");
    for b in buf.iter_mut().skip(n + 16).take(16) {
        *b = 0xAB;
    }

    buf[SHSTR_OFF as usize..SHSTR_OFF as usize + shstr.len()].copy_from_slice(&shstr);

    // Section headers. SHT_PROGBITS=1, SHT_NOTE=7, SHT_STRTAB=3;
    // SHF_ALLOC=2, SHF_EXECINSTR=4.
    let base = SHT_OFF as usize;
    put_sh(&mut buf, base + SH, text_name, 1, 2 | 4, TEXT_OFF, 0x10);
    put_sh(&mut buf, base + 2 * SH, note_name, 7, 2, NOTE_OFF, 0x20);
    put_sh(
        &mut buf,
        base + 3 * SH,
        attack_name,
        1,
        2 | 4,
        ATTACK_OFF,
        0x10,
    );
    // .shstrtab: not allocated, sh_offset is its file position.
    let sb = base + 4 * SH;
    w32(&mut buf, sb, shstrtab_name);
    w32(&mut buf, sb + 4, 3);
    w64(&mut buf, sb + 24, SHSTR_OFF);
    w64(&mut buf, sb + 32, shstr.len() as u64);
    w64(&mut buf, sb + 48, 1);

    buf
}

#[test]
fn note_cavity_infected_trips_all_signals_and_retains_build_id() {
    let (v, _, m) = run(&note_cavity_elf(true));
    assert_eq!(m.get("elf.executable_segment_count"), Some(2.0));
    assert_eq!(m.get("elf.entry_in_nonstandard_section"), Some(1.0));
    assert_eq!(m.get("elf.entry_in_last_segment"), Some(1.0));
    assert_eq!(m.get("elf.uncovered_note_count"), Some(1.0));
    assert_eq!(m.get("elf.build_id_uncovered"), Some(1.0));
    // Identity retained: read from the section table even though no
    // PT_NOTE covers the build-id note any more.
    assert!(v.get("elf.build_id").is_some());
    assert_eq!(m.get("elf.has_build_id"), Some(1.0));
}

#[test]
fn note_cavity_clean_trips_no_infection_signals() {
    let (v, _, m) = run(&note_cavity_elf(false));
    assert_eq!(m.get("elf.executable_segment_count"), Some(1.0));
    assert!(m.get("elf.entry_in_nonstandard_section").is_none());
    assert!(m.get("elf.uncovered_note_count").is_none());
    assert!(m.get("elf.build_id_uncovered").is_none());
    // Build-id still read, here from the PT_NOTE-covered note section.
    assert!(v.get("elf.build_id").is_some());
}

#[test]
fn header_and_layout_anomalies_fire_on_patched_bytes() {
    let mut b = note_cavity_elf(false);
    // Non-zero EI_PAD byte (e_ident[10]) — a hidden-data channel.
    b[10] = 0x41;
    // Blow up `.text` (section index 1) so its bytes run past EOF:
    // sh_size lives at SHT_OFF(0x600) + 1*SH(64) + 32.
    let sh_size_off = 0x600 + 64 + 32;
    b[sh_size_off..sh_size_off + 8].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    let (v, _, m) = run(&b);
    assert_eq!(m.get("elf.ident_pad_nonzero"), Some(1.0));
    assert!(v.get("elf.ident_pad").is_some());
    assert!(m.get("elf.section_past_eof_count").is_some());
}
