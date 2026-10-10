use super::*;
use crate::output::{Metrics, Strings, Values};

#[test]
fn header_only_and_memory_only_segments_do_not_admit_code_recovery() {
    let mut bytes = note_cavity_elf(false);
    let parsed = goblin::elf::Elf::parse(&bytes).unwrap();
    assert!(has_present_load_or_code_bytes(&parsed, bytes.len()));
    // A complete program table remains, while both payload and section table
    // have been split away. The load segment starts beyond this member.
    bytes[40..48].copy_from_slice(&0_u64.to_le_bytes());
    bytes[60..64].fill(0);
    bytes[72..80].copy_from_slice(&0x200_u64.to_le_bytes());
    bytes.truncate(0x200);
    let mut elf = goblin::elf::Elf::parse(&bytes).unwrap();
    assert!(!has_present_load_or_code_bytes(&elf, bytes.len()));
    let load = elf
        .program_headers
        .iter_mut()
        .find(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .unwrap();
    load.p_offset = 0x100;
    load.p_filesz = 0; // BSS reserves memory without supplying instruction bytes.
    assert!(!has_present_load_or_code_bytes(&elf, bytes.len()));
    let load = elf
        .program_headers
        .iter_mut()
        .find(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .unwrap();
    load.p_filesz = 1; // A present prefix is still worth recovering.
    assert!(has_present_load_or_code_bytes(&elf, bytes.len()));
}

fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
    let mut out = crate::formats::Sinks::default();
    // Ignore the Result — most negative-path tests pass malformed
    // bytes and we only care that extract returns without panic.
    extract(bytes, out.ctx());
    (out.values, out.strings, out.metrics)
}

#[test]
fn split_mdt_header_contract_requires_private_segments_and_absent_load_bytes() {
    let mut b = vec![0_u8; 148];
    b[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    b[16..18].copy_from_slice(&2_u16.to_le_bytes());
    b[18..20].copy_from_slice(&3_u16.to_le_bytes());
    b[20..24].copy_from_slice(&1_u32.to_le_bytes());
    b[28..32].copy_from_slice(&52_u32.to_le_bytes());
    b[40..42].copy_from_slice(&52_u16.to_le_bytes());
    b[42..44].copy_from_slice(&32_u16.to_le_bytes());
    b[44..46].copy_from_slice(&3_u16.to_le_bytes());
    b[46..48].copy_from_slice(&40_u16.to_le_bytes());
    // First NULL segment contains the complete ELF/program header pair.
    b[68..72].copy_from_slice(&148_u32.to_le_bytes());
    b[76..80].copy_from_slice(&(7_u32 << 24).to_le_bytes());
    // The hash NULL segment and the actual LOAD live in sibling members.
    b[88..92].copy_from_slice(&4096_u32.to_le_bytes());
    b[100..104].copy_from_slice(&136_u32.to_le_bytes());
    b[108..112].copy_from_slice(&(2_u32 << 24).to_le_bytes());
    b[116..120].copy_from_slice(&1_u32.to_le_bytes());
    b[120..124].copy_from_slice(&8192_u32.to_le_bytes());
    b[132..136].copy_from_slice(&16_u32.to_le_bytes());
    b[136..140].copy_from_slice(&16_u32.to_le_bytes());
    b[140..144].copy_from_slice(&5_u32.to_le_bytes());
    let (_, _, m) = run(&b);
    assert_eq!(m.get("elf.qcom_mdt_header_layout"), Some(1.0));
    assert_eq!(m.get("elf.load_segments_without_member_bytes"), Some(1.0));
    b[108..112].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(run(&b).2.get("elf.qcom_mdt_header_layout"), Some(0.0));
    b[108..112].copy_from_slice(&(2_u32 << 24).to_le_bytes());
    b[68..72].copy_from_slice(&147_u32.to_le_bytes());
    assert_eq!(run(&b).2.get("elf.qcom_mdt_header_layout"), Some(0.0));
    b[68..72].copy_from_slice(&148_u32.to_le_bytes());
    b.resize(8193, 0);
    let (_, _, m) = run(&b);
    assert_eq!(m.get("elf.qcom_mdt_header_layout"), Some(1.0));
    assert_eq!(m.get("elf.load_segments_without_member_bytes"), Some(0.0));
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

#[test]
fn absence_fields_distinguish_section_presence_and_empty_full_tables() {
    let absent = elf_with_section(".data", &[0]);
    let (v, _, m) = run(&absent);
    assert_eq!(m.get("binary.full_symbol_table_absent_or_empty"), Some(1.0));
    assert!(
        v.get("elf.absent_metadata_sections")
            .unwrap()
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(".comment"))
    );
    let comment = elf_with_section(".comment", b"compiler\0");
    let (v, _, _) = run(&comment);
    assert!(
        !v.get("elf.absent_metadata_sections")
            .unwrap()
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(".comment"))
    );

    // A declared zero-entry SHT_SYMTAB is empty, not evidence of a prior
    // stripping operation. A table containing an entry is not empty.
    for (entries, expected) in [(0, 1.0), (1, 0.0)] {
        let mut bytes = elf_with_section(".symtab", &vec![0; entries * 24]);
        let base = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize + 64;
        bytes[base + 4..base + 8].copy_from_slice(&2_u32.to_le_bytes());
        bytes[base + 40..base + 44].copy_from_slice(&2_u32.to_le_bytes());
        bytes[base + 56..base + 64].copy_from_slice(&24_u64.to_le_bytes());
        let elf = Elf::parse(&bytes).unwrap();
        assert_eq!(elf.syms.len(), entries);
        let (_, _, m) = run(&bytes);
        assert_eq!(
            m.get("binary.full_symbol_table_absent_or_empty"),
            Some(expected)
        );
        // The legacy absence-only flag keeps its established API contract.
        assert_eq!(m.get("binary.is_stripped"), Some(0.0));
    }
}

/// One section header for [`elf_over_payload`], over the file range
/// `off..off + size`.
#[derive(Clone, Copy, Default)]
struct Sec<'a> {
    name: &'a str,
    ty: u32,
    flags: u64,
    off: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

/// File offset of the `payload` argument in [`elf_over_payload`].
const PAYLOAD: u64 = 64;

/// A little-endian ELF64 `ET_DYN` with `payload` at [`PAYLOAD`], then a
/// `.shstrtab`, the program headers `phdrs` (`(p_type, p_offset, p_filesz)`,
/// vaddr equal to offset) and the section headers `secs` (indices from 1,
/// `.shstrtab` last). Equal names share one string.
fn elf_over_payload(payload: &[u8], phdrs: &[(u32, u64, u64)], secs: &[Sec<'_>]) -> Vec<u8> {
    let mut b = vec![0u8; PAYLOAD as usize];
    b.extend_from_slice(payload);
    let shstr_off = b.len();
    let mut shstr = vec![0u8];
    let mut name_off = std::collections::HashMap::new();
    for name in secs.iter().map(|s| s.name).chain([".shstrtab"]) {
        name_off.entry(name).or_insert_with(|| {
            let off = shstr.len() as u32;
            shstr.extend_from_slice(name.as_bytes());
            shstr.push(0);
            off
        });
    }
    b.extend_from_slice(&shstr);
    b.resize(b.len().next_multiple_of(8), 0);
    let phoff = b.len();
    for &(ty, off, size) in phdrs {
        let mut ph = [0u8; 56];
        ph[0..4].copy_from_slice(&ty.to_le_bytes());
        ph[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        ph[8..16].copy_from_slice(&off.to_le_bytes());
        ph[16..24].copy_from_slice(&off.to_le_bytes());
        ph[24..32].copy_from_slice(&off.to_le_bytes());
        ph[32..40].copy_from_slice(&size.to_le_bytes());
        ph[40..48].copy_from_slice(&size.to_le_bytes());
        ph[48..56].copy_from_slice(&4u64.to_le_bytes());
        b.extend_from_slice(&ph);
    }
    let shoff = b.len();
    b.extend_from_slice(&[0u8; 64]); // SHN_UNDEF
    let shstrtab = Sec {
        name: ".shstrtab",
        ty: 3,
        off: shstr_off as u64,
        size: shstr.len() as u64,
        ..Sec::default()
    };
    for s in secs.iter().chain([&shstrtab]) {
        let mut sh = [0u8; 64];
        sh[0..4].copy_from_slice(&name_off[s.name].to_le_bytes());
        sh[4..8].copy_from_slice(&s.ty.to_le_bytes());
        sh[8..16].copy_from_slice(&s.flags.to_le_bytes());
        sh[24..32].copy_from_slice(&s.off.to_le_bytes());
        sh[32..40].copy_from_slice(&s.size.to_le_bytes());
        sh[40..44].copy_from_slice(&s.link.to_le_bytes());
        sh[44..48].copy_from_slice(&s.info.to_le_bytes());
        sh[48..56].copy_from_slice(&8u64.to_le_bytes());
        sh[56..64].copy_from_slice(&s.entsize.to_le_bytes());
        b.extend_from_slice(&sh);
    }
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // ELFDATA2LSB
    b[6] = 1; // EV_CURRENT
    b[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    b[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&(secs.len() as u16 + 2).to_le_bytes());
    b[62..64].copy_from_slice(&(secs.len() as u16 + 1).to_le_bytes());
    b
}

/// A `.dynamic` image: each `(d_tag, d_val)` then `DT_NULL`.
fn dynamic_entries(entries: &[(u64, u64)]) -> Vec<u8> {
    entries
        .iter()
        .chain([&(0, 0)])
        .flat_map(|&(tag, val)| [tag.to_le_bytes(), val.to_le_bytes()])
        .flatten()
        .collect()
}

/// Total bytes of the strings in the JSON array at `key`.
fn string_bytes(v: &Values, key: &str) -> usize {
    v.get(key).and_then(JsonValue::as_array).map_or(0, |a| {
        a.iter().filter_map(JsonValue::as_str).map(str::len).sum()
    })
}

#[test]
fn name_budget_refuses_everything_after_the_first_overrun() {
    let mut names = NameBudget::new(5);
    assert!(names.take(6));
    assert!(names.take(4));
    assert!(!names.refused());
    assert!(!names.take(1));
    assert!(!names.take(0), "a spent view stays spent");
    assert!(names.refused());
}

#[test]
fn range_cover_matches_a_pairwise_scan() {
    let ranges = [(0, 10), (5, 7), (20, 30), (25, 40), (100, 100)];
    let cover = RangeCover::new(ranges.to_vec());
    for start in 0..45 {
        for end in start..45 {
            let pairwise = ranges.iter().any(|&(s, e)| start >= s && end <= e);
            assert_eq!(cover.contains(start, end), pairwise, "{start}..{end}");
        }
    }
    assert!(!cover.is_empty());
    assert!(RangeCover::new(Vec::new()).is_empty());
    assert!(!RangeCover::new(Vec::new()).contains(0, 0));
}

/// Every `DT_NEEDED` entry may name the same NUL-less run: 2048 entries over
/// a 64 KiB run was 128 MiB of library names, and twice that again in
/// `dyn_hash`. The copies now stop at twice the file length.
#[test]
fn shared_long_library_name_is_not_copied_per_entry() {
    const RUN: usize = 64 * 1024;
    const NEEDED: u64 = 2048;
    let mut payload = vec![0u8]; // dynstr: "" then a run with no NUL
    payload.extend(std::iter::repeat_n(b'a', RUN));
    let dyn_off = PAYLOAD + payload.len() as u64;
    let mut entries = vec![(5, PAYLOAD), (10, payload.len() as u64)]; // DT_STRTAB, DT_STRSZ
    entries.extend((0..NEEDED).map(|_| (1, 1))); // DT_NEEDED "aaa…"
    let dynamic = dynamic_entries(&entries);
    payload.extend_from_slice(&dynamic);
    let file_end = PAYLOAD + payload.len() as u64;
    let bytes = elf_over_payload(
        &payload,
        &[(1, 0, file_end), (2, dyn_off, dynamic.len() as u64)], // PT_LOAD, PT_DYNAMIC
        &[],
    );
    let elf = Elf::parse(&bytes).unwrap();
    assert_eq!(
        elf.libraries.len(),
        NEEDED as usize,
        "goblin keeps every entry"
    );

    let (v, _, _) = run(&bytes);
    let copied = string_bytes(&v, "elf.needed");
    assert!(
        copied > 0 && copied <= 2 * bytes.len(),
        "{copied} bytes copied"
    );
    assert!(
        v.get("elf.hashes.dyn_hash").is_none(),
        "no hash of a partial list"
    );
}

/// `.symtab` entries may all name one NUL-less run: symhash lowercased a copy
/// per entry (4096 × 64 KiB = 256 MiB). An overrun now yields no hash, while
/// an ordinary table still hashes.
#[test]
fn shared_long_symbol_name_does_not_amplify_symhash() {
    fn symtab_elf(strtab: &[u8], count: usize) -> Vec<u8> {
        let mut payload = strtab.to_vec();
        payload.resize(payload.len().next_multiple_of(8), 0);
        let symtab_off = PAYLOAD + payload.len() as u64;
        for _ in 0..count {
            let mut sym = [0u8; 24];
            sym[0..4].copy_from_slice(&1u32.to_le_bytes()); // st_name
            sym[4] = 0x10; // STB_GLOBAL, SHN_UNDEF
            payload.extend_from_slice(&sym);
        }
        elf_over_payload(
            &payload,
            &[],
            &[
                Sec {
                    name: ".strtab",
                    ty: 3,
                    off: PAYLOAD,
                    size: strtab.len() as u64,
                    ..Sec::default()
                },
                Sec {
                    name: ".symtab",
                    ty: 2,
                    off: symtab_off,
                    size: (count * 24) as u64,
                    link: 1,
                    entsize: 24,
                    ..Sec::default()
                },
            ],
        )
    }
    let mut run_strtab = vec![0u8];
    run_strtab.extend(std::iter::repeat_n(b'A', 64 * 1024));
    let bytes = symtab_elf(&run_strtab, 4096);
    assert_eq!(Elf::parse(&bytes).unwrap().syms.len(), 4096);
    assert!(run(&bytes).0.get("elf.hashes.symhash").is_none());

    let bytes = symtab_elf(b"\0printf\0", 2);
    assert!(run(&bytes).0.get("elf.hashes.symhash").is_some());
}

/// Version-need walks follow file-controlled links with a 16-bit aux count
/// per need, so 1024 needs sharing one 1024-entry aux chain was a million
/// `lib@ver` strings from 32 KiB. The walk now stops at the record cap.
#[test]
fn shared_verneed_aux_chain_is_walked_once_per_cap() {
    const NEEDS: u32 = 1024;
    const AUX: u32 = 1024;
    let mut payload = b"\0a\0b\0".to_vec(); // dynstr
    payload.resize(8, 0);
    let verneed_off = PAYLOAD + payload.len() as u64;
    let aux_start = 16 * NEEDS;
    for i in 0..NEEDS {
        payload.extend_from_slice(&1u16.to_le_bytes()); // vn_version
        payload.extend_from_slice(&(AUX as u16).to_le_bytes()); // vn_cnt
        payload.extend_from_slice(&1u32.to_le_bytes()); // vn_file "a"
        payload.extend_from_slice(&(aux_start - 16 * i).to_le_bytes()); // vn_aux
        payload.extend_from_slice(&16u32.to_le_bytes()); // vn_next
    }
    for _ in 0..AUX {
        payload.extend_from_slice(&[0; 8]); // vna_hash, vna_flags, vna_other
        payload.extend_from_slice(&3u32.to_le_bytes()); // vna_name "b"
        payload.extend_from_slice(&16u32.to_le_bytes()); // vna_next
    }
    let verneed_len = PAYLOAD + payload.len() as u64 - verneed_off;
    let dyn_off = PAYLOAD + payload.len() as u64;
    let dynamic = dynamic_entries(&[(5, PAYLOAD), (10, 5)]); // DT_STRTAB, DT_STRSZ
    payload.extend_from_slice(&dynamic);
    let file_end = PAYLOAD + payload.len() as u64;
    let bytes = elf_over_payload(
        &payload,
        &[(1, 0, file_end), (2, dyn_off, dynamic.len() as u64)],
        &[Sec {
            name: ".gnu.version_r",
            ty: 0x6fff_fffe, // SHT_GNU_VERNEED
            off: verneed_off,
            size: verneed_len,
            info: NEEDS, // need count
            ..Sec::default()
        }],
    );
    let (v, _, _) = run(&bytes);
    let versions = v.get("elf.needed_versions").unwrap().as_array().unwrap();
    assert_eq!(versions.len(), MAX_VERSION_RECORDS);
    assert_eq!(versions[0], "a@b");
}

/// Note program headers may all cover one run of notes: 2000 `PT_NOTE`
/// headers over 4096 empty notes was 8 million drained notes. The walk is now
/// charged against the file length.
#[test]
fn overlapping_note_segments_are_walked_within_the_file_budget() {
    let mut payload = Vec::new();
    for _ in 0..4096 {
        payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]); // empty note, type 1
    }
    let len = payload.len() as u64;
    let phdrs = vec![(4, PAYLOAD, len); 2000]; // PT_NOTE
    let bytes = elf_over_payload(&payload, &phdrs, &[]);
    let (_, _, m) = run(&bytes);
    let notes = m.get("elf.note_count").unwrap();
    assert!(
        notes >= 4096.0 && notes <= (bytes.len() / 12) as f64,
        "{notes}"
    );
}

/// Section names are cut before they are hashed or copied: every header may
/// name a distinct suffix of one NUL-less run, which `name_seen` used to copy
/// whole (1000 headers over 64 KiB is 64 MiB of keys).
#[test]
fn distinct_long_section_names_are_cut() {
    let mut payload = vec![b'.'];
    payload.extend(std::iter::repeat_n(b'x', 64 * 1024));
    let mut bytes = elf_over_payload(&payload, &[], &[]);
    let elf = Elf::parse(&bytes).unwrap();
    let shstrtab = elf.section_headers.last().unwrap().clone();
    drop(elf);
    // Point `.shstrtab` at the run plus its own table, then grow the header
    // count by repeating the last header with names walking the run.
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let run_size = shstrtab.sh_offset + shstrtab.sh_size - PAYLOAD;
    bytes[shoff + 64 + 24..shoff + 64 + 32].copy_from_slice(&PAYLOAD.to_le_bytes());
    bytes[shoff + 64 + 32..shoff + 64 + 40].copy_from_slice(&run_size.to_le_bytes());
    let template: [u8; 64] = bytes[shoff + 64..shoff + 128].try_into().unwrap();
    for i in 0..1000u32 {
        let mut sh = template;
        sh[0..4].copy_from_slice(&i.to_le_bytes());
        sh[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        bytes.extend_from_slice(&sh);
    }
    bytes[60..62].copy_from_slice(&1002u16.to_le_bytes());
    let elf = Elf::parse(&bytes).unwrap();
    let names: Vec<&str> = elf
        .section_headers
        .iter()
        .map(|sh| section_name(&elf, sh))
        .collect();
    assert!(names.iter().all(|n| n.chars().count() <= MAX_SECTION_NAME));
    assert!(names.iter().any(|n| n.chars().count() == MAX_SECTION_NAME));
    let (_, _, m) = run(&bytes);
    assert!(m.get("elf.duplicate_section_name_count").is_some());
}
