use super::*;

#[test]
fn x86_register_copy_and_read_only_operands() {
    // mov ebx,18; mov eax,ebx; cmp eax,0; test eax,eax
    let code = [0xbb, 18, 0, 0, 0, 0x89, 0xd8, 0x83, 0xf8, 0, 0x85, 0xc0];
    assert_eq!(resolve_x86_syscall(&code, code.len()).number, Some(18));
}

#[test]
fn x86_clobbers_do_not_preserve_stale_numbers() {
    for suffix in [
        vec![0xb0, 1],
        vec![0x0f, 5],
        vec![0xeb, 0],
        vec![0xf7, 0xe3],
    ] {
        let mut code = vec![0xb8, 18, 0, 0, 0];
        code.extend(suffix);
        assert_eq!(resolve_x86_syscall(&code, code.len()).number, None);
    }
}

#[test]
fn syscall_bytes_inside_immediate_are_not_sites() {
    let bytes = elf_with_exec_sections(EM_X86_64, &[0xb8, 0x0f, 0x05, 0, 0], 1);
    let elf = Elf::parse(&bytes).unwrap();
    assert_eq!(scan_x86_64(&elf, &bytes, &mut Sites::new()), 0);
}

#[test]
fn file_io_unknown_numbers_and_overlap_are_preserved() {
    let mut code = Vec::new();
    for number in [0u32, 1, 2, 3, 4, 5, 17, 18, 77, 89, 10000] {
        code.push(0xb8);
        code.extend(number.to_le_bytes());
        code.extend([0x0f, 5]);
    }
    let bytes = elf_with_exec_sections(EM_X86_64, &code, 3);
    let elf = Elf::parse(&bytes).unwrap();
    let mut sites = Sites::new();
    assert_eq!(scan_x86_64(&elf, &bytes, &mut sites), 11);
    assert_eq!(sites.len(), 11);
    let unknown = sites.values().find(|s| s.number == 10000).unwrap();
    assert_eq!(unknown.name, "unknown");
    assert_eq!(x86_64_syscall_name(18), Some("pwrite64"));
    assert_eq!(aarch64_syscall_name(68), Some("pwrite64"));
}

#[test]
fn sectionless_executable_segment_is_scanned() {
    let code = [0xb8, 18, 0, 0, 0, 0x0f, 5];
    let mut bytes = elf_with_exec_sections(EM_X86_64, &[], 0);
    bytes.resize(120 + code.len(), 0);
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[40..48].fill(0);
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[60..62].fill(0);
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&120u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[120..].copy_from_slice(&code);
    let elf = Elf::parse(&bytes).unwrap();
    let mut sites = Sites::new();
    assert_eq!(scan_x86_64(&elf, &bytes, &mut sites), 1);
    assert_eq!(sites[&125].name, "pwrite64");
}

#[test]
fn aarch64_unknown_instruction_invalidates_constants() {
    let mut code = (0xd2800000u32 | (226 << 5) | 8).to_le_bytes().to_vec();
    code.extend(0xd4000001u32.to_le_bytes());
    assert_eq!(resolve_aarch64_syscall(&code, code.len()).number, None);
}

#[test]
fn x86_resolves_mov_eax_then_syscall() {
    // mov eax, 10 (mprotect); syscall
    let code = [0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05];
    assert_eq!(resolve_x86_syscall(&code, 5).number, Some(10));
    assert_eq!(x86_64_syscall_name(10), Some("mprotect"));
}

#[test]
fn x86_resolves_xor_eax_then_syscall() {
    // xor eax, eax (read=0); syscall
    let code = [0x31, 0xC0, 0x0F, 0x05];
    assert_eq!(resolve_x86_syscall(&code, 2).number, Some(0));
}

#[test]
fn x86_resolves_mprotect_prot_arg() {
    // mov edx, 7 (PROT_READ|WRITE|EXEC); mov eax, 10 (mprotect); syscall
    let code = [
        0xBA, 0x07, 0x00, 0x00, 0x00, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05,
    ];
    let res = resolve_x86_syscall(&code, 10);
    assert_eq!(res.number, Some(10));
    assert_eq!(res.args[2], Some(7)); // prot arg carries the raw constant
}

#[test]
fn x86_computed_arg_is_unresolved() {
    // mov edx, eax (computed prot); mov eax, 10; syscall — arg 2 must be None.
    let code = [0x89, 0xC2, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let res = resolve_x86_syscall(&code, 7);
    assert_eq!(res.number, Some(10));
    assert_eq!(res.args[2], None);
}

#[test]
fn x86_out_of_range_number_resolves_to_nothing() {
    // mov rax, -1; syscall — sign-extends to u64::MAX. Truncating to u32
    // would alias onto a real syscall, so it must resolve to no number.
    let code = [0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x05];
    assert_eq!(resolve_x86_syscall(&code, 7).number, None);
}

#[test]
fn site_json_carries_number_and_trims_trailing_unresolved_args() {
    let mut args = [None; N_ARGS];
    args[2] = Some(7);
    let site = Site {
        name: "mprotect",
        number: 10,
        args,
    };
    let j = site_json((&0x1234, &site));
    assert_eq!(j["name"], "mprotect");
    // Rules filter on `number`; emitting it is what makes that filter work.
    assert_eq!(j["number"], 10);
    assert_eq!(j["offset"], 0x1234);
    assert_eq!(j["args"], serde_json::json!([null, null, 7]));
}

/// Minimal goblin-parseable ELF64 LE holding `code` once, declared by
/// `n_exec` executable section headers that all point at the same bytes —
/// the shape a crafted input uses to multiply scan work.
fn elf_with_exec_sections(machine: u16, code: &[u8], n_exec: u16) -> Vec<u8> {
    const EH: usize = 64; // ELF64 header size
    const SH: usize = 64; // ELF64 section header size

    let code_off = EH;
    let shtab_off = code_off + code.len();
    let shnum = n_exec + 1; // [0] is the mandatory null header
    let mut buf = vec![0u8; shtab_off + usize::from(shnum) * SH];

    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    buf[18..20].copy_from_slice(&machine.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    buf[40..48].copy_from_slice(&(shtab_off as u64).to_le_bytes()); // e_shoff
    buf[52..54].copy_from_slice(&(EH as u16).to_le_bytes()); // e_ehsize
    buf[58..60].copy_from_slice(&(SH as u16).to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&shnum.to_le_bytes()); // e_shnum

    buf[code_off..code_off + code.len()].copy_from_slice(code);

    for i in 1..=usize::from(n_exec) {
        let base = shtab_off + i * SH;
        buf[base + 4..base + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        buf[base + 8..base + 16].copy_from_slice(&u64::from(SHF_EXECINSTR).to_le_bytes()); // sh_flags
        buf[base + 24..base + 32].copy_from_slice(&(code_off as u64).to_le_bytes());
        buf[base + 32..base + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
    }
    buf
}

/// End-to-end: a real `mprotect` site reaches `elf.syscalls_direct[]` with
/// its number intact, alongside the arch label needed to interpret it.
#[test]
fn emit_publishes_resolved_number_with_arch() {
    // mov edx, 7 (PROT_RWX); mov eax, 10 (mprotect); syscall
    let code = [
        0xBA, 0x07, 0x00, 0x00, 0x00, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05,
    ];
    let bytes = elf_with_exec_sections(EM_X86_64, &code, 1);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");

    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(&elf, &bytes, &mut values, &mut metrics);

    let sites = values
        .get("elf.syscalls_direct")
        .and_then(|v| v.as_array())
        .expect("a direct syscall site must be published");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0]["name"], "mprotect");
    assert_eq!(sites[0]["number"], 10);
    assert_eq!(sites[0]["args"], serde_json::json!([null, null, 7]));
    assert_eq!(
        values.get("elf.syscalls_arch").and_then(|v| v.as_str()),
        Some("x86_64"),
        "the number is meaningless without the table that produced it"
    );
    // The section starts at file offset 64 and `0F 05` sits 10 bytes in.
    // A section-*relative* 10 here would silently anchor every finding to
    // the wrong bytes, so pin the absolute value.
    assert_eq!(sites[0]["offset"], 74);
}

/// Repeated calls retain distinct evidence offsets and count independently.
#[test]
fn repeated_identical_calls_keep_each_offset() {
    // Two identical `mov eax,10; syscall` sequences, 16 bytes apart.
    let one = [0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let mut code = one.to_vec();
    code.resize(16, 0x90); // pad with NOPs
    code.extend_from_slice(&one);

    let bytes = elf_with_exec_sections(EM_X86_64, &code, 1);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");
    let mut sites = Sites::new();
    let direct = scan_x86_64(&elf, &bytes, &mut sites);

    assert_eq!(direct, 2, "both call sites are counted");
    assert_eq!(
        sites.len(),
        2,
        "each instruction retains its evidence offset"
    );
    assert_eq!(
        sites.keys().next(),
        Some(&(64 + 5)),
        "the earlier offset wins"
    );
}

/// A crafted aarch64 binary can hold arbitrarily many *distinct* syscall
/// sites: `movz x0, #i` varies the resolved arg, so every site is a new
/// `BTreeSet` entry. Without a decode budget the site set — and every
/// downstream copy of it — grows with the file. x86-64 has always had this
/// budget; aarch64 must too.
#[test]
fn aarch64_site_set_is_bounded_by_candidate_budget() {
    let movz_x8 = 0xD280_0000u32 | (226u32 << 5) | 8; // mprotect
    let svc = 0xD400_0001u32;
    let mut code = Vec::new();
    for i in 0..(MAX_CANDIDATES as u32 + 500) {
        let movz_x0 = 0xD280_0000u32 | ((i & 0xFFFF) << 5); // Rd = x0
        code.extend_from_slice(&movz_x0.to_le_bytes());
        code.extend_from_slice(&movz_x8.to_le_bytes());
        code.extend_from_slice(&svc.to_le_bytes());
    }
    let bytes = elf_with_exec_sections(EM_AARCH64, &code, 1);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");

    let mut sites = Sites::new();
    let direct = scan_aarch64(&elf, &bytes, &mut sites);

    assert!(!sites.is_empty(), "the scan must still find real sites");
    assert!(
        sites.len() <= MAX_CANDIDATES,
        "site set must stay bounded, got {}",
        sites.len()
    );
    // The *count* metric stays honest past the budget, as on x86-64.
    assert_eq!(direct, u64::from(MAX_CANDIDATES as u32 + 500));
}

/// Section headers are attacker-supplied and need not be disjoint. Many
/// headers over one range must not multiply the bytes scanned.
#[test]
fn overlapping_exec_sections_cannot_multiply_scan_work() {
    const SECTION_LEN: usize = 1024 * 1024;
    let code = vec![0u8; SECTION_LEN];
    // 300 × 1 MiB claims 300 MiB of scanning from a ~1 MiB file.
    let bytes = elf_with_exec_sections(EM_X86_64, &code, 300);
    let elf = Elf::parse(&bytes).expect("synthetic ELF must parse");

    let scanned: usize = exec_regions(&elf, &bytes).map(|(_, r)| r.len()).sum();
    assert!(
        scanned <= bytes.len(),
        "300 MiB of claims must collapse to at most one {}-byte pass, got {scanned}",
        bytes.len()
    );

    // An honest section is scanned in full — the cap costs no coverage.
    let one = elf_with_exec_sections(EM_X86_64, &code, 1);
    let elf = Elf::parse(&one).expect("synthetic ELF must parse");
    let scanned: usize = exec_regions(&elf, &one).map(|(_, r)| r.len()).sum();
    assert_eq!(scanned, SECTION_LEN);
}

#[test]
fn aarch64_resolves_movz_x8_and_args() {
    // movz x2, #4 (PROT_EXEC); movz x8, #226 (mprotect); svc #0
    let movz_x2 = 0xD280_0000u32 | (4u32 << 5) | 2;
    let movz_x8 = 0xD280_0000u32 | (226u32 << 5) | 8;
    let mut region = movz_x2.to_le_bytes().to_vec();
    region.extend_from_slice(&movz_x8.to_le_bytes());
    region.extend_from_slice(&0xD400_0001u32.to_le_bytes());
    let res = resolve_aarch64_syscall(&region, 8);
    assert_eq!(res.number, Some(226));
    assert_eq!(res.args[2], Some(4));
    assert_eq!(aarch64_syscall_name(226), Some("mprotect"));
}
/// Test the emitted facts contract, without cleave or external binaries.
fn emitted_sites(machine: u16, code: &[u8]) -> Vec<JsonValue> {
    let bytes = elf_with_exec_sections(machine, code, 1);
    let elf = Elf::parse(&bytes).unwrap();
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(&elf, &bytes, &mut values, &mut metrics);
    assert_eq!(
        values.get("elf.syscalls_arch").unwrap(),
        if machine == EM_X86_64 {
            "x86_64"
        } else {
            "aarch64"
        }
    );
    values
        .get("elf.syscalls_direct")
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn x86_emit_preserves_all_six_abi_arguments_and_zero_extension() {
    // Linux uses r10, not rcx, for arg 3. A 32-bit write zero-extends.
    let code = [
        0xbf, 1, 0, 0, 0, // edi = 1
        0xbe, 2, 0, 0, 0, // esi = 2
        0xba, 0x80, 0xff, 0xff, 0xff, // edx = 0xffffff80
        0x41, 0xba, 4, 0, 0, 0, // r10d = 4
        0x41, 0xb8, 5, 0, 0, 0, // r8d = 5
        0x41, 0xb9, 6, 0, 0, 0, // r9d = 6
        0xb9, 99, 0, 0, 0, // ecx must not replace arg 3
        0xb8, 9, 0, 0, 0, 0x0f, 0x05, // mmap
    ];
    let sites = emitted_sites(EM_X86_64, &code);
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0]["name"], "mmap");
    assert_eq!(
        sites[0]["args"],
        serde_json::json!([1, 2, 4294967168u64, 4, 5, 6])
    );
    assert_eq!(sites[0]["offset"], 64 + code.len() - 2);
}

#[test]
fn x86_emit_keeps_per_site_arguments_without_cross_call_leakage() {
    let code = [
        0xba, 2, 0, 0, 0, 0xb8, 10, 0, 0, 0, 0x0f, 5, // mprotect PROT_WRITE
        0xba, 4, 0, 0, 0, 0xb8, 10, 0, 0, 0, 0x0f, 5, // mprotect PROT_EXEC
        0xb8, 10, 0, 0, 0, 0x0f, 5, // unknown protection
    ];
    let sites = emitted_sites(EM_X86_64, &code);
    assert_eq!(sites.len(), 3);
    assert_eq!(sites[0]["args"], serde_json::json!([null, null, 2]));
    assert_eq!(sites[1]["args"], serde_json::json!([null, null, 4]));
    assert_eq!(sites[2]["args"], serde_json::json!([]));
    assert_eq!(
        sites
            .iter()
            .map(|s| s["offset"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![74, 86, 93]
    );
}

fn aarch64_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

#[test]
fn aarch64_emit_preserves_six_arguments_and_unknown_numbers() {
    // Six MOVZ argument loads, a NOP, then an unmapped syscall number.
    let mut words: Vec<u32> = (0..6).map(|r| 0xd2800000 | ((r + 1) << 5) | r).collect();
    words.extend([0xd503201f, 0xd2800008 | (10000 << 5), 0xd4000001]);
    let sites = emitted_sites(EM_AARCH64, &aarch64_words(&words));
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0]["name"], "unknown");
    assert_eq!(sites[0]["number"], 10000);
    assert_eq!(sites[0]["args"], serde_json::json!([1, 2, 3, 4, 5, 6]));
    assert_eq!(sites[0]["offset"], 96);
}

#[test]
fn aarch64_emit_does_not_leak_arguments_across_svc() {
    let code = aarch64_words(&[
        0xd2800002 | (4 << 5), // x2 = PROT_EXEC
        0xd2800008 | (226 << 5),
        0xd4000001,
        0xd2800008 | (226 << 5),
        0xd4000001,
    ]);
    let sites = emitted_sites(EM_AARCH64, &code);
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0]["name"], "mprotect");
    assert_eq!(sites[0]["args"], serde_json::json!([null, null, 4]));
    assert_eq!(sites[1]["args"], serde_json::json!([]));
    assert_eq!(sites[0]["offset"], 72);
    assert_eq!(sites[1]["offset"], 80);
}

#[test]
fn aarch64_shifted_constant_is_unknown_not_a_small_flag() {
    let code = aarch64_words(&[
        0xd2a00000 | (0x1000 << 5), // movz x0, #0x1000, lsl #16
        0xd2800008 | (97 << 5),
        0xd4000001, // unshare
    ]);
    let sites = emitted_sites(EM_AARCH64, &code);
    assert_eq!(sites[0]["name"], "unshare");
    // Until shifted MOVZ is supported, do not fabricate arg 0 = 0x1000.
    assert_eq!(sites[0]["args"], serde_json::json!([]));
}

#[test]
fn aarch64_file_io_names_use_the_correct_abi_table() {
    let cases = [
        (56, "openat"),
        (57, "close"),
        (63, "read"),
        (64, "write"),
        (67, "pread64"),
        (68, "pwrite64"),
        (46, "ftruncate"),
        (78, "readlinkat"),
        (79, "newfstatat"),
        (80, "fstat"),
    ];
    let words: Vec<u32> = cases
        .iter()
        .flat_map(|(number, _)| [0xd2800008 | (number << 5), 0xd4000001])
        .collect();
    let sites = emitted_sites(EM_AARCH64, &aarch64_words(&words));
    assert_eq!(sites.len(), cases.len());
    for (site, (number, name)) in sites.iter().zip(cases) {
        assert_eq!(site["number"], number);
        assert_eq!(site["name"], name);
    }
}

/// The name tables are indexed by number: the first and last slots resolve,
/// and gaps, the reserved range between the classic and the shared
/// 424+ numbers, and anything past the end are unnamed.
#[test]
fn syscall_tables_resolve_by_index_and_leave_gaps_unnamed() {
    assert_eq!(x86_64_syscall_name(0), Some("read"));
    assert_eq!(aarch64_syscall_name(0), Some("io_setup"));
    assert_eq!(x86_64_syscall_name(462), Some("mseal"));
    assert_eq!(x86_64_syscall_name(424), Some("pidfd_send_signal"));
    assert_eq!(aarch64_syscall_name(424), Some("pidfd_send_signal"));
    assert_eq!(x86_64_syscall_name(400), None);
    assert_eq!(aarch64_syscall_name(400), None);
    assert_eq!(x86_64_syscall_name(463), None);
    assert_eq!(x86_64_syscall_name(u32::MAX), None);
}
