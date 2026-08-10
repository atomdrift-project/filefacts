//! ELF **direct** syscall inventory — syscalls issued via a raw `syscall`/`svc`
//! instruction rather than a libc wrapper.
//!
//! This is deliberately narrow. *Imported* syscall wrappers (`mprotect@plt`, …)
//! are common in legitimate software and are already visible in the imports
//! table, so scoring them invites false positives — that judgment belongs in
//! the ML layer, which weighs the combination. What's genuinely anomalous, and
//! not otherwise visible, is code that issues a syscall **directly, bypassing
//! the library** — the classic evasion move.
//!
//! For each direct site we resolve the syscall number, its name, and any
//! **immediate argument registers**, and emit one `{name, number, offset, args}`
//! record per distinct site into `elf.syscalls_direct[]` (plus
//! `elf.syscalls_arch`, `elf.direct_syscall_count`, `elf.has_indirect_syscall`).
//! Numbers are arch-specific, so read them against `elf.syscalls_arch`; `offset`
//! is a byte offset into the file, at the first call site of that record.
//! We do **not** interpret the arguments here — the flag semantics
//! (`prot & PROT_EXEC`, `personality(ADDR_NO_RANDOMIZE)`, …) live in the trait
//! layer via the `type: syscall` matcher's `arg:` predicate, so a rule can match
//! any constant against any argument without a bespoke fact per flag. Only
//! constant arguments resolve; a computed address or length stays `null`.
//!
//! # Performance
//!
//! `O(text) + O(candidates)`, no global disassembly: a SIMD `memmem` scan for
//! the `syscall`/`svc` opcode over *executable* sections only finds candidate
//! sites; a **bounded local decode** (a short window ending at the site)
//! resolves the number and argument immediates. We never disassemble the whole
//! `.text`. Argument resolution tracks a handful more registers in the same
//! per-candidate decode, so it costs nothing measurable over a number-only pass.

use goblin::elf::Elf;
use goblin::elf::header::{EM_AARCH64, EM_X86_64};
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

use crate::output::{Metrics, Values};

/// Cap on candidate decodes per binary — a backstop against a pathological
/// input full of `0F 05` bytes in data. Real code has few syscall sites.
const MAX_CANDIDATES: usize = 4096;

/// Number of argument registers tracked (the Linux syscall ABI arg count).
const N_ARGS: usize = 6;

/// Resolved operands at one direct-syscall site: the syscall number and up to
/// six argument-register immediates (`None` when an argument isn't a clean
/// constant — a computed address, a value from a prior call, etc.).
#[derive(Default)]
struct Resolved {
    number: Option<u32>,
    args: [Option<u64>; N_ARGS],
}

/// One distinct direct-syscall site: the resolved syscall, plus the argument
/// immediates it was called with. Deduped as a whole, so the same call made with
/// different constants counts as two sites — that difference is the signal.
///
/// `number` is redundant with `name` (the name is looked up *from* the number in
/// this scan's arch table) but is carried anyway: it is what a rule filtering by
/// `number` matches on, and re-deriving it downstream would mean shipping the
/// arch tables there too. Ordering is by name first, so the emitted array reads
/// grouped by syscall.
///
/// The call's file offset is deliberately *not* here — it is the [`Sites`] value,
/// not part of the key, so that two identical calls at different addresses still
/// collapse to one site.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    name: &'static str,
    number: u32,
    args: [Option<u64>; N_ARGS],
}

/// Distinct sites, each mapped to the file offset where it was *first* seen —
/// enough to anchor a finding at real bytes, without the per-call-site fan-out
/// that keeping every offset would cost.
type Sites = BTreeMap<Site, u64>;

pub(super) fn emit(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let mut sites = Sites::new();

    // The generic `syscall()` wrapper takes a runtime number we can't resolve;
    // note its presence (an unresolved computed-number site) but nothing more.
    let indirect = elf
        .dynsyms
        .iter()
        .any(|sym| sym.st_shndx == 0 && elf.dynstrtab.get_at(sym.st_name) == Some("syscall"));

    // Direct syscall instructions — the anomalous, not-otherwise-visible case.
    // The arch label rides along with its scan: syscall numbers are
    // arch-specific, so the label is only meaningful for the table that
    // resolved these names (cleave's `SyscallInfo.arch`).
    let scanned = match elf.header.e_machine {
        EM_X86_64 => Some(("x86_64", scan_x86_64(elf, bytes, &mut sites))),
        EM_AARCH64 => Some(("aarch64", scan_aarch64(elf, bytes, &mut sites))),
        _ => None,
    };
    if let Some((arch, direct)) = scanned {
        if !sites.is_empty() {
            let arr = sites.iter().map(site_json).collect();
            values.insert("elf.syscalls_direct", JsonValue::Array(arr));
            values.insert("elf.syscalls_arch", arch.into());
        }
        if direct > 0 {
            metrics.insert("elf.direct_syscall_count", direct as f64);
        }
    }
    if indirect {
        metrics.insert("elf.has_indirect_syscall", 1.0);
    }
}

/// `{ "name": <str>, "number": <u32>, "offset": <u64>, "args": [<u64|null>, …] }`,
/// trailing unresolved args trimmed. Consumers index `args` positionally (arg 0
/// = `rdi`/`x0`, …), read `number` against this scan's `elf.syscalls_arch`, and
/// treat `offset` as a byte offset into the file.
fn site_json((site, &offset): (&Site, &u64)) -> JsonValue {
    let end = site
        .args
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |i| i + 1);
    let vals: Vec<JsonValue> = site.args[..end]
        .iter()
        .map(|a| a.map_or(JsonValue::Null, JsonValue::from))
        .collect();
    serde_json::json!({
        "name": site.name,
        "number": site.number,
        "offset": offset,
        "args": vals,
    })
}

/// Every executable, file-backed section as `(file offset, bytes)`, yielding no
/// more than the file's own length in total.
///
/// The offset is where the slice starts *in the file*, so a hit's position can
/// be reported as a file offset rather than a section-relative one — the latter
/// is meaningless to every consumer downstream.
///
/// That budget is load-bearing, not tidiness. Section headers are
/// attacker-supplied and nothing requires them to be disjoint: `e_shnum` headers
/// can all point at the same range, so an uncapped walk scans `e_shnum ×
/// filesize` — a few MB of crafted headers becomes terabytes of scanning.
/// One file-length is also the exact bound an *honest* ELF needs, since its
/// executable sections are disjoint slices of that same file, so the cap costs
/// no coverage on any real binary however large.
fn exec_regions<'a>(elf: &'a Elf<'_>, bytes: &'a [u8]) -> impl Iterator<Item = (usize, &'a [u8])> {
    elf.section_headers
        .iter()
        .filter(|sh| sh.sh_flags & u64::from(SHF_EXECINSTR) != 0 && sh.sh_type != SHT_NOBITS)
        .filter_map(|sh| {
            let start = sh.sh_offset as usize;
            Some((
                start,
                bytes.get(start..start.checked_add(sh.sh_size as usize)?)?,
            ))
        })
        .scan(bytes.len(), |budget, (start, region)| {
            if *budget == 0 {
                return None; // spent: stop, rather than yield empty regions
            }
            let take = region.len().min(*budget);
            *budget -= take;
            Some((start, region.get(..take)?))
        })
}

/// x86-64: scan for `0F 05` (`syscall`), resolve the number and arguments from
/// the preceding immediate register loads.
fn scan_x86_64(elf: &Elf<'_>, bytes: &[u8], sites: &mut Sites) -> u64 {
    let finder = memchr::memmem::Finder::new(&[0x0F, 0x05]);
    let mut direct = 0u64;
    let mut budget = MAX_CANDIDATES;
    for (region_off, region) in exec_regions(elf, bytes) {
        for pos in finder.find_iter(region) {
            direct += 1;
            if budget == 0 {
                continue;
            }
            budget -= 1;
            let res = resolve_x86_syscall(region, pos);
            if let Some(nr) = res.number
                && let Some(name) = x86_64_syscall_name(nr)
            {
                sites
                    .entry(Site {
                        name,
                        number: nr,
                        args: res.args,
                    })
                    .or_insert((region_off + pos) as u64);
            }
        }
    }
    direct
}

/// Which field of [`Resolved`] a register write lands in.
#[derive(Clone, Copy)]
enum Slot {
    Number,
    Arg(usize),
}

/// The syscall-ABI slot a register feeds, or `None` if it's not one we track:
/// `rax` carries the number, `rdi, rsi, rdx, r10, r8, r9` the arguments in
/// order. Both the 64- and 32-bit names map to the same slot (a 32-bit write
/// zero-extends into the full register).
fn x86_slot(r: iced_x86::Register) -> Option<Slot> {
    use iced_x86::Register as R;
    Some(match r {
        R::RAX | R::EAX => Slot::Number,
        R::RDI | R::EDI => Slot::Arg(0),
        R::RSI | R::ESI => Slot::Arg(1),
        R::RDX | R::EDX => Slot::Arg(2),
        R::R10 | R::R10D => Slot::Arg(3),
        R::R8 | R::R8D => Slot::Arg(4),
        R::R9 | R::R9D => Slot::Arg(5),
        _ => return None,
    })
}

fn store(res: &mut Resolved, slot: Slot, v: Option<u64>) {
    match slot {
        // A constant too large to be a syscall number (a sign-extended -1, an
        // address) resolves to nothing rather than truncating onto a real one.
        Slot::Number => res.number = v.and_then(|n| u32::try_from(n).ok()),
        Slot::Arg(i) => res.args[i] = v,
    }
}

/// Bounded resolution: decode *forward* through a small window ending at the
/// `syscall` site, keeping the last immediate written to each argument register.
/// A non-immediate write to a tracked register invalidates that slot (the value
/// is computed, not a constant); a `call` clobbers the caller-saved set; an
/// invalid decode means we began mid-instruction, so we resync by resetting.
fn resolve_x86_syscall(region: &[u8], syscall_pos: usize) -> Resolved {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
    const WINDOW: usize = 64;
    let start = syscall_pos.saturating_sub(WINDOW);
    let Some(slice) = region.get(start..syscall_pos) else {
        return Resolved::default();
    };
    let mut dec = Decoder::with_ip(64, slice, start as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut res = Resolved::default();
    while dec.can_decode() {
        dec.decode_out(&mut instr);
        if instr.is_invalid() {
            res = Resolved::default();
            continue;
        }
        let mn = instr.mnemonic();
        if mn == Mnemonic::Call {
            res = Resolved::default();
            continue;
        }
        let Some(slot) = x86_slot(instr.op0_register()) else {
            continue;
        };
        match mn {
            // `try_immediate` is `Err` for a register/memory source, which is
            // exactly the non-constant case below — so both fold into one arm.
            Mnemonic::Mov => store(&mut res, slot, instr.try_immediate(1).ok()),
            Mnemonic::Xor if instr.op0_register() == instr.op1_register() => {
                store(&mut res, slot, Some(0))
            }
            // Any other write to a tracked register makes its value non-constant.
            _ => store(&mut res, slot, None),
        }
    }
    res
}

/// aarch64: fixed-width 4-byte instructions. Scan aligned words for `svc #0`
/// (`0xD4000001`); resolve the number (`x8`) and arguments (`x0..x5`) from
/// preceding `movz Xd, #imm16` loads.
fn scan_aarch64(elf: &Elf<'_>, bytes: &[u8], sites: &mut Sites) -> u64 {
    const SVC0: u32 = 0xD400_0001;
    let mut direct = 0u64;
    let mut budget = MAX_CANDIDATES;
    for (region_off, region) in exec_regions(elf, bytes) {
        for (word, insn) in region.chunks_exact(4).enumerate() {
            if u32::from_le_bytes([insn[0], insn[1], insn[2], insn[3]]) != SVC0 {
                continue;
            }
            direct += 1;
            if budget == 0 {
                continue;
            }
            budget -= 1;
            let res = resolve_aarch64_syscall(region, word * 4);
            if let Some(nr) = res.number
                && let Some(name) = aarch64_syscall_name(nr)
            {
                sites
                    .entry(Site {
                        name,
                        number: nr,
                        args: res.args,
                    })
                    .or_insert((region_off + word * 4) as u64);
            }
        }
    }
    direct
}

/// Look back a small window for `movz Xd, #imm16` (no shift) into the number
/// register (`x8`) or an argument register (`x0..x5`), later writes winning.
/// Shifted `movz`/`movk` chains (immediates above 16 bits) aren't reconstructed,
/// so large argument constants may stay unresolved on aarch64.
fn resolve_aarch64_syscall(region: &[u8], svc_pos: usize) -> Resolved {
    const WINDOW_WORDS: usize = 12;
    let mut res = Resolved::default();
    let Some(window) = region.get(svc_pos.saturating_sub(WINDOW_WORDS * 4)..svc_pos) else {
        return res;
    };
    for insn in window.chunks_exact(4) {
        let w = u32::from_le_bytes([insn[0], insn[1], insn[2], insn[3]]);
        // MOVZ (64-bit), hw = 0: bits [31:21] == 0xD2800000; Rd = w[4:0],
        // imm16 = w[20:5].
        if w & 0xFFE0_0000 != 0xD280_0000 {
            continue;
        }
        let imm = (w >> 5) & 0xFFFF;
        match (w & 0x1F) as usize {
            rd @ 0..=5 => res.args[rd] = Some(u64::from(imm)),
            8 => res.number = Some(imm),
            _ => {}
        }
    }
    res
}

/// x86-64 syscall numbers (from `arch/x86/entry/syscalls`), sensitive subset —
/// execution/memory, process manipulation, evasion, networking. Only these are
/// named; any other resolved number is counted but not surfaced.
fn x86_64_syscall_name(nr: u32) -> Option<&'static str> {
    Some(match nr {
        9 => "mmap",
        10 => "mprotect",
        25 => "mremap",
        41 => "socket",
        42 => "connect",
        44 => "sendto",
        49 => "bind",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        62 => "kill",
        101 => "ptrace",
        135 => "personality",
        157 => "prctl",
        234 => "tgkill",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        317 => "seccomp",
        319 => "memfd_create",
        322 => "execveat",
        _ => return None,
    })
}

/// aarch64 syscall numbers (asm-generic unistd), sensitive subset.
fn aarch64_syscall_name(nr: u32) -> Option<&'static str> {
    Some(match nr {
        92 => "personality",
        117 => "ptrace",
        129 => "kill",
        131 => "tgkill",
        167 => "prctl",
        198 => "socket",
        200 => "bind",
        203 => "connect",
        206 => "sendto",
        216 => "mremap",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        226 => "mprotect",
        270 => "process_vm_readv",
        271 => "process_vm_writev",
        277 => "seccomp",
        279 => "memfd_create",
        281 => "execveat",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let j = site_json((&site, &0x1234));
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

    /// The same call from two addresses is still one site — the offset rides
    /// along as a value, so it must not split the record — and the offset kept
    /// is the first one, not the last.
    #[test]
    fn repeated_identical_calls_collapse_to_the_first_offset() {
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
        assert_eq!(sites.len(), 1, "but they are one distinct site");
        assert_eq!(
            sites.values().next(),
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
}
