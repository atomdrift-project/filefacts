//! Manual Windows API resolution in native code: the PEB reads, checked
//! export-directory walks and byte-hash loops an importless loader uses to
//! find its APIs by hash and, when rizin recovers the call graph, the hash
//! each call into the resolver requests.
//!
//! These are mechanics, not a claim that a binary communicates over the
//! network. Combined, they distinguish an importless PE's custom
//! module/export resolver from an ordinary PEB read or arithmetic loop. The
//! detectors match instruction shapes, not one compiler's register choice:
//! any general register may carry the accumulator, the byte, or the case
//! folding.

use std::collections::HashMap;

use goblin::pe::PE;
use goblin::pe::section_table::SectionTable;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use memchr::memmem;
use serde_json::Value as JsonValue;

use super::layout::va_to_file_offset;
use crate::formats::common::bytes_at::u32_le;
use crate::formats::common::{RizinTarget, rizin_decision};
use crate::metric;
use crate::output::{Metrics, Section, Values};
use crate::value_key;

/// Cap on the site records [`native_resolver_signals`] emits per kind. One
/// six-byte `fs:[0x30]` needle per match would otherwise let a file of
/// repeated opcodes emit a JSON object for every six bytes it holds.
const MAX_NATIVE_SITES: usize = 4096;

/// `IMAGE_SCN_MEM_EXECUTE`.
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// The resolver mechanics [`native_resolver_signals`] located, for the call
/// graph correlation in [`rizin_importless_analysis`]: the same records it
/// published, capped alike.
pub(super) struct NativeSignals {
    /// VAs of the checked export-directory walks.
    walk_vas: Vec<u64>,
    /// Hash loops whose seed was recovered, so their hashes can be replayed.
    profiles: Vec<LocatedHashProfile>,
}

/// A byte-hash loop's state update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    /// `hash = rol(hash * multiplier ^ byte ^ constant, bits)`.
    MultiplyXorRotate,
    /// `hash = rol(hash ^ constant, bits) * multiplier ^ byte`.
    XorRotateMultiplyXor,
}

impl HashKind {
    fn label(self) -> &'static str {
        match self {
            Self::MultiplyXorRotate => "multiply_xor_rotate",
            Self::XorRotateMultiplyXor => "xor_rotate_multiply_xor",
        }
    }

    /// One step of the update for `byte`.
    fn step(self, hash: u32, byte: u8, multiplier: u32, constant: u32, bits: u32) -> u32 {
        match self {
            Self::MultiplyXorRotate => {
                (hash.wrapping_mul(multiplier) ^ u32::from(byte) ^ constant).rotate_left(bits)
            }
            Self::XorRotateMultiplyXor => {
                (hash ^ constant).rotate_left(bits).wrapping_mul(multiplier) ^ u32::from(byte)
            }
        }
    }
}

/// A byte-hash loop recovered from code, at `loop_offset` in the scanned
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApiHashProfile {
    loop_offset: usize,
    kind: HashKind,
    seed: Option<u32>,
    multiplier: u32,
    xor_constant: u32,
    rotate_bits: u8,
    ascii_lowercase: bool,
}

/// A hash loop at a virtual address, with the seed that makes its hashes
/// reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocatedHashProfile {
    va: u64,
    seed: u32,
    profile: ApiHashProfile,
}

impl LocatedHashProfile {
    /// The hash this loop computes over `name`.
    fn hash(&self, name: &str) -> u32 {
        let p = &self.profile;
        name.bytes().fold(self.seed, |hash, byte| {
            let byte = if p.ascii_lowercase {
                byte.to_ascii_lowercase()
            } else {
                byte
            };
            p.kind.step(
                hash,
                byte,
                p.multiplier,
                p.xor_constant,
                u32::from(p.rotate_bits),
            )
        })
    }
}

/// Where a call site's requested hash came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashSource {
    /// Pushed as an immediate.
    Immediate,
    /// Computed from constants (immediates and initialized data) in the
    /// straight-line code before the call.
    ConstantFolded,
}

impl HashSource {
    fn label(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::ConstantFolded => "constant_folded",
        }
    }
}

/// Cheap native-code indicators for manual Windows API resolution, in
/// executable sections only: scanning resources and encrypted data would
/// make an instruction-shaped byte sequence a noisy fact rather than
/// evidence of resolver code.
pub(super) fn native_resolver_signals(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> NativeSignals {
    let mut peb_x86 = 0;
    let mut peb_x64 = 0;
    let mut export_walks = 0;
    let mut hash_loops = 0;
    let mut peb_sites = Vec::new();
    let mut export_walk_sites = Vec::new();
    let mut hash_profiles = Vec::new();
    let mut signals = NativeSignals {
        walk_vas: Vec::new(),
        profiles: Vec::new(),
    };
    // Section headers may all claim the same raw bytes (up to 192 of them),
    // so clip overlaps first: every file byte is scanned once and every site
    // reported once, attributed to the first section that covers it.
    let ranges = pe
        .sections
        .iter()
        .filter(|section| section.characteristics & SCN_MEM_EXECUTE != 0)
        .map(|section| {
            (
                section.pointer_to_raw_data as usize,
                section.size_of_raw_data as usize,
                section,
            )
        })
        .collect();
    for (range, section) in crate::formats::common::disjoint_file_ranges(ranges, bytes.len()) {
        let start = range.start;
        let Some(code) = bytes.get(range) else {
            continue;
        };
        let site = |local: usize| Site::new(pe, section, start.saturating_add(local));
        // memmem reports non-overlapping matches; no opcode needle searched
        // for here can overlap itself, so that is every match.
        for local in memmem::find_iter(code, b"\x64\xa1\x30\x00\x00\x00") {
            peb_x86 += 1;
            if peb_sites.len() < MAX_NATIVE_SITES {
                peb_sites.push(site(local).fact(serde_json::json!({
                    "architecture": "x86",
                    "mechanism": "fs:[0x30]",
                })));
            }
        }
        for local in memmem::find_iter(code, b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00") {
            peb_x64 += 1;
            if peb_sites.len() < MAX_NATIVE_SITES {
                peb_sites.push(site(local).fact(serde_json::json!({
                    "architecture": "x86_64",
                    "mechanism": "gs:[0x60]",
                })));
            }
        }
        for walk in find_checked_export_walks_x86(code) {
            export_walks += 1;
            if export_walk_sites.len() >= MAX_NATIVE_SITES {
                continue;
            }
            let at = site(walk.mz_check);
            signals.walk_vas.push(at.va);
            export_walk_sites.push(at.fact(serde_json::json!({
                "architecture": "x86",
                "kind": "checked_pe32_export_directory_walk",
                "checks": ["mz_signature", "pe_signature", "export_rva", "export_size"],
                "anchors": {
                    "mz_check_file_offset": start.saturating_add(walk.mz_check),
                    "e_lfanew_file_offset": start.saturating_add(walk.e_lfanew),
                    "pe_check_file_offset": start.saturating_add(walk.pe_check),
                    "export_rva_file_offset": start.saturating_add(walk.export_rva),
                    "export_size_file_offset": start.saturating_add(walk.export_size),
                },
            })));
        }
        for profile in find_custom_byte_hash_profiles_x86(code) {
            hash_loops += 1;
            if hash_profiles.len() >= MAX_NATIVE_SITES {
                continue;
            }
            let at = site(profile.loop_offset);
            if let Some(seed) = profile.seed {
                signals.profiles.push(LocatedHashProfile {
                    va: at.va,
                    seed,
                    profile,
                });
            }
            let mut fact = serde_json::json!({
                "architecture": "x86",
                "kind": profile.kind.label(),
                "multiplier": profile.multiplier,
                "xor_constant": profile.xor_constant,
                "rotate": {
                    "direction": "left",
                    "bits": profile.rotate_bits,
                },
            });
            if let Some(object) = fact.as_object_mut() {
                if let Some(seed) = profile.seed {
                    object.insert("seed".into(), seed.into());
                }
                if profile.ascii_lowercase {
                    object.insert("normalization".into(), "ascii_lowercase".into());
                }
            }
            hash_profiles.push(at.fact(fact));
        }
    }
    // The counts are exact; only the per-site records are capped.
    if peb_x86 + peb_x64 > peb_sites.len()
        || export_walks > export_walk_sites.len()
        || hash_loops > hash_profiles.len()
    {
        metrics.insert(metric!("pe.native_resolver_sites_capped"), 1.0);
    }
    if peb_x86 > 0 {
        metrics.insert(metric!("pe.peb_access_x86_count"), peb_x86 as f64);
    }
    if peb_x64 > 0 {
        metrics.insert(metric!("pe.peb_access_x64_count"), peb_x64 as f64);
    }
    if export_walks > 0 {
        metrics.insert(
            metric!("pe.checked_export_walk_x86_count"),
            export_walks as f64,
        );
    }
    if hash_loops > 0 {
        metrics.insert(
            metric!("pe.custom_byte_hash_loop_x86_count"),
            hash_loops as f64,
        );
    }
    if !peb_sites.is_empty() {
        values.insert_key(
            value_key!("pe.peb_access_sites"),
            JsonValue::Array(peb_sites),
        );
    }
    if !export_walk_sites.is_empty() {
        values.insert_key(
            value_key!("pe.checked_export_walk_sites"),
            JsonValue::Array(export_walk_sites),
        );
    }
    if !hash_profiles.is_empty() {
        values.insert_key(
            value_key!("pe.api_hash_profiles"),
            JsonValue::Array(hash_profiles),
        );
    }
    signals
}

/// Where a native signal sits: its file offset, RVA, VA and section.
struct Site<'a> {
    file_offset: usize,
    rva: u64,
    va: u64,
    section: &'a str,
}

impl<'a> Site<'a> {
    fn new(pe: &PE<'_>, section: &'a SectionTable, file_offset: usize) -> Self {
        let delta = file_offset.saturating_sub(section.pointer_to_raw_data as usize);
        let rva = u64::from(section.virtual_address).saturating_add(delta as u64);
        Self {
            file_offset,
            rva,
            va: pe.image_base.saturating_add(rva),
            section: section.name().unwrap_or(""),
        }
    }

    /// `fact` with the location fields added.
    fn fact(&self, mut fact: JsonValue) -> JsonValue {
        if let Some(object) = fact.as_object_mut() {
            object.insert("file_offset".into(), self.file_offset.into());
            object.insert("rva".into(), self.rva.into());
            object.insert("va".into(), self.va.into());
            object.insert("section".into(), self.section.into());
        }
        fact
    }
}

/// Recover function facts and correlate manual export walkers with their
/// concrete callsites for small importless PEs. This turns "there is an API
/// hash loop somewhere" into the more useful fact "this call requested this
/// hash, which exactly matches this known API under the recovered profile".
pub(super) fn rizin_importless_analysis(
    pe: &PE<'_>,
    target: RizinTarget<'_>,
    native: &NativeSignals,
    values: &mut Values,
    sections: &[Section],
    symbols: &mut crate::Symbols,
    metrics: &mut Metrics,
) {
    let RizinTarget {
        bytes,
        go_function_metadata,
        settings: rizin,
        ..
    } = target;
    const MAX_IMPORTLESS_ANALYSIS_BYTES: usize = 5 * 1024 * 1024;
    if bytes.len() > MAX_IMPORTLESS_ANALYSIS_BYTES
        || symbols
            .iter()
            .any(|symbol| symbol.kind() == crate::SymbolKind::Import)
    {
        return;
    }
    if !rizin_decision(&target, sections, symbols, metrics).runs() || !rizin.admits(bytes) {
        return;
    }
    let Some(recovery) =
        crate::rizin::recover_with_symbols(bytes, symbols.len(), go_function_metadata, rizin)
    else {
        return;
    };
    recover_api_hash_requests(pe, bytes, native, values, metrics, &recovery);
    let recovery = if super::declares_export_directory(pe.header.optional_header.as_ref()) {
        recovery
    } else {
        recovery.without_exports()
    };
    let counts = recovery.apply(symbols, metrics);
    metrics.insert(metric!("pe.rizin_importless_analysis"), 1.0);
    if counts.functions > 0 {
        metrics.insert(
            metric!("pe.rizin_importless_function_count"),
            f64::from(counts.functions),
        );
    }
}

fn recover_api_hash_requests(
    pe: &PE<'_>,
    bytes: &[u8],
    native: &NativeSignals,
    values: &mut Values,
    metrics: &mut Metrics,
    recovery: &crate::rizin::RizinRecovery,
) {
    if native.walk_vas.is_empty() {
        return;
    }
    let ranges = recovery.function_ranges();
    let call_edges = recovery.direct_call_edges();
    let resolved = resolver_calls(
        &ranges,
        &call_edges,
        native.walk_vas.clone(),
        &native.profiles,
    );
    if resolved.is_empty() {
        return;
    }

    let mut requests = Vec::new();
    let mut request_count = 0_usize;
    let mut name_matches = 0_u32;
    let mut folded = 0_u32;
    for (caller_va, callsite_va, resolver_va, profile) in resolved {
        let mut fact = serde_json::Map::new();
        fact.insert("kind".into(), "hashed_pe_export_resolution".into());
        fact.insert("architecture".into(), "x86".into());
        fact.insert("caller_va".into(), caller_va.into());
        fact.insert("callsite_va".into(), callsite_va.into());
        fact.insert("resolver_va".into(), resolver_va.into());
        fact.insert(
            "hash_profile_kind".into(),
            profile.profile.kind.label().into(),
        );
        fact.insert("hash_profile_va".into(), profile.va.into());
        if let Some(callsite_file_offset) = va_to_file_offset(pe, callsite_va) {
            fact.insert("callsite_file_offset".into(), callsite_file_offset.into());
        }
        match recover_x86_hash_argument(pe, bytes, callsite_va) {
            Some((hash, source)) => {
                fact.insert("hash".into(), hash.into());
                fact.insert("hash_hex".into(), format!("0x{hash:08x}").into());
                fact.insert("hash_source".into(), source.label().into());
                if source == HashSource::ConstantFolded {
                    folded = folded.saturating_add(1);
                }
                let matches: Vec<_> = WINDOWS_API_HASH_CANDIDATES
                    .iter()
                    .filter(|(_, name)| profile.hash(name) == hash)
                    .collect();
                if let [(library, name)] = matches.as_slice() {
                    fact.insert("resolved_name".into(), (*name).into());
                    fact.insert("resolved_library".into(), (*library).into());
                    fact.insert("resolution".into(), "exact_hash_match".into());
                    name_matches = name_matches.saturating_add(1);
                }
            }
            None => {
                fact.insert("hash_source".into(), "runtime_expression".into());
            }
        }
        // As for the native sites: the counts are exact, the records capped.
        request_count += 1;
        if requests.len() < MAX_NATIVE_SITES {
            requests.push(JsonValue::Object(fact));
        }
    }
    if request_count > requests.len() {
        metrics.insert(metric!("pe.native_resolver_sites_capped"), 1.0);
    }
    metrics.insert(
        metric!("pe.api_hash_resolver_request_count"),
        request_count as f64,
    );
    if folded > 0 {
        metrics.insert(
            metric!("pe.api_hash_constant_folded_request_count"),
            f64::from(folded),
        );
    }
    if name_matches > 0 {
        metrics.insert(
            metric!("pe.api_hash_name_match_count"),
            f64::from(name_matches),
        );
    }
    values.insert_key(
        value_key!("pe.api_hash_resolver_requests"),
        JsonValue::Array(requests),
    );
}

/// The direct calls into a resolver, `(caller, callsite, resolver)` in edge
/// order, each paired with the hash profile the resolver uses.
///
/// A resolver is a function holding a checked export walk (`walk_sites`). Its
/// profile is the lowest-addressed one inside it or, failing that, inside the
/// first function it calls that holds one. Everything is indexed up front, so
/// the cost is the edge count times a logarithm: rizin may report a million
/// call edges for a few megabytes of `call` instructions.
fn resolver_calls<'p>(
    ranges: &[(u64, u64)],
    call_edges: &[(u64, u64, u64)],
    mut walk_sites: Vec<u64>,
    profiles: &'p [LocatedHashProfile],
) -> Vec<(u64, u64, u64, &'p LocatedHashProfile)> {
    // The first range reported for each entry address, as a linear `find`
    // over `ranges` would pick.
    let mut size_of: HashMap<u64, u64> = HashMap::with_capacity(ranges.len());
    for &(start, size) in ranges {
        size_of.entry(start).or_insert(size);
    }
    walk_sites.sort_unstable();
    let mut by_va: Vec<&LocatedHashProfile> = profiles.iter().collect();
    by_va.sort_by_key(|profile| profile.va);
    // Sorted addresses put the lowest one at or past `start` first; if it is
    // not inside the function, none after it is.
    let first_in = |start: u64| -> Option<&'p LocatedHashProfile> {
        let size = *size_of.get(&start)?;
        let at = by_va.partition_point(|profile| profile.va < start);
        by_va
            .get(at)
            .copied()
            .filter(|profile| va_in_function(profile.va, start, size))
    };

    let mut resolvers: HashMap<u64, Option<&'p LocatedHashProfile>> = ranges
        .iter()
        .filter(|&&(start, size)| {
            let at = walk_sites.partition_point(|&site| site < start);
            walk_sites
                .get(at)
                .is_some_and(|&site| va_in_function(site, start, size))
        })
        .map(|&(start, _)| (start, first_in(start)))
        .collect();
    // A resolver without a hash loop of its own delegates to a helper: the
    // first callee, in edge order, that has one.
    for &(caller, _, target) in call_edges {
        if let Some(slot @ None) = resolvers.get_mut(&caller) {
            *slot = first_in(target);
        }
    }
    call_edges
        .iter()
        .filter_map(|&(caller, callsite, resolver)| {
            let profile = (*resolvers.get(&resolver)?)?;
            Some((caller, callsite, resolver, profile))
        })
        .collect()
}

/// Whether `va` lies in the function at `start`; a zero-sized function holds
/// only its entry.
fn va_in_function(va: u64, start: u64, size: u64) -> bool {
    if size == 0 {
        va == start
    } else {
        va >= start && va < start.saturating_add(size)
    }
}

/// Bytes before a call site searched for the code that computes its hash.
const HASH_ARGUMENT_WINDOW: usize = 48;

/// The hash a stdcall/cdecl call `resolver(module, hash)` at `callsite_va`
/// requests: the second-to-last value pushed before the call (the module is
/// pushed last), when the straight-line code before it fixes that value.
///
/// The code is decoded forward from each offset in a short window before the
/// call, and the decode that lands exactly on the call is evaluated over the
/// 32-bit registers: immediates, loads from initialized data, and `mov`,
/// `xor`, `add`, `sub`, `or`, `and` between them. Anything else that writes a
/// register makes it unknown, so a value is only reported when every step of
/// its computation is a constant, whichever registers carry it.
fn recover_x86_hash_argument(
    pe: &PE<'_>,
    bytes: &[u8],
    callsite_va: u64,
) -> Option<(u32, HashSource)> {
    let callsite = va_to_file_offset(pe, callsite_va)?;
    let start = callsite.saturating_sub(HASH_ARGUMENT_WINDOW);
    let window = bytes.get(start..callsite)?;
    let window_va = callsite_va.checked_sub(window.len() as u64)?;
    let mut info = InstructionInfoFactory::new();
    (0..window.len()).find_map(|skip| {
        let code = window.get(skip..)?;
        let pushes = straight_line_pushes(pe, bytes, code, window_va + skip as u64, &mut info)?;
        match pushes.as_slice() {
            [.., Some(hash), _] => Some(*hash),
            _ => None,
        }
    })
}

/// A 32-bit general register's slot in [`straight_line_pushes`]' state.
fn gpr32(register: Register) -> Option<usize> {
    const GPRS: [Register; 8] = [
        Register::EAX,
        Register::ECX,
        Register::EDX,
        Register::EBX,
        Register::ESP,
        Register::EBP,
        Register::ESI,
        Register::EDI,
    ];
    let full = register.full_register32();
    GPRS.iter().position(|&r| r == full)
}

/// The values pushed by `code`, decoded as 32-bit x86 at `ip` to its end:
/// `Some` where constant, with how it was formed. `None` when the code does
/// not decode as straight-line instructions ending exactly at its last byte.
fn straight_line_pushes(
    pe: &PE<'_>,
    bytes: &[u8],
    code: &[u8],
    ip: u64,
    info: &mut InstructionInfoFactory,
) -> Option<Vec<Option<(u32, HashSource)>>> {
    type Value = Option<(u32, HashSource)>;
    let mut regs: [Value; 8] = [None; 8];
    let read = |regs: &[Value; 8], register: Register| {
        gpr32(register).and_then(|slot| regs.get(slot).copied().flatten())
    };
    let mut pushes = Vec::new();
    let mut decoder = Decoder::with_ip(32, code, ip, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut ins);
        if ins.is_invalid() || ins.flow_control() != FlowControl::Next {
            return None;
        }
        // A constant operand: an immediate, a register holding one, or a
        // dword of initialized data at an absolute address.
        let operand = |regs: &[Value; 8], n: u32| match ins.op_kind(n) {
            OpKind::Immediate8to32 | OpKind::Immediate32 => {
                u32::try_from(ins.immediate(n) & u64::from(u32::MAX))
                    .ok()
                    .map(|v| (v, HashSource::Immediate))
            }
            OpKind::Register => read(regs, ins.op_register(n)),
            OpKind::Memory
                if ins.memory_base() == Register::None
                    && ins.memory_index() == Register::None
                    && ins.memory_size().size() == 4 =>
            {
                let at = va_to_file_offset(pe, u64::from(ins.memory_displacement32()))?;
                u32_le(bytes, at).map(|v| (v, HashSource::ConstantFolded))
            }
            _ => None,
        };
        let dest = (ins.op_count() > 0 && ins.op0_kind() == OpKind::Register)
            .then(|| ins.op0_register())
            .filter(|r| r.is_gpr32());
        let value = match (ins.mnemonic(), dest) {
            (Mnemonic::Push, _) => {
                pushes.push(operand(&regs, 0));
                continue;
            }
            (Mnemonic::Mov, Some(_)) => {
                operand(&regs, 1).map(|(v, _)| (v, HashSource::ConstantFolded))
            }
            // `xor r, r` and `sub r, r` zero the register whatever it held.
            (Mnemonic::Xor | Mnemonic::Sub, Some(d))
                if ins.op1_kind() == OpKind::Register && ins.op1_register() == d =>
            {
                Some((0, HashSource::ConstantFolded))
            }
            (
                Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Or | Mnemonic::And,
                Some(d),
            ) => read(&regs, d)
                .zip(operand(&regs, 1))
                .map(|((a, _), (b, _))| {
                    let v = match ins.mnemonic() {
                        Mnemonic::Xor => a ^ b,
                        Mnemonic::Add => a.wrapping_add(b),
                        Mnemonic::Sub => a.wrapping_sub(b),
                        Mnemonic::Or => a | b,
                        _ => a & b,
                    };
                    (v, HashSource::ConstantFolded)
                }),
            _ => {
                for used in info.info(&ins).used_registers() {
                    if matches!(
                        used.access(),
                        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite
                    ) && let Some(slot) = gpr32(used.register()).and_then(|i| regs.get_mut(i))
                    {
                        *slot = None;
                    }
                }
                continue;
            }
        };
        if let Some(slot) = dest.and_then(gpr32).and_then(|i| regs.get_mut(i)) {
            *slot = value;
        }
    }
    (decoder.position() == code.len()).then_some(pushes)
}

/// The first offset in `bytes[start..start + max]` at which `predicate`
/// holds for the bytes from there on.
fn contains_after(
    bytes: &[u8],
    start: usize,
    max: usize,
    predicate: impl Fn(&[u8]) -> bool,
) -> Option<usize> {
    let end = start.saturating_add(max).min(bytes.len());
    (start..end).find(|&i| bytes.get(i..).is_some_and(&predicate))
}

/// ModR/M with a register operand (`mod == 11`).
fn register_form(modrm: u8) -> bool {
    modrm & 0xc0 == 0xc0
}

/// ModR/M addressing `[esp + disp8]` (`mod == 01`, `rm == 100` with a SIB).
fn esp_disp8_form(modrm: u8) -> bool {
    modrm & 0xc7 == 0x44
}

/// `C1 /0 ib`, ROL r32 by an immediate under 32; the other C1 groups are
/// shifts or ROR.
fn rol_imm(op: &[u8]) -> Option<u8> {
    match *op {
        [0xc1, modrm, bits, ..] if register_form(modrm) && modrm & 0x38 == 0 && bits < 32 => {
            Some(bits)
        }
        _ => None,
    }
}

/// `XOR r32, imm32`, in the accumulator's short form or as `81 /6`: the
/// immediate, and the instruction's length.
fn xor_imm32(op: &[u8]) -> Option<(u32, usize)> {
    match *op {
        [0x35, ..] => Some((u32_le(op, 1)?, 5)),
        [0x81, modrm, ..] if register_form(modrm) && modrm & 0x38 == 0x30 => {
            Some((u32_le(op, 2)?, 6))
        }
        _ => None,
    }
}

/// Whether `code` holds the ASCII case-folding idiom: an `or r8, 0x20` that
/// sets the lowercase bit and a `cmp r8, 0x1a` range check over the 26
/// letters, in any byte registers.
fn folds_ascii_case(code: &[u8]) -> bool {
    // `80 /ext ib` with a register operand, or the AL short form.
    let has = |ext: u8, al_form: u8, imm: u8| {
        code.windows(3).any(|op| {
            matches!(*op, [0x80, modrm, value]
                if register_form(modrm) && (modrm >> 3) & 7 == ext && value == imm)
        }) || code.windows(2).any(|op| op == [al_form, imm])
    };
    has(1, 0x0c, 0x20) && has(7, 0x3c, 0x1a)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckedExportWalk {
    mz_check: usize,
    e_lfanew: usize,
    pe_check: usize,
    export_rva: usize,
    export_size: usize,
}

fn find_checked_export_walks_x86(bytes: &[u8]) -> Vec<CheckedExportWalk> {
    bytes
        .windows(5)
        .enumerate()
        .filter(|(_, w)| {
            // `cmp word ptr [reg], 0x5a4d`: opcode 81 /7 with a memory
            // operand, not an arbitrary 81 instruction containing `MZ`.
            matches!(**w, [0x66, 0x81, modrm, 0x4d, 0x5a]
                if modrm & 0x38 == 0x38 && !register_form(modrm))
        })
        .filter_map(|(start, _)| {
            let pe_offset = contains_after(bytes, start + 5, 64, |b| {
                // `mov reg, [reg+0x3c]` (the PE e_lfanew field).
                matches!(*b, [0x8b, modrm, 0x3c, ..] if modrm & 0xc0 == 0x40)
            })?;
            let signature = contains_after(bytes, pe_offset + 3, 64, |b| {
                // `cmp dword ptr [base+e_lfanew], 0x4550`.
                matches!(*b, [0x81, modrm, _, 0x50, 0x45, 0, 0, ..]
                    if modrm & 0x38 == 0x38 && !register_form(modrm))
            })?;
            let export_directory = contains_after(bytes, signature + 7, 64, |b| {
                // `mov reg, [base+e_lfanew+0x78]`: PE32 export directory.
                matches!(*b, [0x8b, modrm, _, 0x78, ..] if modrm & 0xc0 == 0x40)
            })?;
            let export_size = contains_after(bytes, export_directory + 4, 32, |b| {
                // A checked resolver also reads the paired export-directory
                // size field at +0x7c before dereferencing the directory.
                matches!(*b, [0x8b, modrm, _, 0x7c, ..] if modrm & 0xc0 == 0x40)
            })?;
            Some(CheckedExportWalk {
                mz_check: start,
                e_lfanew: pe_offset,
                pe_check: signature,
                export_rva: export_directory,
                export_size,
            })
        })
        .collect()
}

/// Every byte-hash loop in `bytes`, of either kind, one per loop offset.
fn find_custom_byte_hash_profiles_x86(bytes: &[u8]) -> Vec<ApiHashProfile> {
    let mut profiles: Vec<ApiHashProfile> = bytes
        .windows(6)
        .enumerate()
        // Register-register IMUL with a trailing imm32. Requiring mod=3
        // makes bytes 2..6 unambiguously the multiplier.
        .filter(|(_, w)| matches!(**w, [0x69, modrm, ..] if register_form(modrm)))
        .filter_map(|(start, multiply)| {
            let byte_load = contains_after(bytes, start + 6, 16, |b| b.starts_with(&[0x0f, 0xb6]))?;
            let xor_register = contains_after(bytes, byte_load + 2, 16, |b| {
                b.first().is_some_and(|op| matches!(*op, 0x31 | 0x33))
            })?;
            let xor_constant =
                contains_after(bytes, xor_register + 2, 16, |b| xor_imm32(b).is_some())?;
            let (xor_value, xor_len) = xor_imm32(bytes.get(xor_constant..)?)?;
            let rotate =
                contains_after(bytes, xor_constant + xor_len, 16, |b| rol_imm(b).is_some())?;
            // The seed: the last `mov r32, imm32` before the loop.
            let seed = bytes
                .get(start.saturating_sub(64)..start)
                .and_then(|prefix| {
                    prefix
                        .windows(5)
                        .rfind(|op| matches!(op.first(), Some(0xb8..=0xbf)))
                        .and_then(|op| u32_le(op, 1))
                });
            Some(ApiHashProfile {
                loop_offset: start,
                kind: HashKind::MultiplyXorRotate,
                seed,
                multiplier: u32_le(multiply, 2)?,
                xor_constant: xor_value,
                rotate_bits: rol_imm(bytes.get(rotate..)?)?,
                ascii_lowercase: bytes
                    .get(start.saturating_sub(32)..start)
                    .is_some_and(folds_ascii_case),
            })
        })
        .collect();
    profiles.extend(find_xor_rotate_multiply_hash_profiles_x86(bytes));
    profiles.sort_by_key(|profile| profile.loop_offset);
    profiles.dedup_by_key(|profile| profile.loop_offset);
    profiles
}

/// Recover the alternate state update used by flattened resolvers:
///
/// `hash = (rol(hash ^ constant, bits) * multiplier) ^ lowercase(byte)`.
///
/// The seed may be initialized in a different dispatcher block. We only
/// report it when a concrete stack-slot copy connects the initialization to
/// the accumulator slot loaded by the loop.
fn find_xor_rotate_multiply_hash_profiles_x86(bytes: &[u8]) -> Vec<ApiHashProfile> {
    let mut profiles = Vec::new();
    for (multiply_offset, multiply) in bytes.windows(6).enumerate() {
        if !matches!(*multiply, [0x69, modrm, ..] if register_form(modrm)) {
            continue;
        }
        let rotate_start = multiply_offset.saturating_sub(16);
        let Some((rotate_rel, rotate_bits)) =
            bytes.get(rotate_start..multiply_offset).and_then(|prefix| {
                prefix
                    .windows(3)
                    .enumerate()
                    .rev()
                    .find_map(|(at, op)| Some((at, rol_imm(op)?)))
            })
        else {
            continue;
        };
        let rotate_offset = rotate_start + rotate_rel;
        let xor_start = rotate_offset.saturating_sub(12);
        let Some(xor_rel) = bytes.get(xor_start..rotate_offset).and_then(|prefix| {
            prefix
                .windows(2)
                .rposition(|op| matches!(*op, [0x31 | 0x33, modrm] if register_form(modrm)))
        }) else {
            continue;
        };
        let xor_offset = xor_start + xor_rel;
        let constant_start = xor_offset.saturating_sub(10);
        let Some(constant_load) = bytes.get(constant_start..xor_offset).and_then(|prefix| {
            prefix
                .windows(5)
                .rfind(|op| matches!(op.first(), Some(0xb8..=0xbf)))
        }) else {
            continue;
        };
        let Some(byte_load) = contains_after(bytes, multiply_offset + 6, 16, |op| {
            matches!(*op, [0x0f, 0xb6, _, ..])
        }) else {
            continue;
        };
        if contains_after(bytes, byte_load + 3, 12, |op| {
            op.first().is_some_and(|byte| matches!(*byte, 0x31 | 0x33))
        })
        .is_none()
        {
            continue;
        }
        profiles.push(ApiHashProfile {
            loop_offset: byte_load,
            kind: HashKind::XorRotateMultiplyXor,
            seed: recover_flattened_stack_hash_seed(bytes, xor_offset),
            multiplier: u32_le(multiply, 2).unwrap_or(0),
            xor_constant: u32_le(constant_load, 1).unwrap_or(0),
            rotate_bits,
            ascii_lowercase: bytes
                .get(byte_load.saturating_sub(32)..byte_load)
                .is_some_and(folds_ascii_case),
        });
    }
    profiles
}

/// The seed a flattened resolver copies into its accumulator's stack slot:
/// the loop loads the accumulator from `[esp+hash_slot]`, a dispatcher block
/// copies `[esp+source_slot]` there through a register, and `source_slot`
/// is initialized with an immediate.
fn recover_flattened_stack_hash_seed(bytes: &[u8], loop_offset: usize) -> Option<u32> {
    let prefix = bytes.get(loop_offset.saturating_sub(512)..loop_offset)?;

    // `mov r32, [esp+hash_slot]`
    let hash_slot = prefix.windows(4).rev().find_map(|op| match *op {
        [0x8b, modrm, 0x24, slot] if esp_disp8_form(modrm) => Some(slot),
        _ => None,
    })?;

    // Dispatcher transfer through one register:
    // `mov r32, [esp+source_slot]; mov [esp+hash_slot], r32`.
    let source_slot = prefix.windows(8).rev().find_map(|op| match *op {
        [0x8b, load, 0x24, slot, 0x89, store, 0x24, dst]
            if esp_disp8_form(load) && store == load && dst == hash_slot =>
        {
            Some(slot)
        }
        _ => None,
    })?;

    // `mov dword [esp+source_slot], imm32`.
    prefix.windows(8).rev().find_map(|op| match *op {
        [0xc7, 0x44, 0x24, slot, ..] if slot == source_slot => u32_le(op, 4),
        _ => None,
    })
}

/// The APIs a recovered hash is matched against: the process, memory,
/// thread and networking primitives a loader resolves by hash.
const WINDOWS_API_HASH_CANDIDATES: &[(&str, &str)] = &[
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtClose"),
    ("ntdll.dll", "NtCreateFile"),
    ("ntdll.dll", "NtCreateProcess"),
    ("ntdll.dll", "NtCreateSection"),
    ("ntdll.dll", "NtCreateThreadEx"),
    ("ntdll.dll", "NtDelayExecution"),
    ("ntdll.dll", "NtFreeVirtualMemory"),
    ("ntdll.dll", "NtMapViewOfSection"),
    ("ntdll.dll", "NtOpenProcess"),
    ("ntdll.dll", "NtProtectVirtualMemory"),
    ("ntdll.dll", "NtQueryInformationProcess"),
    ("ntdll.dll", "NtQuerySystemInformation"),
    ("ntdll.dll", "NtReadVirtualMemory"),
    ("ntdll.dll", "NtResumeThread"),
    ("ntdll.dll", "NtSetInformationThread"),
    ("ntdll.dll", "NtTerminateProcess"),
    ("ntdll.dll", "NtUnmapViewOfSection"),
    ("ntdll.dll", "NtWaitForSingleObject"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "RtlAllocateHeap"),
    ("ntdll.dll", "RtlCreateProcessParametersEx"),
    ("ntdll.dll", "RtlGetVersion"),
    ("ntdll.dll", "RtlInitUnicodeString"),
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualProtect"),
    ("winhttp.dll", "WinHttpConnect"),
    ("winhttp.dll", "WinHttpOpen"),
    ("winhttp.dll", "WinHttpOpenRequest"),
    ("winhttp.dll", "WinHttpReadData"),
    ("winhttp.dll", "WinHttpReceiveResponse"),
    ("winhttp.dll", "WinHttpSendRequest"),
    ("wininet.dll", "HttpOpenRequestA"),
    ("wininet.dll", "HttpSendRequestA"),
    ("wininet.dll", "InternetConnectA"),
    ("wininet.dll", "InternetOpenA"),
    ("wininet.dll", "InternetReadFile"),
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "socket"),
];

#[cfg(test)]
mod tests;
