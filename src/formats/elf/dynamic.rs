//! The dynamic section: needed libraries and search paths, `DT_FLAGS`, RELRO,
//! symbol-version requirements and definitions, tag-derived hardening
//! metrics, the dynamic-relocation histogram, resolved init/fini arrays, and
//! the notable `.dynsym` functions.
//!
//! The init/fini resolution reads 64-bit little-endian slots and x86-64 /
//! AArch64 relocation numbers, the targets it was written for; other ELFs
//! still get every count and table above.

use std::collections::{BTreeMap, HashMap};

use goblin::elf::{Elf, dynamic, header, program_header};
use serde_json::Value as JsonValue;

use super::{MAX_VERSION_RECORDS, NameBudget, machine_string, section_bytes, section_header};
use crate::Stage;
use crate::formats::common::put_str;
use crate::formats::goblin_safe;
use crate::metric;
use crate::output::{Errors, Metrics, Values};
use crate::value_key;

/// Decompose `DT_FLAGS` and `DT_FLAGS_1` bitfields into a flat string
/// array — the analyst-facing equivalent of `readelf -d`. Names follow
/// the binutils `DF_*` / `DF_1_*` constants without the prefix.
pub(super) fn dt_flags(elf: &Elf<'_>, values: &mut Values) {
    let Some(dyns) = elf.dynamic.as_ref() else {
        return;
    };
    let mut flags = Vec::new();
    let mut flags1 = Vec::new();
    for d in &dyns.dyns {
        match d.d_tag {
            dynamic::DT_FLAGS => decompose_df(d.d_val, &mut flags),
            dynamic::DT_FLAGS_1 => decompose_df1(d.d_val, &mut flags1),
            _ => {}
        }
    }
    if !flags.is_empty() {
        values.insert_key(
            value_key!("elf.dt_flags"),
            JsonValue::Array(
                flags
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
    if !flags1.is_empty() {
        values.insert_key(
            value_key!("elf.dt_flags_1"),
            JsonValue::Array(
                flags1
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
}

fn decompose_df(v: u64, out: &mut Vec<&'static str>) {
    if v & 0x1 != 0 {
        out.push("origin");
    }
    if v & 0x2 != 0 {
        out.push("symbolic");
    }
    if v & 0x4 != 0 {
        out.push("text_rel");
    }
    if v & 0x8 != 0 {
        out.push("bind_now");
    }
    if v & 0x10 != 0 {
        out.push("static_tls");
    }
}

fn decompose_df1(v: u64, out: &mut Vec<&'static str>) {
    if v & 0x0000_0001 != 0 {
        out.push("now");
    }
    if v & 0x0000_0002 != 0 {
        out.push("global");
    }
    if v & 0x0000_0008 != 0 {
        out.push("no_delete");
    }
    if v & 0x0000_0010 != 0 {
        out.push("load_filter");
    }
    if v & 0x0000_0040 != 0 {
        out.push("init_first");
    }
    if v & 0x0000_0080 != 0 {
        out.push("no_open");
    }
    if v & 0x0000_0100 != 0 {
        out.push("origin");
    }
    if v & 0x0000_0800 != 0 {
        out.push("no_dump");
    }
    if v & 0x0000_2000 != 0 {
        out.push("no_open_2");
    }
    if v & 0x0800_0000 != 0 {
        out.push("pie");
    }
    if v & 0x1000_0000 != 0 {
        out.push("kernel_module");
    }
    if v & 0x4000_0000 != 0 {
        out.push("no_reloc");
    }
}

/// Aggregate per-relocation-type counts across `.rela.dyn` /
/// `.rel.dyn` / `.rela.plt`. The distribution is a useful
/// fingerprint:
///
/// - `R_*_RELATIVE` dominance signals a PIE / shared object
///   resolving load-time fixups.
/// - `R_*_JUMP_SLOT` count tracks the PLT entry count (one per
///   resolved import).
/// - `R_*_COPY` entries indicate the binary needs writable copies
///   of imported `.data` symbols (rare; almost always C++/glibc).
/// - `R_*_IRELATIVE` entries point at `STT_GNU_IFUNC` resolvers —
///   the runtime dispatcher mechanism used by both glibc internal
///   string-function dispatch and a small fraction of malware
///   loaders.
///
/// Names use the canonical binutils mnemonic per architecture.
/// Unrecognised codes fall through to `R_<MACHINE>_<NUM>`.
pub(super) fn relocation_kinds(elf: &Elf<'_>, values: &mut Values) {
    let machine = elf.header.e_machine;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut tally = |r_type: u32| {
        let name = relocation_kind_name(machine, r_type);
        *counts.entry(name).or_insert(0) += 1;
    };
    for r in &elf.dynrelas {
        tally(r.r_type);
    }
    for r in &elf.dynrels {
        tally(r.r_type);
    }
    for r in &elf.pltrelocs {
        tally(r.r_type);
    }
    if counts.is_empty() {
        return;
    }
    let mut obj = serde_json::Map::new();
    for (name, count) in counts {
        obj.insert(name, JsonValue::Number(count.into()));
    }
    values.insert_key(value_key!("elf.relocation_kinds"), JsonValue::Object(obj));
}

/// Per-machine relocation-type mnemonic. Returns the binutils name
/// (`R_X86_64_RELATIVE`, `R_AARCH64_JUMP_SLOT`, …) for the codes
/// most commonly seen in dynamic relocation tables; falls back to a
/// `R_<MACHINE>_<NUM>` string for codes the histogram doesn't cover
/// so unusual values still show up in the output.
fn relocation_kind_name(machine: u16, r_type: u32) -> String {
    let known = match machine {
        header::EM_X86_64 => match r_type {
            0 => Some("R_X86_64_NONE"),
            1 => Some("R_X86_64_64"),
            2 => Some("R_X86_64_PC32"),
            5 => Some("R_X86_64_COPY"),
            6 => Some("R_X86_64_GLOB_DAT"),
            7 => Some("R_X86_64_JUMP_SLOT"),
            8 => Some("R_X86_64_RELATIVE"),
            9 => Some("R_X86_64_GOTPCREL"),
            37 => Some("R_X86_64_IRELATIVE"),
            _ => None,
        },
        header::EM_AARCH64 => match r_type {
            0 => Some("R_AARCH64_NONE"),
            257 => Some("R_AARCH64_ABS64"),
            1024 => Some("R_AARCH64_COPY"),
            1025 => Some("R_AARCH64_GLOB_DAT"),
            1026 => Some("R_AARCH64_JUMP_SLOT"),
            1027 => Some("R_AARCH64_RELATIVE"),
            1042 => Some("R_AARCH64_IRELATIVE"),
            _ => None,
        },
        header::EM_ARM => match r_type {
            0 => Some("R_ARM_NONE"),
            2 => Some("R_ARM_ABS32"),
            18 => Some("R_ARM_COPY"),
            20 => Some("R_ARM_GLOB_DAT"),
            21 => Some("R_ARM_JUMP_SLOT"),
            23 => Some("R_ARM_RELATIVE"),
            160 => Some("R_ARM_IRELATIVE"),
            _ => None,
        },
        header::EM_386 => match r_type {
            0 => Some("R_386_NONE"),
            1 => Some("R_386_32"),
            5 => Some("R_386_COPY"),
            6 => Some("R_386_GLOB_DAT"),
            7 => Some("R_386_JUMP_SLOT"),
            8 => Some("R_386_RELATIVE"),
            42 => Some("R_386_IRELATIVE"),
            _ => None,
        },
        _ => None,
    };
    match known {
        Some(name) => name.to_string(),
        None => format!(
            "R_{}_{r_type}",
            machine_string(machine).to_ascii_uppercase()
        ),
    }
}

/// `elf.*` metrics derived from the dynamic-section tag stream. Each
/// is a hardening / build-environment / sandbox-escape signal the
/// trait engine wants as a numeric/bool flag rather than a substring
/// match against `elf.gnu_property[]` / `elf.dt_flags[]`.
///
/// - `has_dt_textrel` — `DT_TEXTREL` (writable code requirement;
///   normal binaries don't need it, malware loaders sometimes do).
/// - `has_dt_audit` / `has_dt_depaudit` — auditor hooks the loader
///   calls on every dlopen; sandbox-escape signal.
/// - `has_dt_debug` — non-zero `DT_DEBUG` (used by runtime debuggers
///   and some packers).
/// - `has_dt_relr` — modern compressed relocations
///   (glibc 2.36+ / lld 13+).
/// - `has_gnu_hash` — newer hash table format; absence on a recent
///   binary is anomalous.
/// - `init_array_count` / `fini_array_count` / `preinit_array_count`
///   — constructor / destructor counts. CRT-initializer abuse drops
///   payloads into these arrays.
/// - `dt_needed_abs_path_count` / `dt_needed_traversal_count` —
///   anomaly counts over the DT_NEEDED library list.
/// - `dt_runpath_uses_origin` — `$ORIGIN` token in DT_RUNPATH (the
///   canonical relative-path runtime search base; common in modern
///   builds but sometimes abused).
/// - `has_direct_loader_dependency` — a library directly DT_NEEDEDs the
///   dynamic loader (`ld-linux-*.so.*`/`ld-musl-*.so.*`); legit libs
///   pick up the loader transitively via libc, so direct dependency
///   is a strong tampering tell.
pub(super) fn tag_metrics(elf: &Elf<'_>, file_len: usize, metrics: &mut Metrics) {
    use goblin::elf::dynamic::{
        DT_AUDIT, DT_DEBUG, DT_DEPAUDIT, DT_FINI_ARRAYSZ, DT_FLAGS_1, DT_GNU_HASH, DT_INIT_ARRAYSZ,
        DT_PREINIT_ARRAYSZ, DT_RELACOUNT, DT_RPATH, DT_RUNPATH, DT_TEXTREL, DT_VERSYM,
    };
    // DT_RELR (36) isn't a named constant in goblin's enum yet; use
    // the ELF-spec literal directly.
    const DT_RELR: u64 = 36;

    let Some(dynamic) = elf.dynamic.as_ref() else {
        return;
    };

    let mut init_arraysz: u64 = 0;
    let mut fini_arraysz: u64 = 0;
    let mut preinit_arraysz: u64 = 0;
    let mut has_rpath_tag = false;
    let mut has_runpath_tag = false;
    let mut dt_versym_present = false;
    for d in &dynamic.dyns {
        match d.d_tag {
            DT_TEXTREL => {
                metrics.insert(metric!("elf.has_dt_textrel"), 1.0);
            }
            DT_AUDIT => {
                metrics.insert(metric!("elf.has_dt_audit"), 1.0);
            }
            DT_DEPAUDIT => {
                metrics.insert(metric!("elf.has_dt_depaudit"), 1.0);
            }
            DT_DEBUG if d.d_val != 0 => {
                metrics.insert(metric!("elf.has_dt_debug"), 1.0);
            }
            DT_RELR => {
                metrics.insert(metric!("elf.has_dt_relr"), 1.0);
            }
            DT_GNU_HASH => {
                metrics.insert(metric!("elf.has_gnu_hash"), 1.0);
            }
            DT_INIT_ARRAYSZ => init_arraysz = d.d_val,
            DT_FINI_ARRAYSZ => fini_arraysz = d.d_val,
            DT_PREINIT_ARRAYSZ => preinit_arraysz = d.d_val,
            DT_FLAGS_1 => {
                metrics.insert(metric!("elf.dt_flags_1_raw"), d.d_val as f64);
            }
            DT_RELACOUNT => {
                metrics.insert(metric!("elf.relacount"), d.d_val as f64);
            }
            DT_RPATH => has_rpath_tag = true,
            DT_RUNPATH => has_runpath_tag = true,
            DT_VERSYM => dt_versym_present = true,
            _ => {}
        }
    }
    if has_rpath_tag {
        metrics.insert(metric!("elf.has_rpath"), 1.0);
    }
    if has_runpath_tag {
        metrics.insert(metric!("elf.has_runpath"), 1.0);
    }
    // DT_VERSYM presence acts as a marker when the section walk in
    // `elf_numeric_metrics` already established the accurate
    // `.gnu.version` half-count; otherwise this falls back to 1 so
    // trait engines can still distinguish "has versioned symbols at
    // all" from "no versioning".
    if dt_versym_present && metrics.get("elf.dt_versym_count").is_none() {
        metrics.insert(metric!("elf.dt_versym_count"), 1.0);
    }
    let ptr_size = if elf.is_64 { 8u64 } else { 4u64 };
    if init_arraysz > 0 {
        metrics.insert(
            metric!("elf.init_array_count"),
            (init_arraysz / ptr_size) as f64,
        );
    }
    if fini_arraysz > 0 {
        metrics.insert(
            metric!("elf.fini_array_count"),
            (fini_arraysz / ptr_size) as f64,
        );
    }
    if preinit_arraysz > 0 {
        metrics.insert(
            metric!("elf.preinit_array_count"),
            (preinit_arraysz / ptr_size) as f64,
        );
    }

    // DT_NEEDED anomaly walk. Each `elf.libraries` entry is the
    // string already resolved from DT_NEEDED via the dynstr table.
    // Each walk below reads the whole name; entries may all name one long
    // string, so the walks share the budget a copy of them would get.
    let mut scanned = NameBudget::new(file_len);
    let mut abs_path_count: u64 = 0;
    let mut traversal_count: u64 = 0;
    let mut direct_loader_dep = false;
    for needed in elf.libraries.iter().take_while(|s| scanned.take(s.len())) {
        if needed.starts_with('/') {
            abs_path_count += 1;
        }
        if needed.split('/').any(|seg| seg == "..") {
            traversal_count += 1;
        }
        // A library that DT_NEEDs the dynamic loader itself
        // (`ld-linux-*`, `ld-musl-*`, `ld.so`) is anomalous: the loader
        // normally arrives transitively through libc.
        let base = needed.rsplit('/').next().unwrap_or(needed);
        if base.starts_with("ld-linux") || base.starts_with("ld-musl") || base == "ld.so" {
            direct_loader_dep = true;
        }
    }
    if abs_path_count > 0 {
        metrics.insert(
            metric!("elf.dt_needed_abs_path_count"),
            abs_path_count as f64,
        );
    }
    if traversal_count > 0 {
        metrics.insert(
            metric!("elf.dt_needed_traversal_count"),
            traversal_count as f64,
        );
    }
    if direct_loader_dep {
        metrics.insert(metric!("elf.has_direct_loader_dependency"), 1.0);
    }

    // DT_RUNPATH $ORIGIN check — RUNPATH entries also serialise as
    // colon-separated strings via the dynstr table; goblin parsed
    // them into the `runpaths` slice already.
    if elf
        .runpaths
        .iter()
        .take_while(|s| scanned.take(s.len()))
        .any(|p| p.split(':').any(|seg| seg.contains("$ORIGIN")))
    {
        metrics.insert(metric!("elf.dt_runpath_uses_origin"), 1.0);
    }
}

/// Emit the GNU symbol-version requirements one per `library@VERSION`
/// string. Forensically the strongest fingerprint of a Linux binary's
/// build environment: the highest `GLIBC_x.y` in this list is the
/// floor glibc version the binary loads on.
pub(super) fn needed_versions(
    elf: &Elf<'_>,
    file_len: usize,
    values: &mut Values,
    errors_out: &mut Errors,
) {
    let Some(verneed) = elf.verneed.as_ref() else {
        return;
    };
    let mut out: Vec<JsonValue> = Vec::new();
    let mut names = NameBudget::new(file_len);
    // Both levels are lazy walks along file-controlled `vn_next` / `vna_next`
    // links; one record budget spans them.
    let mut left = MAX_VERSION_RECORDS;
    let needs = verneed.iter().take(MAX_VERSION_RECORDS);
    for need in goblin_safe::drain_or_record(needs, errors_out, crate::Stage::ElfParse) {
        let lib = elf.dynstrtab.get_at(need.vn_file).unwrap_or("");
        let auxes = need.iter().take(left);
        let auxes = goblin_safe::drain_or_record(auxes, errors_out, crate::Stage::ElfParse);
        left = left.saturating_sub(auxes.len());
        for aux in auxes {
            let ver = elf.dynstrtab.get_at(aux.vna_name).unwrap_or("");
            if !lib.is_empty() && !ver.is_empty() && names.take(lib.len() + ver.len()) {
                out.push(JsonValue::String(format!("{lib}@{ver}")));
            }
        }
        if left == 0 {
            break;
        }
    }
    if !out.is_empty() {
        values.insert_key(value_key!("elf.needed_versions"), JsonValue::Array(out));
    }
}

/// Determine the RELRO state.
///
/// - **no RELRO** — neither `PT_GNU_RELRO` nor `DT_BIND_NOW`/`DT_FLAGS &
///   BIND_NOW`. Modern toolchains rarely produce this; usually a sign of
///   a hand-rolled or hardened-stripped binary.
/// - **partial** — `PT_GNU_RELRO` present, lazy binding still on. GOT
///   is read-only after relocation but PLT entries are resolved on
///   first call.
/// - **full** — `PT_GNU_RELRO` present AND `DT_BIND_NOW` (or
///   `DT_FLAGS & DF_BIND_NOW`, or `DT_FLAGS_1 & DF_1_NOW`). Everything
///   resolved at load time; GOT *and* PLT are read-only.
pub(super) fn relro(elf: &Elf<'_>, values: &mut Values) {
    let has_relro_segment = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == program_header::PT_GNU_RELRO);
    if !has_relro_segment {
        return;
    }
    let bind_now = elf.dynamic.as_ref().is_some_and(|dyns| {
        dyns.dyns.iter().any(|d| match d.d_tag {
            dynamic::DT_BIND_NOW => true,
            dynamic::DT_FLAGS => (d.d_val & dynamic::DF_BIND_NOW) != 0,
            dynamic::DT_FLAGS_1 => (d.d_val & 0x0000_0001) != 0, // DF_1_NOW
            _ => false,
        })
    });
    put_str(
        values,
        value_key!("elf.relro"),
        if bind_now { "full" } else { "partial" },
    );
}

/// `elf.needed`, `elf.soname`, `elf.rpath` and `elf.runpath`: the library
/// names and search paths the dynamic section declares.
pub(super) fn names(elf: &Elf<'_>, file_len: usize, values: &mut Values) {
    // Every DT_NEEDED / DT_RPATH / DT_RUNPATH entry is a 16-byte record
    // naming a string; they may all name the same long one.
    let mut names = NameBudget::new(file_len);
    let mut copy = |list: &[&str]| -> Vec<JsonValue> {
        list.iter()
            .take_while(|s| names.take(s.len()))
            .map(|s| JsonValue::String((*s).to_string()))
            .collect()
    };
    let needed = copy(&elf.libraries);
    values.insert_key(value_key!("elf.needed"), JsonValue::Array(needed));

    if let Some(soname) = elf.soname {
        put_str(values, value_key!("elf.soname"), soname);
    }
    let rpaths = copy(&elf.rpaths);
    if !rpaths.is_empty() {
        values.insert_key(value_key!("elf.rpath"), JsonValue::Array(rpaths));
    }
    let runpaths = copy(&elf.runpaths);
    if !runpaths.is_empty() {
        values.insert_key(value_key!("elf.runpath"), JsonValue::Array(runpaths));
    }
}

/// Slots emitted per `.init_array` / `.fini_array`. A real binary has a
/// handful of constructors; the section size is file-controlled, and every
/// slot becomes a JSON object.
const MAX_INIT_ARRAY_SLOTS: usize = 4096;

/// Emit `elf.verdef[]`: the symbol versions this object defines, in table
/// order, each with its parent and whether it is the base version.
pub(super) fn verdef(elf: &Elf<'_>, file_len: usize, values: &mut Values, errors_out: &mut Errors) {
    let Some(verdef) = elf.verdef.as_ref() else {
        return;
    };
    let mut out: Vec<JsonValue> = Vec::new();
    let mut names = NameBudget::new(file_len);
    // Both levels are lazy walks along file-controlled `vd_next` / `vda_next`
    // links. Only the first two aux entries (name, parent) are read.
    let defs = verdef.iter().take(MAX_VERSION_RECORDS);
    for def in goblin_safe::drain_or_record(defs, errors_out, Stage::ElfParse) {
        let aux = goblin_safe::drain_or_record(def.iter().take(2), errors_out, Stage::ElfParse);
        let Some(first) = aux.first() else {
            continue;
        };
        let name = elf.dynstrtab.get_at(first.vda_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        // Spec allows multiple aux entries past the head; mainstream
        // toolchains emit at most one (the immediate predecessor).
        let parent = aux
            .get(1)
            .and_then(|a| elf.dynstrtab.get_at(a.vda_name))
            .filter(|s| !s.is_empty());
        if !names.take(name.len() + parent.map_or(0, str::len)) {
            break;
        }
        let is_base = def.vd_flags & 0x1 != 0;
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), JsonValue::String(name.to_string()));
        if let Some(p) = parent {
            obj.insert("parent".into(), JsonValue::String(p.to_string()));
        }
        if is_base {
            obj.insert("base".into(), JsonValue::Bool(true));
        }
        out.push(JsonValue::Object(obj));
    }
    if !out.is_empty() {
        values.insert_key(value_key!("elf.verdef"), JsonValue::Array(out));
    }
}

/// Emit `elf.init_array[]` and `elf.fini_array[]` with each slot's
/// resolved address, exported symbol name (when one matches), and the
/// reloc kind that supplied the address for slots that were 0 at link
/// time. Slots with a direct (non-PIC) pointer have `reloc` unset.
///
/// Only emitted for 64-bit LE ELF — the slot resolution table is
/// arch-specific (x86-64 / aarch64 reloc IDs) and 32-bit ELFs are
/// rare enough to punt. At most [`MAX_INIT_ARRAY_SLOTS`] slots per array
/// are emitted; `elf.init_array_slots_capped` says when more were declared.
pub(super) fn init_arrays(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    if !elf.is_64 || !elf.little_endian {
        tracing::debug!(
            target: "filefacts::elf",
            stage = "init_arrays",
            "init/fini slots are resolved only for 64-bit little-endian ELF"
        );
        return;
    }
    let dynsym_index = DynsymAddressIndex::build(elf);
    // Every slot may resolve to the same long symbol name.
    let mut names = NameBudget::new(bytes.len());
    let relocs = collect_init_relocations(elf);

    for (section, key) in [
        (".init_array", value_key!("elf.init_array")),
        (".fini_array", value_key!("elf.fini_array")),
    ] {
        let Some((sh_addr, slot_bytes)) = section_header(elf, section)
            .and_then(|sh| Some((sh.sh_addr, section_bytes(sh, bytes)?)))
        else {
            continue;
        };
        if slot_bytes.len() / 8 > MAX_INIT_ARRAY_SLOTS {
            metrics.insert(metric!("elf.init_array_slots_capped"), 1.0);
        }
        let out = init_array_entries(sh_addr, slot_bytes, &relocs, &dynsym_index, &mut names);
        if !out.is_empty() {
            values.insert_key(key, JsonValue::Array(out));
        }
    }
}

/// One JSON entry per 8-byte slot of an init/fini array mapped at
/// `sh_addr`, up to [`MAX_INIT_ARRAY_SLOTS`].
fn init_array_entries(
    sh_addr: u64,
    slot_bytes: &[u8],
    relocs: &HashMap<u64, InitReloc>,
    dynsym_index: &DynsymAddressIndex<'_>,
    names: &mut NameBudget,
) -> Vec<JsonValue> {
    let slots = slot_bytes.as_chunks::<8>().0;
    let mut out = Vec::with_capacity(slots.len().min(MAX_INIT_ARRAY_SLOTS));
    for (i, slot) in slots.iter().take(MAX_INIT_ARRAY_SLOTS).enumerate() {
        let direct = u64::from_le_bytes(*slot);
        let slot_va = sh_addr.wrapping_add((i * 8) as u64);
        let (addr, reloc) = resolve_init_slot(direct, slot_va, relocs, dynsym_index);
        let mut node = serde_json::Map::new();
        node.insert("addr".into(), JsonValue::String(format!("0x{addr:x}")));
        if let Some(s) = dynsym_index
            .by_addr
            .get(&addr)
            .copied()
            .filter(|s| names.take(s.len()))
        {
            node.insert("symbol".into(), JsonValue::String(s.to_string()));
        }
        if let Some(r) = reloc {
            node.insert("reloc".into(), JsonValue::String(r.to_string()));
        }
        out.push(JsonValue::Object(node));
    }
    out
}

/// Emit `elf.dynsym_functions[]` — focused subset of FUNC / IFUNC dynsym
/// entries. Skips ordinary global-default-defined entries (those are
/// already in the import/export panes); keeps IFUNC, weak, hidden /
/// protected, and undefined ones.
pub(super) fn dynsym_funcs(elf: &Elf<'_>, file_len: usize, values: &mut Values) {
    let mut out: Vec<JsonValue> = Vec::new();
    let mut names = NameBudget::new(file_len);
    for sym in elf.dynsyms.iter() {
        let st_type = sym.st_info & 0x0f;
        // STT_FUNC = 2, STT_GNU_IFUNC = 10.
        if !matches!(st_type, 2 | 10) {
            continue;
        }
        let st_bind = sym.st_info >> 4;
        let st_vis = sym.st_other & 0x03;
        let defined = sym.st_shndx != 0;
        let interesting = st_type == 10 || st_bind == 2 || matches!(st_vis, 2 | 3) || !defined;
        if !interesting {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if !names.take(name.len()) {
            break;
        }
        let mut node = serde_json::Map::new();
        node.insert("name".into(), JsonValue::String(name.to_string()));
        node.insert(
            "kind".into(),
            JsonValue::String((if st_type == 10 { "ifunc" } else { "func" }).to_string()),
        );
        let binding = match st_bind {
            0 => "local",
            1 => "global",
            2 => "weak",
            _ => "other",
        };
        if binding != "global" {
            node.insert("binding".into(), JsonValue::String(binding.to_string()));
        }
        let visibility = match st_vis {
            0 => "default",
            1 => "internal",
            2 => "hidden",
            3 => "protected",
            _ => "other",
        };
        if visibility != "default" {
            node.insert(
                "visibility".into(),
                JsonValue::String(visibility.to_string()),
            );
        }
        if sym.st_size > 0 {
            node.insert("size".into(), JsonValue::Number(sym.st_size.into()));
        }
        if !defined {
            node.insert("defined".into(), JsonValue::Bool(false));
        }
        out.push(JsonValue::Object(node));
    }
    if out.is_empty() {
        return;
    }
    // Stable order so diffs are meaningful.
    out.sort_by(|a, b| {
        let na = a.get("name").and_then(JsonValue::as_str).unwrap_or("");
        let nb = b.get("name").and_then(JsonValue::as_str).unwrap_or("");
        na.cmp(nb)
    });
    values.insert_key(value_key!("elf.dynsym_functions"), JsonValue::Array(out));
}

#[derive(Debug, Clone, Copy)]
enum RelocKind {
    Relative,
    Irelative,
    Abs64,
    GlobDat,
}

impl RelocKind {
    fn as_str(self) -> &'static str {
        match self {
            RelocKind::Relative => "relative",
            RelocKind::Irelative => "irelative",
            RelocKind::Abs64 => "abs64",
            RelocKind::GlobDat => "glob_dat",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct InitReloc {
    addend: u64,
    sym_idx: u32,
    kind: RelocKind,
}

/// The relocations that can fill an init/fini slot, keyed by the address
/// they patch. When several patch one address the first wins, as a linear
/// scan would have it.
fn collect_init_relocations(elf: &Elf<'_>) -> HashMap<u64, InitReloc> {
    let mut out = HashMap::new();
    for r in elf.dynrelas.iter().chain(elf.pltrelocs.iter()) {
        // x86-64 and aarch64 IDs collapsed into the same arms.
        let kind = match r.r_type {
            8 | 1027 => RelocKind::Relative,
            37 | 1032 => RelocKind::Irelative,
            1 | 257 => RelocKind::Abs64,
            6 | 1025 => RelocKind::GlobDat,
            _ => continue,
        };
        out.entry(r.r_offset).or_insert(InitReloc {
            addend: r.r_addend.unwrap_or(0).cast_unsigned(),
            sym_idx: crate::bytes::sat_u32(r.r_sym),
            kind,
        });
    }
    out
}

fn resolve_init_slot(
    direct: u64,
    slot_va: u64,
    relocs: &HashMap<u64, InitReloc>,
    dynsym: &DynsymAddressIndex<'_>,
) -> (u64, Option<&'static str>) {
    if direct != 0 {
        return (direct, None);
    }
    let Some(r) = relocs.get(&slot_va) else {
        return (0, None);
    };
    match r.kind {
        RelocKind::Relative | RelocKind::Irelative => (r.addend, Some(r.kind.as_str())),
        RelocKind::Abs64 | RelocKind::GlobDat => (
            dynsym.by_index.get(&r.sym_idx).copied().unwrap_or(0),
            Some(r.kind.as_str()),
        ),
    }
}

/// Address-keyed view over `.dynsym` for resolving function pointers
/// to symbol names. Two maps so we can answer both `address → name`
/// (direct/relative slots) and `index → address` (abs64/glob_dat slots
/// referencing a symbol by index), each in constant time per slot.
struct DynsymAddressIndex<'a> {
    /// First symbol at each address, as a linear scan would find it. Address
    /// 0 is never a key: an unresolved slot names no symbol.
    by_addr: HashMap<u64, &'a str>,
    /// Address of each symbol by `.dynsym` index; index 0, the null symbol,
    /// is never a key.
    by_index: HashMap<u32, u64>,
}

impl<'a> DynsymAddressIndex<'a> {
    fn build(elf: &Elf<'a>) -> Self {
        let mut by_addr = HashMap::new();
        let mut by_index = HashMap::new();
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if i == 0 {
                continue;
            }
            let st_type = sym.st_info & 0x0f;
            if !matches!(st_type, 2 | 10) || sym.st_value == 0 {
                continue;
            }
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            by_addr.entry(sym.st_value).or_insert(name);
            let Ok(index) = u32::try_from(i) else { break };
            by_index.insert(index, sym.st_value);
        }
        Self { by_addr, by_index }
    }
}

#[cfg(test)]
mod tests;
