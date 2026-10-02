//! Dynamic-section runtime-shape facts beyond the simple count metrics
//! that live in `elf.rs`. Covers:
//!
//! - `elf.verdef[]` — full `.gnu.version_d` records (`name`, `parent`,
//!   `base`). Preserves link-order so trait authors can detect
//!   out-of-position version inserts across releases.
//! - `elf.init_array[]` / `elf.fini_array[]` — resolved constructor /
//!   destructor entries (`addr`, `symbol`, `reloc`). PIE binaries
//!   populate these slots at load time via relocations; the resolved
//!   entries let trait authors gate on `symbol` rather than addresses
//!   that change with ASLR.
//! - `elf.dynsym_functions[]` — focused subset of `.dynsym` FUNC / IFUNC
//!   entries (IFUNC, weak, hidden/protected, or undefined). The
//!   uninteresting global-default-defined entries are reflected in the
//!   import/export panes already.
//!
//! All three are 64-bit-LE only — that's the xz-class target. 32-bit
//! and big-endian ELFs still get the count metrics from `elf.rs`.

use std::collections::HashMap;

use goblin::elf::Elf;
use serde_json::Value as JsonValue;

use crate::Stage;
use crate::formats::goblin_safe;
use crate::metric;
use crate::output::{Errors, Metrics, Values};
use crate::value_key;

/// Slots emitted per `.init_array` / `.fini_array`. A real binary has a
/// handful of constructors; the section size is file-controlled, and every
/// slot becomes a JSON object.
const MAX_INIT_ARRAY_SLOTS: usize = 4096;

/// Emit `elf.verdef[]` records. Replaces the older flat
/// `elf.provided_versions[]` projection.
pub(super) fn verdef(elf: &Elf<'_>, values: &mut Values, errors_out: &mut Errors) {
    let Some(verdef) = elf.verdef.as_ref() else {
        return;
    };
    let mut out: Vec<JsonValue> = Vec::new();
    // Both levels are lazy walks along file-controlled `vd_next` / `vda_next`
    // links.
    for def in goblin_safe::drain_or_record(verdef.iter(), errors_out, Stage::ElfParse) {
        let aux = goblin_safe::drain_or_record(def.iter(), errors_out, Stage::ElfParse);
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
        return;
    }
    let dynsym_index = DynsymAddressIndex::build(elf);
    let relocs = collect_init_relocations(elf);

    for (section, key) in [
        (".init_array", value_key!("elf.init_array")),
        (".fini_array", value_key!("elf.fini_array")),
    ] {
        let Some((sh_addr, slot_bytes)) = section_addr_and_bytes(elf, bytes, section) else {
            continue;
        };
        if slot_bytes.len() / 8 > MAX_INIT_ARRAY_SLOTS {
            metrics.insert(metric!("elf.init_array_slots_capped"), 1.0);
        }
        let out = init_array_entries(sh_addr, slot_bytes, &relocs, &dynsym_index);
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
) -> Vec<JsonValue> {
    let slots = slot_bytes.as_chunks::<8>().0;
    let mut out = Vec::with_capacity(slots.len().min(MAX_INIT_ARRAY_SLOTS));
    for (i, slot) in slots.iter().take(MAX_INIT_ARRAY_SLOTS).enumerate() {
        let direct = u64::from_le_bytes(*slot);
        let slot_va = sh_addr.wrapping_add((i * 8) as u64);
        let (addr, reloc) = resolve_init_slot(direct, slot_va, relocs, dynsym_index);
        let mut node = serde_json::Map::new();
        node.insert("addr".into(), JsonValue::String(format!("0x{addr:x}")));
        if let Some(s) = dynsym_index.lookup(addr) {
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
pub(super) fn dynsym_funcs(elf: &Elf<'_>, values: &mut Values) {
    let mut out: Vec<JsonValue> = Vec::new();
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

/// Look up a section by name and return `(sh_addr, slice)`.
fn section_addr_and_bytes<'a>(
    elf: &Elf<'_>,
    bytes: &'a [u8],
    name: &str,
) -> Option<(u64, &'a [u8])> {
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))?;
    let start = usize::try_from(sh.sh_offset).ok()?;
    let len = usize::try_from(sh.sh_size).ok()?;
    let end = start.checked_add(len)?;
    Some((sh.sh_addr, bytes.get(start..end)?))
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
            dynsym.address_of_index(r.sym_idx).unwrap_or(0),
            Some(r.kind.as_str()),
        ),
    }
}

/// Address-keyed view over `.dynsym` for resolving function pointers
/// to symbol names. Two maps so we can answer both `address → name`
/// (direct/relative slots) and `index → address` (abs64/glob_dat slots
/// referencing a symbol by index), each in constant time per slot.
struct DynsymAddressIndex<'a> {
    /// First symbol at each address, as a linear scan would find it.
    by_addr: HashMap<u64, &'a str>,
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

    fn lookup(&self, addr: u64) -> Option<&'a str> {
        if addr == 0 {
            return None;
        }
        self.by_addr.get(&addr).copied()
    }

    fn address_of_index(&self, idx: u32) -> Option<u64> {
        if idx == 0 {
            return None;
        }
        self.by_index.get(&idx).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slots resolve through keyed lookups — a direct pointer, a relative
    /// relocation, and a GLOB_DAT through the symbol index — and the output
    /// stops at the cap however many slots the section declares.
    #[test]
    fn init_array_slots_resolve_by_key_and_stop_at_the_cap() {
        let mut relocs = HashMap::new();
        let reloc = |kind, addend, sym_idx| InitReloc {
            addend,
            sym_idx,
            kind,
        };
        relocs.insert(0x1008, reloc(RelocKind::Relative, 0x500, 0));
        relocs.insert(0x1010, reloc(RelocKind::GlobDat, 0, 7));
        let index = DynsymAddressIndex {
            by_addr: HashMap::from([(0x400, "ctor"), (0x500, "reloc_ctor"), (0x600, "glob")]),
            by_index: HashMap::from([(7, 0x600)]),
        };
        let mut slots = 0x400_u64.to_le_bytes().to_vec();
        slots.extend([0; 16]);
        let entries = init_array_entries(0x1000, &slots, &relocs, &index);
        assert_eq!(
            entries,
            [
                serde_json::json!({"addr": "0x400", "symbol": "ctor"}),
                serde_json::json!({"addr": "0x500", "symbol": "reloc_ctor", "reloc": "relative"}),
                serde_json::json!({"addr": "0x600", "symbol": "glob", "reloc": "glob_dat"}),
            ]
        );

        let many = vec![0u8; (MAX_INIT_ARRAY_SLOTS + 100) * 8];
        let entries = init_array_entries(0x1000, &many, &relocs, &index);
        assert_eq!(entries.len(), MAX_INIT_ARRAY_SLOTS);
    }
}
