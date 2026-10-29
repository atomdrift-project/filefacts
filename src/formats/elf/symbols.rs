//! The dynamic and static symbol tables: typed imports and exports, the
//! symbol-kind histograms, hardening markers (FORTIFY, stack canary), and the
//! `.symtab` function fallback for binaries no disassembler covered.

use goblin::elf::Elf;
use serde_json::Value as JsonValue;

use super::{NameBudget, load_segment_va_to_offset, section_header};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Recover functions defined in this file from `.symtab` when disassembly
/// yielded none.
///
/// Every binding counts: a static executable keeps its libc entry points
/// (`execve`, `fexecve`, `syscall`) as `.symtab` globals and weaks with no
/// `.dynsym` to export them, so a local-only walk hides exactly the calls a
/// symbol rule looks for. Functions `.dynsym` already exports stay exports
/// only, so a dynamic object reports each name once, in the same view it did.
pub(super) fn static_function_fallback(elf: &Elf<'_>, file_len: usize, out: &mut crate::Symbols) {
    use crate::output::{Symbol, SymbolKind};
    if out
        .iter()
        .any(|symbol| symbol.kind() == SymbolKind::Function)
    {
        return;
    }
    let exported: std::collections::HashSet<&str> = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.st_shndx != 0)
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .collect();
    let mut names = NameBudget::new(file_len);
    for sym in &elf.syms {
        if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        let Some(section) = elf.section_headers.get(sym.st_shndx) else {
            continue;
        };
        if section.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) == 0 {
            continue;
        }
        let Some(name) = elf.strtab.get_at(sym.st_name).filter(|name| {
            !name.is_empty()
                && (sym.st_bind() == goblin::elf::sym::STB_LOCAL || !exported.contains(name))
        }) else {
            continue;
        };
        if !names.take(name.len()) {
            break;
        }
        out.push(Symbol::Function {
            name: name.to_string(),
            offset: Some(sym.st_value),
            complexity: None,
            callees: Vec::new(),
        });
    }
}

pub(super) fn emit(
    elf: &Elf<'_>,
    file_len: usize,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    // Names copied into the typed symbol view and `elf.ifuncs`.
    let mut names = NameBudget::new(file_len);
    // Dynamic-symbol table: imports are undefined (`SHN_UNDEF`, section
    // index 0); exports are defined globals/weaks. STT_GNU_IFUNC entries
    // stay in `values` as a derived ELF-specific list; ordinary imports and
    // exports live only in the typed symbol views.
    let mut ifuncs = Vec::new();
    let mut fortify_count: u64 = 0;
    let mut hidden_count: u64 = 0;
    let mut stack_canary = false;
    // Aggregate symbol-type / binding / visibility histograms across
    // `.symtab` and `.dynsym`. The forensic value is in the *ratio*
    // (Go binaries skew heavily toward STT_FUNC; C++ STL templates
    // generate huge STT_OBJECT counts; rootkits often have many
    // STT_TLS to hide state) so we surface the counts under
    // `elf.symbol_kinds` rather than as individual metrics.
    let mut sym_type_counts: [u64; 16] = [0; 16];
    let mut sym_bind_counts: [u64; 4] = [0; 4];
    let mut sym_vis_counts: [u64; 4] = [0; 4];
    // Static `.symtab` — hidden visibility + stack-canary symbols.
    // `STB_LOCAL = 0`, `STV_HIDDEN = 2`.
    for sym in elf.syms.iter() {
        if sym.st_bind() == 0 && sym.st_visibility() == 2 {
            hidden_count += 1;
        }
        tally_symbol_kinds(
            sym,
            &mut sym_type_counts,
            &mut sym_bind_counts,
            &mut sym_vis_counts,
        );
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
                stack_canary = true;
            }
        }
    }
    // File offset of the `.dynstr` table, so each dynamic symbol's name can be
    // located in the file (`dynstr_offset + st_name`). ELF binds no useful
    // offset to an import-table *entry*, but the name string itself is a real,
    // anchorable location — what consumers want to point at.
    //
    // Prefer the `.dynstr` section header, but fall back to the dynamic
    // segment's `DT_STRTAB` (a virtual address resolved back to a file offset
    // through `PT_LOAD`) when the section table is absent. Release and packed
    // binaries strip section headers entirely while keeping the dynamic symbols
    // fully resolvable, so the section-only lookup would otherwise leave every
    // import name unanchored.
    let dynstr_offset = section_header(elf, ".dynstr")
        .map(|sh| sh.sh_offset)
        .or_else(|| load_segment_va_to_offset(elf, elf.dynamic.as_ref()?.info.strtab as u64));
    for sym in &elf.dynsyms {
        // Hidden + canary on dynsym too.
        if sym.st_bind() == 0 && sym.st_visibility() == 2 {
            hidden_count += 1;
        }
        tally_symbol_kinds(
            sym,
            &mut sym_type_counts,
            &mut sym_bind_counts,
            &mut sym_vis_counts,
        );
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
            stack_canary = true;
        }
        if name.is_empty() {
            continue;
        }
        // FORTIFY_SOURCE imports the `__*_chk` runtime variants of
        // memcpy / strcpy / sprintf / etc. Count them so a single
        // metric tells the trait engine whether the binary was
        // compiled with -D_FORTIFY_SOURCE.
        if name.starts_with("__") && name.ends_with("_chk") {
            fortify_count += 1;
        }
        if !names.take(name.len()) {
            continue;
        }
        let stt = sym.st_info & 0xf;
        if stt == goblin::elf::sym::STT_GNU_IFUNC {
            ifuncs.push(JsonValue::String(name.to_string()));
        }
        // The symbol name's byte offset in the file (via `.dynstr`): a real,
        // file-backed location every consumer can render. Imports and exports
        // both anchor here. `st_value` is a virtual address, not a file offset,
        // and may point into `.bss` with no file backing — so anchoring exports
        // on the name string keeps them consistent with imports and always
        // pointing at bytes that exist in the file.
        let name_off = dynstr_offset.and_then(|base| {
            u64::try_from(sym.st_name)
                .ok()
                .map(|n| base.saturating_add(n))
        });
        if sym.st_shndx == 0 {
            // ELF doesn't bind a dynsym entry to a specific
            // DT_NEEDED library at link time — the dynamic linker
            // resolves at load. Leave `library` unset; consumers
            // that need it walk `elf.needed[]` separately.
            symbols_out.push(crate::Symbol::Import {
                name: name.to_string(),
                alias: None,
                library: None,
                offset: name_off,
                ordinal: None,
            });
        } else if sym.is_function() || sym.st_type() == goblin::elf::sym::STT_OBJECT {
            // Defined functions and data objects are the exported surface.
            symbols_out.push(crate::Symbol::Export {
                name: name.to_string(),
                offset: name_off,
                ordinal: None,
                // ELF doesn't have a forwarded-export concept like
                // PE's reexports — symbol versioning solves the same
                // problem differently and is surfaced through the
                // version-info extractor.
                forward_to: None,
            });
        }
    }
    // Import/export totals flow through cross-format `imports.count`
    // / `exports.count` emitted by `lib.rs::extract_all` after every
    // format extractor runs. No per-format aliases.
    if fortify_count > 0 {
        metrics.insert(metric!("elf.fortify_source_count"), fortify_count as f64);
    }
    if hidden_count > 0 {
        metrics.insert(metric!("elf.hidden_symbol_count"), hidden_count as f64);
    }
    if stack_canary {
        metrics.insert(metric!("elf.stack_canary"), 1.0);
    }
    if !ifuncs.is_empty() {
        values.insert_key(value_key!("elf.ifuncs"), JsonValue::Array(ifuncs));
    }
    emit_symbol_kind_histograms(&sym_type_counts, &sym_bind_counts, &sym_vis_counts, values);
}

/// Bump the type / binding / visibility tallies for one ELF symbol.
/// `STT_*` types past 15 do not exist (the field is 4 bits); same for
/// the 2-bit visibility. `STB_LOCAL` / `GLOBAL` / `WEAK` (0/1/2) are
/// the entire population in practice — anything else is processor-
/// specific and rare enough to round into the array's last slot.
fn tally_symbol_kinds(
    sym: goblin::elf::sym::Sym,
    types: &mut [u64; 16],
    bindings: &mut [u64; 4],
    visibility: &mut [u64; 4],
) {
    let stt = (sym.st_info & 0xf) as usize;
    if let Some(count) = types.get_mut(stt) {
        *count += 1;
    }
    let stb = ((sym.st_info >> 4) & 0xf) as usize;
    if let Some(count) = bindings.get_mut(stb.min(3)) {
        *count += 1;
    }
    let vis = (sym.st_other & 0x3) as usize;
    if let Some(count) = visibility.get_mut(vis) {
        *count += 1;
    }
}

/// Project the three tally arrays into `elf.symbol_kinds.*` under
/// the canonical lowercase names. Empty buckets are suppressed
/// rather than emitted as zeros to keep the JSON output focused on
/// what's actually present.
fn emit_symbol_kind_histograms(
    types: &[u64; 16],
    bindings: &[u64; 4],
    visibility: &[u64; 4],
    values: &mut Values,
) {
    const TYPE_NAMES: [&str; 16] = [
        "notype",
        "object",
        "func",
        "section",
        "file",
        "common",
        "tls",
        "stt_7",
        "stt_8",
        "stt_9",
        "gnu_ifunc",
        "stt_11",
        "stt_12",
        "stt_13",
        "stt_14",
        "stt_15",
    ];
    const BIND_NAMES: [&str; 4] = ["local", "global", "weak", "other"];
    const VIS_NAMES: [&str; 4] = ["default", "internal", "hidden", "protected"];

    let mut by_type = serde_json::Map::new();
    for (name, count) in TYPE_NAMES.iter().zip(types) {
        if *count > 0 {
            by_type.insert((*name).to_string(), JsonValue::Number((*count).into()));
        }
    }
    if !by_type.is_empty() {
        values.insert_key(
            value_key!("elf.symbol_kinds.types"),
            JsonValue::Object(by_type),
        );
    }
    let mut by_bind = serde_json::Map::new();
    for (name, count) in BIND_NAMES.iter().zip(bindings) {
        if *count > 0 {
            by_bind.insert((*name).to_string(), JsonValue::Number((*count).into()));
        }
    }
    if !by_bind.is_empty() {
        values.insert_key(
            value_key!("elf.symbol_kinds.bindings"),
            JsonValue::Object(by_bind),
        );
    }
    let mut by_vis = serde_json::Map::new();
    for (name, count) in VIS_NAMES.iter().zip(visibility) {
        if *count > 0 {
            by_vis.insert((*name).to_string(), JsonValue::Number((*count).into()));
        }
    }
    if !by_vis.is_empty() {
        values.insert_key(
            value_key!("elf.symbol_kinds.visibility"),
            JsonValue::Object(by_vis),
        );
    }
}
