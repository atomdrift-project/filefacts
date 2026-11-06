//! The dynamic and static symbol tables: typed imports and exports, the
//! symbol-kind histograms, hardening markers (FORTIFY, stack canary), and the
//! `.symtab` function fallback for binaries binform could not recover.

use std::collections::HashMap;

use goblin::elf::Elf;
use goblin::elf::sym::{STB_LOCAL, STV_HIDDEN};
use serde_json::Value as JsonValue;

use super::{NameBudget, load_segment_va_to_offset, section_header};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Name the `.symtab` functions that lie in executable sections: the last
/// resort when binform recovered no inventory (an instruction set it does not
/// decode) and there was no pclntab. A no-op when `out` already holds any
/// function. These names carry no complexity or call graph.
///
/// Every binding counts: a static executable keeps its libc entry points
/// (`execve`, `fexecve`, `syscall`) as `.symtab` globals and weaks with no
/// `.dynsym` to export them, so a local-only walk hides exactly the calls a
/// symbol rule looks for. Functions `.dynsym` already exports stay exports
/// only, so a dynamic object reports each name once, in the same view it did.
///
/// When an inventory already exists (binform recovered it), only the public
/// `.symtab` names it lacks are added: binform names each address once, so a
/// static libc's weak entry point (`sendto`) disappears behind its internal
/// alias (`__sendto`) at the same address, and with no `.dynsym` nothing else
/// reports it.
pub(super) fn static_function_fallback(elf: &Elf<'_>, file_len: usize, out: &mut crate::Symbols) {
    use crate::output::{Symbol, SymbolKind};
    let have_inventory = crate::formats::common::has_functions(out);
    let present: std::collections::HashSet<String> = if have_inventory {
        out.iter()
            .filter(|symbol| matches!(symbol.kind(), SymbolKind::Function | SymbolKind::Export))
            .filter_map(Symbol::name)
            .map(str::to_string)
            .collect()
    } else {
        std::collections::HashSet::new()
    };
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
                && (sym.st_bind() == STB_LOCAL || !exported.contains(name))
                && (!have_inventory || (sym.st_bind() != STB_LOCAL && !present.contains(*name)))
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
    layout: Option<&binform::Binary<'_>>,
    file_len: usize,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    // Names copied into the typed symbol view and `elf.ifuncs`.
    let mut names = NameBudget::new(file_len);
    // The typed imports and exports are binform's (see `push_tables`); the
    // dynamic-symbol table walk here locates their names and derives the
    // ELF-specific facts. STT_GNU_IFUNC entries stay in `values` as a
    // derived list.
    let mut name_offsets: HashMap<&str, u64> = HashMap::new();
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
    for sym in elf.syms.iter() {
        if sym.st_bind() == STB_LOCAL && sym.st_visibility() == STV_HIDDEN {
            hidden_count += 1;
        }
        tally_symbol_kinds(
            sym,
            &mut sym_type_counts,
            &mut sym_bind_counts,
            &mut sym_vis_counts,
        );
        if let Some(name) = elf.strtab.get_at(sym.st_name)
            && (name == "__stack_chk_fail" || name == "__stack_chk_guard")
        {
            stack_canary = true;
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
        if sym.st_bind() == STB_LOCAL && sym.st_visibility() == STV_HIDDEN {
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
        let stt = sym.st_info & 0xf;
        if stt == goblin::elf::sym::STT_GNU_IFUNC && names.take(name.len()) {
            ifuncs.push(JsonValue::String(name.to_string()));
        }
        // The symbol name's byte offset in the file (via `.dynstr`), where
        // its import or export is anchored (see `push_tables`).
        if let Some(offset) = dynstr_offset.and_then(|base| {
            u64::try_from(sym.st_name)
                .ok()
                .map(|n| base.saturating_add(n))
        }) {
            name_offsets.entry(name).or_insert(offset);
        }
    }
    // An object's (or a static executable's) undefined and global symbols,
    // which binform lists when there is no dynamic table, anchor in `.strtab`.
    let strtab = if elf.dynsyms.is_empty() {
        elf.section_headers
            .iter()
            .find(|sh| sh.sh_type == goblin::elf::section_header::SHT_SYMTAB)
            .and_then(|symtab| {
                elf.section_headers
                    .get(crate::bytes::sat_usize(symtab.sh_link))
            })
            .map(|sh| sh.sh_offset)
    } else {
        None
    };
    if let Some(strtab) = strtab {
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name).filter(|n| !n.is_empty())
                && let Ok(n) = u64::try_from(sym.st_name)
            {
                name_offsets
                    .entry(name)
                    .or_insert_with(|| strtab.saturating_add(n));
            }
        }
    }
    push_tables(layout, &name_offsets, &mut names, symbols_out);
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

/// binform's imports (the undefined symbols the loader binds, or in an
/// object the linker) and exports (the defined globals and weaks other
/// images can bind to), each anchored at its name's bytes in the file: ELF
/// binds no useful offset to an import-table entry, and `st_value` is a
/// virtual address that may point into `.bss`, with no file backing. An
/// import's `library` is the file its symbol version is required from
/// (`printf@GLIBC_2.2.5` from `libc.so.6`, as `libc`); an unversioned import
/// names none, since ELF binds no symbol to a `DT_NEEDED` library, and
/// consumers that need one walk `elf.needed[]`. ELF has no forwarders: symbol
/// versioning solves that problem, surfaced through the version-info
/// extractor.
pub(super) fn push_tables(
    layout: Option<&binform::Binary<'_>>,
    name_offsets: &HashMap<&str, u64>,
    names: &mut NameBudget,
    symbols_out: &mut crate::Symbols,
) {
    let Some(layout) = layout else {
        return;
    };
    for import in layout.imports() {
        if !names.take(import.name.len()) {
            return;
        }
        symbols_out.push(crate::Symbol::Import {
            name: import.name.clone(),
            alias: None,
            library: import.library.as_deref().map(soname_stem),
            offset: name_offsets.get(import.name.as_str()).copied(),
            ordinal: None,
        });
    }
    for export in layout.exports() {
        if !names.take(export.name.len()) {
            return;
        }
        symbols_out.push(crate::Symbol::Export {
            name: export.name.clone(),
            offset: name_offsets.get(export.name.as_str()).copied(),
            ordinal: None,
            forward_to: None,
        });
    }
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
    let stt = usize::from(sym.st_info & 0xf);
    if let Some(count) = types.get_mut(stt) {
        *count += 1;
    }
    let stb = usize::from((sym.st_info >> 4) & 0xf);
    if let Some(count) = bindings.get_mut(stb.min(3)) {
        *count += 1;
    }
    let vis = usize::from(sym.st_other & 0x3);
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

    for (key, names, counts) in [
        (
            value_key!("elf.symbol_kinds.types"),
            &TYPE_NAMES[..],
            &types[..],
        ),
        (
            value_key!("elf.symbol_kinds.bindings"),
            &BIND_NAMES,
            bindings,
        ),
        (
            value_key!("elf.symbol_kinds.visibility"),
            &VIS_NAMES,
            visibility,
        ),
    ] {
        let histogram: serde_json::Map<String, JsonValue> = names
            .iter()
            .zip(counts)
            .filter(|&(_, &count)| count > 0)
            .map(|(&name, &count)| (name.to_string(), JsonValue::from(count)))
            .collect();
        if !histogram.is_empty() {
            values.insert_key(key, JsonValue::Object(histogram));
        }
    }
}

/// A shared object's name as the import view spells libraries in every
/// format: its file name's stem, lowercased, without the `.so` and version
/// suffix (`libc.so.6` is `libc`, `ld-linux-x86-64.so.2` is
/// `ld-linux-x86-64`). A name with no `.so` is kept whole.
pub(super) fn soname_stem(soname: &str) -> String {
    let file = soname.rsplit_once('/').map_or(soname, |(_, file)| file);
    let stem = file
        .match_indices(".so")
        .find(|&(at, _)| matches!(file.as_bytes().get(at + 3), None | Some(b'.')))
        .map_or(file, |(at, _)| &file[..at]);
    stem.to_ascii_lowercase()
}
