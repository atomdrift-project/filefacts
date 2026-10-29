//! ELF similarity hashes for family clustering, built with the shared
//! sorted-set construction in [`crate::formats::symbol_hashes`] and emitted
//! under `elf.hashes.*`:
//!
//! - **`import_hash`** — the lowercased imported-symbol names (undefined
//!   `.dynsym` entries). An unordered set, unlike PE's order-preserving
//!   `pe.hashes.imphash`; Greg Lesnewich's `telfhash` is TLSH over a similar
//!   list, and MD5 keeps it dependency-light and comparable with the Mach-O
//!   `import_hash`.
//! - **`export_hash`** — the lowercased exported-symbol names.
//! - **`dyn_hash`** — the lowercased `DT_NEEDED` entries. Identical across
//!   compatible builds of the same binary.
//! - **`symtab_import_hash`** — the lowercased names of the external,
//!   undefined `.symtab` entries: Anomali's symhash selection over the
//!   static table, which is independent of the dynamic one. Lowercased, so it
//!   is not the case-preserving Mach-O `symhash`.
//!
//! Missing inputs (no imports, no DT_NEEDED, no `.symtab`) suppress the
//! corresponding hash rather than emit the MD5 of the empty string.

use goblin::elf::Elf;

use super::NameBudget;
use crate::formats::common::put_str;
use crate::formats::symbol_hashes::{export_hash, import_hash, md5_of_set};
use crate::output::{Symbols, Values};
use crate::value_key;

pub(super) fn emit(elf: &Elf<'_>, file_len: usize, values: &mut Values, symbols: &Symbols) {
    if let Some(h) = import_hash(symbols) {
        put_str(values, value_key!("elf.hashes.import_hash"), h);
    }
    if let Some(h) = export_hash(symbols) {
        put_str(values, value_key!("elf.hashes.export_hash"), h);
    }
    if let Some(h) = dyn_hash(elf, file_len) {
        put_str(values, value_key!("elf.hashes.dyn_hash"), h);
    }
    if let Some(h) = symtab_import_hash(elf, file_len) {
        put_str(values, value_key!("elf.hashes.symtab_import_hash"), h);
    }
}

/// MD5 of the sorted, lowercased `DT_NEEDED` library list. Stable
/// across compiler versions and a useful first-cut dependency
/// fingerprint. `None` when the names overrun their [`NameBudget`]: a hash
/// of part of the list would pass for the hash of all of it.
fn dyn_hash(elf: &Elf<'_>, file_len: usize) -> Option<String> {
    let mut names = NameBudget::new(file_len);
    let libs = elf
        .libraries
        .iter()
        .take_while(|s| names.take(s.len()))
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if names.refused() {
        return None;
    }
    md5_of_set(libs)
}

/// MD5 of the sorted, lowercased names of the external (`STB_GLOBAL` /
/// `STB_WEAK`), undefined (`SHN_UNDEF`) `.symtab` entries. `None` when there
/// is no `.symtab`, no such entry, or the names overrun their [`NameBudget`].
fn symtab_import_hash(elf: &Elf<'_>, file_len: usize) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut budget = NameBudget::new(file_len);
    for sym in elf.syms.iter() {
        if sym.st_bind() == goblin::elf::sym::STB_LOCAL || sym.st_shndx != 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name)
            && !name.is_empty()
        {
            if !budget.take(name.len()) {
                return None;
            }
            names.push(name.to_ascii_lowercase());
        }
    }
    md5_of_set(names)
}
