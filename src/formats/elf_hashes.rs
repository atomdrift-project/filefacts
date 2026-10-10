//! ELF similarity hashes used for malware-family clustering.
//!
//! Four MD5-based fingerprints mirroring [`super::macho_hashes`], built with
//! the shared construction in [`super::symbol_hashes`]:
//!
//! - **`imphash`** — sorted, lowercased, dedup'd list of imported
//!   function names (dyld bind imports). Greg Lesnewich's `telfhash`
//!   is TLSH over a similar list; we use MD5 instead to stay
//!   dependency-light and consistent with the Mach-O / PE hashes.
//! - **`export_hash`** — sorted, lowercased dynsym defined-symbol
//!   names. Useful for shared libraries.
//! - **`dyn_hash`**    — `DT_NEEDED` entries sorted + lowercased.
//!   Identical across compatible builds of the same binary.
//! - **`symhash`**     — Anomali Labs' construction applied to ELF:
//!   external + undefined entries from `.symtab` (when present). The
//!   static symbol-table view is independent of the bind table and
//!   survives `objcopy --only-keep-debug` style stripping where only
//!   debug info goes.
//!
//! All four are emitted under `elf.hashes.*`; missing inputs (empty
//! imports, no DT_NEEDED, stripped symtab) suppress the corresponding
//! field rather than emit an MD5 of the empty string.

use goblin::elf::Elf;

use super::elf::NameBudget;
use super::symbol_hashes::{export_hash, imphash, md5_of_set};
use crate::formats::common::put_str;
use crate::output::{Symbols, Values};
use crate::value_key;

pub(super) fn emit(elf: &Elf<'_>, file_len: usize, values: &mut Values, symbols: &Symbols) {
    // imphash: imported function names (`STB_GLOBAL`/`STB_WEAK` with
    // `SHN_UNDEF`); export_hash: defined dynsym names.
    if let Some(h) = imphash(symbols) {
        put_str(values, value_key!("elf.hashes.imphash"), h);
    }
    if let Some(h) = export_hash(symbols) {
        put_str(values, value_key!("elf.hashes.export_hash"), h);
    }
    if let Some(h) = dyn_hash(elf, file_len) {
        put_str(values, value_key!("elf.hashes.dyn_hash"), h);
    }
    if let Some(h) = symhash(elf, file_len) {
        put_str(values, value_key!("elf.hashes.symhash"), h);
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

/// Anomali Labs' symhash, applied to ELF's static symbol table.
/// External (`STB_GLOBAL`/`STB_WEAK`) + undefined (`SHN_UNDEF`)
/// entries' names are sorted, comma-joined, MD5'd. Returns `None`
/// when the symtab has been stripped, contains no matching entries, or its
/// names overrun their [`NameBudget`].
fn symhash(elf: &Elf<'_>, file_len: usize) -> Option<String> {
    // STB_LOCAL = 0, STB_GLOBAL = 1, STB_WEAK = 2.
    let mut names: Vec<String> = Vec::new();
    let mut budget = NameBudget::new(file_len);
    for sym in elf.syms.iter() {
        if sym.st_bind() == 0 {
            continue;
        }
        if sym.st_shndx != 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                if !budget.take(name.len()) {
                    return None;
                }
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    md5_of_set(names)
}
