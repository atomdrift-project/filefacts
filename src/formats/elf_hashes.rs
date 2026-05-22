//! ELF similarity hashes used for malware-family clustering.
//!
//! Four MD5-based fingerprints mirroring [`super::macho_hashes`]:
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
use md5::{Digest, Md5};

use crate::formats::common::{hex_encode, put_str};
use crate::output::Values;

pub(super) fn emit(
    elf: &Elf<'_>,
    values: &mut Values,
    imports: &crate::Imports,
    exports: &crate::Exports,
) {
    if let Some(h) = imphash(imports) {
        put_str(values, "elf.hashes.imphash", h);
    }
    if let Some(h) = export_hash(exports) {
        put_str(values, "elf.hashes.export_hash", h);
    }
    if let Some(h) = dyn_hash(elf) {
        put_str(values, "elf.hashes.dyn_hash", h);
    }
    if let Some(h) = symhash(elf) {
        put_str(values, "elf.hashes.symhash", h);
    }
}

/// MD5 of the sorted, lowercased, dedup'd imported-symbol names
/// (`STB_GLOBAL`/`STB_WEAK` symbols with `SHN_UNDEF`).
fn imphash(imports: &crate::Imports) -> Option<String> {
    let mut names: Vec<String> = imports
        .iter()
        .map(|i| i.name.to_ascii_lowercase())
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

fn export_hash(exports: &crate::Exports) -> Option<String> {
    let mut names: Vec<String> = exports
        .iter()
        .map(|e| e.name.to_ascii_lowercase())
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

/// MD5 of the sorted, lowercased `DT_NEEDED` library list. Stable
/// across compiler versions and a useful first-cut dependency
/// fingerprint.
fn dyn_hash(elf: &Elf<'_>) -> Option<String> {
    let mut names: Vec<String> = elf
        .libraries
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

/// Anomali Labs' symhash, applied to ELF's static symbol table.
/// External (`STB_GLOBAL`/`STB_WEAK`) + undefined (`SHN_UNDEF`)
/// entries' names are sorted, comma-joined, MD5'd. Returns `None`
/// when the symtab has been stripped or contains no matching entries.
fn symhash(elf: &Elf<'_>) -> Option<String> {
    // STB_LOCAL = 0, STB_GLOBAL = 1, STB_WEAK = 2.
    let mut names: Vec<String> = Vec::new();
    for sym in elf.syms.iter() {
        if sym.st_bind() == 0 {
            continue;
        }
        if sym.st_shndx != 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

fn md5_of_csv(parts: &[String]) -> String {
    let joined = parts.join(",");
    let digest = Md5::digest(joined.as_bytes());
    hex_encode(&digest)
}

#[cfg(test)]
mod tests {
    use super::md5_of_csv;

    #[test]
    fn matches_macho_hash_construction() {
        // The construction must be byte-identical to the Mach-O
        // hashes module (`md5("a,b,c")`) so a binary that exposes
        // the same import set under both formats fingerprints
        // identically.
        assert_eq!(
            md5_of_csv(&["a".into(), "b".into(), "c".into()]),
            "a44c56c8177e32d3613988f4dba7962e"
        );
    }
}
