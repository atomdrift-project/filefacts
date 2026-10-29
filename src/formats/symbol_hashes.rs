//! The set-fingerprint construction behind the ELF and Mach-O similarity
//! hashes (`elf.hashes.*`, `macho.hashes.*`).
//!
//! Every hash is MD5 over a sorted, deduplicated list joined by commas — the
//! construction VirusTotal, MalwareBazaar, machofile and YARA-X use — so a
//! binary exposing the same import set under either format fingerprints
//! identically. Keeping it in one place keeps the two formats from drifting.
//!
//! The import hash here is a *set*: order and duplicates are dropped. PE's
//! `pe.hashes.imphash` is the Mandiant construction, which keeps import order
//! and library names, so the two are named apart.

use md5::{Digest, Md5};

use crate::formats::common::hex_encode;
use crate::output::{Symbol, SymbolKind, Symbols};

/// MD5 of `names` sorted, deduplicated and comma-joined. `None` for an empty
/// set: a missing input suppresses its hash rather than emitting the MD5 of
/// the empty string.
pub(super) fn md5_of_set(mut names: Vec<String>) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    names.sort_unstable();
    names.dedup();
    Some(hex_encode(&Md5::digest(names.join(",").as_bytes())))
}

/// The import hash: [`md5_of_set`] over the lowercased imported-symbol names
/// in the unified symbols view.
pub(super) fn import_hash(symbols: &Symbols) -> Option<String> {
    md5_of_set(
        symbols
            .iter_kind(SymbolKind::Import)
            .filter_map(|s| match s {
                Symbol::Import { name, .. } => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect(),
    )
}

/// The export hash: [`md5_of_set`] over the lowercased exported-symbol names.
pub(super) fn export_hash(symbols: &Symbols) -> Option<String> {
    md5_of_set(
        symbols
            .iter_kind(SymbolKind::Export)
            .filter_map(|s| match s {
                Symbol::Export { name, .. } => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests;
