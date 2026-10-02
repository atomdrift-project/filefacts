//! The set-fingerprint construction behind the ELF and Mach-O similarity
//! hashes ([`super::elf_hashes`], [`super::macho_hashes`]).
//!
//! Every hash is MD5 over a sorted, deduplicated list joined by commas — the
//! construction VirusTotal, MalwareBazaar, machofile and YARA-X use — so a
//! binary exposing the same import set under either format fingerprints
//! identically. Keeping it in one place keeps the two formats from drifting.

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
    Some(md5_of_csv(&names))
}

/// The imphash: [`md5_of_set`] over the lowercased imported-symbol names in
/// the unified symbols view.
pub(super) fn imphash(symbols: &Symbols) -> Option<String> {
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

fn md5_of_csv(parts: &[String]) -> String {
    hex_encode(&Md5::digest(parts.join(",").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_md5_vector() {
        // MD5("a,b,c"): the comma-join + md5 step alone.
        assert_eq!(
            md5_of_csv(&["a".into(), "b".into(), "c".into()]),
            "a44c56c8177e32d3613988f4dba7962e"
        );
        // MD5(""): the helper does not synthesise input.
        assert_eq!(md5_of_csv(&[]), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn set_hash_sorts_dedups_and_skips_the_empty_set() {
        let set = |names: &[&str]| md5_of_set(names.iter().map(|s| (*s).to_string()).collect());
        assert_eq!(
            set(&["c", "a", "b", "a"]).as_deref(),
            Some("a44c56c8177e32d3613988f4dba7962e")
        );
        assert_eq!(set(&[]), None);
    }
}
