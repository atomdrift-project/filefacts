//! Mach-O similarity hashes used for malware-family clustering.
//!
//! Five MD5-based fingerprints, each consuming a sorted, lowercased,
//! deduplicated list joined by commas. The construction matches what
//! VirusTotal, MalwareBazaar, machofile, and YARA-X emit so values
//! line up across toolchains:
//!
//! - **`imphash`**       — imported symbol names (function-only, no
//!   dylib prefix). Mach-O's analogue of Mandiant's PE imphash.
//! - **`dylib_hash`**    — `LC_LOAD_DYLIB` paths.
//! - **`export_hash`**   — names from the dyld export trie.
//! - **`symhash`**       — Anomali Labs' construction: external +
//!   undefined entries from the static `LC_SYMTAB`. Distinct from
//!   `imphash` because `LC_SYMTAB` is independent of dyld bind info
//!   and survives stripping of bind opcodes.
//! - **`entitlement_hash`** — entitlement keys plus any array values,
//!   pulled from the parsed `macho.code_signature.entitlements`
//!   subtree.
//!
//! All five are emitted under `macho.hashes.*`; missing inputs
//! (no imports, unsigned binary, no entitlements) suppress the
//! corresponding field rather than emitting an MD5 of empty string.

use goblin::mach::MachO;
use md5::{Digest, Md5};
use serde_json::Value as JsonValue;

use crate::formats::common::{hex_encode, put_str};
use crate::output::{Symbol, SymbolKind, Symbols, Values};

/// Populate `macho.hashes.*` from the parsed Mach-O plus the unified
/// symbols view (which the imports/exports extractor has already
/// filled in).
pub(super) fn emit(macho: &MachO<'_>, values: &mut Values, symbols: &Symbols) {
    if let Some(h) = imphash(symbols) {
        put_str(values, "macho.hashes.imphash", h);
    }
    if let Some(h) = dylib_hash(macho) {
        put_str(values, "macho.hashes.dylib_hash", h);
    }
    if let Some(h) = export_hash(symbols) {
        put_str(values, "macho.hashes.export_hash", h);
    }
    if let Some(h) = symhash(macho) {
        put_str(values, "macho.hashes.symhash", h);
    }
    if let Some(h) = entitlement_hash(values) {
        put_str(values, "macho.hashes.entitlement_hash", h);
    }
}

/// MD5 of the sorted, lowercased, dedup'd imported-function names,
/// comma-joined. `None` when no imports were recovered.
fn imphash(symbols: &Symbols) -> Option<String> {
    let mut names: Vec<String> = symbols
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, .. } => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

/// MD5 of the sorted, lowercased dylib paths (every `LC_LOAD_*_DYLIB`
/// kind), comma-joined. Excludes goblin's `"self"` pseudo-entry and
/// any empty slot. `None` when no dylibs are referenced.
fn dylib_hash(macho: &MachO<'_>) -> Option<String> {
    let mut names: Vec<String> = macho
        .libs
        .iter()
        .filter(|s| !s.is_empty() && **s != "self")
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

/// MD5 of the sorted, lowercased, dedup'd export-trie names.
fn export_hash(symbols: &Symbols) -> Option<String> {
    let mut names: Vec<String> = symbols
        .iter_kind(SymbolKind::Export)
        .filter_map(|s| match s {
            Symbol::Export { name, .. } => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

/// Anomali Labs' Mach-O symhash. Reads the static `LC_SYMTAB` and
/// keeps only **external + undefined** entries (`N_EXT` set, type
/// bits == `N_UNDF`). Names are sorted, comma-joined, MD5'd. The
/// `nlist` `n_strx == 0` entries are skipped — they have no name.
///
/// Unlike the sibling hashers in this module, symhash does **not**
/// lowercase symbol names. Mach-O linker symbols are case-sensitive
/// (`_Foo` and `_foo` are distinct symbols), and the canonical
/// Anomali / YARA-X implementations preserve case — lowercasing here
/// would diverge from those reference outputs.
fn symhash(macho: &MachO<'_>) -> Option<String> {
    const N_EXT: u8 = 0x01;
    const N_TYPE_MASK: u8 = 0x0e;
    const N_UNDF: u8 = 0x00;
    let symbols = macho.symbols.as_ref()?;
    let mut names = Vec::new();
    for sym in symbols.iter() {
        let Ok((name, nlist)) = sym else { continue };
        if nlist.n_type & N_EXT == 0 {
            continue;
        }
        if nlist.n_type & N_TYPE_MASK != N_UNDF {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        names.push(name.to_string());
    }
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_of_csv(&names))
}

/// MD5 of the sorted, lowercased entitlement keys plus any string
/// values found in array-typed entitlements (e.g. the bundle IDs
/// inside `com.apple.security.application-groups`). Mirrors the
/// construction from Greg Lesnewich + Jacob Latonis's OBTS v7 talk.
fn entitlement_hash(values: &Values) -> Option<String> {
    let entitlements = values.get("macho.code_signature.entitlements")?;
    let JsonValue::Object(map) = entitlements else {
        return None;
    };
    let mut tokens: Vec<String> = Vec::new();
    for (key, val) in map {
        tokens.push(key.to_ascii_lowercase());
        if let JsonValue::Array(arr) = val {
            for v in arr {
                if let JsonValue::String(s) = v {
                    tokens.push(s.to_ascii_lowercase());
                }
            }
        }
    }
    if tokens.is_empty() {
        return None;
    }
    tokens.sort();
    tokens.dedup();
    Some(md5_of_csv(&tokens))
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
    fn known_md5_vector() {
        // MD5("a,b,c") = a44c56c8177e32d3613988f4dba7962e — the
        // construction is "sort, dedup, lowercase, comma-join, md5";
        // here we exercise the comma-join + md5 step alone.
        assert_eq!(
            md5_of_csv(&["a".into(), "b".into(), "c".into()]),
            "a44c56c8177e32d3613988f4dba7962e"
        );
    }

    #[test]
    fn empty_input_hashes_empty_string() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e — sanity check
        // that the helper itself doesn't synthesise input.
        assert_eq!(md5_of_csv(&[]), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
