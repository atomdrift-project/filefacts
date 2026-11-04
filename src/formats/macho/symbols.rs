//! Typed imports and exports, from binform's layout, with Darwin `$VARIANT`
//! spellings folded to their base symbol and imports anchored at their
//! `LC_SYMTAB` names.

use goblin::mach::{self, MachO};

use crate::bytes;
use crate::formats::goblin_safe;
use crate::output::Symbols;

/// The typed imports and exports, from binform: one import per undefined
/// external symbol, bound to the library its two-level ordinal, its bind
/// opcodes or its chained-fixup import table name; one export per defined
/// external symbol and export-trie entry.
///
/// Library names are normalised to the bare stem (lowercased, basename only,
/// `.dylib`/`.tbd` suffix stripped) so trait authors can match against
/// `"libsystem.b"` rather than `"/usr/lib/libSystem.B.dylib"`. A flat
/// namespace or flat-lookup import binds to no library in particular, and
/// carries none.
pub(super) fn extract(
    macho: &MachO<'_>,
    layout: Option<&binform::Binary<'_>>,
    bytes: &[u8],
    symbols_out: &mut Symbols,
) {
    let Some(layout) = layout else {
        return;
    };
    // Each undefined external symbol's name in the `LC_SYMTAB` string table.
    // Every consumer anchors a symbol at its human-readable name — ELF
    // imports point into `.dynstr`, and the hex/context view expects to
    // render the name's ASCII — so Mach-O imports do too.
    let name_offsets = import_name_offsets(macho, bytes);
    for imp in layout.imports() {
        symbols_out.push(crate::Symbol::Import {
            // Record the base symbol, not the Darwin `$VARIANT` spelling,
            // so anchored trait matchers and imphash see `popen` rather
            // than `popen$DARWIN_EXTSN`. The offset lookup still uses the
            // raw name — that is how it is keyed in `LC_SYMTAB`.
            name: strip_darwin_symbol_variant(&imp.name).to_string(),
            alias: None,
            library: imp.library.as_deref().map(normalize_dylib_path),
            offset: name_offsets.get(imp.name.as_str()).copied(),
            ordinal: None,
        });
    }

    // Exports at their offset from the Mach header (the `__TEXT` segment's
    // start), as the export trie records them. Re-exports (e.g. `libSystem`
    // forwarding to `libdyld`) have no address of their own; they carry
    // their target in `forward_to` as `<library stem>.<symbol>`, the shape
    // PE forwards take.
    let base = macho
        .segments
        .iter()
        .find(|segment| segment.name().is_ok_and(|name| name == "__TEXT"))
        .map_or(0, |segment| segment.vmaddr);
    for exp in layout.exports() {
        symbols_out.push(crate::Symbol::Export {
            // Normalize the same Darwin `$VARIANT` suffix as imports: these
            // markers are *defined* in libSystem, so a library re-exporting
            // libc carries them here. The allow-list leaves a binary's own
            // `_OBJC_CLASS_$_…` exports intact.
            name: strip_darwin_symbol_variant(&exp.name).to_string(),
            // A re-export has no address of its own.
            offset: exp.addr.and_then(|addr| addr.checked_sub(base)),
            ordinal: None,
            forward_to: exp
                .forward
                .as_deref()
                .map(|forward| reexport_target(&macho.libs, forward)),
        });
    }
}

/// A re-export's `<library stem>.<symbol>` with the stem normalised as
/// imports' libraries are. binform keeps the stem's case, and the stem
/// itself may hold dots (`libSystem.B`), so it is matched against the
/// binary's own dylibs rather than split.
fn reexport_target(libs: &[&str], forward: &str) -> String {
    libs.iter()
        .find_map(|lib| {
            let base = lib.rsplit_once('/').map_or(*lib, |(_, base)| base);
            let stem = base
                .strip_suffix(".dylib")
                .or_else(|| base.strip_suffix(".tbd"))
                .unwrap_or(base);
            let symbol = forward.strip_prefix(stem)?.strip_prefix('.')?;
            Some(format!("{}.{symbol}", normalize_dylib_path(lib)))
        })
        .unwrap_or_else(|| forward.to_owned())
}

/// Build a map from undefined-external symbol name to the file offset of
/// that name in the `LC_SYMTAB` string table (`stroff + n_strx`).
///
/// These are the binary's imports as recorded in the static symbol table.
/// goblin's `SymbolIterator` already resolves each `nlist` to its name, so
/// we only need the absolute `stroff` from the symtab load command to turn
/// the relative `n_strx` into a file offset. Returns an empty map when the
/// binary is stripped (no `LC_SYMTAB`) — callers fall back to the bind slot.
pub(super) fn import_name_offsets<'a>(
    macho: &MachO<'a>,
    bytes: &[u8],
) -> std::collections::HashMap<&'a str, u64> {
    const N_EXT: u8 = 0x01;
    const N_TYPE_MASK: u8 = 0x0e;
    const N_UNDF: u8 = 0x00;

    let mut offsets = std::collections::HashMap::new();
    let Some(stroff) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::Symtab(st) => Some(u64::from(st.stroff)),
        _ => None,
    }) else {
        return offsets;
    };

    // goblin resolves each name through a file-controlled `n_strx` as the
    // walk advances; an unwalkable table leaves only the bind-slot offsets.
    let symbols = goblin_safe::drain(symtab_symbols(macho, bytes))
        .ok()
        .unwrap_or_default();
    for sym in symbols {
        let Ok((name, nlist)) = sym else { continue };
        // External + undefined == imported symbol; `n_strx == 0` has no name.
        if nlist.n_type & N_EXT == 0
            || nlist.n_type & N_TYPE_MASK != N_UNDF
            || nlist.n_strx == 0
            || name.is_empty()
        {
            continue;
        }
        // First occurrence wins; duplicate undefined entries are degenerate.
        offsets
            .entry(name)
            .or_insert_with(|| stroff + nlist.n_strx as u64);
    }
    offsets
}

/// The `LC_SYMTAB` entries whose `nlist` lies inside `bytes`, the buffer
/// `macho` was parsed from.
///
/// goblin walks the header's `nsyms` (up to `u32::MAX`) without checking it
/// against the file and yields an error for every entry past the end, so a
/// forged count costs four billion steps, and collecting the walk aborts on
/// the allocation. No entry past the end can parse, so stopping there loses
/// nothing.
pub(super) fn symtab_symbols<'a>(
    macho: &MachO<'a>,
    bytes: &[u8],
) -> std::iter::Take<mach::symbols::SymbolIterator<'a>> {
    let nlist_size = if macho.is_64 { 16 } else { 12 };
    let fitting = macho
        .load_commands
        .iter()
        .find_map(|lc| match lc.command {
            mach::load_command::CommandVariant::Symtab(st) => {
                Some(bytes.len().saturating_sub(bytes::sat_usize(st.symoff)) / nlist_size)
            }
            _ => None,
        })
        .unwrap_or(0);
    macho.symbols().take(fitting)
}

/// Symbol-variant markers Darwin appends to a libc name after a `$`. Each
/// selects a binary-compatible implementation of the *same* function, so it
/// is an ABI/SDK detail rather than a distinct capability. This is the
/// complete set libSystem uses; extend it here if Apple introduces another.
const DARWIN_SYMBOL_VARIANTS: &[&str] =
    &["UNIX2003", "DARWIN_EXTSN", "INODE64", "NOCANCEL", "1050"];

/// Strip a macOS symbol-variant suffix, returning the base symbol.
///
/// Darwin records several libc calls under a `$`-variant spelling:
/// `popen$DARWIN_EXTSN`, `open$NOCANCEL`, `stat$INODE64`, `write$UNIX2003`
/// (variants can chain, e.g. `close$NOCANCEL$UNIX2003`). The analytically
/// meaningful name is the base before the first `$` — the function the symbol
/// actually refers to, whether the binary imports it or (as libSystem and its
/// re-exporters do) defines it. Recording the raw spelling let anchored trait
/// matchers (`^popen$`) and imphash/export-hash clustering miss it.
///
/// Only a suffix built entirely from known [`DARWIN_SYMBOL_VARIANTS`] tokens
/// is stripped. `$` also carries unrelated conventions — Objective-C class
/// references (`_OBJC_CLASS_$_NSURL`) and linker directives (`$ld$hide$…`) —
/// and those must survive untouched, so a shape heuristic is not enough: an
/// all-caps class name like `NSURL` would be mistaken for a variant. The
/// allow-list keys on the actual ABI markers instead.
pub(super) fn strip_darwin_symbol_variant(name: &str) -> &str {
    match name.split_once('$') {
        Some((base, tail))
            if !base.is_empty()
                && tail
                    .split('$')
                    .all(|token| DARWIN_SYMBOL_VARIANTS.contains(&token)) =>
        {
            base
        }
        _ => name,
    }
}

/// Reduce a recorded dylib path to its bare library stem, lowercased.
/// `/usr/lib/libSystem.B.dylib` -> `"libsystem.b"`. Compatible with
/// PE's `library` normalisation convention so trait matchers can
/// share library names across formats.
pub(super) fn normalize_dylib_path(path: &str) -> String {
    let basename = path.rsplit_once('/').map(|(_, name)| name).unwrap_or(path);
    let stem = basename
        .strip_suffix(".dylib")
        .or_else(|| basename.strip_suffix(".tbd"))
        .unwrap_or(basename);
    stem.to_ascii_lowercase()
}
