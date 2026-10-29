//! Typed imports and exports: dyld bind imports, the `LC_SYMTAB` fallback
//! for chained-fixup binaries, and the export trie, with Darwin `$VARIANT`
//! spellings folded to their base symbol.

use goblin::mach::{self, MachO};

use crate::bytes;
use crate::formats::goblin_safe;
use crate::output::{Errors, Symbols};

/// Walk Mach-O's dyld bind-info (imports) and export trie (exports)
/// and surface them as typed `Import`/`Export` symbols.
///
/// Bind imports carry the resolving dylib's stem as their library; imports
/// recovered from `LC_SYMTAB` for chained-fixup binaries carry none. A bind
/// stream or export trie refused as hostile yields no entries and is
/// recorded in `errors`.
pub(super) fn extract(
    macho: &MachO<'_>,
    bytes: &[u8],
    symbols_out: &mut Symbols,
    errors: &mut Errors,
) {
    // Map each undefined external symbol to the file offset of its name in
    // the `LC_SYMTAB` string table. goblin's `Import::offset` is the dyld
    // *bind* slot (a pointer in `__got`/`__DATA`, binary data), but every
    // other consumer anchors a symbol at its human-readable name — ELF
    // imports point into `.dynstr`, and the hex/context view expects to
    // render the name's ASCII. Anchoring imports at the name string keeps
    // Mach-O consistent with ELF and makes the annotated bytes readable.
    let name_offsets = import_name_offsets(macho, bytes);

    // Imports — dylib stems are normalised to the bare library name
    // (lowercased, basename only, `.dylib`/`.tbd` suffix stripped) so
    // trait authors can match against `"libsystem.b"` rather than
    // `"/usr/lib/libSystem.B.dylib"`.
    let mut bind_imports = 0usize;
    // `imports()` walks dyld bind opcodes lazily, after `parse_mach` has
    // already returned, so the parse-time guard does not cover it. goblin
    // indexes the libs table with an unchecked ordinal (mach/imports.rs) and
    // panics on a malformed one; a panic here yields no imports and is
    // recorded in `errors`.
    // The opcodes are counted first: a forged repeat count makes goblin
    // allocate billions of imports, and `catch` cannot stop an out-of-memory
    // abort (see `validate_bind_opcodes`).
    let imports = match goblin_safe::validate_bind_opcodes(macho, bytes) {
        Ok(()) => goblin_safe::catch(|| macho.imports()),
        Err(reason) => {
            errors.record_malformed(crate::Stage::MachoParse, reason.to_string());
            goblin_safe::GoblinOutcome::Failed(goblin::error::Error::Malformed(reason.to_string()))
        }
    };
    if let goblin_safe::GoblinOutcome::Panicked(msg) = &imports {
        errors.record_panic(crate::Stage::MachoParse, msg.clone());
    }
    if let goblin_safe::GoblinOutcome::Ok(imports) = imports {
        for imp in &imports {
            let library = normalize_dylib_path(imp.dylib);
            // Prefer the name-string offset; fall back to the bind slot
            // when the symbol has no `LC_SYMTAB` entry (rare, e.g.
            // dyld-info-only binaries).
            let offset = name_offsets.get(imp.name).copied().unwrap_or(imp.offset);
            bind_imports += 1;
            symbols_out.push(crate::Symbol::Import {
                // Record the base symbol, not the Darwin `$VARIANT` spelling,
                // so anchored trait matchers and imphash see `popen` rather
                // than `popen$DARWIN_EXTSN`. The offset lookup above still uses
                // the raw name — that is how it is keyed in `LC_SYMTAB`.
                name: strip_darwin_symbol_variant(imp.name).to_string(),
                alias: None,
                library: Some(library),
                offset: Some(offset),
                ordinal: None,
            });
        }
        // Import count flows through cross-format `imports.count`.
    }

    // Chained-fixups fallback.
    //
    // `macho.imports()` reads dyld *bind opcodes* (`LC_DYLD_INFO`). Binaries
    // linked for macOS 12 and later carry `LC_DYLD_CHAINED_FIXUPS` instead and
    // have no bind opcodes at all, so that call returns an empty list for
    // every current macOS build.
    //
    // The undefined external symbols in `LC_SYMTAB` are those same imports,
    // and `import_name_offsets` has already walked them to build the offset
    // map above, so recovering them costs nothing extra. The dylib each one
    // resolves to lives in the fixup chains rather than the symbol table, so
    // `library` is left unset here instead of guessed at -- trait matchers key
    // on the symbol name, and a wrong library is worse than none.
    if bind_imports == 0 && !name_offsets.is_empty() {
        let mut names: Vec<(&str, u64)> = name_offsets.iter().map(|(n, o)| (*n, *o)).collect();
        names.sort_unstable();
        for (name, offset) in names {
            symbols_out.push(crate::Symbol::Import {
                name: strip_darwin_symbol_variant(name).to_string(),
                alias: None,
                library: None,
                offset: Some(offset),
                ordinal: None,
            });
        }
    }

    // Exports — recovered from the dyld export trie. Re-exports
    // (e.g. `libSystem` forwarding to `libdyld`) carry their target in
    // `forward_to` as `<library stem>.<symbol>`, the shape PE forwards take.
    // Same exposure as `imports()` above: the export trie is walked lazily and
    // goblin indexes it unchecked (mach/exports.rs:99). Worse than a panic, a
    // trie with an edge back to an ancestor walks forever, and `catch` cannot
    // interrupt a walk that never faults — so the trie is checked for loops
    // first and a malformed one yields no exports (see `validate_export_trie`).
    let exports = match goblin_safe::validate_export_trie(macho, bytes) {
        Ok(()) => goblin_safe::catch(|| macho.exports()),
        Err(reason) => {
            errors.record_malformed(crate::Stage::MachoParse, reason.to_string());
            goblin_safe::GoblinOutcome::Failed(goblin::error::Error::Malformed(reason.to_string()))
        }
    };
    if let goblin_safe::GoblinOutcome::Panicked(msg) = &exports {
        errors.record_panic(crate::Stage::MachoParse, msg.clone());
    }
    if let goblin_safe::GoblinOutcome::Ok(exports) = exports {
        for exp in &exports {
            symbols_out.push(crate::Symbol::Export {
                // Normalize the same Darwin `$VARIANT` suffix as imports: these
                // markers are *defined* in libSystem, so a library re-exporting
                // libc carries them here. The allow-list leaves a binary's own
                // `_OBJC_CLASS_$_…` exports intact.
                name: strip_darwin_symbol_variant(&exp.name).to_string(),
                offset: Some(exp.offset),
                ordinal: None,
                forward_to: match exp.info {
                    goblin::mach::exports::ExportInfo::Reexport {
                        lib,
                        lib_symbol_name,
                        ..
                    } => Some(format!(
                        "{}.{}",
                        normalize_dylib_path(lib),
                        lib_symbol_name.unwrap_or(&exp.name)
                    )),
                    _ => None,
                },
            });
        }
        // Export count flows through cross-format `exports.count`.
    }
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
