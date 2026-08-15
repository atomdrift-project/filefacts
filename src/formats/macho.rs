//! Mach-O extractor.
//!
//! Reads macOS / iOS executables, dylibs, kernel extensions, and Mach-O
//! FAT (universal) binaries. Surfaces header fields, the load-command
//! list, LC_LOAD_DYLIB references, LC_RPATH entries, the LC_UUID, and
//! code-signature presence.
//!
//! For FAT binaries, exposes per-arch slices under `macho.slices[]`
//! and surfaces the first slice's metadata at the top level so simple
//! consumers don't have to enumerate the array.

use goblin::mach::{self, Mach, MachO};
use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{
    NativeFormat, XorScan, extract_binary_strings, extract_binary_strings_from_object, put_str,
    put_u64, rizin_fallback,
};
use crate::formats::goblin_safe;
use crate::output::{Errors, Metrics, Section, Strings, Values};
use crate::scan::entropy;

#[allow(clippy::too_many_arguments)]
pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
    symbols_out: &mut crate::Symbols,
    errors_out: &mut Errors,
) -> Result<(), Error> {
    // Wrap goblin parse in catch_unwind. Fat-header arithmetic
    // overflow on malformed Mach-O has historically panicked
    // goblin; record the failure and return Ok so byte-level
    // metrics from the generic pass aren't lost.
    let parsed = match goblin_safe::parse_mach(bytes) {
        goblin_safe::GoblinOutcome::Ok(m) => m,
        goblin_safe::GoblinOutcome::Failed(e) => {
            // Parse failed: let stng parse the bytes itself so strings are
            // still recovered from the malformed input.
            extract_binary_strings(bytes, strings, XorScan::Yes);
            errors_out.record_malformed(crate::Stage::MachoParse, e.to_string());
            metrics.insert("macho.parse_failed", 1.0);
            return Ok(());
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            extract_binary_strings(bytes, strings, XorScan::Yes);
            errors_out.record_panic(crate::Stage::MachoParse, msg);
            metrics.insert("macho.parse_panicked", 1.0);
            return Ok(());
        }
    };
    // Reuse this parse for string extraction instead of having stng parse the
    // binary a second time.
    let object = goblin::Object::Mach(parsed);
    extract_binary_strings_from_object(&object, bytes, strings, XorScan::Yes);
    let goblin::Object::Mach(parsed) = object else {
        unreachable!("constructed as Object::Mach")
    };
    // Resolve the Go attribution sections (pclntab + read-only data) from
    // the thin-binary case while the parsed Mach-O is in scope; the bytes
    // they reference outlive it. Fat binaries skip pclntab-based GoRoot
    // recovery (rare for Go) but still get build-id via the marker scan.
    // When native-arch-only mode is on (e.g. `ascan ps`), hand rizin just the
    // host-native slice of a fat binary instead of the whole universal file —
    // the other slices will never run here and full `aaa` on each is the bulk
    // of the per-binary cost. Falls back to the whole input for thin binaries
    // or when no native slice is found.
    let mut native_rizin_range: Option<(usize, usize)> = None;
    let (go_pclntab, go_rodata) = match parsed {
        Mach::Binary(macho) => {
            single_arch(&macho, bytes, values, metrics, sections_out, symbols_out);
            macho_go_sections(&macho)
        }
        Mach::Fat(fat) => {
            fat_binary(bytes, &fat, values, metrics, sections_out, symbols_out);
            if crate::rizin::native_arch_only() {
                native_rizin_range = native_slice_range(bytes, &fat);
            }
            (None, None)
        }
    };
    let rizin_bytes = match native_rizin_range {
        Some((start, end)) => &bytes[start..end],
        None => bytes,
    };
    let has_go_pclntab = go_pclntab.is_some_and(super::go_buildinfo::has_pclntab_magic);
    rizin_fallback(
        NativeFormat::MachO,
        rizin_bytes,
        strings,
        sections_out,
        symbols_out,
        metrics,
        has_go_pclntab,
    );
    super::upx::detect(bytes, values);
    let go_sections = super::go_buildinfo::GoSections {
        buildid_note: None,
        pclntab: go_pclntab,
        rodata: go_rodata,
    };
    super::go_buildinfo::detect(bytes, values, "macho", None, &go_sections);
    Ok(())
}

/// Resolve the `__TEXT,__gopclntab` and read-only data (`__const`,
/// falling back to `__rodata`) section bytes used for Go attribution.
fn macho_go_sections<'a>(macho: &MachO<'a>) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
    let (mut pclntab, mut const_data, mut rodata) = (None, None, None);
    for segment in &macho.segments {
        if segment.name().unwrap_or("") != "__TEXT" {
            continue;
        }
        let Ok(secs) = segment.sections() else {
            continue;
        };
        for (section, data) in secs {
            match section.name().unwrap_or("") {
                "__gopclntab" => pclntab = Some(data),
                "__const" => const_data = Some(data),
                "__rodata" => rodata = Some(data),
                _ => {}
            }
        }
    }
    (pclntab, const_data.or(rodata))
}

/// Byte range of the host-native architecture slice within a fat Mach-O, used to
/// hand rizin only the slice that can run on this host (see `extract`). Matches
/// on `cputype` so `arm64` and `arm64e` (same cputype, different subtype) both
/// resolve on Apple silicon. Returns `None` for an unknown host arch or when no
/// slice matches — callers fall back to the whole input.
fn native_slice_range(bytes: &[u8], fat: &mach::MultiArch<'_>) -> Option<(usize, usize)> {
    // CPU_TYPE_* constants (mach/machine.h). The CPU_ARCH_ABI64 bit (0x0100_0000)
    // is set on the 64-bit variants we target.
    #[cfg(target_arch = "aarch64")]
    const NATIVE_CPU_TYPE: u32 = 0x0100_000C; // CPU_TYPE_ARM64
    #[cfg(target_arch = "x86_64")]
    const NATIVE_CPU_TYPE: u32 = 0x0100_0007; // CPU_TYPE_X86_64
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const NATIVE_CPU_TYPE: u32 = 0;

    if NATIVE_CPU_TYPE == 0 {
        return None;
    }
    for slice in fat.iter_arches() {
        let Ok(arch) = slice else { continue };
        if arch.cputype != NATIVE_CPU_TYPE {
            continue;
        }
        let start = arch.offset as usize;
        if start >= bytes.len() {
            return None;
        }
        let end = start.saturating_add(arch.size as usize).min(bytes.len());
        if end > start {
            return Some((start, end));
        }
    }
    None
}

fn fat_binary(
    bytes: &[u8],
    fat: &mach::MultiArch<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
    symbols_out: &mut crate::Symbols,
) {
    let mut archs: Vec<JsonValue> = Vec::new();
    for (idx, slice) in fat.iter_arches().enumerate() {
        let Ok(arch) = slice else { continue };
        // `arch.offset` and `arch.size` come from the fat header — on
        // a misclassified CAFEBABE input (Java `.class` mistaken for
        // Mach-O fat) they are random bytes and routinely overflow
        // the file. Validate the start before slicing; `.min(end)`
        // alone only clamps the upper bound and still panics on a
        // huge start.
        let start = arch.offset as usize;
        if start >= bytes.len() {
            continue;
        }
        let end = start.saturating_add(arch.size as usize).min(bytes.len());
        let slice_bytes = &bytes[start..end];
        let Ok(macho) = MachO::parse(slice_bytes, 0) else {
            continue;
        };
        // Every slice gets the same forensic analysis as a single-arch
        // binary: full header/load-command extraction, code signature,
        // similarity hashes, segments. The result lands in this
        // slice's entry of `macho.slices[]`. File-offset extent within
        // the fat wrapper (`file_offset` + `file_size`) is added by
        // the caller — consumers walking per-arch byte ranges read
        // those rather than re-parsing the fat header.
        let mut slice_entry = analyze_slice(&macho, slice_bytes);
        if let JsonValue::Object(ref mut obj) = slice_entry {
            obj.insert("file_offset".into(), JsonValue::Number(arch.offset.into()));
            obj.insert("file_size".into(), JsonValue::Number(arch.size.into()));
        }
        archs.push(slice_entry);
        if idx == 0 {
            single_arch(
                &macho,
                slice_bytes,
                values,
                metrics,
                sections_out,
                symbols_out,
            );
        }
    }
    metrics.insert("macho.slice_count", archs.len() as f64);
    values.insert("macho.slices", JsonValue::Array(archs));
}

/// Run the full single-arch extractor on a slice and return the
/// resulting `macho.*` subtree as a JSON object. Used for FAT
/// binaries so each architecture's view is recoverable independently
/// of which slice happens to sit at index zero. Throws away the
/// cross-format `Metrics`, `Symbols`, and `Section` outputs — those
/// keep tracking the preferred slice via `single_arch`.
fn analyze_slice(macho: &MachO<'_>, slice_bytes: &[u8]) -> JsonValue {
    use crate::output::SymbolKind;
    let mut slice_values = Values::new();
    let mut throwaway_metrics = Metrics::new();
    let mut throwaway_sections: Vec<Section> = Vec::new();
    let mut throwaway_symbols = crate::Symbols::new();

    extract_sections(
        macho,
        slice_bytes,
        &mut throwaway_metrics,
        &mut throwaway_sections,
    );
    extract_header_and_loads(
        macho,
        slice_bytes,
        &mut slice_values,
        &mut throwaway_metrics,
    );
    extract_symbols(macho, &mut throwaway_symbols);
    super::macho_hashes::emit(macho, &mut slice_values, &throwaway_symbols);

    let import_count = throwaway_symbols.iter_kind(SymbolKind::Import).count() as u64;
    let export_count = throwaway_symbols.iter_kind(SymbolKind::Export).count() as u64;

    // Pluck the `macho.*` subtree the extractors built and return it
    // as the slice entry. Anything else (a flat key the future code
    // path might add) is dropped — slices carry only Mach-O-shaped
    // data.
    let mut root = slice_values.into_json();
    if let Some(obj) = root.as_object_mut() {
        if let Some(macho_sub) = obj.remove("macho") {
            // Counts the slice has at the unified-view level — exported
            // as integers on the slice for symmetry with `imports.count`
            // / `exports.count` on the top-level binary.
            if let JsonValue::Object(mut m) = macho_sub {
                m.insert(
                    "import_count".into(),
                    JsonValue::Number(import_count.into()),
                );
                m.insert(
                    "export_count".into(),
                    JsonValue::Number(export_count.into()),
                );
                m.insert(
                    "section_count".into(),
                    JsonValue::Number((throwaway_sections.len() as u64).into()),
                );
                return JsonValue::Object(m);
            }
            return macho_sub;
        }
    }
    JsonValue::Object(serde_json::Map::new())
}

fn single_arch(
    macho: &MachO<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
    symbols_out: &mut crate::Symbols,
) {
    extract_sections(macho, bytes, metrics, sections_out);
    extract_header_and_loads(macho, bytes, values, metrics);
    extract_symbols(macho, symbols_out);
    super::macho_hashes::emit(macho, values, symbols_out);
    super::build_toolchain::from_macho(values, sections_out);
}

/// Walk Mach-O's dyld bind-info (imports) and export trie (exports)
/// and surface them as typed `Imports`/`Exports` entries.
///
/// Two source tags distinguish how the entry was discovered:
/// `macho-bind` for two-level-namespace bind imports (carrying the
/// resolving dylib stem), `macho-trie` for exports recovered from
/// the dyld export trie.
fn extract_symbols(macho: &MachO<'_>, symbols_out: &mut crate::Symbols) {
    // Map each undefined external symbol to the file offset of its name in
    // the `LC_SYMTAB` string table. goblin's `Import::offset` is the dyld
    // *bind* slot (a pointer in `__got`/`__DATA`, binary data), but every
    // other consumer anchors a symbol at its human-readable name — ELF
    // imports point into `.dynstr`, and the hex/context view expects to
    // render the name's ASCII. Anchoring imports at the name string keeps
    // Mach-O consistent with ELF and makes the annotated bytes readable.
    let name_offsets = import_name_offsets(macho);

    // Imports — dylib stems are normalised to the bare library name
    // (lowercased, basename only, `.dylib`/`.tbd` suffix stripped) so
    // trait authors can match against `"libsystem.b"` rather than
    // `"/usr/lib/libSystem.B.dylib"`.
    if let Ok(imports) = macho.imports() {
        for imp in &imports {
            let library = normalize_dylib_path(imp.dylib);
            // Prefer the name-string offset; fall back to the bind slot
            // when the symbol has no `LC_SYMTAB` entry (rare, e.g.
            // dyld-info-only binaries).
            let offset = name_offsets.get(imp.name).copied().unwrap_or(imp.offset);
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

    // Exports — recovered from the dyld export trie. Re-exports
    // (e.g. `libSystem` forwarding to `libdyld`) come through as
    // regular `Export` entries; we surface only the name here, with
    // forwarded-target handling left to a follow-up.
    if let Ok(exports) = macho.exports() {
        for exp in &exports {
            symbols_out.push(crate::Symbol::Export {
                // Normalize the same Darwin `$VARIANT` suffix as imports: these
                // markers are *defined* in libSystem, so a library re-exporting
                // libc carries them here. The allow-list leaves a binary's own
                // `_OBJC_CLASS_$_…` exports intact.
                name: strip_darwin_symbol_variant(&exp.name).to_string(),
                offset: Some(exp.offset),
                ordinal: None,
                // dyld re-exports are surfaced via ExportInfo::Reexport
                // in goblin; this extractor surfaces them as plain
                // entries today and leaves forwarded-target decoding
                // for a follow-up.
                forward_to: None,
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
fn import_name_offsets<'a>(macho: &MachO<'a>) -> std::collections::HashMap<&'a str, u64> {
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

    for sym in macho.symbols() {
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
fn strip_darwin_symbol_variant(name: &str) -> &str {
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
fn normalize_dylib_path(path: &str) -> String {
    let basename = path.rsplit_once('/').map(|(_, name)| name).unwrap_or(path);
    let stem = basename
        .strip_suffix(".dylib")
        .or_else(|| basename.strip_suffix(".tbd"))
        .unwrap_or(basename);
    stem.to_ascii_lowercase()
}

/// Walk `LC_SEGMENT` / `LC_SEGMENT_64` and surface each named
/// section. Mach-O nests sections inside segments; we flatten the
/// hierarchy with the canonical `__SEGMENT,__section` naming so
/// `__TEXT,__text` etc. survives to the output.
fn extract_sections(
    macho: &MachO<'_>,
    bytes: &[u8],
    _metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
) {
    for segment in &macho.segments {
        let segment_name = segment.name().unwrap_or("").to_owned();
        let flags = macho_segment_flags(segment.initprot);
        let initprot = u64::from(segment.initprot);
        let Ok(secs) = segment.sections() else {
            continue;
        };
        for (section, _data) in secs {
            let section_name = section.name().unwrap_or("").to_owned();
            let display = if section_name.is_empty() {
                segment_name.clone()
            } else {
                format!("{segment_name},{section_name}")
            };
            let file_offset = u64::from(section.offset);
            let file_size = section.size;
            let entropy = (file_size > 0).then(|| section_entropy(bytes, file_offset, file_size));
            sections_out.push(Section {
                name: display,
                vaddr: section.addr,
                vsize: section.size,
                file_offset,
                file_size,
                flags: flags.iter().map(|s| (*s).to_string()).collect(),
                flags_raw: Some(initprot),
                entropy,
            });
        }
    }
}

fn macho_segment_flags(initprot: u32) -> Vec<&'static str> {
    // VM_PROT_READ = 1, VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4.
    let mut out = Vec::new();
    if initprot & 1 != 0 {
        out.push("readable");
    }
    if initprot & 2 != 0 {
        out.push("writable");
    }
    if initprot & 4 != 0 {
        out.push("executable");
    }
    out
}

fn section_entropy(bytes: &[u8], offset: u64, size: u64) -> f64 {
    if size == 0 {
        return 0.0;
    }
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
    if start >= bytes.len() {
        return 0.0;
    }
    let end = end.min(bytes.len());
    entropy::shannon(&bytes[start..end])
}

fn extract_header_and_loads(
    macho: &MachO<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    put_str(
        values,
        "macho.cpu_type",
        cpu_kind_string(macho.header.cputype(), macho.header.cpusubtype()),
    );
    // Raw CPU type / file type / flags. The string-decoded fields above
    // are for trait authors; consumers that need to round-trip the
    // u32 (cleave's typed metrics keep the raw header values) read
    // these `_raw` siblings.
    put_u64(
        values,
        "macho.cpu_type_raw",
        u64::from(macho.header.cputype()),
    );
    put_u64(
        values,
        "macho.cpu_subtype",
        u64::from(macho.header.cpusubtype()),
    );
    put_str(
        values,
        "macho.file_type",
        file_type_string(macho.header.filetype),
    );
    put_u64(
        values,
        "macho.file_type_raw",
        u64::from(macho.header.filetype),
    );
    // Pike-style decomposed flag array — matches `pe.dll_characteristics[]`
    // / `lnk.header.flags[]` schema rather than emitting a raw bitfield
    // that traits would have to mask themselves.
    let mh_flags = mh_flag_names(macho.header.flags);
    if !mh_flags.is_empty() {
        values.insert(
            "macho.flags",
            JsonValue::Array(
                mh_flags
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
    // Raw flags bitfield (typed consumers need the unmasked u32).
    put_u64(values, "macho.flags_raw", u64::from(macho.header.flags));
    put_str(
        values,
        "macho.endian",
        if macho.little_endian { "little" } else { "big" },
    );
    // 32-bit vs 64-bit. Trait authors read `macho.class_bits == 64`;
    // typed consumers (`MachoMetrics::class_bits`) take the same u64.
    put_u64(
        values,
        "macho.class_bits",
        if macho.is_64 { 64 } else { 32 },
    );
    // Entry point address — Mach-O's `entry` (LC_MAIN.entryoff) or
    // legacy LC_UNIXTHREAD thread-state PC. `old_style_entry` is set
    // when the entry came from LC_UNIXTHREAD.
    put_u64(values, "macho.entry", macho.entry);
    if macho.old_style_entry {
        metrics.insert("macho.old_style_entry", 1.0);
    }
    // Raw header counts: number of load commands and their cumulative
    // byte size. `macho.load_command_count` already exists as a
    // metric; `macho.load_commands_size` is new.
    put_u64(
        values,
        "macho.load_commands_size",
        u64::from(macho.header.sizeofcmds),
    );

    let libs: Vec<JsonValue> = macho
        .libs
        .iter()
        .filter(|s| !s.is_empty() && **s != "self")
        .map(|s| JsonValue::String((*s).to_string()))
        .collect();
    // LC_LOAD_DYLIB count surfaces under the cross-format
    // `dependencies.count` metric. No per-format alias.
    metrics.insert("dependencies.count", libs.len() as f64);
    values.insert("macho.libraries", JsonValue::Array(libs));

    let rpaths: Vec<JsonValue> = macho
        .rpaths
        .iter()
        .map(|s| JsonValue::String((*s).to_string()))
        .collect();
    if !rpaths.is_empty() {
        values.insert("macho.rpaths", JsonValue::Array(rpaths));
    }

    // Load commands are the most useful structural fingerprint of a
    // Mach-O. Emit their `cmd` (LC_*) names in order.
    let lcs: Vec<JsonValue> = macho
        .load_commands
        .iter()
        .map(|lc| JsonValue::String(load_command_name(lc.command.cmd()).to_string()))
        .collect();
    metrics.insert("macho.load_command_count", lcs.len() as f64);
    values.insert("macho.load_commands", JsonValue::Array(lcs));

    // Find the LC_CODE_SIGNATURE entry — its `dataoff`/`datasize`
    // point at the embedded code-signature blob inside the
    // `__LINKEDIT` segment. Presence/absence of any
    // `macho.code_signature.*` field IS the "is this binary signed"
    // signal; we don't emit a separate boolean for it.
    let code_sig = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::CodeSignature(cs) => Some(cs),
        _ => None,
    });
    if let Some(cs) = code_sig {
        // Surface the LC_CODE_SIGNATURE blob size up front — cleave's
        // typed `MachoMetrics::code_signature_size` reads this even
        // when the deeper signature parse fails. The blob *offset*
        // isn't useful to downstream consumers (they don't seek into
        // it) so we skip it.
        put_u64(values, "macho.code_signature_size", u64::from(cs.datasize));
        // The blob's file offset — consumers anchor the code-signature
        // finding's evidence here rather than at the header.
        put_u64(values, "macho.code_signature_offset", u64::from(cs.dataoff));
        super::macho_code_signature::parse(
            bytes,
            cs.dataoff as usize,
            cs.datasize as usize,
            values,
        );
    }

    // LC_UUID — 128-bit build fingerprint. Stable per-build, used by
    // dSYM correlation and crash-report symbolication. The canonical
    // text form is the lowercase 8-4-4-4-12 hyphenated layout that
    // `dwarfdump --uuid` emits.
    if let Some((uuid, lc_offset)) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::Uuid(c) => Some((c.uuid, lc.offset)),
        _ => None,
    }) {
        put_str(values, "macho.uuid", format_macho_uuid(&uuid));
        // Anchor the value at the 16 UUID bytes (past the 8-byte cmd/cmdsize
        // header), so a `value` match on `macho.uuid` renders in the hex view.
        put_u64(values, "macho.uuid_offset", (lc_offset + 8) as u64);
    }

    // __TEXT,__info_plist — many Apple tools embed a CFBundle-style
    // Info.plist directly in the binary instead of pairing it with a
    // .app bundle. The content is XML or binary plist; we parse and
    // surface the dictionary under `macho.info_plist`. Forensically
    // valuable: the plist carries `CFBundleIdentifier`, executable
    // name, and any `LSEnvironment` / `LSUIElement` flags that affect
    // load behaviour.
    info_plist_section(macho, bytes, values);
    build_version(macho, bytes, values);
    source_version(macho, values);
    install_name(macho, values);
    load_dylinker(macho, bytes, values);
    load_dylibs(macho, values);
    linker_options(macho, bytes, values);
    objc_image_info(macho, bytes, values);
    swift_sections(macho, values);
    segment_analysis(macho, values, metrics);
    chained_fixups_marker(macho, metrics);
    function_starts(macho, bytes, values, metrics);
    data_in_code_kinds(macho, bytes, values);

    binary_flags(macho, metrics);
}

/// Walk Mach-O segments + sections and emit segment-shape metrics:
///
/// - `macho.wx_segment_count`     — segments with both `WRITE` and
///   `EXECUTE` in their initprot. Almost always 0 in legitimate
///   binaries; non-zero indicates shellcode-friendly layout.
/// - `macho.text_segment_writable` — `__TEXT` segment with write
///   permission. Legit `__TEXT` is `r-x`; writable text is a
///   self-modifying / unpacker signal.
/// - `macho.pagezero_size`        — size of the `__PAGEZERO` segment.
///   Standard is 4 GiB on 64-bit; unusually small / absent values
///   defeat the standard NULL-pointer fault and are an anti-debug
///   tell.
/// - `macho.has_encrypted_section` — any segment with
///   `S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SELF_MODIFYING_CODE` flag
///   bits set (Apple-encrypted FairPlay binaries).
/// - `macho.entry_in_writable_segment` — entry-point address lands
///   in a write-permitted segment.
/// - `macho.entry_outside_segments`   — entry-point address falls
///   outside every load segment (extremely rare; tampered binary).
/// - `macho.segments[]` (values)  — typed program-header listing,
///   mirroring `elf.segments[]`.
fn segment_analysis(macho: &MachO<'_>, values: &mut Values, metrics: &mut Metrics) {
    // VM_PROT_* flags (bits in `initprot`/`maxprot`).
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;

    let entry = entry_point(macho);
    let mut wx_count: u64 = 0;
    let mut wx_segments: Vec<JsonValue> = Vec::new();
    let mut text_writable = false;
    let mut pagezero_size: u64 = 0;
    let mut entry_in_writable = false;
    let mut entry_in_segment = false;
    let mut has_data_const = false;
    let mut segments_out: Vec<JsonValue> = Vec::new();
    for segment in &macho.segments {
        let name = segment.name().unwrap_or("").to_string();
        let writable = segment.initprot & VM_PROT_WRITE != 0;
        let executable = segment.initprot & VM_PROT_EXECUTE != 0;
        let readable = segment.initprot & VM_PROT_READ != 0;
        if writable && executable {
            wx_count += 1;
            wx_segments.push(JsonValue::String(name.clone()));
        }
        if name == "__TEXT" && writable {
            text_writable = true;
        }
        if name == "__PAGEZERO" {
            pagezero_size = segment.vmsize;
        }
        if name == "__DATA_CONST" {
            has_data_const = true;
        }
        if entry != 0 {
            let end = segment.vmaddr.saturating_add(segment.vmsize);
            if entry >= segment.vmaddr && entry < end {
                entry_in_segment = true;
                if writable {
                    entry_in_writable = true;
                }
            }
        }

        let mut entry_obj = serde_json::Map::new();
        entry_obj.insert("name".into(), JsonValue::String(name));
        entry_obj.insert("vaddr".into(), JsonValue::Number(segment.vmaddr.into()));
        entry_obj.insert("vsize".into(), JsonValue::Number(segment.vmsize.into()));
        entry_obj.insert(
            "file_offset".into(),
            JsonValue::Number(segment.fileoff.into()),
        );
        entry_obj.insert(
            "file_size".into(),
            JsonValue::Number(segment.filesize.into()),
        );
        let perms = format!(
            "{}{}{}",
            if readable { "r" } else { "-" },
            if writable { "w" } else { "-" },
            if executable { "x" } else { "-" },
        );
        entry_obj.insert("perms".into(), JsonValue::String(perms));
        // Raw VM protection bitfields. Typed consumers display them as
        // hex (e.g. cleave's `MachoSegmentEntry::initprot_hex`); we
        // emit the u32 and let the consumer choose the formatting.
        entry_obj.insert(
            "initprot_raw".into(),
            JsonValue::Number(u64::from(segment.initprot).into()),
        );
        entry_obj.insert(
            "maxprot_raw".into(),
            JsonValue::Number(u64::from(segment.maxprot).into()),
        );
        segments_out.push(JsonValue::Object(entry_obj));
    }
    metrics.insert("macho.wx_segment_count", wx_count as f64);
    if !wx_segments.is_empty() {
        values.insert("macho.wx_segments", JsonValue::Array(wx_segments));
    }
    if text_writable {
        metrics.insert("macho.text_segment_writable", 1.0);
    }
    if pagezero_size != 0 {
        metrics.insert("macho.pagezero_size", pagezero_size as f64);
    }
    if entry_in_writable {
        metrics.insert("macho.entry_in_writable_segment", 1.0);
    }
    if entry != 0 && !entry_in_segment {
        metrics.insert("macho.entry_outside_segments", 1.0);
    }
    if has_data_const {
        metrics.insert("macho.has_data_const_segment", 1.0);
    }
    if !segments_out.is_empty() {
        values.insert("macho.segments", JsonValue::Array(segments_out));
    }
}

/// Entry-point address from `LC_MAIN`'s `entryoff` (modern dylinker)
/// or the legacy `LC_UNIXTHREAD`'s thread-state PC. Returns `0` when
/// neither is present (typical for shared libraries).
fn entry_point(macho: &MachO<'_>) -> u64 {
    for lc in &macho.load_commands {
        if let mach::load_command::CommandVariant::Main(main) = lc.command {
            return main.entryoff;
        }
    }
    macho.entry
}

/// Per-load-command shape metrics. Combines several presence checks
/// in one walk so we don't iterate the load-command list more than
/// once: chained fixups vs legacy dyld_info, encrypted regions,
/// legacy `LC_VERSION_MIN_*`, `LC_DATA_IN_CODE` entry count, and the
/// `LC_MAIN` / `LC_UNIXTHREAD` entry-style markers.
fn chained_fixups_marker(macho: &MachO<'_>, metrics: &mut Metrics) {
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    let mut has_chained = false;
    let mut has_legacy_dyld_info = false;
    let mut has_encrypted = false;
    let mut uses_legacy_version_min = false;
    let mut data_in_code_count: u32 = 0;
    let mut has_main_command = false;
    let mut has_unixthread_command = false;
    for lc in &macho.load_commands {
        let cmd = lc.command.cmd();
        if cmd == LC_DYLD_CHAINED_FIXUPS {
            has_chained = true;
        }
        match lc.command {
            mach::load_command::CommandVariant::DyldInfo(_)
            | mach::load_command::CommandVariant::DyldInfoOnly(_) => {
                has_legacy_dyld_info = true;
            }
            mach::load_command::CommandVariant::EncryptionInfo32(e) if e.cryptid != 0 => {
                has_encrypted = true;
            }
            mach::load_command::CommandVariant::EncryptionInfo64(e) if e.cryptid != 0 => {
                has_encrypted = true;
            }
            mach::load_command::CommandVariant::VersionMinMacosx(_)
            | mach::load_command::CommandVariant::VersionMinIphoneos(_)
            | mach::load_command::CommandVariant::VersionMinTvos(_)
            | mach::load_command::CommandVariant::VersionMinWatchos(_) => {
                uses_legacy_version_min = true;
            }
            mach::load_command::CommandVariant::DataInCode(c) => {
                // Each entry is 8 bytes (offset:u32, length:u16, kind:u16).
                data_in_code_count = c.datasize / 8;
            }
            mach::load_command::CommandVariant::Main(_) => {
                has_main_command = true;
            }
            mach::load_command::CommandVariant::Unixthread(_) => {
                has_unixthread_command = true;
            }
            _ => {}
        }
    }
    if has_chained {
        metrics.insert("macho.has_chained_fixups", 1.0);
    }
    if has_legacy_dyld_info {
        metrics.insert("macho.has_dyld_info_legacy", 1.0);
    }
    if has_encrypted {
        metrics.insert("macho.has_encrypted_section", 1.0);
    }
    if uses_legacy_version_min {
        metrics.insert("macho.uses_legacy_version_min", 1.0);
    }
    if data_in_code_count > 0 {
        metrics.insert("macho.data_in_code_count", f64::from(data_in_code_count));
    }
    if has_main_command {
        metrics.insert("macho.has_main_command", 1.0);
    }
    if has_unixthread_command {
        metrics.insert("macho.has_unixthread_command", 1.0);
    }
}

/// `LC_FUNCTION_STARTS` — ULEB128-encoded deltas from `__TEXT` base
/// to each function entry. Counting non-zero deltas (a zero byte
/// terminates the stream) gives the function count the linker
/// recorded. Forensically useful: stripped binaries still carry
/// this, so it's the best lower bound on function count when no
/// symbol table is present. Emits `macho.function_starts_count` as
/// a metric.
fn function_starts(macho: &MachO<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(fs) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::FunctionStarts(c) => Some(c),
        _ => None,
    }) else {
        return;
    };
    let start = fs.dataoff as usize;
    let size = fs.datasize as usize;
    let end = start.saturating_add(size).min(bytes.len());
    if start >= bytes.len() || start >= end {
        return;
    }
    let data = &bytes[start..end];
    let mut count: u64 = 0;
    let mut i = 0usize;
    while i < data.len() {
        // Read one ULEB128. Zero is the stream terminator and
        // signals end-of-table (any padding bytes after it are
        // ignored).
        let mut value: u64 = 0;
        let mut shift = 0u32;
        let mut consumed = 0usize;
        loop {
            if i + consumed >= data.len() {
                break;
            }
            let b = data[i + consumed];
            consumed += 1;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                break;
            }
        }
        i += consumed;
        if value == 0 {
            break;
        }
        count += 1;
    }
    metrics.insert("macho.function_starts_count", count as f64);
    put_u64(values, "macho.function_starts_count", count);
}

/// `LC_DATA_IN_CODE` — table of (offset, length, kind) triples
/// marking byte ranges inside `__TEXT,__text` that are *data*
/// rather than executable code. Reverse engineers hit these as
/// jump tables and inline constants the disassembler must skip
/// over.
///
/// Kind values are stable Apple constants (`<mach-o/loader.h>`
/// `DICE_KIND_*`); a histogram is more useful than the raw count
/// because the kind distribution is itself a fingerprint of the
/// compiler's switch-statement codegen.
fn data_in_code_kinds(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    let Some(dic) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::DataInCode(c) => Some(c),
        _ => None,
    }) else {
        return;
    };
    let start = dic.dataoff as usize;
    let size = dic.datasize as usize;
    let end = start.saturating_add(size).min(bytes.len());
    if start >= end {
        return;
    }
    let little_endian = macho.little_endian;
    let mut kinds = serde_json::Map::new();
    for chunk in bytes[start..end].chunks_exact(8) {
        let kind = if little_endian {
            u16::from_le_bytes([chunk[6], chunk[7]])
        } else {
            u16::from_be_bytes([chunk[6], chunk[7]])
        };
        let name = data_in_code_kind_name(kind);
        let entry = kinds
            .entry(name.to_string())
            .or_insert(JsonValue::Number(0.into()));
        if let Some(n) = entry.as_u64() {
            *entry = JsonValue::Number((n + 1).into());
        }
    }
    if !kinds.is_empty() {
        values.insert("macho.data_in_code_kinds", JsonValue::Object(kinds));
    }
}

fn data_in_code_kind_name(kind: u16) -> &'static str {
    // `<mach-o/loader.h>` `DICE_KIND_*`.
    match kind {
        1 => "data",
        2 => "jump_table8",
        3 => "jump_table16",
        4 => "jump_table32",
        5 => "abs_jump_table32",
        _ => "unknown",
    }
}

/// `LC_LINKER_OPTION` (cmd `0x2d`) — embeds linker arguments
/// (`-framework Foundation`, `-lc++`, …) the link step would
/// otherwise consume off the command line. The body is a `u32`
/// count followed by `count` NUL-terminated strings, padded to
/// 8-byte alignment. Surfaces each string as an element of
/// `macho.linker_options[]`.
fn linker_options(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    let little_endian = macho.little_endian;
    let mut all: Vec<JsonValue> = Vec::new();
    for lc in &macho.load_commands {
        let mach::load_command::CommandVariant::LinkerOption(c) = lc.command else {
            continue;
        };
        let cmd_offset = lc.offset;
        let cmd_size = c.cmdsize as usize;
        let header_size = 12_usize; // cmd + cmdsize + count
        let body_start = cmd_offset.saturating_add(header_size);
        let body_end = cmd_offset.saturating_add(cmd_size).min(bytes.len());
        if body_start + 4 > body_end {
            continue;
        }
        let count_field_start = cmd_offset.saturating_add(8);
        let count = read_u32(
            &bytes[count_field_start..count_field_start + 4],
            0,
            little_endian,
        ) as usize;
        let body = &bytes[body_start..body_end];
        let mut taken = 0;
        for chunk in body.split(|&b| b == 0) {
            if taken >= count {
                break;
            }
            if chunk.is_empty() {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(chunk) {
                all.push(JsonValue::String(s.to_string()));
                taken += 1;
            }
        }
    }
    if !all.is_empty() {
        values.insert("macho.linker_options", JsonValue::Array(all));
    }
}

/// `__OBJC,__image_info` / `__DATA,__objc_imageinfo` — 8-byte
/// section: `(version: u32, flags: u32)`. The Swift ABI version
/// lives in `flags[15:8]`; presence alone signals the binary
/// links the Objective-C runtime.
fn objc_image_info(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _data) in sections {
            let name = section.name().unwrap_or("");
            if name != "__image_info" && name != "__objc_imageinfo" {
                continue;
            }
            let off = section.offset as usize;
            let end = off.saturating_add(section.size as usize).min(bytes.len());
            if end < off + 8 {
                return;
            }
            let little_endian = macho.little_endian;
            let _version = read_u32(&bytes[off..off + 4], 0, little_endian);
            let flags = read_u32(&bytes[off + 4..off + 8], 0, little_endian);
            let swift_version = (flags >> 8) & 0xff;
            let mut obj = serde_json::Map::new();
            obj.insert(
                "flags_raw".into(),
                JsonValue::Number(u64::from(flags).into()),
            );
            if swift_version != 0 {
                obj.insert(
                    "swift_version".into(),
                    JsonValue::Number(u64::from(swift_version).into()),
                );
                if let Some(label) = swift_version_label(swift_version as u8) {
                    obj.insert(
                        "swift_version_label".into(),
                        JsonValue::String(label.to_string()),
                    );
                }
            }
            // Bit 3: OBJC_IMAGE_OPTIMIZED_BY_DYLD.
            // Bit 5: OBJC_IMAGE_IS_SIMULATED.
            // Bit 6: OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES.
            if flags & (1 << 3) != 0 {
                obj.insert("optimized_by_dyld".into(), JsonValue::Bool(true));
            }
            if flags & (1 << 5) != 0 {
                obj.insert("simulator".into(), JsonValue::Bool(true));
            }
            if flags & (1 << 6) != 0 {
                obj.insert(
                    "has_category_class_properties".into(),
                    JsonValue::Bool(true),
                );
            }
            values.insert("macho.objc", JsonValue::Object(obj));
            return;
        }
    }
}

/// Apple's Swift runtime version table — values >= 8 indicate Swift
/// 5.x where the exact version is encoded in additional metadata.
fn swift_version_label(byte: u8) -> Option<&'static str> {
    Some(match byte {
        0 => return None,
        1 => "1.0",
        2 => "1.1",
        3 => "2.0",
        4 => "3.0",
        5 => "4.0",
        6 => "4.1",
        7 => "4.2",
        _ => "5.0+",
    })
}

/// `__TEXT,__swift5_*` section family — protocol/type/reflection
/// metadata emitted by every swiftc-built binary. The specific subset
/// present pins the Swift compiler version (acfuncs ≥ 5.5, mpenum
/// newer, …). Emitted as `macho.swift_sections[]` (sorted, deduped
/// section names with their `__` prefix).
fn swift_sections(macho: &MachO<'_>, values: &mut Values) {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for segment in &macho.segments {
        if segment.name().unwrap_or("") != "__TEXT" {
            continue;
        }
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _data) in sections {
            let name = section.name().unwrap_or("");
            if name.starts_with("__swift5_") {
                out.insert(name.to_string());
            }
        }
    }
    if !out.is_empty() {
        values.insert(
            "macho.swift_sections",
            JsonValue::Array(out.into_iter().map(JsonValue::String).collect()),
        );
    }
}

/// Per-dylib metadata for every `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` /
/// `LC_REEXPORT_DYLIB` / `LC_LAZY_LOAD_DYLIB` command. Surfaces the
/// path (already in `macho.libraries[]`), the load kind (`load` /
/// `load_weak` / `reexport` / `lazy_load`), the dylib's declared
/// `current_version` and `compatibility_version`, and the linker
/// timestamp it was prebound against. `LC_ID_DYLIB` is excluded —
/// that's the dylib's own identity, already exposed as
/// `macho.install_name`.
fn load_dylibs(macho: &MachO<'_>, values: &mut Values) {
    let mut entries: Vec<JsonValue> = Vec::new();
    for lc in &macho.load_commands {
        let (kind, dylib) = match lc.command {
            mach::load_command::CommandVariant::LoadDylib(c) => ("load", c.dylib),
            mach::load_command::CommandVariant::LoadWeakDylib(c) => ("load_weak", c.dylib),
            mach::load_command::CommandVariant::ReexportDylib(c) => ("reexport", c.dylib),
            mach::load_command::CommandVariant::LazyLoadDylib(c) => ("lazy_load", c.dylib),
            mach::load_command::CommandVariant::LoadUpwardDylib(c) => ("upward", c.dylib),
            _ => continue,
        };
        // The dylib name is an `LcStr` (offset into the command's
        // bytes). Goblin's `MachO::libs` array carries the resolved
        // strings in load-command order with the ID_DYLIB / "self"
        // slot at index 0; the LoadDylib variants we keep here start
        // at index 1.
        let idx = entries.len() + 1;
        let path = macho.libs.get(idx).copied().unwrap_or("");
        let mut entry = serde_json::Map::new();
        entry.insert("path".into(), JsonValue::String(path.to_string()));
        // File offset of this LC_LOAD*_DYLIB load command — where the dylib
        // reference physically sits, so consumers can anchor evidence there.
        entry.insert(
            "offset".into(),
            JsonValue::Number((lc.offset as u64).into()),
        );
        entry.insert("kind".into(), JsonValue::String(kind.to_string()));
        entry.insert(
            "path_kind".into(),
            JsonValue::String(install_name_kind(path).to_string()),
        );
        entry.insert(
            "current_version".into(),
            JsonValue::String(decode_version_nibbles(dylib.current_version)),
        );
        // Raw packed u32 — typed consumers (cleave's `MachoDylibEntry`)
        // keep the unencoded value alongside the human-readable form.
        entry.insert(
            "current_version_raw".into(),
            JsonValue::Number(u64::from(dylib.current_version).into()),
        );
        entry.insert(
            "compatibility_version".into(),
            JsonValue::String(decode_version_nibbles(dylib.compatibility_version)),
        );
        entry.insert(
            "compatibility_version_raw".into(),
            JsonValue::Number(u64::from(dylib.compatibility_version).into()),
        );
        if dylib.timestamp != 0 {
            entry.insert(
                "timestamp".into(),
                JsonValue::Number(dylib.timestamp.into()),
            );
        }
        entries.push(JsonValue::Object(entry));
    }
    if !entries.is_empty() {
        values.insert("macho.load_dylibs", JsonValue::Array(entries));
    }
}

/// `LC_BUILD_VERSION` — declares the platform (`macos`, `ios`, `tvos`,
/// `watchos`, …), the minimum-supported OS version, the SDK version
/// the toolchain was built against, and a list of `BuildToolVersion`
/// entries naming each tool (clang, ld, swift, …) that contributed.
/// Replaces the legacy `LC_VERSION_MIN_*` commands on modern (10.14+)
/// toolchains.
///
/// `goblin` parses the 24-byte header but stops there; we read the
/// `ntools` × 8-byte `BuildToolVersion` array that follows.
fn build_version(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    let Some((lc_offset, bv)) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::BuildVersion(c) => Some((lc.offset, c)),
        _ => None,
    }) else {
        return;
    };
    let mut obj = serde_json::Map::new();
    obj.insert(
        "platform".into(),
        JsonValue::String(platform_name(bv.platform).to_string()),
    );
    if bv.minos != 0 {
        obj.insert(
            "min_os".into(),
            JsonValue::String(decode_version_nibbles(bv.minos)),
        );
    }
    if bv.sdk != 0 {
        obj.insert(
            "sdk".into(),
            JsonValue::String(decode_version_nibbles(bv.sdk)),
        );
    }
    if bv.ntools > 0 {
        let header_size = 24_usize;
        let tools_start = lc_offset.saturating_add(header_size);
        let entries_bytes = (bv.ntools as usize).saturating_mul(8);
        let tools_end = tools_start.saturating_add(entries_bytes).min(bytes.len());
        if tools_start + 8 <= tools_end {
            let little_endian = macho.little_endian;
            let tools: Vec<JsonValue> = bytes[tools_start..tools_end]
                .chunks_exact(8)
                .map(|c| {
                    let tool = read_u32(c, 0, little_endian);
                    let version = read_u32(c, 4, little_endian);
                    let mut entry = serde_json::Map::new();
                    entry.insert(
                        "tool".into(),
                        JsonValue::String(build_tool_name(tool).to_string()),
                    );
                    entry.insert(
                        "version".into(),
                        JsonValue::String(decode_version_nibbles(version)),
                    );
                    JsonValue::Object(entry)
                })
                .collect();
            if !tools.is_empty() {
                obj.insert("tools".into(), JsonValue::Array(tools));
            }
        }
    }
    values.insert("macho.build_version", JsonValue::Object(obj));
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> u32 {
    use crate::formats::common::bytes_at;
    if little_endian {
        bytes_at::u32_le(bytes, offset).unwrap_or(0)
    } else {
        bytes_at::u32_be(bytes, offset).unwrap_or(0)
    }
}

/// `<mach-o/loader.h>` `TOOL_*` constants.
fn build_tool_name(tool: u32) -> &'static str {
    match tool {
        1 => "clang",
        2 => "swift",
        3 => "ld",
        4 => "lld",
        5 => "metal",
        _ => "unknown",
    }
}

/// `LC_SOURCE_VERSION` — developer-stamped source-tree version
/// (`a.b.c.d.e` packed as 24/10/10/10/10 bits). Almost always
/// unset (zero) on stock binaries; populated when the build system
/// explicitly threads a version through the linker.
fn source_version(macho: &MachO<'_>, values: &mut Values) {
    let Some(sv) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::SourceVersion(c) => Some(c.version),
        _ => None,
    }) else {
        return;
    };
    if sv == 0 {
        return;
    }
    let a = (sv >> 40) & 0xFF_FFFF;
    let b = (sv >> 30) & 0x3FF;
    let c = (sv >> 20) & 0x3FF;
    let d = (sv >> 10) & 0x3FF;
    let e = sv & 0x3FF;
    put_str(
        values,
        "macho.source_version",
        format!("{a}.{b}.{c}.{d}.{e}"),
    );
}

/// `LC_ID_DYLIB` — the dylib's own install name (only present on
/// shared libraries / frameworks). Always the first dylib command;
/// downstream `LC_LOAD_DYLIB`s reference other libraries.
fn install_name(macho: &MachO<'_>, values: &mut Values) {
    let Some(id) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::IdDylib(c) => Some(c),
        _ => None,
    }) else {
        return;
    };
    // The Dylib `name` is an offset into the command bytes; goblin
    // surfaces every dylib path through `macho.libs`, with the
    // ID_DYLIB slot at index 0 (or "self" for non-dylibs). For the
    // install-name field we want the resolved string — pull it from
    // `libs[0]` when the binary is a dylib and the slot isn't `self`.
    let _ = id; // suppress unused; resolution done via libs below
    if let Some(name) = macho.libs.first().copied() {
        if !name.is_empty() && name != "self" {
            put_str(values, "macho.install_name", name);
            put_str(values, "macho.install_name_kind", install_name_kind(name));
        }
    }
}

/// Classify an install_name / dylib path by its leading dyld token.
/// The 3CX backdoor toggled libffmpeg's `install_name` from `@rpath`
/// to `@loader_path`; surfacing the kind lets trait authors compare
/// the categorical form rather than regex-matching the raw string.
fn install_name_kind(path: &str) -> &'static str {
    if let Some(rest) = path.strip_prefix('@') {
        if rest == "rpath" || rest.starts_with("rpath/") {
            "rpath"
        } else if rest == "loader_path" || rest.starts_with("loader_path/") {
            "loader_path"
        } else if rest == "executable_path" || rest.starts_with("executable_path/") {
            "executable_path"
        } else {
            "other_token"
        }
    } else if path.starts_with('/') {
        "absolute"
    } else {
        "relative"
    }
}

/// `LC_LOAD_DYLINKER` — path to the dynamic linker the binary was
/// linked against. On macOS this is almost always `/usr/lib/dyld`;
/// any other path is a strong injection / tampering signal (custom
/// dyld replacements have been used by both Apple-internal tools and
/// targeted attacks). Emitted as `macho.dyld_path`.
fn load_dylinker(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    let Some((lc_offset, name_offset)) =
        macho.load_commands.iter().find_map(|lc| match lc.command {
            mach::load_command::CommandVariant::LoadDylinker(c) => {
                Some((lc.offset, c.name as usize))
            }
            _ => None,
        })
    else {
        return;
    };
    let start = lc_offset.saturating_add(name_offset);
    if start >= bytes.len() {
        return;
    }
    let tail = &bytes[start..];
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    if let Ok(s) = std::str::from_utf8(&tail[..end]) {
        if !s.is_empty() {
            put_str(values, "macho.dyld_path", s);
        }
    }
}

/// Decode a Mach-O version field (`X.Y.Z` packed as `xxxx.yy.zz`
/// nibbles in a `u32`).
fn decode_version_nibbles(v: u32) -> String {
    let x = (v >> 16) & 0xFFFF;
    let y = (v >> 8) & 0xFF;
    let z = v & 0xFF;
    format!("{x}.{y}.{z}")
}

/// Map `LC_BUILD_VERSION.platform` to a canonical lowercase name.
fn platform_name(p: u32) -> &'static str {
    // `<mach-o/loader.h>` `PLATFORM_*`.
    match p {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "maccatalyst",
        7 => "ios_simulator",
        8 => "tvos_simulator",
        9 => "watchos_simulator",
        10 => "driverkit",
        11 => "visionos",
        12 => "visionos_simulator",
        _ => "unknown",
    }
}

/// Cross-format `binary.*` metrics derivable from Mach-O header / load
/// commands.
fn binary_flags(macho: &MachO<'_>, metrics: &mut Metrics) {
    // PIE: `MH_PIE = 0x00200000` in the header flags. Set by the
    // linker for position-independent executables; required for
    // App Store / hardened runtime.
    const MH_PIE: u32 = 0x0020_0000;
    let is_pie = macho.header.flags & MH_PIE != 0;
    metrics.insert("binary.is_pie", f64::from(u8::from(is_pie)));

    // Stripped: `LC_SYMTAB.nsyms == 0`. The `nlist` table is the
    // Mach-O equivalent of ELF's `.symtab`; `strip` zeroes it out.
    let nsyms = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::Symtab(st) => Some(st.nsyms),
        _ => None,
    });
    let is_stripped = nsyms.is_some_and(|n| n == 0);
    metrics.insert("binary.is_stripped", f64::from(u8::from(is_stripped)));
}

fn info_plist_section(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    // Both sections live under `__TEXT` and store a serialized plist
    // dictionary (XML or binary). `__info_plist` carries the CFBundle
    // metadata; `__launchd_plist` carries the launchd job spec for
    // self-installing daemons (`ProgramArguments`, `KeepAlive`,
    // `RunAtLoad`, …). Surfaced under sibling subtrees so trait
    // authors can read both with the same shape.
    for (section_name, value_key) in [
        ("__info_plist", "macho.info_plist"),
        ("__launchd_plist", "macho.launchd_plist"),
    ] {
        emit_embedded_plist(macho, bytes, values, section_name, value_key);
    }
}

/// Maximum recursion depth honoured when projecting a parsed plist
/// into JSON. Bounds stack usage on plists whose value graph nests
/// arrays and dictionaries beyond what real Apple artifacts emit.
const MAX_EMBEDDED_PLIST_DEPTH: u8 = 64;

/// Upper bound on the bytes we hand to `plist::Value::from_reader` for
/// `__info_plist` / `__launchd_plist` sections. Real binaries carry at
/// most a few hundred KiB; capping prevents an oversized embedded
/// plist from forcing megabytes of attacker XML through the parser.
const MAX_EMBEDDED_PLIST_BYTES: usize = 8 << 20;

fn emit_embedded_plist(
    macho: &MachO<'_>,
    bytes: &[u8],
    values: &mut Values,
    section_name: &str,
    value_key: &str,
) {
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _data) in sections {
            if section.name().unwrap_or("") != section_name {
                continue;
            }
            let off = section.offset as usize;
            let len = section.size as usize;
            let end = off.saturating_add(len);
            if off >= bytes.len() || end > bytes.len() || len == 0 {
                return;
            }
            if len > MAX_EMBEDDED_PLIST_BYTES {
                return;
            }
            let plist_bytes = &bytes[off..end];
            if let Ok(parsed) = plist::Value::from_reader(std::io::Cursor::new(plist_bytes)) {
                values.insert(value_key, plist_to_json(parsed, 0));
            }
            return;
        }
    }
}

fn plist_to_json(value: plist::Value, depth: u8) -> JsonValue {
    use plist::Value as P;
    if depth > MAX_EMBEDDED_PLIST_DEPTH {
        return JsonValue::Null;
    }
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(format!("{d:?}")),
        P::Array(arr) => JsonValue::Array(
            arr.into_iter()
                .map(|v| plist_to_json(v, depth + 1))
                .collect(),
        ),
        P::Dictionary(dict) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v, depth + 1));
            }
            JsonValue::Object(obj)
        }
        _ => JsonValue::Null,
    }
}

fn format_macho_uuid(b: &[u8; 16]) -> String {
    // RFC-4122-style hyphenation, kept lowercase to match every Apple
    // tool's output (codesign, dwarfdump, otool -l).
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Decompose Mach-O header flags into a Pike-style array of names.
/// Values from `<mach-o/loader.h>` `MH_*`; word boundaries are
/// preserved so the names read naturally instead of running the
/// loader.h symbol's letters together.
fn mh_flag_names(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0000_0001 != 0 {
        out.push("no_undefs");
    }
    if flags & 0x0000_0002 != 0 {
        out.push("incremental_link");
    }
    if flags & 0x0000_0004 != 0 {
        out.push("dyld_link");
    }
    if flags & 0x0000_0008 != 0 {
        out.push("bind_at_load");
    }
    if flags & 0x0000_0010 != 0 {
        out.push("pre_bound");
    }
    if flags & 0x0000_0020 != 0 {
        out.push("split_segments");
    }
    if flags & 0x0000_0040 != 0 {
        out.push("lazy_init");
    }
    if flags & 0x0000_0080 != 0 {
        out.push("two_level");
    }
    if flags & 0x0000_0100 != 0 {
        out.push("force_flat");
    }
    if flags & 0x0000_0200 != 0 {
        out.push("no_multi_defs");
    }
    if flags & 0x0000_0400 != 0 {
        out.push("no_fix_pre_binding");
    }
    if flags & 0x0000_0800 != 0 {
        out.push("pre_bindable");
    }
    if flags & 0x0000_1000 != 0 {
        out.push("all_mods_bound");
    }
    if flags & 0x0000_2000 != 0 {
        out.push("subsections_via_symbols");
    }
    if flags & 0x0000_4000 != 0 {
        out.push("canonical");
    }
    if flags & 0x0000_8000 != 0 {
        out.push("weak_defines");
    }
    if flags & 0x0001_0000 != 0 {
        out.push("binds_to_weak");
    }
    if flags & 0x0002_0000 != 0 {
        out.push("allow_stack_execution");
    }
    if flags & 0x0004_0000 != 0 {
        out.push("root_safe");
    }
    if flags & 0x0008_0000 != 0 {
        out.push("setuid_safe");
    }
    if flags & 0x0010_0000 != 0 {
        out.push("no_reexported_dylibs");
    }
    if flags & 0x0020_0000 != 0 {
        out.push("pie");
    }
    if flags & 0x0040_0000 != 0 {
        out.push("dead_strippable_dylib");
    }
    if flags & 0x0080_0000 != 0 {
        out.push("has_tlv_descriptors");
    }
    if flags & 0x0100_0000 != 0 {
        out.push("no_heap_execution");
    }
    if flags & 0x0200_0000 != 0 {
        out.push("app_extension_safe");
    }
    out
}

fn cpu_type_string(cpu_type: u32) -> &'static str {
    // From `<mach/machine.h>` `CPU_TYPE_*`.
    match cpu_type {
        0x0000_0007 => "x86",
        0x0100_0007 => "x86_64",
        0x0000_000c => "arm",
        0x0100_000c => "arm64",
        0x0200_000c => "arm64_32",
        0x0000_0012 => "powerpc",
        0x0100_0012 => "powerpc64",
        _ => "unknown",
    }
}

/// Render the canonical Apple shorthand for a (cputype, cpusubtype)
/// pair. `arm64e` and `x86_64h` are the forensically interesting ones
/// — both are subtype-driven variants the bare cputype loses:
/// `arm64e` carries pointer-authentication (PAC) bindings,
/// `x86_64h` is the Haswell-only slice. The low byte of cpusubtype
/// carries the family value; the high byte holds capability flags
/// (`CPU_SUBTYPE_MASK`) we strip before matching.
fn cpu_kind_string(cpu_type: u32, cpu_subtype: u32) -> &'static str {
    let sub = (cpu_subtype & 0x00ff_ffff) as u8;
    match (cpu_type, sub) {
        (0x0100_000c, 0) => "arm64",
        (0x0100_000c, 1) => "arm64v8",
        (0x0100_000c, 2) => "arm64e",
        (0x0200_000c, 0) => "arm64_32",
        (0x0200_000c, 1) => "arm64_32v8",
        (0x0100_0007, 3) => "x86_64",
        (0x0100_0007, 8) => "x86_64h",
        _ => cpu_type_string(cpu_type),
    }
}

fn file_type_string(filetype: u32) -> &'static str {
    // From `<mach-o/loader.h>` `MH_*`.
    match filetype {
        0x1 => "object",
        0x2 => "executable",
        0x3 => "fvmlib",
        0x4 => "core",
        0x5 => "preload",
        0x6 => "dylib",
        0x7 => "dylinker",
        0x8 => "bundle",
        0x9 => "dylib_stub",
        0xa => "dsym",
        0xb => "kext_bundle",
        0xc => "fileset",
        _ => "unknown",
    }
}

fn load_command_name(cmd: u32) -> &'static str {
    // Subset of `LC_*`. Comprehensive enough for forensic fingerprinting.
    match cmd {
        0x01 => "LC_SEGMENT",
        0x02 => "LC_SYMTAB",
        0x0b => "LC_DYSYMTAB",
        0x0c => "LC_LOAD_DYLIB",
        0x0d => "LC_ID_DYLIB",
        0x0e => "LC_LOAD_DYLINKER",
        0x0f => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x12 => "LC_SUB_FRAMEWORK",
        0x18 => "LC_LOAD_WEAK_DYLIB",
        0x19 => "LC_SEGMENT_64",
        0x1a => "LC_ROUTINES_64",
        0x1b => "LC_UUID",
        0x1c => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x1f => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x28 => "LC_MAIN",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINT",
        0x2f => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        0x33 => "LC_DYLD_EXPORTS_TRIE",
        0x34 => "LC_DYLD_CHAINED_FIXUPS",
        0x35 => "LC_FILESET_ENTRY",
        // High bit set indicates required for execution; mask it off.
        other if other & 0x8000_0000 != 0 => load_command_name(other & 0x7fff_ffff),
        _ => "LC_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_type_string_known() {
        assert_eq!(cpu_type_string(0x0100_0007), "x86_64");
        assert_eq!(cpu_type_string(0x0100_000c), "arm64");
        assert_eq!(cpu_type_string(0xffff_ffff), "unknown");
    }

    #[test]
    fn macho_go_pclntab_magic_is_validated() {
        let pclntab = [0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08];
        assert!(crate::formats::go_buildinfo::has_pclntab_magic(&pclntab));
    }

    #[test]
    fn macho_spoofed_pclntab_is_not_treated_as_go() {
        assert!(!crate::formats::go_buildinfo::has_pclntab_magic(
            b"not a real pclntab"
        ));
    }

    #[test]
    fn file_type_string_known() {
        assert_eq!(file_type_string(0x2), "executable");
        assert_eq!(file_type_string(0x6), "dylib");
        assert_eq!(file_type_string(0xb), "kext_bundle");
    }

    #[test]
    fn strip_darwin_symbol_variant_recovers_base() {
        // Darwin libc variant suffixes are stripped to the base symbol.
        assert_eq!(strip_darwin_symbol_variant("popen$DARWIN_EXTSN"), "popen");
        assert_eq!(strip_darwin_symbol_variant("write$UNIX2003"), "write");
        assert_eq!(strip_darwin_symbol_variant("stat$INODE64"), "stat");
        assert_eq!(strip_darwin_symbol_variant("open$NOCANCEL"), "open");
        assert_eq!(strip_darwin_symbol_variant("time$1050"), "time");
        // Chained variants collapse to the single base symbol.
        assert_eq!(
            strip_darwin_symbol_variant("close$NOCANCEL$UNIX2003"),
            "close"
        );
        // Plain symbols are untouched.
        assert_eq!(strip_darwin_symbol_variant("popen"), "popen");
        assert_eq!(
            strip_darwin_symbol_variant("_objc_msgSend"),
            "_objc_msgSend"
        );
        // Objective-C class/metaclass references (imported and exported) also
        // use `$`; they must survive, even when the class name is entirely
        // upper-case and so looks variant-shaped — the case a naive shape
        // heuristic truncates to `_OBJC_CLASS_`.
        assert_eq!(
            strip_darwin_symbol_variant("_OBJC_CLASS_$_NSURL"),
            "_OBJC_CLASS_$_NSURL"
        );
        assert_eq!(
            strip_darwin_symbol_variant("_OBJC_CLASS_$_ABC"),
            "_OBJC_CLASS_$_ABC"
        );
        assert_eq!(
            strip_darwin_symbol_variant("_OBJC_METACLASS_$_ABC"),
            "_OBJC_METACLASS_$_ABC"
        );
        // Linker directives (leading `$`) and unknown `$` tails are preserved.
        assert_eq!(
            strip_darwin_symbol_variant("$ld$hide$os10.4$_foo"),
            "$ld$hide$os10.4$_foo"
        );
        assert_eq!(strip_darwin_symbol_variant("foo$bar"), "foo$bar");
    }

    #[test]
    fn load_command_name_strips_required_bit() {
        // LC_LOAD_DYLIB with `LC_REQ_DYLD` bit set
        assert_eq!(load_command_name(0x8000_000c), "LC_LOAD_DYLIB");
    }

    /// End-to-end coverage of the variant-suffix normalization through the
    /// full `open()` pipeline, on a real Mach-O whose `LC_SYMTAB` records
    /// libc calls under Darwin's `$`-variant spelling. The fixture is a live
    /// (already-public) malware sample, so it is stored zstd-compressed — both
    /// to keep it small and to keep an executable backdoor from sitting
    /// unpacked in the tree where on-access scanners would quarantine it.
    #[test]
    fn open_normalizes_darwin_variant_import_names() {
        let compressed = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/macho-darwin-variant-symbols.dylib.zst"
        ))
        .expect("fixture present");
        let bytes = zstd::decode_all(compressed.as_slice()).expect("fixture decompresses");

        let parsed = crate::open(&bytes).expect("fixture parses");
        let imports: Vec<&str> = parsed
            .symbols()
            .iter_kind(crate::SymbolKind::Import)
            .filter_map(|s| match s {
                crate::Symbol::Import { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert!(!imports.is_empty(), "dylib imports should populate");

        // Variant suffixes are stripped to the base symbol.
        assert!(
            imports.contains(&"_popen"),
            "popen$DARWIN_EXTSN should normalize to _popen; got {imports:?}"
        );
        assert!(
            imports.contains(&"_fopen") && imports.contains(&"_fdopen"),
            "fopen/fdopen variants should normalize to their base names"
        );
        // No import retains a Darwin variant suffix.
        assert!(
            !imports.iter().any(|n| n.contains("$DARWIN_EXTSN")
                || n.contains("$UNIX2003")
                || n.contains("$INODE64")
                || n.contains("$NOCANCEL")),
            "no import should retain a Darwin variant suffix; got {imports:?}"
        );
        // Objective-C class references also contain `$` and must survive intact,
        // never truncated at the `$` to a bare `_OBJC_CLASS_`.
        assert!(
            imports.contains(&"_OBJC_CLASS_$_NSURL"),
            "ObjC class import must survive normalization intact"
        );
        assert!(
            !imports.contains(&"_OBJC_CLASS_") && !imports.contains(&"_OBJC_METACLASS_"),
            "ObjC class reference must not be truncated at its `$`"
        );
    }

    /// Regression test for a panic seen in the field: a small file
    /// whose CAFEBABE prefix made goblin parse a fat header with
    /// implausible arch offsets. The old slicing path computed
    /// `&bytes[start..end]` where `start > bytes.len()` and panicked
    /// with `range start index N out of range`. We now bail before
    /// the slice and `extract` returns cleanly.
    #[test]
    fn fat_header_with_out_of_range_arch_offset_does_not_panic() {
        // CAFEBABE + nfat_arch=2 + two arch entries each claiming a
        // multi-gigabyte offset/size. Mirrors junk Java `.class` files
        // misclassified as Mach-O fat via the magic check.
        let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        // arch 0: cputype=7, subtype=3, offset=0xFFFFFFF0, size=0x1000, align=12
        bytes.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x00, 0x0C,
        ]);
        // arch 1: cputype=0x0100_000C, subtype=0, offset=0x4D11ABD4, size=0x800, align=12
        bytes.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x11, 0xAB, 0xD4, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x00, 0x0C,
        ]);
        // Pad to a plausible class-file size so the body slicing path
        // still operates against bounded input.
        bytes.resize(1024, 0);

        let mut values = Values::new();
        let mut strings = crate::output::Strings::default();
        let mut metrics = Metrics::new();
        let mut sections: Vec<Section> = Vec::new();
        let mut symbols = crate::Symbols::new();
        let mut errors = crate::output::Errors::new();
        // The point of the test is non-panicking completion.
        let _ = extract(
            &bytes,
            &mut values,
            &mut strings,
            &mut metrics,
            &mut sections,
            &mut symbols,
            &mut errors,
        );
    }

    fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
        let (v, s, m, _) = run_with_symbols(bytes);
        (v, s, m)
    }

    fn run_with_symbols(bytes: &[u8]) -> (Values, Strings, Metrics, crate::Symbols) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut symbols = crate::Symbols::new();
        let mut errors = Errors::new();
        let _ = extract(
            bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut symbols,
            &mut errors,
        );
        (v, s, m, symbols)
    }

    /// Every Mach-O import offset must anchor at the symbol *name* in the
    /// `LC_SYMTAB` string table — the bytes at that offset spell the name
    /// (NUL-terminated), human-readable and consistent with ELF `.dynstr`.
    /// Regression guard for the universal-binary hex view, which rendered
    /// `__got` bind-slot pointer bytes (pure binary) before this anchor was
    /// introduced.
    #[test]
    fn import_offsets_anchor_at_name_string() {
        use crate::output::Symbol;
        let bytes = read_fixture("test.macho");
        let (_, _, _, symbols) = run_with_symbols(&bytes);

        let mut checked = 0;
        for sym in symbols.iter() {
            let Symbol::Import {
                name,
                offset: Some(off),
                ..
            } = sym
            else {
                continue;
            };
            let off = *off as usize;
            // The string-table entry is the name followed by a NUL.
            let end = off + name.len();
            assert!(
                bytes.get(off..end) == Some(name.as_bytes()) && bytes.get(end) == Some(&0u8),
                "import {name:?} offset {off:#x} should point at its NUL-terminated \
                 name in LC_SYMTAB, found {:?}",
                bytes
                    .get(off..end.min(bytes.len()))
                    .map(String::from_utf8_lossy)
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "fixture should expose at least one import with an offset"
        );
    }

    fn read_fixture(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    #[test]
    fn cpu_type_string_arm32_and_x86() {
        assert_eq!(cpu_type_string(0x0000_0007), "x86");
        assert_eq!(cpu_type_string(0x0000_000c), "arm");
        assert_eq!(cpu_type_string(0x0200_000c), "arm64_32");
    }

    #[test]
    fn file_type_string_object_and_core() {
        assert_eq!(file_type_string(0x1), "object");
        assert_eq!(file_type_string(0x4), "core");
        assert_eq!(file_type_string(0x99), "unknown");
    }

    #[test]
    fn load_command_name_known_set() {
        // LC_SEGMENT_64 = 0x19, LC_UUID = 0x1b, LC_CODE_SIGNATURE = 0x1d
        assert_eq!(load_command_name(0x19), "LC_SEGMENT_64");
        assert_eq!(load_command_name(0x1b), "LC_UUID");
        assert_eq!(load_command_name(0x1d), "LC_CODE_SIGNATURE");
    }

    #[test]
    fn empty_input_doesnt_crash() {
        let (_, _, _) = run(&[]);
    }

    #[test]
    fn non_macho_input_is_silent() {
        let (v, _, m) = run(b"\x00\x00\x00 not macho");
        assert!(v.is_empty() || v.get("macho").is_none());
        assert!(m.get("binary.is_pie").is_none());
    }

    #[test]
    fn truncated_macho_doesnt_crash() {
        // Mach-O magic but no real payload.
        let bytes = vec![0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
        let (_, _, _) = run(&bytes);
    }

    #[test]
    fn end_to_end_parses_real_macho_fixture() {
        let bytes = read_fixture("test.macho");
        let (v, _, m) = run(&bytes);
        // Flat schema: macho.{cpu_type, file_type, …} live directly
        // under the namespace.
        assert!(v.get("macho.cpu_type").is_some());
        assert!(v.get("macho.file_type").is_some());
        // PIE / stripped metrics emitted for every Mach-O.
        assert!(m.get("binary.is_pie").is_some());
        assert!(m.get("binary.is_stripped").is_some());
    }

    /// Pin the `_raw` header fields and class_bits / entry / load
    /// command size values that downstream typed consumers
    /// (`cleave::MachoMetrics`) deserialise. test.macho is an x86_64
    /// (cputype `0x01000007`) thin executable (`MH_EXECUTE = 0x2`).
    #[test]
    fn raw_header_fields_pinned() {
        let bytes = read_fixture("test.macho");
        let (v, _, _) = run(&bytes);
        assert_eq!(
            v.get("macho.cpu_type_raw").and_then(|x| x.as_u64()),
            Some(0x0100_0007),
        );
        assert_eq!(
            v.get("macho.file_type_raw").and_then(|x| x.as_u64()),
            Some(0x2),
        );
        // Flags must be non-zero for any real Mach-O — at minimum
        // MH_DYLDLINK | MH_TWOLEVEL.
        assert!(
            v.get("macho.flags_raw")
                .and_then(|x| x.as_u64())
                .is_some_and(|f| f != 0),
        );
        // class_bits is 64 for an arm64 executable.
        assert_eq!(v.get("macho.class_bits").and_then(|x| x.as_u64()), Some(64));
        // Entry point must be set on an executable (LC_MAIN.entryoff).
        assert!(v.get("macho.entry").and_then(|x| x.as_u64()).unwrap_or(0) > 0);
        // sizeofcmds is always non-zero for a valid Mach-O.
        assert!(
            v.get("macho.load_commands_size")
                .and_then(|x| x.as_u64())
                .is_some_and(|n| n > 0)
        );
    }

    /// Pin per-segment raw initprot/maxprot fields used by cleave's
    /// `MachoSegmentEntry::{initprot_hex, maxprot_hex}`.
    #[test]
    fn segment_raw_protections_emitted() {
        let bytes = read_fixture("test.macho");
        let (v, _, _) = run(&bytes);
        let segs = v
            .get("macho.segments")
            .and_then(|s| s.as_array())
            .expect("segments emitted");
        assert!(!segs.is_empty());
        // __TEXT segment has initprot r-x (5) and maxprot rwx (7) on
        // every Apple-shipped binary; the trivial test fixture matches.
        let text = segs
            .iter()
            .find(|s| s.get("name").and_then(|n| n.as_str()) == Some("__TEXT"))
            .expect("__TEXT segment present");
        assert_eq!(text.get("initprot_raw").and_then(|x| x.as_u64()), Some(5));
        assert_eq!(text.get("maxprot_raw").and_then(|x| x.as_u64()), Some(5));
    }

    /// Pin per-dylib raw current/compat versions used by cleave's
    /// typed `MachoDylibEntry`.
    #[test]
    fn load_dylibs_raw_versions_emitted() {
        let bytes = read_fixture("test.macho");
        let (v, _, _) = run(&bytes);
        let dylibs = v
            .get("macho.load_dylibs")
            .and_then(|d| d.as_array())
            .expect("load_dylibs emitted");
        assert!(!dylibs.is_empty());
        for entry in dylibs {
            assert!(entry.get("current_version_raw").is_some());
            assert!(entry.get("compatibility_version_raw").is_some());
        }
    }

    #[test]
    fn normalize_dylib_path_strips_dir_and_suffix() {
        assert_eq!(
            normalize_dylib_path("/usr/lib/libSystem.B.dylib"),
            "libsystem.b"
        );
        assert_eq!(normalize_dylib_path("libobjc.A.tbd"), "libobjc.a");
        // Bare names without prefix or suffix are lowercased.
        assert_eq!(normalize_dylib_path("Foo"), "foo");
    }

    /// Verifies the unified Symbols view is populated for Mach-O
    /// imports/exports and that library names come back normalised.
    #[test]
    fn typed_imports_and_exports_populated_for_macho() {
        let bytes = read_fixture("test.macho");
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut symbols = crate::Symbols::new();
        let mut errors = Errors::new();
        extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut symbols,
            &mut errors,
        )
        .unwrap();
        // The trivial test.macho fixture might have no exports but
        // any real binary has bind imports for libSystem.
        for sym in symbols.iter_kind(crate::SymbolKind::Import) {
            let crate::Symbol::Import { library, .. } = sym else {
                unreachable!();
            };
            let lib = library
                .as_deref()
                .expect("Mach-O bind imports carry library");
            assert_eq!(lib, &lib.to_ascii_lowercase());
            assert!(!lib.ends_with(".dylib") && !lib.ends_with(".tbd"));
        }
        for sym in symbols.iter_kind(crate::SymbolKind::Export) {
            assert!(matches!(sym, crate::Symbol::Export { .. }));
        }
    }

    #[test]
    fn mh_flag_names_decompose_canonical_set() {
        // dyld_link | two_level | pie
        let names = mh_flag_names(0x4 | 0x80 | 0x0020_0000);
        assert!(names.contains(&"dyld_link"));
        assert!(names.contains(&"two_level"));
        assert!(names.contains(&"pie"));
        // No spurious flags.
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn mh_flag_names_empty_when_zero() {
        assert!(mh_flag_names(0).is_empty());
    }
}
