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

use crate::bytes;
use crate::metric;
use crate::value_key;
use goblin::mach::{self, Mach, MachO};
use serde_json::Value as JsonValue;

use crate::formats::common::{
    NativeFormat, RizinTarget, XorScan, extract_binary_strings, extract_binary_strings_from_object,
    plist_to_json, put_str, put_u64, rizin_fallback, section_entropy,
};
use crate::formats::goblin_safe;
use crate::output::{Errors, Metrics, Section, SectionFlag, ValueKey, Values};

pub(super) fn extract(bytes: &[u8], ctx: super::ExtractCtx<'_>) {
    let super::ExtractCtx {
        values,
        strings,
        metrics,
        sections: sections_out,
        symbols: symbols_out,
        errors: errors_out,
        image_end,
        ref rizin,
        ..
    } = ctx;
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
            metrics.insert(metric!("macho.parse_failed"), 1.0);
            return;
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            extract_binary_strings(bytes, strings, XorScan::Yes);
            errors_out.record_panic(crate::Stage::MachoParse, msg);
            metrics.insert(metric!("macho.parse_panicked"), 1.0);
            return;
        }
    };
    // A fat header claiming more entries than the file can hold is not a
    // universal binary anything downstream can use, and walks that trust the
    // count (rizin; stng's walk of a parsed object) visit every claimed entry,
    // up to `u32::MAX` of them.
    let fat_table_fits = match &parsed {
        Mach::Fat(fat) => fat_table_fits(fat.narches, bytes.len()),
        Mach::Binary(_) => true,
    };
    // stng's ARM64 stack-XOR scan calls goblin's `imports()` itself, outside
    // the bind budget `extract_symbols` enforces, and a forged repeat count
    // has goblin push billions of imports there. Where a slice's bind
    // streams fail that budget, stng gets a copy with them emptied; every
    // other byte, and so every string offset, is the file's own.
    let defused = bind_defused_copy(&parsed, bytes);
    // Otherwise reuse this parse for string extraction instead of having stng
    // parse the binary a second time.
    let object = goblin::Object::Mach(parsed);
    match &defused {
        Some(copy) => extract_binary_strings(copy, strings, XorScan::Yes),
        None if fat_table_fits => {
            extract_binary_strings_from_object(&object, bytes, strings, XorScan::Yes);
        }
        None => extract_binary_strings(bytes, strings, XorScan::Yes),
    }
    let goblin::Object::Mach(parsed) = object else {
        unreachable!("constructed as Object::Mach")
    };
    // Resolve the Go attribution sections (pclntab + read-only data) from
    // the thin-binary case while the parsed Mach-O is in scope; the bytes
    // they reference outlive it. Fat binaries skip pclntab-based GoRoot
    // recovery (rare for Go) but still get build-id via the marker scan.
    // When the open asked for native-arch-only (e.g. `ascan ps`), hand rizin just the
    // host-native slice of a fat binary instead of the whole universal file —
    // the other slices will never run here and full `aaa` on each is the bulk
    // of the per-binary cost. Falls back to the whole input for thin binaries
    // or when no native slice is found.
    let mut native_rizin_range: Option<(usize, usize)> = None;
    let (go_pclntab, go_rodata) = match parsed {
        Mach::Binary(macho) => {
            single_arch(
                &macho,
                bytes,
                values,
                metrics,
                sections_out,
                symbols_out,
                errors_out,
            );
            *image_end = Some(image_end_of(&macho));
            macho_go_sections(&macho)
        }
        Mach::Fat(fat) => {
            // goblin reads the arch table lazily; walk it once, guarded.
            // Entries are contiguous, so the first unreadable one ends it.
            let arches = goblin_safe::drain_or_record(
                fat.iter_arches().take(MAX_FAT_ARCHES).map_while(Result::ok),
                errors_out,
                crate::Stage::MachoParse,
            );
            *image_end = fat_binary(
                bytes,
                &arches,
                values,
                metrics,
                sections_out,
                symbols_out,
                errors_out,
            );
            if rizin.native_arch_only {
                native_rizin_range = native_slice_range(bytes, &arches);
            }
            (None, None)
        }
    };
    let rizin_bytes = match native_rizin_range {
        Some((start, end)) => bytes.get(start..end).unwrap_or(bytes),
        None => bytes,
    };
    let has_go_pclntab = go_pclntab.is_some_and(super::go_buildinfo::has_pclntab_magic);
    if fat_table_fits {
        rizin_fallback(
            RizinTarget {
                format: NativeFormat::MachO,
                bytes: rizin_bytes,
                strings,
                go_function_metadata: has_go_pclntab,
                settings: rizin,
            },
            sections_out,
            symbols_out,
            metrics,
        );
    }
    super::upx::detect(bytes, values);
    let go_sections = super::go_buildinfo::GoSections {
        buildid_note: None,
        pclntab: go_pclntab,
        rodata: go_rodata,
    };
    super::go_buildinfo::detect(bytes, values, value_key!("macho.go"), None, &go_sections);
}

/// A segment's sections, which goblin reads lazily from the load command on
/// each call; guarded like every other post-parse walk. `None` when goblin
/// rejects or panics on the table.
fn segment_sections<'a>(
    segment: &mach::segment::Segment<'a>,
) -> Option<Vec<(mach::segment::Section, mach::segment::SectionData<'a>)>> {
    goblin_safe::catch(|| segment.sections()).ok()
}

/// Resolve the `__TEXT,__gopclntab` and read-only data (`__const`,
/// falling back to `__rodata`) section bytes used for Go attribution.
fn macho_go_sections<'a>(macho: &MachO<'a>) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
    let (mut pclntab, mut const_data, mut rodata) = (None, None, None);
    for segment in &macho.segments {
        if segment.name().unwrap_or("") != "__TEXT" {
            continue;
        }
        let Some(secs) = segment_sections(segment) else {
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

/// Whether a fat header's declared arch count fits in a file of `len` bytes.
/// A copy of `bytes` in which every slice whose bind streams
/// [`goblin_safe::validate_bind_opcodes`] rejects has its `LC_DYLD_INFO`
/// bind and lazy-bind sizes zeroed, so goblin's `imports()` finds nothing to
/// interpret there. Zero reads the same in either byte order. `None` when no
/// slice needs it.
fn bind_defused_copy(parsed: &Mach<'_>, bytes: &[u8]) -> Option<Vec<u8>> {
    use mach::load_command::CommandVariant;
    // `bind_size` and `lazy_bind_size` within a `dyld_info_command`.
    const SIZE_FIELDS: [usize; 2] = [20, 36];
    let mut patches: Vec<usize> = Vec::new();
    let mut defuse = |macho: &MachO<'_>, slice: &[u8], base: usize| {
        if goblin_safe::validate_bind_opcodes(macho, slice).is_ok() {
            return;
        }
        for lc in &macho.load_commands {
            if let CommandVariant::DyldInfo(_) | CommandVariant::DyldInfoOnly(_) = lc.command {
                patches.extend(SIZE_FIELDS.iter().map(|field| base + lc.offset + field));
            }
        }
    };
    match parsed {
        Mach::Binary(macho) => defuse(macho, bytes, 0),
        Mach::Fat(fat) => {
            let arches = goblin_safe::catch_infallible(|| {
                fat.iter_arches()
                    .take(MAX_FAT_ARCHES)
                    .map_while(Result::ok)
                    .collect::<Vec<_>>()
            })
            .ok()
            .unwrap_or_default();
            for arch in arches {
                let start = arch.offset as usize;
                let end = start.saturating_add(arch.size as usize).min(bytes.len());
                if let Some(slice) = bytes.get(start..end)
                    && let goblin_safe::GoblinOutcome::Ok(macho) =
                        goblin_safe::parse_macho_slice(slice)
                {
                    defuse(&macho, slice, start);
                }
            }
        }
    }
    if patches.is_empty() {
        return None;
    }
    let mut copy = bytes.to_vec();
    for at in patches {
        if let Some(field) = copy.get_mut(at..at.saturating_add(4)) {
            field.fill(0);
        }
    }
    Some(copy)
}

fn fat_table_fits(narches: usize, len: usize) -> bool {
    narches
        <= len.saturating_sub(goblin::mach::fat::SIZEOF_FAT_HEADER)
            / goblin::mach::fat::SIZEOF_FAT_ARCH
}

/// Most fat-header entries examined. `iter_arches` runs to the header's
/// `nfat_arch` (up to `u32::MAX`) without checking it against the buffer, and
/// each in-bounds entry costs a full slice analysis; real binaries carry a few.
const MAX_FAT_ARCHES: usize = 64;

/// Byte range of the host-native architecture slice within a fat Mach-O, used to
/// hand rizin only the slice that can run on this host (see `extract`). Matches
/// on `cputype` so `arm64` and `arm64e` (same cputype, different subtype) both
/// resolve on Apple silicon. Returns `None` for an unknown host arch or when no
/// slice matches — callers fall back to the whole input.
fn native_slice_range(bytes: &[u8], arches: &[mach::fat::FatArch]) -> Option<(usize, usize)> {
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
    for arch in arches {
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

/// Analyse every slice of a fat binary; returns the end of the last
/// slice's image in whole-file offsets (see [`image_end_of`]), or `None`
/// when no slice parsed.
fn fat_binary(
    bytes: &[u8],
    arches: &[mach::fat::FatArch],
    values: &mut Values,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
    symbols_out: &mut crate::Symbols,
    errors_out: &mut Errors,
) -> Option<u64> {
    let mut slices: Vec<JsonValue> = Vec::new();
    let mut image_end: Option<u64> = None;
    for (idx, arch) in arches.iter().enumerate() {
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
        let Some(slice_bytes) = bytes.get(start..end) else {
            continue;
        };
        // An unparseable slice is skipped; a panicking one is also recorded,
        // as a panic on the container itself would be.
        let macho = match goblin_safe::parse_macho_slice(slice_bytes) {
            goblin_safe::GoblinOutcome::Ok(macho) => macho,
            goblin_safe::GoblinOutcome::Failed(_) => continue,
            goblin_safe::GoblinOutcome::Panicked(msg) => {
                errors_out.record_panic(crate::Stage::MachoParse, msg);
                continue;
            }
        };
        let slice_end = u64::from(arch.offset).saturating_add(image_end_of(&macho));
        image_end = image_end.max(Some(slice_end));
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
        slices.push(slice_entry);
        if idx == 0 {
            let first_section = sections_out.len();
            single_arch(
                &macho,
                slice_bytes,
                values,
                metrics,
                sections_out,
                symbols_out,
                errors_out,
            );
            // Unified sections address the whole input; load-command offsets
            // address the slice. Entropy was already computed on slice bytes.
            for section in sections_out.iter_mut().skip(first_section) {
                if section.file_size > 0 {
                    section.file_offset = section.file_offset.saturating_add(start as u64);
                }
            }
        }
    }
    metrics.insert(metric!("macho.slice_count"), slices.len() as f64);
    values.insert_key(value_key!("macho.slices"), JsonValue::Array(slices));
    image_end
}

/// File offset one past the last byte the image itself accounts for:
/// the load-command area, every segment's on-disk extent (including
/// `__LINKEDIT`, which has no sections yet holds the symbol/string
/// tables, dyld info and the code signature), and the linkedit blobs and
/// relocation tables the load commands point at directly (an `MH_OBJECT`
/// has no `__LINKEDIT` segment, so its symtab sits past every segment).
/// Only bytes past this are appended payload, i.e. an overlay.
///
/// Offsets are relative to the start of this Mach-O (a fat slice's
/// start, not the fat file's). Declared extents are not clamped to the
/// input: an end past EOF simply means there is no overlay.
fn image_end_of(macho: &MachO<'_>) -> u64 {
    use goblin::mach::load_command::CommandVariant as Cmd;

    fn extent(off: u32, count: u32, entry_size: u64) -> u64 {
        if count == 0 {
            return 0;
        }
        u64::from(off).saturating_add(u64::from(count).saturating_mul(entry_size))
    }
    fn blob(off: u32, size: u32) -> u64 {
        extent(off, size, 1)
    }

    let header_size: u64 = if macho.is_64 { 32 } else { 28 };
    let nlist_size: u64 = if macho.is_64 { 16 } else { 12 };
    let mut end = header_size.saturating_add(u64::from(macho.header.sizeofcmds));
    for segment in &macho.segments {
        if segment.filesize > 0 {
            end = end.max(segment.fileoff.saturating_add(segment.filesize));
        }
        // `MH_OBJECT` relocation entries (8 bytes each) live outside
        // any segment.
        if let Some(sections) = segment_sections(segment) {
            for (section, _) in sections {
                end = end.max(extent(section.reloff, section.nreloc, 8));
            }
        }
    }
    for lc in &macho.load_commands {
        let blob_end = match &lc.command {
            Cmd::Symtab(c) => extent(c.symoff, c.nsyms, nlist_size).max(blob(c.stroff, c.strsize)),
            Cmd::Dysymtab(c) => extent(c.indirectsymoff, c.nindirectsyms, 4)
                .max(extent(c.extrefsymoff, c.nextrefsyms, 4))
                .max(extent(c.extreloff, c.nextrel, 8))
                .max(extent(c.locreloff, c.nlocrel, 8)),
            Cmd::DyldInfo(c) | Cmd::DyldInfoOnly(c) => blob(c.rebase_off, c.rebase_size)
                .max(blob(c.bind_off, c.bind_size))
                .max(blob(c.weak_bind_off, c.weak_bind_size))
                .max(blob(c.lazy_bind_off, c.lazy_bind_size))
                .max(blob(c.export_off, c.export_size)),
            Cmd::CodeSignature(c)
            | Cmd::SegmentSplitInfo(c)
            | Cmd::FunctionStarts(c)
            | Cmd::DataInCode(c)
            | Cmd::DylibCodeSignDrs(c)
            | Cmd::LinkerOptimizationHint(c)
            | Cmd::DyldExportsTrie(c)
            | Cmd::DyldChainedFixups(c) => blob(c.dataoff, c.datasize),
            // LC_LINKER_OPTION shares goblin's LinkeditDataCommand shape
            // but its payload is inline in the command, not in linkedit.
            _ => 0,
        };
        end = end.max(blob_end);
    }
    end
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
    extract_symbols(
        macho,
        slice_bytes,
        &mut throwaway_symbols,
        &mut Errors::new(),
    );
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
    errors_out: &mut Errors,
) {
    extract_sections(macho, bytes, metrics, sections_out);
    extract_header_and_loads(macho, bytes, values, metrics);
    extract_symbols(macho, bytes, symbols_out, errors_out);
    super::macho_hashes::emit(macho, values, symbols_out);
    super::build_toolchain::from_macho(values, sections_out);
}

/// Walk Mach-O's dyld bind-info (imports) and export trie (exports)
/// and surface them as typed `Imports`/`Exports` entries.
///
/// Two source tags distinguish how the entry was discovered:
/// `macho-bind` for two-level-namespace bind imports (carrying the
/// resolving dylib stem), `macho-trie` for exports recovered from
/// the dyld export trie. A bind stream or export trie refused as hostile
/// yields no entries and is recorded in `errors`.
fn extract_symbols(
    macho: &MachO<'_>,
    bytes: &[u8],
    symbols_out: &mut crate::Symbols,
    errors: &mut Errors,
) {
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
    let mut bind_imports = 0usize;
    // `imports()` walks dyld bind opcodes lazily, after `parse_mach` has
    // already returned, so the parse-time guard does not cover it. goblin
    // 0.10.7 indexes the libs table with an unchecked ordinal
    // (mach/imports.rs:103) and panics on a malformed one. LLVM's test corpus
    // is full of deliberately malformed Mach-O, and a panic on a rayon worker
    // took down the whole scan of llvm-toolchain-17 (142MB) with SIGSEGV.
    // A panic here yields no imports and is recorded in `errors`.
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
    // have no bind opcodes at all, so that call returns an empty list and the
    // binary appeared to import nothing -- which is every current macOS build,
    // malware included. A stealer whose only libc import is `system` looked
    // identical to a binary with no imports whatsoever, and every `type:
    // import` trait was blind to it.
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
    // (e.g. `libSystem` forwarding to `libdyld`) come through as
    // regular `Export` entries; we surface only the name here, with
    // forwarded-target handling left to a follow-up.
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

    // goblin resolves each name through a file-controlled `n_strx` as the
    // walk advances; an unwalkable table leaves only the bind-slot offsets.
    let symbols = goblin_safe::drain(macho.symbols()).ok().unwrap_or_default();
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
        let Some(secs) = segment_sections(segment) else {
            continue;
        };
        for (section, _data) in secs {
            let section_name = section.name().unwrap_or("").to_owned();
            let display = if section_name.is_empty() {
                segment_name.clone()
            } else {
                format!("{segment_name},{section_name}")
            };
            let zero_filled = matches!(
                section.flags & mach::constants::SECTION_TYPE,
                mach::constants::S_ZEROFILL
                    | mach::constants::S_GB_ZEROFILL
                    | mach::constants::S_THREAD_LOCAL_ZEROFILL
            );
            let file_offset = if zero_filled {
                0
            } else {
                u64::from(section.offset)
            };
            let file_size = if zero_filled { 0 } else { section.size };
            let entropy = (file_size > 0).then(|| section_entropy(bytes, file_offset, file_size));
            // __TEXT also holds constants and unwind metadata. Segment execute
            // permission must not make those bytes count as instruction code.
            let contains_instructions = section.flags
                & (mach::constants::S_ATTR_PURE_INSTRUCTIONS
                    | mach::constants::S_ATTR_SOME_INSTRUCTIONS)
                != 0
                || section.flags & mach::constants::SECTION_TYPE == mach::constants::S_SYMBOL_STUBS;
            let section_flags = flags
                .iter()
                .copied()
                .chain(std::iter::once(if contains_instructions {
                    SectionFlag::Code
                } else {
                    SectionFlag::Data
                }))
                .collect();
            sections_out.push(Section {
                name: display,
                vaddr: section.addr,
                vsize: section.size,
                file_offset,
                file_size,
                flags: section_flags,
                flags_raw: Some(initprot),
                entropy,
            });
        }
    }
}

fn macho_segment_flags(initprot: u32) -> Vec<SectionFlag> {
    // VM_PROT_READ = 1, VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4.
    [
        (1, SectionFlag::Readable),
        (2, SectionFlag::Writable),
        (4, SectionFlag::Executable),
    ]
    .into_iter()
    .filter_map(|(bit, flag)| (initprot & bit != 0).then_some(flag))
    .collect()
}

fn extract_header_and_loads(
    macho: &MachO<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    put_str(
        values,
        value_key!("macho.cpu_type"),
        cpu_kind_string(macho.header.cputype(), macho.header.cpusubtype()),
    );
    // Raw CPU type / file type / flags. The string-decoded fields above
    // are for trait authors; consumers that need to round-trip the
    // u32 (cleave's typed metrics keep the raw header values) read
    // these `_raw` siblings.
    put_u64(
        values,
        value_key!("macho.cpu_type_raw"),
        u64::from(macho.header.cputype()),
    );
    put_u64(
        values,
        value_key!("macho.cpu_subtype"),
        u64::from(macho.header.cpusubtype()),
    );
    put_str(
        values,
        value_key!("macho.file_type"),
        file_type_string(macho.header.filetype),
    );
    put_u64(
        values,
        value_key!("macho.file_type_raw"),
        u64::from(macho.header.filetype),
    );
    // Pike-style decomposed flag array — matches `pe.dll_characteristics[]`
    // / `lnk.header.flags[]` schema rather than emitting a raw bitfield
    // that traits would have to mask themselves.
    let mh_flags = mh_flag_names(macho.header.flags);
    if !mh_flags.is_empty() {
        values.insert_key(
            value_key!("macho.flags"),
            JsonValue::Array(
                mh_flags
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
    // Raw flags bitfield (typed consumers need the unmasked u32).
    put_u64(
        values,
        value_key!("macho.flags_raw"),
        u64::from(macho.header.flags),
    );
    put_str(
        values,
        value_key!("macho.endian"),
        if macho.little_endian { "little" } else { "big" },
    );
    // 32-bit vs 64-bit. Trait authors read `macho.class_bits == 64`;
    // typed consumers (`MachoMetrics::class_bits`) take the same u64.
    put_u64(
        values,
        value_key!("macho.class_bits"),
        if macho.is_64 { 64 } else { 32 },
    );
    // Entry point address — Mach-O's `entry` (LC_MAIN.entryoff) or
    // legacy LC_UNIXTHREAD thread-state PC. `old_style_entry` is set
    // when the entry came from LC_UNIXTHREAD.
    put_u64(values, value_key!("macho.entry"), macho.entry);
    if macho.old_style_entry {
        metrics.insert(metric!("macho.old_style_entry"), 1.0);
    }
    // Raw header counts: number of load commands and their cumulative
    // byte size. `macho.load_command_count` already exists as a
    // metric; `macho.load_commands_size` is new.
    put_u64(
        values,
        value_key!("macho.load_commands_size"),
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
    metrics.insert(metric!("dependencies.count"), libs.len() as f64);
    values.insert_key(value_key!("macho.libraries"), JsonValue::Array(libs));

    let rpaths: Vec<JsonValue> = macho
        .rpaths
        .iter()
        .map(|s| JsonValue::String((*s).to_string()))
        .collect();
    if !rpaths.is_empty() {
        values.insert_key(value_key!("macho.rpaths"), JsonValue::Array(rpaths));
    }

    // Load commands are the most useful structural fingerprint of a
    // Mach-O. Emit their `cmd` (LC_*) names in order.
    let lcs: Vec<JsonValue> = macho
        .load_commands
        .iter()
        .map(|lc| JsonValue::String(load_command_name(lc.command.cmd()).to_string()))
        .collect();
    metrics.insert(metric!("macho.load_command_count"), lcs.len() as f64);
    values.insert_key(value_key!("macho.load_commands"), JsonValue::Array(lcs));

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
        put_u64(
            values,
            value_key!("macho.code_signature_size"),
            u64::from(cs.datasize),
        );
        metrics.insert(metric!("macho.code_signature_size"), f64::from(cs.datasize));
        // The blob's file offset — consumers anchor the code-signature
        // finding's evidence here rather than at the header.
        put_u64(
            values,
            value_key!("macho.code_signature_offset"),
            u64::from(cs.dataoff),
        );
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
        put_str(values, value_key!("macho.uuid"), format_macho_uuid(&uuid));
        // Anchor the value at the 16 UUID bytes (past the 8-byte cmd/cmdsize
        // header), so a `value` match on `macho.uuid` renders in the hex view.
        put_u64(
            values,
            value_key!("macho.uuid_offset"),
            (lc_offset + 8) as u64,
        );
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
    let mut exec_segment_count: u64 = 0;
    let mut wx_segments: Vec<JsonValue> = Vec::new();
    let mut text_writable = false;
    let mut pagezero_size: u64 = 0;
    let mut entry_in_writable = false;
    let mut entry_in_segment = false;
    let mut entry_section: Option<String> = None;
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
        if executable {
            exec_segment_count += 1;
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
                // Resolve the entry to the section holding it, so a
                // redirected entry in a grafted section (`__evil`,
                // `.attack`) is nameable — the Mach-O analogue of ELF's
                // entry_section / entry_in_nonstandard_section.
                if entry_section.is_none()
                    && let Some(secs) = segment_sections(segment)
                {
                    for (section, _data) in secs {
                        let s_addr = section.addr;
                        let s_end = s_addr.saturating_add(section.size);
                        if section.size > 0 && entry >= s_addr && entry < s_end {
                            entry_section = Some(section.name().unwrap_or("").to_string());
                            break;
                        }
                    }
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
    metrics.insert(metric!("macho.wx_segment_count"), wx_count as f64);
    metrics.insert(
        metric!("macho.executable_segment_count"),
        exec_segment_count as f64,
    );
    if !wx_segments.is_empty() {
        values.insert_key(
            value_key!("macho.wx_segments"),
            JsonValue::Array(wx_segments),
        );
    }
    if let Some(name) = entry_section {
        // Entry belongs in __text; an entry resolving into a section
        // outside the toolchain set is the redirection tell.
        if !crate::is_well_known_section_name(&name) {
            metrics.insert(metric!("macho.entry_in_nonstandard_section"), 1.0);
        }
        put_str(values, value_key!("macho.entry_section"), &name);
    }
    if text_writable {
        metrics.insert(metric!("macho.text_segment_writable"), 1.0);
    }
    if pagezero_size != 0 {
        metrics.insert(metric!("macho.pagezero_size"), pagezero_size as f64);
    }
    if entry_in_writable {
        metrics.insert(metric!("macho.entry_in_writable_segment"), 1.0);
    }
    if entry != 0 && !entry_in_segment {
        metrics.insert(metric!("macho.entry_outside_segments"), 1.0);
    }
    if has_data_const {
        metrics.insert(metric!("macho.has_data_const_segment"), 1.0);
    }
    if !segments_out.is_empty() {
        values.insert_key(value_key!("macho.segments"), JsonValue::Array(segments_out));
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
        metrics.insert(metric!("macho.has_chained_fixups"), 1.0);
    }
    if has_legacy_dyld_info {
        metrics.insert(metric!("macho.has_dyld_info_legacy"), 1.0);
    }
    if has_encrypted {
        metrics.insert(metric!("macho.has_encrypted_section"), 1.0);
    }
    if uses_legacy_version_min {
        metrics.insert(metric!("macho.uses_legacy_version_min"), 1.0);
    }
    if data_in_code_count > 0 {
        metrics.insert(
            metric!("macho.data_in_code_count"),
            f64::from(data_in_code_count),
        );
    }
    if has_main_command {
        metrics.insert(metric!("macho.has_main_command"), 1.0);
    }
    if has_unixthread_command {
        metrics.insert(metric!("macho.has_unixthread_command"), 1.0);
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
    let Some(data) = bytes.get(start..end) else {
        return;
    };
    // One ULEB128 delta per function. Zero is the stream terminator and
    // signals end-of-table (any padding bytes after it are ignored); a
    // truncated or over-long delta ends the table too.
    let mut count: u64 = 0;
    let mut i = 0usize;
    while super::common::read_uleb128(data, &mut i).is_some_and(|delta| delta != 0) {
        count += 1;
    }
    metrics.insert(metric!("macho.function_starts_count"), count as f64);
    put_u64(values, value_key!("macho.function_starts_count"), count);
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
    for &[.., k0, k1] in bytes.get(start..end).unwrap_or_default().as_chunks::<8>().0 {
        let kind = if little_endian {
            u16::from_le_bytes([k0, k1])
        } else {
            u16::from_be_bytes([k0, k1])
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
        values.insert_key(
            value_key!("macho.data_in_code_kinds"),
            JsonValue::Object(kinds),
        );
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
    let read_u32 = u32_reader(macho);
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
        let Some(count) = read_u32(bytes, cmd_offset.saturating_add(8)) else {
            continue;
        };
        let count = count as usize;
        let Some(body) = bytes.get(body_start..body_end) else {
            continue;
        };
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
        values.insert_key(value_key!("macho.linker_options"), JsonValue::Array(all));
    }
}

/// `__OBJC,__image_info` / `__DATA,__objc_imageinfo` — 8-byte
/// section: `(version: u32, flags: u32)`. The Swift ABI version
/// lives in `flags[15:8]`; presence alone signals the binary
/// links the Objective-C runtime.
fn objc_image_info(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    for segment in &macho.segments {
        let Some(sections) = segment_sections(segment) else {
            continue;
        };
        for (section, _data) in sections {
            let name = section.name().unwrap_or("");
            if name != "__image_info" && name != "__objc_imageinfo" {
                continue;
            }
            let off = section.offset as usize;
            let len = usize::try_from(section.size).unwrap_or(usize::MAX);
            let end = off.saturating_add(len).min(bytes.len());
            if end < off + 8 {
                return;
            }
            let read_u32 = u32_reader(macho);
            // `flags` follows the unused `version` word.
            let Some(flags) = read_u32(bytes, off + 4) else {
                return;
            };
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
            values.insert_key(value_key!("macho.objc"), JsonValue::Object(obj));
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
        let Some(sections) = segment_sections(segment) else {
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
        values.insert_key(
            value_key!("macho.swift_sections"),
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
        values.insert_key(value_key!("macho.load_dylibs"), JsonValue::Array(entries));
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
            let read_u32 = u32_reader(macho);
            let tools: Vec<JsonValue> = bytes
                .get(tools_start..tools_end)
                .unwrap_or_default()
                .as_chunks::<8>()
                .0
                .iter()
                .filter_map(|c| {
                    let tool = read_u32(c, 0)?;
                    let version = read_u32(c, 4)?;
                    let mut entry = serde_json::Map::new();
                    entry.insert(
                        "tool".into(),
                        JsonValue::String(build_tool_name(tool).to_string()),
                    );
                    entry.insert(
                        "version".into(),
                        JsonValue::String(decode_version_nibbles(version)),
                    );
                    Some(JsonValue::Object(entry))
                })
                .collect();
            if !tools.is_empty() {
                obj.insert("tools".into(), JsonValue::Array(tools));
            }
        }
    }
    values.insert_key(value_key!("macho.build_version"), JsonValue::Object(obj));
}

/// The `crate::bytes` reader for a `u32` in `macho`'s byte order.
fn u32_reader(macho: &MachO<'_>) -> fn(&[u8], usize) -> Option<u32> {
    if macho.little_endian {
        bytes::u32_le
    } else {
        bytes::u32_be
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
        value_key!("macho.source_version"),
        format!("{a}.{b}.{c}.{d}.{e}"),
    );
}

/// `LC_ID_DYLIB` — the dylib's own install name (only present on
/// shared libraries / frameworks). Always the first dylib command;
/// downstream `LC_LOAD_DYLIB`s reference other libraries.
fn install_name(macho: &MachO<'_>, values: &mut Values) {
    if !macho
        .load_commands
        .iter()
        .any(|lc| matches!(lc.command, mach::load_command::CommandVariant::IdDylib(_)))
    {
        return;
    }
    // The Dylib `name` is an offset into the command bytes; goblin
    // surfaces every dylib path through `macho.libs`, with the
    // ID_DYLIB slot at index 0 (or "self" for non-dylibs). For the
    // install-name field we want the resolved string — pull it from
    // `libs[0]` when the binary is a dylib and the slot isn't `self`.
    if let Some(name) = macho.libs.first().copied() {
        if !name.is_empty() && name != "self" {
            put_str(values, value_key!("macho.install_name"), name);
            put_str(
                values,
                value_key!("macho.install_name_kind"),
                install_name_kind(name),
            );
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
    let tail = bytes.get(start..).unwrap_or_default();
    let name = tail.split(|&b| b == 0).next().unwrap_or(tail);
    if let Ok(s) = std::str::from_utf8(name) {
        if !s.is_empty() {
            put_str(values, value_key!("macho.dyld_path"), s);
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
    metrics.insert(metric!("binary.is_pie"), f64::from(u8::from(is_pie)));

    // A declared empty LC_SYMTAB supplies no full-table symbols. This
    // observes table state and does not establish a removal operation.
    let nsyms = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::Symtab(st) => Some(st.nsyms),
        _ => None,
    });
    let is_stripped = nsyms.is_some_and(|n| n == 0);
    metrics.insert(
        metric!("binary.full_symbol_table_absent_or_empty"),
        f64::from(u8::from(is_stripped)),
    );
    // Legacy field retains its existing zero-table semantics.
    metrics.insert(
        metric!("binary.is_stripped"),
        f64::from(u8::from(is_stripped)),
    );
}

fn info_plist_section(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    // Both sections live under `__TEXT` and store a serialized plist
    // dictionary (XML or binary). `__info_plist` carries the CFBundle
    // metadata; `__launchd_plist` carries the launchd job spec for
    // self-installing daemons (`ProgramArguments`, `KeepAlive`,
    // `RunAtLoad`, …). Surfaced under sibling subtrees so trait
    // authors can read both with the same shape.
    for (section_name, key) in [
        ("__info_plist", value_key!("macho.info_plist")),
        ("__launchd_plist", value_key!("macho.launchd_plist")),
    ] {
        emit_embedded_plist(macho, bytes, values, section_name, key);
    }
}

/// Upper bound on the bytes we hand to `plist_guard::parse` for
/// `__info_plist` / `__launchd_plist` sections. Real binaries carry at
/// most a few hundred KiB; capping prevents an oversized embedded
/// plist from forcing megabytes of attacker XML through the parser.
const MAX_EMBEDDED_PLIST_BYTES: usize = 8 << 20;

fn emit_embedded_plist(
    macho: &MachO<'_>,
    bytes: &[u8],
    values: &mut Values,
    section_name: &str,
    key: ValueKey,
) {
    for segment in &macho.segments {
        let Some(sections) = segment_sections(segment) else {
            continue;
        };
        for (section, _data) in sections {
            if section.name().unwrap_or("") != section_name {
                continue;
            }
            let off = section.offset as usize;
            // `size` is a u64 from the file: don't let a 32-bit host truncate
            // it into a plausible length.
            let Ok(len) = usize::try_from(section.size) else {
                return;
            };
            let end = off.saturating_add(len);
            if off >= bytes.len() || end > bytes.len() || len == 0 {
                return;
            }
            if len > MAX_EMBEDDED_PLIST_BYTES {
                return;
            }
            let Some(plist_bytes) = bytes.get(off..end) else {
                return;
            };
            if let Ok(parsed) = super::plist_guard::parse(plist_bytes) {
                values.insert_key(key, plist_to_json(parsed, 0));
            }
            return;
        }
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
    // Match the masked 24-bit value: narrowing it to a byte would alias a
    // subtype like 0x102 onto 2 (arm64e).
    let sub = cpu_subtype & 0x00ff_ffff;
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
mod tests;
