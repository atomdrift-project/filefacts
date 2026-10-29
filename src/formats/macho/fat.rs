//! FAT (universal) Mach-O: per-slice analysis into `macho.slices[]`, with the
//! first slice that parses also reported at the top level.

use goblin::mach::{MachO, fat::FatArch};
use serde_json::Value as JsonValue;

use super::{extract_header_and_loads, extract_sections, go_build_info, symbols};
use super::{image_end_of, single_arch};
use crate::formats::goblin_safe;
use crate::metric;
use crate::output::{Errors, Metrics, Section, SymbolKind, Values};
use crate::{Stage, Symbols, value_key};

/// Most fat-header entries examined. `iter_arches` runs to the header's
/// `nfat_arch` (up to `u32::MAX`) without checking it against the buffer, and
/// each in-bounds entry costs a full slice analysis; real binaries carry a few.
pub(super) const MAX_ARCHES: usize = 64;

/// Whether a fat header's declared arch count fits in a file of `len` bytes.
pub(super) fn table_fits(narches: usize, len: usize) -> bool {
    narches
        <= len.saturating_sub(goblin::mach::fat::SIZEOF_FAT_HEADER)
            / goblin::mach::fat::SIZEOF_FAT_ARCH
}

/// Byte range of the host-native architecture slice within a fat Mach-O, used to
/// hand rizin only the slice that can run on this host. Matches on `cputype` so
/// `arm64` and `arm64e` (same cputype, different subtype) both resolve on Apple
/// silicon. Returns `None` for an unknown host arch or when no slice matches —
/// callers fall back to the whole input.
pub(super) fn native_slice_range(bytes: &[u8], arches: &[FatArch]) -> Option<(usize, usize)> {
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

/// What the top level needs from a fat binary's analysis.
pub(super) struct Analysed {
    /// The end of the furthest slice's image in whole-file offsets (see
    /// [`image_end_of`]); `None` when no slice parsed.
    pub(super) image_end: Option<u64>,
    /// Whether the primary slice carries a real Go pclntab.
    pub(super) has_go_pclntab: bool,
}

/// Analyse each slice of a fat binary once. Every slice gets the same
/// extraction as a single-arch binary, recorded as its entry of
/// `macho.slices[]` with its `file_offset` and `file_size` in the fat file.
/// The first slice that parses is the primary: its extraction also fills the
/// top-level values, metrics, sections and symbols, and its `macho.*`
/// subtree is its slice entry. What any slice's extraction records in
/// `errors` is kept.
pub(super) fn analyse(
    bytes: &[u8],
    arches: &[FatArch],
    values: &mut Values,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
    symbols_out: &mut Symbols,
    errors_out: &mut Errors,
) -> Analysed {
    let mut slices: Vec<JsonValue> = Vec::new();
    let mut out = Analysed {
        image_end: None,
        has_go_pclntab: false,
    };
    let mut primary_seen = false;
    // Slices of a real universal binary are disjoint. Each slice gets a full
    // analysis (code-page hashing, plists, symbols), and nothing else stops
    // every arch entry naming the same whole-file slice, multiplying that
    // work by `MAX_ARCHES`; a slice overlapping one already analysed is
    // skipped, so together they cost one pass over the file.
    let mut analysed: Vec<std::ops::Range<usize>> = Vec::new();
    for (idx, arch) in arches.iter().enumerate() {
        // `arch.offset` and `arch.size` come from the fat header — on
        // a misclassified CAFEBABE input (Java `.class` mistaken for
        // Mach-O fat) they are random bytes and routinely overflow
        // the file. Validate the start before slicing; `.min(end)`
        // alone only clamps the upper bound.
        let start = arch.offset as usize;
        if start >= bytes.len() {
            errors_out.record_malformed(
                Stage::MachoParse,
                format!("fat slice {idx} starts at {start}, past the end of the file"),
            );
            continue;
        }
        let end = start.saturating_add(arch.size as usize).min(bytes.len());
        let Some(slice_bytes) = bytes.get(start..end) else {
            continue;
        };
        if analysed.iter().any(|r| r.start < end && start < r.end) {
            errors_out.record_malformed(
                Stage::MachoParse,
                format!("fat slice {idx} overlaps the slices before it"),
            );
            continue;
        }
        analysed.push(start..end);
        let macho = match goblin_safe::parse_macho_slice(slice_bytes) {
            goblin_safe::GoblinOutcome::Ok(macho) => macho,
            goblin_safe::GoblinOutcome::Failed(e) => {
                errors_out.record_malformed(
                    Stage::MachoParse,
                    format!("fat slice {idx} does not parse: {e}"),
                );
                continue;
            }
            goblin_safe::GoblinOutcome::Panicked(msg) => {
                errors_out.record_panic(Stage::MachoParse, msg);
                continue;
            }
        };
        let slice_end = u64::from(arch.offset).saturating_add(image_end_of(&macho));
        out.image_end = out.image_end.max(Some(slice_end));
        let mut entry = if primary_seen {
            analyse_slice(&macho, slice_bytes, errors_out)
        } else {
            primary_seen = true;
            let (first_section, imports, exports) = (
                sections_out.len(),
                symbols_out.iter_kind(SymbolKind::Import).count(),
                symbols_out.iter_kind(SymbolKind::Export).count(),
            );
            single_arch(
                &macho,
                slice_bytes,
                values,
                metrics,
                sections_out,
                symbols_out,
                errors_out,
            );
            // Taken before Go decoding adds `macho.go`, which no slice entry
            // carries.
            let entry = slice_entry(
                values.get("macho").cloned(),
                symbols_out.iter_kind(SymbolKind::Import).count() - imports,
                symbols_out.iter_kind(SymbolKind::Export).count() - exports,
                sections_out.len() - first_section,
            );
            out.has_go_pclntab = go_build_info(&macho, slice_bytes, values);
            // Unified sections address the whole input; load-command offsets
            // address the slice. Entropy was already computed on slice bytes.
            for section in sections_out.iter_mut().skip(first_section) {
                if section.file_size > 0 {
                    section.file_offset = section.file_offset.saturating_add(start as u64);
                }
            }
            entry
        };
        if let JsonValue::Object(ref mut obj) = entry {
            obj.insert("file_offset".into(), JsonValue::Number(arch.offset.into()));
            obj.insert("file_size".into(), JsonValue::Number(arch.size.into()));
        }
        slices.push(entry);
    }
    metrics.insert(metric!("macho.slice_count"), slices.len() as f64);
    values.insert_key(value_key!("macho.slices"), JsonValue::Array(slices));
    out
}

/// Run the single-arch extraction on a non-primary slice into outputs of its
/// own, and return its `macho.*` subtree as the slice's entry. The slice's
/// metrics, sections and symbols are counted into the entry and otherwise
/// dropped: the top-level views describe the primary slice.
fn analyse_slice(macho: &MachO<'_>, slice_bytes: &[u8], errors: &mut Errors) -> JsonValue {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut slice_symbols = Symbols::new();
    extract_sections(macho, slice_bytes, &mut sections);
    extract_header_and_loads(macho, slice_bytes, &mut values, &mut metrics);
    symbols::extract(macho, slice_bytes, &mut slice_symbols, errors);
    super::hashes::emit(macho, slice_bytes, &mut values, &slice_symbols);
    slice_entry(
        values.into_json().get_mut("macho").map(JsonValue::take),
        slice_symbols.iter_kind(SymbolKind::Import).count(),
        slice_symbols.iter_kind(SymbolKind::Export).count(),
        sections.len(),
    )
}

/// A slice's `macho.*` subtree with its unified-view counts added, mirroring
/// `imports.count` / `exports.count` / `sections.count` at the top level.
fn slice_entry(
    macho: Option<JsonValue>,
    import_count: usize,
    export_count: usize,
    section_count: usize,
) -> JsonValue {
    let mut entry = match macho {
        Some(JsonValue::Object(entry)) => entry,
        _ => serde_json::Map::new(),
    };
    for (key, count) in [
        ("import_count", import_count),
        ("export_count", export_count),
        ("section_count", section_count),
    ] {
        entry.insert(key.into(), JsonValue::from(count));
    }
    JsonValue::Object(entry)
}
