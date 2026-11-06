//! FAT (universal) Mach-O: per-slice analysis into `macho.slices[]`, with the
//! preferred slice that parses (x86-64, else arm64, else one binform
//! decodes, else the first) also reported at the top level.

use goblin::mach::{MachO, fat::FatArch};
use serde_json::Value as JsonValue;

use super::{Views, go_build_info, image_end_of, sections_of, single_arch};
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

/// What the top level needs from a fat binary's analysis.
pub(super) struct Analysed {
    /// The end of the furthest slice's image in whole-file offsets (see
    /// [`image_end_of`]); `None` when no slice parsed.
    pub(super) image_end: Option<u64>,
    /// Where the primary slice starts in the file; `None` when no slice
    /// parsed.
    pub(super) primary: Option<u64>,
}

/// Analyse each slice of a fat binary once. Every slice gets the same
/// extraction as a single-arch binary, recorded as its entry of
/// `macho.slices[]` with its `file_offset` and `file_size` in the fat file.
/// Of the slices that parse, the primary is the one [`preference`] ranks
/// first: its extraction also fills the top-level values, metrics, sections
/// and symbols, its `macho.*` subtree is its slice entry, and functions are
/// recovered from it. What any slice's extraction records in `errors` is
/// kept.
pub(super) fn analyse(
    bytes: &[u8],
    arches: &[FatArch],
    layouts: &[Layout<'_>],
    out: &mut Views<'_>,
) -> Analysed {
    let errors_out = &mut *out.errors;
    let mut slices: Vec<JsonValue> = Vec::new();
    let mut analysed_out = Analysed {
        image_end: None,
        primary: None,
    };
    let mut images = Vec::new();
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
            goblin_safe::GoblinOutcome::Ok(macho) => {
                // goblin read the slice, so binform failing to is news.
                if let Some((_, Err(error))) =
                    layouts.iter().find(|(at, _)| *at == u64::from(arch.offset))
                {
                    errors_out.record_malformed(Stage::MachoParse, error.clone());
                }
                macho
            }
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
        images.push((arch, start, slice_bytes, macho));
    }
    let primary = images
        .iter()
        .enumerate()
        .min_by_key(|(_, (arch, ..))| preference(layout_at(layouts, u64::from(arch.offset))))
        .map_or(0, |(i, _)| i);
    for (i, (arch, start, slice_bytes, macho)) in images.into_iter().enumerate() {
        let layout = layout_at(layouts, u64::from(arch.offset));
        let sections = sections_of(&macho);
        let slice_end = u64::from(arch.offset).saturating_add(image_end_of(&macho, &sections));
        analysed_out.image_end = analysed_out.image_end.max(Some(slice_end));
        let mut entry = if i == primary {
            analysed_out.primary = Some(u64::from(arch.offset));
            let (first_section, imports, exports) = (
                out.sections.len(),
                out.symbols.iter_kind(SymbolKind::Import).count(),
                out.symbols.iter_kind(SymbolKind::Export).count(),
            );
            single_arch(&macho, &sections, layout, slice_bytes, out);
            // Taken before Go decoding adds `macho.go`, which no slice entry
            // carries.
            let entry = slice_entry(
                out.values.get("macho").cloned(),
                out.symbols.iter_kind(SymbolKind::Import).count() - imports,
                out.symbols.iter_kind(SymbolKind::Export).count() - exports,
                out.sections.len() - first_section,
            );
            go_build_info(&macho, &sections, slice_bytes, out.values, out.symbols);
            // Unified sections address the whole input; load-command offsets
            // address the slice. Entropy was already computed on slice bytes.
            for section in out.sections.iter_mut().skip(first_section) {
                if section.file_size > 0 {
                    section.file_offset = section.file_offset.saturating_add(start as u64);
                }
            }
            entry
        } else {
            analyse_slice(&macho, &sections, layout, slice_bytes, out.errors)
        };
        if let JsonValue::Object(ref mut obj) = entry {
            obj.insert("file_offset".into(), JsonValue::Number(arch.offset.into()));
            obj.insert("file_size".into(), JsonValue::Number(arch.size.into()));
        }
        slices.push(entry);
    }
    out.metrics
        .insert(metric!("macho.slice_count"), slices.len() as f64);
    out.values
        .insert_key(value_key!("macho.slices"), JsonValue::Array(slices));
    analysed_out
}

/// How strongly a slice is preferred as the primary, by the instruction set
/// binform read in it (`layout`), lowest first: the one a 64-bit x86 host
/// runs, else Apple silicon's, else another binform decodes, else any. The
/// order binform itself reads a universal binary in; ties go to header
/// order. A slice binform decodes yields functions, so the top-level views
/// describe the image they come from.
fn preference(layout: Option<&binform::Binary<'_>>) -> u8 {
    match layout.and_then(|layout| layout.arch()) {
        Some(binform::Arch::X86_64) => 0,
        Some(binform::Arch::Arm64) => 1,
        Some(_) => 2,
        None => 3,
    }
}

/// Run the single-arch extraction on a non-primary slice into outputs of its
/// own, and return its `macho.*` subtree as the slice's entry. The slice's
/// metrics, sections and symbols are counted into the entry and otherwise
/// dropped: the top-level views describe the primary slice.
fn analyse_slice(
    macho: &MachO<'_>,
    macho_sections: &[super::MachSection<'_>],
    layout: Option<&binform::Binary<'_>>,
    slice_bytes: &[u8],
    errors: &mut Errors,
) -> JsonValue {
    let mut values = Values::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut slice_symbols = Symbols::new();
    single_arch(
        macho,
        macho_sections,
        layout,
        slice_bytes,
        &mut Views {
            values: &mut values,
            metrics: &mut Metrics::new(),
            sections: &mut sections,
            symbols: &mut slice_symbols,
            errors,
        },
    );
    slice_entry(
        values.into_json().get_mut("macho").map(JsonValue::take),
        slice_symbols.iter_kind(SymbolKind::Import).count(),
        slice_symbols.iter_kind(SymbolKind::Export).count(),
        sections.len(),
    )
}

/// binform's layout of each slice [`analyse`] will visit, by the slice's file
/// offset, read once for every pass over it. The slices it skips (one
/// starting past the end of the file, or overlapping one before it) are
/// skipped here too, without a record: `analyse` records them.
pub(super) fn layouts<'a>(bytes: &'a [u8], arches: &[FatArch]) -> Vec<Layout<'a>> {
    let mut seen: Vec<std::ops::Range<usize>> = Vec::new();
    let mut layouts = Vec::new();
    for arch in arches {
        let start = arch.offset as usize;
        let end = start.saturating_add(arch.size as usize).min(bytes.len());
        let Some(slice) = bytes.get(start..end).filter(|_| start < bytes.len()) else {
            continue;
        };
        if seen.iter().any(|r| r.start < end && start < r.end) {
            continue;
        }
        seen.push(start..end);
        // `analyse` takes only slices that are Mach-O images; a universal
        // static library's slices are `ar` archives, no error of the file's.
        let image = matches!(
            slice.get(..4),
            Some([0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe])
        );
        if !image {
            continue;
        }
        layouts.push((
            u64::from(arch.offset),
            super::super::common::read_layout(slice),
        ));
    }
    layouts
}

/// binform's reading of the image at a file offset: its layout, or why it
/// has none. [`analyse`] records the reason only for a slice goblin reads,
/// since goblin's own reason says the same.
pub(super) type Layout<'a> = (u64, Result<binform::Binary<'a>, String>);

/// The layouts read, each with its image's file offset.
pub(super) fn read<'l, 'a>(
    layouts: &'l [Layout<'a>],
) -> impl Iterator<Item = (u64, &'l binform::Binary<'a>)> {
    layouts
        .iter()
        .filter_map(|(at, read)| Some((*at, read.as_ref().ok()?)))
}

/// The layout read from the image at file offset `offset`.
pub(super) fn layout_at<'l, 'a>(
    layouts: &'l [Layout<'a>],
    offset: u64,
) -> Option<&'l binform::Binary<'a>> {
    read(layouts)
        .find(|(at, _)| *at == offset)
        .map(|(_, layout)| layout)
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
