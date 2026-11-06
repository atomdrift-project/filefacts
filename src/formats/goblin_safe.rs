//! Panic-safe wrappers around the [`goblin`] crate's binary parsers.
//!
//! goblin parses the format-specific metadata of PE, ELF and Mach-O images
//! (headers, load commands, resources, debug and TLS directories, notes,
//! dynamic tables); binform reads their sections, imports, exports and
//! functions. goblin has a long history of panicking on malformed inputs
//! (out-of-range slice indexing in PE resource walkers, fat-header
//! arithmetic overflow in Mach-O, malformed dynamic sections in ELF), and
//! forensic-grade callers need parsing to *fail softly* on hostile inputs:
//! a `None` is fine, a process abort is not. Every goblin parse and lazy
//! walk goes through this module.
//!
//! ## Protections, layered
//!
//! 1. **Header pre-validation**: before goblin sees a PE,
//!    [`validate_pe_header`] rejects one whose COFF section count or
//!    data-directory sizes make goblin's walkers degenerate into massive
//!    allocations or hangs, and [`prepare_pe`] keeps from goblin the
//!    structures it cannot survive.
//! 2. **No work nothing reads**: goblin's PE import walk and
//!    attribute-certificate parse are switched off; the imports are
//!    binform's and Authenticode is read in-house.
//! 3. **catch_unwind around every goblin call**, including lazy walks
//!    performed *after* `PE::parse` returns. The resource-tree walker
//!    (`pe.resource_data.entries()`) slices with unchecked header offsets
//!    and panics on truncated tables, so parse-time safety is not enough by
//!    itself.
//! 4. **Strict→permissive fallback**: a PE strict mode rejects is parsed
//!    again in `ParseMode::Permissive`, which recovers more of a packed
//!    binary.
//!
//! ## When to use what
//!
//! | Operation                                              | Helper                |
//! |--------------------------------------------------------|------------------------|
//! | `PE::parse(...)` / `parse_with_opts(...)`              | [`prepare_pe`] then [`parse_pe`] |
//! | `pe::header::Header::parse(...)`                       | [`parse_pe_header`]    |
//! | `Elf::parse(...)`                                      | [`parse_elf`]          |
//! | `Mach::parse(...)`                                     | [`parse_mach`]         |
//! | `MachO::parse(...)` on one fat-binary slice            | [`parse_macho_slice`]  |
//! | A `Result<T, goblin::error::Error>` you call later     | [`catch`]              |
//! | A non-`Result` lazy access (e.g. `resource_data.count()`) | [`crate::panic_guard::catch_infallible`] |
//! | A lazy iterator (notes, debug entries, symbol versions) | [`drain`] / [`drain_or_record`] |
//!
//! `parse_pe` does the strict→permissive fallback itself; callers should not
//! reach for `PE::parse_with_opts` directly.

use std::borrow::Cow;

use goblin::elf::Elf;
use goblin::error::Error as GoblinError;
use goblin::mach::{Mach, MachO};
use goblin::pe::PE;
use goblin::pe::header::Header as PeHeader;
use goblin::pe::optional_header::OptionalHeader;
use goblin::pe::resource::{
    IMAGE_RESOURCE_DATA_IS_DIRECTORY, IMAGE_RESOURCE_NAME_IS_STRING, RT_MANIFEST, RT_VERSION,
};
use goblin::pe::section_table::SectionTable;
use std::fmt;

use crate::Stage;
use crate::bytes::{sat_usize, u16_le, u32_le};
use crate::formats::pe::layout::{self, EXPORT_DIRECTORY, MAX_SECTIONS, RESOURCE_DIRECTORY};
use crate::output::Errors;

/// Outcome of a goblin operation, distinguishing a normal `Err` from
/// a caught panic so callers can log them differently.
#[derive(Debug)]
pub(crate) enum GoblinOutcome<T> {
    /// goblin succeeded and produced a value.
    Ok(T),
    /// goblin returned a normal `Err` (truncated header, bad magic).
    Failed(GoblinError),
    /// goblin panicked while parsing/walking; payload is the
    /// extracted message.
    Panicked(String),
}

impl<T> GoblinOutcome<T> {
    /// Discard the failure context and return `Some(value)` only on
    /// `Ok`. Use this when the caller's recovery is the same for any
    /// failure mode (most format extractors).
    pub(crate) fn ok(self) -> Option<T> {
        match self {
            Self::Ok(t) => Some(t),
            Self::Failed(_) | Self::Panicked(_) => None,
        }
    }
}

/// Why a pre-check refused to let goblin walk a structure. Callers render it
/// with `Display` into `GoblinError::Malformed` or the structured errors view,
/// so the text is part of the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// COFF `NumberOfSections` far past what any loader accepts.
    TooManySections(u16),
    /// Optional-header `NumberOfRvaAndSizes` past [`MAX_DATA_DIRECTORIES`].
    TooManyDataDirectories(u32),
    /// A resource directory `size` beyond the file or
    /// [`MAX_RESOURCE_DIRECTORY_SIZE`].
    OversizedDirectory { table: &'static str, size: u32 },
    /// Export and forwarder names, summed over every name pointer, past
    /// budget.
    OversizedExportNames,
    /// The resource directories under `RT_VERSION` or `RT_MANIFEST` nested
    /// past [`MAX_RESOURCE_DEPTH`].
    DeepResourceTree,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooManySections(n) => write!(f, "too many sections ({n})"),
            Self::TooManyDataDirectories(n) => write!(f, "too many data directories ({n})"),
            Self::OversizedDirectory { table, size } => {
                write!(f, "malformed {table} table size ({size} bytes)")
            }
            Self::OversizedExportNames => {
                write!(f, "export names exceed {MAX_SYMBOL_NAME_BYTES} bytes")
            }
            Self::DeepResourceTree => {
                write!(
                    f,
                    "resource directories nested past {MAX_RESOURCE_DEPTH} levels"
                )
            }
        }
    }
}

/// Catch panics around a fallible goblin call.
pub(crate) fn catch<T, F>(f: F) -> GoblinOutcome<T>
where
    F: FnOnce() -> Result<T, GoblinError>,
{
    match crate::panic_guard::catch_infallible(f) {
        Ok(Ok(value)) => GoblinOutcome::Ok(value),
        Ok(Err(e)) => GoblinOutcome::Failed(e),
        Err(message) => GoblinOutcome::Panicked(message),
    }
}

/// A PE's bytes made safe to hand to goblin, and what had to be given up for
/// that. Built by [`prepare_pe`]; parse it with [`parse_pe`].
pub(crate) struct PreparedPe<'a> {
    /// The input, or one copy of it with the structures goblin cannot
    /// survive cleared. File offsets are unchanged, so the copy reads
    /// alongside the original bytes.
    pub(crate) bytes: Cow<'a, [u8]>,
    /// The header failed the pre-validation, so goblin must not see it.
    rejected: Option<Rejection>,
    /// `Some(reason)` when the export directory's names exceed the budget,
    /// so its slot is cleared in `bytes` and goblin parses no exports.
    /// Callers should surface it: a forged export table is a fact about the
    /// sample, not an internal detail.
    pub(crate) exports_skipped: Option<Rejection>,
    /// `Some(reason)` when goblin's walk of the resource tree would be
    /// unbounded, so goblin parses no resources. Surfaced like
    /// `exports_skipped`.
    pub(crate) resources_skipped: Option<Rejection>,
}

/// Check a PE's headers before goblin sees them, and neutralize what goblin
/// cannot survive, on at most one copy of `data`:
///
/// - a header [`validate_pe_header`] rejects is never parsed;
/// - a Rich header that goblin would reject as fatal has every `Rich`
///   magic in the DOS stub cleared;
/// - an export table whose names would cost goblin a quadratic walk has its
///   data-directory slot cleared, since goblin cannot be told to skip
///   exports;
/// - a resource tree goblin would descend without bound is marked to be
///   skipped.
///
/// Every copy-free path stays copy-free.
pub(crate) fn prepare_pe(data: &[u8]) -> PreparedPe<'_> {
    let mut prepared = PreparedPe {
        bytes: Cow::Borrowed(data),
        rejected: validate_pe_header(data).err(),
        exports_skipped: None,
        resources_skipped: None,
    };
    if let Some(reason) = prepared.rejected {
        tracing::debug!(
            target: "filefacts::goblin_safe",
            format = "pe",
            stage = "validate",
            len = data.len(),
            reason = %reason,
            "PE header rejected before parsing"
        );
        return prepared;
    }
    // goblin 0.10 parses the Rich header inside both `PE::parse` and the
    // header-only `Header::parse`, strict and permissive alike, and any
    // failure there aborts the *entire* parse, leaving every section-scoped
    // fact blind. It decodes the first `Rich` marker after the DOS header
    // and fails when no `DanS` anywhere in the stub decodes under its key,
    // or the table between them is not whole words: a forged or decoy
    // marker, which packed and mangled binaries carry routinely, and which
    // the loader never reads. When goblin's own decode fails, every marker
    // in the stub is cleared, so goblin finds none and treats the header
    // as absent; the Rich-header extractor still reads the untouched bytes.
    if !matches!(
        catch(|| goblin::pe::header::RichHeader::parse(data)),
        GoblinOutcome::Ok(_)
    ) && let Some(pe_pointer) = u32_le(data, 0x3c).map(sat_usize)
        && let Some(stub) = data.get(..pe_pointer.min(data.len()))
    {
        let markers: Vec<usize> = memchr::memmem::find_iter(stub, b"Rich").collect();
        if !markers.is_empty() {
            tracing::debug!(
                target: "filefacts::goblin_safe",
                format = "pe",
                stage = "rich-header",
                markers = markers.len(),
                "Rich header goblin cannot decode cleared for goblin"
            );
            let copy = prepared.bytes.to_mut();
            for at in markers {
                if let Some(magic) = copy.get_mut(at..at + 4) {
                    magic.fill(0);
                }
            }
        }
    }
    let Some((pe_pointer, optional, sections)) = header_and_sections(&prepared.bytes) else {
        return prepared;
    };
    if let Err(reason) = export_walk_budget(&prepared.bytes, &sections, &optional)
        && let Some(slot) = layout::data_directory_offset(
            pe_pointer,
            optional.standard_fields.magic,
            EXPORT_DIRECTORY,
        )
        && let Some(end) = slot.checked_add(8).filter(|&end| end <= data.len())
        && let Some(entry) = prepared.bytes.to_mut().get_mut(slot..end)
    {
        tracing::debug!(
            target: "filefacts::goblin_safe",
            format = "pe",
            stage = "exports",
            reason = %reason,
            "export directory past budget; kept from goblin"
        );
        entry.fill(0);
        prepared.exports_skipped = Some(reason);
    }
    if let Err(reason) = resource_walk_budget(&prepared.bytes, &sections, &optional) {
        tracing::debug!(
            target: "filefacts::goblin_safe",
            format = "pe",
            stage = "resources",
            reason = %reason,
            "resource directory past budget; kept from goblin"
        );
        prepared.resources_skipped = Some(reason);
    }
    prepared
}

/// The PE signature's offset (`e_lfanew`), the optional header and the
/// section table, read the way `PE::parse` reads them and owned so the bytes
/// they were read from can still be patched. `None` when they do not parse:
/// the full parse then fails on the same bytes before it reaches the
/// exports, so the budget fails open.
fn header_and_sections(data: &[u8]) -> Option<(usize, OptionalHeader, Vec<SectionTable>)> {
    let GoblinOutcome::Ok(header) = parse_pe_header(data) else {
        return None;
    };
    let optional = header.optional_header?;
    let pe_pointer = sat_usize(header.dos_header.pe_pointer);
    let mut offset = layout::optional_header_offset(pe_pointer)?
        .saturating_add(usize::from(header.coff_header.size_of_optional_header));
    let GoblinOutcome::Ok(sections) = catch(|| header.coff_header.sections(data, &mut offset))
    else {
        return None;
    };
    Some((pe_pointer, optional, sections))
}

/// Parse a prepared PE, panic-safe and with built-in permissive fallback.
///
/// Strict mode is tried first; if it fails OR panics, the call is retried
/// with `ParseMode::Permissive`. Returns the strict failure only when the
/// permissive retry itself panicked (in which case the strict error is the
/// more actionable signal). goblin's import walk and attribute-certificate
/// parse are off in both: nothing reads them, and a forged import table
/// makes the walk quadratic in the file size.
pub(crate) fn parse_pe<'a>(prepared: &'a PreparedPe<'_>) -> GoblinOutcome<PE<'a>> {
    if let Some(reason) = prepared.rejected {
        return GoblinOutcome::Failed(GoblinError::Malformed(reason.to_string()));
    }
    let data: &'a [u8] = &prepared.bytes;
    let mut strict = goblin::pe::options::ParseOptions::default()
        .with_parse_imports(false)
        .with_parse_resources(prepared.resources_skipped.is_none());
    strict.parse_attribute_certificates = false;
    let permissive = strict.with_parse_mode(goblin::options::ParseMode::Permissive);
    let first = catch(|| PE::parse_with_opts(data, &strict));
    if matches!(first, GoblinOutcome::Ok(_)) {
        return first;
    }
    let second = catch(|| PE::parse_with_opts(data, &permissive));
    match (&first, &second) {
        // Strict failed cleanly; permissive panicked — prefer the
        // clean failure message.
        (GoblinOutcome::Failed(_), GoblinOutcome::Panicked(_)) => first,
        _ => second,
    }
}

/// Name bytes goblin may be asked to read across one export table.
///
/// goblin reads each name pointer's string afresh, scanning to its NUL.
/// The entry count does not bound that product: a quarter-million name
/// pointers may all point at one name a megabyte long, a quarter of a
/// terabyte to scan from a file of a few megabytes. Real tables total well
/// under a megabyte of names, the largest C++ export tables a few.
const MAX_SYMBOL_NAME_BYTES: usize = 32 * 1024 * 1024;

/// Bytes before the NUL ending the string at `offset`, or `None` once they
/// pass `budget`. A string running to the end of `data` counts to its end.
fn name_len(data: &[u8], offset: usize, budget: usize) -> Option<usize> {
    let tail = data.get(offset..).unwrap_or_default();
    let window = tail.get(..budget.saturating_add(1)).unwrap_or(tail);
    let len = memchr::memchr(0, window).unwrap_or(window.len());
    (len <= budget).then_some(len)
}

/// Decide whether goblin's export walk over `data` reads a bounded number of
/// name bytes.
///
/// `Export::parse_with_opts` reads, for every entry of the export name
/// pointer table, the name it points at and, when the entry's address falls
/// inside the export directory, the forwarder string there — each scanned to
/// its NUL from scratch. The table may hold a quarter of the file's size in
/// entries and every one may point at the same long string, which makes the
/// walk quadratic in the file size and the symbols filefacts copies out of it
/// quadratic in memory. goblin offers no switch for exports, so this replays
/// the walk with goblin's own `find_offset`, summing the string lengths, and
/// stops once they pass [`MAX_SYMBOL_NAME_BYTES`].
///
/// Fails open: a table goblin would itself reject or cannot resolve counts as
/// within budget.
fn export_walk_budget(
    data: &[u8],
    sections: &[SectionTable],
    optional_header: &OptionalHeader,
) -> Result<(), Rejection> {
    use goblin::pe::options::ParseOptions;

    let Some(export_table) = optional_header.data_directories.get_export_table() else {
        return Ok(());
    };
    let file_alignment = optional_header.windows_fields.file_alignment;
    let opts = ParseOptions::default().with_parse_mode(goblin::options::ParseMode::Permissive);
    let resolve =
        |rva: u32| goblin::pe::utils::find_offset(sat_usize(rva), sections, file_alignment, &opts);

    // IMAGE_EXPORT_DIRECTORY: AddressTableEntries at 20, NumberOfNamePointers
    // at 24, then the address, name-pointer and ordinal table RVAs.
    let Some(directory) = resolve(export_table.virtual_address) else {
        return Ok(());
    };
    let field = |at: usize| u32_le(data, directory.saturating_add(at));
    let (Some(address_entries), Some(name_pointers), Some(eat), Some(names), Some(ordinals)) =
        (field(20), field(24), field(28), field(32), field(36))
    else {
        return Ok(());
    };
    // goblin refuses either count past the file length outright.
    let (address_entries, name_pointers) = (sat_usize(address_entries), sat_usize(name_pointers));
    if address_entries > data.len() || name_pointers > data.len() {
        return Ok(());
    }
    // Without a name-pointer table goblin synthesizes no exports at all.
    let Some(names) = resolve(names) else {
        return Ok(());
    };
    let (eat, ordinals) = (resolve(eat), resolve(ordinals));
    let forwarders = u64::from(export_table.virtual_address)
        ..u64::from(export_table.virtual_address) + u64::from(export_table.size);

    let mut name_bytes = 0usize;
    let mut count = |at: Option<usize>| -> Result<(), Rejection> {
        let Some(at) = at else {
            return Ok(());
        };
        let left = MAX_SYMBOL_NAME_BYTES - name_bytes;
        name_bytes += name_len(data, at, left).ok_or(Rejection::OversizedExportNames)?;
        Ok(())
    };
    for idx in 0..name_pointers {
        // goblin stops reading each table at the first entry past the file.
        let Some(pointer) = u32_le(data, names.saturating_add(idx.saturating_mul(4))) else {
            break;
        };
        count(resolve(pointer))?;
        let forwarder = ordinals
            .and_then(|table| u16_le(data, table.saturating_add(idx.saturating_mul(2))))
            .map(usize::from)
            .filter(|&ordinal| ordinal < address_entries)
            .zip(eat)
            .and_then(|(ordinal, table)| {
                u32_le(data, table.saturating_add(ordinal.saturating_mul(4)))
            })
            .filter(|&rva| forwarders.contains(&u64::from(rva)));
        count(forwarder.and_then(resolve))?;
    }
    Ok(())
}

/// Directory levels goblin may descend below a resource type. The loader
/// reads three (type, name, language); goblin follows each directory's
/// first entry for as long as it is another directory.
const MAX_RESOURCE_DEPTH: usize = 8;

/// Decide whether goblin's resource parse descends a bounded number of
/// directories.
///
/// To find the version and manifest resources, `ResourceData::parse`
/// starts at the first root entry with the `RT_VERSION` (then
/// `RT_MANIFEST`) id and moves to the first entry of the directory it
/// points at while that entry is a directory, collecting every entry of
/// each directory on the way. Directories may overlap, so a chain of them,
/// each claiming 65535 entries, makes the walk quadratic in the resource
/// size: minutes for a few megabytes. This replays the descent, reading
/// only each directory's header and first entry, and stops it past
/// [`MAX_RESOURCE_DEPTH`].
///
/// Fails open: a tree goblin would reject before descending that far counts
/// as within budget, since goblin then stops as quickly.
fn resource_walk_budget(
    data: &[u8],
    sections: &[SectionTable],
    optional_header: &OptionalHeader,
) -> Result<(), Rejection> {
    use goblin::pe::options::ParseOptions;

    let Some(table) = optional_header.data_directories.get_resource_table() else {
        return Ok(());
    };
    let opts = ParseOptions::default().with_parse_mode(goblin::options::ParseMode::Permissive);
    let Some(tree) = goblin::pe::utils::find_offset(
        sat_usize(table.virtual_address),
        sections,
        optional_header.windows_fields.file_alignment,
        &opts,
    )
    .and_then(|start| data.get(start..start.checked_add(sat_usize(table.size))?)) else {
        return Ok(());
    };
    // The entries of the directory at `offset` in the tree, as goblin reads
    // them: all of them in bounds, or none.
    let entries = |offset: usize| -> Option<&[u8]> {
        let named = u16_le(tree, offset.checked_add(12)?)?;
        let ids = u16_le(tree, offset.checked_add(14)?)?;
        let start = offset.checked_add(16)?;
        tree.get(start..start.checked_add(usize::from(named.saturating_add(ids)) * 8)?)
    };
    let Some(root) = entries(0) else {
        return Ok(());
    };
    for id in [RT_VERSION, RT_MANIFEST] {
        // `ResourceEntryIterator::find_by_id`: the first entry whose id, a
        // name that is not a string, is `id` in its low 16 bits.
        let Some(mut target) = root.as_chunks::<8>().0.iter().find_map(|entry| {
            let name = u32_le(entry, 0)?;
            (name & IMAGE_RESOURCE_NAME_IS_STRING == 0 && name & 0xffff == u32::from(id))
                .then(|| u32_le(entry, 4))?
        }) else {
            continue;
        };
        // Each step reads the first entry of the directory `target` points
        // at, and goes on while that entry is a directory itself.
        let mut depth = 0;
        while let Some(next) = entries(sat_usize(target & !IMAGE_RESOURCE_DATA_IS_DIRECTORY))
            .and_then(|entries| u32_le(entries, 4))
            .filter(|next| next & IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0)
        {
            depth += 1;
            if depth > MAX_RESOURCE_DEPTH {
                return Err(Rejection::DeepResourceTree);
            }
            target = next;
        }
    }
    Ok(())
}

/// The data-directory slots the PE specification defines.
const MAX_DATA_DIRECTORIES: u32 = 16;

/// Largest resource directory goblin is handed.
const MAX_RESOURCE_DIRECTORY_SIZE: u32 = 10 * 1024 * 1024;

/// Basic structural validation of PE headers, run *before* goblin
/// sees the bytes. Defends against known panic / OOM triggers:
///
/// - COFF `NumberOfSections` past [`MAX_SECTIONS`]: four-figure counts are
///   a forged header crashing the section walker.
/// - Optional-header `NumberOfRvaAndSizes` past [`MAX_DATA_DIRECTORIES`].
/// - A resource data-directory `size` past [`MAX_RESOURCE_DIRECTORY_SIZE`]
///   or the file size: a forged size makes goblin allocate gigabytes for
///   the resource tree.
fn validate_pe_header(data: &[u8]) -> Result<(), Rejection> {
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return Ok(());
    }
    // `e_lfanew`, the PE signature's offset.
    let Some(pe_offset) = u32_le(data, 0x3C).map(sat_usize) else {
        return Ok(());
    };
    if pe_offset.saturating_add(24) > data.len()
        || data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0".as_slice())
    {
        return Ok(());
    }

    let coff_offset = pe_offset + 4;
    let Some(n_sections) = u16_le(data, coff_offset + 2) else {
        return Ok(());
    };
    if usize::from(n_sections) > MAX_SECTIONS {
        return Err(Rejection::TooManySections(n_sections));
    }

    let Some(magic) = u16_le(data, coff_offset + 20) else {
        return Ok(());
    };
    // `NumberOfRvaAndSizes` is the word just before the data-directory array.
    let Some(n_dirs) = layout::data_directory_offset(pe_offset, magic, 0)
        .and_then(|at| u32_le(data, at.checked_sub(4)?))
    else {
        return Ok(());
    };
    if n_dirs > MAX_DATA_DIRECTORIES {
        return Err(Rejection::TooManyDataDirectories(n_dirs));
    }

    if sat_usize(n_dirs) > RESOURCE_DIRECTORY
        && let Some(size) = layout::data_directory_offset(pe_offset, magic, RESOURCE_DIRECTORY)
            .and_then(|at| u32_le(data, at.checked_add(4)?))
        && (size > MAX_RESOURCE_DIRECTORY_SIZE || sat_usize(size) > data.len())
    {
        return Err(Rejection::OversizedDirectory {
            table: "resource",
            size,
        });
    }

    Ok(())
}

/// Parse only the DOS, COFF and optional headers of a PE, panic-safe. The
/// fallback for a PE [`parse_pe`] could not parse in full.
pub(crate) fn parse_pe_header(data: &[u8]) -> GoblinOutcome<PeHeader<'_>> {
    catch(|| PeHeader::parse(data))
}

/// Parse an ELF, panic-safe.
pub(crate) fn parse_elf(data: &[u8]) -> GoblinOutcome<Elf<'_>> {
    catch(|| Elf::parse(data))
}

/// Run a lazy goblin walk to completion, panic-safe. goblin's iterators (ELF
/// notes and symbol versions, PE debug entries, Mach-O symbols and fat
/// arches) read file-controlled offsets only as they advance, long after the
/// parse that produced them returned, so each walk needs its own guard.
/// Callers get a finished `Vec`, never a live goblin iterator.
pub(crate) fn drain<I: IntoIterator>(walk: I) -> Result<Vec<I::Item>, String> {
    crate::panic_guard::catch_infallible(|| walk.into_iter().collect())
}

/// [`drain`] for callers that surface failures: a walk that panics is
/// recorded in `errors` at `stage` and yields no items.
pub(crate) fn drain_or_record<I: IntoIterator>(
    walk: I,
    errors: &mut Errors,
    stage: Stage,
) -> Vec<I::Item> {
    drain(walk).unwrap_or_else(|msg| {
        tracing::debug!(
            target: "filefacts::goblin_safe",
            stage = ?stage,
            error = %msg,
            "lazy goblin walk panicked; its items are dropped"
        );
        errors.record_panic(stage, msg);
        Vec::new()
    })
}

/// An ELF whose section header table runs past the end of the file, with
/// that table detached so goblin can parse the segment view.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DetachedElf {
    /// The file with `e_shoff`, `e_shnum` and `e_shstrndx` zeroed. Every
    /// other byte, and so every file offset, is unchanged.
    pub(crate) bytes: Vec<u8>,
    /// The header's own `e_shoff`, before it was zeroed.
    pub(crate) shoff: u64,
    /// The header's own `e_shstrndx`, before it was zeroed.
    pub(crate) shstrndx: u64,
}

/// A copy of `data` with the section header table detached, when that table
/// lies past end of file.
///
/// Truncated binaries are common in malware feeds (partial downloads,
/// size-capped collectors). The section header table sits at the end of a
/// typical ELF, so it is the first thing lost, and goblin then rejects the
/// whole file even though the ELF header and program headers -- all a loader
/// needs -- are intact. Zeroing `e_shoff`/`e_shnum`/`e_shstrndx` lets goblin
/// parse the segment view; every file offset is unchanged, so the result can
/// be read alongside the original bytes. `None` when the table is in bounds
/// (the failure lies elsewhere) or the header itself is truncated.
pub(crate) fn elf_without_truncated_section_headers(data: &[u8]) -> Option<DetachedElf> {
    let is64 = match data.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let big_endian = match data.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let (shoff_at, shoff_len, shentsize_at, shnum_at, shstrndx_at) = if is64 {
        (0x28, 8, 0x3A, 0x3C, 0x3E)
    } else {
        (0x20, 4, 0x2E, 0x30, 0x32)
    };
    let read = |at: usize, len: usize| -> Option<u64> {
        let field = data.get(at..at + len)?;
        let fold = |acc: u64, b: &u8| (acc << 8) | u64::from(*b);
        Some(if big_endian {
            field.iter().fold(0, fold)
        } else {
            field.iter().rev().fold(0, fold)
        })
    };
    let shoff = read(shoff_at, shoff_len)?;
    let table_end = read(shnum_at, 2)?
        .checked_mul(read(shentsize_at, 2)?)
        .and_then(|size| size.checked_add(shoff))?;
    if shoff == 0 || table_end <= data.len() as u64 {
        return None;
    }
    let mut patched = data.to_vec();
    patched.get_mut(shoff_at..shoff_at + shoff_len)?.fill(0);
    patched.get_mut(shnum_at..shnum_at + 2)?.fill(0);
    // `e_shstrndx` sits past every field read above, so a header cut off
    // inside it gets here; that is the "header itself is truncated" case.
    let shstrndx = read(shstrndx_at, 2)?;
    patched.get_mut(shstrndx_at..shstrndx_at + 2)?.fill(0);
    Some(DetachedElf {
        bytes: patched,
        shoff,
        shstrndx,
    })
}

/// Parse a Mach-O (single arch or fat), panic-safe.
pub(crate) fn parse_mach(data: &[u8]) -> GoblinOutcome<Mach<'_>> {
    catch(|| Mach::parse(data))
}

/// Parse one architecture slice of a fat Mach-O, panic-safe. [`parse_mach`]
/// reads only the fat header; every slice is a full parse of its own.
pub(crate) fn parse_macho_slice(data: &[u8]) -> GoblinOutcome<MachO<'_>> {
    catch(|| MachO::parse(data, 0))
}

#[cfg(test)]
pub(crate) mod tests;
