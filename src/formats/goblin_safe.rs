//! Panic-safe wrappers around the [`goblin`] crate's binary parsers.
//!
//! `goblin` is fast but has a long history of panicking on malformed
//! inputs (out-of-range slice indexing in PE resource walkers,
//! fat-header arithmetic overflow in Mach-O, malformed dynamic
//! sections in ELF). Forensic-grade callers need parsing to *fail
//! softly* on hostile inputs — a `None` is fine, a process abort is
//! not. This module is the single chokepoint through which the
//! format extractors talk to goblin.
//!
//! ## Three protections, layered
//!
//! 1. **Header pre-validation** — before goblin sees the bytes,
//!    [`validate_pe_header`] rejects PEs whose COFF section count or
//!    data-directory size make goblin's lazy walkers degenerate into
//!    massive allocations or hangs.
//! 2. **catch_unwind around every goblin call** — including lazy
//!    walks performed *after* `PE::parse` returns. The resource-tree
//!    walker (`pe.resource_data.entries()`) slices with unchecked
//!    header offsets and panics on truncated tables, so the parse-
//!    time safety is not enough by itself.
//! 3. **Strict→permissive fallback** — `PE::parse_with_opts(...,
//!    Permissive)` recovers more imports/exports on packed binaries
//!    that strict mode rejects. Cleave learned this on vxug malware
//!    samples.
//!
//! ## When to use what
//!
//! | Operation                                              | Helper                |
//! |--------------------------------------------------------|------------------------|
//! | `PE::parse(...)` / `parse_with_opts(...)`              | [`parse_pe`]           |
//! | `pe::header::Header::parse(...)`                       | [`parse_pe_header`]    |
//! | `Elf::parse(...)`                                      | [`parse_elf`]          |
//! | `Mach::parse(...)`                                     | [`parse_mach`]         |
//! | `MachO::parse(...)` on one fat-binary slice            | [`parse_macho_slice`]  |
//! | A `Result<T, goblin::error::Error>` you call later     | [`catch`]              |
//! | A non-`Result` lazy access (e.g. `resource_data.count()`) | [`catch_infallible`] |
//! | A lazy iterator (notes, debug entries, symbol versions) | [`drain`] / [`drain_or_record`] |
//!
//! `parse_pe` already does the strict→permissive fallback internally;
//! callers should not reach for `PE::parse_with_opts` directly.

use goblin::elf::Elf;
use goblin::error::Error as GoblinError;
use goblin::mach::{Mach, MachO};
use goblin::pe::PE;
use goblin::pe::header::Header as PeHeader;
use std::cell::Cell;
use std::fmt;
use std::panic;
use std::sync::Once;

use crate::Stage;
use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::formats::common::read_uleb128;
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
            _ => None,
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
    /// Optional-header `NumberOfRvaAndSizes` past the spec's 16.
    TooManyDataDirectories(u32),
    /// An import or resource directory `size` beyond the file or 10 MiB.
    OversizedDirectory { table: &'static str, size: u32 },
    /// An import descriptor array with no terminator within budget.
    UnterminatedImportDirectory,
    /// Import lookup tables too long to walk within budget.
    OversizedImportLookupTables,
    /// An export-trie edge back to a node already visited.
    ExportTrieLoop {
        node: usize,
        start: usize,
        end: usize,
    },
    /// An export-trie node claiming more branches than the trie can hold.
    ExportTrieBranches {
        node: usize,
        branches: u64,
        available: usize,
    },
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooManySections(n) => write!(f, "too many sections ({n})"),
            Self::TooManyDataDirectories(n) => write!(f, "too many data directories ({n})"),
            Self::OversizedDirectory { table, size } => {
                write!(f, "malformed {table} table size ({size} bytes)")
            }
            Self::UnterminatedImportDirectory => write!(
                f,
                "import directory exceeds {MAX_IMPORT_DESCRIPTORS} descriptors without terminating"
            ),
            Self::OversizedImportLookupTables => write!(
                f,
                "import lookup tables exceed {MAX_IMPORT_LOOKUP_ENTRIES} entries"
            ),
            Self::ExportTrieLoop { node, start, end } => write!(
                f,
                "export trie loops back to node {node:#x} (trie {start:#x}..{end:#x})"
            ),
            Self::ExportTrieBranches {
                node,
                branches,
                available,
            } => write!(
                f,
                "export trie node {node:#x} claims {branches} branches in {available} bytes"
            ),
        }
    }
}

pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

thread_local! {
    static SUPPRESS_PANIC_OUTPUT: Cell<bool> = const { Cell::new(false) };
}

/// Install a process-wide panic hook (once) that swallows panic
/// messages from threads that opted into suppression. Replaces the
/// older `take_hook` / `set_hook` swap pattern (which required a
/// global Mutex to serialize swaps) with a single, race-free install.
fn install_suppression_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if SUPPRESS_PANIC_OUTPUT.with(Cell::get) {
                return;
            }
            previous(info);
        }));
    });
}

fn run_with_suppressed_panic_hook<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T,
{
    install_suppression_hook();

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            SUPPRESS_PANIC_OUTPUT.with(|flag| flag.set(false));
        }
    }

    SUPPRESS_PANIC_OUTPUT.with(|flag| flag.set(true));
    let _restore = Restore;
    panic::catch_unwind(panic::AssertUnwindSafe(f))
}

/// Catch panics around a fallible goblin call.
pub(crate) fn catch<T, F>(f: F) -> GoblinOutcome<T>
where
    F: FnOnce() -> Result<T, GoblinError>,
{
    match run_with_suppressed_panic_hook(f) {
        Ok(Ok(value)) => GoblinOutcome::Ok(value),
        Ok(Err(e)) => GoblinOutcome::Failed(e),
        Err(payload) => GoblinOutcome::Panicked(panic_message(&*payload)),
    }
}

/// Catch panics around an infallible (lazy-walk) goblin call.
pub(crate) fn catch_infallible<T, F>(f: F) -> GoblinOutcome<T>
where
    F: FnOnce() -> T,
{
    match run_with_suppressed_panic_hook(f) {
        Ok(value) => GoblinOutcome::Ok(value),
        Err(payload) => GoblinOutcome::Panicked(panic_message(&*payload)),
    }
}

/// What [`parse_pe`] produced: the parse itself, plus whether its import
/// table had to be abandoned to keep the parse bounded.
pub(crate) struct PeParse<'a> {
    pub(crate) outcome: GoblinOutcome<PE<'a>>,
    /// `Some(reason)` when the import directory could not be walked within
    /// budget, so the returned PE was parsed with imports disabled. Callers
    /// should surface it: an unwalkable import table is a fact about the
    /// sample, not an internal detail.
    pub(crate) imports_skipped: Option<Rejection>,
}

impl<'a> PeParse<'a> {
    /// The ordinary outcome: whatever goblin produced, imports included.
    fn parsed(outcome: GoblinOutcome<PE<'a>>) -> Self {
        Self {
            outcome,
            imports_skipped: None,
        }
    }
}

/// Parse a PE file, panic-safe and with built-in permissive
/// fallback.
///
/// Strict mode is tried first; if it fails OR panics, the call is
/// retried with `ParseMode::Permissive`. Returns the strict failure
/// only when the permissive retry itself panicked (in which case the
/// strict error is the more actionable signal).
pub(crate) fn parse_pe(data: &[u8]) -> PeParse<'_> {
    if let Err(e) = validate_pe_header(data) {
        return PeParse::parsed(GoblinOutcome::Failed(GoblinError::Malformed(e.to_string())));
    }

    let strict = catch(|| PE::parse(data));
    if matches!(strict, GoblinOutcome::Ok(_)) {
        return PeParse::parsed(strict);
    }

    // Strict failed, so the permissive retry is next — but permissive is
    // exactly the mode whose import walker can run away (see
    // `import_walk_budget`). Parse once with imports off: that is bounded by
    // construction, and it yields the section table and file alignment the
    // budget check needs to resolve the import directory the way goblin will.
    let base_opts = goblin::pe::options::ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive);
    let importless_opts = base_opts.with_parse_imports(false);
    let importless = catch(|| PE::parse_with_opts(data, &importless_opts));

    // Fail open: if the import-less parse did not survive either, there is
    // nothing to budget against, so let the original permissive path run and
    // report whatever it finds.
    let over_budget = match &importless {
        GoblinOutcome::Ok(pe) => import_walk_budget(data, pe).err(),
        _ => None,
    };

    if let Some(reason) = over_budget {
        // A forged import directory. Keep every other fact (headers, sections,
        // exports, resources, Authenticode) rather than failing the whole PE:
        // an unwalkable import table is itself a signal, not a reason to go
        // blind on the sample.
        return PeParse {
            outcome: importless,
            imports_skipped: Some(reason),
        };
    }

    let permissive = catch(|| PE::parse_with_opts(data, &base_opts));

    PeParse::parsed(match (&strict, &permissive) {
        // Strict failed cleanly; permissive panicked — prefer the
        // clean failure message.
        (GoblinOutcome::Failed(_), GoblinOutcome::Panicked(_)) => strict,
        _ => permissive,
    })
}

/// Import-directory descriptors a real PE ever declares. Linkers emit one per
/// imported DLL: a handful is typical, a hundred is a heavyweight application.
/// Past this the array is not an import table.
const MAX_IMPORT_DESCRIPTORS: usize = 256;

/// Import-lookup-table entries goblin may be asked to synthesize across the
/// whole file. Each entry costs it a `Vec` push, an RVA resolution, a
/// hint/name read and — on a bad RVA — a `warn!`, so this is the real budget;
/// the descriptor cap alone does not bound the product.
const MAX_IMPORT_LOOKUP_ENTRIES: usize = 256 * 1024;

/// Decide whether goblin's permissive import walk over `data` is bounded.
///
/// `ImportData::parse_with_opts` walks 20-byte descriptors from the import
/// data directory until one is null or "not possibly valid", and walks each
/// descriptor's lookup table until a zero entry. In permissive mode a
/// malformed entry is *skipped* rather than fatal, so a forged directory
/// pointing into dense non-zero bytes yields `file_len / 20` descriptors, each
/// re-walking a lookup table of up to `file_len / entry_size` entries. That
/// product is quadratic in the file size and, measured on a wedged production
/// worker 2026-09-04, does not finish: one Rayon thread spent hours inside
/// `ImportData::parse_with_opts` while every other worker in the shared pool
/// parked on a join latch behind it, taking the whole process down.
///
/// goblin offers no cap of its own (`ParseOptions::parse_imports` is
/// all-or-nothing), so this walks the same structure first, using goblin's own
/// `find_offset` so the traversal agrees with the one being budgeted, but
/// without the allocation, name parsing, or logging that makes goblin's
/// version orders of magnitude more expensive per entry. It reads at most
/// `MAX_IMPORT_LOOKUP_ENTRIES` entries before giving its answer.
///
/// Fails open: anything it cannot resolve counts as within budget, so a PE
/// shape this pre-walk does not model keeps exactly today's behaviour.
fn import_walk_budget(data: &[u8], pe: &PE<'_>) -> Result<(), Rejection> {
    use goblin::pe::import::SIZEOF_IMPORT_DIRECTORY_ENTRY;
    use goblin::pe::options::ParseOptions;

    let Some(optional_header) = pe.header.optional_header else {
        return Ok(());
    };
    let Some(import_table) = optional_header.data_directories.get_import_table() else {
        return Ok(());
    };
    let file_alignment = optional_header.windows_fields.file_alignment;
    // PE32 lookup entries are 4 bytes, PE32+ are 8. `is_64` is goblin's own
    // reading of the optional-header magic, the same bit that picks the
    // `Bitfield` width it walks the table with.
    let entry_size = if pe.is_64 { 8 } else { 4 };
    let opts = ParseOptions::default().with_parse_mode(goblin::options::ParseMode::Permissive);

    let resolve = |rva: u32| {
        goblin::pe::utils::find_offset(rva as usize, &pe.sections, file_alignment, &opts)
    };

    let Some(mut offset) = resolve(import_table.virtual_address) else {
        return Ok(());
    };

    let mut descriptors = 0usize;
    let mut entries = 0usize;
    while offset + SIZEOF_IMPORT_DIRECTORY_ENTRY <= data.len() {
        // Field layout of `ImportDirectoryEntry`, little-endian: lookup-table
        // RVA, timestamp, forwarder chain, name RVA, address-table RVA.
        // In bounds by the loop guard; a short read would yield the all-zero
        // terminator, ending the walk as running out of bytes does.
        let word = |i: usize| -> u32 { u32_le(data, offset + i * 4).unwrap_or(0) };
        let (lookup_rva, name_rva, address_rva) = (word(0), word(3), word(4));
        let is_null = (0..5).all(|i| word(i) == 0);
        // Mirrors `ImportDirectoryEntry::is_possibly_valid`.
        let is_possibly_valid = name_rva != 0 && address_rva != 0;
        if is_null || !is_possibly_valid {
            return Ok(());
        }

        descriptors += 1;
        if descriptors > MAX_IMPORT_DESCRIPTORS {
            return Err(Rejection::UnterminatedImportDirectory);
        }

        // goblin prefers the lookup table and falls back to the address table.
        if let Some(mut cursor) = resolve(lookup_rva).or_else(|| resolve(address_rva)) {
            while let Some(entry) = data.get(cursor..cursor + entry_size) {
                if entry.iter().all(|&b| b == 0) {
                    break;
                }
                entries += 1;
                if entries > MAX_IMPORT_LOOKUP_ENTRIES {
                    return Err(Rejection::OversizedImportLookupTables);
                }
                cursor += entry_size;
            }
        }

        offset += SIZEOF_IMPORT_DIRECTORY_ENTRY;
    }

    Ok(())
}

/// Detect a Rich header that goblin's parser would treat as a fatal
/// `Malformed` error — the `Rich` marker is present in the DOS stub but
/// no XOR-decodable `DanS` table precedes it — and return an owned copy
/// of `data` with the marker neutralized so the rest of the PE still
/// parses. Returns `None` when no Rich marker is present or the header is
/// well-formed, so the common path never copies.
///
/// goblin 0.10 parses the Rich header inside both `PE::parse` and the
/// header-only `Header::parse`, and a corrupt stub aborts the *entire*
/// parse (strict and permissive alike) — leaving every section- and
/// import-scoped fact blind. Packed and intentionally-mangled samples
/// emit forged Rich stubs routinely. Zeroing the 4-byte `Rich` magic
/// makes goblin's marker scan find nothing and treat the header as
/// absent (`Ok(None)`); filefacts' own `pe_rich` extractor still reads
/// the untouched bytes, so a genuine Rich hash is unaffected.
pub(crate) fn neutralize_malformed_rich_header(data: &[u8]) -> Option<Vec<u8>> {
    const RICH_MAGIC: &[u8; 4] = b"Rich";
    // "DanS" little-endian as u32.
    const DANS_MARKER: u32 = 0x536e_6144;

    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32_le(data, 0x3c)? as usize;
    let scan_end = e_lfanew.min(data.len());
    if scan_end < 8 {
        return None;
    }
    let rich_pos = data
        .get(..scan_end)?
        .windows(4)
        .rposition(|w| w == RICH_MAGIC)?;
    let key = u32_le(data, rich_pos + 4)?;
    // Walk backwards in 4-byte words: a decodable DanS marker means the
    // header is well-formed and goblin will parse it without complaint.
    let mut pos = rich_pos;
    while pos >= 4 {
        pos -= 4;
        let word = u32_le(data, pos)?;
        if word ^ key == DANS_MARKER {
            return None;
        }
    }
    // No DanS table reachable — goblin would abort. Hand back a copy with
    // the `Rich` magic cleared so its marker scan finds nothing.
    let mut patched = data.to_vec();
    patched.get_mut(rich_pos..rich_pos + 4)?.fill(0);
    Some(patched)
}

/// Basic structural validation of PE headers, run *before* goblin
/// sees the bytes. Defends against known panic / OOM triggers:
///
/// - COFF `NumberOfSections > 192` (PE spec caps at 96; real-world
///   Windows tolerates a bit more, but four-figure counts are a
///   forged header crashing the section walker).
/// - Optional-header `NumberOfRvaAndSizes > 16` (spec maximum).
/// - Import / resource data-directory `size > 10 MiB` or `> file
///   size` (forged sizes cause goblin to allocate gigabytes for the
///   import table).
fn validate_pe_header(data: &[u8]) -> Result<(), Rejection> {
    if data.len() < 64 {
        return Ok(());
    }

    if !data.starts_with(b"MZ") {
        return Ok(());
    }

    let pe_ptr_offset = 0x3C;
    let Some(pe_offset) = u32_le(data, pe_ptr_offset) else {
        return Ok(());
    };
    let pe_offset = pe_offset as usize;

    if pe_offset + 24 > data.len() {
        return Ok(());
    }
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0".as_slice()) {
        return Ok(());
    }

    let coff_offset = pe_offset + 4;
    let Some(n_sections) = u16_le(data, coff_offset + 2) else {
        return Ok(());
    };
    if n_sections > 192 {
        return Err(Rejection::TooManySections(n_sections));
    }

    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return Ok(());
    }

    let Some(magic) = u16_le(data, opt_offset) else {
        return Ok(());
    };
    let (data_dir_count_offset, data_dir_offset) = match magic {
        0x010b => (92, 96),   // PE32
        0x020b => (108, 112), // PE32+
        _ => return Ok(()),
    };

    let dir_count_ptr = opt_offset + data_dir_count_offset;
    if dir_count_ptr + 4 > data.len() {
        return Ok(());
    }

    let Some(n_dirs) = u32_le(data, dir_count_ptr) else {
        return Ok(());
    };

    if n_dirs > 16 {
        return Err(Rejection::TooManyDataDirectories(n_dirs));
    }

    // Check the Imports (idx 1) and Resources (idx 2) data
    // directories specifically — they're the two whose forged
    // `size` field most reliably blows up goblin.
    for i in 1..=2 {
        if n_dirs > i as u32 {
            let dir_ptr = opt_offset + data_dir_offset + (i * 8);
            if let Some(size) = u32_le(data, dir_ptr + 4)
                && (size > 10 * 1024 * 1024 || size as usize > data.len())
            {
                let table = if i == 1 { "import" } else { "resource" };
                return Err(Rejection::OversizedDirectory { table, size });
            }
        }
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
pub(crate) fn drain<I: IntoIterator>(walk: I) -> GoblinOutcome<Vec<I::Item>> {
    catch_infallible(|| walk.into_iter().collect())
}

/// [`drain`] for callers that surface failures: a walk that panics is
/// recorded in `errors` at `stage` and yields no items.
pub(crate) fn drain_or_record<I: IntoIterator>(
    walk: I,
    errors: &mut Errors,
    stage: Stage,
) -> Vec<I::Item> {
    match drain(walk) {
        GoblinOutcome::Ok(items) => items,
        GoblinOutcome::Panicked(msg) => {
            errors.record_panic(stage, msg);
            Vec::new()
        }
        // A drain cannot fail; goblin's per-item errors are items themselves.
        GoblinOutcome::Failed(_) => Vec::new(),
    }
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
pub(crate) fn elf_without_truncated_section_headers(data: &[u8]) -> Option<Vec<u8>> {
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
    patched.get_mut(shstrndx_at..shstrndx_at + 2)?.fill(0);
    Some(patched)
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

/// Pre-validate the dyld export trie before `macho.exports()` walks it.
///
/// goblin's `ExportTrie::walk_trie` (mach/exports.rs, 0.10.7 and master)
/// recurses into every child edge with no visited set, no depth bound and no
/// requirement that a child lie past its parent. A trie whose edge points back
/// at an ancestor therefore never terminates: each level clones the growing
/// symbol prefix and pushes another `Export`, and the process is out of memory
/// long before the stack is — measured at 16 GiB in 6 s on a 232 KiB arm64
/// binary whose root edge pointed at offset 0 (llvm-objdump rejects the same
/// file with "loop in children in export trie data"). Neither `catch` nor a
/// panic hook can stop a walk that never faults.
///
/// This walks the same nodes goblin will, iteratively, and refuses the trie on
/// the first revisited node or branch count the trie cannot hold. Anything
/// goblin would itself reject (a truncated ULEB, an edge past the file) is
/// waved through: goblin's own `Err` is the more precise report for those.
///
/// Mirrors goblin's selection of the trie: the last `LC_DYLD_INFO`,
/// `LC_DYLD_INFO_ONLY` or `LC_DYLD_EXPORTS_TRIE` command wins.
pub(crate) fn validate_export_trie(macho: &MachO<'_>, bytes: &[u8]) -> Result<(), Rejection> {
    use goblin::mach::load_command::CommandVariant;
    let mut location = None;
    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) => {
                location = Some((c.export_off as usize, c.export_size as usize));
            }
            CommandVariant::DyldExportsTrie(c) => {
                location = Some((c.dataoff as usize, c.datasize as usize));
            }
            _ => {}
        }
    }
    match location {
        Some((start, size)) => validate_export_trie_bytes(bytes, start, size),
        None => Ok(()),
    }
}

/// [`validate_export_trie`] on an explicit trie range; the walk itself.
fn validate_export_trie_bytes(bytes: &[u8], start: usize, size: usize) -> Result<(), Rejection> {
    // goblin's `new_impl` collapses an out-of-file range to an empty trie.
    let Some(end) = start.checked_add(size).filter(|end| *end <= bytes.len()) else {
        return Ok(());
    };
    // One flag per byte of the trie: a node is at least one byte, so the
    // visited set is bounded by the trie's own size.
    let mut visited = vec![false; size];
    let mut pending = vec![start];
    while let Some(node) = pending.pop() {
        // goblin's `walk_trie` returns Ok for a node at or past the end.
        if node >= end {
            continue;
        }
        // `node >= start`: it is `start` or a child offset added to it.
        let Some(seen) = visited.get_mut(node - start) else {
            continue;
        };
        if std::mem::replace(seen, true) {
            return Err(Rejection::ExportTrieLoop { node, start, end });
        }
        let mut offset = node;
        let Some(terminal_size) = read_uleb128(bytes, &mut offset) else {
            return Ok(());
        };
        let children_start = if terminal_size == 0 {
            offset
        } else {
            let Some(next) = offset.checked_add(terminal_size as usize) else {
                return Ok(());
            };
            next
        };
        offset = children_start;
        let Some(nbranches) = read_uleb128(bytes, &mut offset) else {
            return Ok(());
        };
        // Every edge takes at least one byte, so a count the remaining trie
        // cannot hold is forged; goblin would only stop walking it once a read
        // fell off the end of the file. This also bounds the loop below.
        let available = end - offset.min(end);
        if nbranches > available as u64 {
            return Err(Rejection::ExportTrieBranches {
                node,
                branches: nbranches,
                available,
            });
        }
        for _ in 0..nbranches {
            let Some(label_len) = bytes
                .get(offset..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
            else {
                return Ok(());
            };
            offset += label_len + 1;
            let Some(child) = read_uleb128(bytes, &mut offset) else {
                return Ok(());
            };
            // goblin: `next_node = uleb + self.location.start`.
            let Some(child) = usize::try_from(child)
                .ok()
                .and_then(|c| c.checked_add(start))
            else {
                return Ok(());
            };
            pending.push(child);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_fixture(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    /// Offsets into `test.exe` (PE32+): the section table and the import
    /// data directory. Returned rather than hardcoded so the helpers below
    /// keep working if the fixture is regenerated.
    fn pe_layout(bytes: &[u8]) -> (usize, usize, usize) {
        let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let coff = pe_offset + 4;
        let sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
        let size_of_optional = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap());
        let optional = coff + 20;
        assert_eq!(
            u16::from_le_bytes(bytes[optional..optional + 2].try_into().unwrap()),
            0x20b,
            "fixture is expected to be PE32+"
        );
        let section_table = optional + size_of_optional as usize;
        // Data directory 1 is the import table; PE32+ puts the array at +112.
        let import_dir = optional + 112 + 8;
        (section_table, sections, import_dir)
    }

    fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Build a PE whose import directory is a forgery.
    ///
    /// The last section is grown to 3 MiB and filled with `0x11` bytes, which
    /// is exactly the shape that drives goblin's permissive lookup-table walk:
    /// non-zero (so the walk does not terminate), top bit clear (so the entry
    /// is a name RVA rather than a cheap ordinal), and pointing at an RVA that
    /// resolves to nothing (so each iteration takes the "bad RVA, skip entry"
    /// branch — a `warn!` and a `continue`, with no allocation). That is the
    /// loop the production worker was found spinning in.
    ///
    /// `descriptors` 20-byte import descriptors are written at the section
    /// start, followed by a null terminator. Each points its lookup table at
    /// the `0x11` region when `long_lookup_tables`, giving the descriptor
    /// count times ~390k entries of work; otherwise the lookup RVAs resolve to
    /// nothing and each descriptor is individually cheap.
    fn pe_with_forged_import_directory(descriptors: usize, long_lookup_tables: bool) -> Vec<u8> {
        const SECTION_SIZE: usize = 3 * 1024 * 1024;
        let mut bytes = read_fixture("test.exe");
        let (section_table, count, import_dir) = pe_layout(&bytes);
        let last = section_table + (count - 1) * 40;
        let virtual_address = u32::from_le_bytes(bytes[last + 12..last + 16].try_into().unwrap());
        let pointer = u32::from_le_bytes(bytes[last + 20..last + 24].try_into().unwrap()) as usize;

        bytes.resize(pointer + SECTION_SIZE, 0x11);
        bytes[pointer..pointer + SECTION_SIZE].fill(0x11);
        put_u32(&mut bytes, last + 8, SECTION_SIZE as u32); // virtual_size
        put_u32(&mut bytes, last + 16, SECTION_SIZE as u32); // size_of_raw_data

        // Lookup tables live past the descriptor array, in the 0x11 fill.
        let lookup_offset = (descriptors + 1) * 20;
        let lookup_rva = if long_lookup_tables {
            virtual_address + lookup_offset as u32
        } else {
            // Resolves to nothing, so goblin abandons this descriptor at once.
            0x1111_1111
        };
        for i in 0..descriptors {
            let at = pointer + i * 20;
            put_u32(&mut bytes, at, lookup_rva); // import_lookup_table_rva
            put_u32(&mut bytes, at + 4, 0); // time_date_stamp
            put_u32(&mut bytes, at + 8, 0); // forwarder_chain
            put_u32(&mut bytes, at + 12, 1); // name_rva: non-zero, unresolvable
            put_u32(&mut bytes, at + 16, 1); // import_address_table_rva
        }
        bytes[pointer + descriptors * 20..pointer + (descriptors + 1) * 20].fill(0);

        put_u32(&mut bytes, import_dir, virtual_address);
        put_u32(&mut bytes, import_dir + 4, 20); // declared size stays sane
        bytes
    }

    fn importless_parse(bytes: &[u8]) -> PE<'_> {
        let opts = goblin::pe::options::ParseOptions::default()
            .with_parse_mode(goblin::options::ParseMode::Permissive)
            .with_parse_imports(false);
        PE::parse_with_opts(bytes, &opts).expect("import-less permissive parse")
    }

    #[test]
    fn import_walk_budget_accepts_a_real_pe() {
        let bytes = read_fixture("test.exe");
        let pe = PE::parse(&bytes).expect("fixture PE");
        assert!(
            import_walk_budget(&bytes, &pe).is_ok(),
            "a linker-produced import table must stay within budget"
        );
    }

    #[test]
    fn import_walk_budget_rejects_too_many_descriptors() {
        let bytes = pe_with_forged_import_directory(MAX_IMPORT_DESCRIPTORS + 1, false);
        let pe = importless_parse(&bytes);
        let err = import_walk_budget(&bytes, &pe).expect_err("descriptor cap must trip");
        assert_eq!(err, Rejection::UnterminatedImportDirectory);
    }

    /// The quadratic the bound exists for: a descriptor count a cap on
    /// descriptors alone would wave through, each re-walking a lookup table
    /// hundreds of thousands of entries long.
    #[test]
    fn import_walk_budget_rejects_oversized_lookup_tables() {
        let bytes = pe_with_forged_import_directory(8, true);
        let pe = importless_parse(&bytes);
        let err = import_walk_budget(&bytes, &pe).expect_err("entry budget must trip");
        assert_eq!(err, Rejection::OversizedImportLookupTables);
    }

    /// The bound has to be wired into `parse_pe`, not merely available: a
    /// forged table must cost the imports and nothing else.
    #[test]
    fn parse_pe_drops_a_forged_import_table_and_keeps_the_rest() {
        let bytes = pe_with_forged_import_directory(8, true);
        let parse = parse_pe(&bytes);
        assert_eq!(
            parse.imports_skipped,
            Some(Rejection::OversizedImportLookupTables),
            "parse_pe must report the abandoned import table"
        );
        let pe = parse
            .outcome
            .ok()
            .expect("headers and sections still parse");
        assert!(
            pe.imports.is_empty(),
            "the forged import table must not be synthesized"
        );
        assert!(
            !pe.sections.is_empty(),
            "dropping imports must not cost us the section table"
        );
        assert!(
            pe.header.optional_header.is_some(),
            "dropping imports must not cost us the optional header"
        );
    }

    #[test]
    fn validate_rejects_oversized_section_count() {
        let mut data = vec![0u8; 1024];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        // n_sections = 0x00FF = 255 (>192 threshold).
        data[0x46] = 0xFF;
        assert_eq!(
            validate_pe_header(&data),
            Err(Rejection::TooManySections(255))
        );
    }

    #[test]
    fn validate_rejects_oversized_import_table() {
        let mut data = vec![0u8; 1024];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x46] = 1; // n_sections = 1
        data[0x58] = 0x0B;
        data[0x59] = 0x01; // PE32 magic
        data[0x40 + 24 + 92] = 16; // n_dirs = 16
        let import_size_ptr = 0x40 + 24 + 96 + 8 + 4;
        data[import_size_ptr + 3] = 0x01; // size = 16 MiB (>10 MiB cap)
        assert_eq!(
            validate_pe_header(&data),
            Err(Rejection::OversizedDirectory {
                table: "import",
                size: 16 << 20,
            })
        );
    }

    /// The reasons land verbatim in the structured errors view, so the typed
    /// enum must render exactly the text the old `String` reasons carried.
    #[test]
    fn rejection_messages_are_unchanged() {
        for (reason, text) in [
            (Rejection::TooManySections(255), "too many sections (255)"),
            (
                Rejection::TooManyDataDirectories(17),
                "too many data directories (17)",
            ),
            (
                Rejection::OversizedDirectory {
                    table: "resource",
                    size: 16 << 20,
                },
                "malformed resource table size (16777216 bytes)",
            ),
            (
                Rejection::UnterminatedImportDirectory,
                "import directory exceeds 256 descriptors without terminating",
            ),
            (
                Rejection::OversizedImportLookupTables,
                "import lookup tables exceed 262144 entries",
            ),
            (
                Rejection::ExportTrieLoop {
                    node: 0x20,
                    start: 0x10,
                    end: 0x40,
                },
                "export trie loops back to node 0x20 (trie 0x10..0x40)",
            ),
            (
                Rejection::ExportTrieBranches {
                    node: 0,
                    branches: 100,
                    available: 4,
                },
                "export trie node 0x0 claims 100 branches in 4 bytes",
            ),
        ] {
            assert_eq!(reason.to_string(), text);
        }
    }

    #[test]
    fn parse_pe_header_handles_garbage_and_real_headers() {
        assert!(matches!(
            parse_pe_header(b"not a PE file at all"),
            GoblinOutcome::Failed(_)
        ));
        let bytes = read_fixture("test.exe");
        let header = parse_pe_header(&bytes).ok().expect("fixture headers parse");
        assert!(header.optional_header.is_some());
    }

    #[test]
    fn parse_macho_slice_handles_garbage_and_real_slices() {
        assert!(matches!(
            parse_macho_slice(b"not a Mach-O"),
            GoblinOutcome::Failed(_)
        ));
        let bytes = read_fixture("test.macho");
        let macho = parse_macho_slice(&bytes).ok().expect("thin fixture parses");
        assert!(!macho.load_commands.is_empty());
    }

    #[test]
    fn drain_runs_a_lazy_walk_to_completion() {
        let bytes = read_fixture("test.elf");
        let elf = Elf::parse(&bytes).expect("fixture ELF");
        let notes = drain(
            elf.iter_note_headers(&bytes)
                .into_iter()
                .flatten()
                .flatten(),
        )
        .ok()
        .expect("note walk completes");
        // The fixture's single PT_NOTE carries its GNU build-id.
        assert_eq!(notes.len(), 1);
        assert_eq!((notes[0].name, notes[0].n_type), ("GNU", 3));
    }

    #[test]
    fn drain_or_record_reports_a_walk_that_panics() {
        let walk = (0..4).map(|i| if i == 2 { panic!("walker tripped") } else { i });
        let mut errors = Errors::new();
        assert!(drain_or_record(walk, &mut errors, Stage::PeParse).is_empty());
        let recorded = errors.as_slice();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].stage, Stage::PeParse);
        assert!(recorded[0].message.contains("walker tripped"));

        let mut errors = Errors::new();
        assert_eq!(
            drain_or_record(0..3, &mut errors, Stage::PeParse),
            vec![0, 1, 2]
        );
        assert!(errors.as_slice().is_empty());
    }

    #[test]
    fn validate_accepts_too_short_to_be_pe() {
        // Anything below 64 bytes can't possibly be a parseable PE;
        // hand the bytes to goblin without flagging.
        assert!(validate_pe_header(&[]).is_ok());
        assert!(validate_pe_header(&[0u8; 16]).is_ok());
    }

    #[test]
    fn validate_accepts_non_pe_bytes() {
        // Bytes that don't start with MZ get through — the caller's
        // strict parse will report a clean error.
        let data = vec![0u8; 256];
        assert!(validate_pe_header(&data).is_ok());
    }

    #[test]
    fn catch_returns_ok_for_passing_call() {
        let result: GoblinOutcome<i32> = catch(|| Ok(42));
        assert!(matches!(result, GoblinOutcome::Ok(42)));
    }

    #[test]
    fn catch_returns_failed_on_error() {
        let result: GoblinOutcome<i32> = catch(|| Err(GoblinError::Malformed("nope".into())));
        assert!(matches!(result, GoblinOutcome::Failed(_)));
    }

    #[test]
    fn catch_converts_panic_to_outcome() {
        let result: GoblinOutcome<i32> = catch(|| -> Result<i32, GoblinError> { panic!("boom") });
        match result {
            GoblinOutcome::Panicked(msg) => assert!(msg.contains("boom")),
            other => panic!("expected Panicked, got {other:?}"),
        }
    }

    #[test]
    fn catch_infallible_handles_clean_value() {
        let result: GoblinOutcome<&str> = catch_infallible(|| "ok");
        assert!(matches!(result, GoblinOutcome::Ok("ok")));
    }

    #[test]
    fn catch_infallible_catches_lazy_walker_panic() {
        let result: GoblinOutcome<()> = catch_infallible(|| panic!("walker tripped"));
        match result {
            GoblinOutcome::Panicked(msg) => assert!(msg.contains("walker tripped")),
            other => panic!("expected Panicked, got {other:?}"),
        }
    }

    #[test]
    fn parse_pe_rejects_garbage() {
        let result = parse_pe(b"not a PE file at all").outcome;
        match result {
            GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_) => {}
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn parse_pe_short_input_falls_through_to_goblin() {
        // Below the 64-byte gate, validate_pe_header returns Ok and
        // we hand the bytes straight to goblin, which fails cleanly.
        let result = parse_pe(&[0u8; 16]).outcome;
        assert!(matches!(
            result,
            GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_)
        ));
    }

    #[test]
    fn parse_elf_handles_garbage() {
        let result = parse_elf(b"not an ELF");
        assert!(matches!(
            result,
            GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_)
        ));
    }

    #[test]
    fn parse_mach_handles_garbage() {
        let result = parse_mach(b"not a Mach-O");
        assert!(matches!(
            result,
            GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_)
        ));
    }

    /// A two-node trie as a linker emits it: a non-terminal root with one
    /// edge `_a` to a terminal leaf (flags 0, address 0x10, no children).
    const WELL_FORMED_TRIE: &[u8] = &[
        0x00, 0x01, b'_', b'a', 0x00, 0x06, // root @0: 1 branch, child @6
        0x02, 0x00, 0x10, 0x00, // leaf @6: terminal, no children
    ];

    #[test]
    fn export_trie_accepts_well_formed() {
        assert!(validate_export_trie_bytes(WELL_FORMED_TRIE, 0, WELL_FORMED_TRIE.len()).is_ok());
        // Embedded past a header, as in a real file.
        let mut file = vec![0xAAu8; 64];
        file.extend_from_slice(WELL_FORMED_TRIE);
        assert!(validate_export_trie_bytes(&file, 64, WELL_FORMED_TRIE.len()).is_ok());
    }

    /// The leptris shape: the root's only edge points back at the root, so
    /// goblin's walk never ends. llvm-objdump: "loop in children in export
    /// trie data at node: 0x0 back to node: 0x0".
    #[test]
    fn export_trie_rejects_root_self_loop() {
        let trie = [0x00, 0x01, b'_', b'a', 0x00, 0x00];
        let err = validate_export_trie_bytes(&trie, 0, trie.len()).expect_err("loop must trip");
        assert!(
            matches!(err, Rejection::ExportTrieLoop { node: 0, .. }),
            "unexpected reason: {err}"
        );
    }

    #[test]
    fn export_trie_rejects_deep_cycle() {
        // root -> leaf, and the leaf (terminal with one child) points at root.
        let trie = [
            0x00, 0x01, b'_', b'a', 0x00, 0x06, // root @0 -> @6
            0x02, 0x00, 0x10, 0x01, b'b', 0x00, 0x00, // leaf @6, 1 child -> @0
        ];
        assert!(validate_export_trie_bytes(&trie, 0, trie.len()).is_err());
    }

    #[test]
    fn export_trie_rejects_forged_branch_count() {
        // Root claims 100 branches in a 6-byte trie.
        let trie = [0x00, 0x64, b'_', b'a', 0x00, 0x06];
        let err = validate_export_trie_bytes(&trie, 0, trie.len()).expect_err("count must trip");
        assert!(
            matches!(err, Rejection::ExportTrieBranches { branches: 100, .. }),
            "unexpected reason: {err}"
        );
    }

    #[test]
    fn export_trie_waves_through_what_goblin_rejects() {
        // Range past the file: goblin treats it as an empty trie.
        assert!(validate_export_trie_bytes(WELL_FORMED_TRIE, 4, 100).is_ok());
        assert!(validate_export_trie_bytes(&[], 0, 0).is_ok());
        // Truncated ULEB / label: goblin's own Err is the report.
        assert!(validate_export_trie_bytes(&[0x00, 0x01, b'_'], 0, 3).is_ok());
        assert!(validate_export_trie_bytes(&[0x80], 0, 1).is_ok());
    }

    /// A header cut off inside `e_shstrndx`, the last field zeroed, used to
    /// panic slicing the patched copy: every field the helper reads is in
    /// bounds, but the one it then writes is not.
    #[test]
    fn elf_detach_rejects_header_truncated_in_shstrndx() {
        // (EI_CLASS, e_shoff, e_shentsize, e_shnum, e_shstrndx) offsets.
        for (class, shoff_at, shentsize_at, shnum_at, shstrndx_at) in
            [(2u8, 0x28, 0x3A, 0x3C, 0x3E), (1, 0x20, 0x2E, 0x30, 0x32)]
        {
            let mut header = vec![0u8; shstrndx_at + 2];
            header[..4].copy_from_slice(b"\x7fELF");
            header[4] = class;
            header[5] = 1; // little-endian
            header[shoff_at] = 0x10;
            header[shentsize_at] = 0x40;
            header[shnum_at] = 5;
            header[shstrndx_at] = 3;
            // Section table at 0x10 + 5 * 0x40 ends past EOF: detach it.
            let patched = elf_without_truncated_section_headers(&header).expect("detached");
            assert_eq!(
                [patched[shoff_at], patched[shnum_at], patched[shstrndx_at]],
                [0, 0, 0]
            );
            assert_eq!(patched[shentsize_at], 0x40);
            for len in [shstrndx_at, shstrndx_at + 1] {
                assert_eq!(elf_without_truncated_section_headers(&header[..len]), None);
            }
        }
    }

    #[test]
    fn uleb128_matches_scroll() {
        let mut off = 0;
        assert_eq!(read_uleb128(&[0xE5, 0x8E, 0x26], &mut off), Some(624_485));
        assert_eq!(off, 3);
        let mut off = 0;
        assert_eq!(read_uleb128(&[0x80], &mut off), None);
        let mut off = 0;
        assert_eq!(read_uleb128(&[0xff; 11], &mut off), None);
    }
}
