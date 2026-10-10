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
    /// Import names, summed over every lookup entry, past budget.
    OversizedImportNames,
    /// Export and forwarder names, summed over every name pointer, past
    /// budget.
    OversizedExportNames,
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
    /// An export-trie path deeper than [`MAX_EXPORT_TRIE_DEPTH`] nodes.
    ExportTrieTooDeep { node: usize, depth: usize },
    /// Mach-O bind opcodes that would make goblin synthesize more imports
    /// than [`MAX_MACHO_BIND_IMPORTS`].
    OversizedBindStream { stream: &'static str, imports: u64 },
    /// Mach-O bind opcodes that bind through a dylib ordinal or segment index
    /// past the binary's own tables, which goblin indexes without a check.
    BindIndexOutOfRange {
        stream: &'static str,
        table: &'static str,
        index: u64,
        len: usize,
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
            Self::OversizedImportNames => {
                write!(f, "import names exceed {MAX_SYMBOL_NAME_BYTES} bytes")
            }
            Self::OversizedExportNames => {
                write!(f, "export names exceed {MAX_SYMBOL_NAME_BYTES} bytes")
            }
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
            Self::ExportTrieTooDeep { node, depth } => write!(
                f,
                "export trie reaches node {node:#x} at depth {depth}, past {MAX_EXPORT_TRIE_DEPTH}"
            ),
            Self::OversizedBindStream { stream, imports } => write!(
                f,
                "{stream} bind opcodes declare at least {imports} imports, past {MAX_MACHO_BIND_IMPORTS}"
            ),
            Self::BindIndexOutOfRange {
                stream,
                table,
                index,
                len,
            } => write!(
                f,
                "{stream} bind opcodes bind through {table} {index} of {len}"
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

// Every guard in this module, and the per-stage guards in `lib.rs`, turn a
// parser panic into a recorded error by unwinding. Under `panic = "abort"`
// `catch_unwind` catches nothing and one malformed file kills the host
// process, so refuse to build that way rather than silently lose the
// guarantee.
#[cfg(panic = "abort")]
compile_error!(
    "filefacts requires `panic = \"unwind\"`: hostile inputs make its parsers panic, and \
     those panics are caught with `catch_unwind` and reported as errors. With \
     `panic = \"abort\"` a single malformed file would abort the whole process."
);

thread_local! {
    static SUPPRESS_PANIC_OUTPUT: Cell<bool> = const { Cell::new(false) };
}

/// Install a process-wide panic hook (once) that swallows panic
/// messages from threads that opted into suppression. Replaces the
/// older `take_hook` / `set_hook` swap pattern (which required a
/// global Mutex to serialize swaps) with a single, race-free install.
///
/// This is deliberately process-global — a panic hook cannot be anything
/// else — but it is installed at most once and only filters: it chains to
/// whatever hook was installed before it (the host's, or std's default), and
/// silences a panic only while the panicking thread is inside one of this
/// module's guards. Panics anywhere else reach the previous hook untouched.
/// A host that installs its own hook *after* filefacts' first parse replaces
/// this one, which costs only the suppression of expected parser panics.
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

    /// Puts back the flag as the guard found it, so a guard nested inside
    /// another leaves the outer one still suppressing when it returns.
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            SUPPRESS_PANIC_OUTPUT.with(|flag| flag.set(self.0));
        }
    }

    let _restore = Restore(SUPPRESS_PANIC_OUTPUT.with(|flag| flag.replace(true)));
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
/// The import directory is budgeted first (see [`import_walk_budget`]); an
/// over-budget one is dropped and everything else parsed. Otherwise strict
/// mode is tried; if it fails OR panics, the call is retried with
/// `ParseMode::Permissive`. Returns the strict failure only when the
/// permissive retry itself panicked (in which case the strict error is the
/// more actionable signal).
pub(crate) fn parse_pe(data: &[u8]) -> PeParse<'_> {
    if let Err(e) = validate_pe_header(data) {
        return PeParse::parsed(GoblinOutcome::Failed(GoblinError::Malformed(e.to_string())));
    }

    let base_opts = goblin::pe::options::ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive);

    // Budget the import walk before any full parse. Strict mode is not safe
    // from it either: a few hundred well-formed descriptors that all share one
    // long table of ordinal entries make goblin synthesize descriptors x
    // entries imports, each with its own `format!("ORDINAL n")`, which is
    // billions from a megabyte. Only the headers and section table are needed
    // to resolve the directory the way goblin will, and those are cheap.
    if let Err(reason) = import_walk_budget_from_headers(data) {
        // A forged import directory. Keep every other fact (headers, sections,
        // exports, resources, Authenticode) rather than failing the whole PE:
        // an unwalkable import table is itself a signal, not a reason to go
        // blind on the sample. With imports off the parse is bounded.
        let importless_opts = base_opts.with_parse_imports(false);
        return PeParse {
            outcome: catch(|| PE::parse_with_opts(data, &importless_opts)),
            imports_skipped: Some(reason),
        };
    }

    let strict = catch(|| PE::parse(data));
    if matches!(strict, GoblinOutcome::Ok(_)) {
        return PeParse::parsed(strict);
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

/// Name bytes goblin may be asked to read across one import or export table.
///
/// goblin reads each lookup entry's or name pointer's string afresh, scanning
/// to its NUL, and filefacts then copies each into its symbol view. Neither
/// the entry budget nor the file size bounds that product: a quarter-million
/// entries may all point at one name a megabyte long, a quarter of a terabyte
/// to scan and to copy from a file of a few megabytes. Real tables total well
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

/// Decide whether goblin's import walk over `data` is bounded, in either
/// parse mode.
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
/// parked on a join latch behind it, taking the whole process down. Strict
/// mode is exposed too: well-formed descriptors may all share one long lookup
/// table, and goblin materialises an `Import` per descriptor per entry.
///
/// goblin offers no cap of its own (`ParseOptions::parse_imports` is
/// all-or-nothing), so this walks the same structure first, using goblin's own
/// `find_offset` so the traversal agrees with the one being budgeted, but
/// without the allocation, name parsing, or logging that makes goblin's
/// version orders of magnitude more expensive per entry. It reads at most
/// `MAX_IMPORT_LOOKUP_ENTRIES` entries, and [`MAX_SYMBOL_NAME_BYTES`] of the
/// hint/name strings they point at, before giving its answer.
///
/// Fails open: anything it cannot resolve counts as within budget, so a PE
/// shape this pre-walk does not model keeps exactly today's behaviour.
fn import_walk_budget(
    data: &[u8],
    sections: &[goblin::pe::section_table::SectionTable],
    optional_header: &goblin::pe::optional_header::OptionalHeader,
) -> Result<(), Rejection> {
    use goblin::pe::import::SIZEOF_IMPORT_DIRECTORY_ENTRY;
    use goblin::pe::options::ParseOptions;

    let Some(import_table) = optional_header.data_directories.get_import_table() else {
        return Ok(());
    };
    let file_alignment = optional_header.windows_fields.file_alignment;
    // PE32 lookup entries are 4 bytes, PE32+ are 8: the optional-header magic
    // is the same bit goblin's `is_64` reads to pick the `Bitfield` width it
    // walks the table with.
    let entry_size =
        if optional_header.standard_fields.magic == goblin::pe::optional_header::MAGIC_64 {
            8
        } else {
            4
        };
    let opts = ParseOptions::default().with_parse_mode(goblin::options::ParseMode::Permissive);

    let resolve =
        |rva: u32| goblin::pe::utils::find_offset(rva as usize, sections, file_alignment, &opts);

    let Some(mut offset) = resolve(import_table.virtual_address) else {
        return Ok(());
    };

    let mut descriptors = 0usize;
    let mut entries = 0usize;
    let mut name_bytes = 0usize;
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
                // A clear top bit names a hint/name entry, whose string goblin
                // reads past the two-byte hint (`Bitfield::to_rva`).
                let value = entry
                    .iter()
                    .rev()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                let by_ordinal = value >> (entry_size * 8 - 1) != 0;
                if !by_ordinal && let Some(at) = resolve(crate::bytes::sat_u32(value & 0x7fff_ffff))
                {
                    let left = MAX_SYMBOL_NAME_BYTES - name_bytes;
                    let Some(len) = name_len(data, at.saturating_add(2), left) else {
                        return Err(Rejection::OversizedImportNames);
                    };
                    name_bytes += len;
                }
                cursor += entry_size;
            }
        }

        offset += SIZEOF_IMPORT_DIRECTORY_ENTRY;
    }

    Ok(())
}

/// [`import_walk_budget`] over the headers and section table alone, read the
/// way `PE::parse` reads them. Fails open when those do not parse: the full
/// parse will then fail on the same bytes before it reaches the imports.
fn import_walk_budget_from_headers(data: &[u8]) -> Result<(), Rejection> {
    use goblin::pe::header::{SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
    let GoblinOutcome::Ok(header) = parse_pe_header(data) else {
        return Ok(());
    };
    let Some(optional_header) = header.optional_header else {
        return Ok(());
    };
    let mut offset = (header.dos_header.pe_pointer as usize)
        .saturating_add(SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER)
        .saturating_add(usize::from(header.coff_header.size_of_optional_header));
    let GoblinOutcome::Ok(sections) = catch(|| header.coff_header.sections(data, &mut offset))
    else {
        return Ok(());
    };
    import_walk_budget(data, &sections, &optional_header)
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
/// Fails open like [`import_walk_budget`]: a table goblin would itself reject
/// or cannot resolve counts as within budget.
fn export_walk_budget(
    data: &[u8],
    sections: &[goblin::pe::section_table::SectionTable],
    optional_header: &goblin::pe::optional_header::OptionalHeader,
) -> Result<(), Rejection> {
    use goblin::pe::options::ParseOptions;

    let Some(export_table) = optional_header.data_directories.get_export_table() else {
        return Ok(());
    };
    let file_alignment = optional_header.windows_fields.file_alignment;
    let opts = ParseOptions::default().with_parse_mode(goblin::options::ParseMode::Permissive);
    let resolve =
        |rva: u32| goblin::pe::utils::find_offset(rva as usize, sections, file_alignment, &opts);

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
    let (address_entries, name_pointers) = (
        crate::bytes::sat_usize(address_entries),
        crate::bytes::sat_usize(name_pointers),
    );
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
            .and_then(|(ordinal, table)| u32_le(data, table.saturating_add(ordinal * 4)))
            .filter(|&rva| forwarders.contains(&u64::from(rva)));
        count(forwarder.and_then(resolve))?;
    }
    Ok(())
}

/// A copy of `data` with the export data directory cleared, when goblin's
/// export walk would exceed [`export_walk_budget`]; `None` otherwise, so the
/// common path never copies. Clearing the slot is the only way to keep goblin
/// off the table while it parses everything else: the caller then reports the
/// rejection, and keeps reading the untouched bytes for everything goblin
/// does not parse.
pub(crate) fn neutralize_oversized_export_directory(data: &[u8]) -> Option<(Vec<u8>, Rejection)> {
    use goblin::pe::header::{SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
    let GoblinOutcome::Ok(header) = parse_pe_header(data) else {
        return None;
    };
    let optional_header = header.optional_header?;
    let optional_offset = (header.dos_header.pe_pointer as usize)
        .saturating_add(SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER);
    let mut offset =
        optional_offset.saturating_add(usize::from(header.coff_header.size_of_optional_header));
    let GoblinOutcome::Ok(sections) = catch(|| header.coff_header.sections(data, &mut offset))
    else {
        return None;
    };
    let reason = export_walk_budget(data, &sections, &optional_header).err()?;
    // The data-directory array opens the optional header's tail; the export
    // directory is its first slot.
    let slot = optional_offset.saturating_add(
        if optional_header.standard_fields.magic == goblin::pe::optional_header::MAGIC_64 {
            112
        } else {
            96
        },
    );
    let mut patched = data.to_vec();
    patched.get_mut(slot..slot.saturating_add(8))?.fill(0);
    Some((patched, reason))
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
    let rich = super::pe_rich::locate(data)?;
    // A decodable DanS marker means the header is well-formed and goblin
    // will parse it without complaint.
    if rich.dans_pos.is_some() {
        return None;
    }
    // No DanS table reachable — goblin would abort. Hand back a copy with
    // the `Rich` magic cleared so its marker scan finds nothing.
    let mut patched = data.to_vec();
    patched.get_mut(rich.rich_pos..rich.rich_pos + 4)?.fill(0);
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
        if n_dirs as usize > i {
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
/// The walk is also recursive, so an acyclic but deep trie — a straight chain
/// of five-byte nodes with empty edge labels — exhausts the stack instead: a
/// 25 KiB trie is enough on a 2 MiB worker thread, and a stack overflow aborts
/// the process just as surely as the out-of-memory case.
///
/// This walks the same nodes goblin will, iteratively, and refuses the trie on
/// the first revisited node, branch count the trie cannot hold, or path
/// deeper than [`MAX_EXPORT_TRIE_DEPTH`]. Anything
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

/// Deepest export-trie path [`validate_export_trie`] lets goblin recurse
/// into. dyld's own trie lookup gives up at 128 nodes, so no binary the loader
/// accepts needs more, and goblin's three frames per level stay far inside a
/// 2 MiB worker stack at this depth.
pub(crate) const MAX_EXPORT_TRIE_DEPTH: usize = 128;

/// [`validate_export_trie`] on an explicit trie range; the walk itself.
fn validate_export_trie_bytes(bytes: &[u8], start: usize, size: usize) -> Result<(), Rejection> {
    // goblin's `new_impl` collapses an out-of-file range to an empty trie.
    let Some(end) = start.checked_add(size).filter(|end| *end <= bytes.len()) else {
        return Ok(());
    };
    // One flag per byte of the trie: a node is at least one byte, so the
    // visited set is bounded by the trie's own size.
    let mut visited = vec![false; size];
    let mut pending = vec![(start, 1usize)];
    while let Some((node, depth)) = pending.pop() {
        // goblin's `walk_trie` returns Ok for a node at or past the end.
        if node >= end {
            continue;
        }
        if depth > MAX_EXPORT_TRIE_DEPTH {
            return Err(Rejection::ExportTrieTooDeep { node, depth });
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
            let Some(next) = offset.checked_add(crate::bytes::sat_usize(terminal_size)) else {
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
            pending.push((child, depth + 1));
        }
    }
    Ok(())
}

/// Imports goblin's bind interpreter may synthesize across a Mach-O's bind
/// and lazy-bind streams. Each costs an `Import` (about 100 bytes) plus a
/// symbol downstream; the largest frameworks bind tens of thousands of slots,
/// so this is generous for real binaries and still bounds the allocation.
pub(crate) const MAX_MACHO_BIND_IMPORTS: u64 = 256 * 1024;

/// Pre-validate the dyld bind opcodes before `macho.imports()` runs them.
///
/// goblin's `BindInterpreter::run` (mach/imports.rs, 0.10.7) executes
/// `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` as `for _ in 0..count {
/// imports.push(..) }` with `count` read straight from a ULEB, so the seven
/// bytes `C0 FF FF FF FF 0F 00` ask for four billion imports. The process runs out of
/// memory long before anything panics, and an allocation failure aborts rather
/// than unwinding, so [`catch`] cannot contain it.
///
/// This replays the same opcode streams goblin will (the last `LC_DYLD_INFO`
/// or `LC_DYLD_INFO_ONLY` wins, bind stream then lazy-bind stream) and counts
/// the imports they would produce without materialising any. A stream goblin
/// would itself reject (a truncated ULEB or symbol name) is waved through:
/// goblin stops there with its own `Err`.
pub(crate) fn validate_bind_opcodes(macho: &MachO<'_>, bytes: &[u8]) -> Result<(), Rejection> {
    use goblin::mach::load_command::CommandVariant;
    let mut streams = None;
    for lc in &macho.load_commands {
        if let CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) = &lc.command {
            streams = Some([
                ("bind", c.bind_off as usize, c.bind_size as usize),
                ("lazy", c.lazy_bind_off as usize, c.lazy_bind_size as usize),
            ]);
        }
    }
    let tables = BindTables {
        libs: macho.libs.len(),
        segments: macho.segments.len(),
    };
    let mut imports = 0u64;
    for (stream, off, size) in streams.into_iter().flatten() {
        imports = walk_bind_stream(bytes, off, off.saturating_add(size), imports, tables).map_err(
            |(table, index, len)| Rejection::BindIndexOutOfRange {
                stream,
                table,
                index,
                len,
            },
        )?;
        if imports > MAX_MACHO_BIND_IMPORTS {
            return Err(Rejection::OversizedBindStream { stream, imports });
        }
    }
    Ok(())
}

/// A ULEB dylib ordinal as goblin's interpreter stores it: its low byte.
#[expect(
    clippy::cast_possible_truncation,
    reason = "goblin truncates the ordinal to u8; the walk must index what goblin will"
)]
fn goblin_ordinal(value: u64) -> u8 {
    value as u8
}

/// The table sizes a bind stream's indices must stay within.
#[derive(Clone, Copy)]
struct BindTables {
    libs: usize,
    segments: usize,
}

/// Add the imports one bind-opcode stream at `start..end` would produce to
/// `imports`, stopping as soon as the total passes the budget. Unbounded
/// tables: only the count matters.
#[cfg(test)]
fn count_bind_imports(bytes: &[u8], start: usize, end: usize, imports: u64) -> u64 {
    let unbounded = BindTables {
        libs: usize::MAX,
        segments: usize::MAX,
    };
    walk_bind_stream(bytes, start, end, imports, unbounded).unwrap_or(imports)
}

/// Replay one bind-opcode stream at `start..end` as goblin's interpreter
/// does, adding the imports it would produce to `imports`. Each import
/// goblin builds indexes `libs[ordinal]` and `segments[segment]` unchecked,
/// so a bind through either past `tables` is returned as
/// `(table, index, len)` instead.
fn walk_bind_stream(
    bytes: &[u8],
    start: usize,
    end: usize,
    mut imports: u64,
    tables: BindTables,
) -> Result<u64, (&'static str, u64, usize)> {
    use goblin::mach::bind_opcodes::{
        BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
        BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_MASK,
        BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
        BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    };
    // goblin's `BindInformation` state: both start at 0, and `DONE` resets
    // them. The ULEB ordinal is truncated to `u8`, as goblin stores it.
    let mut ordinal: u8 = 0;
    let mut segment: u8 = 0;
    let bind = |imports: u64, ordinal: u8, segment: u8| {
        if usize::from(ordinal) >= tables.libs {
            return Err(("dylib ordinal", u64::from(ordinal), tables.libs));
        }
        if usize::from(segment) >= tables.segments {
            return Err(("segment", u64::from(segment), tables.segments));
        }
        Ok(imports)
    };
    let mut offset = start;
    while offset < end && imports <= MAX_MACHO_BIND_IMPORTS {
        let Some(&opcode) = bytes.get(offset) else {
            break;
        };
        offset += 1;
        let immediate = opcode & BIND_IMMEDIATE_MASK;
        let operand = match opcode & BIND_OPCODE_MASK {
            BIND_OPCODE_DONE => {
                ordinal = 0;
                segment = 0;
                Some(())
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                ordinal = immediate;
                Some(())
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => read_uleb128(bytes, &mut offset).map(|value| {
                ordinal = goblin_ordinal(value);
            }),
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment = immediate;
                read_uleb128(bytes, &mut offset).map(|_| ())
            }
            BIND_OPCODE_ADD_ADDR_ULEB => read_uleb128(bytes, &mut offset).map(|_| ()),
            // SLEB and ULEB share the continuation-bit framing.
            BIND_OPCODE_SET_ADDEND_SLEB => read_uleb128(bytes, &mut offset).map(|_| ()),
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => bytes
                .get(offset..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
                .map(|len| offset += len + 1),
            BIND_OPCODE_DO_BIND | BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                imports = bind(imports, ordinal, segment)? + 1;
                Some(())
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                imports = bind(imports, ordinal, segment)? + 1;
                read_uleb128(bytes, &mut offset).map(|_| ())
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let Some(count) = read_uleb128(bytes, &mut offset) else {
                    break;
                };
                // goblin reads the skip before pushing anything, and pushes
                // nothing, so indexes nothing, for a count of 0.
                if read_uleb128(bytes, &mut offset).is_none() {
                    break;
                }
                if count > 0 {
                    imports = bind(imports, ordinal, segment)?;
                }
                imports = imports.saturating_add(count);
                Some(())
            }
            _ => Some(()),
        };
        if operand.is_none() {
            // goblin's own read fails here and ends the walk with `Err`.
            break;
        }
    }
    Ok(imports)
}

#[cfg(test)]
pub(crate) mod tests;
