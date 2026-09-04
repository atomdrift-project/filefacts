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
//! | `Elf::parse(...)`                                      | [`parse_elf`]          |
//! | `Mach::parse(...)`                                     | [`parse_mach`]         |
//! | A `Result<T, goblin::error::Error>` you call later     | [`catch`]              |
//! | A non-`Result` lazy access (e.g. `resource_data.count()`) | [`catch_infallible`] |
//!
//! `parse_pe` already does the strict→permissive fallback internally;
//! callers should not reach for `PE::parse_with_opts` directly.

use goblin::elf::Elf;
use goblin::error::Error as GoblinError;
use goblin::mach::Mach;
use goblin::pe::PE;
use std::cell::Cell;
use std::panic;
use std::sync::Once;

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
    pub(crate) imports_skipped: Option<String>,
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
        return PeParse::parsed(GoblinOutcome::Failed(GoblinError::Malformed(e)));
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
fn import_walk_budget(data: &[u8], pe: &PE<'_>) -> Result<(), String> {
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
        let word = |i: usize| -> u32 {
            let at = offset + i * 4;
            u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
        };
        let (lookup_rva, name_rva, address_rva) = (word(0), word(3), word(4));
        let is_null = (0..5).all(|i| word(i) == 0);
        // Mirrors `ImportDirectoryEntry::is_possibly_valid`.
        let is_possibly_valid = name_rva != 0 && address_rva != 0;
        if is_null || !is_possibly_valid {
            return Ok(());
        }

        descriptors += 1;
        if descriptors > MAX_IMPORT_DESCRIPTORS {
            return Err(format!(
                "import directory exceeds {MAX_IMPORT_DESCRIPTORS} descriptors without terminating"
            ));
        }

        // goblin prefers the lookup table and falls back to the address table.
        if let Some(mut cursor) = resolve(lookup_rva).or_else(|| resolve(address_rva)) {
            while cursor + entry_size <= data.len() {
                if data[cursor..cursor + entry_size].iter().all(|&b| b == 0) {
                    break;
                }
                entries += 1;
                if entries > MAX_IMPORT_LOOKUP_ENTRIES {
                    return Err(format!(
                        "import lookup tables exceed {MAX_IMPORT_LOOKUP_ENTRIES} entries"
                    ));
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
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let scan_end = e_lfanew.min(data.len());
    if scan_end < 8 {
        return None;
    }
    let rich_pos = data[..scan_end].windows(4).rposition(|w| w == RICH_MAGIC)?;
    if rich_pos + 8 > data.len() {
        return None;
    }
    let key = u32::from_le_bytes([
        data[rich_pos + 4],
        data[rich_pos + 5],
        data[rich_pos + 6],
        data[rich_pos + 7],
    ]);
    // Walk backwards in 4-byte words: a decodable DanS marker means the
    // header is well-formed and goblin will parse it without complaint.
    let mut pos = rich_pos;
    while pos >= 4 {
        pos -= 4;
        let word = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if word ^ key == DANS_MARKER {
            return None;
        }
    }
    // No DanS table reachable — goblin would abort. Hand back a copy with
    // the `Rich` magic cleared so its marker scan finds nothing.
    let mut patched = data.to_vec();
    patched[rich_pos..rich_pos + 4].fill(0);
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
fn validate_pe_header(data: &[u8]) -> Result<(), String> {
    if data.len() < 64 {
        return Ok(());
    }

    if data[0] != b'M' || data[1] != b'Z' {
        return Ok(());
    }

    let pe_ptr_offset = 0x3C;
    let pe_offset = u32::from_le_bytes([
        data[pe_ptr_offset],
        data[pe_ptr_offset + 1],
        data[pe_ptr_offset + 2],
        data[pe_ptr_offset + 3],
    ]) as usize;

    if pe_offset + 24 > data.len() {
        return Ok(());
    }
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Ok(());
    }

    let coff_offset = pe_offset + 4;
    let n_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    if n_sections > 192 {
        return Err(format!("too many sections ({n_sections})"));
    }

    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return Ok(());
    }

    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let (data_dir_count_offset, data_dir_offset) = match magic {
        0x010b => (92, 96),   // PE32
        0x020b => (108, 112), // PE32+
        _ => return Ok(()),
    };

    let dir_count_ptr = opt_offset + data_dir_count_offset;
    if dir_count_ptr + 4 > data.len() {
        return Ok(());
    }

    let n_dirs = u32::from_le_bytes([
        data[dir_count_ptr],
        data[dir_count_ptr + 1],
        data[dir_count_ptr + 2],
        data[dir_count_ptr + 3],
    ]);

    if n_dirs > 16 {
        return Err(format!("too many data directories ({n_dirs})"));
    }

    // Check the Imports (idx 1) and Resources (idx 2) data
    // directories specifically — they're the two whose forged
    // `size` field most reliably blows up goblin.
    for i in 1..=2 {
        if n_dirs > i as u32 {
            let dir_ptr = opt_offset + data_dir_offset + (i * 8);
            if dir_ptr + 8 <= data.len() {
                let size = u32::from_le_bytes([
                    data[dir_ptr + 4],
                    data[dir_ptr + 5],
                    data[dir_ptr + 6],
                    data[dir_ptr + 7],
                ]);
                if size > 10 * 1024 * 1024 || size as usize > data.len() {
                    let name = if i == 1 { "import" } else { "resource" };
                    return Err(format!("malformed {name} table size ({size} bytes)"));
                }
            }
        }
    }

    Ok(())
}

/// Parse an ELF, panic-safe.
pub(crate) fn parse_elf(data: &[u8]) -> GoblinOutcome<Elf<'_>> {
    catch(|| Elf::parse(data))
}

/// Parse a Mach-O (single arch or fat), panic-safe.
pub(crate) fn parse_mach(data: &[u8]) -> GoblinOutcome<Mach<'_>> {
    catch(|| Mach::parse(data))
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
        assert!(err.contains("descriptors"), "unexpected reason: {err}");
    }

    /// The quadratic the bound exists for: a descriptor count a cap on
    /// descriptors alone would wave through, each re-walking a lookup table
    /// hundreds of thousands of entries long.
    #[test]
    fn import_walk_budget_rejects_oversized_lookup_tables() {
        let bytes = pe_with_forged_import_directory(8, true);
        let pe = importless_parse(&bytes);
        let err = import_walk_budget(&bytes, &pe).expect_err("entry budget must trip");
        assert!(err.contains("entries"), "unexpected reason: {err}");
    }

    /// The bound has to be wired into `parse_pe`, not merely available: a
    /// forged table must cost the imports and nothing else.
    #[test]
    fn parse_pe_drops_a_forged_import_table_and_keeps_the_rest() {
        let bytes = pe_with_forged_import_directory(8, true);
        let parse = parse_pe(&bytes);
        let reason = parse
            .imports_skipped
            .as_deref()
            .expect("parse_pe must report the abandoned import table");
        assert!(reason.contains("entries"), "unexpected reason: {reason}");
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
        assert!(validate_pe_header(&data).is_err());
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
        assert!(validate_pe_header(&data).is_err());
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
}
