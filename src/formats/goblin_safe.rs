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

/// Parse a PE file, panic-safe and with built-in permissive
/// fallback.
///
/// Strict mode is tried first; if it fails OR panics, the call is
/// retried with `ParseMode::Permissive`. Returns the strict failure
/// only when the permissive retry itself panicked (in which case the
/// strict error is the more actionable signal).
pub(crate) fn parse_pe(data: &[u8]) -> GoblinOutcome<PE<'_>> {
    if let Err(e) = validate_pe_header(data) {
        return GoblinOutcome::Failed(GoblinError::Malformed(e));
    }

    let strict = catch(|| PE::parse(data));
    if matches!(strict, GoblinOutcome::Ok(_)) {
        return strict;
    }

    let opts = goblin::pe::options::ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive);
    let permissive = catch(|| PE::parse_with_opts(data, &opts));

    match (&strict, &permissive) {
        // Strict failed cleanly; permissive panicked — prefer the
        // clean failure message.
        (GoblinOutcome::Failed(_), GoblinOutcome::Panicked(_)) => strict,
        _ => permissive,
    }
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
        let result: GoblinOutcome<i32> = catch(|| -> Result<i32, GoblinError> {
            panic!("boom")
        });
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
        let result = parse_pe(b"not a PE file at all");
        match result {
            GoblinOutcome::Failed(_) | GoblinOutcome::Panicked(_) => {}
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn parse_pe_short_input_falls_through_to_goblin() {
        // Below the 64-byte gate, validate_pe_header returns Ok and
        // we hand the bytes straight to goblin, which fails cleanly.
        let result = parse_pe(&[0u8; 16]);
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
