//! Shared driver for the filefacts fuzz targets.
//!
//! Every target runs its input on a 2 MiB thread, the stack a rayon worker
//! gets. libFuzzer calls targets on the main thread, whose 8 MiB stack hides
//! recursion that overflows in a real scan.

use std::cell::Cell;
use std::hint::black_box;
use std::path::Path;
use std::sync::{Mutex, Once};

use filefacts::{DiagnosticKind, FileId, FileType, OpenOptions, ParsedFile};

/// The stack a rayon worker thread gets by default.
const WORKER_STACK: usize = 2 << 20;

/// Options for a hermetic open: no disk cache and no rizin subprocess.
fn options() -> OpenOptions<'static> {
    OpenOptions::new().cache(false).rizin(false)
}

thread_local! {
    /// Set on the worker thread, whose panics [`on_worker_stack`] reports.
    static ON_WORKER: Cell<bool> = const { Cell::new(false) };
}

/// Where and why the worker last panicked.
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

/// libFuzzer's hook aborts on every panic, even one the code under test
/// catches itself (filefacts' and stng's guards around goblin). On the worker
/// thread, record the panic instead and let it unwind: a guard that catches
/// it is working, and one that escapes reaches [`on_worker_stack`], which
/// re-raises it as a crash.
fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let libfuzzer = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if ON_WORKER.with(Cell::get) {
                if let Ok(mut last) = LAST_PANIC.lock() {
                    *last = Some(info.to_string());
                }
                return;
            }
            libfuzzer(info);
        }));
    });
}

/// Run `work` on a [`WORKER_STACK`] thread, re-raising a panic that escapes
/// it so libFuzzer records the input as a crash.
fn on_worker_stack(work: impl FnOnce() + Send) {
    install_panic_hook();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn_scoped(scope, || {
                ON_WORKER.with(|on| on.set(true));
                work();
            })
            .expect("spawn fuzz worker thread");
        if worker.join().is_err() {
            let last = LAST_PANIC.lock().ok().and_then(|mut l| l.take());
            panic!(
                "panic escaped filefacts: {}",
                last.as_deref().unwrap_or("<no message>")
            );
        }
    });
}

/// Touch every view so each lazy extraction stage runs, the flow graph and
/// the source AST included.
fn touch_all(parsed: &ParsedFile<'_>) {
    black_box(parsed.fileid().file_type());
    black_box(parsed.values());
    black_box(parsed.text().len());
    black_box(parsed.literals());
    black_box(parsed.comments());
    black_box(parsed.metrics().len());
    black_box(parsed.archive_members().len());
    black_box(parsed.source_ast().is_some());
    black_box(parsed.sections());
    black_box(parsed.symbols());
    black_box(parsed.flow());
    black_box(parsed.identity());
    black_box(parsed.references().len());
    black_box(parsed.errors());
    black_box(parsed.embedded_sources().count());
    black_box(parsed.symbol_iter().count());
    fail_on_caught_panic(parsed);
}

/// filefacts catches extractor panics and records them as `panic`
/// diagnostics, so a panicking parser never reaches libFuzzer on its own.
/// Each one is still a bug, ours or a dependency's: re-raise it so the input
/// is saved. Set `FUZZ_ALLOW_CAUGHT_PANICS` to hunt only for what the
/// catch cannot stop (aborts, runaway memory and time).
fn fail_on_caught_panic(parsed: &ParsedFile<'_>) {
    if std::env::var_os("FUZZ_ALLOW_CAUGHT_PANICS").is_some() {
        return;
    }
    if let Some(caught) = parsed
        .errors()
        .iter()
        .find(|d| d.kind == DiagnosticKind::Panic)
    {
        panic!("filefacts caught a panic: {caught}");
    }
}

/// Identify `data` from its content alone and extract every view.
pub fn open_all_views(data: &[u8]) {
    on_worker_stack(|| touch_all(&options().open(data)));
}

/// Run identification only.
pub fn fileid(data: &[u8]) {
    on_worker_stack(|| {
        black_box(FileId::from_bytes(data));
        black_box(FileId::from_path_and_bytes(Path::new("sample"), data));
    });
}

/// Force `file_type` so the fuzzer reaches that extractor even when the
/// input stops matching the format's magic, then extract every view.
pub fn forced(file_type: FileType, basename: &str, data: &[u8]) {
    on_worker_stack(|| {
        let parsed = options()
            .path(Path::new(basename))
            .file_type(file_type)
            .open(data);
        touch_all(&parsed);
    });
}
