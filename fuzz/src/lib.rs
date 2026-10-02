//! Shared driver for the filefacts fuzz targets.
//!
//! Every target runs its input on a 2 MiB thread, the stack a rayon worker
//! gets. libFuzzer calls targets on the main thread, whose 8 MiB stack hides
//! recursion that overflows in a real scan.

use std::hint::black_box;
use std::path::Path;

use filefacts::{FileId, FileType, OpenOptions, ParsedFile};

/// The stack a rayon worker thread gets by default.
const WORKER_STACK: usize = 2 << 20;

/// Options for a hermetic open: no disk cache and no rizin subprocess.
fn options() -> OpenOptions<'static> {
    OpenOptions::new().cache(false).rizin(false)
}

/// Run `work` on a [`WORKER_STACK`] thread, re-raising its panic so
/// libFuzzer records the input as a crash.
fn on_worker_stack(work: impl FnOnce() + Send) {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn_scoped(scope, work)
            .expect("spawn fuzz worker thread");
        if let Err(payload) = worker.join() {
            std::panic::resume_unwind(payload);
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
