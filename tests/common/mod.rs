//! Helpers shared by the integration test binaries.
//!
//! Every open here is hermetic: the disk cache and rizin are off, so a
//! result depends on the bytes alone — not on `FILEFACTS_CACHE`, a warm
//! entry from an earlier run, or whether rizin is installed — and
//! `parse_count() == 1` holds wherever a test asserts it.
#![allow(
    dead_code,
    reason = "each test binary compiles this module and uses its own subset"
)]

pub(crate) mod iso;

use std::hint::black_box;
use std::path::Path;

use filefacts::{OpenOptions, ParsedFile, Symbol, SymbolKind};

/// Options for a hermetic open: no disk cache and no rizin subprocess.
pub(crate) fn options() -> OpenOptions<'static> {
    OpenOptions::new().cache(false).rizin(false)
}

/// `bytes` opened hermetically, without a path.
pub(crate) fn open(bytes: &[u8]) -> ParsedFile<'_> {
    options().open(bytes)
}

/// `bytes` opened hermetically under the file name `name`.
pub(crate) fn open_named<'a>(name: &str, bytes: &'a [u8]) -> ParsedFile<'a> {
    options().path(Path::new(name)).open(bytes)
}

/// Touch every view so each lazy extraction stage runs, the flow graph and
/// the source AST included.
pub(crate) fn touch_all(parsed: &ParsedFile<'_>) {
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
}

/// Every call target (`Symbol::Call.target`) of a parsed file, dropping
/// dynamic-callee entries.
pub(crate) fn call_targets(parsed: &ParsedFile<'_>) -> Vec<String> {
    parsed
        .symbols()
        .iter_kind(SymbolKind::Call)
        .filter_map(|s| match s {
            Symbol::Call { target, .. } => target.clone(),
            _ => None,
        })
        .collect()
}

/// Every import name of a parsed file.
pub(crate) fn import_names(parsed: &ParsedFile<'_>) -> Vec<String> {
    parsed
        .symbols()
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Every function name of a parsed file.
pub(crate) fn function_names(parsed: &ParsedFile<'_>) -> Vec<String> {
    parsed
        .symbols()
        .iter_kind(SymbolKind::Function)
        .filter_map(|s| match s {
            Symbol::Function { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}
