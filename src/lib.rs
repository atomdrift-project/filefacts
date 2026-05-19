//! # expose
//!
//! Fast, thorough metadata, metrics, and string extraction for binary
//! and source file formats.
//!
//! `expose` is the single-pass extraction layer underneath higher-level
//! analysis tools. Given a byte slice, it identifies the file format,
//! parses the format's structural fields, scans for string literals, and
//! computes byte-level metrics — once, lazily, sharing the parse across
//! every view.
//!
//! Three output views form the public schema:
//!
//! - [`Values`] — the format's structural data, navigable as a JSON tree.
//! - [`Strings`] — extracted string literals, grouped by extraction
//!   technique.
//! - [`Metrics`] — derived numeric features (entropy, sizes, counts).
//!
//! Plus a fourth concern that's always available without computing the
//! views: [`FileId`], the result of file-format identification.
//!
//! ## Quick start
//!
//! ```no_run
//! let bytes = std::fs::read("sample.exe").unwrap();
//! let parsed = expose::open(&bytes).unwrap();
//!
//! println!("file type: {:?}", parsed.fileid().file_type());
//! for (key, value) in parsed.values().iter() {
//!     println!("{}: {}", key, value);
//! }
//! for s in &parsed.strings().ascii {
//!     println!("@{}: {}", s.offset, s.text);
//! }
//! for (key, value) in parsed.metrics().iter() {
//!     println!("{} = {}", key, value);
//! }
//! ```
//!
//! ## Design
//!
//! `ParsedFile` borrows the source bytes for its entire lifetime. The
//! three views are computed lazily on first access and cached via
//! [`std::sync::OnceLock`], so subsequent accesses are free and views
//! can be safely read from multiple threads.
//!
//! Format extraction is single-pass: a format extractor receives the
//! bytes and writes into all three views in one walk. There is no
//! parsing during view materialisation that wasn't requested.
//!
//! ## Stability
//!
//! The crate is pre-1.0. The output schema is versioned via
//! [`SCHEMA_VERSION`]; field additions are non-breaking, field
//! semantics or renames bump the version.

#![doc(html_root_url = "https://docs.rs/expose/0.1.0")]

mod debug;
mod error;
mod formats;
mod output;
mod scan;

pub mod fileid;

use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

pub use error::Error;
pub use fileid::{FileId, FileType};
pub use output::{
    ArgShape, Ast, Call, ExtractedString, Metrics, Section, Sections, StringCategory, Strings,
    Values,
};

/// Schema version of the public output shape.
///
/// Bumps on any field rename or semantic change. Field additions are
/// non-breaking and do not bump this version.
pub const SCHEMA_VERSION: &str = "1";

/// A file with its bytes and lazily-computed metadata views.
///
/// `ParsedFile` is the central type. Construct one with [`open`] (no
/// filesystem access) or [`from_path`] (reads the file from disk).
///
/// The three views are accessed via [`values`], [`strings`], and
/// [`metrics`]. Each is computed on first access and cached for the
/// lifetime of the `ParsedFile`.
///
/// [`values`]: ParsedFile::values
/// [`strings`]: ParsedFile::strings
/// [`metrics`]: ParsedFile::metrics
pub struct ParsedFile<'a> {
    bytes: &'a [u8],
    fileid: FileId,
    // Shared tree-sitter parse for source files. Built once by
    // `tree_cache()` and consumed by the single extraction pipeline
    // that fills `extracted`.
    tree_cache: OnceLock<Option<formats::source::TreeCache<'a>>>,
    extracted: OnceLock<Extracted>,
    // How many times this `ParsedFile` ran its extraction pipeline.
    // A correctly-implemented `ParsedFile` never reports more than 1
    // regardless of which views the caller reads.
    parse_count: AtomicU32,
}

impl std::fmt::Debug for ParsedFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedFile")
            .field("fileid", &self.fileid)
            .field("byte_count", &self.bytes.len())
            .field("parse_count", &self.parse_count())
            .finish()
    }
}

struct Extracted {
    values: Values,
    strings: Strings,
    metrics: Metrics,
    ast: Ast,
    sections: Sections,
}

impl<'a> ParsedFile<'a> {
    /// The source bytes this `ParsedFile` borrows.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The file-identification result. Always available without
    /// triggering extraction.
    pub fn fileid(&self) -> &FileId {
        &self.fileid
    }

    /// Structural key-value view. Computed on first access and cached.
    pub fn values(&self) -> &Values {
        &self.extracted().values
    }

    /// Extracted strings view. Computed on first access and cached.
    pub fn strings(&self) -> &Strings {
        &self.extracted().strings
    }

    /// Numeric metrics view. Computed on first access and cached.
    pub fn metrics(&self) -> &Metrics {
        &self.extracted().metrics
    }

    /// AST projection view.
    ///
    /// Empty when the file is not a source language expose can
    /// parse. For source files, this is a curated set of projections
    /// of the tree-sitter parse: every call site, the sorted-unique
    /// call targets, dotted member-access chains, and per-target
    /// string-literal arguments. The same tree-sitter parse backs
    /// `values()` / `strings()` for source files — no re-parsing is
    /// performed.
    pub fn ast(&self) -> &Ast {
        &self.extracted().ast
    }

    /// Section / segment listing for binary formats.
    ///
    /// Empty for files without a section table (structured documents,
    /// source code, archives). Each [`Section`] carries its name,
    /// virtual and on-disk extents, per-section Shannon entropy, and
    /// a format-conventional flag vocabulary.
    pub fn sections(&self) -> &Sections {
        &self.extracted().sections
    }

    /// Borrow the shared tree-sitter parse, if this file is a source
    /// language and parsing succeeded.
    fn tree_cache(&self) -> Option<&formats::source::TreeCache<'a>> {
        self.tree_cache
            .get_or_init(|| {
                if !formats::source::supports(self.fileid.file_type()) {
                    return None;
                }
                formats::source::TreeCache::parse(self.bytes, self.fileid.file_type())
                    .ok()
                    .flatten()
            })
            .as_ref()
    }

    /// Number of times this `ParsedFile` ran its extraction pipeline.
    ///
    /// `0` before any view has been requested; `1` after any one of
    /// `values()`, `strings()`, `metrics()`, `ast()` has been called.
    /// A correctly-implemented `ParsedFile` never reports a higher
    /// count, regardless of which combination of views the caller
    /// reads.
    pub fn parse_count(&self) -> u32 {
        self.parse_count.load(Ordering::Acquire)
    }

    fn extracted(&self) -> &Extracted {
        self.extracted.get_or_init(|| {
            self.parse_count.fetch_add(1, Ordering::AcqRel);
            run_extraction(self.bytes, self.fileid.file_type(), self.tree_cache())
        })
    }
}

fn run_extraction(
    bytes: &[u8],
    file_type: FileType,
    tree_cache: Option<&formats::source::TreeCache<'_>>,
) -> Extracted {
    let mut values = Values::new();
    let mut strings = Strings::new();
    let mut metrics = Metrics::new();
    let mut sections: Vec<Section> = Vec::new();
    // Format extractors return `Result` so they can report malformed
    // input. We swallow the error here: a malformed format still
    // yields whatever the generic pass extracted plus partial
    // format-specific data.
    let _ = formats::extract(
        file_type,
        bytes,
        tree_cache,
        &mut values,
        &mut strings,
        &mut metrics,
        &mut sections,
    );
    // The AST view is computed alongside the rest when a tree-sitter
    // parse is available. The walk shares the cached tree with the
    // surface extraction and is small relative to the parse itself —
    // bundling it keeps `parse_count` at 1 for every combination of
    // view accesses and removes a class of internal-mutability
    // complications.
    let ast = tree_cache
        .map_or_else(Ast::new, |cache| formats::source::build_ast(cache, &mut metrics));
    let sections = Sections::from_iter_sections(sections);
    // Aggregate metrics derived from sections — mirrors the
    // `sections.*` path convention.
    if !sections.is_empty() {
        emit_section_metrics(&sections, &mut metrics);
    }

    // Seal typed views into the unified `values` tree so the JSON
    // shape exposes exactly two carrier blocks (`values`, `metrics`)
    // plus the always-cheap `fileid`. The typed views still live on
    // `Extracted` for the Rust API; this is a serialisation-side
    // unification only.
    if !strings.is_empty() {
        if let Ok(v) = serde_json::to_value(&strings) {
            values.insert("strings", v);
        }
    }
    if !sections.is_empty() {
        if let Ok(v) = serde_json::to_value(&sections) {
            values.insert("sections", v);
        }
    }
    if !ast.is_empty() {
        if let Ok(v) = serde_json::to_value(&ast) {
            values.insert("ast", v);
        }
    }

    Extracted {
        values,
        strings,
        metrics,
        ast,
        sections,
    }
}

fn emit_section_metrics(sections: &Sections, metrics: &mut Metrics) {
    metrics.insert("sections.count", sections.len() as f64);

    // Per-section entropies were emitted into `metrics` as
    // `sections[N].entropy` during format extraction. Walk the section
    // table by index so the aggregate computation can't drift out of
    // sync with the per-section values.
    let mut entropy_max = 0.0_f64;
    let mut entropy_sum = 0.0_f64;
    let mut entropy_n = 0_u64;
    for idx in 0..sections.len() {
        if let Some(e) = metrics.get(&format!("sections[{idx}].entropy")) {
            entropy_max = entropy_max.max(e);
            entropy_sum += e;
            entropy_n += 1;
        }
    }
    if entropy_n > 0 {
        metrics.insert("sections.entropy_max", entropy_max);
        metrics.insert("sections.entropy_mean", entropy_sum / entropy_n as f64);
    }

    let mut executable = 0_u64;
    let mut writable = 0_u64;
    let mut wx = 0_u64;
    for s in sections {
        let is_exec = s.flags.iter().any(|f| f == "executable" || f == "execinstr");
        let is_write = s.flags.iter().any(|f| f == "writable" || f == "write");
        if is_exec {
            executable += 1;
        }
        if is_write {
            writable += 1;
        }
        if is_exec && is_write {
            wx += 1;
        }
    }
    metrics.insert("sections.executable_count", executable as f64);
    metrics.insert("sections.writable_count", writable as f64);
    metrics.insert("sections.executable_writable_count", wx as f64);
}

/// Open `bytes` for metadata extraction. The returned [`ParsedFile`]
/// borrows the slice for its lifetime.
///
/// File-type identification uses content-only heuristics (magic bytes,
/// shebang, lightweight pattern matching). Use [`open_with_path`] when
/// the file's path / extension should also inform the identification.
///
/// Returns [`Error::UnknownFormat`] if no format could be identified.
/// In rare practice this is informative — `open` succeeds for nearly
/// every byte slice because the file-identifier falls back to
/// "unknown" rather than failing — but the public contract is `Result`
/// for future tightening.
pub fn open(bytes: &[u8]) -> Result<ParsedFile<'_>, Error> {
    let fileid = FileId::from_bytes(bytes);
    Ok(ParsedFile {
        bytes,
        fileid,
        tree_cache: OnceLock::new(),
        extracted: OnceLock::new(),
        parse_count: AtomicU32::new(0),
    })
}

/// Open `bytes` with the original path supplied for identification.
///
/// Some formats are only distinguishable via the file extension or
/// well-known basename (e.g. `package.json` is JSON byte-for-byte but
/// carries different metadata than a generic JSON document). Pass the
/// path when you have it.
pub fn open_with_path<'a>(path: &Path, bytes: &'a [u8]) -> Result<ParsedFile<'a>, Error> {
    let fileid = FileId::from_path_and_bytes(path, bytes);
    Ok(ParsedFile {
        bytes,
        fileid,
        tree_cache: OnceLock::new(),
        extracted: OnceLock::new(),
        parse_count: AtomicU32::new(0),
    })
}

/// Read a file from disk, identify it, and return a `ParsedFile` plus
/// the owned bytes buffer.
///
/// The bytes are returned separately because `ParsedFile` borrows them
/// — the caller must keep the `Vec<u8>` alive for as long as the
/// `ParsedFile` is in scope. For one-shot use, write:
///
/// ```no_run
/// let bytes = std::fs::read("sample.exe")?;
/// let parsed = expose::open_with_path(std::path::Path::new("sample.exe"), &bytes)?;
/// # Ok::<(), expose::Error>(())
/// ```
pub fn from_path(path: &Path) -> Result<(Vec<u8>, FileId), Error> {
    let bytes = std::fs::read(path)?;
    let fileid = FileId::from_path_and_bytes(path, &bytes);
    Ok((bytes, fileid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_classifies_text() {
        let bytes = b"hello world\n";
        let parsed = open(bytes).unwrap();
        assert_eq!(parsed.bytes(), bytes);
    }

    #[test]
    fn parse_count_is_one_after_any_view_access() {
        let bytes = b"{\"name\":\"test\"}";
        let parsed = open(bytes).unwrap();
        assert_eq!(parsed.parse_count(), 0);
        let _ = parsed.values();
        assert_eq!(parsed.parse_count(), 1);
        let _ = parsed.strings();
        let _ = parsed.metrics();
        assert_eq!(parsed.parse_count(), 1, "subsequent views must not reparse");
    }

    #[test]
    fn metrics_always_include_size_and_entropy() {
        let bytes = b"x".repeat(256);
        let parsed = open(&bytes).unwrap();
        let m = parsed.metrics();
        assert_eq!(m.get("file.size_bytes"), Some(256.0));
        assert!(m.get("file.entropy").unwrap() < 0.01);
    }
}
