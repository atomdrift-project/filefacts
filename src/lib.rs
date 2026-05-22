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

pub mod cache;
pub mod fileid;

/// Optional rizin/radare2 integration with hardened subprocess
/// discipline (RLIMIT, PR_SET_PDEATHSIG, process-group SIGKILL on
/// timeout / output-cap overflow). Exposed as a public module so host
/// CLIs can mute it during scans (`scoped_disable`), reap in-flight
/// workers (`kill_all_rizin_groups`) from a signal handler, and emit
/// `tracing` telemetry (`log_stats`) at shutdown.
pub mod rizin {
    pub use crate::rizin_impl::{
        available, disable, is_disabled, kill_all_rizin_groups, log_stats, scoped_disable, stats,
        ScopedDisable,
    };
}

#[path = "rizin.rs"]
mod rizin_impl;

/// VBA `<non-literal>` sentinel re-export.
///
/// Re-exported from the internal `formats::vba_symbols` module so
/// downstream crates can compare against it without learning a
/// private path. The full extractor stays internal: VBA symbols
/// flow out through the unified [`Imports`] / [`Functions`] views
/// like every other format, not through a format-specific public
/// function.
pub mod vba_symbols {
    pub use crate::formats::vba_symbols::NON_LITERAL_SENTINEL;
}

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

pub use error::Error;
pub use fileid::{FileId, FileType};
pub use output::{
    ArgShape, Ast, Call, Errors, Export, Exports, ExtractedString, Function, Functions, Import,
    Imports, Metrics, ParseError, Section, Sections, StringCategory, Strings, Values,
};

/// Schema version of the public output shape.
///
/// Bumps on any field rename or semantic change. Field additions are
/// non-breaking and do not bump this version. Wave A of the cleave
/// rizin migration grows `Function` and `ExtractedString` with several
/// new optional fields; pure additions, so no bump is required on
/// JSON shape grounds. The on-disk cache (`expose::cache`) carries a
/// distinct schema version that *is* bumped on every addition so
/// cached bytes from old binaries are not silently reused.
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
    imports: Imports,
    exports: Exports,
    functions: Functions,
    errors: Errors,
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

    /// Foreign-symbol references — entries this file uses that are
    /// defined elsewhere (PE imports, ELF `.dynsym` undefined,
    /// Mach-O undef symbols, VBA `Declare` / `CreateObject`,
    /// Java constant-pool class refs, source-level `import` /
    /// `require`). Each [`Import`] carries `name`, optional
    /// `library`, a `source` tag identifying the extraction site,
    /// and optional `offset` / `ordinal`. See [`crate::Import`].
    pub fn imports(&self) -> &Imports {
        &self.extracted().imports
    }

    /// Locally-defined symbols this file makes externally visible
    /// (PE export table, ELF `.dynsym` defined, Mach-O dyld trie,
    /// Java public methods, source-level `export` statements). Each
    /// [`Export`] carries `name`, `source`, and optional `offset` /
    /// `ordinal`.
    pub fn exports(&self) -> &Exports {
        &self.extracted().exports
    }

    /// Functions / methods / subroutines defined inside this file.
    /// Distinct from [`Self::exports`] — a function may be local
    /// without being exported, and an export entry may point at a
    /// function whose body is also enumerated here with extra
    /// detail. Each [`Function`] carries `name`, `source`, optional
    /// `offset`, and optional `kind`.
    pub fn functions(&self) -> &Functions {
        &self.extracted().functions
    }

    /// Non-fatal extraction errors encountered during the parse.
    ///
    /// Expose always returns as much data as it can: when a goblin
    /// lazy walker panics or a sub-table is truncated, the failure
    /// is recorded here and the rest of the extraction continues.
    /// Empty when nothing went wrong. See [`crate::ParseError`] for
    /// the entry shape.
    pub fn errors(&self) -> &Errors {
        &self.extracted().errors
    }

    /// Iterate every symbol name across [`Self::imports`],
    /// [`Self::exports`], and [`Self::functions`] in that order.
    /// Convenience for cross-cutting trait matchers ("any symbol
    /// of this name regardless of category"). Yields `(name,
    /// source)` so the caller can disambiguate when needed.
    pub fn symbol_iter(&self) -> impl Iterator<Item = (&str, &'static str)> {
        let imports = self.imports().iter().map(|i| (i.name.as_str(), i.source));
        let exports = self.exports().iter().map(|e| (e.name.as_str(), e.source));
        let functions = self.functions().iter().map(|f| (f.name.as_str(), f.source));
        imports.chain(exports).chain(functions)
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
    let mut imports = Imports::new();
    let mut exports = Exports::new();
    let mut functions = Functions::new();
    let mut errors = Errors::new();
    // Format extractors return `Result` so they can report a hard
    // "this file is not in the format I expect" failure. Any
    // recoverable mid-extraction issues (goblin lazy-walker panics,
    // truncated sub-tables, permissive-mode fallbacks) are recorded
    // through the typed `Errors` view instead — we want consumers to
    // get everything we did manage to extract even when some sub-
    // stage failed, since cleave depends on the partial data.
    if let Err(e) = formats::extract(
        file_type,
        bytes,
        tree_cache,
        &mut values,
        &mut strings,
        &mut metrics,
        &mut sections,
        &mut imports,
        &mut exports,
        &mut functions,
        &mut errors,
    ) {
        // The format extractor bailed entirely. Surface that as a
        // `malformed` entry so cleave can see *why* the
        // format-specific view is sparse.
        errors.record_malformed(stage_for(file_type), e.to_string());
    }
    // The AST view is computed alongside the rest when a tree-sitter
    // parse is available. The walk shares the cached tree with the
    // surface extraction and is small relative to the parse itself —
    // bundling it keeps `parse_count` at 1 for every combination of
    // view accesses and removes a class of internal-mutability
    // complications.
    let ast = tree_cache.map_or_else(Ast::new, |cache| {
        formats::source::build_ast(cache, &mut metrics)
    });
    let sections = Sections::from_iter_sections(sections);
    // Aggregate metrics derived from sections — mirrors the
    // `sections.*` path convention.
    if !sections.is_empty() {
        emit_section_metrics(&sections, &mut metrics);
        emit_binary_aggregates(&sections, &strings, bytes, &mut metrics);
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
    // Project typed symbol collections into the values tree so kv-path
    // consumers can read them as ordinary arrays. Each entry serializes
    // through the structs' `#[serde]` derives (skips empty optionals).
    if !imports.is_empty() {
        if let Ok(v) = serde_json::to_value(&imports) {
            values.insert("imports", v);
        }
    }
    if !exports.is_empty() {
        if let Ok(v) = serde_json::to_value(&exports) {
            values.insert("exports", v);
        }
    }
    if !functions.is_empty() {
        if let Ok(v) = serde_json::to_value(&functions) {
            values.insert("functions", v);
        }
    }
    if !errors.is_empty() {
        // Mirror parse errors into the values tree so kv-path
        // consumers (cleave's trait engine) can match on them
        // (`type: kv path: errors[*].kind exact: panic`). The typed
        // `Errors` view stays the Rust-side API.
        if let Ok(v) = serde_json::to_value(&errors) {
            values.insert("errors", v);
        }
        // Pike-style numeric summary: a single `parse.error_count`
        // metric so traits can fire on "did any sub-stage fail" /
        // "more than N stages failed" without re-walking the typed
        // view.
        metrics.insert("parse.error_count", errors.len() as f64);
    }

    Extracted {
        values,
        strings,
        metrics,
        ast,
        sections,
        imports,
        exports,
        functions,
        errors,
    }
}

/// Heuristic: "looks like a natural-language sentence" — short enough
/// to be ML-cheap, long enough to filter out short tokens. A binary
/// embedding many of these usually contains documentation strings,
/// error messages, or string-table assets — a different population
/// than a binary whose strings are all `__cxx_…` symbols or paths.
fn is_sentence_like(text: &str) -> bool {
    if text.len() < 12 {
        return false;
    }
    let mut spaces = 0_usize;
    for b in text.bytes() {
        if b == b' ' {
            spaces += 1;
        }
    }
    if spaces < 2 {
        return false;
    }
    let mut alpha_tokens = 0_usize;
    let mut tokens = 0_usize;
    for tok in text.split_whitespace() {
        tokens += 1;
        if tok.chars().filter(|c| c.is_alphabetic()).count() >= 2 {
            alpha_tokens += 1;
        }
    }
    tokens >= 3 && alpha_tokens >= 2
}

/// Map a [`FileType`] to the short `stage` tag we use when an
/// extractor returns `Err` and we have to synthesise a fallback
/// error record. Stage tags are stable across releases.
fn stage_for(file_type: FileType) -> &'static str {
    match file_type {
        FileType::Pe => "pe-parse",
        FileType::Elf => "elf-parse",
        FileType::MachO => "macho-parse",
        FileType::Ooxml => "ooxml-parse",
        FileType::OleDoc => "ole2-parse",
        FileType::Zip | FileType::Crx | FileType::Odf | FileType::Jar => "zip-parse",
        FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst => {
            "tar-parse"
        }
        FileType::JavaClass => "class-parse",
        FileType::Pdf => "pdf-parse",
        FileType::Rpm => "rpm-parse",
        _ => "format-extract",
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
        let is_exec = s
            .flags
            .iter()
            .any(|f| f == "executable" || f == "execinstr");
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

/// Cross-format `binary.*` aggregates derived from sections + strings +
/// raw bytes. Keeps the keys cleave's trait engine has used historically
/// without each format extractor re-deriving the same logic.
///
/// Emits (only the useful subset — fields cleave computed but no trait
/// queried were dropped):
/// - `binary.string_count`, `binary.max_string_length`,
///   `binary.avg_string_length`, `binary.high_entropy_string_count`.
/// - `binary.entropy_variance` — population variance across the
///   per-section entropies. Packers tend to flatten this; a normal
///   binary spreads across `.text` (~6), `.rodata` (~5), `.data` (~3).
/// - `binary.code_to_data_ratio`, `binary.largest_section_ratio` —
///   simple structural ratios over `Sections.file_size`.
/// - `binary.has_overlay`, `binary.overlay_size`,
///   `binary.overlay_ratio`, `binary.overlay_entropy` — bytes beyond
///   the last on-disk section extent (PE installer droppers, ELF
///   self-extractors).
fn emit_binary_aggregates(
    sections: &Sections,
    strings: &Strings,
    bytes: &[u8],
    metrics: &mut Metrics,
) {
    // -- Strings ------------------------------------------------------
    let total = strings.len();
    if total > 0 {
        let mut max_len = 0_usize;
        let mut sum_len = 0_usize;
        let mut high_entropy = 0_u64;
        let mut sentence = 0_u64;
        // Collect lengths once; second pass below computes stddev.
        let mut lengths: Vec<usize> = Vec::with_capacity(total);
        for s in strings.iter() {
            let len = s.text.len();
            max_len = max_len.max(len);
            sum_len = sum_len.saturating_add(len);
            lengths.push(len);
            // Shannon-entropy floor of 6.0 bits/byte separates random-
            // looking strings (base64, keys, hex blobs) from English /
            // identifier-shaped text (~3–4.5).
            if scan::entropy::shannon(s.text.as_bytes()) >= 6.0 {
                high_entropy += 1;
            }
            if is_sentence_like(&s.text) {
                sentence += 1;
            }
        }
        let avg = sum_len as f64 / total as f64;
        let variance = lengths
            .iter()
            .map(|&l| {
                let d = l as f64 - avg;
                d * d
            })
            .sum::<f64>()
            / total as f64;
        metrics.insert("binary.string_count", total as f64);
        metrics.insert("binary.max_string_length", max_len as f64);
        metrics.insert("binary.avg_string_length", avg);
        metrics.insert("binary.string_length_stddev", variance.sqrt());
        metrics.insert("binary.high_entropy_string_count", high_entropy as f64);
        metrics.insert("binary.sentence_string_count", sentence as f64);
        metrics.insert(
            "binary.sentence_string_ratio",
            sentence as f64 / total as f64,
        );
    }

    // -- Per-section entropy variance --------------------------------
    let mut entropies: Vec<f64> = Vec::new();
    for idx in 0..sections.len() {
        if let Some(e) = metrics.get(&format!("sections[{idx}].entropy")) {
            entropies.push(e);
        }
    }
    if entropies.len() >= 2 {
        let mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let var =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / entropies.len() as f64;
        metrics.insert("binary.entropy_variance", var);
    }

    // -- Section ratios + size-weighted entropy ----------------------
    // `binary.code_entropy` / `binary.data_entropy` are size-weighted
    // averages of per-section entropies (already in `metrics` as
    // `sections[idx].entropy`). Weighting by `file_size` is what
    // packer detectors want — a tiny `.init` block at 7.9 entropy
    // shouldn't dominate the `.text` average.
    let mut code_size: u64 = 0;
    let mut data_size: u64 = 0;
    let mut largest: u64 = 0;
    let mut code_entropy_sum = 0.0_f64;
    let mut data_entropy_sum = 0.0_f64;
    for (idx, s) in sections.as_slice().iter().enumerate() {
        let is_exec = s
            .flags
            .iter()
            .any(|f| f == "executable" || f == "execinstr");
        let is_write = s.flags.iter().any(|f| f == "writable" || f == "write");
        let on_disk = s.file_size;
        largest = largest.max(on_disk);
        let entropy = metrics
            .get(&format!("sections[{idx}].entropy"))
            .unwrap_or(0.0);
        if is_exec {
            code_size = code_size.saturating_add(on_disk);
            code_entropy_sum += entropy * on_disk as f64;
        } else if is_write {
            data_size = data_size.saturating_add(on_disk);
            data_entropy_sum += entropy * on_disk as f64;
        }
    }
    if code_size > 0 {
        metrics.insert("binary.code_entropy", code_entropy_sum / code_size as f64);
    }
    if data_size > 0 {
        metrics.insert("binary.data_entropy", data_entropy_sum / data_size as f64);
    }
    if code_size + data_size > 0 {
        metrics.insert(
            "binary.code_to_data_ratio",
            code_size as f64 / (code_size + data_size) as f64,
        );
    }
    let file_size = bytes.len() as u64;
    if file_size > 0 && largest > 0 {
        metrics.insert(
            "binary.largest_section_ratio",
            largest as f64 / file_size as f64,
        );
    }

    // -- Overlay ------------------------------------------------------
    // Last on-disk extent across sections. Anything past it is
    // appended payload (NSIS installer stubs, self-extractors).
    let last_extent = sections
        .as_slice()
        .iter()
        .map(|s| s.file_offset.saturating_add(s.file_size))
        .max()
        .unwrap_or(0);
    if last_extent > 0 && file_size > last_extent {
        let overlay_size = file_size - last_extent;
        metrics.insert("binary.has_overlay", 1.0);
        metrics.insert("binary.overlay_size", overlay_size as f64);
        metrics.insert(
            "binary.overlay_ratio",
            overlay_size as f64 / file_size as f64,
        );
        let start = last_extent as usize;
        let end = bytes.len();
        if start < end {
            metrics.insert(
                "binary.overlay_entropy",
                scan::entropy::shannon(&bytes[start..end]),
            );
        }
    }
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

    /// `ParsedFile::symbol_iter` walks every Import / Export /
    /// Function in one pass. Used by trait matchers that don't
    /// care which collection a name appears in.
    #[test]
    fn symbol_iter_walks_all_three_collections() {
        let bytes = std::fs::read("../cleave/tests/fixtures/test.exe")
            .expect("test.exe fixture should exist");
        let parsed = open(&bytes).unwrap();
        // Realize the views before iterating — the lazy parse runs
        // on first `.values()` access.
        let _ = parsed.values();
        let imports = parsed.imports();
        assert!(!imports.is_empty(), "PE fixture should have imports");
        let total = parsed.symbol_iter().count();
        assert_eq!(
            total,
            parsed.imports().len() + parsed.exports().len() + parsed.functions().len(),
            "symbol_iter must visit every entry in all three collections",
        );
        // All PE-sourced entries carry source == "pe".
        let sources: std::collections::HashSet<&'static str> =
            parsed.symbol_iter().map(|(_, src)| src).collect();
        assert!(sources.contains("pe"));
    }

    /// A healthy PE fixture should produce zero parse errors and
    /// no `parse.error_count` metric — the typed Errors view stays
    /// empty.
    #[test]
    fn healthy_pe_emits_no_parse_errors() {
        let bytes = std::fs::read("../cleave/tests/fixtures/test.exe")
            .expect("test.exe fixture should exist");
        let parsed = open(&bytes).unwrap();
        // Realize.
        let _ = parsed.values();
        assert!(parsed.errors().is_empty());
        assert!(parsed.metrics().get("parse.error_count").is_none());
    }

    /// Malformed ELF bytes (anything that starts \x7fELF but is
    /// otherwise truncated) trip goblin's parse. The error must
    /// land in the typed Errors view tagged `elf-parse` and the
    /// generic byte-level metrics (file.size_bytes, file.entropy)
    /// must still be present — partial data is the contract.
    #[test]
    fn malformed_elf_records_error_but_keeps_byte_metrics() {
        // ELF magic + half a header — enough to be classified as
        // ELF by fileid, not enough for goblin to parse.
        let mut bytes = Vec::from(b"\x7fELF" as &[u8]);
        bytes.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let parsed = open(&bytes).unwrap();
        let _ = parsed.values();

        // Byte-level metrics survive even though the format parse
        // failed — generic::extract ran before format dispatch.
        assert!(parsed.metrics().get("file.size_bytes").is_some());

        // Structured error recorded.
        let errors = parsed.errors();
        assert!(!errors.is_empty(), "expected a malformed-elf error entry");
        let entry = errors.iter().next().unwrap();
        assert_eq!(entry.kind, "malformed");
        assert_eq!(entry.stage, "elf-parse");

        // Aggregate count metric.
        assert!(parsed.metrics().get("parse.error_count").is_some());
        // Specific format metric.
        assert!(parsed.metrics().get("elf.parse_failed").is_some());
    }
}
