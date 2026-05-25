//! # filefacts
//!
//! Fast, thorough metadata, metrics, and string extraction for binary
//! and source file formats.
//!
//! `filefacts` is the single-pass extraction layer underneath higher-level
//! analysis tools. Given a byte slice, it identifies the file format,
//! parses the format's structural fields, scans for string literals, and
//! computes byte-level metrics — once, lazily, sharing the parse across
//! every view.
//!
//! Output views form the public schema:
//!
//! - [`Values`] — residual format structural data, navigable as a JSON tree.
//! - [`Strings`] — extracted string literals, grouped by extraction
//!   technique.
//! - [`Metrics`] — derived numeric features (entropy, sizes, counts).
//! - [`Sections`] — binary section / segment listings.
//! - [`Symbols`] — unified named-entity facts (imports, exports,
//!   functions, calls, members, binds, identifiers) tagged by kind.
//! - [`Errors`] — recoverable extractor diagnostics.
//!
//! Plus a fourth concern that's always available without computing the
//! views: [`FileId`], the result of file-format identification.
//!
//! ## Quick start
//!
//! ```no_run
//! let bytes = std::fs::read("sample.exe").unwrap();
//! let parsed = filefacts::open(&bytes).unwrap();
//!
//! println!("file type: {:?}", parsed.fileid().file_type());
//! for (key, value) in parsed.values().iter() {
//!     println!("{}: {}", key, value);
//! }
//! for s in &parsed.text().ascii {
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
//! extraction views are computed lazily on first access and cached via
//! [`std::sync::OnceLock`], so subsequent accesses are free and views
//! can be safely read from multiple threads.
//!
//! Format extraction is single-pass: a format extractor receives the
//! bytes and writes into every view in one walk. There is no
//! parsing during view materialisation that wasn't requested.
//!
//! ## Stability
//!
//! The crate is pre-1.0. The output schema is versioned via
//! [`SCHEMA_VERSION`]; field additions are non-breaking, field
//! semantics or renames bump the version.

#![doc(html_root_url = "https://docs.rs/filefacts/0.1.0")]

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
/// private path. The full extractor stays internal: VBA symbols flow
/// out through the unified [`Symbols`] view like every other format,
/// not through a format-specific public function.
pub mod vba_symbols {
    pub use crate::formats::vba_symbols::NON_LITERAL_SENTINEL;
}

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

pub use error::Error;
pub use fileid::{FileId, FileType};
pub use output::{
    ArchiveMember, Arg, ArgShape, Errors, ExtractedString, Literals, Metrics, ParseError, Section,
    Sections, Symbol, SymbolKind, Symbols, Text, Values,
};

/// Schema version of the public output shape.
///
/// Bumps on any field rename or semantic change. Field additions are
/// non-breaking and do not bump this version. The on-disk cache
/// (`filefacts::cache`) carries a distinct schema version that *is*
/// bumped on every addition so cached bytes from old binaries are not
/// silently reused.
///
/// **v5** — the `Imports`, `Exports`, `Functions`, and `Ast` peer
/// types are collapsed into a single tagged [`Symbol`] enum. The
/// `Function.kind` field is renamed to `decl` (to free the word `kind`
/// for the discriminator) and `Function.calls` is renamed to `callees`
/// (to disambiguate from the new [`Symbol::Call`] kind).
///
/// **v6** — the `Strings` collection is split into peer top-level
/// [`Text`] (byte-scan: ascii + utf16le) and [`Literals`] (parser-
/// extracted language string literals). The `StringCategory` enum and
/// `ExtractedString.category` field are removed; the container
/// identifies the tier.
pub const SCHEMA_VERSION: &str = "6";

/// A file with its bytes and lazily-computed metadata views.
///
/// `ParsedFile` is the central type. Construct one with [`open`] (no
/// filesystem access) or [`from_path`] (reads the file from disk).
///
/// Views are computed on first access and cached for the lifetime of
/// the `ParsedFile`. Typed fact families such as strings, sections,
/// symbols, AST projections, and recoverable errors live in their own
/// views; [`values`] is only for residual format structure that does
/// not already have a typed home.
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

/// Borrowed source parse owned by a [`ParsedFile`].
///
/// This exposes the shared tree-sitter tree to host tools that need
/// their own AST queries. The tree is still owned and cached by
/// `ParsedFile`; callers borrow it and must keep the `ParsedFile`
/// alive for as long as they use this view.
#[derive(Debug, Clone, Copy)]
pub struct SourceAst<'tree> {
    /// UTF-8 source text used to build the tree.
    pub source: &'tree str,
    /// Shared tree-sitter parse tree.
    pub tree: &'tree tree_sitter::Tree,
    /// File type used to select the parser.
    pub file_type: FileType,
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
    strings: output::Strings,
    metrics: Metrics,
    archive_members: Vec<ArchiveMember>,
    sections: Sections,
    symbols: Symbols,
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

    /// Byte-scan extracted strings (printable ASCII / UTF-16LE runs).
    /// The Unix `strings(1)` tier. Computed on first access and cached.
    pub fn text(&self) -> &Text {
        &self.extracted().strings.text
    }

    /// Parser-extracted language string literals (tree-sitter / JSON /
    /// YAML / TOML). The precise tier — no comment or code false
    /// positives. Computed on first access and cached.
    pub fn literals(&self) -> &Literals {
        &self.extracted().strings.literals
    }

    /// Numeric metrics view. Computed on first access and cached.
    pub fn metrics(&self) -> &Metrics {
        &self.extracted().metrics
    }

    /// Typed archive member index.
    ///
    /// Empty for non-archive formats. For ZIP-family files, this is
    /// built from the same central-directory walk that emits
    /// `archive.members[]`, so callers can consume offsets and
    /// metadata without re-reading JSON.
    pub fn archive_members(&self) -> &[ArchiveMember] {
        &self.extracted().archive_members
    }

    /// Borrow the shared tree-sitter parse, if this is a supported
    /// UTF-8 source file and parsing succeeded.
    ///
    /// This is the zero-copy handoff for downstream rule engines: it
    /// returns the same tree used by filefacts's own source extraction
    /// rather than forcing callers to parse the source again.
    pub fn source_ast(&self) -> Option<SourceAst<'_>> {
        self.tree_cache().map(|cache| SourceAst {
            source: cache.source(),
            tree: cache.tree(),
            file_type: cache.file_type(),
        })
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

    /// Unified named-entity facts about this file.
    ///
    /// Every row is a [`Symbol`] tagged by [`SymbolKind`]: imports,
    /// exports, locally-defined functions (with CFG metrics when rizin
    /// disassembled), source call sites, dotted member-access chains,
    /// static bindings, and bare identifiers. Which kinds populate
    /// depends on the file type. Filter with [`Symbols::iter_kind`].
    pub fn symbols(&self) -> &Symbols {
        &self.extracted().symbols
    }

    /// Non-fatal extraction errors encountered during the parse.
    ///
    /// Filefacts always returns as much data as it can: when a goblin
    /// lazy walker panics or a sub-table is truncated, the failure
    /// is recorded here and the rest of the extraction continues.
    /// Empty when nothing went wrong. See [`crate::ParseError`] for
    /// the entry shape.
    pub fn errors(&self) -> &Errors {
        &self.extracted().errors
    }

    /// Iterate every symbol name across the declaration kinds
    /// (`Import`, `Export`, `Function`) for cross-cutting matchers
    /// that ask "any declared name of this value regardless of role."
    /// Yields `(name, source)` so callers can disambiguate when
    /// needed.
    pub fn symbol_iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.symbols().iter().filter_map(|s| match s {
            Symbol::Import { name, source, .. }
            | Symbol::Export { name, source, .. }
            | Symbol::Function { name, source, .. } => Some((name.as_str(), source.as_str())),
            _ => None,
        })
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
    let mut strings = output::Strings::new();
    let mut metrics = Metrics::new();
    let mut archive_members = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut symbols = Symbols::new();
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
        &mut archive_members,
        &mut sections,
        &mut symbols,
        &mut errors,
    ) {
        // The format extractor bailed entirely. Surface that as a
        // `malformed` entry so cleave can see *why* the
        // format-specific view is sparse.
        errors.record_malformed(stage_for(file_type), e.to_string());
    }
    // Tree-sitter source extraction also pushes Call/Member/Bind/
    // Identifier symbols when a parse is available. Bundling here
    // keeps `parse_count` at 1 regardless of which views the caller
    // reads.
    if let Some(cache) = tree_cache {
        formats::source::build_symbols(cache, &mut symbols, &mut metrics);
    }
    let sections = Sections::from_iter_sections(sections);
    // Aggregate metrics derived from sections — mirrors the
    // `sections.*` path convention.
    if !sections.is_empty() {
        emit_section_metrics(&sections, &mut metrics);
        emit_binary_aggregates(&sections, &strings, bytes, &mut metrics);
    }

    // Per-kind counts for ergonomic rule filtering. Derived from the
    // unified `symbols` view.
    emit_symbol_kind_counts(&symbols, &mut metrics);
    if !errors.is_empty() {
        metrics.insert("parse.error_count", errors.len() as f64);
    }

    Extracted {
        values,
        strings,
        metrics,
        archive_members,
        sections,
        symbols,
        errors,
    }
}

/// Emit `imports.count`, `exports.count`, `functions.count`,
/// `calls.count`, `members.count`, `binds.count`, `identifiers.count`
/// for whichever kinds have at least one entry.
fn emit_symbol_kind_counts(symbols: &Symbols, metrics: &mut Metrics) {
    let mut imports = 0u64;
    let mut exports = 0u64;
    let mut functions = 0u64;
    let mut calls = 0u64;
    let mut members = 0u64;
    let mut binds = 0u64;
    let mut identifiers = 0u64;
    for s in symbols {
        match s.kind() {
            SymbolKind::Import => imports += 1,
            SymbolKind::Export => exports += 1,
            SymbolKind::Function => functions += 1,
            SymbolKind::Call => calls += 1,
            SymbolKind::Member => members += 1,
            SymbolKind::Bind => binds += 1,
            SymbolKind::Identifier => identifiers += 1,
        }
    }
    if imports > 0 {
        metrics.insert("imports.count", imports as f64);
    }
    if exports > 0 {
        metrics.insert("exports.count", exports as f64);
    }
    if functions > 0 {
        metrics.insert("functions.count", functions as f64);
    }
    if calls > 0 {
        metrics.insert("calls.count", calls as f64);
    }
    if members > 0 {
        metrics.insert("members.count", members as f64);
    }
    if binds > 0 {
        metrics.insert("binds.count", binds as f64);
    }
    if identifiers > 0 {
        metrics.insert("identifiers.count", identifiers as f64);
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

    // Per-section entropies live on `Section.entropy`. Aggregate
    // max / mean across the sections that have file-backed bytes (the
    // `None` entries are SHT_NOBITS / BSS-style purely-virtual regions
    // and shouldn't pull the mean toward zero).
    let mut entropy_max = 0.0_f64;
    let mut entropy_sum = 0.0_f64;
    let mut entropy_n = 0_u64;
    for s in sections {
        if let Some(e) = s.entropy {
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
    let mut code_size: u64 = 0;
    let mut nonstandard = 0_u64;
    let mut concatenated_names: Vec<u8> = Vec::new();
    for s in sections {
        let is_exec = s
            .flags
            .iter()
            .any(|f| f == "executable" || f == "execinstr");
        let is_write = s.flags.iter().any(|f| f == "writable" || f == "write");
        if is_exec {
            executable += 1;
            code_size = code_size.saturating_add(s.file_size);
        }
        if is_write {
            writable += 1;
        }
        if is_exec && is_write {
            wx += 1;
        }
        if !is_well_known_section_name(&s.name) {
            nonstandard += 1;
        }
        concatenated_names.extend_from_slice(s.name.as_bytes());
    }
    metrics.insert("sections.executable_count", executable as f64);
    metrics.insert("sections.writable_count", writable as f64);
    metrics.insert("sections.executable_writable_count", wx as f64);
    if code_size > 0 {
        metrics.insert("sections.code_size", code_size as f64);
    }
    metrics.insert("sections.nonstandard_count", nonstandard as f64);
    if !concatenated_names.is_empty() {
        metrics.insert(
            "sections.name_entropy",
            scan::entropy::shannon(&concatenated_names),
        );
    }
}

/// `true` when `name` matches a section name routinely produced by
/// upstream toolchains across PE/ELF/Mach-O. Packers and obfuscators
/// rename or invent sections (`.UPX0`, `.aspack`, random hex tags)
/// which trip `sections.nonstandard_count`. Membership is intentionally
/// loose — any section the test corpus shows in benign binaries is in.
fn is_well_known_section_name(name: &str) -> bool {
    // Mach-O sections come in as `SEGMENT,section` (e.g. `__TEXT,__text`).
    // Strip the segment prefix and check the section stem. For PE/ELF
    // we additionally strip a leading dot so dotted (`.text`) and
    // undotted (`text`) forms share the same lookup.
    let stem = name
        .rsplit_once(',')
        .map_or(name, |(_, s)| s)
        .trim_start_matches('.');
    matches!(
        stem,
        // PE / ELF — the canonical set.
        "text" | "rdata" | "data" | "bss" | "rodata" | "idata" | "edata"
        | "pdata" | "xdata" | "tls" | "reloc" | "rsrc" | "debug" | "init"
        | "fini" | "plt" | "got" | "got.plt" | "plt.got" | "plt.sec"
        | "dynamic" | "dynsym" | "dynstr" | "symtab" | "strtab" | "shstrtab"
        | "interp" | "note" | "hash" | "gnu.hash" | "gnu.version"
        | "gnu.version_r" | "gnu.version_d" | "eh_frame" | "eh_frame_hdr"
        | "comment" | "ARM.exidx" | "ARM.extab" | "ARM.attributes"
        | "init_array" | "fini_array" | "preinit_array" | "ctors" | "dtors"
        | "tbss" | "tdata" | "tm_clone_table" | "data.rel.ro"
        | "got.plt.sec" | "stab" | "stabstr" | "drectve" | "didat"
        // Mach-O segment,section combos (after dot-strip we still match the
        // common ones — the names below come from the typical Mach-O
        // layout where `Section.name` is `"__text"`, `"__data"`, etc.,
        // *without* the segment prefix).
        | "__text" | "__data" | "__bss" | "__cstring" | "__const"
        | "__objc_classlist" | "__objc_classrefs" | "__objc_data"
        | "__objc_classname" | "__objc_const" | "__objc_methname"
        | "__objc_methtype" | "__objc_selrefs" | "__objc_imageinfo"
        | "__la_symbol_ptr" | "__nl_symbol_ptr" | "__got" | "__stubs"
        | "__stub_helper" | "__cfstring" | "__unwind_info" | "__eh_frame"
        | "__info_plist" | "__swift5_proto" | "__swift5_types"
        | "__swift5_fieldmd" | "__swift5_typeref" | "__swift5_reflstr"
        | "__swift5_assocty" | "__swift5_capture" | "__swift5_builtin"
        | "__swift5_acfuncs" | "__swift5_mpenum" | "__llvm_covmap"
        | "__llvm_covfun" | "__llvm_prf_cnts" | "__llvm_prf_data"
        | "__llvm_prf_names" | "__llvm_prf_vnds"
    )
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
    strings: &output::Strings,
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
    let entropies: Vec<f64> = sections.iter().filter_map(|s| s.entropy).collect();
    if entropies.len() >= 2 {
        let mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let var =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / entropies.len() as f64;
        metrics.insert("binary.entropy_variance", var);
    }

    // -- Section ratios + size-weighted entropy ----------------------
    // `binary.code_entropy` / `binary.data_entropy` are size-weighted
    // averages of per-section entropies. Weighting by `file_size` is
    // what packer detectors want — a tiny `.init` block at 7.9 entropy
    // shouldn't dominate the `.text` average.
    let mut code_size: u64 = 0;
    let mut data_size: u64 = 0;
    let mut largest: u64 = 0;
    let mut code_entropy_sum = 0.0_f64;
    let mut data_entropy_sum = 0.0_f64;
    for s in sections {
        let is_exec = s
            .flags
            .iter()
            .any(|f| f == "executable" || f == "execinstr");
        let is_write = s.flags.iter().any(|f| f == "writable" || f == "write");
        let on_disk = s.file_size;
        largest = largest.max(on_disk);
        let entropy = s.entropy.unwrap_or(0.0);
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
/// let parsed = filefacts::open_with_path(std::path::Path::new("sample.exe"), &bytes)?;
/// # Ok::<(), filefacts::Error>(())
/// ```
pub fn from_path(path: &Path) -> Result<(Vec<u8>, FileId), Error> {
    let bytes = std::fs::read(path)?;
    let fileid = FileId::from_path_and_bytes(path, &bytes);
    Ok((bytes, fileid))
}

/// Compile a tree-sitter S-expression query against the grammar named
/// `language`. Used by rule engines that want to validate a query
/// string at load time without holding a parsed file. Recognised
/// language names match the values exposed under `values.source.language`
/// (e.g. `"python"`, `"javascript"`, `"perl"`, `"makefile"`).
///
/// Returns `Ok(())` on success; on failure, returns an `Error` whose
/// message identifies whether the language is unknown or the query
/// string is malformed.
pub fn validate_source_query(language: &str, query: &str) -> Result<(), Error> {
    let Some(file_type) = file_type_for_language(language) else {
        return Err(Error::malformed(
            "source",
            format!("unsupported language for ast query: {language}"),
        ));
    };
    let Some(ts_lang) = formats::source::tree_sitter_language(file_type) else {
        return Err(Error::malformed(
            "source",
            format!("no tree-sitter grammar registered for {language}"),
        ));
    };
    tree_sitter::Query::new(&ts_lang, query)
        .map(|_| ())
        .map_err(|e| Error::malformed("source", format!("invalid tree-sitter query: {e}")))
}

fn file_type_for_language(name: &str) -> Option<FileType> {
    Some(match name {
        "c" => FileType::C,
        "python" => FileType::Python,
        "javascript" | "js" => FileType::JavaScript,
        "typescript" | "ts" => FileType::TypeScript,
        "rust" => FileType::Rust,
        "go" => FileType::Go,
        "java" => FileType::Java,
        "ruby" => FileType::Ruby,
        "shell" | "bash" => FileType::Shell,
        "php" => FileType::Php,
        "csharp" | "c#" => FileType::CSharp,
        "lua" => FileType::Lua,
        "perl" => FileType::Perl,
        "powershell" | "ps1" => FileType::PowerShell,
        "swift" => FileType::Swift,
        "objc" | "objective-c" => FileType::ObjectiveC,
        "groovy" => FileType::Groovy,
        "scala" => FileType::Scala,
        "kotlin" => FileType::Kotlin,
        "zig" => FileType::Zig,
        "elixir" => FileType::Elixir,
        "makefile" | "make" => FileType::Makefile,
        _ => return None,
    })
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
        let _ = parsed.text();
        let _ = parsed.literals();
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
    /// Function row in one pass. Used by trait matchers that don't
    /// care which sub-kind a name appears in.
    #[test]
    fn symbol_iter_walks_all_three_collections() {
        let bytes = std::fs::read("../cleave/tests/fixtures/test.exe")
            .expect("test.exe fixture should exist");
        let parsed = open(&bytes).unwrap();
        // Realize the views before iterating — the lazy parse runs
        // on first `.values()` access.
        let _ = parsed.values();
        let symbols = parsed.symbols();
        let import_count = symbols.iter_kind(SymbolKind::Import).count();
        assert!(import_count > 0, "PE fixture should have imports");
        let total = parsed.symbol_iter().count();
        let expected = symbols.iter_kind(SymbolKind::Import).count()
            + symbols.iter_kind(SymbolKind::Export).count()
            + symbols.iter_kind(SymbolKind::Function).count();
        assert_eq!(
            total, expected,
            "symbol_iter must visit every Import/Export/Function row"
        );
        // All PE-sourced entries carry source == "pe".
        let sources: std::collections::HashSet<&str> =
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
