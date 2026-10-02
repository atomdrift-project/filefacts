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
//! - [`Text`] — byte-level printable runs, grouped by extraction
//!   technique.
//! - [`Literals`] — language-defined string literals from source and
//!   structured formats.
//! - [`Metrics`] — derived numeric features (entropy, sizes, counts).
//! - [`Sections`] — binary section / segment listings.
//! - [`Symbols`] — unified named-entity facts (imports, exports,
//!   functions, calls, members, binds, identifiers) tagged by kind.
//! - [`Errors`] — recoverable extractor diagnostics.
//!
//! Alongside the views, [`FileId`] — the result of file-format
//! identification — is always available without computing them.
//!
//! ## Quick start
//!
//! ```no_run
//! let bytes = std::fs::read("sample.exe").unwrap();
//! let parsed = filefacts::open(&bytes);
//!
//! println!("file type: {:?}", parsed.fileid().file_type());
//! for (key, value) in parsed.values().iter() {
//!     println!("{}: {}", key, value);
//! }
//! for s in parsed.text().ascii() {
//!     println!("@{}: {}", s.data_offset, s.value);
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
//! ## Configuration
//!
//! [`open`] uses the library defaults. [`OpenOptions`] supplies a path, a
//! known type or [`FileId`], a cancellation flag, and the cache and rizin
//! settings. Every setting belongs to the [`ParsedFile`] it opens, so one
//! process can open files under different settings at once.
//!
//! ```no_run
//! use std::path::Path;
//!
//! let bytes = std::fs::read("sample.exe").unwrap();
//! let parsed = filefacts::OpenOptions::new()
//!     .path(Path::new("sample.exe"))
//!     .rizin(false)
//!     .open(&bytes);
//! ```
//!
//! ## Side effects
//!
//! Opening a file only identifies it. The first view access runs the
//! extraction, which may spawn an installed rizin: once per process to read
//! its version, and per file to recover symbols from PE, ELF and Mach-O
//! binaries (see [`rizin`]). Turn that off with [`OpenOptions::rizin`].
//!
//! The disk cache in [`cache`] is off unless the host opts in with
//! [`OpenOptions::cache`], or the `FILEFACTS_CACHE` environment variable
//! turns it on for hosts that did not choose. When on, the first view access
//! reads a matching entry from the user cache directory, or writes one after
//! computing the views. The `filefacts` CLI opts in (`FILEFACTS_CACHE=0`
//! still turns it off). Diagnostics are written to stderr only when
//! `FILEFACTS_DEBUG` is set.
//!
//! ## Stability
//!
//! The Rust API follows semantic versioning. The output schema is
//! versioned separately via [`SCHEMA_VERSION`]; field additions are
//! non-breaking, field semantics or renames bump the version.
#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::float_cmp,
        clippy::match_wildcard_for_single_variants,
        clippy::type_complexity,
        clippy::case_sensitive_file_extension_comparisons,
        reason = "test fixtures build binary layouts from literals and compare exact \
                  expected values; the non-test lib target lints production code"
    )
)]

mod bytes;
mod debug;
mod derived_metrics;
pub(crate) use derived_metrics::is_well_known_section_name;
mod embedded_sources;
mod error;
mod formats;
mod go_dependency_context;
mod go_package_context;
pub mod package_context;
pub use go_dependency_context::{ReferenceMember, go_dependency_context};
pub use go_package_context::{
    GoFileFlow, GoPackage, GoPackageFlow, GoSourceContext, go_source_context,
};
mod output;
mod registry;
mod scan;

// The string-extraction and parsing engines whose types appear in this
// crate's API (`Text` rows, `SourceAst::tree`, `Error::InvalidQuery`), so a
// consumer names exactly the versions filefacts was built against.
pub use stng;
pub use tree_sitter;

// `metric!` / `value_key!` resolve keys against the catalogs at compile time;
// re-exported here so every module imports them as `crate::metric`.
pub(crate) use output::{metric, value_key};

pub mod cache;
pub mod cache_sweep;
pub mod fileid;
pub mod tools;

/// Optional rizin/radare2 integration with hardened subprocess
/// discipline (RLIMIT, PR_SET_PDEATHSIG, process-group SIGKILL on
/// timeout / output-cap overflow). Configured per file through
/// [`OpenOptions`]; exposed as a public module only for what is genuinely
/// process-wide: reaping in-flight workers (`kill_all_rizin_groups`) from a
/// signal-handling thread (e.g. `ctrlc`), not an async signal handler, and
/// `tracing` telemetry (`stats`, `log_stats`).
pub mod rizin;

pub use formats::source::decode_source_escapes;
pub use formats::source::go_package_payload_flow;

/// Additional reference metadata selected by filename, independently of the
/// detected file type. Archive walkers must retain these even when detection
/// calls them non-program data. Type-identified manifests need no exception.
#[must_use]
pub fn has_named_reference_metadata(path: &std::path::Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("go.work" | "go.work.sum" | "modules.txt")
    )
}

pub use output::{Flow, FlowFunction, FlowKind, FlowOrigin, FlowOrigins, FlowTransfer, FlowValue};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub use embedded_sources::EmbeddedSource;
pub use error::Error;
pub use fileid::{ArchiveFormat, Compression, Container, FileId, FileType, container_of};
pub use output::{
    ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership, Arg, ArgShape, CATALOG,
    Claim, Comments, Diagnostic, DiagnosticKind, Errors, FAMILIES, Fact, HashAlgo, Identity,
    Literal, LiteralEncoding, LiteralMethod, Literals, MetricKey, Metrics, Party, PinnedHash,
    QueryLimit, RefKind, RefLocator, Reference, Section, SectionFlag, Sections, Signer, Span,
    Stage, Symbol, SymbolKind, Symbols, Text, Trust, Url, UrlKind, VALUE_CATALOG, VALUE_FAMILIES,
    ValueKey, Values, archive_entry_type_count, archive_method_count, ast_op, ast_op_density,
    dmg_codec_count, extension_content_mismatch, source_query_limited,
};
pub use registry::Registry;

/// Every metric key this build can emit, as fixed names plus the templates
/// for the few keys with a data-derived segment.
///
/// This is the enumeration downstream validators consume — cleave checks
/// every `type: metrics` field in the trait corpus against it, so a rule
/// naming a metric that no extractor emits is a build-time error there
/// rather than a rule that silently never fires. Deriving the same list by
/// scanning filefacts' source is the thing this exists to replace.
#[must_use]
pub fn known_metrics() -> (&'static [&'static str], &'static [&'static str]) {
    (CATALOG, FAMILIES)
}

/// Every [`Values`] key this build can write, as fixed keys
/// ([`VALUE_CATALOG`]) plus templates for keys with a data-derived segment
/// inside the path ([`VALUE_FAMILIES`]).
///
/// This is the [`known_metrics`] counterpart for `type: values` rule fields.
/// Unlike a metric, a value can be an object or an array that a rule reaches
/// into, so a validator should accept a rule path when it:
///
/// - equals a fixed key;
/// - extends a fixed key with `.` or `[`, as in `pe.signatures[0].subject`,
///   `pdf.info.Author` or `npm.author.email`. This also covers data tails
///   written below a key, such as `pkg.<field>` or `wasm.producers.<field>`;
/// - matches a template, where each `<name>` placeholder stands for a
///   non-empty run of characters other than `.` and `[`, either exactly or
///   extended with `.` or `[` as above.
///
/// An index in a rule path, whether `[0]` or the `[*]` wildcard, matches the
/// same way. One kind of path is outside this list: the parsed document of a
/// structured format (JSON, YAML, TOML, plist, `PKG-INFO` and Xcode project
/// files), which filefacts places at the values root verbatim. A rule that
/// reads such a document's own fields, such as `scripts.postinstall` in a
/// `package.json`, names data rather than a filefacts key, so the validator
/// should not report it as unknown.
#[must_use]
pub fn known_values() -> (&'static [&'static str], &'static [&'static str]) {
    (VALUE_CATALOG, VALUE_FAMILIES)
}

/// Schema version of the public output shape.
///
/// Bumps on any field rename or semantic change. Field additions are
/// non-breaking and do not bump this version. The on-disk cache carries a
/// distinct [`cache::CACHE_SCHEMA_VERSION`], bumped only for breaking
/// changes to its format; entries from older builds are never reused
/// because every cache key includes a hash of filefacts' source.
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
///
/// **v7** — adds the [`Identity`] view: normalized, cross-format
/// identity claims (name, identifier, project, signer, trust tier,
/// authors, document title/producer, unique ids) folded out of the
/// per-format structural values, each tagged claimed-vs-verified.
///
/// **v8** — metrics gain byte-span provenance. A *located* metric (one
/// measured from a specific region — `binary.peak_region_entropy`,
/// `text.invisible_chars`, `sections.entropy_max`, …) now serializes as
/// `{"value": n, "spans": [{"offset", "len"}, …]}` instead of a bare
/// number; unlocated metrics are unchanged. This is a value-shape change,
/// so a consumer parsing every metric as a number must handle the object
/// form. `stng::ExtractedString` also gains a `data_len` source extent.
///
/// **v9** — 75 value and metric keys are renamed to follow one naming
/// convention (21 value keys, 54 metric keys); no key changes meaning or
/// value except its name. Package links and identity fold onto the
/// cross-format names (`whl.home_page`, `crx.homepage_url`, `rpm.url` →
/// `<fmt>.homepage`; `deb.package`, `nupkg.id`, `apk.pkgname` →
/// `<fmt>.name`), `pe.imphash` moves to `pe.hashes.imphash` beside the ELF
/// and Mach-O fingerprints, counts take `_count` (`scpt.handlers` →
/// `scpt.handler_count`), abbreviations are spelled out
/// (`binary.huge_func_count` → `binary.huge_function_count`), and units
/// that are not bytes become a suffix (`deb.installed_size` →
/// `deb.installed_size_kib`). Identity claim sources name the new keys.
/// `docs/NAMING.md` states the convention and `docs/schema-v9-renames.tsv`
/// lists every old → new pair. Section flags share one vocabulary
/// ([`SectionFlag`]), so ELF's `write` is now `writable` in both the sections
/// view and `elf.sections[].flags`. A [`Reference`] with no locatable
/// position omits `offset` rather than writing `0`, and a VBA import built at
/// run time carries no `<non-literal>` placeholder: a non-literal `Lib`
/// leaves `library` absent and a non-literal ProgID emits no import.
pub const SCHEMA_VERSION: &str = "9";

/// A file with its bytes and lazily-computed metadata views.
///
/// `ParsedFile` is the central type. Construct one with [`open`] or its
/// path-aware variants; [`from_path`] reads the bytes from disk first.
///
/// Views are computed on first access and cached for the lifetime of
/// the `ParsedFile`. That first access may spawn rizin, and reads and
/// writes the disk cache when the host enabled it; see the crate-level
/// "Side effects" section.
///
/// Typed fact families such as strings, sections, symbols, AST
/// projections, and recoverable errors live in their own views;
/// [`values`] is only for residual format structure that does not
/// already have a typed home.
///
/// [`values`]: ParsedFile::values
#[must_use = "ParsedFile owns the extraction pipeline; dropping it discards every view"]
pub struct ParsedFile<'a> {
    bytes: &'a [u8],
    fileid: FileId,
    // Basename of the path given to `OpenOptions::path`. None when the
    // file was opened from a byte slice with no associated path. When
    // present, surfaced as the `file.basename` value during extraction so
    // traits can match against it via `type: value, path: file.basename`.
    basename: Option<String>,
    // Shared tree-sitter parse for source files. Built once by
    // `tree_cache()` and consumed by the single extraction pipeline
    // that fills `extracted`.
    tree_parse: OnceLock<Option<formats::source::TreeParse<'a>>>,
    flow: OnceLock<Option<Flow>>,
    /// `Err` holds the panic the CFML parse raised.
    cfml_parse: OnceLock<Option<Result<formats::cfml::Parsed, PanicMessage>>>,
    // Caller's cancellation flag, polled by long-running leaf work (currently
    // the tree-sitter parse). Borrowed rather than `Arc`-shared, and never
    // written here: filefacts only ever reads it.
    cancellation: Option<&'a AtomicBool>,
    // Whether `extracted` reads and writes the disk cache.
    cache: bool,
    // The host's addition to every disk-cache key (`OpenOptions::cache_namespace`).
    cache_namespace: Option<Arc<str>>,
    // This file's rizin settings, carried into the extraction.
    rizin: rizin::Settings,
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

/// The owned, serializable extraction snapshot. Round-trips through the
/// disk cache ([`crate::cache`]) so the expensive recovery — chiefly the
/// rizin disassembly pass folded into `symbols`/`sections`/`metrics` —
/// is computed once per `(content, filefacts build, rizin config)` and
/// reused across processes rather than re-run on every `open`.
#[derive(serde::Serialize, serde::Deserialize)]
struct Extracted {
    values: Values,
    strings: output::Strings,
    metrics: Metrics,
    archive_members: Vec<ArchiveMember>,
    sections: Sections,
    symbols: Symbols,
    identity: Identity,
    references: Vec<Reference>,
    errors: Errors,
}

/// On-disk cache form of [`Extracted`]. The byte-scan `text` rows are stored
/// as one list in extraction order: `Text`'s own serialized form groups them
/// by encoding, which would hand a second `open` the rows in another order.
///
/// They are cached under filefacts' key like everything else here, and that
/// key covers `Cargo.toml` (see `build.rs`), which pins stng to an exact
/// commit: bumping stng retires every entry, with no version to maintain.
#[derive(serde::Serialize, serde::Deserialize)]
struct ExtractedSnapshot {
    values: Values,
    /// The rows `Text` shares, not a copy of them: snapshotting a fresh
    /// extraction for the cache must not clone every string.
    #[serde(with = "shared_rows")]
    text: std::sync::Arc<[stng::ExtractedString]>,
    literals: output::Literals,
    comments: output::Comments,
    metrics: Metrics,
    archive_members: Vec<ArchiveMember>,
    sections: Sections,
    symbols: Symbols,
    identity: Identity,
    references: Vec<Reference>,
    errors: Errors,
}

impl From<Extracted> for ExtractedSnapshot {
    fn from(e: Extracted) -> Self {
        Self {
            values: e.values,
            text: std::sync::Arc::clone(e.strings.text.rows()),
            literals: e.strings.literals,
            comments: e.strings.comments,
            metrics: e.metrics,
            archive_members: e.archive_members,
            sections: e.sections,
            symbols: e.symbols,
            identity: e.identity,
            references: e.references,
            errors: e.errors,
        }
    }
}

impl From<ExtractedSnapshot> for Extracted {
    fn from(s: ExtractedSnapshot) -> Self {
        Self {
            values: s.values,
            strings: output::Strings {
                text: output::Text::from_rows(s.text),
                literals: s.literals,
                comments: s.comments,
            },
            metrics: s.metrics,
            archive_members: s.archive_members,
            sections: s.sections,
            symbols: s.symbols,
            identity: s.identity,
            references: s.references,
            errors: s.errors,
        }
    }
}

/// Serde for a shared row slice: written as a sequence straight from the
/// borrowed rows, read back into a fresh `Arc`.
mod shared_rows {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub(super) fn serialize<S: Serializer>(
        rows: &Arc<[stng::ExtractedString]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(rows.iter())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Arc<[stng::ExtractedString]>, D::Error> {
        Vec::<stng::ExtractedString>::deserialize(deserializer).map(Arc::from)
    }
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

    /// Declared script bodies in a supported container format. Bodies borrow
    /// the parsed values; no script is executed and no reference is fetched.
    /// Unknown interpreters remain explicit rather than being guessed from text.
    pub fn embedded_sources(&self) -> impl Iterator<Item = EmbeddedSource<'_>> {
        // Each reader sees the value tree only for the format it understands,
        // and only that format pays for the extraction.
        let file_type = self.fileid.file_type();
        let actions = (file_type == FileType::GithubActions).then(|| self.values());
        let rpm = (file_type == FileType::Rpm).then(|| self.values());
        embedded_sources::github_actions(actions).chain(embedded_sources::rpm(rpm))
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

    /// Source-code comment bodies — the comment-scoped tier. Populated
    /// for source files from the language's comment style. Matching here
    /// never fires on a keyword in code or a string, only in a genuine
    /// comment. Computed on first access and cached.
    pub fn comments(&self) -> &Comments {
        &self.extracted().strings.comments
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

    /// Lazily compute format-neutral value relationships.
    /// No security policy or library model is assumed. Reading other views
    /// does not pay for this graph, and repeated reads never parse again.
    /// Returns `None` when flow extraction is unavailable, not an empty graph.
    /// Source parsers (tree-sitter and bounded CFML tags) produce flow; binary flow recovery is
    /// not implemented. The graph records its producer and known limitations.
    pub fn flow(&self) -> Option<&Flow> {
        if let Some(parsed) = self.cfml_parse() {
            return Some(&parsed.flow);
        }
        self.flow
            .get_or_init(|| {
                let cache = self.tree_cache()?;
                // A panic leaves flow unavailable rather than taking the
                // caller down; the other views are unaffected.
                guarded(|| formats::source::build_value_flow(cache, self.symbols())).ok()
            })
            .as_ref()
    }

    /// Normalized identity claims: who and what the artifact says it
    /// is, folded across formats into one shape and tagged
    /// claimed-vs-verified. Computed on first access and cached.
    ///
    /// Empty (see [`Identity::is_empty`]) for files that assert no
    /// identity and carry no signature.
    pub fn identity(&self) -> &Identity {
        &self.extracted().identity
    }

    /// External references this artifact points at — declared packages,
    /// install-hook URLs, staged downloads — normalized to PURL where the
    /// ecosystem is identifiable, else a raw URL. Recorded, never fetched;
    /// a downstream fetcher resolves and verifies them. Empty for files
    /// that reference nothing. Computed on first access and cached.
    pub fn references(&self) -> &[Reference] {
        &self.extracted().references
    }

    /// Non-fatal extraction errors encountered during the parse.
    ///
    /// Filefacts always returns as much data as it can: when a goblin
    /// lazy walker panics or a sub-table is truncated, the failure
    /// is recorded here and the rest of the extraction continues.
    /// Empty when nothing went wrong. See [`crate::Diagnostic`] for
    /// the entry shape.
    pub fn errors(&self) -> &Errors {
        &self.extracted().errors
    }

    /// Whether rizin symbol recovery was attempted but did not complete
    /// on this run.
    ///
    /// `true` means rizin is installed (so the symbol/section views would
    /// normally be rizin-grade) yet this particular run produced nothing
    /// — it timed out, was killed on the output cap, or had turned itself
    /// off after too many abandoned output readers. The bytes are
    /// unchanged, so a later run may succeed; a caller caching analysis
    /// output keyed by content **must not persist a payload while this is
    /// `true`**, or the degraded result would be served to every future
    /// run. Pair with [`crate::cache::Computed::Transient`] and
    /// [`OpenOptions::rizin_fingerprint`]. Always `false` when rizin is not
    /// installed, turned off with [`OpenOptions::rizin`], or skipped the
    /// input under [`OpenOptions::rizin_max_bytes`]: those results are
    /// correct for that environment and those settings, and keyed as such.
    pub fn rizin_recovery_incomplete(&self) -> bool {
        rizin_incomplete(self.metrics())
    }

    /// Iterate every symbol name across the declaration kinds
    /// (`Import`, `Export`, `Function`) for cross-cutting matchers
    /// that ask "any declared name of this value regardless of role."
    pub fn symbol_iter(&self) -> impl Iterator<Item = &str> {
        self.symbols().iter().filter_map(|s| match s {
            Symbol::Import { name, .. }
            | Symbol::Export { name, .. }
            | Symbol::Function { name, .. } => Some(name.as_str()),
            _ => None,
        })
    }

    /// Borrow the shared tree-sitter parse, if this file is a source
    /// language and parsing succeeded.
    fn tree_cache(&self) -> Option<&formats::source::TreeCache<'a>> {
        self.tree_parse()
            .and_then(formats::source::TreeParse::cache)
    }

    fn tree_parse(&self) -> Option<&formats::source::TreeParse<'a>> {
        self.tree_parse
            .get_or_init(|| {
                if !formats::source::supports(self.fileid.file_type()) {
                    return None;
                }
                let parsed = guarded(|| {
                    formats::source::TreeCache::parse(
                        self.bytes,
                        self.fileid.file_type(),
                        self.cancellation,
                    )
                });
                Some(parsed.unwrap_or_else(|panic| {
                    formats::source::TreeParse::Unavailable(
                        formats::source::TreeSitterDiagnostic::parse_failed(panic.0),
                    )
                }))
            })
            .as_ref()
    }

    /// Number of times this `ParsedFile` ran its extraction pipeline.
    ///
    /// `0` before any view has been requested, and stays `0` when the
    /// views were served from the disk cache; otherwise `1` after the
    /// first call to any extraction view (`values()`, `text()`,
    /// `metrics()`, `symbols()`, …). A correctly-implemented `ParsedFile`
    /// never reports a higher count, regardless of which combination of
    /// views the caller reads.
    pub fn parse_count(&self) -> u32 {
        self.parse_count.load(Ordering::Acquire)
    }

    fn cfml_parse(&self) -> Option<&formats::cfml::Parsed> {
        self.cfml_outcome()?.as_ref().ok()
    }

    fn cfml_outcome(&self) -> Option<&Result<formats::cfml::Parsed, PanicMessage>> {
        if self.fileid.file_type() != FileType::Cfml {
            return None;
        }
        self.cfml_parse
            .get_or_init(|| Some(guarded(|| formats::cfml::parse(self.bytes))))
            .as_ref()
    }

    fn extracted(&self) -> &Extracted {
        self.extracted.get_or_init(|| {
            if !self.cache {
                return self.run_pipeline();
            }
            // The disk cache is keyed by (content, filefacts build, detected
            // type, basename, rizin settings). Type belongs in the key because detection
            // may use the logical filename: identical gzip bytes named
            // `package.tgz` and `hash.sample` are npm and generic gzip inputs,
            // respectively, and expose different identity/structure views.
            // Basename also produces facts independent of detected type:
            // `build.rs` and `lib.rs` must not share `file.basename`, nor may
            // Go workspace and module metadata inherit one another's context.
            // A degraded rizin run, or a source parse stopped by the
            // wall-clock backstop or cancellation, is returned but not
            // persisted, so a later healthy run still gets to fill the entry.
            let variant = extraction_cache_variant(
                &self.rizin,
                self.cache_namespace.as_deref(),
                self.fileid.file_type(),
                self.fileid.extension_mismatch(),
                self.fileid.extension_mismatch_transition(),
                self.basename.as_deref(),
            );
            let snapshot: Option<ExtractedSnapshot> =
                cache::open_with_cache(self.bytes, &variant, |_| {
                    let extracted = self.run_pipeline();
                    let transient = rizin_incomplete(&extracted.metrics)
                        || self
                            .tree_parse()
                            .and_then(formats::source::TreeParse::diagnostic)
                            .is_some_and(formats::source::TreeSitterDiagnostic::is_transient);
                    let snapshot = ExtractedSnapshot::from(extracted);
                    if transient {
                        Some(cache::Computed::Transient(snapshot))
                    } else {
                        Some(cache::Computed::Cacheable(snapshot))
                    }
                });
            // `None` only when the closure declines, which it never does.
            snapshot.map_or_else(|| self.run_pipeline(), Extracted::from)
        })
    }

    /// Run the extraction pipeline once and count it. The single place
    /// `run_extraction` is invoked, whether the result is destined for the
    /// cache or returned directly.
    fn run_pipeline(&self) -> Extracted {
        self.parse_count.fetch_add(1, Ordering::AcqRel);
        let mut extracted = run_extraction(
            self.bytes,
            &self.fileid,
            self.basename.as_deref(),
            self.tree_cache(),
            self.tree_parse()
                .and_then(formats::source::TreeParse::diagnostic),
            self.rizin,
        );
        match self.cfml_outcome() {
            Some(Ok(parsed)) => {
                for symbol in parsed.symbols.iter() {
                    extracted.symbols.push(symbol.clone());
                }
            }
            Some(Err(panic)) => {
                extracted
                    .errors
                    .record_panic(Stage::SourceParse, panic.0.clone());
                extracted
                    .metrics
                    .insert(metric!("parse.error_count"), extracted.errors.len() as f64);
            }
            None => {}
        }
        extracted
    }
}

/// The message of a panic caught by [`guarded`].
#[derive(Debug)]
struct PanicMessage(String);

/// Run parse work that sits outside the extraction pipeline's own
/// `catch_unwind` (the source parse, the CFML parse, the flow graph), turning
/// a panic into its message. Without this, one malformed file takes down the
/// whole host process.
fn guarded<T>(work: impl FnOnce() -> T) -> Result<T, PanicMessage> {
    match formats::goblin_safe::catch_infallible(work) {
        formats::goblin_safe::GoblinOutcome::Ok(value) => Ok(value),
        formats::goblin_safe::GoblinOutcome::Panicked(message) => Err(PanicMessage(message)),
        // `catch_infallible` runs no goblin call, so it never reports one
        // failing; carry the text rather than assert that.
        formats::goblin_safe::GoblinOutcome::Failed(error) => Err(PanicMessage(error.to_string())),
    }
}

/// Whether a rizin run that should have recovered symbols did not complete.
/// Both the public predicate and the don't-persist decision read it here, so
/// they cannot disagree; `metric!` checks the key against the catalog.
fn rizin_incomplete(metrics: &Metrics) -> bool {
    metrics
        .get(metric!("binary.rizin_incomplete").as_str())
        .is_some()
}

/// Everything besides the bytes and the build that a cached extraction
/// depends on (see [`ParsedFile::extracted`]); [`cache::cache_key`] folds in
/// the rest.
fn extraction_cache_variant(
    rizin: &rizin::Settings,
    namespace: Option<&str>,
    file_type: FileType,
    extension_mismatch: bool,
    mismatch_transition: Option<(&'static str, &'static str)>,
    basename: Option<&str>,
) -> String {
    // The content/extension transition is path-derived but lands in the
    // extraction output as `consistency.extension_content_mismatch.*`, so it
    // belongs in the key: identical bytes named `x.woff2` and `x.wav` detect
    // as the same type but produce different metrics, and must not share an
    // entry. Without this, whichever name was scanned first won and every
    // later identical-byte file inherited its verdict — a shell script named
    // `.woff2` reported `script_as_unknown` (missing the masquerade) or a
    // `.wav` reported `script_as_font` (inventing one), purely by scan order.
    //
    // The *group* is folded in rather than the raw extension, so the key
    // space stays small: every unrecognised suffix collapses to one bucket,
    // and the thousands of `.woff2` fonts in a tree still share entries.
    let transition = match (extension_mismatch, mismatch_transition) {
        (false, _) => std::borrow::Cow::Borrowed("-"),
        (true, None) => std::borrow::Cow::Borrowed("?"),
        (true, Some((content, ext))) => std::borrow::Cow::Owned(format!("{content}_as_{ext}")),
    };
    format!(
        "{};namespace={namespace:?};file_type={};mismatch={};basename={basename:?}",
        rizin::cache_fingerprint(rizin),
        file_type.label(),
        transition
    )
}

fn run_extraction(
    bytes: &[u8],
    fileid: &FileId,
    basename: Option<&str>,
    tree_cache: Option<&formats::source::TreeCache<'_>>,
    tree_diagnostic: Option<&formats::source::TreeSitterDiagnostic>,
    rizin: rizin::Settings,
) -> Extracted {
    let file_type = fileid.file_type();
    let extension_mismatch = fileid.extension_mismatch();
    let mismatch_transition = fileid.extension_mismatch_transition();
    let xor_pe_key = fileid.xor_pe_key();
    let mut values = Values::new();
    let mut strings = output::Strings::new();
    let mut metrics = Metrics::new();
    let mut archive_members = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut image_end: Option<u64> = None;
    let mut symbols = Symbols::new();
    let mut errors = Errors::new();
    if fileid.source() == fileid::DetectionSource::Failed {
        errors.record_panic(Stage::Identify, "file identification panicked");
    }
    if let Some(name) = basename {
        values.insert_key(
            value_key!("file.basename"),
            serde_json::Value::String(name.to_string()),
        );
        values.insert_key(
            value_key!("file.stem"),
            serde_json::Value::String(formats::common::stem(name)),
        );
    }
    // Content-based detection disagreed with the file's extension — a
    // low-friction masquerade signal. Emitted only when true (and only when a
    // path/extension was supplied), mirroring the pe.dos_stub_* convention.
    // The typed sub-metric names the content→extension group transition
    // (e.g. `…_mismatch.binary_as_image` for a PE named `.png`) so a trait can
    // decide which transitions are dangerous instead of relying on a severity
    // verdict baked in here.
    if extension_mismatch {
        metrics.insert(metric!("consistency.extension_content_mismatch"), 1.0);
        if let Some((content, ext)) = mismatch_transition {
            metrics.insert(crate::extension_content_mismatch(content, ext), 1.0);
        }
    }
    if let Some(diagnostic) = tree_diagnostic {
        metrics.insert(metric!("source.ast_unavailable"), 1.0);
        metrics.insert(diagnostic.metric.clone(), 1.0);
        errors.record_fallback(crate::Stage::SourceParse, diagnostic.message.clone());
    }
    // Format extractors return `Result` so they can report a hard
    // "this file is not in the format I expect" failure. Any
    // recoverable mid-extraction issues (goblin lazy-walker panics,
    // truncated sub-tables, permissive-mode fallbacks) are recorded
    // through the typed `Errors` view instead — we want consumers to
    // get everything we did manage to extract even when some sub-
    // stage failed, since cleave depends on the partial data.
    let extract_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        formats::extract(
            file_type,
            bytes,
            tree_cache,
            formats::ExtractCtx {
                values: &mut values,
                strings: &mut strings,
                metrics: &mut metrics,
                archive_members: &mut archive_members,
                sections: &mut sections,
                symbols: &mut symbols,
                errors: &mut errors,
                image_end: &mut image_end,
                basename,
                xor_pe_key,
                rizin,
            },
        )
    }));
    match extract_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // The format extractor bailed entirely. Surface that as a
            // `malformed` entry so cleave can see *why* the
            // format-specific view is sparse.
            errors.record_malformed(stage_for(file_type), error::display_chain(&e));
        }
        Err(payload) => {
            let stage = stage_for(file_type);
            if stage == Stage::SourceExtract {
                metrics.insert(metric!("source.extract_panicked"), 1.0);
                metrics.insert(metric!("source.ast_unavailable"), 1.0);
            }
            errors.record_panic(stage, panic_payload_message(payload));
        }
    }
    // Tree-sitter source extraction also pushes Call/Member/Bind/
    // Identifier symbols when a parse is available. Bundling here
    // keeps `parse_count` at 1 regardless of which views the caller
    // reads.
    if let Some(cache) = tree_cache {
        let walk_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            formats::source::build_symbols(cache, &mut symbols, &mut metrics);
        }));
        if let Err(payload) = walk_result {
            metrics.insert(metric!("source.ast_walk_panicked"), 1.0);
            metrics.insert(metric!("source.ast_unavailable"), 1.0);
            errors.record_panic(Stage::SourceAstWalk, panic_payload_message(payload));
        }
    }
    let sections = Sections::from_iter(sections);
    // Aggregate metrics derived from sections — mirrors the
    // `sections.*` path convention.
    if !sections.is_empty() {
        derived_metrics::emit_section_metrics(&sections, &mut metrics);
        derived_metrics::emit_binary_aggregates(&sections, &strings, bytes, &mut metrics);
    }
    if image_end.is_some() || !sections.is_empty() {
        derived_metrics::emit_binary_overlay(&sections, bytes, image_end, &mut metrics);
    }

    // Per-kind counts for ergonomic rule filtering. Derived from the
    // unified `symbols` view.
    derived_metrics::emit_symbol_kind_counts(&symbols, &mut metrics);
    if !errors.is_empty() {
        metrics.insert(metric!("parse.error_count"), errors.len() as f64);
    }

    // Fold the per-format structural values into the normalized,
    // cross-format identity view. Runs last so it can read everything
    // every extractor wrote (signature fields, manifest claims,
    // document properties). Never fails — absent inputs yield an empty
    // identity.
    let identity = formats::identity::derive(file_type, bytes, &values);

    // External references this file points at (declared packages, install
    // hooks, staged URLs), normalized to PURL/URL. Reads the same `values`
    // the format extractors wrote; never fetches.
    let references = formats::references::derive(file_type, bytes, &values);

    Extracted {
        values,
        strings,
        metrics,
        archive_members,
        sections,
        symbols,
        identity,
        references,
        errors,
    }
}

/// Map a [`FileType`] to the [`Stage`] we tag against when an
/// extractor returns `Err` and we have to synthesise a fallback
/// error record. Stage values are stable across releases.
fn stage_for(file_type: FileType) -> Stage {
    // Every tree-sitter language, so a new grammar needs no entry here. JCL
    // has no grammar but has always reported as source.
    if formats::source::supports(file_type) || file_type == FileType::Jcl {
        return Stage::SourceExtract;
    }
    match file_type {
        FileType::Pe => Stage::PeParse,
        FileType::Elf => Stage::ElfParse,
        FileType::MachO => Stage::MachoParse,
        FileType::Ooxml => Stage::OoxmlParse,
        FileType::OleDoc | FileType::Msi => Stage::Ole2Parse,
        FileType::Zip | FileType::Crx | FileType::Odf | FileType::Jar => Stage::ZipParse,
        FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst => {
            Stage::TarParse
        }
        FileType::JavaClass => Stage::ClassParse,
        FileType::Pdf => Stage::PdfParse,
        FileType::Rpm => Stage::RpmParse,
        FileType::Wasm => Stage::WasmParse,
        FileType::SevenZ => Stage::SevenZipParse,
        _ => Stage::FormatExtract,
    }
}

fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => String::new(),
        },
    }
}

impl<'a> ParsedFile<'a> {
    fn new(bytes: &'a [u8], fileid: FileId, basename: Option<String>) -> Self {
        Self {
            bytes,
            fileid,
            basename,
            tree_parse: OnceLock::new(),
            flow: OnceLock::new(),
            cfml_parse: OnceLock::new(),
            cancellation: None,
            cache: false,
            cache_namespace: None,
            rizin: rizin::Settings::default(),
            extracted: OnceLock::new(),
            parse_count: AtomicU32::new(0),
        }
    }
}

/// The basename surfaced as `file.basename`. Lossy rather than dropped: a
/// name that is not valid UTF-8 is common among samples, and losing it would
/// hide `file.basename` / `file.stem` from exactly those files.
fn basename_of(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// How [`OpenOptions::open`] settles the file type.
#[derive(Clone, Copy, Debug)]
enum Identification {
    /// Detect from the bytes, and from the path when one was given.
    Detect,
    /// The caller's type, bypassing detection ([`OpenOptions::file_type`]).
    Forced(FileType),
    /// The caller's own detection result ([`OpenOptions::fileid`]).
    Precomputed(FileId),
}

/// How to open bytes as a [`ParsedFile`]: what identification may use, and
/// the settings its extraction runs under.
///
/// Every setting belongs to the `ParsedFile` it opens. Nothing here is
/// process-wide, so one process can open files under different settings at
/// the same time — rizin on for one and off for another, the disk cache on
/// for one and off for another — without either seeing the other's.
///
/// [`OpenOptions::new`] gives the library defaults; [`open`] is shorthand
/// for opening with them. Setters consume and return the options, and
/// [`open`](Self::open) borrows them, so one value configured once can open
/// many files (clone it to vary the path per file):
///
/// ```no_run
/// use std::path::Path;
/// use std::time::Duration;
///
/// let options = filefacts::OpenOptions::new().rizin_timeout(Duration::from_secs(60));
/// for name in ["a.exe", "b.so"] {
///     let bytes = std::fs::read(name)?;
///     let parsed = options.clone().path(Path::new(name)).open(&bytes);
///     println!("{name}: {:?}", parsed.fileid().file_type());
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
#[must_use]
#[derive(Clone, Debug)]
pub struct OpenOptions<'a> {
    path: Option<PathBuf>,
    identification: Identification,
    cancellation: Option<&'a AtomicBool>,
    cache: bool,
    cache_namespace: Option<Arc<str>>,
    rizin: rizin::Settings,
}

impl Default for OpenOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> OpenOptions<'a> {
    /// The library defaults:
    ///
    /// * identification from the bytes alone (until [`path`](Self::path)
    ///   is given);
    /// * no cancellation flag;
    /// * the disk cache off, unless the `FILEFACTS_CACHE` environment
    ///   variable turns it on (see [`cache::env_override`]);
    /// * rizin on when it is installed, with a
    ///   [`rizin::DEFAULT_RIZIN_TIMEOUT_SECS`] budget per run, no size cap,
    ///   and every slice of a fat Mach-O analysed.
    pub fn new() -> Self {
        Self {
            path: None,
            identification: Identification::Detect,
            cancellation: None,
            cache: cache::env_override().unwrap_or(false),
            cache_namespace: None,
            rizin: rizin::Settings::default(),
        }
    }

    /// The file's path, for identification and for `file.basename`.
    ///
    /// Some formats are only distinguishable by extension or well-known
    /// basename (`package.json` is JSON byte for byte but carries different
    /// metadata than a generic JSON document), so pass the path when you have
    /// it. The basename is surfaced as the `file.basename` and `file.stem`
    /// values. Nothing is read from the path.
    pub fn path(mut self, path: &Path) -> Self {
        self.path = Some(path.to_path_buf());
        self
    }

    /// Force the file type, bypassing content and extension detection.
    ///
    /// Identification normally trusts magic bytes, then the path/extension,
    /// then content heuristics. Some callers already know the language from
    /// context the bytes don't carry, and detection would otherwise give the
    /// wrong answer or fall back to [`FileType::Unknown`]. The motivating
    /// case is an interpreter inline-code payload: the body extracted from
    /// `python3 -c "<code>"` is genuine Python, but stripped of its shebang
    /// and carried under a virtual path with no usable extension, so the
    /// detector can't see it. Forcing the type lets
    /// [`ParsedFile::source_ast`] select the correct tree-sitter grammar.
    ///
    /// A [`path`](Self::path) then only supplies the basename. Replaces an
    /// earlier [`fileid`](Self::fileid).
    pub fn file_type(mut self, file_type: FileType) -> Self {
        self.identification = Identification::Forced(file_type);
        self
    }

    /// Use a [`FileId`] the caller already computed with
    /// [`FileId::from_path_and_bytes`] instead of detecting again. Detection
    /// on a compressed tar inflates up to 64 MiB of it to decide npm/sdist,
    /// so a caller that has already paid for that must not pay it twice.
    ///
    /// A [`path`](Self::path) then only supplies the basename. Replaces an
    /// earlier [`file_type`](Self::file_type).
    pub fn fileid(mut self, fileid: FileId) -> Self {
        self.identification = Identification::Precomputed(fileid);
        self
    }

    /// Poll `flag` during long-running leaf work, abandoning it when the flag
    /// goes true. Currently observed by the tree-sitter parse, the one leaf
    /// that can run long on adversarial input without spawning a process.
    ///
    /// Cancelling is *not* an error: the affected view degrades to a
    /// diagnostic (`source.ast_unavailable.parse_cancelled`) and every other
    /// fact family still extracts, so a caller that cancels mid-file still
    /// gets a usable — if shallower — result.
    ///
    /// The flag is borrowed for the [`ParsedFile`]'s lifetime. filefacts
    /// only ever reads it, never sets it, which is what makes it safe to
    /// share across threads without an `Arc` here.
    ///
    /// Rizin is deliberately *not* wired to this: it enforces its own hard
    /// wall-clock budget ([`rizin_timeout`](Self::rizin_timeout)) and kills
    /// its process group, so it is already bounded.
    pub fn cancellation(mut self, flag: &'a AtomicBool) -> Self {
        self.cancellation = Some(flag);
        self
    }

    /// Read and write the disk cache in [`cache`].
    ///
    /// When on, the first view access reads a matching entry from the user
    /// cache directory, or writes one after computing the views; a later open
    /// of the same bytes, under the same settings, skips the extraction (and
    /// its rizin run). The key covers the bytes, the filefacts build, the
    /// detected type, the basename and
    /// [`rizin_fingerprint`](Self::rizin_fingerprint). Outranks
    /// `FILEFACTS_CACHE`.
    pub fn cache(mut self, enabled: bool) -> Self {
        self.cache = enabled;
        self
    }

    /// Add `namespace` to every disk-cache key, so entries written under a
    /// different namespace are never read.
    ///
    /// The key already covers filefacts' source and, when the build finds
    /// it, the `Cargo.lock` that chose filefacts' dependency versions. A
    /// host that builds with a relocated target directory (where that lock
    /// is not found), or that wants its own invalidation, passes something
    /// that changes with what it ships — a hash of its own lockfile, its
    /// version.
    pub fn cache_namespace(mut self, namespace: &str) -> Self {
        self.cache_namespace = Some(Arc::from(namespace));
        self
    }

    /// Run an installed rizin to recover symbols, functions and sections
    /// from PE, ELF and Mach-O binaries the static parse leaves thin (see
    /// [`rizin`]). On by default; turn it off to keep extraction free of
    /// subprocesses.
    pub fn rizin(mut self, enabled: bool) -> Self {
        self.rizin.enabled = enabled;
        self
    }

    /// Wall-clock budget for one rizin run; a run past it is killed with its
    /// process group and the file keeps its static facts.
    /// [`rizin::DEFAULT_RIZIN_TIMEOUT_SECS`] by default. Latency-sensitive
    /// hosts lower it.
    pub fn rizin_timeout(mut self, timeout: Duration) -> Self {
        self.rizin.timeout = timeout;
        self
    }

    /// Skip rizin for inputs larger than `max_bytes`. A full analysis of a
    /// 100 MB+ stripped binary costs minutes, so a latency-sensitive host
    /// caps it to keep one giant from dominating a scan. No cap by default.
    pub fn rizin_max_bytes(mut self, max_bytes: usize) -> Self {
        self.rizin.max_bytes = Some(max_bytes);
        self
    }

    /// Hand rizin only the host-native slice of a fat Mach-O instead of the
    /// whole universal binary: the other slices never run on this host, and
    /// analysing each is the bulk of the cost. Off by default, so a
    /// filesystem scan covers every slice.
    pub fn rizin_native_arch_only(mut self, enabled: bool) -> Self {
        self.rizin.native_arch_only = enabled;
        self
    }

    /// The rizin part of the disk-cache key for files opened with these
    /// options: whether rizin runs (installed and enabled), its version,
    /// native-arch slicing and the size cap — every rizin setting that
    /// changes a persisted extraction. The timeout is not part of it: a run
    /// that completes is the same under any budget, and one that times out
    /// is never persisted (see [`ParsedFile::rizin_recovery_incomplete`]).
    ///
    /// For a host keying its own cache of results derived from filefacts.
    #[must_use]
    pub fn rizin_fingerprint(&self) -> String {
        rizin::cache_fingerprint(&self.rizin)
    }

    /// Identify `bytes` and return a [`ParsedFile`] that borrows them.
    ///
    /// Identification falls back to [`FileType::Unknown`] rather than
    /// failing, so this cannot fail. No filesystem access happens here; the
    /// first view access runs the extraction, which may use the disk cache
    /// and spawn rizin as these options allow.
    pub fn open<'b>(&self, bytes: &'b [u8]) -> ParsedFile<'b>
    where
        'a: 'b,
    {
        let fileid = match (self.identification, self.path.as_deref()) {
            (Identification::Detect, None) => FileId::from_bytes(bytes),
            (Identification::Detect, Some(path)) => FileId::from_path_and_bytes(path, bytes),
            (Identification::Forced(file_type), _) => FileId::forced(file_type),
            (Identification::Precomputed(fileid), _) => fileid,
        };
        let mut parsed = ParsedFile::new(bytes, fileid, self.path.as_deref().and_then(basename_of));
        parsed.cancellation = self.cancellation;
        parsed.cache = self.cache;
        parsed.cache_namespace.clone_from(&self.cache_namespace);
        parsed.rizin = self.rizin;
        parsed
    }
}

/// Open `bytes` with the default [`OpenOptions`]: identified from content
/// alone (magic bytes, shebang, lightweight pattern matching), with the
/// library's default cache and rizin settings. Use [`OpenOptions`] to supply
/// a path, a known type, a cancellation flag or other settings.
///
/// The returned [`ParsedFile`] borrows the slice for its lifetime. No
/// filesystem access happens here; the first view access may use the disk
/// cache (see the crate-level "Side effects" section).
pub fn open(bytes: &[u8]) -> ParsedFile<'_> {
    OpenOptions::new().open(bytes)
}

/// Read a file from disk, identify it, and return its bytes paired
/// with a [`FileId`].
///
/// The bytes and identification are returned so the caller can open them
/// without re-reading or re-identifying the file:
///
/// ```no_run
/// let path = std::path::Path::new("sample.exe");
/// let (bytes, fileid) = filefacts::from_path(path)?;
/// let parsed = filefacts::OpenOptions::new()
///     .path(path)
///     .fileid(fileid)
///     .open(&bytes);
/// # Ok::<(), filefacts::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be read, is not a regular file, or is
/// larger than [`MAX_INPUT_BYTES`] (see [`read_input`]).
pub fn from_path(path: &Path) -> Result<(Vec<u8>, FileId), Error> {
    let bytes = read_input(path, MAX_INPUT_BYTES)?;
    let fileid = FileId::from_path_and_bytes(path, &bytes);
    Ok((bytes, fileid))
}

/// Default size cap for [`from_path`]: 2 GiB. filefacts holds the whole
/// input in memory, and its views several times over, so a larger file is
/// better refused than analysed into an out-of-memory abort.
pub const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Read the regular file at `path`, refusing anything larger than
/// `max_bytes`.
///
/// Opens without blocking and checks the opened file, so a FIFO, socket or
/// device named on the command line is refused instead of hanging the read or
/// streaming without end, and a file swapped for one after a check is caught.
///
/// # Errors
///
/// [`Error::Io`] naming `path`: the open or read failed; it is not a regular
/// file ([`std::io::ErrorKind::InvalidInput`]); or it holds more than
/// `max_bytes` ([`std::io::ErrorKind::FileTooLarge`]).
pub fn read_input(path: &Path, max_bytes: u64) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let fail = |source| Error::io(path, source);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // A FIFO's `open` blocks until a writer appears; O_NONBLOCK returns at
    // once, and changes nothing for a regular file's reads.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let file = options.open(path).map_err(fail)?;
    let meta = file.metadata().map_err(fail)?;
    if !meta.is_file() {
        return Err(fail(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        )));
    }
    let too_large = || {
        fail(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("larger than the {max_bytes}-byte input cap"),
        ))
    };
    if meta.len() > max_bytes {
        return Err(too_large());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    // `take` guards a file that grows between the `stat` and the read.
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    if bytes.len() as u64 > max_bytes {
        return Err(too_large());
    }
    Ok(bytes)
}

/// Compile a tree-sitter S-expression query against the grammar named
/// `language`. Used by rule engines that want to validate a query
/// string at load time without holding a parsed file. Recognised
/// language names match the values exposed under `values.source.language`
/// (e.g. `"python"`, `"javascript"`, `"perl"`, `"makefile"`), plus a few
/// common aliases such as `"js"`, `"shell"` and `"c#"`.
///
/// # Errors
///
/// [`Error::UnsupportedLanguage`] when no grammar answers to `language`, and
/// [`Error::InvalidQuery`], carrying the [`tree_sitter::QueryError`], when
/// `query` does not compile against it.
pub fn validate_source_query(language: &str, query: &str) -> Result<(), Error> {
    let unsupported = || Error::UnsupportedLanguage(language.to_string());
    let file_type = file_type_for_language(language).ok_or_else(unsupported)?;
    let ts_lang = formats::source::tree_sitter_language(file_type).ok_or_else(unsupported)?;
    tree_sitter::Query::new(&ts_lang, query)
        .map(|_| ())
        .map_err(|source| Error::InvalidQuery {
            language: language.to_string(),
            source,
        })
}

/// Alternative spellings [`validate_source_query`] accepts, each mapped to
/// the `values.source.language` label it stands for.
const SOURCE_LANGUAGE_ALIASES: &[(&str, &str)] = &[
    ("js", "javascript"),
    ("ts", "typescript"),
    ("shell", "bash"),
    ("c#", "csharp"),
    ("ps1", "powershell"),
    ("objective-c", "objc"),
    ("clj", "clojure"),
    ("cljs", "clojure"),
    ("cljc", "clojure"),
    ("make", "makefile"),
];

/// The source file type named `name`: a `values.source.language` label or
/// one of [`SOURCE_LANGUAGE_ALIASES`].
fn file_type_for_language(name: &str) -> Option<FileType> {
    let label = SOURCE_LANGUAGE_ALIASES
        .iter()
        .find_map(|&(alias, label)| (alias == name).then_some(label))
        .unwrap_or(name);
    formats::source::file_type_for_language(label)
}

#[cfg(test)]
mod tests;
