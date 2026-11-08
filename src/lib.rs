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
//! known type or [`FileId`], a cancellation flag, and the cache settings.
//! Every setting belongs to the [`ParsedFile`] it opens, so one process can
//! open files under different settings at once.
//!
//! ```no_run
//! use std::path::Path;
//!
//! let bytes = std::fs::read("sample.exe").unwrap();
//! let parsed = filefacts::OpenOptions::new()
//!     .path(Path::new("sample.exe"))
//!     .open(&bytes);
//! ```
//!
//! ## Side effects
//!
//! Opening a file only identifies it. The first view access runs the
//! extraction, in-process: filefacts starts no subprocess.
//!
//! The disk cache in [`cache`] is off unless the host opts in with
//! [`OpenOptions::cache`]. When on, the first view access reads a matching
//! entry from the cache directory, or writes one after computing the views.
//! A store that finds the cache over its budget, like the host's own call to
//! [`cache::cleanup`] or [`cache::cleanup_in`], starts a detached
//! `filefacts-cache-sweep` thread that deletes expired and least recently
//! used entries, and superseded version directories, inside the cache's own
//! tagged directory. The library reads no environment variables: a host that
//! wants `FILEFACTS_CACHE` to decide passes [`cache::env_override`] itself.
//!
//! Identification and every extraction stage run under
//! [`std::panic::catch_unwind`], so a parser panic on hostile input becomes
//! an [`Errors`] entry (or [`FileType::Unknown`]) rather than an unwind into
//! the host. To keep those expected panics off stderr, the first open
//! installs a process-wide panic hook, once. It chains to the hook
//! installed before it and stays silent only for a panic raised inside a
//! filefacts guard on the panicking thread; every other panic reaches the
//! previous hook unchanged. A host that installs its own hook later replaces
//! it, losing only that silencing. filefacts requires `panic = "unwind"` and
//! fails to build under `panic = "abort"`.
//!
//! filefacts reports what it decided, skipped and recovered from through
//! [`tracing`], under `filefacts::<module>` targets. It never writes to stderr
//! itself; what is shown, and where, is the host's choice of subscriber.
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
mod derived_metrics;
pub(crate) use derived_metrics::is_well_known_section_name;
mod embedded_sources;
mod error;
mod formats;
mod functions;
mod go_dependency_context;
mod go_package_context;
mod identity;
pub mod package_context;
pub use output::{Replaced, Resolution, UnresolvedReason};
mod output;
mod panic_guard;
mod registry;
mod scan;
mod time;

// The string-extraction and parsing engines whose types appear in this
// crate's API (`Text` rows, `SourceAst::tree`, `Error::InvalidQuery`), so a
// consumer names exactly the versions filefacts was built against.
pub use stng;
pub use tree_sitter;

// `metric!` / `value_key!` resolve keys against the catalogs at compile time;
// re-exported here so every module imports them as `crate::metric`.
pub(crate) use output::{metric, value_key};

mod rc4_container;

/// Recovery of code that a format hides from ordinary extraction, for a host
/// that has the bytes in hand (an archive member, a companion runtime, a key
/// it found). Every recovery is static and bounded: nothing it decodes is run.
pub mod recover {
    /// Bounded static recovery of supported PyArmor layouts using a companion
    /// runtime. Recovery never executes Python objects or the native runtime.
    pub mod pyarmor {
        pub use crate::formats::pyarmor::{
            RecoveredPyc, Recovery, is_container, python_containers, recover,
        };
    }

    /// Bounded, integrity-checked recovery of RC4-encrypted code containers.
    pub mod rc4 {
        pub use crate::rc4_container::{Kind, MAX_INPUT, Recovery, recover};
    }

    /// Ren'Py RPA archive members, for hosts that extract them.
    pub mod rpa {
        pub use crate::formats::rpa::{Chunk, Member, members};
    }

    /// Structurally framed JVM classes embedded in a JPHP compiled module.
    pub use crate::formats::jphp::class_frames as jphp_class_frames;
}

pub mod cache;
pub mod fileid;
pub mod values;

pub use functions::{RecoveryStats, recovery_stats};

mod bundle;
pub use bundle::{Bundle, View, ViewData};

pub use formats::source::decode_source_escapes_for_type;

pub use output::{
    Flow, FlowFunction, FlowKind, FlowOrigin, FlowOrigins, FlowTransfer, FlowValue, Limitation,
};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

pub use embedded_sources::{EmbeddedSource, Origin, ScriptScope};
pub use formats::archive_magic::archive_magic;
/// The directory of a Compiled HTML Help (`.chm`) file: every internal
/// file, its content section and extent. Consumers that decompress the
/// LZX section read entries from here rather than re-walking the directory.
pub mod chm {
    pub use crate::formats::chm::{DirEntry, Directory, directory};
}

/// Whether `bytes` carries a whole PE or ELF executable inside it (raw or
/// base64-encoded), by the header validation behind `binary.embedded[]`.
/// For callers deciding whether an otherwise unidentified blob is worth
/// analyzing as a wrapper.
#[must_use]
pub fn has_embedded_executable(bytes: &[u8]) -> bool {
    !formats::embedded::scan(bytes).is_empty()
}
pub use error::Error;
pub use fileid::{ArchiveFormat, Compression, Container, FileId, FileType, Group, container_of};
pub use output::EntryType;
pub use output::{
    ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership, Arg, ArgShape, Claim,
    Comments, DependencyContext, DependencyScope, Diagnostic, DiagnosticKind, Errors, Fact,
    HashAlgo, Identity, Literal, LiteralEncoding, LiteralMethod, Literals, Metrics, Party,
    PartyRole, PinnedHash, RefKind, RefLocator, Reference, Section, SectionFlag, Sections, Signer,
    Span, Stage, Symbol, SymbolKind, Symbols, Text, Trust, Url, UrlKind, Values,
};
// Key types and the templated metric-key constructors: only filefacts emits
// keys, so none of these is public.
pub(crate) use output::{
    MetricKey, QueryLimit, ValueKey, archive_entry_type_count, archive_method_count, ast_op,
    ast_op_density, dmg_codec_count, extension_content_mismatch, source_query_limited,
};
pub use registry::{Ecosystem, Registry};

/// Every metric key this build can emit, as fixed names plus the templates
/// for the few keys with a data-derived segment.
///
/// A rule engine checks every metric a rule names against this list, so a
/// rule naming a metric that no extractor emits fails when the rules load
/// rather than silently never firing.
#[must_use]
pub fn known_metrics() -> (&'static [&'static str], &'static [&'static str]) {
    (output::CATALOG, output::FAMILIES)
}

/// Every [`Values`] key this build can write.
///
/// This is the [`known_metrics`] counterpart for `type: values` rule fields.
/// Unlike a metric, a value can be an object or an array that a rule reaches
/// into, so a validator should accept a rule path when it equals a listed key
/// or extends one with `.` or `[`, as in `pe.signatures[0].subject`,
/// `pdf.info.Author` or `npm.author.email`. That also covers data tails
/// written below a key, such as `pkg.<field>` or `wasm.producers.<field>`. An
/// index in a rule path, whether `[0]` or the `[*]` wildcard, matches the
/// same way.
///
/// One kind of path is outside this list: the parsed document of a
/// structured format (JSON, YAML, TOML, plist, `PKG-INFO` and Xcode project
/// files), which filefacts places at the values root verbatim. A rule that
/// reads such a document's own fields, such as `scripts.postinstall` in a
/// `package.json`, names data rather than a filefacts key, so the validator
/// should not report it as unknown.
#[must_use]
pub fn known_values() -> &'static [&'static str] {
    output::VALUE_CATALOG
}

/// The function-recovery part of the disk-cache key: binform's recovery
/// policy. For a host keying its own cache of results derived from
/// filefacts, so an upgrade that changes recovery invalidates it.
pub const RECOVERY_FINGERPRINT: &str = functions::POLICY;

/// Schema version of the public output shape.
///
/// Bumps on any field rename or semantic change. Field additions are
/// non-breaking and do not bump this version. The on-disk cache has its own
/// format version, and never serves an entry written by another build of
/// filefacts: every cache key includes a hash of filefacts' source.
pub const SCHEMA_VERSION: &str = "11";

/// A file with its bytes and lazily-computed metadata views.
///
/// `ParsedFile` is the central type. Construct one with [`open`] or
/// [`OpenOptions::open`]; [`from_path`] reads and identifies the bytes from
/// disk first.
///
/// Views are computed on first access and cached for the lifetime of
/// the `ParsedFile`. That first access reads and writes the disk cache when
/// the host enabled it; see the crate-level "Side effects" section.
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
    /// The CFML parse, for a CFML file only; `Err` holds the panic it raised.
    cfml_parse: OnceLock<Result<formats::cfml::Parsed, PanicMessage>>,
    // Caller's cancellation flag, polled by long-running leaf work (currently
    // the tree-sitter parse). Borrowed rather than `Arc`-shared, and never
    // written here: filefacts only ever reads it.
    cancellation: Option<&'a AtomicBool>,
    // Where `extracted` reads and writes the disk cache; `None` when it
    // does not.
    cache: Option<CacheSettings>,
    extracted: OnceLock<Extracted>,
    // How many times this `ParsedFile` ran its extraction pipeline.
    // A correctly-implemented `ParsedFile` never reports more than 1
    // regardless of which views the caller reads.
    parse_count: AtomicU32,
}

/// Return the UTF-8 source view used by the source parser.
///
/// Valid UTF-8 is borrowed. Each invalid byte is replaced by one ASCII `_`,
/// preserving all byte offsets and valid sequences. This is syntax recovery,
/// not character-set decoding; callers must not treat masked text as original
/// literal content. Use this view with a cached source AST from the same bytes.
pub fn source_text_for_ast(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    formats::source::utf8_source(bytes).0
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

/// Everything one extraction produces. Round-trips through the disk cache
/// ([`crate::cache`]) so the expensive recovery — chiefly function recovery
/// folded into `symbols`/`sections`/`metrics` — is computed once per
/// `(content, filefacts build, binform policy)` and reused across
/// processes rather than re-run on every `open`.
///
/// The byte-scan `text` rows are cached in extraction order (see
/// [`output::Strings`]), and under filefacts' key like everything else here.
/// That key covers filefacts' own `Cargo.lock` (see `build.rs`), which pins
/// stng to an exact commit, so in a standalone build bumping stng retires
/// every entry. When filefacts is a dependency the consumer's lock chooses
/// stng, and the key does not see it (see [`crate::cache`]).
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
    /// An HTML or SVG page yields each executable inline script as an
    /// [`Origin::Script`] unit, found on first iteration.
    pub fn embedded_sources(&self) -> impl Iterator<Item = EmbeddedSource<'_>> {
        // Each reader sees the value tree only for the format it understands,
        // and only that format pays for the extraction.
        let file_type = self.fileid.file_type();
        let actions = (file_type == FileType::GithubActions).then(|| self.values());
        let rpm = (file_type == FileType::Rpm).then(|| self.values());
        let rpyc = (file_type == FileType::Rpyc).then(|| self.values());
        let page =
            matches!(file_type, FileType::Html | FileType::Svg).then_some((self.bytes, file_type));
        embedded_sources::github_actions(actions)
            .chain(embedded_sources::rpm(rpm))
            .chain(embedded_sources::rpyc(rpyc))
            .chain(
                // The page scan runs on the host's thread, outside the
                // extraction stages, so it gets its own panic guard.
                std::iter::once_with(move || {
                    guarded("embedded_sources", || {
                        embedded_sources::html::inline_scripts(page).collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
                })
                .flatten(),
            )
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
    /// exports, locally-defined functions (with CFG metrics when binform
    /// recovered them), source call sites, dotted member-access chains,
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
        if let Some(Ok(parsed)) = self.cfml_outcome() {
            return Some(&parsed.flow);
        }
        self.flow
            .get_or_init(|| {
                let cache = self.tree_cache()?;
                // A panic leaves flow unavailable rather than taking the
                // caller down; the other views are unaffected.
                guarded("source-flow", || {
                    formats::source::build_value_flow(cache, self.symbols())
                })
                .ok()
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
    /// Filefacts always returns as much data as it can: when a parser
    /// (filefacts' own, or goblin, binform, tree-sitter, …) panics or a
    /// sub-table is truncated, the failure is recorded here and the rest of
    /// the extraction continues.
    /// Empty when nothing went wrong. See [`crate::Diagnostic`] for
    /// the entry shape.
    pub fn errors(&self) -> &Errors {
        &self.extracted().errors
    }

    /// Whether the source parse was cut short by something other than the
    /// bytes: the wall-clock backstop, which depends on how loaded the
    /// machine was, or cancellation.
    ///
    /// The AST facts are then missing for this run only. As with
    /// any cached result, a caller caching analysis output
    /// keyed by content **must not persist a payload while this is `true`**.
    /// Every other reason a source file has no AST — its size, a scanner
    /// guard, a work budget — follows from the bytes and is safe to cache.
    /// Always `false` for views served from filefacts' own disk cache, which
    /// never stores such a result.
    pub fn source_parse_incomplete(&self) -> bool {
        // Extraction is what parses; a cache hit never does.
        let _ = self.extracted();
        self.tree_parse
            .get()
            .and_then(Option::as_ref)
            .and_then(formats::source::TreeParse::diagnostic)
            .is_some_and(formats::source::TreeSitterDiagnostic::is_transient)
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
                let parsed = guarded(Stage::SourceParse.as_str(), || {
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

    fn cfml_outcome(&self) -> Option<&Result<formats::cfml::Parsed, PanicMessage>> {
        if self.fileid.file_type() != FileType::Cfml {
            return None;
        }
        Some(self.cfml_parse.get_or_init(|| {
            guarded(Stage::SourceParse.as_str(), || {
                formats::cfml::parse(self.bytes)
            })
        }))
    }

    fn extracted(&self) -> &Extracted {
        self.extracted.get_or_init(|| {
            let Some(cache) = &self.cache else {
                return self.run_pipeline();
            };
            // The disk cache is keyed by (content, filefacts build, detected
            // type, basename, binform policy). Type belongs in the key because detection
            // may use the logical filename: identical gzip bytes named
            // `package.tgz` and `hash.sample` are npm and generic gzip inputs,
            // respectively, and expose different identity/structure views.
            // Basename also produces facts independent of detected type:
            // `build.rs` and `lib.rs` must not share `file.basename`, nor may
            // Go workspace and module metadata inherit one another's context.
            // An extraction that stopped at a load-dependent point is
            // returned but not persisted (see `cache_outcome`), so a later
            // healthy run still gets to fill the entry.
            let variant = extraction_cache_variant(
                cache.namespace.as_deref(),
                self.fileid.file_type(),
                self.fileid.extension_mismatch(),
                self.fileid.extension_mismatch_transition(),
                self.basename.as_deref(),
            );
            cache::open_with_cache(cache.dir.as_deref(), self.bytes, &variant, || {
                let extracted = self.run_pipeline();
                let parse_transient = self
                    .tree_parse()
                    .and_then(formats::source::TreeParse::diagnostic)
                    .is_some_and(formats::source::TreeSitterDiagnostic::is_transient);
                cache_outcome(extracted, parse_transient)
            })
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

/// Whether a fresh extraction may be persisted: a payload must be a function
/// of its cache key, and two stops depend on load instead. One is the source
/// parse stopping at its wall-clock backstop or on cancellation
/// (`parse_transient`). The other is a source query stopping at its time
/// budget: the query's work budget and its wall-clock backstop both report
/// as `source.query_limited.<query>.timeout`, so neither is cached, or a run
/// on a busy machine would decide the facts of every later open of the same
/// bytes.
fn cache_outcome(extracted: Extracted, parse_transient: bool) -> cache::Computed<Extracted> {
    let query_timed_out = extracted.metrics.iter().any(|(key, _)| {
        key.strip_prefix("source.query_limited.")
            .is_some_and(|query| query.ends_with(".timeout"))
    });
    if parse_transient || query_timed_out {
        cache::Computed::Transient(extracted)
    } else {
        cache::Computed::Cacheable(extracted)
    }
}

/// The message of a panic caught by [`guarded`].
#[derive(Debug)]
struct PanicMessage(String);

/// Run `work`, turning a panic into its message instead of unwinding into the
/// host. Every stage of the pipeline runs under one of these, through
/// [`panic_guard`], so the expected panic is not also printed by the panic
/// hook. A caught panic is a filefacts bug worth seeing, so it is
/// logged with the stage it cost: a [`Stage`] tag, or `source-flow` for the
/// value-flow graph, which is built after the views and so has no entry in
/// [`Errors`].
fn guarded<T>(stage: &'static str, work: impl FnOnce() -> T) -> Result<T, PanicMessage> {
    panic_guard::catch_infallible(work).map_err(|message| {
        tracing::warn!(stage, %message, "caught panic; stage facts lost");
        PanicMessage(message)
    })
}

/// Everything besides the bytes and the build that a cached extraction
/// depends on (see [`ParsedFile::extracted`]); the cache key folds in the
/// rest.
fn extraction_cache_variant(
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
    // entry, or whichever name was scanned first would decide the verdict
    // for every later identical-byte file, missing a masquerade or inventing
    // one purely by scan order.
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
        crate::functions::POLICY,
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
            serde_json::Value::String(formats::common::stem(name).to_owned()),
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
    // Source that is not quite UTF-8 is still parsed (each stray byte as
    // `_`); how much of it there was is a fact of its own.
    if let Some(invalid) = tree_cache
        .map(formats::source::TreeCache::invalid_utf8_bytes)
        .filter(|&n| n > 0)
    {
        metrics.insert(metric!("source.invalid_utf8_bytes"), invalid as f64);
    }
    // Format extractors return `Result` so they can report a hard
    // "this file is not in the format I expect" failure. Any
    // recoverable mid-extraction issues (parser panics, truncated
    // sub-tables, permissive-mode fallbacks) are recorded
    // through the typed `Errors` view instead: a consumer gets everything
    // that was extracted even when some sub-stage failed.
    let stage = stage_for(file_type);
    let extract_result = guarded(stage.as_str(), || {
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
            },
        )
    });
    match extract_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // The format extractor bailed entirely. Surface that as a
            // `malformed` entry so a consumer can see *why* the
            // format-specific view is sparse.
            tracing::debug!(
                stage = stage.as_str(),
                error = %error::display_chain(&e),
                "format extraction failed"
            );
            errors.record_malformed(stage, error::display_chain(&e));
        }
        Err(panic) => {
            if stage == Stage::SourceExtract {
                metrics.insert(metric!("source.extract_panicked"), 1.0);
                metrics.insert(metric!("source.ast_unavailable"), 1.0);
            }
            errors.record_panic(stage, panic.0);
        }
    }
    let dropped = strings.text.dropped();
    if dropped > 0 {
        tracing::debug!(
            stage = "strings",
            kept = strings.text.len(),
            dropped,
            "byte-scan rows past the per-file cap not kept"
        );
        metrics.insert(metric!("strings.text_truncated"), 1.0);
    }
    // Tree-sitter source extraction also pushes Call/Member/Bind/
    // Identifier symbols when a parse is available. Bundling here
    // keeps `parse_count` at 1 regardless of which views the caller
    // reads.
    if let Some(cache) = tree_cache {
        let walk_result = guarded(Stage::SourceAstWalk.as_str(), || {
            formats::source::build_symbols(cache, &mut symbols, &mut metrics);
        });
        if let Err(panic) = walk_result {
            metrics.insert(metric!("source.ast_walk_panicked"), 1.0);
            metrics.insert(metric!("source.ast_unavailable"), 1.0);
            errors.record_panic(Stage::SourceAstWalk, panic.0);
        }
    }
    let sections = Sections::from_iter(sections);
    // The derivations below read the input bytes and every extractor's
    // output, so they get the same panic containment as the extractors: a
    // panic costs that derivation's facts, never the host process.
    let derived_result = guarded(Stage::FormatExtract.as_str(), || {
        // Aggregate metrics derived from sections — mirrors the
        // `sections.*` path convention.
        if !sections.is_empty() {
            derived_metrics::emit_section_metrics(&sections, &mut metrics);
            derived_metrics::emit_binary_aggregates(&sections, &strings, bytes, &mut metrics);
        }
        if image_end.is_some() || !sections.is_empty() {
            let overlay =
                derived_metrics::emit_binary_overlay(&sections, bytes, image_end, &mut metrics);
            // The archive an ELF or Mach-O overlay starts with (a PE's comes
            // from its own extent, which leaves out the Authenticode table).
            if values
                .lookup(value_key!("binary.overlay_archive"))
                .is_none()
                && let Some(kind) = overlay
                    .and_then(|start| bytes.get(crate::bytes::sat_usize(start)..))
                    .and_then(formats::archive_magic::archive_magic)
            {
                values.insert_key(
                    value_key!("binary.overlay_archive"),
                    serde_json::Value::String(kind.into()),
                );
            }
        }

        // Per-kind counts for ergonomic rule filtering. Derived from the
        // unified `symbols` view.
        derived_metrics::emit_symbol_kind_counts(&symbols, &mut metrics);
    });
    if let Err(panic) = derived_result {
        errors.record_panic(Stage::FormatExtract, panic.0);
    }

    // Fold the per-format structural values into the normalized,
    // cross-format identity view. Runs last so it can read everything
    // every extractor wrote (signature fields, manifest claims,
    // document properties). Never fails — absent inputs yield an empty
    // identity.
    let identity = guarded(Stage::FormatExtract.as_str(), || {
        identity::derive(file_type, bytes, &values)
    })
    .unwrap_or_else(|panic| {
        errors.record_panic(Stage::FormatExtract, panic.0);
        Identity::default()
    });

    // External references this file points at (declared packages, install
    // hooks, staged URLs), normalized to PURL/URL. Reads the same `values`
    // the format extractors wrote; never fetches.
    let references = guarded(Stage::FormatExtract.as_str(), || {
        formats::references::derive(file_type, bytes, &values)
    })
    .unwrap_or_else(|panic| {
        errors.record_panic(Stage::FormatExtract, panic.0);
        Vec::new()
    });

    if !errors.is_empty() {
        metrics.insert(metric!("parse.error_count"), errors.len() as f64);
    }

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
        FileType::Zip
        | FileType::GoModule
        | FileType::Composer
        | FileType::Crx
        | FileType::Odf
        | FileType::Jar => Stage::ZipParse,
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
            cache: None,
            extracted: OnceLock::new(),
            parse_count: AtomicU32::new(0),
        }
    }
}

/// Where the disk cache lives and how its keys are namespaced: the
/// [`OpenOptions::cache_dir`] and [`OpenOptions::cache_namespace`] settings.
#[derive(Clone, Debug, Default)]
struct CacheSettings {
    /// The host's cache root; `None` for the per-user default.
    dir: Option<Arc<Path>>,
    /// The host's addition to every disk-cache key.
    namespace: Option<Arc<str>>,
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
/// the same time — the disk cache on for one and off for another — without
/// either seeing the other's.
///
/// [`OpenOptions::new`] gives the library defaults; [`open`] is shorthand
/// for opening with them. Setters consume and return the options, and
/// [`open`](Self::open) borrows them, so one value configured once can open
/// many files (clone it to vary the path per file):
///
/// ```no_run
/// use std::path::Path;
///
/// let options = filefacts::OpenOptions::new().cache(true);
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
    cache_settings: CacheSettings,
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
    /// * the disk cache off, and the per-user cache directory as its root
    ///   once [`cache`](Self::cache) turns it on.
    pub fn new() -> Self {
        Self {
            path: None,
            identification: Identification::Detect,
            cancellation: None,
            cache: false,
            cache_settings: CacheSettings::default(),
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
    pub fn cancellation(mut self, flag: &'a AtomicBool) -> Self {
        self.cancellation = Some(flag);
        self
    }

    /// Read and write the disk cache in [`cache`].
    ///
    /// When on, the first view access reads a matching entry from the cache
    /// directory, or writes one after computing the views; a later open of
    /// the same bytes, under the same settings, skips the extraction. The key
    /// covers the bytes, the filefacts build, the detected type, the
    /// basename and [`RECOVERY_FINGERPRINT`]. Off
    /// by default.
    pub fn cache(mut self, enabled: bool) -> Self {
        self.cache = enabled;
        self
    }

    /// Keep the disk cache under `dir` instead of the per-user cache
    /// directory. Created if missing; it must be an absolute path that no
    /// other user can change, or the cache is skipped for these opens (its
    /// entries are served as results and its sweep deletes by path). Does not
    /// turn the cache on; see [`cache`](Self::cache).
    ///
    /// The cache keeps to a `filefacts` directory it creates and tags inside
    /// `dir`, so `dir` may hold other files; [`cache::cleanup_in`] bounds it.
    pub fn cache_dir(mut self, dir: &Path) -> Self {
        self.cache_settings.dir = Some(Arc::from(dir));
        self
    }

    /// Add `namespace` to every disk-cache key, so entries written under a
    /// different namespace are never read.
    ///
    /// The key already covers filefacts' source and filefacts' own
    /// `Cargo.lock`, but not the lock of a build that depends on filefacts,
    /// which is what chooses stng, binform and the grammars there. Such a
    /// host passes something that changes with what it ships — a hash of
    /// its own lockfile, its version — so updating them retires its entries.
    pub fn cache_namespace(mut self, namespace: &str) -> Self {
        self.cache_settings.namespace = Some(Arc::from(namespace));
        self
    }

    /// Identify `bytes` and return a [`ParsedFile`] that borrows them.
    ///
    /// Identification falls back to [`FileType::Unknown`] rather than
    /// failing, so this cannot fail. No filesystem access happens here; the
    /// first view access runs the extraction, which may use the disk cache
    /// as these options allow.
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
        // Lossy rather than dropped: a name that is not valid UTF-8 is common
        // among samples, and losing it would hide `file.basename` /
        // `file.stem` from exactly those files.
        let basename = self
            .path
            .as_deref()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned());
        let mut parsed = ParsedFile::new(bytes, fileid, basename);
        parsed.cancellation = self.cancellation;
        parsed.cache = self.cache.then(|| self.cache_settings.clone());
        parsed
    }
}

/// Open `bytes` with the default [`OpenOptions`]: identified from content
/// alone (magic bytes, shebang, lightweight pattern matching), with the
/// library's default cache settings. Use [`OpenOptions`] to supply
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
    // once, and changes nothing for a regular file's reads. O_NOCTTY keeps a
    // terminal device named as input from becoming the controlling terminal.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NONBLOCK | libc::O_NOCTTY,
    );
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
    let ts_lang = formats::source::tree_sitter_language_named(canonical_source_language(language))
        .ok_or_else(unsupported)?;
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
    ("c++", "cpp"),
    ("ps1", "powershell"),
    ("objective-c", "objc"),
    ("clj", "clojure"),
    ("cljs", "clojure"),
    ("cljc", "clojure"),
    ("make", "makefile"),
];

/// The source file type named `name`: a `values.source.language` label or
/// one of [`SOURCE_LANGUAGE_ALIASES`].
#[cfg(test)]
fn file_type_for_language(name: &str) -> Option<FileType> {
    formats::source::file_type_for_language(canonical_source_language(name))
}

fn canonical_source_language(name: &str) -> &str {
    SOURCE_LANGUAGE_ALIASES
        .iter()
        .find_map(|&(alias, label)| (alias == name).then_some(label))
        .unwrap_or(name)
}

#[cfg(test)]
mod tests;
