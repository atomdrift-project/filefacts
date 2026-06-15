//! Output views every `ParsedFile` exposes.
//!
//! These are the public output schema. Their JSON serialisation is the
//! contract: keys, nesting, and types are governed by filefacts
//! `SCHEMA_VERSION`. Field additions are non-breaking; renames or
//! semantic changes require a schema-version bump.
//!
//! The split mirrors the natural shape of forensic file metadata:
//!
//! - [`Values`] — structural facts the format itself carries (headers,
//!   manifest fields, archive index entries). Navigable as a JSON object
//!   with dot-path lookup.
//! - [`Text`] — byte-scan extracted strings (printable ASCII /
//!   UTF-16LE runs); the Unix `strings(1)` tier.
//! - [`Literals`] — parser-extracted language string literals from
//!   tree-sitter / structured-format parses; the precise tier.
//! - [`Metrics`] — derived numeric features (entropy, sizes, counts,
//!   ratios). Anything that answers "how much / how many / how
//!   spread" rather than "what does it contain".
//! - [`Sections`] — unified section / segment listing for binary
//!   formats, with per-section entropy and flag vocabulary.
//! - [`Symbols`] — unified named-entity facts (imports, exports,
//!   functions, calls, members, binds, identifiers) tagged by
//!   [`SymbolKind`].
//! - [`Errors`] — recoverable extractor diagnostics.

mod archive;
mod errors;
mod identity;
mod metrics;
mod references;
mod sections;
mod strings;
mod symbols;
mod values;

pub use archive::{ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership};
pub use errors::{ErrorKind, Errors, ParseError, Stage};
pub use identity::{Claim, Identity, Party, Signer, Trust, Url, UrlKind};
pub use metrics::Metrics;
pub use references::{ExternalRef, HashAlgo, PinnedHash, RefKind, RefLocator};
pub use sections::{Section, Sections};
pub use strings::{Comments, ExtractedString, Literals, Text};
// Crate-internal bundle of Text + Literals — used by format extractors
// so they can push to either tier without juggling two parameters.
// Not part of the public schema.
pub(crate) use strings::Strings;
pub use symbols::{Arg, ArgShape, Symbol, SymbolKind, Symbols};
pub use values::Values;
