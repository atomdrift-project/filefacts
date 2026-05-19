//! Output views every `ParsedFile` exposes.
//!
//! These are the public output schema. Their JSON serialisation is the
//! contract: keys, nesting, types are governed by expose's
//! `SCHEMA_VERSION`. Field additions are non-breaking; renames or
//! semantic changes require a schema-version bump.
//!
//! The split mirrors the natural shape of forensic file metadata:
//!
//! - [`Values`] — structural facts the format itself carries (headers,
//!   manifest fields, archive index entries). Navigable as a JSON object
//!   with dot-path lookup.
//! - [`Strings`] — extracted string literals grouped by extraction
//!   technique (printable ASCII run, UTF-16LE run, language-level
//!   string literal).
//! - [`Metrics`] — derived numeric features (entropy, sizes, counts,
//!   ratios). Anything that answers "how much / how many / how
//!   spread" rather than "what does it contain".
//! - [`Sections`] — unified section / segment listing for binary
//!   formats, with per-section entropy and flag vocabulary.
//! - [`Ast`] — call-graph and member-access projection of the
//!   tree-sitter parse for source files.

mod ast;
mod metrics;
mod sections;
mod strings;
mod values;

pub use ast::{ArgShape, Ast, Call};
pub use metrics::Metrics;
pub use sections::{Section, Sections};
pub use strings::{ExtractedString, StringCategory, Strings};
pub use values::Values;
