//! Error types for the public API.

use std::io;

use thiserror::Error;

/// Error returned by filefacts' public API.
///
/// Variants are stable; new variants are additive and gated by
/// `#[non_exhaustive]`. Existing variants will not be renamed or removed
/// in 0.x without a minor-version bump.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error while reading bytes (only emitted by helpers that touch the
    /// filesystem; the core `open()` API takes a byte slice and never does
    /// I/O).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// File type could not be identified from the supplied bytes.
    ///
    /// Returned by `open()` when neither magic-byte detection nor content
    /// heuristics produce a result. The bytes themselves may be valid for
    /// some format filefacts does not yet support.
    #[error("unrecognised file format")]
    UnknownFormat,

    /// A format extractor encountered structurally invalid data.
    ///
    /// The file's magic bytes claimed format X, but the rest of the file is
    /// not a well-formed instance of that format. Carries a human-readable
    /// description of what specifically failed.
    #[error("malformed {format}: {detail}")]
    Malformed {
        /// Short label for the format that failed to parse (e.g. `"pe"`,
        /// `"elf"`, `"zip"`).
        format: &'static str,
        /// What specifically went wrong, suitable for display to the user.
        detail: String,
    },
}

impl Error {
    /// Build a `Malformed` error without the `format!` macro at the call
    /// site, for places where the format label is a constant and the detail
    /// is a `String` already.
    pub(crate) fn malformed(format: &'static str, detail: impl Into<String>) -> Self {
        Self::Malformed {
            format,
            detail: detail.into(),
        }
    }
}
