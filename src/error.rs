//! Error types for the public API.

use std::error::Error as StdError;
use std::io;

use thiserror::Error;

/// Error returned by filefacts' public API.
///
/// New variants (and new fields on the struct-like variants) are additive and
/// gated by `#[non_exhaustive]`, so match with a wildcard arm and `..`.
/// Existing variants will not be renamed or removed without a major-version
/// bump.
///
/// Where an underlying error caused the failure, it is exposed through
/// [`std::error::Error::source`]. The `Display` text stays self-contained, so
/// printing only the top-level error loses nothing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error while reading the input file, from [`crate::from_path`].
    ///
    /// The `open*` constructors take a byte slice and never return it. View
    /// access may read and write the disk cache ([`crate::cache`]), but
    /// cache I/O is best-effort and its failures are not reported here.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A format extractor encountered structurally invalid data.
    ///
    /// The file's magic bytes claimed format X, but the rest of the file is
    /// not a well-formed instance of that format. `detail` describes what
    /// specifically failed; when a decoder or parser error caused it, that
    /// error is `source`.
    #[error("malformed {format}: {detail}")]
    #[non_exhaustive]
    Malformed {
        /// Short label for the format that failed to parse (e.g. `"pe"`,
        /// `"elf"`, `"zip"`).
        format: &'static str,
        /// What specifically went wrong, suitable for display to the user.
        /// Already includes the text of `source`, if any.
        detail: String,
        /// The underlying parser or decoder error, when there is one.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    },

    /// [`crate::validate_source_query`] was given a language name that has no
    /// tree-sitter grammar. Carries the name as supplied.
    #[error("unsupported language for ast query: {0}")]
    UnsupportedLanguage(String),

    /// [`crate::validate_source_query`] was given a query that does not
    /// compile against the language's grammar.
    #[error("invalid tree-sitter query for {language}: {source}")]
    #[non_exhaustive]
    InvalidQuery {
        /// The language name, as supplied.
        language: String,
        /// The compile error, with the row, column and offset of the fault.
        #[source]
        source: tree_sitter::QueryError,
    },
}

impl Error {
    /// A `Malformed` error with no underlying cause, for structural checks
    /// filefacts makes itself.
    pub(crate) fn malformed(format: &'static str, detail: impl Into<String>) -> Self {
        Self::Malformed {
            format,
            detail: detail.into(),
            source: None,
        }
    }

    /// A `Malformed` error caused by `source`, typically a third-party
    /// parser's error. `detail` is still the whole user-facing text, so it
    /// usually embeds `source`'s message as well.
    pub(crate) fn malformed_with_source(
        format: &'static str,
        detail: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Malformed {
            format,
            detail: detail.into(),
            source: Some(Box::new(source)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_keeps_its_display_and_exposes_the_cause() {
        let plain = Error::malformed("cab", "not a cabinet (bad CFHEADER magic)");
        assert_eq!(
            plain.to_string(),
            "malformed cab: not a cabinet (bad CFHEADER magic)"
        );
        assert!(plain.source().is_none());

        let cause = io::Error::other("unexpected end of file");
        let caused = Error::malformed_with_source("tar", cause.to_string(), cause);
        assert_eq!(caused.to_string(), "malformed tar: unexpected end of file");
        let source = caused.source().expect("source");
        assert_eq!(source.to_string(), "unexpected end of file");
        assert!(source.downcast_ref::<io::Error>().is_some());
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Error>();
    }
}
