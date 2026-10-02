//! Error types for the public API.

use std::error::Error as StdError;
use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Error returned by filefacts' public API.
///
/// New variants (and new fields on the struct-like variants) are additive and
/// gated by `#[non_exhaustive]`, so match with a wildcard arm and `..`.
/// Existing variants will not be renamed or removed without a major-version
/// bump.
///
/// Where an underlying error caused the failure, it is exposed through
/// [`std::error::Error::source`] and *not* repeated in this error's
/// `Display`, following the standard library's convention: a reporter that
/// walks the chain (`anyhow`, `eyre`, [`std::error::Report`]) prints each
/// cause once. Print the whole chain to see the cause.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error while reading the input file, from [`crate::from_path`] or
    /// [`crate::read_input`].
    ///
    /// The `open*` constructors take a byte slice and never return it. View
    /// access may read and write the disk cache ([`crate::cache`]), but
    /// cache I/O is best-effort and its failures are not reported here.
    #[error("{}", io_context(.path.as_ref()))]
    #[non_exhaustive]
    Io {
        /// The file being read, when the failure is tied to one.
        path: Option<PathBuf>,
        /// The operating system's error. Its kind is
        /// [`io::ErrorKind::InvalidInput`] for an input that is not a
        /// regular file and [`io::ErrorKind::FileTooLarge`] for one over the
        /// size cap.
        #[source]
        source: io::Error,
    },

    /// A format extractor encountered structurally invalid data.
    ///
    /// The file's magic bytes claimed format X, but the rest of the file is
    /// not a well-formed instance of that format. `detail` describes what
    /// specifically failed; when a decoder or parser error caused it, that
    /// error is `source`.
    #[error("malformed {format}{}", detail_suffix(.detail))]
    #[non_exhaustive]
    Malformed {
        /// Short label for the format that failed to parse (e.g. `"pe"`,
        /// `"elf"`, `"zip"`).
        format: &'static str,
        /// What specifically went wrong, suitable for display to the user.
        /// Context only: the text of `source`, if any, is not repeated here.
        /// Empty when `source` says it all.
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
    #[error("invalid tree-sitter query for {language}")]
    #[non_exhaustive]
    InvalidQuery {
        /// The language name, as supplied.
        language: String,
        /// The compile error, with the row, column and offset of the fault.
        #[source]
        source: tree_sitter::QueryError,
    },
}

/// `Display` text for [`Error::Io`].
fn io_context(path: Option<&PathBuf>) -> String {
    match path {
        Some(path) => format!("cannot read {}", path.display()),
        None => "i/o error".to_string(),
    }
}

/// `": {detail}"`, or nothing for an empty detail.
fn detail_suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

/// An I/O error not tied to one path. Prefer [`Error::Io`] with the path
/// whenever there is one.
impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::Io { path: None, source }
    }
}

impl Error {
    /// An [`Error::Io`] for `path`.
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: Some(path.into()),
            source,
        }
    }

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
    /// parser's error, with `context` saying where it struck. `context` must
    /// not repeat `source`'s message: `source` is reported after it.
    pub(crate) fn malformed_with_source(
        format: &'static str,
        context: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Malformed {
            format,
            detail: context.into(),
            source: Some(Box::new(source)),
        }
    }

    /// A `Malformed` error whose cause, `source`, needs no added context.
    pub(crate) fn malformed_caused_by(
        format: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::malformed_with_source(format, String::new(), source)
    }
}

/// `err` and each of its causes, joined with `": "` — the one-line form for
/// output that has no room for a chain, like the errors view.
pub(crate) fn display_chain(err: &(dyn StdError + 'static)) -> String {
    let mut text = err.to_string();
    let mut cause = err.source();
    while let Some(err) = cause {
        text.push_str(": ");
        text.push_str(&err.to_string());
        cause = err.source();
    }
    text
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
        let caused = Error::malformed_caused_by("tar", cause);
        assert_eq!(caused.to_string(), "malformed tar");
        let source = caused.source().expect("source");
        assert_eq!(source.to_string(), "unexpected end of file");
        assert!(source.downcast_ref::<io::Error>().is_some());
        assert_eq!(
            display_chain(&caused),
            "malformed tar: unexpected end of file"
        );

        let in_context =
            Error::malformed_with_source("zip", "entry 3", io::Error::other("bad crc"));
        assert_eq!(in_context.to_string(), "malformed zip: entry 3");
        assert_eq!(
            display_chain(&in_context),
            "malformed zip: entry 3: bad crc"
        );
    }

    #[test]
    fn a_chain_reporter_prints_each_cause_once() {
        let errors = [
            Error::malformed_caused_by("tar", io::Error::other("unexpected end of file")),
            Error::io("/tmp/x", io::Error::other("permission denied")),
        ];
        for err in &errors {
            let chain = display_chain(err);
            let cause = err.source().expect("source").to_string();
            assert_eq!(chain.matches(&cause).count(), 1, "{chain}");
        }
    }

    #[test]
    fn io_names_the_path_and_keeps_the_kind() {
        let err = Error::io(
            "/samples/a.bin",
            io::Error::new(io::ErrorKind::NotFound, "gone"),
        );
        assert_eq!(err.to_string(), "cannot read /samples/a.bin");
        let Error::Io { path, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(
            path.as_deref(),
            Some(std::path::Path::new("/samples/a.bin"))
        );
        assert_eq!(source.kind(), io::ErrorKind::NotFound);
        let bare: Error = io::Error::other("disk on fire").into();
        assert_eq!(bare.to_string(), "i/o error");
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Error>();
    }
}
