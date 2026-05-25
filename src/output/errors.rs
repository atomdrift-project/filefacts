//! Non-fatal extraction errors surfaced alongside the rest of the output.
//!
//! Filefacts' contract is *return as much data as we possibly can*: a
//! truncated PE that goblin chokes on still gets its byte-level
//! metrics emitted; a malformed Mach-O fat header still gets a
//! Magic-byte–derived [`crate::FileId`]. When a sub-extractor fails
//! or panics, the surrounding extractor *records the failure here*
//! and keeps going, rather than propagating the error and dropping
//! every fact it had already collected.
//!
//! Two distinct things land in this view:
//!
//! 1. **Hard failures** — `kind: "panic"` / `"malformed"` /
//!    `"truncated"`. The data the failing stage would have produced
//!    is missing.
//! 2. **Soft fallbacks** — `kind: "fallback"`. The data IS present
//!    but came from a less-strict parse path (PE permissive mode,
//!    header-only retry). Consumers can decide whether the looser
//!    interpretation meets their threshold.
//!
//! Strange-but-recoverable conditions that do *not* prevent
//! extraction (`section.entropy > 7.9`, `pe.section_count > 50`,
//! `tls_callback_count > 4`) belong in [`crate::Metrics`] instead —
//! they are quantitative facts the file genuinely has, not
//! diagnostics about filefacts' parse.
//!
//! Schema:
//!
//! - `kind` — closed set of short tags (`"panic"`, `"malformed"`,
//!   `"truncated"`, `"fallback"`).
//! - `stage` — extractor / sub-extractor name (`"pe-parse"`,
//!   `"pe-resource-walk"`, `"elf-parse"`, `"macho-parse"`,
//!   `"ooxml-zip-walk"`, …). Used by the analyst to localise the
//!   failure without re-reading the call stack.
//! - `message` — verbatim diagnostic from the failing stage, when
//!   one is available.

use serde::Serialize;

/// Closed set of failure categories. The JSON wire form serialises
/// as the lowercase variant name (`"panic"`, `"malformed"`,
/// `"truncated"`, `"fallback"`) so downstream rules and dashboards
/// keep working unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ErrorKind {
    /// A sub-extractor panicked; surrounding code caught the unwind.
    Panic,
    /// The bytes claimed a format but failed strict validation.
    Malformed,
    /// The input was cut short of what the format requires.
    Truncated,
    /// The strict parse failed but a less-strict path succeeded; the
    /// data is present but came from a fallback interpretation.
    Fallback,
}

/// Extractor / sub-extractor that recorded the failure. Serialises
/// as kebab-case (`"pe-parse"`, `"pe-resource-walk"`, `"elf-parse"`,
/// …) — same vocabulary the previous `&'static str` field used,
/// preserved verbatim so existing rules keep matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Stage {
    /// Top-level PE/COFF header parse.
    PeParse,
    /// PE resource directory walk.
    PeResourceWalk,
    /// Top-level ELF header parse.
    ElfParse,
    /// Top-level Mach-O header parse.
    MachoParse,
    /// OOXML package open / parts walk.
    OoxmlParse,
    /// OLE2 / Compound File Binary open.
    Ole2Parse,
    /// ZIP central-directory walk.
    ZipParse,
    /// TAR header walk.
    TarParse,
    /// Java `.class` parse.
    ClassParse,
    /// PDF object scan.
    PdfParse,
    /// RPM header parse.
    RpmParse,
    /// Generic / catch-all extraction stage.
    FormatExtract,
}

/// One non-fatal extraction error.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ParseError {
    /// Category of the failure.
    pub kind: ErrorKind,
    /// Extractor / sub-extractor where the failure was caught.
    pub stage: Stage,
    /// Verbatim diagnostic message, when available. Empty string
    /// when the failing stage produced no message (raw panic with a
    /// non-string payload, header-only fallback signal, …).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub message: String,
}

/// Non-fatal extraction errors collected across the parse, in the
/// order they were encountered. Empty when the parse hit no
/// failures or fallbacks.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Errors(Vec<ParseError>);

impl Errors {
    /// Construct an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an extractor failure at the given stage. Replaces the
    /// older `record_panic` / `record_malformed` / `record_fallback`
    /// trio with a single entry point.
    pub(crate) fn record(&mut self, kind: ErrorKind, stage: Stage, message: impl Into<String>) {
        self.0.push(ParseError {
            kind,
            stage,
            message: message.into(),
        });
    }

    /// Convenience for the common case — record a panic.
    pub(crate) fn record_panic(&mut self, stage: Stage, message: impl Into<String>) {
        self.record(ErrorKind::Panic, stage, message);
    }

    /// Convenience for the common case — record a clean malformed-
    /// header failure.
    pub(crate) fn record_malformed(&mut self, stage: Stage, message: impl Into<String>) {
        self.record(ErrorKind::Malformed, stage, message);
    }

    /// Convenience — record a soft fallback (parse succeeded but
    /// took a less-strict path).
    pub(crate) fn record_fallback(&mut self, stage: Stage, message: impl Into<String>) {
        self.record(ErrorKind::Fallback, stage, message);
    }

    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[ParseError] {
        &self.0
    }
    /// Iterate every recorded error.
    pub fn iter(&self) -> std::slice::Iter<'_, ParseError> {
        self.0.iter()
    }
    /// Number of errors recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when no errors were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Errors {
    type Item = &'a ParseError;
    type IntoIter = std::slice::Iter<'a, ParseError>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_push_and_iterate() {
        let mut errs = Errors::new();
        errs.record_panic(Stage::PeResourceWalk, "out of range");
        errs.record_fallback(Stage::PeParse, "permissive mode succeeded");
        assert_eq!(errs.len(), 2);
        let kinds: Vec<ErrorKind> = errs.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![ErrorKind::Panic, ErrorKind::Fallback]);
    }

    #[test]
    fn errors_serialize_omits_empty_message() {
        let mut errs = Errors::new();
        errs.record_panic(Stage::MachoParse, String::new());
        let json = serde_json::to_value(&errs).unwrap();
        let arr = json.as_array().unwrap();
        let obj = arr[0].as_object().unwrap();
        assert!(!obj.contains_key("message"));
        assert_eq!(obj.get("kind").and_then(|v| v.as_str()), Some("panic"));
        assert_eq!(
            obj.get("stage").and_then(|v| v.as_str()),
            Some("macho-parse")
        );
    }

    #[test]
    fn errors_serialize_as_bare_array() {
        let mut errs = Errors::new();
        errs.record_malformed(Stage::ElfParse, "bad magic");
        let json = serde_json::to_string(&errs).unwrap();
        // `#[serde(transparent)]` means the collection serializes as
        // a bare JSON array, not `{ "0": [...] }`.
        assert!(json.starts_with('['));
        assert!(json.contains("\"kind\":\"malformed\""));
        assert!(json.contains("\"stage\":\"elf-parse\""));
    }
}
