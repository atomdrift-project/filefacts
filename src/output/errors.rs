//! Non-fatal extraction errors surfaced alongside the rest of the output.
//!
//! Expose's contract is *return as much data as we possibly can*: a
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
//! diagnostics about expose's parse.
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

/// One non-fatal extraction error.
///
/// `kind` and `stage` are `&'static str` rather than enums because
/// the closed-set vocabulary is small and the JSON wire-format is the
/// contract; widening either set is a non-breaking schema change.
#[derive(Debug, Clone, Serialize)]
pub struct ParseError {
    /// Short tag categorising the failure. One of `"panic"`,
    /// `"malformed"`, `"truncated"`, `"fallback"`.
    pub kind: &'static str,
    /// Extractor / sub-extractor name where the failure was caught.
    pub stage: &'static str,
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

    /// Convenience for the common case — record a panic.
    pub(crate) fn record_panic(&mut self, stage: &'static str, message: impl Into<String>) {
        self.0.push(ParseError {
            kind: "panic",
            stage,
            message: message.into(),
        });
    }

    /// Convenience for the common case — record a clean malformed-
    /// header failure.
    pub(crate) fn record_malformed(&mut self, stage: &'static str, message: impl Into<String>) {
        self.0.push(ParseError {
            kind: "malformed",
            stage,
            message: message.into(),
        });
    }

    /// Convenience — record a soft fallback (parse succeeded but
    /// took a less-strict path).
    pub(crate) fn record_fallback(&mut self, stage: &'static str, message: impl Into<String>) {
        self.0.push(ParseError {
            kind: "fallback",
            stage,
            message: message.into(),
        });
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
        errs.record_panic("pe-resource-walk", "out of range");
        errs.record_fallback("pe-parse", "permissive mode succeeded");
        assert_eq!(errs.len(), 2);
        let kinds: Vec<&str> = errs.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec!["panic", "fallback"]);
    }

    #[test]
    fn errors_serialize_omits_empty_message() {
        let mut errs = Errors::new();
        errs.record_panic("macho-parse", String::new());
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
        errs.record_malformed("elf-parse", "bad magic");
        let json = serde_json::to_string(&errs).unwrap();
        // `#[serde(transparent)]` means the collection serializes as
        // a bare JSON array, not `{ "0": [...] }`.
        assert!(json.starts_with('['));
        assert!(json.contains("\"kind\":\"malformed\""));
        assert!(json.contains("\"stage\":\"elf-parse\""));
    }
}
