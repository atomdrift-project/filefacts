//! Extracted strings, split by extraction technique.
//!
//! Two peer collections at the top level:
//!
//! - [`Text`] — byte-scan output (printable ASCII / UTF-16LE runs).
//!   Mirrors what Unix `strings(1)` would produce, partitioned by
//!   encoding so consumers can pull one slice cheaply.
//! - [`Literals`] — parser-extracted language string literals
//!   (tree-sitter for source code, structured-format parser for
//!   JSON / YAML / TOML / etc.). The precise tier — no comment /
//!   code false positives.
//!
//! The two tiers have two row types, because they record different things:
//!
//! - [`Text`] rows are [`stng::ExtractedString`] (re-exported as
//!   `filefacts::stng`): the scanner's own record, with its typed
//!   [`stng::StringMethod`] and [`stng::StringKind`], and its exact source
//!   extent (`data_offset`, `data_len`, stack-string fragments).
//! - [`Literals`] and [`Comments`] rows are [`Literal`]: a parser-recovered
//!   value, its file offset, and how it was recovered when a parser did more
//!   than read a quoted string.
//!
//! Both carry `u64` file offsets. The *container* identifies the tier.

use serde::{Deserialize, Serialize};

use super::Span;

/// How a [`Literal`] was recovered, when more than reading a quoted string
/// out of a parse tree was involved.
///
/// Serialized as the kebab-case label (`"scpt-literal"`, `"nib-string"`,
/// `"scpt-base64"`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum LiteralMethod {
    /// A string literal read from compiled AppleScript.
    ScptLiteral,
    /// A constant recovered from compiled AppleScript bytecode.
    ScptConstant,
    /// A base64 payload decoded out of an AppleScript literal.
    ScptBase64,
    /// An obfuscated base64 payload decoded out of an AppleScript literal.
    ScptBase64Obf,
    /// A hex payload decoded out of an AppleScript literal.
    ScptHex,
    /// A URL-encoded payload decoded out of an AppleScript literal.
    ScptUrl,
    /// A `\uXXXX`-escaped payload decoded out of an AppleScript literal.
    ScptUnicodeEscape,
    /// A base32 payload decoded out of an AppleScript literal.
    ScptBase32,
    /// A base85 payload decoded out of an AppleScript literal.
    ScptBase85,
    /// A ROT13-then-base64 payload decoded out of an AppleScript literal.
    ScptRot13Base64,
    /// A string from a compiled Interface Builder (`.nib`) archive.
    NibString,
}

impl LiteralMethod {
    /// The serialized label, e.g. `"scpt-literal"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScptLiteral => "scpt-literal",
            Self::ScptConstant => "scpt-constant",
            Self::ScptBase64 => "scpt-base64",
            Self::ScptBase64Obf => "scpt-base64-obf",
            Self::ScptHex => "scpt-hex",
            Self::ScptUrl => "scpt-url",
            Self::ScptUnicodeEscape => "scpt-unicode-escape",
            Self::ScptBase32 => "scpt-base32",
            Self::ScptBase85 => "scpt-base85",
            Self::ScptRot13Base64 => "scpt-rot13-base64",
            Self::NibString => "nib-string",
        }
    }
}

/// The encoding a [`Literal`]'s source bytes were stored in, when it is not
/// the file's own text encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum LiteralEncoding {
    /// UTF-8.
    Utf8,
    /// UTF-16, big-endian.
    Utf16be,
}

/// One parser-recovered string: a [`Literals`] or [`Comments`] row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Literal {
    /// The value, decoded to UTF-8.
    pub text: String,
    /// Byte offset in the analysed file where the value's source starts.
    /// `0` for a comment body, whose position is not tracked.
    pub offset: u64,
    /// How the value was recovered; `None` for a literal read straight out
    /// of a parse tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<LiteralMethod>,
    /// How the value's source bytes were encoded; `None` when they are in
    /// the file's own text encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<LiteralEncoding>,
}

impl Literal {
    /// A literal recovered at `offset` with no further annotation.
    #[must_use]
    pub fn new(text: impl Into<String>, offset: u64) -> Self {
        Self {
            text: text.into(),
            offset,
            method: None,
            encoding: None,
        }
    }

    /// Annotate how the value was recovered.
    #[must_use]
    pub fn with_method(mut self, method: LiteralMethod) -> Self {
        self.method = Some(method);
        self
    }

    /// Annotate how the value's source bytes were encoded.
    #[must_use]
    pub fn with_encoding(mut self, encoding: LiteralEncoding) -> Self {
        self.encoding = Some(encoding);
        self
    }
}

/// Producer-side row for the tree-sitter extractors, which locate nodes by
/// `usize` byte offset. Converted to a [`Literal`] on push; new producers
/// build a [`Literal`] directly.
#[derive(Debug, Default)]
pub(crate) struct ExtractedString {
    pub(crate) text: String,
    pub(crate) offset: usize,
    /// Never set by the source extractors; present so their
    /// `..Default::default()` row literals stay meaningful.
    pub(crate) method: Option<LiteralMethod>,
}

impl From<ExtractedString> for Literal {
    fn from(row: ExtractedString) -> Self {
        Self {
            text: row.text,
            offset: row.offset as u64,
            method: row.method,
            encoding: None,
        }
    }
}

/// Byte-scan extracted strings — the Unix `strings(1)` tier.
///
/// Partitioned by encoding so consumers can pull a single slice
/// cheaply. Within a partition, order matches the byte order of the
/// source — earlier bytes first.
///
/// Rows are the raw `stng::ExtractedString` (the single string-extraction
/// engine), retained typed so the sole consumer (cleave) reads stng's
/// `StringKind`/`StringMethod` enums directly rather than re-parsing labels.
/// Round-trips through the disk cache, so `stng::ExtractedString` carries
/// `Deserialize` alongside `Serialize`.
#[derive(Debug, Clone, Default)]
pub struct Text {
    /// All byte-scan rows, held as the shared `Arc` stng handed back so
    /// downstream consumers (cleave) borrow this allocation instead of
    /// cloning. ASCII and UTF-16LE are not separate buffers — the encoding
    /// split is a view ([`Text::ascii`] / [`Text::utf16le`]) over `rows`,
    /// which preserves the serialized `{ascii, utf16le}` shape.
    rows: std::sync::Arc<[stng::ExtractedString]>,
}

impl Text {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    /// Wrap the shared rows stng produced (no copy).
    pub(crate) fn from_rows(rows: std::sync::Arc<[stng::ExtractedString]>) -> Self {
        Self { rows }
    }
    /// Append rows extracted from somewhere other than the file's own bytes.
    ///
    /// Costs an allocation, because `rows` is a shared `Arc` slice that
    /// consumers borrow rather than copy. That is the right trade only where
    /// the extra rows cannot be had any other way -- text recovered from a
    /// decoded blob, whose plaintext does not exist anywhere in the file --
    /// so every other path keeps using [`Text::from_rows`] and stays copy-free.
    pub(crate) fn append_rows(&mut self, extra: &[stng::ExtractedString]) {
        if extra.is_empty() {
            return;
        }
        let mut rows: Vec<stng::ExtractedString> = self.rows.iter().cloned().collect();
        rows.extend_from_slice(extra);
        self.rows = rows.into();
    }
    /// The shared row slice — lets consumers hold an `Arc` clone (a refcount
    /// bump) rather than cloning the string data.
    pub fn rows(&self) -> &std::sync::Arc<[stng::ExtractedString]> {
        &self.rows
    }
    /// Total run count across both encodings.
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    /// True when no runs were extracted.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    /// Iterate every run in (ascii, utf16le) order. Derived from the encoding
    /// views rather than the raw `rows` so the order is identical whether the
    /// rows came fresh from stng (offset-sorted, interleaved) or from the disk
    /// cache (deserialized ascii-then-utf16) — i.e. the cache stays transparent.
    pub fn iter(&self) -> impl Iterator<Item = &stng::ExtractedString> {
        self.ascii().chain(self.utf16le())
    }
    /// True for the UTF-16 extraction methods.
    fn is_utf16(method: stng::StringMethod) -> bool {
        matches!(
            method,
            stng::StringMethod::WideString
                | stng::StringMethod::Utf16LeDecode
                | stng::StringMethod::Utf16BeDecode
        )
    }
    /// Printable ASCII runs (view over `rows`).
    pub fn ascii(&self) -> impl Iterator<Item = &stng::ExtractedString> {
        self.rows.iter().filter(|s| !Self::is_utf16(s.method))
    }
    /// Printable UTF-16LE runs (view over `rows`).
    pub fn utf16le(&self) -> impl Iterator<Item = &stng::ExtractedString> {
        self.rows.iter().filter(|s| Self::is_utf16(s.method))
    }
}

// Serialize keeping the historical `{ascii, utf16le}` schema (a view over the
// shared rows); deserialize concatenates the two arrays back into one `Arc`,
// ascii first, matching `from_rows` order.
impl Serialize for Text {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let ascii: Vec<&stng::ExtractedString> = self.ascii().collect();
        let utf16le: Vec<&stng::ExtractedString> = self.utf16le().collect();
        let mut st = serializer.serialize_struct("Text", 2)?;
        st.serialize_field("ascii", &ascii)?;
        st.serialize_field("utf16le", &utf16le)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            ascii: Vec<stng::ExtractedString>,
            #[serde(default)]
            utf16le: Vec<stng::ExtractedString>,
        }
        let mut raw = Raw::deserialize(deserializer)?;
        raw.ascii.extend(raw.utf16le);
        Ok(Self {
            rows: raw.ascii.into(),
        })
    }
}

/// Parser-extracted string literals — the precise tier.
///
/// Populated by tree-sitter (for source code) and structured-format
/// parsers (JSON/YAML/TOML/etc.). Distinct from [`Text`] because
/// these are language-defined literals, not byte-level printable
/// runs — no comment or code false positives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Literals(Vec<Literal>);

impl Literals {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, lit: impl Into<Literal>) {
        self.0.push(lit.into());
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[Literal] {
        &self.0
    }
    /// Iterate every recorded literal.
    pub fn iter(&self) -> std::slice::Iter<'_, Literal> {
        self.0.iter()
    }
    /// Number of literals recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when no literals were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Literals {
    type Item = &'a Literal;
    type IntoIter = std::slice::Iter<'a, Literal>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Source-code comment bodies — the comment-scoped tier.
///
/// Populated for source files from the language's comment style (the
/// same extraction that drives `comments.*` metrics). Distinct from
/// [`Text`] (which is a byte-level scan that mixes comments, code, and
/// strings) and [`Literals`] (string literals only): matching here can
/// never fire on a keyword that appears in code or a string, only in a
/// genuine comment — the lowest-false-positive home for "this keyword
/// is mentioned in a comment" rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Comments(Vec<Literal>);

impl Comments {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, c: impl Into<Literal>) {
        self.0.push(c.into());
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[Literal] {
        &self.0
    }
    /// Iterate every recorded comment.
    pub fn iter(&self) -> std::slice::Iter<'_, Literal> {
        self.0.iter()
    }
    /// Number of comments recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when no comments were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Comments {
    type Item = &'a Literal;
    type IntoIter = std::slice::Iter<'a, Literal>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Internal extractor-facing bundle of [`Text`] + [`Literals`] +
/// [`Comments`].
///
/// Format extractors take `&mut Strings` so they can push to any
/// tier without juggling parameters. The bundle is *not* part of
/// the public schema — consumers read [`ParsedFile::text`],
/// [`ParsedFile::literals`], and [`ParsedFile::comments`] separately.
///
/// [`ParsedFile::text`]: crate::ParsedFile::text
/// [`ParsedFile::literals`]: crate::ParsedFile::literals
/// [`ParsedFile::comments`]: crate::ParsedFile::comments
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Strings {
    pub(crate) text: Text,
    pub(crate) literals: Literals,
    pub(crate) comments: Comments,
}

impl Strings {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn len(&self) -> usize {
        self.text.len() + self.literals.len()
    }
    /// Each string paired with the source [`Span`] it was recovered from, in
    /// (text.ascii, text.utf16le, literals) order.
    ///
    /// The span's *offset* is correct for locating the string in the file: a
    /// `StackString` is synthesised from scattered instructions, so its bytes
    /// are not contiguous at `data_offset` — anchor at the first source
    /// fragment instead of claiming a bogus run.
    ///
    /// The span's *length* is the decoded value's byte length: exact for byte
    /// strings, an under-count for UTF-16LE / base64 (their encoded source is
    /// longer). That matches how the string-length metrics are defined and the
    /// rendered preview is capped regardless, so the approximation is bounded.
    pub(crate) fn text_spans(&self) -> impl Iterator<Item = (Span, &str)> {
        // stng records each string's exact source extent (encoded length,
        // fragments for stack strings); `source_spans` returns it correctly for
        // every encoding. Anchor at the first span — the largest interest for a
        // single-anchor metric — falling back to the raw offset only for the
        // degenerate empty-fragments case.
        let text = self.text.iter().map(|s| {
            let (off, len) = s
                .source_spans()
                .next()
                .unwrap_or((s.data_offset, s.value.len() as u64));
            (Span::new(off, len), s.value.as_str())
        });
        // The literals tier is already decoded and its source length isn't
        // tracked, so use the value length.
        let literals = self
            .literals
            .iter()
            .map(|s| (Span::new(s.offset, s.text.len() as u64), s.text.as_str()));
        text.chain(literals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_spans_locate_each_string_kind_correctly() {
        let text_rows: std::sync::Arc<[stng::ExtractedString]> = vec![
            // StackString: source is scattered across instructions, so the span
            // anchors at the first fragment — NOT the (non-contiguous) data_offset.
            stng::ExtractedString {
                value: "STACKSTR".into(),
                data_offset: 9999,
                method: stng::StringMethod::StackString,
                fragments: Some(Box::new(vec![
                    stng::StringFragment {
                        offset: 0x100,
                        length: 4,
                    },
                    stng::StringFragment {
                        offset: 0x200,
                        length: 4,
                    },
                ])),
                ..Default::default()
            },
            // Plain byte-scan literal: span at its file offset.
            stng::ExtractedString {
                value: "plain".into(),
                data_offset: 0x10,
                method: stng::StringMethod::RawScan,
                ..Default::default()
            },
        ]
        .into();
        let literals = Literals(vec![
            Literal::new("decoded", 0x500).with_method(LiteralMethod::ScptBase64),
            Literal::new("lit", 0x40),
        ]);
        let strings = Strings {
            text: Text::from_rows(text_rows),
            literals,
            comments: Comments::new(),
        };
        let spans: Vec<(Span, &str)> = strings.text_spans().collect();
        assert_eq!(
            spans,
            vec![
                (Span::new(0x100, 4), "STACKSTR"), // first fragment, not (9999, 8)
                (Span::new(0x10, 5), "plain"),
                (Span::new(0x500, 7), "decoded"),
                (Span::new(0x40, 3), "lit"),
            ]
        );
    }

    #[test]
    fn text_iter_walks_both_encodings() {
        let rows: std::sync::Arc<[stng::ExtractedString]> = vec![
            stng::ExtractedString {
                value: "Mozilla/5.0".into(),
                data_offset: 100,
                method: stng::StringMethod::RawScan,
                ..Default::default()
            },
            stng::ExtractedString {
                value: "RegOpenKeyExW".into(),
                data_offset: 200,
                method: stng::StringMethod::WideString,
                ..Default::default()
            },
        ]
        .into();
        let t = Text::from_rows(rows);
        let texts: Vec<&str> = t.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(texts, vec!["Mozilla/5.0", "RegOpenKeyExW"]);
        assert_eq!(t.len(), 2);
        assert_eq!(t.ascii().count(), 1);
        assert_eq!(t.utf16le().count(), 1);
    }

    #[test]
    fn literals_is_flat_serde_array() {
        let mut lits = Literals::new();
        lits.push(Literal::new("https://example/", 1024));
        lits.push(
            Literal::new("Hello", 7)
                .with_method(LiteralMethod::ScptLiteral)
                .with_encoding(LiteralEncoding::Utf16be),
        );
        let json = serde_json::to_string(&lits).unwrap();
        assert!(json.starts_with('['), "literals serialises as bare array");
        assert!(
            json.contains(r#""method":"scpt-literal","encoding":"utf16be""#),
            "{json}"
        );
        let back: Literals = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_slice(), lits.as_slice());
    }

    /// The serialized label and `as_str` agree for every method.
    #[test]
    fn literal_method_labels_match_serde() {
        for method in [
            LiteralMethod::ScptLiteral,
            LiteralMethod::ScptConstant,
            LiteralMethod::ScptBase64,
            LiteralMethod::ScptBase64Obf,
            LiteralMethod::ScptHex,
            LiteralMethod::ScptUrl,
            LiteralMethod::ScptUnicodeEscape,
            LiteralMethod::ScptBase32,
            LiteralMethod::ScptBase85,
            LiteralMethod::ScptRot13Base64,
            LiteralMethod::NibString,
        ] {
            assert_eq!(
                serde_json::to_value(method).unwrap(),
                serde_json::Value::from(method.as_str())
            );
        }
    }

    /// A source-extractor row keeps its text and offset through the push.
    #[test]
    fn producer_rows_convert_on_push() {
        let mut lits = Literals::new();
        lits.push(ExtractedString {
            text: "x".into(),
            offset: 9,
            ..ExtractedString::default()
        });
        assert_eq!(lits.as_slice(), &[Literal::new("x", 9)]);
    }
}
