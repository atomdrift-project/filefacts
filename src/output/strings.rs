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
//! Both collections carry the same row shape ([`ExtractedString`]);
//! the *container* identifies which tier produced the row.

use serde::{Deserialize, Serialize};

use super::Span;

/// One extracted string with its offset and optional metadata.
///
/// `offset` is the byte position of the first character within the
/// source bytes given to `filefacts::open`. For UTF-16 strings, this
/// is the byte offset of the first code unit, not a character index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExtractedString {
    /// Decoded text. UTF-16LE runs are decoded to UTF-8 here; invalid
    /// surrogates are replaced with `U+FFFD`.
    pub text: String,
    /// Byte offset of the first character in the source bytes.
    pub offset: usize,
    /// Recovery method when something more specific than the byte-level
    /// tier applies — e.g. `"go-string"` for a fat-pointer Go string,
    /// `"rust-string"` for `&str`/`String`, `"xor"` for an
    /// XOR-deobfuscated run, `"base64"` for a base64-decoded payload.
    /// `None` for plain ASCII / UTF-16 runs that need no annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Classifier kind when the recovered string fits a recognised
    /// shape (e.g. `"url"`, `"path"`, `"sql"`). Used by trait engines
    /// that want to filter by intent rather than substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Section the string was recovered from when the format had
    /// addressable sections (PE/ELF/Mach-O); `None` for bare byte
    /// scans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Virtual address — set when the extractor knew the loaded
    /// image's layout (rizin's `izj` output). `None` for byte-level
    /// scans that only know the file offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vaddr: Option<u64>,
    /// Physical / file offset reported by the extractor. Distinct
    /// from `offset` only when an extractor labels positions in a
    /// layout the slice itself doesn't expose — e.g. rizin's `paddr`
    /// for a string discovered inside a packed section the byte-level
    /// scan didn't reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paddr: Option<u64>,
    /// Encoding label as the extractor reports it (`"ascii"`, `"utf8"`,
    /// `"utf16le"`, `"utf32le"`, …). `None` when the container's
    /// tier already implies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
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
pub struct Literals(Vec<ExtractedString>);

impl Literals {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, lit: ExtractedString) {
        self.0.push(lit);
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[ExtractedString] {
        &self.0
    }
    /// Iterate every recorded literal.
    pub fn iter(&self) -> std::slice::Iter<'_, ExtractedString> {
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
    type Item = &'a ExtractedString;
    type IntoIter = std::slice::Iter<'a, ExtractedString>;
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
pub struct Comments(Vec<ExtractedString>);

impl Comments {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, c: ExtractedString) {
        self.0.push(c);
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[ExtractedString] {
        &self.0
    }
    /// Iterate every recorded comment.
    pub fn iter(&self) -> std::slice::Iter<'_, ExtractedString> {
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
    type Item = &'a ExtractedString;
    type IntoIter = std::slice::Iter<'a, ExtractedString>;
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
    /// stng's cache key for the `text` rows, recorded so the disk cache can drop
    /// the row bytes and rehydrate them from stng's cache (the single owner)
    /// instead of persisting a second copy. `None` when no text tier ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) text_key: Option<String>,
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
    /// The span's *offset* is correct for locating the string in the file:
    /// - a `StackString` is synthesised from scattered instructions, so its
    ///   bytes are not contiguous at `data_offset` — anchor at the first source
    ///   fragment instead of claiming a bogus run;
    /// - a literal recovered by rizin inside a packed section reports its file
    ///   offset in `paddr`, not the (slice-relative) `offset` — prefer `paddr`.
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
        // The literals tier is filefacts-native (rizin-recovered, already
        // decoded); its source length isn't tracked, so use the value length and
        // the physical file offset (`paddr`) when the slice-relative `offset`
        // doesn't address the file.
        let literals = self.literals.iter().map(|s| {
            let offset = s.paddr.unwrap_or(s.offset as u64);
            (Span::new(offset, s.text.len() as u64), s.text.as_str())
        });
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
            // rizin-recovered inside a packed section: prefer the physical
            // file offset (paddr) over the slice-relative offset.
            ExtractedString {
                text: "packed".into(),
                offset: 7,
                paddr: Some(0x500),
                ..Default::default()
            },
            // ordinary literal with no paddr: use offset.
            ExtractedString {
                text: "lit".into(),
                offset: 0x40,
                ..Default::default()
            },
        ]);
        let strings = Strings {
            text: Text::from_rows(text_rows),
            literals,
            comments: Comments::new(),
            text_key: None,
        };
        let spans: Vec<(Span, &str)> = strings.text_spans().collect();
        assert_eq!(
            spans,
            vec![
                (Span::new(0x100, 4), "STACKSTR"), // first fragment, not (9999, 8)
                (Span::new(0x10, 5), "plain"),
                (Span::new(0x500, 6), "packed"), // paddr, not offset 7
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
        lits.push(ExtractedString {
            text: "https://example/".into(),
            offset: 1024,
            ..Default::default()
        });
        let json = serde_json::to_string(&lits).unwrap();
        assert!(json.starts_with('['), "literals serialises as bare array");
        let back: Literals = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.iter().next().unwrap().text, "https://example/");
    }
}
