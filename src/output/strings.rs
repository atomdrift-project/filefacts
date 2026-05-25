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

/// One extracted string with its offset and optional metadata.
///
/// `offset` is the byte position of the first character within the
/// source bytes given to `filefacts::open`. For UTF-16 strings, this
/// is the byte offset of the first code unit, not a character index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Text {
    /// Printable ASCII runs.
    pub ascii: Vec<ExtractedString>,
    /// Printable UTF-16LE runs.
    pub utf16le: Vec<ExtractedString>,
}

impl Text {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    /// Total run count across both encodings.
    pub fn len(&self) -> usize {
        self.ascii.len() + self.utf16le.len()
    }
    /// True when no runs were extracted.
    pub fn is_empty(&self) -> bool {
        self.ascii.is_empty() && self.utf16le.is_empty()
    }
    /// Iterate every run regardless of encoding, in (ascii, utf16le)
    /// order. Within each encoding, order is by source byte offset.
    pub fn iter(&self) -> impl Iterator<Item = &ExtractedString> {
        self.ascii.iter().chain(self.utf16le.iter())
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

/// Internal extractor-facing bundle of [`Text`] + [`Literals`].
///
/// Format extractors take `&mut Strings` so they can push to either
/// tier without juggling two parameters. The bundle is *not* part of
/// the public schema — consumers read [`ParsedFile::text`] and
/// [`ParsedFile::literals`] separately.
///
/// [`ParsedFile::text`]: crate::ParsedFile::text
/// [`ParsedFile::literals`]: crate::ParsedFile::literals
#[derive(Debug, Clone, Default)]
pub(crate) struct Strings {
    pub(crate) text: Text,
    pub(crate) literals: Literals,
}

impl Strings {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn len(&self) -> usize {
        self.text.len() + self.literals.len()
    }
    /// Iterate every extracted string across both tiers, in
    /// (text.ascii, text.utf16le, literals) order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &ExtractedString> {
        self.text.iter().chain(self.literals.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_iter_walks_both_encodings() {
        let mut t = Text::new();
        t.ascii.push(ExtractedString {
            text: "Mozilla/5.0".into(),
            offset: 100,
            ..Default::default()
        });
        t.utf16le.push(ExtractedString {
            text: "RegOpenKeyExW".into(),
            offset: 200,
            ..Default::default()
        });
        let texts: Vec<&str> = t.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, vec!["Mozilla/5.0", "RegOpenKeyExW"]);
        assert_eq!(t.len(), 2);
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
