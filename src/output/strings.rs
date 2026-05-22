//! Extracted string literals, grouped by extraction technique.

use serde::Serialize;

/// How a string was recovered from the source bytes.
///
/// Categories reflect the *technique* used to find the string, not its
/// semantic role. A consumer wanting "all imports across all formats"
/// reads `Values` (where the format's structural symbol tables live);
/// `Strings` is the raw byte-level extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StringCategory {
    /// Run of printable 7-bit ASCII bytes terminated by a non-printable
    /// byte. Minimum length is set by the extractor.
    Ascii,
    /// Run of UTF-16 little-endian code units whose decoded bytes are
    /// printable. Common in PE resources and Windows-side payloads.
    Utf16Le,
    /// A language-defined string literal recovered from a structured
    /// parse (tree-sitter for source code, structured-format parser
    /// for JSON/YAML/TOML). Not yet emitted by the v1 extractors.
    Literal,
}

/// One extracted string with its category and offset.
///
/// `offset` is the byte position of the first character within the source
/// bytes given to `expose::open`. For UTF-16 strings, this is the byte
/// offset of the first code unit, not a character index.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    /// How this string was recovered.
    pub category: StringCategory,
    /// Decoded text. UTF-16LE runs are decoded to UTF-8 here; invalid
    /// surrogates are replaced with `U+FFFD`.
    pub text: String,
    /// Byte offset of the first character in the source bytes.
    pub offset: usize,
    /// Recovery method when something more specific than the byte-level
    /// category applies — e.g. `"go-string"` for a fat-pointer Go
    /// string, `"rust-string"` for `&str`/`String`, `"xor"` for an
    /// XOR-deobfuscated run, `"base64"` for a base64-decoded payload.
    /// `None` for plain ASCII / UTF-16 runs that need no annotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Classifier kind when the recovered string fits a recognised
    /// shape (e.g. `"url"`, `"path"`, `"sql"`). Used by trait engines
    /// that want to filter by intent rather than substring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Section the string was recovered from when the format had
    /// addressable sections (PE/ELF/Mach-O); `None` for bare byte
    /// scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Virtual address — set when the extractor knew the loaded
    /// image's layout (rizin's `izj` output). `None` for byte-level
    /// scans that only know the file offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vaddr: Option<u64>,
    /// Physical / file offset reported by the extractor. Distinct
    /// from `offset` (which is always the byte position in the input
    /// slice) only when an extractor labels positions in a layout
    /// the slice itself doesn't expose — e.g. rizin's `paddr` for a
    /// string discovered inside a packed section the byte-level scan
    /// didn't reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paddr: Option<u64>,
    /// Encoding label as rizin / the extractor reports it
    /// (`"ascii"`, `"utf8"`, `"utf16le"`, `"utf32le"`, …). Distinct
    /// from `category`, which is expose's coarse technique
    /// classification. `None` for category-only entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

impl Default for ExtractedString {
    fn default() -> Self {
        Self {
            category: StringCategory::Ascii,
            text: String::new(),
            offset: 0,
            method: None,
            kind: None,
            section: None,
            vaddr: None,
            paddr: None,
            encoding: None,
        }
    }
}

/// Collection of strings extracted from a file.
///
/// Strings are partitioned by category so consumers can pull a single
/// view cheaply. Within a category, order matches the byte order of the
/// source — earlier bytes first.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Strings {
    /// Printable ASCII runs.
    pub ascii: Vec<ExtractedString>,
    /// Printable UTF-16LE runs.
    pub utf16le: Vec<ExtractedString>,
    /// Language-defined string literals from structured parses.
    pub literals: Vec<ExtractedString>,
}

impl Strings {
    /// Empty strings collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total string count across all categories.
    pub fn len(&self) -> usize {
        self.ascii.len() + self.utf16le.len() + self.literals.len()
    }

    /// True when no strings were extracted.
    pub fn is_empty(&self) -> bool {
        self.ascii.is_empty() && self.utf16le.is_empty() && self.literals.is_empty()
    }

    /// Iterate every string regardless of category, in (ascii, utf16le,
    /// literals) order. Within each category, order is by source byte
    /// offset.
    pub fn iter(&self) -> impl Iterator<Item = &ExtractedString> {
        self.ascii
            .iter()
            .chain(self.utf16le.iter())
            .chain(self.literals.iter())
    }
}
