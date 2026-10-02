//! Recognizers for encoded payloads in text: base64 and hex.
//!
//! Every caller tallies the same byte classes, so the tally lives here once.
//! The thresholds differ on purpose: a long carrier region tolerates line
//! breaks, a comment is judged word by word. Each caller's rule is a named
//! function with its thresholds spelled out, rather than one rule bent to fit.
//!
//! | Rule | Text | Shape |
//! |---|---|---|
//! | [`is_base64_region`] | carrier region | ≥ 64 bytes, ≥ 98% alphabet or line breaks |
//! | [`is_base64_comment_word`] | word in a comment | ≥ 20 bytes, > 90% alphabet, mixed case |
//! | [`is_base64_literal`] | string literal | ≥ 16 bytes, multiple of 4, all alphabet, mixed case |
//! | [`is_base64_identifier`] | identifier | ≥ 8 bytes, > 95% alphabet, mixed case and a digit |
//! | [`is_hex_literal`] | string literal | ≥ 8 bytes, even, all hex after an optional `0x` |
//! | [`is_hex_identifier`] | identifier | ≥ 6 bytes, even, > 90% hex digits |

/// Byte-class counts over a piece of text.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Bytes counted.
    pub(crate) len: usize,
    /// Bytes from the base64 alphabet: `A-Z`, `a-z`, `0-9`, `+`, `/`, `=`.
    pub(crate) base64: usize,
    /// `\n` and `\r`, which wrapped base64 interleaves with its alphabet.
    pub(crate) line_breaks: usize,
    pub(crate) upper: bool,
    pub(crate) lower: bool,
    pub(crate) digit: bool,
}

impl Tally {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        let mut tally = Self {
            len: bytes.len(),
            ..Self::default()
        };
        for &b in bytes {
            tally.base64 += usize::from(is_base64_byte(b));
            tally.line_breaks += usize::from(matches!(b, b'\n' | b'\r'));
            tally.upper |= b.is_ascii_uppercase();
            tally.lower |= b.is_ascii_lowercase();
            tally.digit |= b.is_ascii_digit();
        }
        tally
    }
}

/// Whether `b` is in the standard base64 alphabet, padding included.
pub(crate) fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

/// Shortest comment word read as base64.
pub(crate) const COMMENT_WORD_MIN_LEN: usize = 20;

/// A whitespace-free word inside a comment that reads as base64: at least
/// [`COMMENT_WORD_MIN_LEN`] bytes, more than 90% base64 alphabet, with both
/// upper- and lower-case letters (which hex and prose identifiers rarely mix
/// at that density).
pub(crate) fn is_base64_comment_word(word: &str) -> bool {
    if word.len() < COMMENT_WORD_MIN_LEN {
        return false;
    }
    let tally = Tally::of(word.as_bytes());
    // More than 90%, in integers: base64 / len > 9 / 10.
    tally.base64 * 10 > tally.len * 9 && tally.upper && tally.lower
}

/// Bytes of a carrier region sampled for the base64 test.
pub(crate) const REGION_SAMPLE_LEN: usize = 4096;
/// Shortest carrier region read as base64.
pub(crate) const REGION_MIN_LEN: usize = 64;

/// A carrier region that reads as base64 rather than prose: its first
/// [`REGION_SAMPLE_LEN`] bytes are at least [`REGION_MIN_LEN`] long and at
/// least 98% base64 alphabet or line breaks, as wrapped base64 is.
pub(crate) fn is_base64_region(region: &[u8]) -> bool {
    let sample = region.get(..REGION_SAMPLE_LEN).unwrap_or(region);
    let tally = Tally::of(sample);
    tally.len >= REGION_MIN_LEN && (tally.base64 + tally.line_breaks) * 100 / tally.len >= 98
}

/// Shortest string literal read as base64.
pub(crate) const LITERAL_BASE64_MIN_LEN: usize = 16;

/// A string literal that is a base64 payload: at least
/// [`LITERAL_BASE64_MIN_LEN`] bytes, a whole number of 4-byte groups, every
/// byte in the alphabet, mixed case, and, if it holds any `=`, ending in one.
pub(crate) fn is_base64_literal(s: &str) -> bool {
    if s.len() < LITERAL_BASE64_MIN_LEN || !s.len().is_multiple_of(4) {
        return false;
    }
    let tally = Tally::of(s.as_bytes());
    let valid_padding = !s.contains('=') || s.ends_with('=');
    tally.base64 == tally.len && tally.upper && tally.lower && valid_padding
}

/// Shortest identifier read as base64.
pub(crate) const IDENTIFIER_BASE64_MIN_LEN: usize = 8;

/// An identifier that looks like base64 rather than a name: at least
/// [`IDENTIFIER_BASE64_MIN_LEN`] bytes, more than 95% alphabet, with upper
/// case, lower case and a digit.
pub(crate) fn is_base64_identifier(s: &str) -> bool {
    if s.len() < IDENTIFIER_BASE64_MIN_LEN {
        return false;
    }
    let tally = Tally::of(s.as_bytes());
    // More than 95%, in integers: base64 / len > 19 / 20.
    tally.base64 * 20 > tally.len * 19 && tally.upper && tally.lower && tally.digit
}

/// Shortest string literal read as hex, counting any `0x` prefix.
pub(crate) const LITERAL_HEX_MIN_LEN: usize = 8;

/// A string literal that is hex: at least [`LITERAL_HEX_MIN_LEN`] bytes, an
/// even length (prefix included), and only hex digits after an optional
/// `0x`/`0X`.
pub(crate) fn is_hex_literal(s: &str) -> bool {
    if s.len() < LITERAL_HEX_MIN_LEN || !s.len().is_multiple_of(2) {
        return false;
    }
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    digits.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Shortest identifier read as hex.
pub(crate) const IDENTIFIER_HEX_MIN_LEN: usize = 6;

/// An identifier that looks like hex: at least [`IDENTIFIER_HEX_MIN_LEN`]
/// bytes, an even length, and more than 90% hex digits.
pub(crate) fn is_hex_identifier(s: &str) -> bool {
    if s.len() < IDENTIFIER_HEX_MIN_LEN || !s.len().is_multiple_of(2) {
        return false;
    }
    let hex = s.bytes().filter(u8::is_ascii_hexdigit).count();
    // More than 90%, in integers: hex / len > 9 / 10.
    hex * 10 > s.len() * 9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_identifier_rules() {
        assert!(is_base64_literal("SGVsbG8gV29ybGQh"));
        assert!(!is_base64_literal("SGVsbG8gV29ybGQhX"));
        assert!(!is_base64_literal("sgvsbg8gv29ybgqh"));
        assert!(!is_base64_literal("SGVs=G8gV29ybGQh"));
        assert!(is_base64_literal("SGVsbG8gV29ybA=="));
        assert!(is_base64_identifier("aB3dE5gH"));
        assert!(!is_base64_identifier("aBcdEfgH"));
        assert!(is_hex_literal("deadbeef"));
        assert!(is_hex_literal("0xdeadbeef"));
        assert!(!is_hex_literal("deadbeefa"));
        assert!(is_hex_identifier("deadbe"));
        assert!(!is_hex_identifier("deadbz"));
    }

    #[test]
    fn tally_counts_each_class() {
        let tally = Tally::of(b"aB3+/=\r\n-");
        assert_eq!(
            tally,
            Tally {
                len: 9,
                base64: 6,
                line_breaks: 2,
                upper: true,
                lower: true,
                digit: true,
            }
        );
    }

    #[test]
    fn comment_words_need_length_density_and_mixed_case() {
        assert!(is_base64_comment_word("aGVsbG8gd29ybGQgdGhpcyBpcw=="));
        assert!(!is_base64_comment_word("aGVsbG8gd29ybGQ"));
        assert!(!is_base64_comment_word("abcdefghijklmnopqrstuvwxyz"));
        assert!(!is_base64_comment_word("deadbeefdeadbeefdeadbeef"));
        // 18 of 20 alphabet bytes is exactly 90%, which is not more than 90%.
        assert!(!is_base64_comment_word("aBcDeFgHiJkLmNoPqR--"));
        assert!(is_base64_comment_word("aBcDeFgHiJkLmNoPqRsT-"));
    }

    #[test]
    fn regions_tolerate_line_breaks_but_not_prose() {
        let wrapped = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n".repeat(4);
        assert!(is_base64_region(wrapped.as_bytes()));
        let prose = "The quick brown fox jumps over the lazy dog. ".repeat(4);
        assert!(!is_base64_region(prose.as_bytes()));
        assert!(!is_base64_region(b"QUJD"));
    }
}
