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
//! | [`is_random_token`] | any string | ≥ 16 bytes, all hex or base64, a letter and a digit, near-random entropy |

/// Byte-class counts over a piece of text.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Tally {
    /// Bytes counted.
    len: usize,
    /// Bytes from the base64 alphabet: `A-Z`, `a-z`, `0-9`, `+`, `/`, `=`.
    base64: usize,
    /// `\n` and `\r`, which wrapped base64 interleaves with its alphabet.
    line_breaks: usize,
    upper: bool,
    lower: bool,
    digit: bool,
}

impl Tally {
    fn of(bytes: &[u8]) -> Self {
        let mut tally = Self {
            len: bytes.len(),
            ..Self::default()
        };
        for &b in bytes {
            // The standard base64 alphabet, padding included.
            tally.base64 +=
                usize::from(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
            tally.line_breaks += usize::from(matches!(b, b'\n' | b'\r'));
            tally.upper |= b.is_ascii_uppercase();
            tally.lower |= b.is_ascii_lowercase();
            tally.digit |= b.is_ascii_digit();
        }
        tally
    }
}

/// Shortest comment word read as base64.
const COMMENT_WORD_MIN_LEN: usize = 20;

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
const REGION_SAMPLE_LEN: usize = 4096;
/// Shortest carrier region read as base64.
const REGION_MIN_LEN: usize = 64;

/// A carrier region that reads as base64 rather than prose: its first
/// [`REGION_SAMPLE_LEN`] bytes are at least [`REGION_MIN_LEN`] long and at
/// least 98% base64 alphabet or line breaks, as wrapped base64 is.
pub(crate) fn is_base64_region(region: &[u8]) -> bool {
    let sample = region.get(..REGION_SAMPLE_LEN).unwrap_or(region);
    let tally = Tally::of(sample);
    tally.len >= REGION_MIN_LEN && (tally.base64 + tally.line_breaks) * 100 / tally.len >= 98
}

/// Shortest string literal read as base64.
const LITERAL_BASE64_MIN_LEN: usize = 16;

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
const IDENTIFIER_BASE64_MIN_LEN: usize = 8;

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
const LITERAL_HEX_MIN_LEN: usize = 8;

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
const IDENTIFIER_HEX_MIN_LEN: usize = 6;

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

/// Shortest string read as a random token.
const TOKEN_MIN_LEN: usize = 16;

/// The share of a random string's expected entropy a token must reach.
/// Random hex and base64 of 16 bytes or more reach it 98 times in 100; names,
/// mangled symbols and repeated patterns fall well short of it.
const TOKEN_MIN_ENTROPY_SHARE: f64 = 0.85;

/// A string shaped like a key, a digest or an encoded blob: at least
/// [`TOKEN_MIN_LEN`] bytes, all hex digits or all standard base64, with a
/// letter and a digit, and a Shannon entropy at least
/// [`TOKEN_MIN_ENTROPY_SHARE`] of what a uniformly random string of the same
/// length over the same alphabet is expected to have. Measuring against that
/// expectation, rather than a fixed number of bits, is what lets a 20-byte
/// key and a 40-digit hex digest qualify: neither can reach the 6 bits per
/// byte of long random base64.
pub(crate) fn is_random_token(s: &[u8]) -> bool {
    if s.len() < TOKEN_MIN_LEN {
        return false;
    }
    let tally = Tally::of(s);
    if tally.base64 != tally.len || !tally.digit || !(tally.upper || tally.lower) {
        return false;
    }
    let alphabet = if s.iter().all(u8::is_ascii_hexdigit) {
        16
    } else {
        64
    };
    super::entropy::shannon(s)
        >= TOKEN_MIN_ENTROPY_SHARE * expected_random_entropy(s.len(), alphabet)
}

/// The expected Shannon entropy, in bits per symbol, of `n` symbols drawn
/// uniformly from an alphabet of `k`: `log2 n - (k / n) E[c log2 c]`, where
/// `c ~ Binomial(n, 1/k)` is one symbol's count. A length past 1024 takes
/// 1024's expectation, already within 1% of `log2 k` for these alphabets,
/// which keeps the binomial terms from underflowing.
fn expected_random_entropy(n: usize, k: u32) -> f64 {
    let n = n.min(1024) as f64;
    let p = 1.0 / f64::from(k);
    let mut pmf = (1.0 - p).powf(n);
    let mut sum = 0.0;
    let mut c = 1.0;
    while c <= n {
        pmf *= (n - c + 1.0) / c * p / (1.0 - p);
        sum += pmf * c * c.log2();
        // Past the mean the terms only shrink; stop once they vanish.
        if c > n * p && pmf < 1e-12 {
            break;
        }
        c += 1.0;
    }
    n.log2() - f64::from(k) * sum / n
}

#[cfg(test)]
mod tests;
