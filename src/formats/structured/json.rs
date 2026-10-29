//! Tolerant JSON-like parsers: gyp's Python-literal syntax and JSON with
//! comments, for documents strict JSON rejects.

use serde_json::{Map, Value as JsonValue};

/// Recursion cap for the gyp parser: deeper than any real build manifest, low
/// enough that a hostile nest cannot overflow the stack or the `Value` drop.
const MAX_GYP_DEPTH: usize = 64;

/// Tolerant parse of the Python-literal subset gyp uses, into a JSON value.
///
/// Returns `None` on anything it cannot parse, so the caller falls back exactly
/// as before — never a partial or guessed tree.
pub(super) fn parse_gyp(content: &[u8]) -> Option<JsonValue> {
    parse_lenient(content, CommentStyle::Python)
}

/// Tolerant parse of JSON with comments (JSONC): `//` and `/* */` comments
/// and trailing commas, on top of strict JSON. Same parser as gyp with the
/// comment syntax swapped; single-quoted strings and hex numbers are accepted
/// as well, which only ever widens what a file can say and never changes the
/// tree of a document strict JSON already accepted (strict runs first).
///
/// Returns `None` on anything it cannot parse, so the caller reports the
/// malformed document exactly as before -- never a partial or guessed tree.
pub(super) fn parse_jsonc(content: &[u8]) -> Option<JsonValue> {
    parse_lenient(content, CommentStyle::Jsonc)
}

fn parse_lenient(content: &[u8], comments: CommentStyle) -> Option<JsonValue> {
    let mut parser = GypParser {
        bytes: content,
        pos: 0,
        comments,
    };
    parser.skip_trivia();
    let value = parser.parse_value(0)?;
    parser.skip_trivia();
    // A gyp manifest is a single top-level dict/list; trailing tokens mean we
    // misparsed, so refuse rather than expose a truncated tree.
    parser.at_end().then_some(value)
}

/// Minimal recursive-descent parser for the Python-literal subset gyp uses:
/// dicts, lists, single/double-quoted strings, numbers, `true`/`false`/`null`,
/// trailing commas, `#` comments, and Python string escapes.
struct GypParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    comments: CommentStyle,
}

/// Which comment syntax the tolerant parser skips as whitespace.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommentStyle {
    /// gyp (Python literal): `#` to end of line.
    Python,
    /// JSON with comments: `//` to end of line and `/* ... */` blocks.
    Jsonc,
}

impl<'a> GypParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// The unconsumed input.
    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.pos..).unwrap_or_default()
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Skip ASCII whitespace and comments in the configured style.
    fn skip_trivia(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else if c == b'#' && self.comments == CommentStyle::Python {
                self.skip_line();
            } else if c == b'/' && self.comments == CommentStyle::Jsonc {
                match self.bytes.get(self.pos + 1) {
                    Some(b'/') => self.skip_line(),
                    Some(b'*') => {
                        self.pos += 2;
                        // An unterminated block comment swallows the rest of
                        // the document; the parse then fails at end of input
                        // exactly as strict JSON would.
                        while self.pos < self.bytes.len() {
                            if self.rest().starts_with(b"*/") {
                                self.pos += 2;
                                break;
                            }
                            self.pos += 1;
                        }
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
    }

    /// Consume through the next newline (line comment body).
    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            self.pos += 1;
            if c == b'\n' {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Option<JsonValue> {
        if depth >= MAX_GYP_DEPTH {
            return None;
        }
        self.skip_trivia();
        match self.peek()? {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'\'' | b'"' => self.parse_string().map(JsonValue::String),
            b't' | b'f' | b'n' => self.parse_ident_literal(),
            b'0'..=b'9' | b'-' | b'+' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: usize) -> Option<JsonValue> {
        self.pos += 1; // consume '{'
        let mut map = Map::new();
        loop {
            self.skip_trivia();
            match self.peek()? {
                b'}' => {
                    self.pos += 1;
                    return Some(JsonValue::Object(map));
                }
                b'\'' | b'"' => {
                    let key = self.parse_string()?;
                    self.skip_trivia();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.pos += 1; // consume ':'
                    let value = self.parse_value(depth + 1)?;
                    map.insert(key, value);
                    self.skip_trivia();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(JsonValue::Object(map));
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Option<JsonValue> {
        self.pos += 1; // consume '['
        let mut arr = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek()? {
                b']' => {
                    self.pos += 1;
                    return Some(JsonValue::Array(arr));
                }
                _ => {
                    arr.push(self.parse_value(depth + 1)?);
                    self.skip_trivia();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(JsonValue::Array(arr));
                        }
                        _ => return None,
                    }
                }
            }
        }
    }

    /// Parse a single- or double-quoted string, decoding Python/JSON escapes.
    fn parse_string(&mut self) -> Option<String> {
        let quote = self.peek()?;
        self.pos += 1; // consume opening quote
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                q if q == quote => return Some(out),
                b'\\' => {
                    let esc = self.peek()?;
                    self.pos += 1;
                    match esc {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'0' => out.push('\0'),
                        b'x' => out.push(self.parse_hex_escape(2)?),
                        b'u' => out.push(self.parse_hex_escape(4)?),
                        b'U' => out.push(self.parse_hex_escape(8)?),
                        // `\\`, `\"`, `\'`, `\/`, and any other escape: the
                        // escaped byte stands for itself (Python leaves unknown
                        // escapes literal; the leading backslash is dropped).
                        other => out.push(other as char),
                    }
                }
                // Multi-byte UTF-8: re-attach the continuation bytes of the
                // lead byte we just consumed so non-ASCII content survives.
                lead if lead >= 0x80 => {
                    let start = self.pos - 1;
                    let end = (start + utf8_width(lead)).min(self.bytes.len());
                    out.push_str(std::str::from_utf8(self.bytes.get(start..end)?).ok()?);
                    self.pos = end;
                }
                _ => out.push(c as char),
            }
        }
    }

    /// Read `digits` hex digits into a `char`. Invalid or out-of-range code
    /// points (lone surrogates, > U+10FFFF) fail the parse.
    fn parse_hex_escape(&mut self, digits: usize) -> Option<char> {
        let mut code: u32 = 0;
        for _ in 0..digits {
            let nibble = (self.peek()? as char).to_digit(16)?;
            code = code.checked_mul(16)?.checked_add(nibble)?;
            self.pos += 1;
        }
        char::from_u32(code)
    }

    fn parse_ident_literal(&mut self) -> Option<JsonValue> {
        for (word, value) in [
            ("true", JsonValue::Bool(true)),
            ("false", JsonValue::Bool(false)),
            ("null", JsonValue::Null),
        ] {
            if self.rest().starts_with(word.as_bytes()) {
                self.pos += word.len();
                return Some(value);
            }
        }
        None
    }

    fn parse_number(&mut self) -> Option<JsonValue> {
        let start = self.pos;
        if matches!(self.peek(), Some(b'-' | b'+')) {
            self.pos += 1;
        }
        // Hex integers (`0x1F`) are valid Python/gyp literals.
        if self.rest().starts_with(b"0x") || self.rest().starts_with(b"0X") {
            self.pos += 2;
            let hex_start = self.pos;
            while matches!(self.peek(), Some(c) if (c as char).is_ascii_hexdigit()) {
                self.pos += 1;
            }
            let hex = std::str::from_utf8(self.bytes.get(hex_start..self.pos)?).ok()?;
            let n = i64::from_str_radix(hex, 16).ok()?;
            let signed = if self.bytes.get(start) == Some(&b'-') {
                -n
            } else {
                n
            };
            return Some(JsonValue::Number(signed.into()));
        }
        while matches!(self.peek(), Some(c) if (c as char).is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(self.bytes.get(start..self.pos)?).ok()?;
        serde_json::from_str::<JsonValue>(text)
            .ok()
            .filter(JsonValue::is_number)
    }
}

/// Byte length of a UTF-8 sequence from its lead byte.
fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}
