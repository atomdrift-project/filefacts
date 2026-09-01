//! Extractors for structured-document formats.
//!
//! For these formats the file's content *is* the metadata. We parse and
//! hand the resulting tree straight to [`Values`] with no synthetic
//! key-namespace prefix — `fileid` already tells consumers which
//! structured format they're looking at.

use crate::metric;
use serde_json::{Map, Value as JsonValue};

use crate::error::Error;
use crate::output::Metrics;
use crate::output::Values;

/// Generic JSON payloads are common, sometimes huge, and not always worth
/// deserializing. Named JSON formats use `extract_json` directly and are not
/// subject to this limit.
pub(crate) const GENERIC_JSON_PARSE_LIMIT_BYTES: usize = 75 * 1024;

/// Parse the bytes as JSON and populate `values` with the parsed
/// content's top-level keys (when the root is an object) or wrap the
/// non-object root under `value` (when it isn't).
pub(super) fn extract_json(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let parsed: JsonValue =
        serde_json::from_slice(bytes).map_err(|e| Error::malformed("json", e.to_string()))?;
    promote_root(parsed, values);
    Ok(())
}

/// Parse a generic `.json` document if it is below the default parse cap.
/// Oversized files stay analyzable as text/raw content, but we avoid building
/// a potentially huge `serde_json::Value` tree.
pub(super) fn extract_generic_json(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    metrics.insert(
        metric!("json.parse_limit_bytes"),
        GENERIC_JSON_PARSE_LIMIT_BYTES as f64,
    );
    if bytes.len() > GENERIC_JSON_PARSE_LIMIT_BYTES {
        values.insert("json.parse.skipped", JsonValue::Bool(true));
        values.insert(
            "json.parse.reason",
            JsonValue::String("size_limit".to_string()),
        );
        values.insert(
            "json.parse.limit_bytes",
            JsonValue::Number((GENERIC_JSON_PARSE_LIMIT_BYTES as u64).into()),
        );
        values.insert(
            "json.parse.size_bytes",
            JsonValue::Number((bytes.len() as u64).into()),
        );
        return Ok(());
    }

    metrics.insert(metric!("json.parsed_bytes"), bytes.len() as f64);
    extract_json(bytes, values)
}

/// Parse a node-gyp build manifest (`binding.gyp`, `.gyp`, `.gypi`).
///
/// gyp is Python-literal syntax, JSON only in the common case. Real manifests
/// use trailing commas, `#` comments, and single quotes; hostile ones add
/// Python string escapes (`\xNN`, `\uNNNN`, `\U00NNNNNN`) so a byte-escaped
/// keyword like `"\x6e\x6f\x6e\x65"` reads as `"none"` only after decoding.
/// Parse as strict JSON first (fast, exact, unchanged behavior for the common
/// case), then fall back to a tolerant Python-literal parse so value paths like
/// `targets[*].sources[*]` and a concealed target `type` still resolve instead
/// of vanishing into a text/raw scan. `gyp.parse_lenient=1` marks a manifest
/// that needed the fallback — a diffable signal, since a build manifest that is
/// not even valid JSON is itself worth a second look.
pub(super) fn extract_gyp(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    metrics.insert(
        metric!("json.parse_limit_bytes"),
        GENERIC_JSON_PARSE_LIMIT_BYTES as f64,
    );
    if bytes.len() > GENERIC_JSON_PARSE_LIMIT_BYTES {
        values.insert("json.parse.skipped", JsonValue::Bool(true));
        values.insert(
            "json.parse.reason",
            JsonValue::String("size_limit".to_string()),
        );
        values.insert(
            "json.parse.limit_bytes",
            JsonValue::Number((GENERIC_JSON_PARSE_LIMIT_BYTES as u64).into()),
        );
        values.insert(
            "json.parse.size_bytes",
            JsonValue::Number((bytes.len() as u64).into()),
        );
        return Ok(());
    }
    metrics.insert(metric!("json.parsed_bytes"), bytes.len() as f64);
    if let Ok(parsed) = serde_json::from_slice::<JsonValue>(bytes) {
        promote_root(parsed, values);
        return Ok(());
    }
    match parse_gyp(bytes) {
        Some(parsed) => {
            metrics.insert(metric!("gyp.parse_lenient"), 1.0);
            promote_root(parsed, values);
            Ok(())
        }
        None => Err(Error::malformed(
            "gyp",
            "not valid JSON or gyp Python-literal syntax".to_string(),
        )),
    }
}

/// Parse the bytes as YAML (1.2). Multi-document streams use the first
/// document only — multi-document semantics aren't well-defined for the
/// single-tree `Values` view.
pub(super) fn extract_yaml(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let parsed: serde_yaml::Value =
        serde_yaml::from_slice(bytes).map_err(|e| Error::malformed("yaml", e.to_string()))?;
    let json = yaml_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse the bytes as TOML.
pub(super) fn extract_toml(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed("toml", format!("input is not utf-8: {e}")))?;
    let parsed: toml::Value = text
        .parse()
        .map_err(|e: toml::de::Error| Error::malformed("toml", e.to_string()))?;
    let json = toml_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse the bytes as an Apple Property List (XML or binary form).
pub(super) fn extract_plist(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let cursor = std::io::Cursor::new(bytes);
    let parsed: plist::Value =
        plist::Value::from_reader(cursor).map_err(|e| Error::malformed("plist", e.to_string()))?;
    let json = plist_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse PKG-INFO / METADATA format (RFC 822-style headers).
///
/// Multi-value headers (a key repeating across lines) become a JSON
/// array. Continuation lines (starting with whitespace) append to the
/// previous header's value.
pub(super) fn extract_pkginfo(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed("pkginfo", format!("input is not utf-8: {e}")))?;
    let mut root: Map<String, JsonValue> = Map::new();
    let mut last_key: Option<String> = None;

    for line in text.lines() {
        if line.is_empty() {
            // Blank line ends the header block. Body (long description)
            // is captured under `description` for parity with PEP 314.
            break;
        }
        if line.starts_with(|c: char| c.is_whitespace()) {
            // Continuation: append to the value of `last_key`.
            if let Some(k) = &last_key {
                if let Some(existing) = root.get_mut(k) {
                    append_continuation(existing, line.trim_start());
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = JsonValue::String(value.trim().to_string());
        match root.get_mut(&key) {
            None => {
                root.insert(key.clone(), value);
            }
            Some(JsonValue::Array(arr)) => arr.push(value),
            Some(existing) => {
                let prior = std::mem::replace(existing, JsonValue::Null);
                *existing = JsonValue::Array(vec![prior, value]);
            }
        }
        last_key = Some(key);
    }

    *values = Values::from_json(JsonValue::Object(root));
    Ok(())
}

/// When the parsed root is an object, splat its entries into `values`
/// directly. When it isn't (root is an array or scalar — rare for our
/// supported formats), park it under `root` so consumers can still
/// retrieve it.
fn promote_root(json: JsonValue, values: &mut Values) {
    match json {
        JsonValue::Object(map) => {
            *values = Values::from_json(JsonValue::Object(map));
        }
        other => {
            let mut wrapper = Map::new();
            wrapper.insert("root".to_string(), other);
            *values = Values::from_json(JsonValue::Object(wrapper));
        }
    }
}

fn append_continuation(existing: &mut JsonValue, line: &str) {
    if let JsonValue::String(s) = existing {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(line);
    }
}

fn yaml_to_json(value: serde_yaml::Value) -> JsonValue {
    use serde_yaml::Value as Y;
    match value {
        Y::Null => JsonValue::Null,
        Y::Bool(b) => JsonValue::Bool(b),
        Y::Number(n) => {
            // serde_yaml's Number maps cleanly to serde_json's Number.
            n.as_i64()
                .map(|i| JsonValue::Number(i.into()))
                .or_else(|| n.as_u64().map(|u| JsonValue::Number(u.into())))
                .or_else(|| {
                    n.as_f64()
                        .and_then(serde_json::Number::from_f64)
                        .map(JsonValue::Number)
                })
                .unwrap_or(JsonValue::Null)
        }
        Y::String(s) => JsonValue::String(s),
        Y::Sequence(seq) => JsonValue::Array(seq.into_iter().map(yaml_to_json).collect()),
        Y::Mapping(map) => {
            let mut obj = Map::new();
            for (k, v) in map {
                // YAML allows non-string map keys; we stringify for JSON.
                let key = yaml_key_to_string(k);
                obj.insert(key, yaml_to_json(v));
            }
            JsonValue::Object(obj)
        }
        Y::Tagged(t) => yaml_to_json(t.value),
    }
}

fn yaml_key_to_string(v: serde_yaml::Value) -> String {
    use serde_yaml::Value as Y;
    match v {
        Y::String(s) => s,
        Y::Bool(b) => b.to_string(),
        Y::Number(n) => n.to_string(),
        Y::Null => "null".to_string(),
        other => serde_yaml::to_string(&other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn toml_to_json(value: toml::Value) -> JsonValue {
    use toml::Value as T;
    match value {
        T::String(s) => JsonValue::String(s),
        T::Integer(i) => JsonValue::Number(i.into()),
        T::Float(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        T::Boolean(b) => JsonValue::Bool(b),
        T::Datetime(dt) => JsonValue::String(dt.to_string()),
        T::Array(arr) => JsonValue::Array(arr.into_iter().map(toml_to_json).collect()),
        T::Table(tab) => {
            let mut obj = Map::new();
            for (k, v) in tab {
                obj.insert(k, toml_to_json(v));
            }
            JsonValue::Object(obj)
        }
    }
}

fn plist_to_json(value: plist::Value) -> JsonValue {
    use plist::Value as P;
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(format!("{d:?}")),
        P::Data(bytes) => JsonValue::String(base64_encode(&bytes)),
        P::Array(arr) => JsonValue::Array(arr.into_iter().map(plist_to_json).collect()),
        P::Dictionary(dict) => {
            let mut obj = Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v));
            }
            JsonValue::Object(obj)
        }
        // `plist::Value` is `#[non_exhaustive]`. Round-trip unknown
        // variants as null rather than panic.
        _ => JsonValue::Null,
    }
}

/// Minimal base64 encoder for plist `Data` blobs. We don't depend on the
/// `base64` crate for one tiny encoding path.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(n & 0x3F) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = u32::from(bytes[i]) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Recursion cap for the gyp parser: deeper than any real build manifest, low
/// enough that a hostile nest cannot overflow the stack or the `Value` drop.
const MAX_GYP_DEPTH: usize = 64;

/// Tolerant parse of the Python-literal subset gyp uses, into a JSON value.
///
/// Returns `None` on anything it cannot parse, so the caller falls back exactly
/// as before — never a partial or guessed tree.
fn parse_gyp(content: &[u8]) -> Option<JsonValue> {
    let mut parser = GypParser {
        bytes: content,
        pos: 0,
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
}

impl GypParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Skip ASCII whitespace and `#` line comments (gyp's only comment form).
    fn skip_trivia(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else if c == b'#' {
                while let Some(c) = self.peek() {
                    self.pos += 1;
                    if c == b'\n' {
                        break;
                    }
                }
            } else {
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
                    out.push_str(std::str::from_utf8(&self.bytes[start..end]).ok()?);
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
            if self.bytes[self.pos..].starts_with(word.as_bytes()) {
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
        if self.bytes[self.pos..].starts_with(b"0x") || self.bytes[self.pos..].starts_with(b"0X") {
            self.pos += 2;
            let hex_start = self.pos;
            while matches!(self.peek(), Some(c) if (c as char).is_ascii_hexdigit()) {
                self.pos += 1;
            }
            let hex = std::str::from_utf8(&self.bytes[hex_start..self.pos]).ok()?;
            let n = i64::from_str_radix(hex, 16).ok()?;
            let signed = if self.bytes[start] == b'-' { -n } else { n };
            return Some(JsonValue::Number(signed.into()));
        }
        while matches!(self.peek(), Some(c) if (c as char).is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_object_is_promoted() {
        let mut v = Values::new();
        extract_json(br#"{"name":"x","version":"1.0"}"#, &mut v).unwrap();
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
        assert_eq!(v.get("version").and_then(|x| x.as_str()), Some("1.0"));
    }

    #[test]
    fn json_array_root_lands_under_root_key() {
        let mut v = Values::new();
        extract_json(b"[1,2,3]", &mut v).unwrap();
        assert!(v.get("root").and_then(|x| x.as_array()).is_some());
    }

    #[test]
    fn json_malformed_returns_error() {
        let mut v = Values::new();
        let err = extract_json(b"{ not json", &mut v).unwrap_err();
        assert!(matches!(err, Error::Malformed { format: "json", .. }));
    }

    #[test]
    fn toml_basic() {
        let mut v = Values::new();
        extract_toml(b"[package]\nname = \"x\"\n", &mut v).unwrap();
        assert_eq!(v.get("package.name").and_then(|x| x.as_str()), Some("x"));
    }

    #[test]
    fn yaml_basic() {
        let mut v = Values::new();
        extract_yaml(b"name: x\non:\n  push:\n    branches: [main]\n", &mut v).unwrap();
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
    }

    #[test]
    fn pkginfo_simple() {
        let mut v = Values::new();
        let input = b"Metadata-Version: 2.1\nName: foo\nVersion: 1.2.3\n";
        extract_pkginfo(input, &mut v).unwrap();
        assert_eq!(
            v.get("metadata-version").and_then(|x| x.as_str()),
            Some("2.1")
        );
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("foo"));
    }

    #[test]
    fn pkginfo_keys_are_lowercase() {
        let mut v = Values::new();
        let input = b"Summary: Dependency confusion PoC\nAuthor-email: a@example.com\n";
        extract_pkginfo(input, &mut v).unwrap();
        assert_eq!(
            v.get("summary").and_then(|x| x.as_str()),
            Some("Dependency confusion PoC")
        );
        assert_eq!(
            v.get("author-email").and_then(|x| x.as_str()),
            Some("a@example.com")
        );
    }

    #[test]
    fn pkginfo_multi_value_becomes_array() {
        let mut v = Values::new();
        let input = b"Classifier: A\nClassifier: B\nClassifier: C\n";
        extract_pkginfo(input, &mut v).unwrap();
        let arr = v.get("classifier").and_then(|x| x.as_array()).unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn base64_encodes_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn gyp_plain_json_uses_the_strict_path() {
        // A conventional binding.gyp is valid JSON; it must parse without the
        // lenient fallback and land its value paths.
        let gyp = br#"{"targets":[{"target_name":"addon","sources":["addon.c"]}]}"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_gyp(gyp, &mut v, &mut m).unwrap();
        assert_eq!(
            v.get("targets[0].target_name").and_then(|x| x.as_str()),
            Some("addon")
        );
        assert!(m.get("gyp.parse_lenient").is_none());
    }

    #[test]
    fn gyp_lenient_decodes_byte_escaped_target_and_sources() {
        // The openapi-react-query-codegen wave's binding.gyp shape: trailing
        // commas, a `<(var)` target name, and a `\x`-escaped `type` that reads
        // as "none" only after decoding. Strict JSON rejects all of it.
        let gyp = br#"{
            "variables": { "var": "Frot", },
            "targets": [ {
                "target_name": "<(var)",
                "type":"\x6e\x6f\x6e\x65",
                "sources": ["dog.c"],
            } ],
        }"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_gyp(gyp, &mut v, &mut m).unwrap();
        assert_eq!(
            v.get("variables.var").and_then(|x| x.as_str()),
            Some("Frot")
        );
        assert_eq!(
            v.get("targets[0].target_name").and_then(|x| x.as_str()),
            Some("<(var)")
        );
        // The concealment is undone: type is the plaintext keyword.
        assert_eq!(
            v.get("targets[0].type").and_then(|x| x.as_str()),
            Some("none")
        );
        assert_eq!(
            v.get("targets[0].sources[0]").and_then(|x| x.as_str()),
            Some("dog.c")
        );
        assert_eq!(m.get("gyp.parse_lenient"), Some(1.0));
    }

    #[test]
    fn gyp_unicode_escape_recovers_the_command_string() {
        // \U00.. escapes reassemble a command hidden from a plaintext scan.
        let gyp =
            br#"{"targets":[{"conditions":[["\U0000006e\U0000006f\U00000064\U00000065", {}]]}]}"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_gyp(gyp, &mut v, &mut m).unwrap();
        // conditions is an array of `[expr, {}]` pairs — nested arrays, which
        // the dotted `get` path can't index in one segment, so assert on the
        // JSON tree directly.
        assert_eq!(
            v.as_json()
                .pointer("/targets/0/conditions/0/0")
                .and_then(|x| x.as_str()),
            Some("node")
        );
    }

    #[test]
    fn gyp_garbage_fails_cleanly() {
        // Neither JSON nor gyp: no tree, so the caller falls through to a scan.
        let mut v = Values::new();
        let mut m = Metrics::new();
        assert!(extract_gyp(b"\x00\x01 not a manifest", &mut v, &mut m).is_err());
    }
}
