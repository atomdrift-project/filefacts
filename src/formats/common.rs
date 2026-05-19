//! Helpers shared across format extractors.

use serde_json::Value as JsonValue;

use crate::output::{Strings, Values};
use crate::scan::ascii;
use crate::scan::utf16;

/// Push every ASCII run in `bytes` into `strings.ascii`, applying the
/// scanner's default minimum length.
pub(super) fn extract_ascii_strings(bytes: &[u8], strings: &mut Strings) {
    strings
        .ascii
        .extend(ascii::extract_runs(bytes, ascii::DEFAULT_MIN_LEN));
}

/// Push every UTF-16LE run in `bytes` into `strings.utf16le`.
pub(super) fn extract_utf16_strings(bytes: &[u8], strings: &mut Strings) {
    strings
        .utf16le
        .extend(utf16::extract_runs(bytes, utf16::DEFAULT_MIN_LEN));
}

/// Convenience wrapper for emitting a string-typed value into `values`.
pub(super) fn put_str(values: &mut Values, path: &str, s: impl Into<String>) {
    values.insert(path, JsonValue::String(s.into()));
}

/// Convenience wrapper for emitting an integer-typed value.
pub(super) fn put_u64(values: &mut Values, path: &str, n: u64) {
    values.insert(path, JsonValue::Number(n.into()));
}

/// Convenience wrapper for emitting a signed-integer value (for fields
/// that are conventionally signed, e.g. Unix timestamps).
pub(super) fn put_i64(values: &mut Values, path: &str, n: i64) {
    values.insert(path, JsonValue::Number(n.into()));
}

// Bool emissions intentionally absent: a "true/false" kv pair where
// `false` simply means "no data" duplicates what trait authors can
// express with `exists:`. Emit a presence marker (or a richer
// numeric/string value) instead — never a bare boolean that mirrors
// presence/absence.

/// Lowercase hex encoding of arbitrary bytes. Used wherever a hash
/// digest or serial number needs a stable, comparable representation.
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hex_encode;

    #[test]
    fn hex_encode_known_vectors() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }
}
