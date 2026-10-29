//! Property lists (XML, binary or ASCII), converted into the JSON tree
//! `values` holds.

use serde_json::{Map, Value as JsonValue};

use crate::error::Error;

/// Nesting cap for plists; see [`plist_guard`](super::super::plist_guard).
#[cfg(test)]
pub(super) const PLIST_MAX_DEPTH: usize = super::super::plist_guard::MAX_DEPTH;

/// Parse a plist (XML, binary or ASCII) into the JSON tree `values` holds,
/// through [`plist_guard::parse`](super::super::plist_guard::parse), which refuses
/// reference expansion and nesting the conversion below could not survive.
pub(super) fn parse_plist(bytes: &[u8]) -> Result<JsonValue, Error> {
    let parsed = super::super::plist_guard::parse(bytes).map_err(|e| e.into_error("plist"))?;
    Ok(plist_to_json(parsed))
}

/// Convert a plist tree already checked by `plist_guard::parse`.
fn plist_to_json(value: ::plist::Value) -> JsonValue {
    use ::plist::Value as P;
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(d.to_xml_format()),
        P::Data(bytes) => JsonValue::String(base64_encode(&bytes)),
        // A keyed-archive object reference, which only the binary form can
        // encode. Spelled the way `plutil -convert xml1` spells it so a rule
        // written against either form of the same archive matches both.
        P::Uid(uid) => {
            let mut obj = Map::new();
            obj.insert("CF$UID".to_string(), JsonValue::Number(uid.get().into()));
            JsonValue::Object(obj)
        }
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
pub(super) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .zip([16, 8, 0])
            .fold(0u32, |n, (&b, shift)| n | (u32::from(b) << shift));
        // A chunk of k bytes fills k + 1 sextets; the rest are padding.
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(match ALPHABET.get(((n >> shift) & 0x3F) as usize) {
                Some(&c) if k <= chunk.len() => char::from(c),
                _ => '=',
            });
        }
    }
    out
}
