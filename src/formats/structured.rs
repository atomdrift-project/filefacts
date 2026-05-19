//! Extractors for structured-document formats.
//!
//! For these formats the file's content *is* the metadata. We parse and
//! hand the resulting tree straight to [`Values`] with no synthetic
//! key-namespace prefix — `fileid` already tells consumers which
//! structured format they're looking at.

use serde_json::{Map, Value as JsonValue};

use crate::error::Error;
use crate::output::Values;

/// Parse the bytes as JSON and populate `values` with the parsed
/// content's top-level keys (when the root is an object) or wrap the
/// non-object root under `value` (when it isn't).
pub(super) fn extract_json(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let parsed: JsonValue = serde_json::from_slice(bytes)
        .map_err(|e| Error::malformed("json", e.to_string()))?;
    promote_root(parsed, values);
    Ok(())
}

/// Parse the bytes as YAML (1.2). Multi-document streams use the first
/// document only — multi-document semantics aren't well-defined for the
/// single-tree `Values` view.
pub(super) fn extract_yaml(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let parsed: serde_yaml::Value = serde_yaml::from_slice(bytes)
        .map_err(|e| Error::malformed("yaml", e.to_string()))?;
    let json = yaml_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse the bytes as TOML.
pub(super) fn extract_toml(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed("toml", format!("input is not utf-8: {e}")))?;
    let parsed: toml::Value =
        text.parse().map_err(|e: toml::de::Error| Error::malformed("toml", e.to_string()))?;
    let json = toml_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse the bytes as an Apple Property List (XML or binary form).
pub(super) fn extract_plist(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let cursor = std::io::Cursor::new(bytes);
    let parsed: plist::Value = plist::Value::from_reader(cursor)
        .map_err(|e| Error::malformed("plist", e.to_string()))?;
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
        let key = key.trim().to_string();
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
        other => serde_yaml::to_string(&other).unwrap_or_default().trim().to_string(),
    }
}

fn toml_to_json(value: toml::Value) -> JsonValue {
    use toml::Value as T;
    match value {
        T::String(s) => JsonValue::String(s),
        T::Integer(i) => JsonValue::Number(i.into()),
        T::Float(f) => {
            serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
        }
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
        P::Real(f) => {
            serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
        }
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
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
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
        assert_eq!(
            v.get("package.name").and_then(|x| x.as_str()),
            Some("x")
        );
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
            v.get("Metadata-Version").and_then(|x| x.as_str()),
            Some("2.1")
        );
        assert_eq!(v.get("Name").and_then(|x| x.as_str()), Some("foo"));
    }

    #[test]
    fn pkginfo_multi_value_becomes_array() {
        let mut v = Values::new();
        let input = b"Classifier: A\nClassifier: B\nClassifier: C\n";
        extract_pkginfo(input, &mut v).unwrap();
        let arr = v.get("Classifier").and_then(|x| x.as_array()).unwrap();
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
}
