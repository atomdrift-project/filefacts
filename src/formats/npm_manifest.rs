//! Reading a bare `package.json` the way an attacker might have written it.
//!
//! npm itself parses strictly, so a manifest that is not valid JSON is
//! already a finding: hand-edited comments and trailing commas, or a
//! document mangled to defeat scanners. And no legitimate manifest carries
//! anything after its closing brace -- JavaScript appended there (sometimes
//! hidden with Unicode variation selectors or zero-width characters) is a
//! known supply-chain vector. So the manifest is read in three stages and
//! each departure from strict JSON is a fact:
//!
//! 1. strict JSON, noting where the object ends;
//! 2. JSON with comments and trailing commas;
//! 3. a salvage of the identity, scripts and dependency fields from a
//!    document neither parse accepts.
//!
//! Facts: `npm.manifest.parse` (`strict` / `lenient` / `salvaged`),
//! `npm.manifest.parse_error` (the strict parser's error), and for content
//! after the object `npm.manifest.trailing_offset` with the metrics
//! `npm.manifest.trailing_size`, `.trailing_variation_selectors`,
//! `.trailing_zero_width` and `.trailing_code`.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value as JsonValue};

use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// How the manifest was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    Strict,
    Lenient,
    Salvaged,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Lenient => "lenient",
            Self::Salvaged => "salvaged",
        }
    }
}

/// A manifest as read, with where its JSON object ends in the file.
#[derive(Debug)]
pub(super) struct Manifest {
    pub(super) doc: JsonValue,
    pub(super) stage: Stage,
    pub(super) error: Option<String>,
    /// Byte offset just past the JSON object.
    pub(super) end: usize,
}

/// Read `bytes` as a package manifest, strictly first.
pub(super) fn parse(bytes: &[u8]) -> Option<Manifest> {
    // A BOM is not JSON, but npm-published manifests carry one often enough
    // that it is not, alone, a departure worth recording.
    let bom = if bytes.starts_with(b"\xEF\xBB\xBF") {
        3
    } else {
        0
    };
    let content = bytes.get(bom..)?;
    let mut stream = serde_json::Deserializer::from_slice(content).into_iter::<JsonValue>();
    let strict_error = match stream.next() {
        Some(Ok(doc)) if doc.is_object() => {
            return Some(Manifest {
                doc,
                stage: Stage::Strict,
                error: None,
                end: bom + stream.byte_offset(),
            });
        }
        Some(Ok(_)) => "top-level value is not an object".to_string(),
        Some(Err(e)) => e.to_string(),
        None => return None,
    };
    if let Some(doc) = super::structured::parse_jsonc(content).filter(JsonValue::is_object) {
        return Some(Manifest {
            doc,
            stage: Stage::Lenient,
            error: Some(strict_error),
            end: bytes.len(),
        });
    }
    let text = std::str::from_utf8(content).ok()?;
    salvage(text).map(|doc| Manifest {
        doc,
        stage: Stage::Salvaged,
        error: Some(strict_error),
        end: bytes.len(),
    })
}

/// Emit the parse-stage and trailing-content facts for `manifest`.
pub(super) fn emit(manifest: &Manifest, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    values.insert_key(
        value_key!("npm.manifest.parse"),
        JsonValue::String(manifest.stage.label().into()),
    );
    if let Some(error) = &manifest.error {
        let error: String = error.chars().take(200).collect();
        values.insert_key(
            value_key!("npm.manifest.parse_error"),
            JsonValue::String(error),
        );
    }
    let Some(trailing) = bytes
        .get(manifest.end..)
        .map(|rest| String::from_utf8_lossy(rest).trim().to_string())
        .filter(|rest| !rest.is_empty())
    else {
        return;
    };
    values.insert_key(
        value_key!("npm.manifest.trailing_offset"),
        JsonValue::from(manifest.end),
    );
    metrics.insert(metric!("npm.manifest.trailing_size"), trailing.len() as f64);
    let variation_selectors = trailing.chars().any(|c| {
        let cp = u32::from(c);
        (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp)
    });
    let zero_width = trailing
        .chars()
        .any(|c| matches!(u32::from(c), 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF));
    const CODE: [&str; 11] = [
        "eval(",
        "require(",
        "function",
        "const ",
        "var ",
        "let ",
        "import ",
        "=>",
        "Buffer.from",
        "process.",
        "module.exports",
    ];
    let code = CODE.iter().any(|token| trailing.contains(token));
    for (key, present) in [
        (
            metric!("npm.manifest.trailing_variation_selectors"),
            variation_selectors,
        ),
        (metric!("npm.manifest.trailing_zero_width"), zero_width),
        (metric!("npm.manifest.trailing_code"), code),
    ] {
        if present {
            metrics.insert(key, 1.0);
        }
    }
}

/// The identity, scripts and dependency fields of a document no JSON parse
/// accepts, read by pattern: `None` when not even a name, a script or a
/// dependency can be found.
fn salvage(content: &str) -> Option<JsonValue> {
    let mut doc = Map::new();
    for key in ["name", "version"] {
        if let Some(value) = string_field(content, key) {
            doc.insert(key.into(), JsonValue::String(value.into()));
        }
    }
    for key in ["scripts", "dependencies", "devDependencies"] {
        let map = string_map(content, key);
        if !map.is_empty() {
            doc.insert(key.into(), JsonValue::Object(map));
        }
    }
    let useful = ["name", "scripts", "dependencies"]
        .iter()
        .any(|key| doc.contains_key(*key));
    useful.then_some(JsonValue::Object(doc))
}

/// The string value of the first `"key": "..."` in `content`.
fn string_field<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    let marker = Regex::new(&format!(r#""{}"\s*:\s*""#, regex::escape(key))).ok()?;
    let rest = content.get(marker.find(content)?.end()..)?;
    rest.get(..rest.find('"')?)
}

/// The `"name": "value"` pairs of the first `"key": { ... }` object.
fn string_map(content: &str, key: &str) -> Map<String, JsonValue> {
    static PAIR: OnceLock<Option<Regex>> = OnceLock::new();
    let mut map = Map::new();
    let Ok(marker) = Regex::new(&format!(r#""{}"\s*:\s*\{{"#, regex::escape(key))) else {
        return map;
    };
    let Some(open) = marker.find(content) else {
        return map;
    };
    let rest = content.get(open.end()..).unwrap_or_default();
    let mut depth = 1_usize;
    let Some(close) = rest.bytes().position(|b| {
        match b {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        depth == 0
    }) else {
        return map;
    };
    let Some(pair) = PAIR
        .get_or_init(|| Regex::new(r#""([^"]+)"\s*:\s*"([^"]*)""#).ok())
        .as_ref()
    else {
        return map;
    };
    for captures in pair.captures_iter(rest.get(..close).unwrap_or_default()) {
        if let (Some(name), Some(value)) = (captures.get(1), captures.get(2)) {
            map.insert(
                name.as_str().into(),
                JsonValue::String(value.as_str().into()),
            );
        }
    }
    map
}

#[cfg(test)]
mod tests;
