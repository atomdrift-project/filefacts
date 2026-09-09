//! Xcode project (`project.pbxproj`) extractor.
//!
//! A `project.pbxproj` is an OpenStep-style property list describing an Xcode
//! project's targets, build phases, and build settings. It is a supply-chain
//! target because it is the one plist dialect that carries *executable* text:
//! a `PBXShellScriptBuildPhase` and a `PBXBuildRule` each hold a shell script
//! that Xcode runs during an ordinary build, so a repository that merely looks
//! like sample code can execute a command the moment it is opened and built.
//!
//! The format addresses everything indirectly: `objects` is a flat map keyed by
//! random 24-hex ids, so the path to any given script differs per project and
//! no fixed path expression can reach one. This extractor therefore keeps the
//! parsed tree *and* republishes the executable text under stable paths:
//!
//! - `pbxproj.archive_version`, `pbxproj.object_version` — header fields.
//! - `pbxproj.scripts[]` — every `shellScript` and build-rule `script` body,
//!   in `objects` order, regardless of which id holds it.
//! - `pbxproj.build_settings[]` — build-setting values across every
//!   configuration. The `PBXBuildRule` shell indirection (`sh -c "${SETTING}"`)
//!   hides its payload in one of these, not in the script itself.
//! - `pbxproj.isa[]` — the `isa` class of each object, so a rule can ask
//!   whether a project defines a build rule at all.
//! - `objects.*` — the raw parsed tree, still addressable via a wildcard
//!   (`objects[*].shellScript`).

use serde_json::{Map, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{XorScan, extract_binary_strings};
use crate::metric;
use crate::output::{Metrics, Strings, Values};

/// Build settings whose values are ordinary project configuration — long
/// lists of flags and paths that would swamp `pbxproj.build_settings[]`
/// without ever carrying a command. Excluding them keeps the list short
/// enough to read and keys it to the settings an attacker actually abuses.
const NOISY_SETTINGS: &[&str] = &[
    "HEADER_SEARCH_PATHS",
    "LIBRARY_SEARCH_PATHS",
    "FRAMEWORK_SEARCH_PATHS",
    "OTHER_LDFLAGS",
    "OTHER_CFLAGS",
    "OTHER_SWIFT_FLAGS",
    "WARNING_CFLAGS",
    "EXCLUDED_ARCHS",
    "INFOPLIST_FILE",
    "PRODUCT_BUNDLE_IDENTIFIER",
];

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    // The byte scan is what feeds the decoder pipeline. A pbxproj payload is
    // routinely a hex or base64 blob inside a build setting, so the decoded
    // command only reaches the rules if the raw text is scanned as well as
    // parsed.
    extract_binary_strings(bytes, strings, XorScan::No);

    let cursor = std::io::Cursor::new(bytes);
    let parsed = plist::Value::from_reader(cursor)
        .map_err(|e| Error::malformed("pbxproj", e.to_string()))?;
    let json = plist_value_to_json(parsed);

    let JsonValue::Object(root) = json else {
        return Err(Error::malformed("pbxproj", "root is not a dictionary"));
    };

    let mut scripts = Vec::new();
    let mut settings = Vec::new();
    let mut isas = Vec::new();

    if let Some(JsonValue::Object(objects)) = root.get("objects") {
        for object in objects.values() {
            let JsonValue::Object(fields) = object else {
                continue;
            };
            if let Some(JsonValue::String(isa)) = fields.get("isa") {
                isas.push(JsonValue::String(isa.clone()));
            }
            // PBXShellScriptBuildPhase spells it `shellScript`; PBXBuildRule
            // spells it `script`. Both are run by the build.
            for key in ["shellScript", "script"] {
                if let Some(JsonValue::String(body)) = fields.get(key) {
                    scripts.push(JsonValue::String(body.clone()));
                }
            }
            if let Some(JsonValue::Object(build_settings)) = fields.get("buildSettings") {
                for (name, value) in build_settings {
                    if NOISY_SETTINGS.contains(&name.as_str()) {
                        continue;
                    }
                    if let JsonValue::String(v) = value {
                        settings.push(JsonValue::String(v.clone()));
                    }
                }
            }
        }
    }

    metrics.insert(metric!("pbxproj.script_count"), scripts.len() as f64);
    metrics.insert(metric!("pbxproj.object_count"), isas.len() as f64);

    let mut out = Map::new();
    for (key, path) in [
        ("archiveVersion", "archive_version"),
        ("objectVersion", "object_version"),
    ] {
        if let Some(v) = root.get(key) {
            out.insert(path.to_string(), v.clone());
        }
    }
    out.insert("scripts".to_string(), JsonValue::Array(scripts));
    out.insert("build_settings".to_string(), JsonValue::Array(settings));
    out.insert("isa".to_string(), JsonValue::Array(isas));

    let mut top = root;
    top.insert("pbxproj".to_string(), JsonValue::Object(out));
    *values = Values::from_json(JsonValue::Object(top));
    Ok(())
}

/// Convert a parsed plist into JSON.
///
/// Mirrors `structured::plist_to_json`, but a pbxproj is pure OpenStep: it has
/// only strings, arrays, and dictionaries, so the numeric, date, and data arms
/// that dialect never produces are collapsed into their string forms rather
/// than duplicated here.
fn plist_value_to_json(value: plist::Value) -> JsonValue {
    match value {
        plist::Value::String(s) => JsonValue::String(s),
        plist::Value::Boolean(b) => JsonValue::Bool(b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .unwrap_or_else(|| JsonValue::String(i.to_string())),
        plist::Value::Real(f) => serde_json::Number::from_f64(f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        plist::Value::Array(arr) => {
            JsonValue::Array(arr.into_iter().map(plist_value_to_json).collect())
        }
        plist::Value::Dictionary(dict) => JsonValue::Object(
            dict.into_iter()
                .map(|(k, v)| (k, plist_value_to_json(v)))
                .collect(),
        ),
        other => JsonValue::String(format!("{other:?}")),
    }
}
