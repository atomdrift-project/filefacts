//! VSIX (`extension.vsixmanifest`) extractor.
//!
//! VS Code / Visual Studio extensions ship a `extension.vsixmanifest`
//! XML file inside the VSIX zip. The forensically interesting fields
//! are the `<Identity>` triple (publisher / id / version) — strong
//! supply-chain attribution — and the `<Property>` entries (in
//! particular `Microsoft.VisualStudio.Code.ExecutesCode` and the
//! activation-event list).
//!
//! Schema:
//!
//! - `vsix.identity.{id, publisher, version, language}` — `<Identity>`
//!   attributes.
//! - `vsix.target_platform` — `<Identity TargetPlatform="…">`.
//! - `vsix.display_name`, `vsix.description` — `<DisplayName>` /
//!   `<Description>`.
//! - `vsix.tags[]` — comma-split `<Tags>` content.
//! - `vsix.categories[]` — comma-split `<Categories>` content.
//! - `vsix.properties.<id>` — `<Property Id="…" Value="…" />` pairs,
//!   with the `Microsoft.VisualStudio.` prefix stripped.

use crate::metric;
use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use super::bounded::Limits;
use crate::formats::common::{XorScan, extract_binary_strings, put_str};
use crate::output::{Errors, Metrics, Stage, Strings, Values};
use crate::value_key;

/// Manifests above this are not legitimate — stop reading rather than
/// buffer a zip-bomb member.
const MAX_MANIFEST: u64 = 4 << 20;

/// Parse the `extension.vsixmanifest` member of an opened `.vsix`
/// container so the ZIP-wrapped package surfaces the same
/// `vsix.identity.*` facts as the bare manifest. Silent when absent.
pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    let mut limits = Limits::default();
    let manifest = super::zip::read_manifest_member(
        zip,
        "extension.vsixmanifest",
        MAX_MANIFEST,
        &mut limits,
        "manifest",
        errors,
    );
    limits.emit(values, value_key!("vsix.limits"));
    if let Some(buf) = manifest {
        extract(&buf, values, strings, metrics, errors);
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(e) => {
            errors.record_malformed(
                Stage::FormatExtract,
                format!("extension.vsixmanifest: not UTF-8: {e}"),
            );
            return;
        }
    };
    // Strip a UTF-8 BOM if present — `<PackageManifest>` won't parse
    // when the document starts with one.
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let doc = match roxmltree::Document::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            errors.record_malformed(Stage::FormatExtract, format!("extension.vsixmanifest: {e}"));
            return;
        }
    };

    // <Identity Id="…" Publisher="…" Version="…" />
    if let Some(node) = doc.descendants().find(|n| n.has_tag_name("Identity")) {
        let mut identity = serde_json::Map::new();
        for (attr, key) in [
            ("Id", "id"),
            ("Publisher", "publisher"),
            ("Version", "version"),
            ("Language", "language"),
        ] {
            if let Some(v) = node.attribute(attr) {
                identity.insert(key.into(), JsonValue::String(v.to_string()));
            }
        }
        if let Some(v) = node.attribute("TargetPlatform") {
            put_str(values, value_key!("vsix.target_platform"), v.to_string());
        }
        if !identity.is_empty() {
            values.insert_key(value_key!("vsix.identity"), JsonValue::Object(identity));
        }
    }

    // <DisplayName>…</DisplayName>, <Description>…</Description>
    for (tag, key) in [
        ("DisplayName", value_key!("vsix.display_name")),
        ("Description", value_key!("vsix.description")),
    ] {
        if let Some(node) = doc.descendants().find(|n| n.has_tag_name(tag)) {
            if let Some(text) = node.text() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    put_str(values, key, trimmed.to_string());
                }
            }
        }
    }

    // <Tags>foo,bar,baz</Tags>, <Categories>One,Two</Categories>
    for (tag, key) in [
        ("Tags", value_key!("vsix.tags")),
        ("Categories", value_key!("vsix.categories")),
    ] {
        if let Some(node) = doc.descendants().find(|n| n.has_tag_name(tag)) {
            if let Some(text) = node.text() {
                let items: Vec<JsonValue> = text
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| JsonValue::String(s.to_string()))
                    .collect();
                if !items.is_empty() {
                    values.insert_key(key, JsonValue::Array(items));
                }
            }
        }
    }

    // <Property Id="X" Value="Y" /> — collect into `vsix.properties.{key}`.
    // The `Microsoft.VisualStudio.` prefix is shortened so trait paths
    // read naturally (e.g. `vsix.properties.code.executes_code`).
    let mut properties = serde_json::Map::new();
    let mut property_count = 0_u32;
    for property in doc.descendants().filter(|n| n.has_tag_name("Property")) {
        let Some(id) = property.attribute("Id") else {
            continue;
        };
        let value = property.attribute("Value").unwrap_or("");
        let key = shorten_property_id(id);
        properties.insert(key, JsonValue::String(value.to_string()));
        property_count += 1;
    }
    if !properties.is_empty() {
        values.insert_key(value_key!("vsix.properties"), JsonValue::Object(properties));
    }
    metrics.insert(metric!("vsix.property_count"), f64::from(property_count));

    // <Dependency> elements signal extension activation chaining. Each
    // dependency surfaces as a `{id, version}` pair.
    let deps: Vec<JsonValue> = doc
        .descendants()
        .filter(|n| n.has_tag_name("Dependency"))
        .map(|n| {
            let mut obj = serde_json::Map::new();
            if let Some(id) = n.attribute("Id") {
                obj.insert("id".into(), JsonValue::String(id.to_string()));
            }
            if let Some(v) = n.attribute("Version") {
                obj.insert("version".into(), JsonValue::String(v.to_string()));
            }
            JsonValue::Object(obj)
        })
        .filter(|v| v.as_object().is_some_and(|o| !o.is_empty()))
        .collect();
    if !deps.is_empty() {
        values.insert_key(value_key!("vsix.dependencies"), JsonValue::Array(deps));
    }

    // <Asset Type="…" Path="…" /> — file roster within the VSIX
    // package. The `Type` URI typically follows the
    // `Microsoft.VisualStudio.Code.Manifest` convention.
    let assets: Vec<JsonValue> = doc
        .descendants()
        .filter(|n| n.has_tag_name("Asset"))
        .filter_map(|n| {
            let mut obj = serde_json::Map::new();
            if let Some(t) = n.attribute("Type") {
                obj.insert("type".into(), JsonValue::String(t.to_string()));
            }
            if let Some(p) = n.attribute("Path") {
                obj.insert("path".into(), JsonValue::String(p.to_string()));
            }
            if obj.is_empty() {
                None
            } else {
                Some(JsonValue::Object(obj))
            }
        })
        .collect();
    if !assets.is_empty() {
        metrics.insert(metric!("vsix.asset_count"), assets.len() as f64);
        values.insert_key(value_key!("vsix.assets"), JsonValue::Array(assets));
    }
}

/// Shorten the verbose `Microsoft.VisualStudio.<area>.<name>` property
/// IDs to `<area>.<name>` so trait paths read naturally. Non-Microsoft
/// IDs are preserved verbatim.
fn shorten_property_id(id: &str) -> String {
    id.strip_prefix("Microsoft.VisualStudio.")
        .map_or_else(|| id.to_string(), |rest| rest.to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
