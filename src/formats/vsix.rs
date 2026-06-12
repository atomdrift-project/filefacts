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

use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str};
use crate::output::{Metrics, Strings, Values};

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
) -> Result<(), Error> {
    let Ok(member) = zip.by_name("extension.vsixmanifest") else {
        return Ok(());
    };
    let mut buf = Vec::new();
    if member.take(MAX_MANIFEST).read_to_end(&mut buf).is_err() {
        return Ok(());
    }
    extract(&buf, values, strings, metrics)
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(());
    };
    // Strip a UTF-8 BOM if present — `<PackageManifest>` won't parse
    // when the document starts with one.
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let Ok(doc) = roxmltree::Document::parse(text) else {
        return Ok(());
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
            put_str(values, "vsix.target_platform", v.to_string());
        }
        if !identity.is_empty() {
            values.insert("vsix.identity", JsonValue::Object(identity));
        }
    }

    // <DisplayName>…</DisplayName>, <Description>…</Description>
    for (tag, key) in [
        ("DisplayName", "vsix.display_name"),
        ("Description", "vsix.description"),
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
    for (tag, key) in [("Tags", "vsix.tags"), ("Categories", "vsix.categories")] {
        if let Some(node) = doc.descendants().find(|n| n.has_tag_name(tag)) {
            if let Some(text) = node.text() {
                let items: Vec<JsonValue> = text
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| JsonValue::String(s.to_string()))
                    .collect();
                if !items.is_empty() {
                    values.insert(key, JsonValue::Array(items));
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
        values.insert("vsix.properties", JsonValue::Object(properties));
    }
    metrics.insert("vsix.property_count", f64::from(property_count));

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
        values.insert("vsix.dependencies", JsonValue::Array(deps));
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
        metrics.insert("vsix.asset_count", assets.len() as f64);
        values.insert("vsix.assets", JsonValue::Array(assets));
    }

    Ok(())
}

/// Shorten the verbose `Microsoft.VisualStudio.<area>.<name>` property
/// IDs to `<area>.<name>` so trait paths read naturally. Non-Microsoft
/// IDs are preserved verbatim.
fn shorten_property_id(id: &str) -> String {
    id.strip_prefix("Microsoft.VisualStudio.")
        .map_or_else(|| id.to_string(), |rest| rest.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(text, &mut v, &mut s, &mut m).unwrap();
        (v, m)
    }

    #[test]
    fn parses_identity() {
        let manifest = br#"<?xml version="1.0" encoding="utf-8"?>
<PackageManifest>
  <Metadata>
    <Identity Id="hello-world" Publisher="acme" Version="1.2.3" Language="en-US" />
    <DisplayName>Hello World</DisplayName>
    <Description>A simple extension</Description>
  </Metadata>
</PackageManifest>"#;
        let (v, _) = run(manifest);
        assert_eq!(
            v.get("vsix.identity.id").and_then(|x| x.as_str()),
            Some("hello-world")
        );
        assert_eq!(
            v.get("vsix.identity.publisher").and_then(|x| x.as_str()),
            Some("acme")
        );
        assert_eq!(
            v.get("vsix.display_name").and_then(|x| x.as_str()),
            Some("Hello World")
        );
    }

    #[test]
    fn surfaces_executes_code_property() {
        let manifest = br#"<?xml version="1.0" encoding="utf-8"?>
<PackageManifest>
  <Metadata>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
    </Properties>
  </Metadata>
</PackageManifest>"#;
        let (v, m) = run(manifest);
        let props = v
            .get("vsix.properties")
            .and_then(|x| x.as_object())
            .unwrap();
        assert_eq!(
            props.get("code.executescode").and_then(|x| x.as_str()),
            Some("true")
        );
        assert_eq!(m.get("vsix.property_count"), Some(2.0));
    }

    #[test]
    fn tags_split_on_commas() {
        let manifest = br#"<PackageManifest>
  <Metadata>
    <Tags>themes, debugger, snippet</Tags>
  </Metadata>
</PackageManifest>"#;
        let (v, _) = run(manifest);
        let tags = v.get("vsix.tags").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = tags.iter().filter_map(|x| x.as_str()).collect();
        assert_eq!(names, vec!["themes", "debugger", "snippet"]);
    }

    #[test]
    fn non_xml_is_silent() {
        let (v, _) = run(b"not xml at all");
        assert!(v.get("vsix.identity").is_none());
    }

    #[test]
    fn dependencies_and_assets_surface() {
        let manifest = br#"<?xml version="1.0" encoding="utf-8"?>
<PackageManifest>
  <Dependencies>
    <Dependency Id="ms-python.python" Version="[2024.0.0,)" />
    <Dependency Id="ms-vscode.vscode-typescript" Version="[1.0.0,)" />
  </Dependencies>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" />
    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="extension/icon.png" />
  </Assets>
</PackageManifest>"#;
        let (v, m) = run(manifest);
        let deps = v
            .get("vsix.dependencies")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(deps.len(), 2);
        let ids: Vec<&str> = deps
            .iter()
            .filter_map(|d| d.get("id").and_then(|x| x.as_str()))
            .collect();
        assert!(ids.contains(&"ms-python.python"));
        let assets = v.get("vsix.assets").and_then(|x| x.as_array()).unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(m.get("vsix.asset_count"), Some(2.0));
    }

    #[test]
    fn utf8_bom_stripped() {
        let mut manifest = vec![0xEF, 0xBB, 0xBF];
        manifest.extend_from_slice(
            br#"<PackageManifest>
  <Metadata>
    <Identity Id="bom-ext" Publisher="me" Version="0.0.1" />
  </Metadata>
</PackageManifest>"#,
        );
        let (v, _) = run(&manifest);
        assert_eq!(
            v.get("vsix.identity.id").and_then(|x| x.as_str()),
            Some("bom-ext")
        );
    }

    #[test]
    fn target_platform_promoted() {
        let manifest = br#"<PackageManifest>
  <Metadata>
    <Identity Id="x" Publisher="p" Version="0.1" TargetPlatform="darwin-arm64" />
  </Metadata>
</PackageManifest>"#;
        let (v, _) = run(manifest);
        assert_eq!(
            v.get("vsix.target_platform").and_then(|x| x.as_str()),
            Some("darwin-arm64")
        );
    }

    #[test]
    fn shorten_property_id_handles_non_microsoft() {
        assert_eq!(
            shorten_property_id("Microsoft.VisualStudio.Code.ExecutesCode"),
            "code.executescode"
        );
        assert_eq!(shorten_property_id("Custom.Whatever"), "Custom.Whatever");
    }

    #[test]
    fn empty_input_is_silent() {
        let (v, m) = run(b"");
        assert!(v.get("vsix.identity").is_none());
        assert!(m.get("vsix.property_count").is_none());
    }

    #[test]
    fn malformed_xml_is_silent() {
        // Unterminated tag — parser must reject without panicking.
        let (v, _) = run(b"<PackageManifest><Identity Id=\"x\"");
        assert!(v.get("vsix.identity").is_none());
    }
}
