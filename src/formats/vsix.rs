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

use crate::error::Error;
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
) -> Result<(), Error> {
    const NAME: &str = "extension.vsixmanifest";
    let member = match zip.by_name(NAME) {
        Ok(member) => member,
        Err(::zip::result::ZipError::FileNotFound) => return Ok(()),
        Err(e) => {
            errors.record_malformed(Stage::ZipParse, format!("{NAME}: {e}"));
            return Ok(());
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = member.take(MAX_MANIFEST + 1).read_to_end(&mut buf) {
        errors.record_malformed(Stage::ZipParse, format!("{NAME}: {e}"));
        return Ok(());
    }
    if buf.len() as u64 > MAX_MANIFEST {
        values.insert_key(
            value_key!("vsix.limits"),
            serde_json::json!([{
                "stage": "manifest",
                "reason": format!("{NAME} over the {MAX_MANIFEST}-byte cap; not parsed"),
            }]),
        );
        return Ok(());
    }
    extract(&buf, values, strings, metrics, errors)
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings, XorScan::No);

    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(e) => {
            errors.record_malformed(
                Stage::FormatExtract,
                format!("extension.vsixmanifest: not UTF-8: {e}"),
            );
            return Ok(());
        }
    };
    // Strip a UTF-8 BOM if present — `<PackageManifest>` won't parse
    // when the document starts with one.
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let doc = match roxmltree::Document::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            errors.record_malformed(Stage::FormatExtract, format!("extension.vsixmanifest: {e}"));
            return Ok(());
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
        let (v, m, e) = run_with_errors(text);
        assert!(e.is_empty(), "{e:?}");
        (v, m)
    }

    fn run_with_errors(text: &[u8]) -> (Values, Metrics, Errors) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut e = Errors::new();
        extract(text, &mut v, &mut s, &mut m, &mut e).unwrap();
        (v, m, e)
    }

    fn vsix_with(members: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = ::zip::write::SimpleFileOptions::default()
            .compression_method(::zip::CompressionMethod::Stored);
        for (name, body) in members {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn run_archive(bytes: &[u8]) -> (Values, Errors) {
        let mut zip = ::zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut v = Values::new();
        let mut e = Errors::new();
        extract_from_archive(
            &mut zip,
            &mut v,
            &mut Strings::default(),
            &mut Metrics::new(),
            &mut e,
        )
        .unwrap();
        (v, e)
    }

    /// The one recorded error's stage and kind.
    fn only_error(errors: &Errors) -> (Stage, crate::ErrorKind) {
        assert_eq!(errors.len(), 1, "{errors:?}");
        (errors.as_slice()[0].stage, errors.as_slice()[0].kind)
    }

    #[test]
    fn archive_manifest_that_is_not_xml_records_one_error() {
        let (v, e) = run_archive(&vsix_with(&[(
            "extension.vsixmanifest",
            b"<PackageManifest><Identity Id=\"x\"",
        )]));
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
        assert!(v.get("vsix.identity").is_none());
        assert!(v.get("vsix.limits").is_none());
    }

    #[test]
    fn archive_with_well_formed_or_absent_manifest_records_nothing() {
        let (v, e) = run_archive(&vsix_with(&[(
            "extension.vsixmanifest",
            b"<PackageManifest><Identity Id=\"x\" Publisher=\"p\" Version=\"1\"/></PackageManifest>",
        )]));
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(
            v.get("vsix.identity.id").and_then(|x| x.as_str()),
            Some("x")
        );
        let (_, e) = run_archive(&vsix_with(&[("extension/package.json", b"{}")]));
        assert!(e.is_empty(), "{e:?}");
    }

    #[test]
    fn archive_manifest_over_the_cap_is_a_limit_not_an_error() {
        let big = vec![b' '; MAX_MANIFEST as usize + 1];
        let (v, e) = run_archive(&vsix_with(&[("extension.vsixmanifest", &big)]));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("vsix.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits[0]["stage"], "manifest");
    }

    #[test]
    fn standalone_manifest_that_is_not_utf8_records_one_error() {
        let (_, _, e) = run_with_errors(b"<PackageManifest>\xff</PackageManifest>");
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
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
    fn non_xml_records_one_error() {
        let (v, _, e) = run_with_errors(b"not xml at all");
        assert!(v.get("vsix.identity").is_none());
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
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
    fn empty_input_records_one_error() {
        // A manifest that is present but empty does not parse.
        let (v, m, e) = run_with_errors(b"");
        assert!(v.get("vsix.identity").is_none());
        assert!(m.get("vsix.property_count").is_none());
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
    }

    #[test]
    fn malformed_xml_records_one_error() {
        // Unterminated tag — parser must reject without panicking.
        let (v, _, e) = run_with_errors(b"<PackageManifest><Identity Id=\"x\"");
        assert!(v.get("vsix.identity").is_none());
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
    }
}
