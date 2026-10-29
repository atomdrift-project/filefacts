use super::*;
use crate::formats::testutil::stored_zip;

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
    extract(text, &mut v, &mut s, &mut m, &mut e);
    (v, m, e)
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
    );
    (v, e)
}

/// The one recorded error's stage and kind.
fn only_error(errors: &Errors) -> (Stage, crate::DiagnosticKind) {
    assert_eq!(errors.len(), 1, "{errors:?}");
    (errors.as_slice()[0].stage, errors.as_slice()[0].kind)
}

#[test]
fn archive_manifest_that_is_not_xml_records_one_error() {
    let (v, e) = run_archive(&stored_zip(&[(
        "extension.vsixmanifest",
        b"<PackageManifest><Identity Id=\"x\"",
    )]));
    assert_eq!(
        only_error(&e),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    assert!(v.get("vsix.identity").is_none());
    assert!(v.get("vsix.limits").is_none());
}

#[test]
fn archive_with_well_formed_or_absent_manifest_records_nothing() {
    let (v, e) = run_archive(&stored_zip(&[(
        "extension.vsixmanifest",
        b"<PackageManifest><Identity Id=\"x\" Publisher=\"p\" Version=\"1\"/></PackageManifest>",
    )]));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(
        v.get("vsix.identity.id").and_then(|x| x.as_str()),
        Some("x")
    );
    let (_, e) = run_archive(&stored_zip(&[("extension/package.json", b"{}")]));
    assert!(e.is_empty(), "{e:?}");
}

#[test]
fn archive_manifest_over_the_cap_is_a_limit_not_an_error() {
    let big = vec![b' '; MAX_MANIFEST as usize + 1];
    let (v, e) = run_archive(&stored_zip(&[("extension.vsixmanifest", &big)]));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("vsix.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits[0]["stage"], "manifest");
}

#[test]
fn standalone_manifest_that_is_not_utf8_records_one_error() {
    let (_, _, e) = run_with_errors(b"<PackageManifest>\xff</PackageManifest>");
    assert_eq!(
        only_error(&e),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
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
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
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
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
}

#[test]
fn malformed_xml_records_one_error() {
    // Unterminated tag — parser must reject without panicking.
    let (v, _, e) = run_with_errors(b"<PackageManifest><Identity Id=\"x\"");
    assert!(v.get("vsix.identity").is_none());
    assert_eq!(
        only_error(&e),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
}
