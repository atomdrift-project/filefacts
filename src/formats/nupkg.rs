//! NuGet package (`.nupkg`) `.nuspec` identity extractor.
//!
//! A `.nupkg` is a ZIP whose root carries a `{id}.nuspec` XML manifest.
//! The generic [`super::zip`] walk lists the members; this reads the
//! manifest for the publisher identity NuGet packages declare —
//! `id`, `version`, `authors`, `owners`, and `projectUrl`.

use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::output::{Metrics, Values};

/// A `.nuspec` above this is not legitimate — stop rather than buffer it.
const MAX_NUSPEC: u64 = 1 << 20;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    _metrics: &mut Metrics,
) -> Result<(), Error> {
    // The manifest is a single root-level `{id}.nuspec`.
    let Some(name) = zip
        .file_names()
        .find(|n| n.ends_with(".nuspec") && !n.contains('/'))
        .map(str::to_string)
    else {
        return Ok(());
    };
    let Ok(member) = zip.by_name(&name) else {
        return Ok(());
    };
    let mut buf = Vec::new();
    if member.take(MAX_NUSPEC).read_to_end(&mut buf).is_err() {
        return Ok(());
    }
    if let Ok(text) = String::from_utf8(buf) {
        parse_nuspec(&text, values);
    }
    Ok(())
}

/// Emit `nupkg.*` from a `.nuspec`. `authors` / `owners` are
/// comma-separated lists the identity normalizer splits into people.
fn parse_nuspec(text: &str, values: &mut Values) {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let Ok(doc) = roxmltree::Document::parse(text) else {
        return;
    };
    const FIELDS: &[(&str, &str)] = &[
        ("id", "nupkg.id"),
        ("version", "nupkg.version"),
        ("title", "nupkg.title"),
        ("authors", "nupkg.authors"),
        ("owners", "nupkg.owners"),
        ("projectUrl", "nupkg.project_url"),
        ("repository", "nupkg.repository_url"),
    ];
    for (tag, key) in FIELDS {
        if let Some(node) = doc.descendants().find(|n| n.has_tag_name(*tag)) {
            // <repository> carries its URL as an attribute, not text.
            let value = if *tag == "repository" {
                node.attribute("url").map(str::trim)
            } else {
                node.text().map(str::trim)
            };
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                values.insert(key, JsonValue::String(value.to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuspec_identity_fields_extracted() {
        let xml = r#"<?xml version="1.0"?>
            <package><metadata>
                <id>Acme.Widgets</id>
                <version>1.2.3</version>
                <authors>Acme Corp</authors>
                <owners>Acme Corp</owners>
                <projectUrl>https://acme.test</projectUrl>
            </metadata></package>"#;
        let mut v = Values::new();
        parse_nuspec(xml, &mut v);
        assert_eq!(
            v.get("nupkg.id").and_then(|x| x.as_str()),
            Some("Acme.Widgets")
        );
        assert_eq!(
            v.get("nupkg.authors").and_then(|x| x.as_str()),
            Some("Acme Corp")
        );
        assert_eq!(
            v.get("nupkg.project_url").and_then(|x| x.as_str()),
            Some("https://acme.test")
        );
    }
}
