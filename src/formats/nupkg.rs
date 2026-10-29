//! NuGet package (`.nupkg`) `.nuspec` identity extractor.
//!
//! A `.nupkg` is a ZIP whose root carries a `{id}.nuspec` XML manifest.
//! The generic [`super::zip`] walk lists the members; this reads the
//! manifest for the publisher identity NuGet packages declare —
//! `id`, `version`, `authors`, `owners`, and `projectUrl`.

use super::people;
use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use super::bounded::Limits;
use super::common::ends_with_ci;
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// A `.nuspec` above this is not legitimate — stop rather than buffer it.
const MAX_NUSPEC: u64 = 1 << 20;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    _metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // The manifest is a single root-level `{id}.nuspec`; NuGet matches the
    // extension without regard to case.
    let Some(name) = zip
        .file_names()
        .filter_map(Result::ok)
        .find(|n| ends_with_ci(n, ".nuspec") && !n.contains('/'))
        .map(std::borrow::Cow::into_owned)
    else {
        return;
    };
    let mut limits = Limits::default();
    let manifest =
        super::zip::read_manifest_member(zip, &name, MAX_NUSPEC, &mut limits, "nuspec", errors);
    limits.emit(values, value_key!("nupkg.limits"));
    let Some(buf) = manifest else {
        return;
    };
    let parsed = String::from_utf8(buf)
        .map_err(|e| format!("not UTF-8: {e}"))
        .and_then(|text| parse_nuspec(&text, values).map_err(|e| e.to_string()));
    if let Err(why) = parsed {
        errors.record_malformed(Stage::FormatExtract, format!("{name}: {why}"));
    }
}

/// Emit `nupkg.*` from a `.nuspec`. Its `authors` and `owners` are
/// comma-separated name lists, published as people.
fn parse_nuspec(text: &str, values: &mut Values) -> Result<(), roxmltree::Error> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let doc = roxmltree::Document::parse(text)?;
    const FIELDS: &[(&str, ValueKey)] = &[
        ("id", value_key!("nupkg.name")),
        ("version", value_key!("nupkg.version")),
        ("title", value_key!("nupkg.title")),
        ("description", value_key!("nupkg.description")),
        ("projectUrl", value_key!("nupkg.homepage")),
        ("repository", value_key!("nupkg.repository")),
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
                values.insert_key(*key, JsonValue::String(value.to_string()));
            }
        }
    }
    for (tag, key) in [
        ("authors", value_key!("nupkg.authors")),
        ("owners", value_key!("nupkg.owners")),
    ] {
        let names = doc
            .descendants()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .unwrap_or_default();
        people::put(
            values,
            key,
            names
                .split(',')
                .map(|name| people::Person::from_fields(Some(name), None)),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
