//! NuGet package (`.nupkg`) `.nuspec` identity extractor.
//!
//! A `.nupkg` is a ZIP whose root carries a `{id}.nuspec` XML manifest.
//! The generic [`super::zip`] walk lists the members; this reads the
//! manifest for the publisher identity NuGet packages declare —
//! `id`, `version`, `authors`, `owners`, and `projectUrl`.

use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// A `.nuspec` above this is not legitimate — stop rather than buffer it.
const MAX_NUSPEC: u64 = 1 << 20;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    _metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    // The manifest is a single root-level `{id}.nuspec`.
    let Some(name) = zip
        .file_names()
        .find(|n| n.ends_with(".nuspec") && !n.contains('/'))
        .map(str::to_string)
    else {
        return Ok(());
    };
    let mut buf = Vec::new();
    if let Err(e) = zip
        .by_name(&name)
        .map_err(std::io::Error::other)
        .and_then(|member| member.take(MAX_NUSPEC + 1).read_to_end(&mut buf))
    {
        errors.record_malformed(Stage::ZipParse, format!("{name}: {e}"));
        return Ok(());
    }
    if buf.len() as u64 > MAX_NUSPEC {
        values.insert(
            "nupkg.limits",
            serde_json::json!([{
                "stage": "nuspec",
                "reason": format!("{name} over the {MAX_NUSPEC}-byte cap; not parsed"),
            }]),
        );
        return Ok(());
    }
    let parsed = String::from_utf8(buf)
        .map_err(|e| format!("not UTF-8: {e}"))
        .and_then(|text| parse_nuspec(&text, values).map_err(|e| e.to_string()));
    if let Err(why) = parsed {
        errors.record_malformed(Stage::FormatExtract, format!("{name}: {why}"));
    }
    Ok(())
}

/// Emit `nupkg.*` from a `.nuspec`. `authors` / `owners` are
/// comma-separated lists the identity normalizer splits into people.
fn parse_nuspec(text: &str, values: &mut Values) -> Result<(), roxmltree::Error> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let doc = roxmltree::Document::parse(text)?;
    const FIELDS: &[(&str, ValueKey)] = &[
        ("id", value_key!("nupkg.id")),
        ("version", value_key!("nupkg.version")),
        ("title", value_key!("nupkg.title")),
        ("description", value_key!("nupkg.description")),
        ("authors", value_key!("nupkg.authors")),
        ("owners", value_key!("nupkg.owners")),
        ("projectUrl", value_key!("nupkg.project_url")),
        ("repository", value_key!("nupkg.repository_url")),
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn nupkg_with(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = ::zip::write::SimpleFileOptions::default()
            .compression_method(::zip::CompressionMethod::Stored);
        for (name, body) in members {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn run(bytes: &[u8]) -> (Values, Errors) {
        let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut v = Values::new();
        let mut e = Errors::new();
        extract_from_archive(&mut zip, &mut v, &mut Metrics::new(), &mut e).unwrap();
        (v, e)
    }

    #[test]
    fn nuspec_that_is_not_xml_records_one_error() {
        let (v, e) = run(&nupkg_with(&[("Acme.nuspec", b"<package><metadata>")]));
        assert_eq!(e.len(), 1, "{e:?}");
        let err = &e.as_slice()[0];
        assert_eq!(
            (err.stage, err.kind),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
        assert!(err.message.starts_with("Acme.nuspec:"), "{}", err.message);
        assert!(v.get("nupkg.limits").is_none());
    }

    #[test]
    fn well_formed_or_absent_nuspec_records_nothing() {
        let (v, e) = run(&nupkg_with(&[(
            "Acme.nuspec",
            b"<package><metadata><id>Acme</id></metadata></package>",
        )]));
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(v.get("nupkg.id").and_then(|x| x.as_str()), Some("Acme"));
        let (_, e) = run(&nupkg_with(&[("lib/a.dll", b"MZ")]));
        assert!(e.is_empty(), "{e:?}");
    }

    #[test]
    fn oversized_nuspec_is_a_limit_not_an_error() {
        let big = vec![b' '; MAX_NUSPEC as usize + 1];
        let (v, e) = run(&nupkg_with(&[("Acme.nuspec", &big)]));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("nupkg.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits[0]["stage"], "nuspec");
    }

    #[test]
    fn nuspec_identity_fields_extracted() {
        let xml = r#"<?xml version="1.0"?>
            <package><metadata>
                <id>Acme.Widgets</id>
                <version>1.2.3</version>
                <authors>Acme Corp</authors>
                <owners>Acme Corp</owners>
                <projectUrl>https://acme.test</projectUrl>
                <description>Widgets for .NET</description>
            </metadata></package>"#;
        let mut v = Values::new();
        parse_nuspec(xml, &mut v).unwrap();
        assert_eq!(
            v.get("nupkg.description").and_then(|x| x.as_str()),
            Some("Widgets for .NET")
        );
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
