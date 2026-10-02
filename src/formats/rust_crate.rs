//! Rust crate (`.crate`) `Cargo.toml` identity extractor.
//!
//! A `.crate` is a gzipped tar whose `{name}-{version}/Cargo.toml`
//! carries the `[package]` identity — name, version, authors, and the
//! repository/homepage URLs. The generic [`super::tar`] walker lists the
//! members; this reads the manifest for the publisher identity.
//!
//! Decompression stops at the first `Cargo.toml`, so a large crate is
//! never fully inflated to read one manifest.

use serde_json::Value as JsonValue;

use super::bounded::{MAX_TARGZ_SEARCH, TarGzSearch, find_targz_member, push_limit};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// Manifests above this are not legitimate — stop rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<(), Error> {
    if let Some(manifest) = cargo_toml(bytes, values, errors) {
        emit(&manifest, values);
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read and parse `{name}-{version}/Cargo.toml` from the gzipped crate.
/// `None` when the crate has none (silently), when it is over the size cap
/// or past the inflate budget (a `crate.limits` entry), or when the crate or
/// manifest is unreadable or not TOML (an error). Decompression stops at
/// the manifest.
fn cargo_toml(bytes: &[u8], values: &mut Values, errors: &mut Errors) -> Option<toml::Value> {
    const SOUGHT: &str = "<root>/Cargo.toml";
    // Exactly `<root>/Cargo.toml` — not the vendored `Cargo.toml.orig`,
    // nor a nested workspace member or test fixture.
    let is_manifest = |path: &str| path.ends_with("/Cargo.toml") && path.split('/').count() == 2;
    let (path, prefix) = match find_targz_member(bytes, is_manifest, MAX_MANIFEST) {
        Ok(TarGzSearch::Found { path, prefix }) => (path, prefix),
        Ok(TarGzSearch::Absent) => return None,
        Ok(TarGzSearch::InflateCapped) => {
            push_limit(
                values,
                value_key!("crate.limits"),
                "manifest-search",
                format!("no {SOUGHT} in the first {MAX_TARGZ_SEARCH} inflated bytes"),
            );
            return None;
        }
        Err(e) => {
            e.into_failure(Stage::TarParse, SOUGHT).record(errors);
            return None;
        }
    };
    if prefix.truncated {
        push_limit(
            values,
            value_key!("crate.limits"),
            "manifest",
            format!("{path} over the {MAX_MANIFEST}-byte cap; not parsed"),
        );
        return None;
    }
    let parsed = String::from_utf8(prefix.bytes)
        .map_err(|e| format!("not UTF-8: {e}"))
        .and_then(|text| {
            toml::from_str::<toml::Value>(&text).map_err(|e| {
                // toml's message can span lines; keep the record on one.
                let message = e.message().lines().collect::<Vec<_>>().join("; ");
                match e.span() {
                    Some(span) => format!("{message} at byte {}", span.start),
                    None => message,
                }
            })
        });
    parsed
        .map_err(|why| errors.record_malformed(Stage::FormatExtract, format!("{path}: {why}")))
        .ok()
}

/// Emit `crate.*` identity from a parsed `Cargo.toml`'s `[package]`.
fn emit(manifest: &toml::Value, values: &mut Values) {
    let Some(pkg) = manifest.get("package") else {
        return;
    };
    let mut put = |key: ValueKey, field: &str| {
        if let Some(v) = pkg.get(field).and_then(toml::Value::as_str) {
            if !v.is_empty() {
                values.insert_key(key, JsonValue::String(v.to_string()));
            }
        }
    };
    put(value_key!("crate.name"), "name");
    put(value_key!("crate.version"), "version");
    put(value_key!("crate.description"), "description");
    put(value_key!("crate.repository"), "repository");
    put(value_key!("crate.homepage"), "homepage");
    if let Some(authors) = pkg.get("authors").and_then(toml::Value::as_array) {
        let list: Vec<JsonValue> = authors
            .iter()
            .filter_map(toml::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| JsonValue::String(s.to_string()))
            .collect();
        if !list.is_empty() {
            values.insert_key(value_key!("crate.authors"), JsonValue::Array(list));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A gzipped tar holding the given members.
    fn crate_with(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, body) in members {
            let mut h = tar::Header::new_ustar();
            h.set_path(path).unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append(&h, *body).unwrap();
        }
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    fn run(bytes: &[u8]) -> (Values, Errors) {
        let mut v = Values::new();
        let mut e = Errors::new();
        extract(
            bytes,
            FileType::Crate,
            &mut v,
            &mut Metrics::new(),
            &mut Vec::new(),
            &mut e,
        )
        .unwrap();
        (v, e)
    }

    /// The one recorded error's stage and kind.
    fn only_error(errors: &Errors) -> (Stage, crate::DiagnosticKind) {
        assert_eq!(errors.len(), 1, "{errors:?}");
        (errors.as_slice()[0].stage, errors.as_slice()[0].kind)
    }

    #[test]
    fn root_manifest_is_read_and_records_nothing() {
        // A nested fixture manifest that does not parse is not the crate's.
        let (v, e) = run(&crate_with(&[
            ("w-0.1.0/Cargo.toml", b"[package]\nname = \"w\"\n"),
            ("w-0.1.0/tests/bad/Cargo.toml", b"[package"),
        ]));
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(v.get("crate.name").and_then(|x| x.as_str()), Some("w"));
        let (_, e) = run(&crate_with(&[("w-0.1.0/src/lib.rs", b"")]));
        assert!(e.is_empty(), "{e:?}");
    }

    #[test]
    fn manifest_that_is_not_toml_records_one_error() {
        let (v, e) = run(&crate_with(&[("w-0.1.0/Cargo.toml", b"[package")]));
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
        );
        let message = &e.as_slice()[0].message;
        assert!(message.starts_with("w-0.1.0/Cargo.toml:"), "{message}");
        assert!(!message.contains('\n'), "{message}");
        assert!(v.get("crate.name").is_none());
    }

    #[test]
    fn corrupt_gzip_stream_records_one_tar_parse_error() {
        let mut bytes = crate_with(&[("w-0.1.0/Cargo.toml", b"[package]\nname = \"w\"\n")]);
        for b in &mut bytes[10..] {
            *b ^= 0x5a;
        }
        let (_, e) = run(&bytes);
        assert_eq!(
            only_error(&e),
            (Stage::TarParse, crate::DiagnosticKind::Malformed)
        );
    }

    #[test]
    fn oversized_manifest_is_a_limit_not_an_error() {
        let big = vec![b'#'; MAX_MANIFEST as usize + 1];
        let (v, e) = run(&crate_with(&[("w-0.1.0/Cargo.toml", &big)]));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("crate.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits[0]["stage"], "manifest");
    }

    #[test]
    fn cargo_toml_package_identity_extracted() {
        let toml = r#"
            [package]
            name = "widget"
            version = "0.3.1"
            description = "Widgets for gadgets"
            authors = ["Jane Dev <jane@example.test>"]
            repository = "https://example.test/widget"
        "#;
        let manifest: toml::Value = toml::from_str(toml).unwrap();
        let mut v = Values::new();
        emit(&manifest, &mut v);
        assert_eq!(v.get("crate.name").and_then(|x| x.as_str()), Some("widget"));
        assert_eq!(
            v.get("crate.description").and_then(|x| x.as_str()),
            Some("Widgets for gadgets")
        );
        assert_eq!(
            v.get("crate.version").and_then(|x| x.as_str()),
            Some("0.3.1")
        );
        assert_eq!(
            v.get("crate.repository").and_then(|x| x.as_str()),
            Some("https://example.test/widget")
        );
        assert_eq!(
            v.get("crate.authors")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_str()),
            Some("Jane Dev <jane@example.test>")
        );
    }
}
