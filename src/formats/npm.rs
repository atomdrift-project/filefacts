//! npm package (`.tgz`) and bare `package.json` identity extractor.
//!
//! The member listing comes from the generic [`super::tar`] walker; this
//! module adds the publisher identity that lives inside the manifest:
//! the package name, version, author and maintainer names/emails, and
//! the repository/homepage URLs. Emails are the strongest cross-package
//! identifier npm carries, so they are surfaced as structured fields the
//! identity normalizer rolls up.
//!
//! Decompression stops at `package/package.json` — npm always packs it
//! near the front — so a multi-megabyte tarball is never fully
//! inflated just to read one manifest.

use std::io::Read;

use flate2::read::GzDecoder;
use serde_json::Value as JsonValue;
use tar::Archive;

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Metrics, Values};

/// Manifests larger than this are almost certainly hostile padding; we
/// stop reading rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    if let Some(manifest) = package_json(bytes) {
        emit(&manifest, values);
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read and parse `package/package.json` from a gzipped npm tarball.
/// Best-effort: any malformed step yields `None`.
fn package_json(bytes: &[u8]) -> Option<JsonValue> {
    let mut archive = Archive::new(GzDecoder::new(bytes));
    for entry in archive.entries().ok()? {
        let Ok(entry) = entry else { break };
        let is_manifest = entry
            .path()
            .map(|p| p.to_string_lossy() == "package/package.json")
            .unwrap_or(false);
        if !is_manifest {
            continue;
        }
        let mut buf = Vec::new();
        entry.take(MAX_MANIFEST).read_to_end(&mut buf).ok()?;
        return serde_json::from_slice(&buf).ok();
    }
    None
}

/// Emit `npm.*` identity values from a parsed `package.json`. Shared by
/// the tarball path and the bare-`package.json` file type.
pub(super) fn emit(manifest: &JsonValue, values: &mut Values) {
    let Some(obj) = manifest.as_object() else {
        return;
    };
    if let Some(name) = obj.get("name").and_then(JsonValue::as_str) {
        values.insert("npm.name", JsonValue::String(name.to_string()));
    }
    if let Some(version) = obj.get("version").and_then(JsonValue::as_str) {
        values.insert("npm.version", JsonValue::String(version.to_string()));
    }
    if let Some(homepage) = obj.get("homepage").and_then(JsonValue::as_str) {
        values.insert("npm.homepage", JsonValue::String(homepage.to_string()));
    }
    if let Some(url) = repository_url(obj.get("repository")) {
        values.insert("npm.repository.url", JsonValue::String(url));
    }
    if let Some(author) = person(obj.get("author")) {
        for (field, value) in author.named_fields() {
            values.insert(&format!("npm.author.{field}"), JsonValue::String(value));
        }
    }
    let maintainers = people(obj.get("maintainers"));
    if !maintainers.is_empty() {
        values.insert("npm.maintainers", JsonValue::Array(maintainers));
    }
}

/// A `repository` is either a string (`"github:user/repo"` or a URL) or
/// an object `{ "url": "…" }`.
fn repository_url(value: Option<&JsonValue>) -> Option<String> {
    match value? {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Object(o) => o.get("url").and_then(JsonValue::as_str).map(str::to_string),
        _ => None,
    }
}

/// A parsed npm "person" — name, email, url — from either the object
/// form or the `"Name <email> (url)"` string form.
struct Person {
    name: Option<String>,
    email: Option<String>,
    url: Option<String>,
}

impl Person {
    fn named_fields(&self) -> impl Iterator<Item = (&'static str, String)> {
        [
            ("name", self.name.clone()),
            ("email", self.email.clone()),
            ("url", self.url.clone()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
    }

    fn into_json(self) -> Option<JsonValue> {
        let mut obj = serde_json::Map::new();
        for (k, v) in self.named_fields() {
            obj.insert(k.to_string(), JsonValue::String(v));
        }
        (!obj.is_empty()).then_some(JsonValue::Object(obj))
    }
}

fn person(value: Option<&JsonValue>) -> Option<Person> {
    match value? {
        JsonValue::String(s) => Some(parse_person_string(s)),
        JsonValue::Object(o) => {
            let p = Person {
                name: o
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                email: o
                    .get("email")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                url: o.get("url").and_then(JsonValue::as_str).map(str::to_string),
            };
            (p.name.is_some() || p.email.is_some()).then_some(p)
        }
        _ => None,
    }
}

fn people(value: Option<&JsonValue>) -> Vec<JsonValue> {
    value
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| person(Some(v)))
        .filter_map(Person::into_json)
        .collect()
}

/// Split `"Name <email> (url)"` into its parts.
fn parse_person_string(s: &str) -> Person {
    let email = between(s, '<', '>');
    let url = between(s, '(', ')');
    let name_end = s.find('<').or_else(|| s.find('(')).unwrap_or(s.len());
    let name = s[..name_end].trim();
    Person {
        name: (!name.is_empty()).then(|| name.to_string()),
        email,
        url,
    }
}

fn between(s: &str, open: char, close: char) -> Option<String> {
    let start = s.find(open)?;
    let end = s[start + 1..].find(close)? + start + 1;
    let inner = s[start + 1..end].trim();
    (!inner.is_empty()).then(|| inner.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_name_version_and_author_email() {
        let manifest = serde_json::json!({
            "name": "left-pad",
            "version": "1.3.0",
            "author": "Azer Koculu <azer@example.com> (http://azer.bike)",
            "repository": { "url": "git+https://github.com/azer/left-pad.git" }
        });
        let mut values = Values::new();
        emit(&manifest, &mut values);
        assert_eq!(
            values.get("npm.name").and_then(JsonValue::as_str),
            Some("left-pad")
        );
        assert_eq!(
            values.get("npm.author.email").and_then(JsonValue::as_str),
            Some("azer@example.com")
        );
        assert_eq!(
            values.get("npm.repository.url").and_then(JsonValue::as_str),
            Some("git+https://github.com/azer/left-pad.git")
        );
    }

    #[test]
    fn maintainers_become_structured_array() {
        let manifest = serde_json::json!({
            "name": "x",
            "maintainers": [{ "name": "a", "email": "a@x.io" }, "b <b@x.io>"]
        });
        let mut values = Values::new();
        emit(&manifest, &mut values);
        let m = values
            .get("npm.maintainers")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(
            m[1].get("email").and_then(JsonValue::as_str),
            Some("b@x.io")
        );
    }
}
