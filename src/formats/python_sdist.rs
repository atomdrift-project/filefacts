//! Python source distribution (`sdist`) identity extractor.
//!
//! The member listing comes from the generic [`super::tar`] walker; this
//! module adds the publisher identity that lives in the `PKG-INFO` metadata
//! file at the root of the `<name>-<version>/` tree. `PKG-INFO` is an
//! RFC 822 / email-style header block (the Core Metadata format), so the
//! fields are read line by line. The author/maintainer emails are the
//! strongest cross-package identifiers a PyPI sdist carries, so they are
//! surfaced as structured fields the identity normalizer rolls up.
//!
//! Decompression stops as soon as `<root>/PKG-INFO` is reached, so a
//! multi-megabyte sdist is rarely fully inflated just to read one manifest.

use std::io::Read;

use flate2::read::GzDecoder;
use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Metrics, Values};

/// `PKG-INFO` headers larger than this are almost certainly hostile padding;
/// we stop reading rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    if let Some(text) = pkg_info(bytes) {
        emit(&text, values);
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read the `<root>/PKG-INFO` metadata from a gzipped sdist tarball.
/// Best-effort: any malformed step yields `None`.
fn pkg_info(bytes: &[u8]) -> Option<String> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    for entry in archive.entries().ok()? {
        let Ok(mut entry) = entry else { break };
        let is_manifest = entry
            .path()
            .map(|p| {
                let p = p.to_string_lossy();
                let trimmed = p.trim_end_matches('/');
                trimmed.ends_with("/PKG-INFO") && trimmed.split('/').count() == 2
            })
            .unwrap_or(false);
        if !is_manifest {
            continue;
        }
        let mut buf = Vec::new();
        (&mut entry).take(MAX_MANIFEST).read_to_end(&mut buf).ok()?;
        return String::from_utf8(buf).ok();
    }
    None
}

/// Emit `python.*` identity values from a parsed `PKG-INFO` header block.
fn emit(text: &str, values: &mut Values) {
    let headers = Headers::parse(text);
    let set = |values: &mut Values, key: &str, field: &str| {
        if let Some(v) = headers.first(field) {
            values.insert(key, JsonValue::String(v.to_string()));
        }
    };
    set(values, "python.name", "name");
    set(values, "python.version", "version");
    set(values, "python.summary", "summary");
    set(values, "python.license", "license");
    set(values, "python.homepage", "home-page");
    set(values, "python.requires_python", "requires-python");

    emit_person(&headers, "author", values, "python.author");
    emit_person(&headers, "maintainer", values, "python.maintainer");
}

/// Emit a `<prefix>.name` / `<prefix>.email` pair from the `<role>` /
/// `<role>-email` headers. Modern `PKG-INFO` often carries the name only in
/// the `*-email` header's `"Name <email>"` form, so the name falls back to
/// that when the plain `<role>` header is absent.
fn emit_person(headers: &Headers, role: &str, values: &mut Values, prefix: &str) {
    let email_field = format!("{role}-email");
    let raw_email = headers.first(&email_field);
    let email = raw_email.and_then(extract_email);
    let name = headers
        .first(role)
        .map(str::to_string)
        .or_else(|| raw_email.and_then(strip_email));
    if let Some(name) = name.filter(|n| !n.is_empty()) {
        values.insert(&format!("{prefix}.name"), JsonValue::String(name));
    }
    if let Some(email) = email {
        values.insert(&format!("{prefix}.email"), JsonValue::String(email));
    }
}

/// Pull the address out of an `"Name <email>"` string, or accept a bare
/// address when it looks like one (`contains('@')`).
fn extract_email(s: &str) -> Option<String> {
    if let (Some(start), Some(end)) = (s.find('<'), s.find('>')) {
        if start < end {
            let inner = s[start + 1..end].trim();
            return (!inner.is_empty()).then(|| inner.to_string());
        }
    }
    let s = s.trim();
    (s.contains('@') && !s.contains(' ')).then(|| s.to_string())
}

/// The display name from an `"Name <email>"` string (the part before `<`).
fn strip_email(s: &str) -> Option<String> {
    let name = s.split('<').next().unwrap_or("").trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// A parsed RFC 822 header block: lowercased field name → first value.
/// Continuation (folded) lines are appended to the current field; parsing
/// stops at the first blank line, which begins the long-description body.
struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    fn parse(text: &str) -> Self {
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                break; // end of headers; body follows
            }
            if line.starts_with([' ', '\t']) {
                if let Some(last) = fields.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line.trim());
                }
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                fields.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Self { fields }
    }

    fn first(&self, field: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_name_version_and_author_email() {
        let text = "Metadata-Version: 2.1\n\
                    Name: requests\n\
                    Version: 2.31.0\n\
                    Summary: Python HTTP for Humans.\n\
                    Home-page: https://requests.readthedocs.io\n\
                    Author: Kenneth Reitz\n\
                    Author-email: me@kennethreitz.org\n\
                    License: Apache 2.0\n\
                    \n\
                    long description body: Name: not-a-header\n";
        let mut values = Values::new();
        emit(text, &mut values);
        assert_eq!(
            values.get("python.name").and_then(JsonValue::as_str),
            Some("requests")
        );
        assert_eq!(
            values.get("python.version").and_then(JsonValue::as_str),
            Some("2.31.0")
        );
        assert_eq!(
            values.get("python.author.name").and_then(JsonValue::as_str),
            Some("Kenneth Reitz")
        );
        assert_eq!(
            values
                .get("python.author.email")
                .and_then(JsonValue::as_str),
            Some("me@kennethreitz.org")
        );
        // The body after the blank line must not leak in as a header.
        assert_eq!(
            values.get("python.name").and_then(JsonValue::as_str),
            Some("requests")
        );
    }

    #[test]
    fn author_email_in_name_angle_form() {
        let text = "Name: x\nAuthor-email: Jane Doe <jane@example.com>\n";
        let mut values = Values::new();
        emit(text, &mut values);
        assert_eq!(
            values.get("python.author.name").and_then(JsonValue::as_str),
            Some("Jane Doe")
        );
        assert_eq!(
            values
                .get("python.author.email")
                .and_then(JsonValue::as_str),
            Some("jane@example.com")
        );
    }
}
