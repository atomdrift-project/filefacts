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
use crate::output::{ArchiveMember, Errors, Metrics, Stage, Values};

/// `PKG-INFO` headers larger than this are almost certainly hostile padding;
/// we stop reading rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<(), Error> {
    match pkg_info(bytes) {
        Ok(Some(text)) => emit(&text, values),
        // No root `PKG-INFO`: nothing to read, nothing failed.
        Ok(None) => {}
        Err((stage, why)) => errors.record_malformed(stage, why),
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read the `<root>/PKG-INFO` metadata from a gzipped sdist tarball;
/// `Ok(None)` when it has none. Only the leading header block is used, so a
/// `PKG-INFO` past the cap is read as its first `MAX_MANIFEST` bytes (to the
/// last whole character) rather than refused. On failure, the stage it
/// failed in and why: the tarball would not decompress, or `PKG-INFO` is
/// not UTF-8.
fn pkg_info(bytes: &[u8]) -> Result<Option<String>, (Stage, String)> {
    let walk = |e: std::io::Error| {
        (
            Stage::TarParse,
            format!("tarball unreadable before <root>/PKG-INFO: {e}"),
        )
    };
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    for entry in archive.entries().map_err(walk)? {
        let mut entry = entry.map_err(walk)?;
        let Some(path) = entry.path().ok().map(|p| p.to_string_lossy().into_owned()) else {
            continue;
        };
        let trimmed = path.trim_end_matches('/');
        if !(trimmed.ends_with("/PKG-INFO") && trimmed.split('/').count() == 2) {
            continue;
        }
        let mut buf = Vec::new();
        (&mut entry)
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut buf)
            .map_err(|e| (Stage::TarParse, format!("{path}: {e}")))?;
        let capped = buf.len() as u64 > MAX_MANIFEST;
        buf.truncate(MAX_MANIFEST as usize);
        return match String::from_utf8(buf) {
            Ok(text) => Ok(Some(text)),
            // The cap cut a multi-byte character in two: not the file's fault.
            Err(e) if capped && e.utf8_error().error_len().is_none() => {
                let valid = e.utf8_error().valid_up_to();
                let mut bytes = e.into_bytes();
                bytes.truncate(valid);
                Ok(String::from_utf8(bytes).ok())
            }
            Err(e) => Err((Stage::FormatExtract, format!("{path}: not UTF-8: {e}"))),
        };
    }
    Ok(None)
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
    use std::io::Write;

    /// A gzipped tar holding the given members.
    fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
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
            FileType::PythonSdist,
            &mut v,
            &mut Metrics::new(),
            &mut Vec::new(),
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
    fn tarball_pkg_info_is_read_and_records_nothing() {
        let (v, e) = run(&tgz(&[("demo-1.0/PKG-INFO", b"Name: demo\n")]));
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(
            v.get("python.name").and_then(JsonValue::as_str),
            Some("demo")
        );
        // An sdist without a root PKG-INFO is not a failure.
        let (_, e) = run(&tgz(&[("demo-1.0/setup.py", b"#")]));
        assert!(e.is_empty(), "{e:?}");
    }

    #[test]
    fn pkg_info_that_is_not_utf8_records_one_error() {
        let (v, e) = run(&tgz(&[("demo-1.0/PKG-INFO", b"Name: d\xe9mo\n")]));
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
        assert!(v.get("python.name").is_none());
    }

    #[test]
    fn corrupt_gzip_stream_records_one_tar_parse_error() {
        let mut bytes = tgz(&[("demo-1.0/PKG-INFO", b"Name: demo\n")]);
        for b in &mut bytes[10..] {
            *b ^= 0x5a;
        }
        let (_, e) = run(&bytes);
        assert_eq!(
            only_error(&e),
            (Stage::TarParse, crate::ErrorKind::Malformed)
        );
    }

    /// Past the cap, the header block is still read, even when the cut lands
    /// inside a multi-byte character.
    #[test]
    fn oversized_pkg_info_is_read_up_to_the_cap() {
        for body_start in ["", "x"] {
            let mut meta = format!("Name: demo\nVersion: 1\n\n{body_start}").into_bytes();
            while meta.len() as u64 <= MAX_MANIFEST {
                meta.extend_from_slice("\u{e9}".as_bytes());
            }
            let (v, e) = run(&tgz(&[("demo-1.0/PKG-INFO", &meta)]));
            assert!(e.is_empty(), "{e:?}");
            assert_eq!(
                v.get("python.name").and_then(JsonValue::as_str),
                Some("demo")
            );
        }
    }

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
