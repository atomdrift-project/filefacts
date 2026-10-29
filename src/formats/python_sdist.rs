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

use super::people::{self, Person};
use serde_json::Value as JsonValue;

use super::bounded::{
    Limits, MAX_TARGZ_SEARCH, MemberFailure, TarGzSearch, find_targz_member, utf8_prefix,
};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

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
    match pkg_info(bytes, values) {
        Ok(Some(text)) => emit(&text, values),
        // No root `PKG-INFO`: nothing to read, nothing failed.
        Ok(None) => {}
        Err(failure) => failure.record(errors),
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read the `<root>/PKG-INFO` metadata from a gzipped sdist tarball;
/// `Ok(None)` when it has none, or when the inflate budget ran out first (a
/// `python.limits` entry). Only the leading header block is used, so a
/// `PKG-INFO` past the cap is read as its first `MAX_MANIFEST` bytes (to the
/// last whole character) rather than refused. Fails when the tarball would
/// not decompress, or `PKG-INFO` is not UTF-8.
fn pkg_info(bytes: &[u8], values: &mut Values) -> Result<Option<String>, MemberFailure> {
    const SOUGHT: &str = "<root>/PKG-INFO";
    let is_pkg_info = |path: &str| {
        let trimmed = path.trim_end_matches('/');
        trimmed.ends_with("/PKG-INFO") && trimmed.split('/').count() == 2
    };
    let (path, prefix) = match find_targz_member(bytes, is_pkg_info, MAX_MANIFEST) {
        Ok(TarGzSearch::Found { path, prefix }) => (path, prefix),
        Ok(TarGzSearch::Absent) => return Ok(None),
        Ok(TarGzSearch::InflateCapped) => {
            let mut limits = Limits::default();
            limits.push(
                "pkg-info-search",
                format!("no {SOUGHT} in the first {MAX_TARGZ_SEARCH} inflated bytes"),
            );
            limits.emit(values, value_key!("python.limits"));
            return Ok(None);
        }
        Err(e) => return Err(e.into_failure(Stage::TarParse, SOUGHT)),
    };
    utf8_prefix(prefix)
        .map(Some)
        .map_err(|e| MemberFailure::new(Stage::FormatExtract, format!("{path}: not UTF-8"), e))
}

/// Emit `python.*` identity values from a parsed `PKG-INFO` header block.
fn emit(text: &str, values: &mut Values) {
    let headers = CoreMetadata::parse(text);
    let set = |values: &mut Values, key: ValueKey, field: &str| {
        if let Some(v) = headers.first(field) {
            values.insert_key(key, JsonValue::String(v.to_string()));
        }
    };
    set(values, value_key!("python.name"), "name");
    set(values, value_key!("python.version"), "version");
    set(values, value_key!("python.description"), "summary");
    set(values, value_key!("python.license"), "license");
    set(values, value_key!("python.homepage"), "home-page");
    set(
        values,
        value_key!("python.requires_python"),
        "requires-python",
    );

    emit_people(
        &headers,
        values,
        value_key!("python.authors"),
        value_key!("python.maintainers"),
    );
}

/// The people a Core Metadata block names in its `<role>` and
/// `<role>-email` headers. PEP 621 writes several as comma-separated lists,
/// `"A <a@x>, B <b@x>"` in the email header, so the two lists pair up when
/// they are the same length; otherwise each entry stands alone. `UNKNOWN`,
/// setuptools' placeholder for a field the author left out, names nobody.
fn core_metadata_people(headers: &CoreMetadata, role: &str) -> Vec<Person> {
    let list = |field: &str| -> Vec<&str> {
        headers
            .first(field)
            .into_iter()
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "UNKNOWN")
            .collect()
    };
    let names = list(role);
    let emails = list(&format!("{role}-email"));
    if names.len() == emails.len() {
        return names
            .iter()
            .zip(&emails)
            .map(|(name, email)| Person::from_fields(Some(name), Some(email)))
            .collect();
    }
    names
        .iter()
        .map(|name| Person::from_fields(Some(name), None))
        .chain(
            emails
                .iter()
                .map(|email| Person::from_fields(None, Some(email))),
        )
        .collect()
}

/// Publish a Core Metadata block's authors and maintainers under `authors`
/// and `maintainers`.
pub(super) fn emit_people(
    headers: &CoreMetadata,
    values: &mut Values,
    authors: ValueKey,
    maintainers: ValueKey,
) {
    people::put(values, authors, core_metadata_people(headers, "author"));
    people::put(
        values,
        maintainers,
        core_metadata_people(headers, "maintainer"),
    );
}

/// A Python Core Metadata header block (`PKG-INFO`, a wheel's `METADATA`):
/// RFC 822 fields in file order, names lowercased, a field repeated once per
/// occurrence. A folded (continuation) line joins the field before it on a
/// newline; the block ends at the first blank line, which begins the long
/// description. The one parser for every Core Metadata reader.
pub(super) struct CoreMetadata {
    pub(super) fields: Vec<(String, String)>,
}

impl CoreMetadata {
    pub(super) fn parse(text: &str) -> Self {
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                break; // end of headers; body follows
            }
            if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = fields.last_mut() {
                    if !value.is_empty() {
                        value.push('\n');
                    }
                    value.push_str(line.trim());
                }
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                fields.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Self { fields }
    }

    /// The first non-empty value of `field`, lowercase.
    pub(super) fn first(&self, field: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

#[cfg(test)]
mod tests;
