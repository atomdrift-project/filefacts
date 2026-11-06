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
//! An installer extracts every member, and `tarfile` looks a name up by its
//! last occurrence, so a later `PKG-INFO` replaces an earlier one: the
//! metadata is the last one in the sdist.

use super::core_metadata::{CoreMetadata, emit_people};
use crate::formats::ExtractCtx;
use serde_json::Value as JsonValue;

use super::bounded::{
    Limits, MAX_MANIFEST_BYTES, MAX_TARGZ_SEARCH, MemberFailure, TarGzSearch, find_targz_member,
    utf8_prefix,
};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{Stage, ValueKey, Values};
use crate::value_key;

pub(super) fn extract(bytes: &[u8], ctx: ExtractCtx<'_>) -> Result<(), Error> {
    let ExtractCtx {
        values,
        metrics,
        archive_members,
        errors,
        ..
    } = ctx;
    match pkg_info(bytes, values) {
        Ok(Some(text)) => emit(&text, values),
        // No root `PKG-INFO`: nothing to read, nothing failed.
        Ok(None) => {}
        Err(failure) => failure.record(errors),
    }
    super::tar::extract(
        bytes,
        FileType::PythonSdist,
        values,
        metrics,
        archive_members,
    )
}

/// Read the `<root>/PKG-INFO` metadata from a gzipped sdist tarball;
/// `Ok(None)` when it has none, or when the inflate budget ran out before
/// the tarball's end (a `python.limits` entry). The last `PKG-INFO` is the
/// one read. Only the leading header block is used, so a
/// `PKG-INFO` past the cap is read as its first [`MAX_MANIFEST_BYTES`] bytes
/// (to the last whole character), with a `python.limits` entry, rather than
/// refused. Fails when the tarball would not decompress, or `PKG-INFO` is
/// not UTF-8.
fn pkg_info(bytes: &[u8], values: &mut Values) -> Result<Option<String>, MemberFailure> {
    const SOUGHT: &str = "<root>/PKG-INFO";
    let is_pkg_info = |path: &str| {
        let trimmed = path.trim_end_matches('/');
        trimmed.ends_with("/PKG-INFO") && trimmed.split('/').count() == 2
    };
    let (path, prefix) = match find_targz_member(bytes, is_pkg_info, MAX_MANIFEST_BYTES) {
        Ok(TarGzSearch::Found { path, prefix }) => (path, prefix),
        Ok(TarGzSearch::Absent) => return Ok(None),
        Ok(TarGzSearch::InflateCapped) => {
            let mut limits = Limits::default();
            limits.push(
                "pkg-info-search",
                format!(
                    "tarball inflates past {MAX_TARGZ_SEARCH} bytes before its end; {SOUGHT} not read"
                ),
            );
            limits.emit(values, value_key!("python.limits"));
            return Ok(None);
        }
        Err(e) => return Err(e.into_failure(Stage::TarParse, SOUGHT)),
    };
    if prefix.truncated {
        let mut limits = Limits::default();
        limits.push(
            "pkg-info",
            format!(
                "{path} over the {MAX_MANIFEST_BYTES}-byte cap; header block read from its prefix"
            ),
        );
        limits.emit(values, value_key!("python.limits"));
    }
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
        value_key!("python.limits"),
    );
}

#[cfg(test)]
mod tests;
