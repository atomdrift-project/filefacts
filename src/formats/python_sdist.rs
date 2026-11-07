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
//! metadata is the last one in the sdist. The same walk reads the
//! `*.egg-info/requires.txt` setuptools writes, whose requirements count
//! toward the package-consistency judgements (see `package_consistency`).

use super::core_metadata::{CoreMetadata, emit_people};
use crate::formats::ExtractCtx;
use serde_json::Value as JsonValue;

use super::bounded::{
    Limits, MAX_MANIFEST_BYTES, MAX_TARGZ_SEARCH, MemberFailure, TarGzMembers, find_targz_members,
    utf8_prefix,
};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{Metrics, Stage, ValueKey, Values};
use crate::value_key;

pub(super) fn extract(bytes: &[u8], ctx: ExtractCtx<'_>) -> Result<(), Error> {
    let ExtractCtx {
        values,
        metrics,
        archive_members,
        errors,
        ..
    } = ctx;
    match metadata(bytes, values) {
        Ok(Some((pkg_info, requires_txt))) => {
            emit(&pkg_info, requires_txt.as_deref(), values, metrics);
        }
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

/// Read the `<root>/PKG-INFO` metadata, and the `requires.txt` of an
/// `*.egg-info` directory when there is one, from a gzipped sdist tarball in
/// one walk; `Ok(None)` when it has no `PKG-INFO`, or when the inflate budget
/// ran out before the tarball's end (a `python.limits` entry). The last of
/// each is the one read. Only the leading header block is used, so a
/// `PKG-INFO` past the cap is read as its first [`MAX_MANIFEST_BYTES`] bytes
/// (to the last whole character), with a `python.limits` entry, rather than
/// refused. Fails when the tarball would not decompress, or `PKG-INFO` is
/// not UTF-8; a `requires.txt` that is not UTF-8 is skipped.
fn metadata(
    bytes: &[u8],
    values: &mut Values,
) -> Result<Option<(String, Option<String>)>, MemberFailure> {
    const SOUGHT: &str = "<root>/PKG-INFO";
    let is_pkg_info = |path: &str| {
        let trimmed = path.trim_end_matches('/');
        trimmed.ends_with("/PKG-INFO") && trimmed.split('/').count() == 2
    };
    let is_requires = |path: &str| {
        path.strip_suffix("/requires.txt")
            .is_some_and(|dir| dir.ends_with(".egg-info"))
    };
    let [pkg_info, requires] = match find_targz_members(
        bytes,
        [&is_pkg_info, &is_requires],
        MAX_MANIFEST_BYTES,
    ) {
        Ok(TarGzMembers::Read(found)) => found,
        Ok(TarGzMembers::InflateCapped) => {
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
    let Some((path, prefix)) = pkg_info else {
        return Ok(None);
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
    let pkg_info = utf8_prefix(prefix)
        .map_err(|e| MemberFailure::new(Stage::FormatExtract, format!("{path}: not UTF-8"), e))?;
    let requires = requires.and_then(|(path, prefix)| match utf8_prefix(prefix) {
        Ok(text) => Some(text),
        Err(error) => {
            tracing::debug!(target: "filefacts::python_sdist", path = %path, %error, "requires.txt not UTF-8; skipped");
            None
        }
    });
    Ok(Some((pkg_info, requires)))
}

/// Emit `python.*` identity values from a parsed `PKG-INFO` header block,
/// and the package-consistency judgements over it and `requires.txt`.
fn emit(text: &str, requires_txt: Option<&str>, values: &mut Values, metrics: &mut Metrics) {
    let headers = CoreMetadata::parse(text);
    super::package_consistency::core_metadata(&headers, requires_txt, metrics);
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
