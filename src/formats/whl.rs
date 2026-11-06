//! Python wheel (`.whl`) central-directory extractor.
//!
//! A wheel is a ZIP that follows PEP 427: it carries a
//! `{distribution}-{version}.dist-info/` directory containing `WHEEL`,
//! `METADATA`, and `RECORD`. The PEP 427 *filename* additionally encodes
//! Python, ABI, and platform tags — those live outside the archive and
//! are not visible to this extractor, which operates on the central
//! directory alone (no decompression, no filesystem access).
//!
//! Emitted keys:
//!
//! - `whl.distribution`, `whl.version` — parsed from the dist-info dir
//!   name (`{name}-{ver}.dist-info/`).
//! - `whl.dist_info_dir` — the observed dist-info directory.
//! - `whl.has_metadata`, `whl.has_wheel`, `whl.has_record` — required
//!   dist-info members. Missing any is a malformed-wheel signal.
//! - `whl.signing.has_record_jws`, `whl.signing.has_record_p7s` — wheel
//!   signing artifacts. JWS is the PEP 376 form; rare in practice.
//! - `whl.has_data_dir` — `{name}-{ver}.data/` present (non-purelib data,
//!   scripts, headers).
//! - `whl.native_extension_count` — `.pyd` (Windows), `.so` (Linux),
//!   `.dylib` (macOS) files anywhere in the archive. Zero implies a
//!   pure-Python wheel; non-zero implies platform-specific binaries.
//! - `whl.purelib_shape` — true when no native extensions found.
//! - `whl.top_level_packages[]` — root-level directories excluding
//!   `.dist-info` and `.data`. These are the import-able package names.

use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;
use std::io::{Read, Seek};

use super::bounded::{Limits, MAX_MANIFEST_BYTES, MemberFailure};
use crate::output::{Errors, Metrics, Stage, Values};

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // Parse the outer wheel filename (set by lib.rs from `OpenOptions::path`)
    // for PEP 427 components. The name_prefix here is the *outer*
    // claim of identity, distinct from `whl.distribution` parsed from
    // the dist-info directory inside the archive. When they disagree,
    // it's an impersonation/repack signal.
    if let Some(basename) = values
        .lookup(value_key!("file.basename"))
        .and_then(JsonValue::as_str)
        .map(str::to_string)
    {
        parse_wheel_filename(&basename, values);
    }

    let mut dist_info_dir: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut has_metadata = false;
    let mut has_wheel = false;
    let mut has_record = false;
    let mut has_record_jws = false;
    let mut has_record_p7s = false;
    let mut native_extension_count: u64 = 0;
    let mut top_level: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for name in zip.file_names().filter_map(Result::ok) {
        let name = name.as_ref();
        // Identify the dist-info / data directories from the first
        // component of any path under them. A malformed wheel may carry
        // several; the first in central-directory order is kept, which is
        // deterministic for a given file. Layout names match exactly, as
        // installers match them.
        let first = name.split('/').next().unwrap_or(name);
        if first.ends_with(".dist-info") {
            dist_info_dir.get_or_insert_with(|| first.to_string());
        } else if first.rsplit_once('.').is_some_and(|(_, ext)| ext == "data") {
            data_dir.get_or_insert_with(|| first.to_string());
        } else if !first.is_empty() && name.contains('/') {
            // Only record root-level *directories* — bare files at
            // the archive root are unusual in wheels but not signal.
            top_level.insert(first.to_string());
        }

        // Per-name dist-info member checks. Match against any
        // `.dist-info/` prefix so a malformed wheel with multiple
        // dist-info dirs still surfaces the canonical-shape facts.
        if let Some((dir, rest)) = name.split_once('/')
            && dir.ends_with(".dist-info")
        {
            match rest {
                "METADATA" => has_metadata = true,
                "WHEEL" => has_wheel = true,
                "RECORD" => has_record = true,
                "RECORD.jws" => has_record_jws = true,
                "RECORD.p7s" => has_record_p7s = true,
                _ => {}
            }
        }

        // Native extensions — basename suffix match. `.pyd` is Windows,
        // `.so` is Linux (and POSIX more broadly), `.dylib` is macOS.
        // Wheels that ship native code carry these under the package
        // tree; pure-python wheels never do.
        let basename = name.rsplit('/').next().unwrap_or(name);
        // Case-insensitive: Windows loads `FOO.PYD` as readily as `foo.pyd`.
        if crate::bytes::ends_with_ci(basename, ".pyd")
            || crate::bytes::ends_with_ci(basename, ".so")
            || ends_with_so_versioned(basename)
            || crate::bytes::ends_with_ci(basename, ".dylib")
        {
            native_extension_count += 1;
        }
    }

    // Wheels without a dist-info directory aren't really wheels — bail
    // silently rather than emit empty `whl.*` keys.
    let Some(ref dist_info) = dist_info_dir else {
        return;
    };
    values.insert_key(
        value_key!("whl.dist_info_dir"),
        JsonValue::String(dist_info.clone()),
    );

    // Parse `{distribution}-{version}.dist-info/` → (distribution, version).
    // Wheel spec: the distribution name is a PEP 503-normalized identifier;
    // version is a PEP 440 version string. Both are non-empty.
    if let Some(stem) = dist_info.strip_suffix(".dist-info")
        && let Some((dist, ver)) = stem.rsplit_once('-')
        && !dist.is_empty()
        && !ver.is_empty()
    {
        values.insert_key(
            value_key!("whl.distribution"),
            JsonValue::String(dist.to_string()),
        );
        values.insert_key(
            value_key!("whl.version"),
            JsonValue::String(ver.to_string()),
        );
    }

    if has_metadata {
        values.insert_key(value_key!("whl.has_metadata"), JsonValue::Bool(true));
        // The dist-info `METADATA` is an RFC 822 header block (PEP 566).
        // Pull the authorship fields — the publisher identity a wheel
        // carries that the filename and dir name don't.
        let name = format!("{dist_info}/METADATA");
        match read_text_member(zip, &name, values) {
            Ok(Some(meta)) => emit_metadata_identity(&meta, values),
            // `has_metadata` can come from a second dist-info directory;
            // the chosen one having none is an absence, not a failure.
            Ok(None) => {}
            Err(failure) => failure.record(errors),
        }
    }
    for (present, key) in [
        (has_wheel, value_key!("whl.has_wheel")),
        (has_record, value_key!("whl.has_record")),
        (has_record_jws, value_key!("whl.signing.has_record_jws")),
        (has_record_p7s, value_key!("whl.signing.has_record_p7s")),
    ] {
        if present {
            values.insert_key(key, JsonValue::Bool(true));
        }
    }
    if let Some(d) = data_dir {
        values.insert_key(value_key!("whl.has_data_dir"), JsonValue::Bool(true));
        values.insert_key(value_key!("whl.data_dir"), JsonValue::String(d));
    }

    metrics.insert(
        metric!("whl.native_extension_count"),
        native_extension_count as f64,
    );
    if native_extension_count == 0 {
        values.insert_key(value_key!("whl.purelib_shape"), JsonValue::Bool(true));
    }

    if !top_level.is_empty() {
        let packages: Vec<JsonValue> = top_level.into_iter().map(JsonValue::String).collect();
        values.insert_key(
            value_key!("whl.top_level_packages"),
            JsonValue::Array(packages),
        );
    }
}

/// Parse a PEP 427 wheel filename and emit `whl.filename.*` facts.
///
/// Format: `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`
///
/// At minimum the filename must end in `.whl` and contain 5 or 6
/// hyphen-separated fields. Build tag is optional and is recognised
/// by digit-leading prefix per the spec.
///
/// The distribution name leaked here is the *outer claim* of identity.
/// Compare against `whl.distribution` (from the dist-info dir) and
/// `dist-info/METADATA::Name` (from the metadata blob) to flag
/// repackaging.
fn parse_wheel_filename(basename: &str, values: &mut Values) {
    let Some(stem) = basename.strip_suffix(".whl") else {
        return;
    };
    let parts: Vec<&str> = stem.split('-').collect();
    // 5 fields: name, version, python, abi, platform.
    // 6 fields: name, version, build, python, abi, platform.
    let (name, version, build, python, abi, platform) = match *parts.as_slice() {
        [name, version, python, abi, platform] => (name, version, None, python, abi, platform),
        [name, version, build, python, abi, platform] => {
            (name, version, Some(build), python, abi, platform)
        }
        _ => return,
    };
    if name.is_empty() || version.is_empty() {
        return;
    }
    for (key, value) in [
        (value_key!("whl.filename.name_prefix"), Some(name)),
        (value_key!("whl.filename.version"), Some(version)),
        (value_key!("whl.filename.build"), build),
        (value_key!("whl.filename.python_tag"), Some(python)),
        (value_key!("whl.filename.abi_tag"), Some(abi)),
        (value_key!("whl.filename.platform_tag"), Some(platform)),
    ] {
        if let Some(value) = value {
            values.insert_key(key, JsonValue::String(value.to_string()));
        }
    }
}

/// Linux shared libraries also appear as `libfoo.so.1`, `libfoo.so.1.2.3`.
/// Match those without false-flagging anything that merely contains
/// `.so` in its basename.
fn ends_with_so_versioned(basename: &str) -> bool {
    let mut chars = basename.rsplit(".so");
    let after_so = chars.next().unwrap_or("");
    // The suffix after `.so` must be empty (handled above) or only
    // digits and dots — `.1`, `.1.2.3`, etc.
    after_so
        .strip_prefix('.')
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
        && chars.next().is_some()
}

/// Read the Core Metadata member `name` as UTF-8 text, capped so a hostile
/// member can't balloon memory; `Ok(None)` when there is no such member.
/// Only the leading header block is used, so a member past the cap is read
/// as its first [`MAX_MANIFEST_BYTES`] bytes (to the last whole character),
/// with a `whl.limits` entry, rather than refused. Fails when the member
/// would not decompress, or is not UTF-8.
fn read_text_member<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
    values: &mut Values,
) -> Result<Option<String>, MemberFailure> {
    let prefix = match super::zip::read_member_prefix(zip, name, MAX_MANIFEST_BYTES) {
        Ok(Some(prefix)) => prefix,
        Ok(None) => return Ok(None),
        Err(e) => return Err(MemberFailure::new(Stage::ZipParse, name, e)),
    };
    if prefix.truncated {
        let mut limits = Limits::default();
        limits.push(
            "metadata",
            format!(
                "{name} over the {MAX_MANIFEST_BYTES}-byte cap; header block read from its prefix"
            ),
        );
        limits.emit(values, value_key!("whl.limits"));
    }
    super::bounded::utf8_prefix(prefix)
        .map(Some)
        .map_err(|e| MemberFailure::new(Stage::FormatExtract, format!("{name}: not UTF-8"), e))
}

/// Emit `whl.authors` / `whl.maintainers`, `whl.homepage` and the one-line
/// `whl.description` from a Core Metadata `METADATA` header block. Only the
/// first occurrence of each field is taken, and `UNKNOWN` placeholders are
/// skipped.
fn emit_metadata_identity(meta: &str, values: &mut Values) {
    let headers = super::core_metadata::CoreMetadata::parse(meta);
    super::core_metadata::emit_people(
        &headers,
        values,
        value_key!("whl.authors"),
        value_key!("whl.maintainers"),
        value_key!("whl.limits"),
    );
    for (field, key) in [
        ("home-page", value_key!("whl.homepage")),
        ("summary", value_key!("whl.description")),
    ] {
        if let Some(value) = headers.first(field).filter(|v| *v != "UNKNOWN") {
            values.insert_key(key, JsonValue::String(value.to_string()));
        }
    }
}

#[cfg(test)]
mod tests;
