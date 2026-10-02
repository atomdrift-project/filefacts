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

use super::bounded::MemberFailure;
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};

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
        .get_key(value_key!("file.basename"))
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

    for name in zip.file_names() {
        // Identify the dist-info / data directories from the first
        // component of any path under them. Multiple matches are
        // permitted in a malformed wheel; we keep the lexically first
        // (BTreeSet ordering keeps that deterministic). Layout names
        // match exactly, as installers match them.
        if let Some(first) = name.split('/').next() {
            if first.ends_with(".dist-info") && dist_info_dir.as_deref() != Some(first) {
                if dist_info_dir.is_none() {
                    dist_info_dir = Some(first.to_string());
                }
            } else if first.rsplit_once('.').is_some_and(|(_, ext)| ext == "data")
                && data_dir.as_deref() != Some(first)
            {
                if data_dir.is_none() {
                    data_dir = Some(first.to_string());
                }
            } else if !first.is_empty()
                && !first.ends_with(".dist-info")
                && first.rsplit_once('.').is_none_or(|(_, ext)| ext != "data")
            {
                // Only record root-level *directories* — bare files at
                // the archive root are unusual in wheels but not signal.
                if name.contains('/') {
                    top_level.insert(first.to_string());
                }
            }
        }

        // Per-name dist-info member checks. Match against any
        // `.dist-info/` prefix so a malformed wheel with multiple
        // dist-info dirs still surfaces the canonical-shape facts.
        if let Some((dir, rest)) = name.split_once('/') {
            if dir.ends_with(".dist-info") {
                match rest {
                    "METADATA" => has_metadata = true,
                    "WHEEL" => has_wheel = true,
                    "RECORD" => has_record = true,
                    "RECORD.jws" => has_record_jws = true,
                    "RECORD.p7s" => has_record_p7s = true,
                    _ => {}
                }
            }
        }

        // Native extensions — basename suffix match. `.pyd` is Windows,
        // `.so` is Linux (and POSIX more broadly), `.dylib` is macOS.
        // Wheels that ship native code carry these under the package
        // tree; pure-python wheels never do.
        let basename = name.rsplit('/').next().unwrap_or(name);
        // Case-insensitive: Windows loads `FOO.PYD` as readily as `foo.pyd`.
        if super::common::ends_with_ci(basename, ".pyd")
            || super::common::ends_with_ci(basename, ".so")
            || ends_with_so_versioned(basename)
            || super::common::ends_with_ci(basename, ".dylib")
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
    if let Some(stem) = dist_info.strip_suffix(".dist-info") {
        if let Some((dist, ver)) = stem.rsplit_once('-') {
            if !dist.is_empty() && !ver.is_empty() {
                values.insert_key(
                    value_key!("whl.distribution"),
                    JsonValue::String(dist.to_string()),
                );
                values.insert_key(
                    value_key!("whl.version"),
                    JsonValue::String(ver.to_string()),
                );
            }
        }
    }

    if has_metadata {
        values.insert_key(value_key!("whl.has_metadata"), JsonValue::Bool(true));
        // The dist-info `METADATA` is an RFC 822 header block (PEP 566).
        // Pull the authorship fields — the publisher identity a wheel
        // carries that the filename and dir name don't.
        let name = format!("{dist_info}/METADATA");
        match read_text_member(zip, &name) {
            Ok(Some(meta)) => emit_metadata_identity(&meta, values),
            // `has_metadata` can come from a second dist-info directory;
            // the chosen one having none is an absence, not a failure.
            Ok(None) => {}
            Err(failure) => failure.record(errors),
        }
    }
    if has_wheel {
        values.insert_key(value_key!("whl.has_wheel"), JsonValue::Bool(true));
    }
    if has_record {
        values.insert_key(value_key!("whl.has_record"), JsonValue::Bool(true));
    }
    if has_record_jws {
        values.insert_key(
            value_key!("whl.signing.has_record_jws"),
            JsonValue::Bool(true),
        );
    }
    if has_record_p7s {
        values.insert_key(
            value_key!("whl.signing.has_record_p7s"),
            JsonValue::Bool(true),
        );
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
    let stem = match basename.strip_suffix(".whl") {
        Some(s) => s,
        None => return,
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
    values.insert_key(
        value_key!("whl.filename.name_prefix"),
        JsonValue::String(name.to_string()),
    );
    values.insert_key(
        value_key!("whl.filename.version"),
        JsonValue::String(version.to_string()),
    );
    if let Some(b) = build {
        values.insert_key(
            value_key!("whl.filename.build"),
            JsonValue::String(b.to_string()),
        );
    }
    values.insert_key(
        value_key!("whl.filename.python_tag"),
        JsonValue::String(python.to_string()),
    );
    values.insert_key(
        value_key!("whl.filename.abi_tag"),
        JsonValue::String(abi.to_string()),
    );
    values.insert_key(
        value_key!("whl.filename.platform_tag"),
        JsonValue::String(platform.to_string()),
    );
}

/// Linux shared libraries also appear as `libfoo.so.1`, `libfoo.so.1.2.3`.
/// Match those without false-flagging anything that merely contains
/// `.so` in its basename.
fn ends_with_so_versioned(basename: &str) -> bool {
    let mut chars = basename.rsplit(".so");
    let after_so = chars.next().unwrap_or("");
    // The suffix after `.so` must be empty (handled above) or only
    // digits and dots — `.1`, `.1.2.3`, etc.
    !after_so.is_empty()
        && after_so.starts_with('.')
        && after_so[1..]
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
        && chars.next().is_some()
}

/// Read a zip member as UTF-8 text, capped so a hostile member can't
/// balloon memory; `Ok(None)` when there is no such member. Only the
/// leading header block is used, so a member past the cap is read as its
/// first `MAX` bytes (to the last whole character) rather than refused. Fails
/// when the member would not decompress, or is not UTF-8.
fn read_text_member<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
) -> Result<Option<String>, MemberFailure> {
    const MAX: u64 = 256 * 1024;
    let prefix = match super::zip::read_member_prefix(zip, name, MAX) {
        Ok(Some(prefix)) => prefix,
        Ok(None) => return Ok(None),
        Err(e) => return Err(MemberFailure::new(Stage::ZipParse, name, e)),
    };
    super::bounded::utf8_prefix(prefix)
        .map(Some)
        .map_err(|e| MemberFailure::new(Stage::FormatExtract, format!("{name}: not UTF-8"), e))
}

/// Emit `whl.author` / `whl.maintainer` (+ `_email`), `whl.homepage` and
/// the one-line `whl.summary` from an RFC 822 `METADATA` header block. Headers end at the first
/// blank line (the long `Description` body follows); only the first
/// occurrence of each field is taken, and `UNKNOWN` placeholders skipped.
fn emit_metadata_identity(meta: &str, values: &mut Values) {
    let put_first = |values: &mut Values, key: ValueKey, val: &str| {
        if !val.is_empty() && val != "UNKNOWN" && values.get_key(key).is_none() {
            values.insert_key(key, JsonValue::String(val.to_string()));
        }
    };
    for line in meta.lines() {
        if line.is_empty() {
            break;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field.trim().to_ascii_lowercase().as_str() {
            "author" => put_first(values, value_key!("whl.author"), value),
            "author-email" => put_first(values, value_key!("whl.author_email"), value),
            "maintainer" => put_first(values, value_key!("whl.maintainer"), value),
            "maintainer-email" => put_first(values, value_key!("whl.maintainer_email"), value),
            "home-page" => put_first(values, value_key!("whl.homepage"), value),
            "summary" => put_first(values, value_key!("whl.summary"), value),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
