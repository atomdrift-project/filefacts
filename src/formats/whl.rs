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

use serde_json::Value as JsonValue;
use std::io::{Read, Seek};

use crate::error::Error;
use crate::output::{Metrics, Values};

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    // Parse the outer wheel filename (set by lib.rs from open_with_path)
    // for PEP 427 components. The name_prefix here is the *outer*
    // claim of identity, distinct from `whl.distribution` parsed from
    // the dist-info directory inside the archive. When they disagree,
    // it's an impersonation/repack signal.
    if let Some(basename) = values
        .get("file.basename")
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
        // (BTreeSet ordering keeps that deterministic).
        if let Some(first) = name.split('/').next() {
            if first.ends_with(".dist-info") && dist_info_dir.as_deref() != Some(first) {
                if dist_info_dir.is_none() {
                    dist_info_dir = Some(first.to_string());
                }
            } else if first.ends_with(".data") && data_dir.as_deref() != Some(first) {
                if data_dir.is_none() {
                    data_dir = Some(first.to_string());
                }
            } else if !first.is_empty()
                && !first.ends_with(".dist-info")
                && !first.ends_with(".data")
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
        if basename.ends_with(".pyd")
            || basename.ends_with(".so")
            || ends_with_so_versioned(basename)
            || basename.ends_with(".dylib")
        {
            native_extension_count += 1;
        }
    }

    // Wheels without a dist-info directory aren't really wheels — bail
    // silently rather than emit empty `whl.*` keys.
    let Some(ref dist_info) = dist_info_dir else {
        return Ok(());
    };
    values.insert("whl.dist_info_dir", JsonValue::String(dist_info.clone()));

    // Parse `{distribution}-{version}.dist-info/` → (distribution, version).
    // Wheel spec: the distribution name is a PEP 503-normalized identifier;
    // version is a PEP 440 version string. Both are non-empty.
    if let Some(stem) = dist_info.strip_suffix(".dist-info") {
        if let Some((dist, ver)) = stem.rsplit_once('-') {
            if !dist.is_empty() && !ver.is_empty() {
                values.insert("whl.distribution", JsonValue::String(dist.to_string()));
                values.insert("whl.version", JsonValue::String(ver.to_string()));
            }
        }
    }

    if has_metadata {
        values.insert("whl.has_metadata", JsonValue::Bool(true));
        // The dist-info `METADATA` is an RFC 822 header block (PEP 566).
        // Pull the authorship fields — the publisher identity a wheel
        // carries that the filename and dir name don't.
        if let Some(meta) = read_text_member(zip, &format!("{dist_info}/METADATA")) {
            emit_metadata_authors(&meta, values);
        }
    }
    if has_wheel {
        values.insert("whl.has_wheel", JsonValue::Bool(true));
    }
    if has_record {
        values.insert("whl.has_record", JsonValue::Bool(true));
    }
    if has_record_jws {
        values.insert("whl.signing.has_record_jws", JsonValue::Bool(true));
    }
    if has_record_p7s {
        values.insert("whl.signing.has_record_p7s", JsonValue::Bool(true));
    }
    if let Some(d) = data_dir {
        values.insert("whl.has_data_dir", JsonValue::Bool(true));
        values.insert("whl.data_dir", JsonValue::String(d));
    }

    metrics.insert("whl.native_extension_count", native_extension_count as f64);
    if native_extension_count == 0 {
        values.insert("whl.purelib_shape", JsonValue::Bool(true));
    }

    if !top_level.is_empty() {
        let packages: Vec<JsonValue> = top_level.into_iter().map(JsonValue::String).collect();
        values.insert("whl.top_level_packages", JsonValue::Array(packages));
    }

    Ok(())
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
    let (name, version, build, python, abi, platform) = match parts.len() {
        5 => (parts[0], parts[1], None, parts[2], parts[3], parts[4]),
        6 => (
            parts[0],
            parts[1],
            Some(parts[2]),
            parts[3],
            parts[4],
            parts[5],
        ),
        _ => return,
    };
    if name.is_empty() || version.is_empty() {
        return;
    }
    values.insert(
        "whl.filename.name_prefix",
        JsonValue::String(name.to_string()),
    );
    values.insert(
        "whl.filename.version",
        JsonValue::String(version.to_string()),
    );
    if let Some(b) = build {
        values.insert("whl.filename.build", JsonValue::String(b.to_string()));
    }
    values.insert(
        "whl.filename.python_tag",
        JsonValue::String(python.to_string()),
    );
    values.insert("whl.filename.abi_tag", JsonValue::String(abi.to_string()));
    values.insert(
        "whl.filename.platform_tag",
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
/// balloon memory. Returns `None` on any failure.
fn read_text_member<R: Read + Seek>(zip: &mut ::zip::ZipArchive<R>, name: &str) -> Option<String> {
    const MAX: u64 = 256 * 1024;
    let member = zip.by_name(name).ok()?;
    let mut buf = Vec::new();
    member.take(MAX).read_to_end(&mut buf).ok()?;
    String::from_utf8(buf).ok()
}

/// Emit `whl.author` / `whl.maintainer` (+ `_email`) and `whl.home_page`
/// from an RFC 822 `METADATA` header block. Headers end at the first
/// blank line (the long `Description` body follows); only the first
/// occurrence of each field is taken, and `UNKNOWN` placeholders skipped.
fn emit_metadata_authors(meta: &str, values: &mut Values) {
    let put_first = |values: &mut Values, key: &str, val: &str| {
        if !val.is_empty() && val != "UNKNOWN" && values.get(key).is_none() {
            values.insert(key, JsonValue::String(val.to_string()));
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
            "author" => put_first(values, "whl.author", value),
            "author-email" => put_first(values, "whl.author_email", value),
            "maintainer" => put_first(values, "whl.maintainer", value),
            "maintainer-email" => put_first(values, "whl.maintainer_email", value),
            "home-page" => put_first(values, "whl.home_page", value),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    fn build_whl(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = ::zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for (name, body) in entries {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(body).unwrap();
            }
            zip.finish().unwrap();
        }
        buf
    }

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        if let Ok(mut zip) = crate::formats::zip::open_archive(bytes) {
            extract_from_archive(&mut zip, &mut v, &mut m).unwrap();
        }
        (v, m)
    }

    #[test]
    fn metadata_author_fields_are_extracted() {
        let whl = build_whl(&[
            ("mypkg/__init__.py", b""),
            (
                "mypkg-1.0.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0.0\nAuthor: trtkajko\nAuthor-email: <mail@mail.com>\nHome-page: https://example.test\n\nLong description body\n",
            ),
            ("mypkg-1.0.0.dist-info/RECORD", b"mypkg/__init__.py,,0\n"),
        ]);
        let (v, _) = run(&whl);
        assert_eq!(
            v.get("whl.author").and_then(|x| x.as_str()),
            Some("trtkajko")
        );
        assert_eq!(
            v.get("whl.author_email").and_then(|x| x.as_str()),
            Some("<mail@mail.com>")
        );
        assert_eq!(
            v.get("whl.home_page").and_then(|x| x.as_str()),
            Some("https://example.test")
        );
    }

    #[test]
    fn pure_python_wheel_emits_purelib_shape() {
        let whl = build_whl(&[
            ("mypkg/__init__.py", b""),
            ("mypkg/core.py", b"x = 1\n"),
            ("mypkg-1.0.0.dist-info/METADATA", b"Name: mypkg\n"),
            ("mypkg-1.0.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("mypkg-1.0.0.dist-info/RECORD", b"mypkg/__init__.py,,0\n"),
        ]);
        let (v, m) = run(&whl);
        assert_eq!(
            v.get("whl.distribution").and_then(|x| x.as_str()),
            Some("mypkg")
        );
        assert_eq!(v.get("whl.version").and_then(|x| x.as_str()), Some("1.0.0"));
        assert_eq!(
            v.get("whl.dist_info_dir").and_then(|x| x.as_str()),
            Some("mypkg-1.0.0.dist-info")
        );
        assert_eq!(
            v.get("whl.has_metadata").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert_eq!(v.get("whl.has_wheel").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(
            v.get("whl.has_record").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert_eq!(
            v.get("whl.purelib_shape").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert_eq!(m.get("whl.native_extension_count"), Some(0.0));
        let packages = v
            .get("whl.top_level_packages")
            .and_then(|x| x.as_array())
            .unwrap();
        let names: Vec<&str> = packages.iter().filter_map(|x| x.as_str()).collect();
        assert_eq!(names, vec!["mypkg"]);
    }

    #[test]
    fn native_extensions_counted_across_platforms() {
        let whl = build_whl(&[
            ("mypkg/__init__.py", b""),
            ("mypkg/_native.pyd", b"MZ"),
            ("mypkg/_core.cpython-310.so", b"\x7fELF"),
            ("mypkg/_thing.dylib", b"\xfe\xed\xfa\xce"),
            ("mypkg/libhelper.so.1.2", b"\x7fELF"),
            ("mypkg-1.0.0.dist-info/METADATA", b"Name: mypkg\n"),
            ("mypkg-1.0.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("mypkg-1.0.0.dist-info/RECORD", b""),
        ]);
        let (v, m) = run(&whl);
        assert_eq!(m.get("whl.native_extension_count"), Some(4.0));
        // Non-zero native ext count → no purelib_shape flag.
        assert!(v.get("whl.purelib_shape").is_none());
    }

    #[test]
    fn ends_with_so_versioned_distinguishes_real_libs() {
        // True for typical Linux shared-library versioning.
        assert!(ends_with_so_versioned("libfoo.so.1"));
        assert!(ends_with_so_versioned("libfoo.so.1.2"));
        assert!(ends_with_so_versioned("libfoo.so.1.2.3"));
        // False for things that just *contain* `.so` in their basename.
        assert!(!ends_with_so_versioned("not_a_so"));
        assert!(!ends_with_so_versioned("README.so.txt"));
        // The bare `.so` case is handled by the basic suffix check
        // upstream; the versioned helper rejects empty-after-dot.
        assert!(!ends_with_so_versioned("libfoo.so"));
    }

    #[test]
    fn record_jws_signing_artifact_detected() {
        let whl = build_whl(&[
            ("mypkg/__init__.py", b""),
            ("mypkg-1.0.0.dist-info/METADATA", b"Name: mypkg\n"),
            ("mypkg-1.0.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("mypkg-1.0.0.dist-info/RECORD", b""),
            ("mypkg-1.0.0.dist-info/RECORD.jws", b"{\"sig\":\"...\"}"),
        ]);
        let (v, _) = run(&whl);
        assert_eq!(
            v.get("whl.signing.has_record_jws")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
        assert!(v.get("whl.signing.has_record_p7s").is_none());
    }

    #[test]
    fn data_dir_detected() {
        let whl = build_whl(&[
            ("mypkg/__init__.py", b""),
            ("mypkg-1.0.0.data/scripts/hello", b"#!/bin/sh\necho hi\n"),
            ("mypkg-1.0.0.dist-info/METADATA", b"Name: mypkg\n"),
            ("mypkg-1.0.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("mypkg-1.0.0.dist-info/RECORD", b""),
        ]);
        let (v, _) = run(&whl);
        assert_eq!(
            v.get("whl.has_data_dir").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert_eq!(
            v.get("whl.data_dir").and_then(|x| x.as_str()),
            Some("mypkg-1.0.0.data")
        );
    }

    #[test]
    fn multi_top_level_packages_listed() {
        let whl = build_whl(&[
            ("first_pkg/__init__.py", b""),
            ("second_pkg/__init__.py", b""),
            ("first_pkg/inner.py", b""),
            ("combined-2.0.dist-info/METADATA", b""),
            ("combined-2.0.dist-info/WHEEL", b""),
            ("combined-2.0.dist-info/RECORD", b""),
        ]);
        let (v, _) = run(&whl);
        let packages = v
            .get("whl.top_level_packages")
            .and_then(|x| x.as_array())
            .unwrap();
        let names: Vec<&str> = packages.iter().filter_map(|x| x.as_str()).collect();
        assert_eq!(names, vec!["first_pkg", "second_pkg"]);
    }

    #[test]
    fn no_dist_info_dir_short_circuits() {
        // ZIP that's structurally not a wheel — we emit nothing in the
        // `whl.*` namespace so consumers don't get phantom facts.
        let whl = build_whl(&[("just/some/file.txt", b"hello")]);
        let (v, m) = run(&whl);
        assert!(v.get("whl.distribution").is_none());
        assert!(v.get("whl.dist_info_dir").is_none());
        assert!(m.get("whl.native_extension_count").is_none());
    }

    #[test]
    fn dist_info_name_without_version_is_ignored_for_parse() {
        // Malformed dist-info dir name — no version field. We still
        // record the dir but skip the distribution/version split.
        let whl = build_whl(&[
            ("broken.dist-info/METADATA", b""),
            ("broken.dist-info/WHEEL", b""),
        ]);
        let (v, _) = run(&whl);
        assert_eq!(
            v.get("whl.dist_info_dir").and_then(|x| x.as_str()),
            Some("broken.dist-info")
        );
        assert!(v.get("whl.distribution").is_none());
        assert!(v.get("whl.version").is_none());
    }

    #[test]
    fn missing_canonical_members_emits_no_has_flags() {
        // A dist-info dir with no METADATA/WHEEL/RECORD — wheel-shape
        // detection still triggers (dir present), but the has_* flags
        // stay off so the caller can tell a stripped wheel from a
        // valid one.
        let whl = build_whl(&[("mypkg-1.0.dist-info/LICENSE", b"MIT\n")]);
        let (v, _) = run(&whl);
        assert_eq!(
            v.get("whl.dist_info_dir").and_then(|x| x.as_str()),
            Some("mypkg-1.0.dist-info")
        );
        assert!(v.get("whl.has_metadata").is_none());
        assert!(v.get("whl.has_wheel").is_none());
        assert!(v.get("whl.has_record").is_none());
    }

    #[test]
    fn non_zip_input_is_silent() {
        let (v, _) = run(b"not a zip");
        assert!(v.get("whl.dist_info_dir").is_none());
    }

    /// Drive `parse_wheel_filename` directly; isolated from ZIP/dist-info
    /// concerns. Returns the populated `whl.filename.*` facts as a map.
    fn parse_only(basename: &str) -> Values {
        let mut v = Values::new();
        super::parse_wheel_filename(basename, &mut v);
        v
    }

    fn fstr(v: &Values, key: &str) -> Option<String> {
        v.get(key).and_then(|x| x.as_str()).map(str::to_string)
    }

    #[test]
    fn wheel_filename_basic_five_fields() {
        let v = parse_only("mempalace_dashboard-0.5.0-py3-none-any.whl");
        assert_eq!(
            fstr(&v, "whl.filename.name_prefix").as_deref(),
            Some("mempalace_dashboard")
        );
        assert_eq!(fstr(&v, "whl.filename.version").as_deref(), Some("0.5.0"));
        assert_eq!(fstr(&v, "whl.filename.python_tag").as_deref(), Some("py3"));
        assert_eq!(fstr(&v, "whl.filename.abi_tag").as_deref(), Some("none"));
        assert_eq!(
            fstr(&v, "whl.filename.platform_tag").as_deref(),
            Some("any")
        );
        // No build tag in this filename — fact should be absent.
        assert!(v.get("whl.filename.build").is_none());
    }

    #[test]
    fn wheel_filename_with_build_tag() {
        let v = parse_only("foo-1.0-1-py3-none-any.whl");
        assert_eq!(fstr(&v, "whl.filename.name_prefix").as_deref(), Some("foo"));
        assert_eq!(fstr(&v, "whl.filename.version").as_deref(), Some("1.0"));
        assert_eq!(fstr(&v, "whl.filename.build").as_deref(), Some("1"));
        assert_eq!(fstr(&v, "whl.filename.python_tag").as_deref(), Some("py3"));
    }

    #[test]
    fn wheel_filename_pep440_post_dev_version() {
        // mixinv2-0.4.0.post45.dev0-py3-none-any.whl — version contains
        // dots but is still a single hyphen-separated field.
        let v = parse_only("mixinv2-0.4.0.post45.dev0-py3-none-any.whl");
        assert_eq!(
            fstr(&v, "whl.filename.name_prefix").as_deref(),
            Some("mixinv2")
        );
        assert_eq!(
            fstr(&v, "whl.filename.version").as_deref(),
            Some("0.4.0.post45.dev0")
        );
    }

    #[test]
    fn wheel_filename_rejects_non_whl_extension() {
        let v = parse_only("mempalace_dashboard-0.5.0-py3-none-any.zip");
        assert!(v.get("whl.filename.name_prefix").is_none());
    }

    #[test]
    fn wheel_filename_rejects_too_few_fields() {
        // Looks like a wheel suffix but missing platform tag.
        let v = parse_only("foo-1.0-py3-none.whl");
        assert!(v.get("whl.filename.name_prefix").is_none());
    }

    #[test]
    fn wheel_filename_rejects_too_many_fields() {
        let v = parse_only("a-b-c-d-e-f-g.whl");
        assert!(v.get("whl.filename.name_prefix").is_none());
    }

    #[test]
    fn wheel_filename_rejects_empty_name_or_version() {
        let v = parse_only("-1.0-py3-none-any.whl");
        assert!(v.get("whl.filename.name_prefix").is_none());
        let v = parse_only("foo--py3-none-any.whl");
        assert!(v.get("whl.filename.name_prefix").is_none());
    }

    /// End-to-end: when a wheel is opened with a path the outer-filename
    /// facts get parsed *before* the inner dist-info extraction runs,
    /// so the disagreement between outer claim (`whl.filename.name_prefix`)
    /// and inner claim (`whl.distribution`) is visible to traits.
    #[test]
    fn outer_filename_facts_disagree_with_inner_dist_info() {
        let whl = build_whl(&[
            ("realpkg/__init__.py", b""),
            ("realpkg-1.0.0.dist-info/METADATA", b"Name: realpkg\n"),
            ("realpkg-1.0.0.dist-info/WHEEL", b""),
            ("realpkg-1.0.0.dist-info/RECORD", b""),
        ]);
        // Pretend an attacker renamed the wheel to claim a different identity.
        let parsed = crate::open_with_path(
            std::path::Path::new("/tmp/fake_name-1.0.0-py3-none-any.whl"),
            &whl,
        )
        .unwrap();
        let v = parsed.values();
        assert_eq!(
            v.get("whl.filename.name_prefix").and_then(|x| x.as_str()),
            Some("fake_name")
        );
        assert_eq!(
            v.get("whl.distribution").and_then(|x| x.as_str()),
            Some("realpkg")
        );
    }
}
