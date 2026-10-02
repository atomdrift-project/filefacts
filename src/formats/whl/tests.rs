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
    let (v, m, e) = run_with_errors(bytes);
    assert!(e.is_empty(), "{e:?}");
    (v, m)
}

fn run_with_errors(bytes: &[u8]) -> (Values, Metrics, Errors) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut e = Errors::new();
    if let Ok(mut zip) = crate::formats::zip::open_archive(bytes) {
        extract_from_archive(&mut zip, &mut v, &mut m, &mut e).unwrap();
    }
    (v, m, e)
}

#[test]
fn metadata_that_is_not_utf8_records_one_error() {
    let whl = build_whl(&[
        ("mypkg/__init__.py", b""),
        (
            "mypkg-1.0.0.dist-info/METADATA",
            b"Name: mypkg\nAuthor: Jos\xe9\n",
        ),
    ]);
    let (v, _, e) = run_with_errors(&whl);
    assert_eq!(e.len(), 1, "{e:?}");
    let err = &e.as_slice()[0];
    assert_eq!(
        (err.stage, err.kind),
        (Stage::FormatExtract, crate::ErrorKind::Malformed)
    );
    assert!(
        err.message
            .starts_with("mypkg-1.0.0.dist-info/METADATA: not UTF-8"),
        "{}",
        err.message
    );
    assert!(v.get("whl.author").is_none());
    // The central-directory facts are unaffected.
    assert_eq!(
        v.get("whl.has_metadata").and_then(|x| x.as_bool()),
        Some(true)
    );
}

/// `METADATA` under a second dist-info directory only: the chosen one
/// has none, which is an absence, not a read failure.
#[test]
fn metadata_absent_from_the_chosen_dist_info_records_nothing() {
    let whl = build_whl(&[
        ("a-1.0.dist-info/RECORD", b""),
        ("b-1.0.dist-info/METADATA", b"Name: b\n"),
    ]);
    let (v, _) = run(&whl);
    assert_eq!(
        v.get("whl.dist_info_dir").and_then(|x| x.as_str()),
        Some("a-1.0.dist-info")
    );
    assert!(v.get("whl.author").is_none());
}

/// Past the cap, the header block is still read, even when the cut lands
/// inside a multi-byte character.
#[test]
fn oversized_metadata_is_read_up_to_the_cap() {
    // An even-length header block puts the cap between two-byte
    // characters; one more body byte puts it inside one.
    for body_start in ["", "x"] {
        let mut meta = format!("Name: mypkg\nAuthor: Jane\n\n{body_start}").into_bytes();
        while meta.len() <= 256 * 1024 {
            meta.extend_from_slice("\u{e9}".as_bytes());
        }
        let whl = build_whl(&[("mypkg-1.0.0.dist-info/METADATA", &meta)]);
        let (v, _) = run(&whl);
        assert_eq!(v.get("whl.author").and_then(|x| x.as_str()), Some("Jane"));
    }
}

#[test]
fn metadata_author_fields_are_extracted() {
    let whl = build_whl(&[
        ("mypkg/__init__.py", b""),
        (
            "mypkg-1.0.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0.0\nSummary: A tiny package\nAuthor: trtkajko\nAuthor-email: <mail@mail.com>\nHome-page: https://example.test\n\nLong description body\n",
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
        v.get("whl.homepage").and_then(|x| x.as_str()),
        Some("https://example.test")
    );
    assert_eq!(
        v.get("whl.summary").and_then(|x| x.as_str()),
        Some("A tiny package")
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
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new(
            "/tmp/fake_name-1.0.0-py3-none-any.whl",
        ))
        .open(&whl);
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
