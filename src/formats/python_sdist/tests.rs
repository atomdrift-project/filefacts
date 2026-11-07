use super::*;
use crate::output::Errors;
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
    let mut sinks = crate::formats::Sinks::default();
    extract(bytes, sinks.ctx()).unwrap();
    let (v, e) = (sinks.values, sinks.errors);
    (v, e)
}

/// The one recorded error's stage and kind.
fn only_error(errors: &Errors) -> (Stage, crate::DiagnosticKind) {
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
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
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
        (Stage::TarParse, crate::DiagnosticKind::Malformed)
    );
}

/// Past the cap, the header block is still read, even when the cut lands
/// inside a multi-byte character.
#[test]
fn oversized_pkg_info_is_read_up_to_the_cap() {
    for body_start in ["", "x"] {
        let mut meta = format!("Name: demo\nVersion: 1\n\n{body_start}").into_bytes();
        while meta.len() as u64 <= MAX_MANIFEST_BYTES {
            meta.extend_from_slice("\u{e9}".as_bytes());
        }
        let (v, e) = run(&tgz(&[("demo-1.0/PKG-INFO", &meta)]));
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(
            v.get("python.name").and_then(JsonValue::as_str),
            Some("demo")
        );
        assert_eq!(
            v.get("python.limits[0].stage").and_then(JsonValue::as_str),
            Some("pkg-info")
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
    emit(text, None, &mut values, &mut Metrics::new());
    assert_eq!(
        values.get("python.name").and_then(JsonValue::as_str),
        Some("requests")
    );
    assert_eq!(
        values.get("python.version").and_then(JsonValue::as_str),
        Some("2.31.0")
    );
    assert_eq!(
        values
            .get("python.authors[0].name")
            .and_then(JsonValue::as_str),
        Some("Kenneth Reitz")
    );
    assert_eq!(
        values
            .get("python.authors[0].email")
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
    emit(text, None, &mut values, &mut Metrics::new());
    assert_eq!(
        values
            .get("python.authors[0].name")
            .and_then(JsonValue::as_str),
        Some("Jane Doe")
    );
    assert_eq!(
        values
            .get("python.authors[0].email")
            .and_then(JsonValue::as_str),
        Some("jane@example.com")
    );
}

/// PEP 621 writes several authors as comma-separated lists; equal-length
/// name and email lists pair up, and `UNKNOWN` names nobody.
#[test]
fn comma_separated_authors_are_separate_people() {
    let mut values = Values::new();
    emit(
        "Name: x\nAuthor: Ada, Grace\nAuthor-email: ada@example.org, grace@example.org\nMaintainer: UNKNOWN\n",
        None,
        &mut values,
        &mut Metrics::new(),
    );
    assert_eq!(
        values.get("python.authors"),
        Some(&serde_json::json!([
            {"name": "Ada", "email": "ada@example.org"},
            {"name": "Grace", "email": "grace@example.org"},
        ]))
    );
    assert!(values.get("python.maintainers").is_none());

    let mut values = Values::new();
    emit(
        "Name: x\nAuthor-email: Ada <ada@example.org>, Grace <grace@example.org>\n",
        None,
        &mut values,
        &mut Metrics::new(),
    );
    assert_eq!(
        values.get("python.authors"),
        Some(&serde_json::json!([
            {"name": "Ada", "email": "ada@example.org"},
            {"name": "Grace", "email": "grace@example.org"},
        ]))
    );
}

/// The `requires.txt` setuptools writes counts toward the self-dependency
/// judgement, read in the same walk as `PKG-INFO`.
#[test]
fn requires_txt_counts_toward_the_self_dependency() {
    let bytes = tgz(&[
        (
            "my-pkg-1.0/PKG-INFO",
            b"Metadata-Version: 1.1\nName: my-pkg\nVersion: 1.0\n",
        ),
        (
            "my-pkg-1.0/my_pkg.egg-info/requires.txt",
            b"requests\nmy_pkg>=1.0\n",
        ),
    ]);
    let mut out = crate::formats::Sinks::default();
    extract(&bytes, out.ctx()).unwrap();
    assert_eq!(out.metrics.get("consistency.self_dependency"), Some(1.0));
    assert_eq!(out.metrics.get("consistency.name_typosquat"), Some(0.0));
}
