use super::*;

/// Run [`extract_pkgbuild`], asserting it records nothing.
fn pkgbuild(src: &[u8], values: &mut Values) {
    let mut errors = Errors::new();
    extract_pkgbuild(src, values, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn non_utf8_pkgbuild_records_one_error() {
    let mut v = Values::new();
    let mut errors = Errors::new();
    extract_pkgbuild(b"pkgname=foo\npkgdesc=\"caf\xe9\"\n", &mut v, &mut errors);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let e = &errors.as_slice()[0];
    assert_eq!(
        (e.stage, e.kind),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    assert!(v.get("pkg.pkgname").is_none());
}

fn pkg(values: &Values, path: &str) -> String {
    values
        .get(&format!("pkg.{path}"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

#[test]
fn pkgbuild_fields_and_checksum_digest() {
    let src = b"pkgname=foo\npkgver=1.2.3\npkgrel=1\nsource=('a.tar.gz::https://x/v$pkgver.tar.gz')\nsha256sums=('SKIP' 'deadbeef')\n";
    let mut v = Values::new();
    pkgbuild(src, &mut v);
    assert_eq!(pkg(&v, "pkgver"), "1.2.3");
    assert_eq!(pkg(&v, "pkgname"), "foo");
    // SKIP excluded; only the real hash drives the digest.
    assert_eq!(pkg(&v, "checksums"), "deadbeef");
    assert!(matches!(v.get("pkg.source"), Some(JsonValue::Array(_))));
}

#[test]
fn github_owner_extraction() {
    assert_eq!(
        github_owner("https://github.com/foo/bar"),
        Some("foo".into())
    );
    assert_eq!(
        github_owner("git+https://github.com/Foo/bar.git#tag=v1"),
        Some("foo".into())
    );
    assert_eq!(
        github_owner("https://github.com/o/r/releases/download/v1/x.tar.gz"),
        Some("o".into())
    );
    // Non-github and unresolved-variable owners aren't comparable.
    assert_eq!(github_owner("https://librewolf.net/x.tar.gz"), None);
    assert_eq!(github_owner("https://github.com/$_owner/r"), None);
}

#[test]
fn github_owner_projections() {
    // url owner and source owners are emitted as neutral facts; the trait
    // does the compare. Here url=foo but the source repo is attacker/payload.
    let src = b"pkgname=tool-bin\nurl=https://github.com/foo/tool\nsource=('https://github.com/attacker/payload/releases/download/v1/t.tar.gz')\nsha256sums=('SKIP')\n";
    let mut v = Values::new();
    pkgbuild(src, &mut v);
    assert_eq!(pkg(&v, "url_github_owner"), "foo");
    assert_eq!(
        v.get("pkg.source_github_owners"),
        Some(&JsonValue::Array(vec![JsonValue::String(
            "attacker".into()
        )]))
    );
}

#[test]
fn srcinfo_matches_pkgbuild_checksum() {
    let pb = b"pkgver=1.0\nsha256sums=('aa' 'bb')\n";
    let si = b"pkgbase = x\n\tpkgver = 1.0\n\tsha256sums = bb\n\tsha256sums = aa\n";
    let mut vp = Values::new();
    let mut vs = Values::new();
    pkgbuild(pb, &mut vp);
    extract_srcinfo(si, &mut vs).unwrap();
    // Sorted+deduped digest is order-independent → equal across both forms.
    assert_eq!(pkg(&vp, "checksums"), pkg(&vs, "checksums"));
    assert_eq!(pkg(&vp, "checksums"), "aa,bb");
}

/// A file naming a derived key, or a key that only shares a known field's
/// prefix, must not overwrite or feed the derived provenance facts.
#[test]
fn file_fields_cannot_overwrite_derived_facts() {
    let srcinfo = b"pkgbase = tool-bin\n\turl = https://github.com/foo/tool\n\turl_github_owner = attacker\n\tsource_github_owners = foo\n\tchecksums = forged\n\tsource = https://github.com/attacker/payload/t.tar.gz\n\tsha256sums = aa\n";
    let pkgbuild_src = b"pkgname=tool-bin\nurl=https://github.com/foo/tool\nurl_github_owner=attacker\nsource_github_owners=(foo)\nchecksums=forged\nsource=('https://github.com/attacker/payload/t.tar.gz')\nsha256sums=('aa')\n";
    let mut from_srcinfo = Values::new();
    extract_srcinfo(srcinfo, &mut from_srcinfo).unwrap();
    let mut from_pkgbuild = Values::new();
    pkgbuild(pkgbuild_src, &mut from_pkgbuild);
    for v in [&from_srcinfo, &from_pkgbuild] {
        assert_eq!(pkg(v, "url_github_owner"), "foo");
        assert_eq!(
            v.get("pkg.source_github_owners"),
            Some(&JsonValue::Array(vec![JsonValue::String(
                "attacker".into()
            )]))
        );
        assert_eq!(pkg(v, "checksums"), "aa");
    }
}

/// A key becomes a path segment; a dot in it must not nest the value.
#[test]
fn dotted_keys_are_not_fields() {
    let si = b"pkgbase = foo\n\tsource_x.y = https://example.com/a\n\tpkgver.x = 1\n";
    let mut v = Values::new();
    extract_srcinfo(si, &mut v).unwrap();
    assert!(v.get("pkg.source_x").is_none());
    assert!(v.get("pkg.pkgver").is_none());
    assert_eq!(pkg(&v, "pkgbase"), "foo");
}

#[test]
fn architecture_suffixed_arrays_are_still_fields() {
    let si = b"pkgbase = foo\n\tsource_x86_64 = https://example.com/a\n\tsha256sums_x86_64 = bb\n";
    let mut v = Values::new();
    extract_srcinfo(si, &mut v).unwrap();
    assert!(matches!(
        v.get("pkg.source_x86_64"),
        Some(JsonValue::Array(_))
    ));
    assert_eq!(pkg(&v, "checksums"), "bb");
}

#[test]
fn srcinfo_multiline_arrays() {
    let si = b"pkgbase = foo\n\tsource = one\n\tsource = two\n";
    let mut v = Values::new();
    extract_srcinfo(si, &mut v).unwrap();
    match v.get("pkg.source") {
        Some(JsonValue::Array(a)) => assert_eq!(a.len(), 2),
        other => panic!("expected array, got {other:?}"),
    }
}
