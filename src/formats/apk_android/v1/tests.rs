use super::*;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

const BOUND_MF: &[u8] = include_bytes!("../../../../tests/fixtures/apk/BOUND.MF");
const BOUND_SF: &[u8] = include_bytes!("../../../../tests/fixtures/apk/BOUND.SF");

fn archive(members: &[(&str, &[u8])]) -> ::zip::ZipArchive<Cursor<Vec<u8>>> {
    let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, body) in members {
        w.start_file(*name, SimpleFileOptions::default()).unwrap();
        w.write_all(body).unwrap();
    }
    ::zip::ZipArchive::new(Cursor::new(w.finish().unwrap().into_inner())).unwrap()
}

fn bound(budget: u64) -> Binding {
    let mut zip = archive(&[
        ("AndroidManifest.xml", b"not axml"),
        ("classes.dex", b"dex\n035\0"),
        ("META-INF/MANIFEST.MF", BOUND_MF),
    ]);
    Verifier::new(budget).bind(&mut zip, BOUND_SF)
}

#[test]
fn a_signature_file_over_its_manifest_and_members_is_bound() {
    assert_eq!(bound(MAX_HASHED_BYTES), Binding::Bound);
}

/// Hashing stops at the budget, and a check it stops is unverifiable,
/// never bound.
#[test]
fn a_spent_hash_budget_is_unverifiable() {
    // The whole manifest digest alone costs its length.
    assert_eq!(
        bound(BOUND_MF.len() as u64 - 1),
        Binding::Unverifiable("hash budget spent")
    );
    // Enough for the manifest, not for both members.
    assert_eq!(
        bound(BOUND_MF.len() as u64 + 8),
        Binding::Unverifiable("hash budget spent")
    );
    assert_eq!(bound(BOUND_MF.len() as u64 + 16), Binding::Bound);
}

/// Sections end at a blank line, which their digest covers; continuation
/// lines join their value; CR LF, LF and CR all end a line.
#[test]
fn manifest_sections_split_as_jar_tools_write_them() {
    let text = b"Manifest-Version: 1.0\r\n\r\nName: a/very/long/na\r\n me.txt\r\nSHA-256-Digest: x\r\n\r\n\nName: b\nSHA1-Digest: y\r";
    let parsed = sections(text).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        &text[parsed[0].raw.clone()],
        b"Manifest-Version: 1.0\r\n\r\n"
    );
    assert_eq!(parsed[1].name(), Some(&b"a/very/long/name.txt"[..]));
    assert!(text[parsed[1].raw.clone()].ends_with(b"x\r\n\r\n"));
    assert_eq!(parsed[2].name(), Some(&b"b"[..]));
    assert_eq!(&text[parsed[2].raw.clone()], b"Name: b\nSHA1-Digest: y\r");
    // A line that is no attribute, and a continuation of nothing.
    assert!(sections(b"Name: a\r\nnot an attribute\r\n").is_none());
    assert!(sections(b" continued\r\n").is_none());
}

/// Every algorithm a section names must match; one that does not, or a
/// section naming only algorithms Android does not check, binds nothing.
#[test]
fn every_named_digest_must_match() {
    let sha256 = STANDARD.encode(Sha256::digest(b"data"));
    let sha1 = STANDARD.encode(Sha1::digest(b"data"));
    let wrong = STANDARD.encode(Sha1::digest(b"other"));
    let section = |attrs: &str| sections(attrs.as_bytes()).unwrap().remove(0);
    let verdict = |attrs: String| {
        matches!(
            check(&section(&attrs), "-Digest", b"data", &mut u64::MAX.clone()),
            Check::Match
        )
    };
    assert!(verdict(format!("SHA-256-Digest: {sha256}\r\n")));
    assert!(verdict(format!(
        "SHA1-Digest: {sha1}\r\nSHA-256-Digest: {sha256}\r\n"
    )));
    assert!(!verdict(format!(
        "SHA1-Digest: {wrong}\r\nSHA-256-Digest: {sha256}\r\n"
    )));
    assert!(!verdict(format!(
        "SHA-256-Digest: {sha256}\r\nSHA-256-Digest: {wrong}\r\n"
    )));
    assert!(matches!(
        check(
            &section("MD5-Digest: x\r\n"),
            "-Digest",
            b"data",
            &mut u64::MAX.clone()
        ),
        Check::Absent
    ));
}

#[test]
fn signing_files_need_no_digest() {
    for name in [
        "META-INF/MANIFEST.MF",
        "META-INF/CERT.SF",
        "META-INF/cert.rsa",
        "META-INF/A.EC",
        "META-INF/SIG-X",
        "res/",
    ] {
        assert!(!needs_digest(name), "{name}");
    }
    for name in [
        "classes.dex",
        "META-INF/services/x",
        "META-INF/a.kotlin_module",
        "meta-inf/CERT.SF",
    ] {
        assert!(needs_digest(name), "{name}");
    }
}
