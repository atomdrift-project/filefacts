use super::*;
use crate::formats::testutil::stored_zip;
use std::io::Cursor;

fn run(bytes: &[u8]) -> (Values, Errors) {
    let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut v = Values::new();
    let mut e = Errors::new();
    extract_from_archive(&mut zip, &mut v, &mut Metrics::new(), &mut e);
    (v, e)
}

#[test]
fn nuspec_that_is_not_xml_records_one_error() {
    let (v, e) = run(&stored_zip(&[("Acme.nuspec", b"<package><metadata>")]));
    assert_eq!(e.len(), 1, "{e:?}");
    let err = &e.as_slice()[0];
    assert_eq!(
        (err.stage, err.kind),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    assert!(err.message.starts_with("Acme.nuspec:"), "{}", err.message);
    assert!(v.get("nupkg.limits").is_none());
}

#[test]
fn well_formed_or_absent_nuspec_records_nothing() {
    let (v, e) = run(&stored_zip(&[(
        "Acme.nuspec",
        b"<package><metadata><id>Acme</id></metadata></package>",
    )]));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(v.get("nupkg.name").and_then(|x| x.as_str()), Some("Acme"));
    let (_, e) = run(&stored_zip(&[("lib/a.dll", b"MZ")]));
    assert!(e.is_empty(), "{e:?}");
}

#[test]
fn oversized_nuspec_is_a_limit_not_an_error() {
    let big = vec![b' '; MAX_NUSPEC as usize + 1];
    let (v, e) = run(&stored_zip(&[("Acme.nuspec", &big)]));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("nupkg.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits[0]["stage"], "nuspec");
}

#[test]
fn nuspec_identity_fields_extracted() {
    let xml = r#"<?xml version="1.0"?>
            <package><metadata>
                <id>Acme.Widgets</id>
                <version>1.2.3</version>
                <authors>Acme Corp</authors>
                <owners>Acme Corp</owners>
                <projectUrl>https://acme.test</projectUrl>
                <description>Widgets for .NET</description>
            </metadata></package>"#;
    let mut v = Values::new();
    parse_nuspec(xml, &mut v).unwrap();
    assert_eq!(
        v.get("nupkg.description").and_then(|x| x.as_str()),
        Some("Widgets for .NET")
    );
    assert_eq!(
        v.get("nupkg.name").and_then(|x| x.as_str()),
        Some("Acme.Widgets")
    );
    assert_eq!(
        v.get("nupkg.authors"),
        Some(&serde_json::json!([{"name": "Acme Corp"}]))
    );
    assert_eq!(
        v.get("nupkg.homepage").and_then(|x| x.as_str()),
        Some("https://acme.test")
    );
}
