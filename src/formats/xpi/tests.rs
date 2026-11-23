use super::*;
use crate::formats::testutil::stored_zip;
use crate::output::Stage;

fn run(bytes: &[u8]) -> Values {
    let (v, e) = run_with_errors(bytes);
    assert!(e.is_empty(), "{e:?}");
    v
}

fn run_with_errors(bytes: &[u8]) -> (Values, Errors) {
    let mut v = Values::new();
    let mut e = Errors::new();
    if let Some(mut zip) = crate::formats::testutil::open_zip(bytes) {
        extract_from_archive(&mut zip, &mut v, &mut e);
    }
    (v, e)
}

#[test]
fn manifest_that_is_not_json_records_one_error() {
    let (v, e) = run_with_errors(&stored_zip(&[("manifest.json", b"{\"name\": ")]));
    assert_eq!(e.len(), 1, "{e:?}");
    let err = &e.as_slice()[0];
    assert_eq!(
        (err.stage, err.kind),
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    assert!(err.message.starts_with("manifest.json:"), "{}", err.message);
    // The filename-shape facts still stand.
    assert_eq!(
        v.get("xpi.has_web_extension_manifest")
            .and_then(|x| x.as_bool()),
        Some(true)
    );
    assert!(v.get("xpi.limits").is_none());
}

#[test]
fn oversized_manifest_is_a_limit_not_an_error() {
    let mut big = b"{\"description\": \"".to_vec();
    big.resize(600 * 1024, b'a');
    big.extend_from_slice(b"\"}");
    let (v, e) = run_with_errors(&stored_zip(&[("manifest.json", &big)]));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("xpi.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits[0]["stage"], "manifest");
}

#[test]
fn pkcs7_signing_scheme_detected() {
    let xpi = stored_zip(&[
        ("manifest.json", b"{}"),
        ("META-INF/mozilla.sf", b"sf"),
        ("META-INF/mozilla.rsa", b"rsa"),
    ]);
    let v = run(&xpi);
    let schemes = v
        .get("xpi.signing.schemes")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = schemes.iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(names, vec!["pkcs7"]);
    assert!(v.get("xpi.unsigned_shape").is_none());
}

#[test]
fn cose_signing_scheme_detected() {
    let xpi = stored_zip(&[
        ("manifest.json", b"{}"),
        ("META-INF/cose.manifest", b"m"),
        ("META-INF/cose.sig", b"s"),
    ]);
    let v = run(&xpi);
    let schemes = v
        .get("xpi.signing.schemes")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = schemes.iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(names, vec!["cose"]);
}

#[test]
fn dual_signing_lists_both_schemes() {
    let xpi = stored_zip(&[
        ("manifest.json", b"{}"),
        ("META-INF/mozilla.sf", b"sf"),
        ("META-INF/mozilla.rsa", b"rsa"),
        ("META-INF/cose.manifest", b"m"),
        ("META-INF/cose.sig", b"s"),
    ]);
    let v = run(&xpi);
    let schemes = v
        .get("xpi.signing.schemes")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = schemes.iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(names, vec!["pkcs7", "cose"]);
}

#[test]
fn unsigned_shape_when_manifest_but_no_signing() {
    let xpi = stored_zip(&[("manifest.json", b"{}"), ("background.js", b"//")]);
    let v = run(&xpi);
    assert_eq!(
        v.get("xpi.unsigned_shape").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert!(v.get("xpi.signing.schemes").is_none());
    assert_eq!(
        v.get("xpi.has_web_extension_manifest")
            .and_then(|x| x.as_bool()),
        Some(true)
    );
}

#[test]
fn manifest_description_extracted_unless_localized() {
    let xpi = stored_zip(&[(
        "manifest.json",
        br#"{"name":"Tabby","description":"Tidies tabs"}"#,
    )]);
    assert_eq!(
        run(&xpi).get("xpi.description").and_then(|x| x.as_str()),
        Some("Tidies tabs")
    );
    let xpi = stored_zip(&[(
        "manifest.json",
        br#"{"description":"__MSG_extDescription__"}"#,
    )]);
    assert!(run(&xpi).get("xpi.description").is_none());
}

#[test]
fn legacy_xul_shape_when_install_rdf_present() {
    let xpi = stored_zip(&[
        ("install.rdf", b"<RDF/>"),
        ("chrome.manifest", b"content x x/"),
    ]);
    let v = run(&xpi);
    assert_eq!(
        v.get("xpi.legacy_xul_shape").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert_eq!(
        v.get("xpi.has_install_rdf").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert_eq!(
        v.get("xpi.has_chrome_manifest").and_then(|x| x.as_bool()),
        Some(true)
    );
    // No WebExtension manifest → no unsigned_shape flag.
    assert!(v.get("xpi.unsigned_shape").is_none());
}

#[test]
fn half_signed_does_not_count_as_scheme() {
    // Just mozilla.sf without mozilla.rsa is not a valid PKCS#7 pair.
    let xpi = stored_zip(&[("manifest.json", b"{}"), ("META-INF/mozilla.sf", b"sf")]);
    let v = run(&xpi);
    assert!(v.get("xpi.signing.schemes").is_none());
    assert_eq!(
        v.get("xpi.unsigned_shape").and_then(|x| x.as_bool()),
        Some(true)
    );
}

#[test]
fn empty_archive_emits_nothing() {
    let xpi = stored_zip(&[]);
    let v = run(&xpi);
    assert!(v.get("xpi.signing.schemes").is_none());
    assert!(v.get("xpi.unsigned_shape").is_none());
    assert!(v.get("xpi.legacy_xul_shape").is_none());
}

#[test]
fn non_zip_input_is_silent() {
    let v = run(b"not a zip");
    assert!(v.get("xpi.signing.schemes").is_none());
}

/// Signature member names are matched without regard to case, as the JAR
/// specification reads them.
#[test]
fn signing_member_names_ignore_case() {
    let xpi = stored_zip(&[
        ("manifest.json", b"{}"),
        ("META-INF/MOZILLA.SF", b"sf"),
        ("meta-inf/Mozilla.RSA", b"rsa"),
        ("META-INF/COSE.MANIFEST", b"m"),
        ("META-INF/Cose.Sig", b"s"),
    ]);
    let v = run(&xpi);
    let schemes = v
        .get("xpi.signing.schemes")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = schemes.iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(names, vec!["pkcs7", "cose"]);
}

const MANIFEST_JSON: &[u8] = br#"{"manifest_version":2,"name":"fixture","version":"1.0"}"#;
const BACKGROUND_JS: &[u8] = br#"console.log("fixture");"#;
const SIGNED_MF: &[u8] = include_bytes!("../../../tests/fixtures/xpi/manifest.mf");
const SIGNED_SF: &[u8] = include_bytes!("../../../tests/fixtures/xpi/mozilla.sf");
const SIGNED_RSA: &[u8] = include_bytes!("../../../tests/fixtures/xpi/mozilla.rsa");

/// The add-on `xpi/generate.sh` signed, with `replace` members put in place
/// of (or beside) its own.
fn signed_xpi(replace: &[(&str, &[u8])]) -> Vec<u8> {
    let mut members: Vec<(&str, &[u8])> = vec![
        ("manifest.json", MANIFEST_JSON),
        ("background.js", BACKGROUND_JS),
        ("META-INF/manifest.mf", SIGNED_MF),
        ("META-INF/mozilla.sf", SIGNED_SF),
        ("META-INF/mozilla.rsa", SIGNED_RSA),
    ];
    for &(name, body) in replace {
        match members.iter_mut().find(|(n, _)| *n == name) {
            Some(member) => *member = (name, body),
            None => members.push((name, body)),
        }
    }
    stored_zip(&members)
}

fn signature(v: &Values) -> serde_json::Map<String, JsonValue> {
    let sigs = v.get("xpi.signatures").and_then(|x| x.as_array()).unwrap();
    assert_eq!(sigs.len(), 1);
    sigs[0].as_object().unwrap().clone()
}

/// AMO's layout: the block signs `mozilla.sf`, which digests only the whole
/// manifest, and the manifest digests every member.
#[test]
fn an_amo_style_signature_verifies_its_signer() {
    let sig = signature(&run(&signed_xpi(&[])));
    assert_eq!(sig["verified"], JsonValue::Bool(true), "{sig:?}");
    assert_eq!(sig["digest_matches"], JsonValue::Bool(true));
    assert_eq!(sig["member"], "META-INF/mozilla.rsa");
    assert_eq!(sig["signed_member"], "META-INF/mozilla.sf");
    assert_eq!(
        sig["subject"],
        "O=Filefacts Fixtures,CN=filefacts xpi fixture"
    );
}

/// A member replaced or added after signing, or a manifest Firefox would
/// not read, leaves the signer named but not proven.
#[test]
fn a_tampered_xpi_does_not_verify() {
    let mut extra_section = SIGNED_MF.to_vec();
    extra_section.extend_from_slice(b"Name: payload.js\nSHA256-Digest: AAAA\n\n");
    for (case, replace) in [
        (
            "replaced member",
            vec![("background.js", &b"fetch(evil)"[..])],
        ),
        ("added member", vec![("payload.js", &b"fetch(evil)"[..])]),
        (
            "edited manifest",
            vec![("META-INF/manifest.mf", extra_section.as_slice())],
        ),
    ] {
        let sig = signature(&run(&signed_xpi(&replace)));
        assert_eq!(sig["verified"], JsonValue::Bool(false), "{case}: {sig:?}");
        assert_eq!(sig["digest_matches"], JsonValue::Bool(false), "{case}");
    }
    // Firefox reads the manifest only as `META-INF/manifest.mf`.
    let renamed = stored_zip(&[
        ("manifest.json", MANIFEST_JSON),
        ("background.js", BACKGROUND_JS),
        ("META-INF/MANIFEST.MF", SIGNED_MF),
        ("META-INF/mozilla.sf", SIGNED_SF),
        ("META-INF/mozilla.rsa", SIGNED_RSA),
    ]);
    let sig = signature(&run(&renamed));
    assert_ne!(sig["verified"], JsonValue::Bool(true), "{sig:?}");
}

/// Only the `mozilla` block is Firefox's; another base name is not read.
#[test]
fn other_signature_blocks_are_not_the_add_on_signer() {
    let xpi = stored_zip(&[
        ("manifest.json", MANIFEST_JSON),
        ("META-INF/cert.sf", SIGNED_SF),
        ("META-INF/cert.rsa", SIGNED_RSA),
    ]);
    assert!(run(&xpi).get("xpi.signatures").is_none());
}
