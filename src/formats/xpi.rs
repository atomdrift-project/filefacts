//! Mozilla XPI (Firefox extension) shape extractor.
//!
//! XPIs are ZIP containers. The generic archive walk in `zip.rs` already
//! emits member listings and the broad signing-shape markers
//! (`archive.signing.mozilla_extension_shape`,
//! `archive.signing.jar_signed_shape`). This module layers XPI-specific
//! facts derived from filename presence in the central directory — no
//! decompression of member bodies.
//!
//! Emitted keys:
//!
//! - `xpi.signing.schemes[]` — array of detected signing schemes.
//!   Possible values: `pkcs7` (META-INF/mozilla.{sf,rsa} pair, AMO v1) and
//!   `cose` (META-INF/cose.{manifest,sig} pair, AMO v2). A single XPI may
//!   carry both ("dual-signed").
//! - `xpi.has_web_extension_manifest` — `manifest.json` present at the
//!   archive root.
//! - `xpi.has_install_rdf` — `install.rdf` present (legacy XUL extension).
//! - `xpi.has_chrome_manifest` — `chrome.manifest` present (legacy XUL).
//! - `xpi.legacy_xul_shape` — true when install.rdf or chrome.manifest
//!   is present, indicating a pre-WebExtension addon.
//! - `xpi.unsigned_shape` — true when `manifest.json` is present but
//!   no signing scheme files are. Distinguishes development/sideloaded
//!   XPIs from AMO-signed ones.

use serde_json::Value as JsonValue;
use std::io::{Read, Seek};

use crate::output::{Errors, Metrics, Values};
use crate::value_key;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    _metrics: &mut Metrics,
    errors: &mut Errors,
) {
    let mut has_manifest_json = false;
    let mut has_install_rdf = false;
    let mut has_chrome_manifest = false;
    let mut has_mozilla_sf = false;
    let mut has_mozilla_rsa = false;
    let mut has_cose_manifest = false;
    let mut has_cose_sig = false;

    for name in zip.file_names() {
        match name {
            "manifest.json" => has_manifest_json = true,
            "install.rdf" => has_install_rdf = true,
            "chrome.manifest" => has_chrome_manifest = true,
            "META-INF/mozilla.sf" => has_mozilla_sf = true,
            "META-INF/mozilla.rsa" => has_mozilla_rsa = true,
            "META-INF/cose.manifest" => has_cose_manifest = true,
            "META-INF/cose.sig" => has_cose_sig = true,
            _ => {}
        }
    }

    let pkcs7 = has_mozilla_sf && has_mozilla_rsa;
    let cose = has_cose_manifest && has_cose_sig;

    let mut schemes: Vec<JsonValue> = Vec::new();
    if pkcs7 {
        schemes.push(JsonValue::String("pkcs7".into()));
    }
    if cose {
        schemes.push(JsonValue::String("cose".into()));
    }
    if !schemes.is_empty() {
        values.insert_key(value_key!("xpi.signing.schemes"), JsonValue::Array(schemes));
    }

    if has_manifest_json {
        values.insert_key(
            value_key!("xpi.has_web_extension_manifest"),
            JsonValue::Bool(true),
        );
    }
    if has_install_rdf {
        values.insert_key(value_key!("xpi.has_install_rdf"), JsonValue::Bool(true));
    }
    if has_chrome_manifest {
        values.insert_key(value_key!("xpi.has_chrome_manifest"), JsonValue::Bool(true));
    }
    if has_install_rdf || has_chrome_manifest {
        values.insert_key(value_key!("xpi.legacy_xul_shape"), JsonValue::Bool(true));
    }
    // Unsigned development/sideloaded XPI: a WebExtension manifest is
    // present but neither signing scheme is. AMO won't distribute these.
    if has_manifest_json && !pkcs7 && !cose {
        values.insert_key(value_key!("xpi.unsigned_shape"), JsonValue::Bool(true));
    }

    // The WebExtension manifest declares the add-on's author and name —
    // the human identity behind a (possibly self-signed) XPI.
    if has_manifest_json {
        if let Some(manifest) = read_manifest(zip, values, errors) {
            emit_manifest_identity(&manifest, values);
        }
    }
}

/// Read and parse the root `manifest.json` of an opened XPI, which the
/// caller has seen listed. `None` when it is over the size cap (an
/// `xpi.limits` entry) or unreadable or not JSON (an error).
fn read_manifest<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    errors: &mut Errors,
) -> Option<JsonValue> {
    super::crx::read_browser_manifest(zip, values, errors, value_key!("xpi.limits"))
}

/// Emit `xpi.author` / `xpi.homepage` and a non-localized name and
/// description from a parsed WebExtension `manifest.json`. `name` and
/// `description` are skipped when they are `__MSG_*__` localization
/// placeholders.
fn emit_manifest_identity(manifest: &JsonValue, values: &mut Values) {
    if let Some(author) = manifest.get("author").and_then(JsonValue::as_str) {
        if !author.is_empty() {
            values.insert_key(
                value_key!("xpi.author"),
                JsonValue::String(author.to_string()),
            );
        }
    }
    if let Some(url) = manifest.get("homepage_url").and_then(JsonValue::as_str) {
        values.insert_key(
            value_key!("xpi.homepage"),
            JsonValue::String(url.to_string()),
        );
    }
    // `__MSG_*__` is a localization placeholder, not the extension's words.
    if let Some(description) = manifest
        .get("description")
        .and_then(JsonValue::as_str)
        .filter(|d| !d.is_empty() && !d.starts_with("__MSG_"))
    {
        values.insert_key(
            value_key!("xpi.description"),
            JsonValue::String(description.to_string()),
        );
    }
    if let Some(name) = manifest.get("name").and_then(JsonValue::as_str) {
        if !name.is_empty() && !name.starts_with("__MSG_") {
            values.insert_key(value_key!("xpi.name"), JsonValue::String(name.to_string()));
        }
    }
    if let Some(version) = manifest.get("version").and_then(JsonValue::as_str) {
        values.insert_key(
            value_key!("xpi.version"),
            JsonValue::String(version.to_string()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Stage;
    use std::io::{Cursor, Write};
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    fn build_xpi(entries: &[(&str, &[u8])]) -> Vec<u8> {
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

    fn run(bytes: &[u8]) -> Values {
        let (v, e) = run_with_errors(bytes);
        assert!(e.is_empty(), "{e:?}");
        v
    }

    fn run_with_errors(bytes: &[u8]) -> (Values, Errors) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut e = Errors::new();
        if let Ok(mut zip) = crate::formats::zip::open_archive(bytes) {
            extract_from_archive(&mut zip, &mut v, &mut m, &mut e);
        }
        (v, e)
    }

    #[test]
    fn manifest_that_is_not_json_records_one_error() {
        let (v, e) = run_with_errors(&build_xpi(&[("manifest.json", b"{\"name\": ")]));
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
        let (v, e) = run_with_errors(&build_xpi(&[("manifest.json", &big)]));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("xpi.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits[0]["stage"], "manifest");
    }

    #[test]
    fn pkcs7_signing_scheme_detected() {
        let xpi = build_xpi(&[
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
        let xpi = build_xpi(&[
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
        let xpi = build_xpi(&[
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
        let xpi = build_xpi(&[("manifest.json", b"{}"), ("background.js", b"//")]);
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
        let xpi = build_xpi(&[(
            "manifest.json",
            br#"{"name":"Tabby","description":"Tidies tabs"}"#,
        )]);
        assert_eq!(
            run(&xpi).get("xpi.description").and_then(|x| x.as_str()),
            Some("Tidies tabs")
        );
        let xpi = build_xpi(&[(
            "manifest.json",
            br#"{"description":"__MSG_extDescription__"}"#,
        )]);
        assert!(run(&xpi).get("xpi.description").is_none());
    }

    #[test]
    fn legacy_xul_shape_when_install_rdf_present() {
        let xpi = build_xpi(&[
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
        let xpi = build_xpi(&[("manifest.json", b"{}"), ("META-INF/mozilla.sf", b"sf")]);
        let v = run(&xpi);
        assert!(v.get("xpi.signing.schemes").is_none());
        assert_eq!(
            v.get("xpi.unsigned_shape").and_then(|x| x.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn empty_archive_emits_nothing() {
        let xpi = build_xpi(&[]);
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
}
