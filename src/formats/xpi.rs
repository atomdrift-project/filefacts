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

use super::bounded::Limits;
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

    for name in zip.file_names().filter_map(Result::ok) {
        match name.as_ref() {
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
        let mut limits = Limits::default();
        let manifest = super::crx::read_browser_manifest(zip, &mut limits, errors);
        limits.emit(values, value_key!("xpi.limits"));
        if let Some(manifest) = manifest {
            super::crx::emit_web_extension_identity(&manifest, &super::crx::XPI_KEYS, values);
        }
    }
}

#[cfg(test)]
mod tests;
