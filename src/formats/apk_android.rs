//! Android APK identity: `AndroidManifest.xml` plus the v1 JAR signer.
//!
//! An APK's zip members were already walked, but nothing read the manifest, so
//! there was no package name, version, SDK level, permission list or signer —
//! the whole of an Android app's declared identity was missing. `package` is
//! the canonical identifier for Android the way a bundle id is for Mach-O.
//!
//! The manifest is binary XML, read by `axml`. The signer comes from the v1
//! (JAR) signature block, `META-INF/*.RSA` / `*.DSA`, which is PKCS#7 — the
//! same structure PE and Mach-O carry, so it goes through the same CMS parser.
//! v2/v3 APK Signature Scheme blocks live before the central directory and are
//! not read here; an APK signed only with those reports no signer rather than a
//! wrong one.

use std::io::{Read, Seek};

use serde_json::{Value as JsonValue, json};

use crate::error::Error;
use crate::metric;
use crate::output::{Errors, Metrics, Stage, Values};
use crate::value_key;

/// Manifest bytes to read. Real manifests are tens of KB; this bounds a
/// decompression bomb disguised as one.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// A v1 signature block is a few KB of DER.
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    manifest(zip, values, metrics, errors);
    signer(zip, values, metrics, errors);
    Ok(())
}

/// Read a member that the central directory lists, capped at `max` bytes.
/// `Ok(None)` when no member has that name.
fn read_member<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
    max: u64,
) -> Result<Option<Vec<u8>>, String> {
    let entry = match zip.by_name(name) {
        Ok(entry) => entry,
        Err(::zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut bytes = Vec::new();
    entry
        .take(max)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(Some(bytes))
}

fn manifest<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // An APK without a manifest has nothing to report; one whose manifest
    // will not decompress is a failure worth stating.
    let bytes = match read_member(zip, "AndroidManifest.xml", MAX_MANIFEST_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return,
        Err(why) => {
            errors.record_malformed(Stage::ZipParse, format!("AndroidManifest.xml: {why}"));
            return;
        }
    };
    let elements = super::axml::parse(&bytes);
    if elements.is_empty() {
        // Present but unreadable. Worth stating: a manifest `aapt` can compile
        // but a parser cannot walk is a deliberate anti-analysis shape, and
        // silence here would be indistinguishable from an APK without one.
        metrics.insert(metric!("android.manifest_unreadable"), 1.0);
        return;
    }

    let mut permissions: Vec<JsonValue> = Vec::new();
    let mut components: Vec<JsonValue> = Vec::new();
    let mut exported_components = 0u64;
    for el in &elements {
        let get = |k: &str| {
            el.attrs
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        match el.name.as_str() {
            "manifest" => {
                for (attr, key) in [
                    ("package", value_key!("android.package")),
                    ("versionName", value_key!("android.version_name")),
                    ("versionCode", value_key!("android.version_code")),
                    ("compileSdkVersion", value_key!("android.compile_sdk")),
                    ("installLocation", value_key!("android.install_location")),
                    ("sharedUserId", value_key!("android.shared_user_id")),
                ] {
                    if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                        values.insert_key(key, JsonValue::String(v.to_string()));
                    }
                }
            }
            "uses-sdk" => {
                for (attr, key) in [
                    ("minSdkVersion", value_key!("android.min_sdk")),
                    ("targetSdkVersion", value_key!("android.target_sdk")),
                ] {
                    if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                        values.insert_key(key, JsonValue::String(v.to_string()));
                    }
                }
            }
            "application" => {
                for (attr, key) in [
                    ("label", value_key!("android.app_label")),
                    ("name", value_key!("android.app_class")),
                    ("debuggable", value_key!("android.debuggable")),
                    ("allowBackup", value_key!("android.allow_backup")),
                    (
                        "usesCleartextTraffic",
                        value_key!("android.cleartext_traffic"),
                    ),
                    (
                        "networkSecurityConfig",
                        value_key!("android.network_security_config"),
                    ),
                ] {
                    if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                        values.insert_key(key, JsonValue::String(v.to_string()));
                    }
                }
            }
            "uses-permission" | "permission" => {
                if let Some(name) = get("name").filter(|v| !v.is_empty()) {
                    permissions.push(JsonValue::String(name.to_string()));
                }
            }
            "activity" | "service" | "receiver" | "provider" => {
                let Some(name) = get("name").filter(|v| !v.is_empty()) else {
                    continue;
                };
                // An exported component is reachable by any other app on the
                // device — the attack surface an APK offers outward.
                let exported = get("exported") == Some("true");
                if exported {
                    exported_components += 1;
                }
                components.push(json!({
                    "kind": el.name,
                    "name": name,
                    "exported": exported,
                }));
            }
            _ => {}
        }
    }

    if !permissions.is_empty() {
        metrics.insert(
            metric!("android.permission_count"),
            permissions.len() as f64,
        );
        values.insert_key(
            value_key!("android.permissions"),
            JsonValue::Array(permissions),
        );
    }
    if !components.is_empty() {
        metrics.insert(metric!("android.component_count"), components.len() as f64);
        metrics.insert(
            metric!("android.exported_component_count"),
            exported_components as f64,
        );
        values.insert_key(
            value_key!("android.components"),
            JsonValue::Array(components),
        );
    }
    // Stated as metrics as well as values so a rule can band them: shipping a
    // debuggable build, or targeting an old SDK to dodge a runtime restriction
    // the platform added later, are both choices worth thresholding on.
    if values
        .get_key(value_key!("android.debuggable"))
        .and_then(JsonValue::as_str)
        == Some("true")
    {
        metrics.insert(metric!("android.debuggable"), 1.0);
    }
    for (key, metric_key) in [
        ("android.min_sdk", metric!("android.min_sdk")),
        ("android.target_sdk", metric!("android.target_sdk")),
    ] {
        if let Some(n) = values
            .get(key)
            .and_then(JsonValue::as_str)
            .and_then(|v| v.parse::<f64>().ok())
        {
            metrics.insert(metric_key, n);
        }
    }
}

fn signer<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    let names: Vec<String> = zip
        .file_names()
        .filter(|n| {
            let upper = n.to_ascii_uppercase();
            upper.starts_with("META-INF/")
                && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
        })
        .map(str::to_string)
        .collect();
    metrics.insert(metric!("android.v1_signature_count"), names.len() as f64);

    let total = names.len();
    let mut signatures = Vec::new();
    // A hostile APK can list any number of signature members, so failures
    // are reported once, in aggregate.
    let mut unreadable = 0usize;
    let mut first_failure = None;
    for name in names {
        let der = match read_member(zip, &name, MAX_SIGNATURE_BYTES) {
            Ok(Some(der)) => der,
            Ok(None) => continue,
            Err(why) => {
                unreadable += 1;
                first_failure.get_or_insert_with(|| format!("{name}: {why}"));
                continue;
            }
        };
        if let Some(mut sig) = super::pe_authenticode::parse_cms_blob(&der)
            && let Some(obj) = sig.as_object_mut()
        {
            obj.insert("member".into(), JsonValue::String(name));
            signatures.push(sig);
        }
    }
    if !signatures.is_empty() {
        values.insert_key(
            value_key!("android.signatures"),
            JsonValue::Array(signatures),
        );
    }
    if let Some(first) = first_failure {
        errors.record_malformed(
            Stage::ZipParse,
            format!("{unreadable} of {total} v1 signature blocks unreadable; first: {first}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn apk_with(manifest: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        w.start_file("AndroidManifest.xml", opts).unwrap();
        w.write_all(manifest).unwrap();
        for (name, body) in extra {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn run(bytes: &[u8]) -> (Values, Metrics, Errors) {
        let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut errors = Errors::new();
        extract_from_archive(&mut zip, &mut values, &mut metrics, &mut errors).unwrap();
        (values, metrics, errors)
    }

    /// Deflate every member, then flip a byte inside the named member's
    /// compressed data so it fails to inflate (or fails its CRC).
    fn apk_with_corrupt(corrupt: &str, members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts =
            SimpleFileOptions::default().compression_method(::zip::CompressionMethod::Deflated);
        for (name, body) in members {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        let mut bytes = w.finish().unwrap().into_inner();
        let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
        let entry = zip.by_name(corrupt).unwrap();
        let start = entry.data_start() as usize;
        let len = entry.compressed_size() as usize;
        drop(entry);
        for b in &mut bytes[start..start + len] {
            *b ^= 0xa5;
        }
        bytes
    }

    fn only_error(errors: &Errors) -> &crate::ParseError {
        assert_eq!(errors.len(), 1, "{errors:?}");
        &errors.as_slice()[0]
    }

    #[test]
    fn an_unreadable_manifest_is_reported_rather_than_passed_over() {
        let (_, metrics, errors) = run(&apk_with(b"not binary xml", &[]));
        assert_eq!(metrics.get("android.manifest_unreadable"), Some(1.0));
        // Present and readable, just not walkable: the metric says so, and
        // no read failure is recorded.
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn a_manifest_that_fails_to_inflate_records_one_zip_parse_error() {
        let body = vec![b'A'; 4096];
        let (values, _, errors) = run(&apk_with_corrupt(
            "AndroidManifest.xml",
            &[("AndroidManifest.xml", &body)],
        ));
        let e = only_error(&errors);
        assert_eq!(
            (e.stage, e.kind),
            (Stage::ZipParse, crate::ErrorKind::Malformed)
        );
        assert!(
            e.message.starts_with("AndroidManifest.xml:"),
            "{}",
            e.message
        );
        assert!(values.get("android.package").is_none());
    }

    #[test]
    fn unreadable_signature_blocks_record_one_aggregate_error() {
        let body = vec![0x30; 4096];
        let (_, metrics, errors) = run(&apk_with_corrupt(
            "META-INF/CERT.RSA",
            &[
                ("AndroidManifest.xml", b"x"),
                ("META-INF/CERT.RSA", &body),
                ("META-INF/OTHER.RSA", b"not der"),
            ],
        ));
        let e = only_error(&errors);
        assert_eq!(
            (e.stage, e.kind),
            (Stage::ZipParse, crate::ErrorKind::Malformed)
        );
        assert!(
            e.message
                .starts_with("1 of 2 v1 signature blocks unreadable; first: META-INF/CERT.RSA:"),
            "{}",
            e.message
        );
        assert_eq!(metrics.get("android.v1_signature_count"), Some(2.0));
    }

    #[test]
    fn v1_signature_members_are_counted_by_extension_and_case() {
        let (_, metrics, errors) = run(&apk_with(
            b"x",
            &[
                ("META-INF/CERT.RSA", b"not der"),
                ("META-INF/cert.dsa", b"not der"),
                ("META-INF/MANIFEST.MF", b"irrelevant"),
                ("classes.dex", b"irrelevant"),
            ],
        ));
        assert_eq!(metrics.get("android.v1_signature_count"), Some(2.0));
        // Readable blocks that are not DER: no signer, and no read failure.
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn an_apk_without_a_manifest_yields_no_android_fields() {
        let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("classes.dex", SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        let bytes = w.finish().unwrap().into_inner();
        let (values, metrics, errors) = run(&bytes);
        assert!(values.get("android.package").is_none());
        assert!(metrics.get("android.manifest_unreadable").is_none());
        assert!(errors.is_empty(), "{errors:?}");
    }
}
