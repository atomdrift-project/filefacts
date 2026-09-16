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
use crate::output::{Metrics, Values};

/// Manifest bytes to read. Real manifests are tens of KB; this bounds a
/// decompression bomb disguised as one.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// A v1 signature block is a few KB of DER.
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    manifest(zip, values, metrics);
    signer(zip, values, metrics);
    Ok(())
}

fn manifest<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Ok(entry) = zip.by_name("AndroidManifest.xml") else {
        return;
    };
    let mut bytes = Vec::new();
    if entry
        .take(MAX_MANIFEST_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return;
    }
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
                    ("package", "android.package"),
                    ("versionName", "android.version_name"),
                    ("versionCode", "android.version_code"),
                    ("compileSdkVersion", "android.compile_sdk"),
                    ("installLocation", "android.install_location"),
                    ("sharedUserId", "android.shared_user_id"),
                ] {
                    if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                        values.insert(key, JsonValue::String(v.to_string()));
                    }
                }
            }
            "uses-sdk" => {
                for (attr, key) in [
                    ("minSdkVersion", "android.min_sdk"),
                    ("targetSdkVersion", "android.target_sdk"),
                ] {
                    if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                        values.insert(key, JsonValue::String(v.to_string()));
                    }
                }
            }
            "application" => {
                for (attr, key) in [
                    ("label", "android.app_label"),
                    ("name", "android.app_class"),
                    ("debuggable", "android.debuggable"),
                    ("allowBackup", "android.allow_backup"),
                    ("usesCleartextTraffic", "android.cleartext_traffic"),
                    ("networkSecurityConfig", "android.network_security_config"),
                ] {
                    if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                        values.insert(key, JsonValue::String(v.to_string()));
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
        values.insert("android.permissions", JsonValue::Array(permissions));
    }
    if !components.is_empty() {
        metrics.insert(metric!("android.component_count"), components.len() as f64);
        metrics.insert(
            metric!("android.exported_component_count"),
            exported_components as f64,
        );
        values.insert("android.components", JsonValue::Array(components));
    }
    // Stated as metrics as well as values so a rule can band them: shipping a
    // debuggable build, or targeting an old SDK to dodge a runtime restriction
    // the platform added later, are both choices worth thresholding on.
    if values.get("android.debuggable").and_then(JsonValue::as_str) == Some("true") {
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

    let mut signatures = Vec::new();
    for name in names {
        let Ok(entry) = zip.by_name(&name) else {
            continue;
        };
        let mut der = Vec::new();
        if entry
            .take(MAX_SIGNATURE_BYTES)
            .read_to_end(&mut der)
            .is_err()
        {
            continue;
        }
        if let Some(mut sig) = super::pe_authenticode::parse_cms_blob(&der)
            && let Some(obj) = sig.as_object_mut()
        {
            obj.insert("member".into(), JsonValue::String(name));
            signatures.push(sig);
        }
    }
    if !signatures.is_empty() {
        values.insert("android.signatures", JsonValue::Array(signatures));
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

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut zip = ::zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        extract_from_archive(&mut zip, &mut values, &mut metrics).unwrap();
        (values, metrics)
    }

    #[test]
    fn an_unreadable_manifest_is_reported_rather_than_passed_over() {
        let (_, metrics) = run(&apk_with(b"not binary xml", &[]));
        assert_eq!(metrics.get("android.manifest_unreadable"), Some(1.0));
    }

    #[test]
    fn v1_signature_members_are_counted_by_extension_and_case() {
        let (_, metrics) = run(&apk_with(
            b"x",
            &[
                ("META-INF/CERT.RSA", b"not der"),
                ("META-INF/cert.dsa", b"not der"),
                ("META-INF/MANIFEST.MF", b"irrelevant"),
                ("classes.dex", b"irrelevant"),
            ],
        ));
        assert_eq!(metrics.get("android.v1_signature_count"), Some(2.0));
    }

    #[test]
    fn an_apk_without_a_manifest_yields_no_android_fields() {
        let mut w = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("classes.dex", SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        let bytes = w.finish().unwrap().into_inner();
        let (values, metrics) = run(&bytes);
        assert!(values.get("android.package").is_none());
        assert!(metrics.get("android.manifest_unreadable").is_none());
    }
}
