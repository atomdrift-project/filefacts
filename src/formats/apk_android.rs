//! Android APK identity: `AndroidManifest.xml` plus the v1 JAR signer.
//!
//! The zip walk lists an APK's members; the manifest and signer read here
//! carry the package name, version, SDK levels, permission list and signer —
//! the whole of an Android app's declared identity. `package` is the
//! canonical identifier for Android the way a bundle id is for Mach-O.
//!
//! The manifest is binary XML, read by `axml`. The signer comes from the v1
//! (JAR) signature block, `META-INF/*.RSA` / `*.DSA`, which is PKCS#7 — the
//! same structure PE and Mach-O carry, so it goes through the same CMS parser.
//! The block is `verified` only when it signs its `.SF` and the `.SF` binds
//! the manifest and every member; `digest_matches` states that binding (see
//! [`jar_signature`], shared with XPI signing).
//! v2/v3 APK Signature Scheme blocks live before the central directory and are
//! not read here; an APK signed only with those reports no signer rather than a
//! wrong one.

use std::io::{Read, Seek};

use serde_json::{Value as JsonValue, json};

use super::bounded::Limits;
use super::jar_signature::{self, Scheme};
use super::zip::read_manifest_member;
use crate::metric;
use crate::output::{Errors, Metrics, ValueKey, Values};
use crate::value_key;

/// Manifest bytes to read. Real manifests are tens of KB; this bounds a
/// decompression bomb disguised as one.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    let mut limits = Limits::default();
    manifest(zip, values, metrics, &mut limits, errors);
    signer(zip, values, metrics, &mut limits, errors);
    limits.emit(values, value_key!("android.limits"));
}

fn manifest<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    limits: &mut Limits,
    errors: &mut Errors,
) {
    // An APK without a manifest has nothing to report; one whose manifest
    // will not decompress is a failure worth stating.
    // An oversized manifest is refused, not read as its first 8 MiB: a
    // cut-off binary XML only parses into a wrong partial manifest.
    let Some(bytes) = read_manifest_member(
        zip,
        "AndroidManifest.xml",
        MAX_MANIFEST_BYTES,
        limits,
        "manifest",
        errors,
    ) else {
        return;
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
        // Android reads the manifest's `package` by name in no namespace
        // (`getAttributeValue(null, "package")`): an `android:package`
        // ahead of it is another attribute, not a second package name.
        let get = |k: &str| {
            el.attrs
                .iter()
                .find(|a| a.name == k && !(k == "package" && a.namespaced))
                .map(|a| a.value.as_str())
        };
        // The identity attributes each element carries, copied as stated.
        let identity: &[(&str, ValueKey)] = match el.name.as_str() {
            "manifest" => &[
                ("package", value_key!("android.package")),
                ("versionName", value_key!("android.version_name")),
                ("versionCode", value_key!("android.version_code")),
                ("compileSdkVersion", value_key!("android.compile_sdk")),
                ("installLocation", value_key!("android.install_location")),
                ("sharedUserId", value_key!("android.shared_user_id")),
            ],
            "uses-sdk" => &[
                ("minSdkVersion", value_key!("android.min_sdk")),
                ("targetSdkVersion", value_key!("android.target_sdk")),
            ],
            "application" => &[
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
            ],
            _ => &[],
        };
        for &(attr, key) in identity {
            if let Some(v) = get(attr).filter(|v| !v.is_empty()) {
                values.insert_key(key, JsonValue::String(v.to_string()));
            }
        }
        match el.name.as_str() {
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
        .lookup(value_key!("android.debuggable"))
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
    limits: &mut Limits,
    errors: &mut Errors,
) {
    let signed = jar_signature::read(zip, Scheme::Android, limits, errors);
    metrics.insert(metric!("android.v1_signature_count"), signed.blocks as f64);
    if !signed.signatures.is_empty() {
        values.insert_key(
            value_key!("android.signatures"),
            JsonValue::Array(signed.signatures),
        );
    }
}

#[cfg(test)]
mod tests;
