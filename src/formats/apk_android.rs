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
//! The block is detached: it signs the `.SF` signature file of the same base
//! name, which is handed over as the content so the signature can verify.
//! v2/v3 APK Signature Scheme blocks live before the central directory and are
//! not read here; an APK signed only with those reports no signer rather than a
//! wrong one.

use std::io::{Read, Seek};

use serde_json::{Value as JsonValue, json};

use super::bounded::Limits;
use super::zip::{MemberError, read_manifest_member, read_member};
use crate::metric;
use crate::output::{Errors, Metrics, Stage, Values};
use crate::value_key;

/// Manifest bytes to read. Real manifests are tens of KB; this bounds a
/// decompression bomb disguised as one.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// A v1 signature block is a few KB of DER.
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024 * 1024;
/// A `.SF` signature file holds a digest line per member, so it grows with
/// the archive; this is well past what the member cap allows for.
const MAX_SIGNATURE_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// v1 signature blocks read and verified. A real APK carries one to three
/// signers; each block costs a read of up to [`MAX_SIGNATURE_BYTES`], one
/// of its `.SF` of up to [`MAX_SIGNATURE_FILE_BYTES`], and a CMS parse, and
/// overlapping central-directory entries let the block count grow with the
/// file. Blocks past this are counted, not read.
const MAX_SIGNATURE_BLOCKS: usize = 8;

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
    limits: &mut Limits,
    errors: &mut Errors,
) {
    let mut names = Vec::new();
    // Signature files by upper-cased base name: `META-INF/CERT.RSA` signs
    // `META-INF/CERT.SF`, matched without regard to case.
    let mut signature_files = std::collections::HashMap::new();
    for name in zip.file_names().filter_map(Result::ok) {
        let upper = name.to_ascii_uppercase();
        if !upper.starts_with("META-INF/") {
            continue;
        }
        if [".RSA", ".DSA", ".EC"]
            .iter()
            .any(|ext| super::common::ends_with_ci(&name, ext))
        {
            names.push(name.to_string());
        } else if let Some(base) = upper.strip_suffix(".SF") {
            signature_files
                .entry(base.to_string())
                .or_insert_with(|| name.to_string());
        }
    }
    metrics.insert(metric!("android.v1_signature_count"), names.len() as f64);
    if names.len() > MAX_SIGNATURE_BLOCKS {
        limits.push(
            "signature-blocks",
            format!(
                "read {MAX_SIGNATURE_BLOCKS} of {} v1 signature blocks",
                names.len()
            ),
        );
        names.truncate(MAX_SIGNATURE_BLOCKS);
    }

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
        let base = name
            .rsplit_once('.')
            .map_or(name.as_str(), |(base, _)| base)
            .to_ascii_uppercase();
        let signature_file = signature_files.get(&base).and_then(|sf_name| {
            match read_member(zip, sf_name, MAX_SIGNATURE_FILE_BYTES) {
                Ok(content) => content.map(|content| (sf_name, content)),
                Err(MemberError::TooLarge { max }) => {
                    limits.push(
                        "signature-file",
                        format!("{sf_name} over the {max}-byte cap; signature not verified"),
                    );
                    None
                }
                Err(why) => {
                    unreadable += 1;
                    first_failure.get_or_insert_with(|| format!("{sf_name}: {why}"));
                    None
                }
            }
        });
        // Without its signature file the block still names a signer, but it
        // reads as unverifiable: there is nothing to check the signature over.
        let parsed = match &signature_file {
            Some((_, content)) => super::cms::parse_detached_cms_blob(&der, content),
            None => super::cms::parse_cms_blob(&der),
        };
        if let Some(mut sig) = parsed
            && let Some(obj) = sig.as_object_mut()
        {
            obj.insert("member".into(), JsonValue::String(name));
            if let Some((sf_name, _)) = signature_file {
                obj.insert("signed_member".into(), JsonValue::String(sf_name.clone()));
            }
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
mod tests;
