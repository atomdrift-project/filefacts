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
//! The block is detached: it signs the `.SF` signature file of the same base
//! name, which is handed over as the content so the signature can verify. A
//! block that verifies over its `.SF` is `verified` only when the `.SF` also
//! binds the manifest and the manifest every member ([`v1`]); `digest_matches`
//! states that binding.
//! v2/v3 APK Signature Scheme blocks live before the central directory and are
//! not read here; an APK signed only with those reports no signer rather than a
//! wrong one.

mod v1;

use std::io::{Read, Seek};

use serde_json::{Value as JsonValue, json};

use super::bounded::Limits;
use super::cms::{Signature, Verdict};
use super::zip::JarSigning;
use super::zip::{MemberError, read_manifest_member, read_member};
use crate::metric;
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};
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
    let mut names = Vec::new();
    // Signature files by upper-cased base name: `META-INF/CERT.RSA` signs
    // `META-INF/CERT.SF`, matched without regard to case.
    let mut signature_files = std::collections::HashMap::new();
    for name in zip.file_names().filter_map(Result::ok) {
        match super::zip::jar_signing(&name) {
            Some((JarSigning::SignatureBlock, base)) => {
                names.push((name.to_string(), base.to_ascii_uppercase()));
            }
            Some((JarSigning::SignatureFile, base)) => {
                signature_files
                    .entry(base.to_ascii_uppercase())
                    .or_insert_with(|| name.to_string());
            }
            None => {}
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
    let mut verifier = v1::Verifier::new(v1::MAX_HASHED_BYTES);
    let mut signatures = Vec::new();
    // A hostile APK can list any number of signature members, so failures
    // are reported once, in aggregate.
    let mut unreadable = 0usize;
    let mut first_failure = None;
    for (name, base) in names {
        let der = match read_member(zip, &name, MAX_SIGNATURE_BYTES) {
            Ok(Some(der)) => der,
            Ok(None) => continue,
            Err(why) => {
                unreadable += 1;
                first_failure.get_or_insert_with(|| format!("{name}: {why}"));
                continue;
            }
        };
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
            Some((sf_name, content)) => {
                super::cms::parse_detached_cms(&der, content).map(|mut sig| {
                    if sig.is_verified() {
                        let binding = verifier.bind(zip, content);
                        record_binding(&mut sig, binding, sf_name, limits);
                    }
                    sig.to_json()
                })
            }
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

/// Fold whether the `.SF` named `sf_name`, over which `sig` verified,
/// binds the archive into `sig`: `verified` stays true only when it does.
fn record_binding(sig: &mut Signature, binding: v1::Binding, sf_name: &str, limits: &mut Limits) {
    match binding {
        v1::Binding::Bound => sig.digest_matches = Some(true),
        v1::Binding::Broken(why) => {
            tracing::debug!(
                target: "filefacts::apk_android",
                stage = "v1-binding",
                member = sf_name,
                failure = ?why,
                "v1 signature verifies over its signature file but does not bind the archive"
            );
            sig.verified = Some(Verdict::Failed(why));
            sig.digest_matches = Some(false);
        }
        v1::Binding::Unverifiable(reason) => {
            limits.push(
                "signature-binding",
                format!("{sf_name}: {reason}; signature not verified"),
            );
            sig.verified = Some(Verdict::Unsupported);
        }
    }
}

#[cfg(test)]
mod tests;
