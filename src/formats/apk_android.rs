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

use super::bounded::push_limit;
use super::zip::{MemberError, read_member};
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
    manifest(zip, values, metrics, errors);
    signer(zip, values, metrics, errors);
}

fn manifest<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    // An APK without a manifest has nothing to report; one whose manifest
    // will not decompress is a failure worth stating.
    // An oversized manifest is refused, not read as its first 8 MiB: a
    // cut-off binary XML only parses into a wrong partial manifest.
    let bytes = match read_member(zip, "AndroidManifest.xml", MAX_MANIFEST_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return,
        Err(MemberError::TooLarge { max }) => {
            push_limit(
                values,
                value_key!("android.limits"),
                "manifest",
                format!("AndroidManifest.xml over the {max}-byte cap; not parsed"),
            );
            return;
        }
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
    let mut names = Vec::new();
    // Signature files by upper-cased base name: `META-INF/CERT.RSA` signs
    // `META-INF/CERT.SF`, matched without regard to case.
    let mut signature_files = std::collections::HashMap::new();
    for name in zip.file_names() {
        let upper = name.to_ascii_uppercase();
        if !upper.starts_with("META-INF/") {
            continue;
        }
        if [".RSA", ".DSA", ".EC"]
            .iter()
            .any(|ext| super::common::ends_with_ci(name, ext))
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
        push_limit(
            values,
            value_key!("android.limits"),
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
                    push_limit(
                        values,
                        value_key!("android.limits"),
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
            Some((_, content)) => super::pe_authenticode::parse_detached_cms_blob(&der, content),
            None => super::pe_authenticode::parse_cms_blob(&der),
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
        extract_from_archive(&mut zip, &mut values, &mut metrics, &mut errors);
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

    fn only_error(errors: &Errors) -> &crate::Diagnostic {
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
            (Stage::ZipParse, crate::DiagnosticKind::Malformed)
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
            (Stage::ZipParse, crate::DiagnosticKind::Malformed)
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

    /// An APK whose first local header lost its signature still reaches the
    /// APK layer: Android reads the central directory, and so does the
    /// recovery in `zip::open_and_walk`.
    #[test]
    fn apk_with_a_corrupted_local_header_still_reaches_the_apk_layer() {
        let mut bytes = apk_with(b"not axml", &[("META-INF/CERT.RSA", b"\x30\x00")]);
        bytes[0..2].copy_from_slice(b"XX");
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut errors = Errors::new();
        let mut members = Vec::new();
        let mut archive = super::super::zip::open_and_walk(
            &bytes,
            &mut values,
            &mut metrics,
            &mut members,
            &mut errors,
        )
        .unwrap()
        .expect("repaired archive");
        extract_from_archive(&mut archive, &mut values, &mut metrics, &mut errors);
        assert_eq!(members.len(), 2);
        assert_eq!(metrics.get("android.v1_signature_count"), Some(1.0));
        assert_eq!(
            metrics.get("archive.local_header_mismatch_count"),
            Some(1.0)
        );
    }

    /// Signature blocks past the cap are counted but not read: each would
    /// otherwise cost a member read and a CMS parse.
    #[test]
    fn signature_blocks_past_the_cap_are_counted_not_read() {
        let names: Vec<String> = (0..MAX_SIGNATURE_BLOCKS + 4)
            .map(|i| format!("META-INF/S{i}.RSA"))
            .collect();
        let members: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"\x30\x00".as_slice()))
            .collect();
        let (values, metrics, _) = run(&apk_with(b"x", &members));
        assert_eq!(
            metrics.get("android.v1_signature_count"),
            Some((MAX_SIGNATURE_BLOCKS + 4) as f64)
        );
        let limits = values
            .get("android.limits")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(limits[0]["stage"].as_str(), Some("signature-blocks"));
    }

    /// A manifest past the cap is refused and recorded, not parsed from its
    /// first 8 MiB.
    #[test]
    fn oversized_manifest_is_a_limit() {
        let big = vec![0_u8; MAX_MANIFEST_BYTES as usize + 1];
        let (values, metrics, errors) = run(&apk_with(&big, &[]));
        let limits = values
            .get("android.limits")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(limits[0]["stage"].as_str(), Some("manifest"));
        assert!(metrics.get("android.manifest_unreadable").is_none());
        assert!(errors.is_empty(), "{errors:?}");
    }

    const V1_SF: &[u8] = include_bytes!("../../tests/fixtures/apk/CERT.SF");
    const V1_RSA: &[u8] = include_bytes!("../../tests/fixtures/apk/CERT.RSA");

    fn v1_signature(values: &Values) -> &serde_json::Map<String, JsonValue> {
        values
            .get_key(value_key!("android.signatures"))
            .and_then(JsonValue::as_array)
            .and_then(|sigs| sigs.first())
            .and_then(JsonValue::as_object)
            .expect("one v1 signature")
    }

    /// A v1 block is detached: it verifies over the `.SF` of the same base
    /// name, matched without regard to case.
    #[test]
    fn v1_signature_verifies_over_its_signature_file() {
        let bytes = apk_with(
            b"not axml",
            &[("META-INF/cert.sf", V1_SF), ("META-INF/CERT.RSA", V1_RSA)],
        );
        let (values, _, errors) = run(&bytes);
        let sig = v1_signature(&values);
        assert_eq!(sig.get("verified"), Some(&JsonValue::Bool(true)), "{sig:?}");
        assert_eq!(
            sig.get("signed_member").and_then(JsonValue::as_str),
            Some("META-INF/cert.sf")
        );
        assert!(errors.is_empty());
    }

    /// A signature file edited after signing no longer matches the block.
    #[test]
    fn v1_signature_over_an_edited_signature_file_fails() {
        let mut sf = V1_SF.to_vec();
        sf.extend_from_slice(b"Name: classes.dex\r\nSHA-256-Digest: AAAA\r\n\r\n");
        let bytes = apk_with(
            b"not axml",
            &[("META-INF/CERT.SF", &sf), ("META-INF/CERT.RSA", V1_RSA)],
        );
        let (values, _, _) = run(&bytes);
        assert_eq!(
            v1_signature(&values).get("verified"),
            Some(&JsonValue::Bool(false))
        );
    }

    /// Without its signature file the signer is still named, but nothing
    /// was verified.
    #[test]
    fn v1_signature_without_its_signature_file_is_unverified() {
        let bytes = apk_with(b"not axml", &[("META-INF/CERT.RSA", V1_RSA)]);
        let (values, _, _) = run(&bytes);
        let sig = v1_signature(&values);
        assert_ne!(sig.get("verified"), Some(&JsonValue::Bool(true)));
        assert!(sig.get("signed_member").is_none());
    }
}
