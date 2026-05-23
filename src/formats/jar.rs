//! JAR / WAR / EAR / Spring Boot fat-jar extractor.
//!
//! Walks the zip central directory once and surfaces:
//!
//! - `jar.manifest.{manifest_version, main_class, created_by, built_by,
//!   build_jdk, build_jdk_spec, build_time, archiver_version,
//!   class_path, implementation_*, specification_*, bundle_*, sealed,
//!   permissions, application_*, codebase, trusted_*, start_class,
//!   spring_boot_version, spring_boot_classes, spring_boot_lib}` —
//!   tracked headers from `META-INF/MANIFEST.MF` parsed with the
//!   JAR continuation-line convention (single-space prefix).
//! - `jar.pom.{group_id, artifact_id, version}` — first
//!   `META-INF/maven/<g>/<a>/pom.properties` we find.
//! - `jar.features[]` — Pike-style flag array (`signed`,
//!   `multi_release`, `native_libs`, `embedded_jars`).
//! - `jar.class_count`, `jar.entry_count`, `jar.embedded_jar_count`,
//!   `jar.signature_count` — flat counts also surfaced as
//!   `metrics.jar.*`.
//!
//! The generic archive walk (`archive.members[]`,
//! `archive.compression.*`) runs on the same ZIP handle before this
//! extractor layers JAR-specific facts on top.

use serde_json::{json, Value as JsonValue};
use std::collections::BTreeMap;
use std::io::{Read, Seek};

use crate::error::Error;
use crate::output::{Metrics, Values};

/// Cap on a single text entry we'll decompress for parsing
/// (MANIFEST.MF / pom.properties). 1 MiB is generous; anything
/// larger is hostile zip-bomb input.
const MAX_TEXT_BYTES: u64 = 1024 * 1024;

const TRACKED_HEADERS: &[(&str, &str)] = &[
    ("Manifest-Version", "manifest_version"),
    ("Main-Class", "main_class"),
    ("Created-By", "created_by"),
    ("Built-By", "built_by"),
    ("Build-Jdk", "build_jdk"),
    ("Build-Jdk-Spec", "build_jdk_spec"),
    ("Build-Time", "build_time"),
    ("Build-Date", "build_date"),
    ("Archiver-Version", "archiver_version"),
    ("Class-Path", "class_path"),
    ("Implementation-Title", "implementation_title"),
    ("Implementation-Version", "implementation_version"),
    ("Implementation-Vendor", "implementation_vendor"),
    ("Implementation-Vendor-Id", "implementation_vendor_id"),
    ("Implementation-Build", "implementation_build"),
    ("Implementation-Build-Date", "implementation_build_date"),
    ("Specification-Title", "specification_title"),
    ("Specification-Version", "specification_version"),
    ("Specification-Vendor", "specification_vendor"),
    ("Bundle-Name", "bundle_name"),
    ("Bundle-SymbolicName", "bundle_symbolic_name"),
    ("Bundle-Version", "bundle_version"),
    ("Bundle-Vendor", "bundle_vendor"),
    (
        "Bundle-RequiredExecutionEnvironment",
        "bundle_required_execution_environment",
    ),
    ("Sealed", "sealed"),
    ("Permissions", "permissions"),
    ("Application-Name", "application_name"),
    (
        "Application-Library-Allowable-Codebase",
        "application_library_allowable_codebase",
    ),
    ("Codebase", "codebase"),
    ("Trusted-Only", "trusted_only"),
    ("Trusted-Library", "trusted_library"),
    ("Start-Class", "start_class"),
    ("Spring-Boot-Version", "spring_boot_version"),
    ("Spring-Boot-Classes", "spring_boot_classes"),
    ("Spring-Boot-Lib", "spring_boot_lib"),
];

pub(super) fn extract_from_archive<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let mut entry_count: u32 = 0;
    let mut class_count: u32 = 0;
    let mut signature_count: u32 = 0;
    let mut embedded_jar_count: u32 = 0;
    let mut native_libs = false;
    let mut multi_release = false;
    let mut manifest: BTreeMap<String, String> = BTreeMap::new();
    let mut pom_group: Option<String> = None;
    let mut pom_artifact: Option<String> = None;
    let mut pom_version: Option<String> = None;

    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    for name in &names {
        if name.ends_with('/') {
            continue;
        }
        entry_count += 1;
        match name
            .rsplit('.')
            .next()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("class") => class_count += 1,
            Some("so" | "dll" | "dylib" | "jnilib") => native_libs = true,
            Some("jar" | "war" | "ear") => {
                embedded_jar_count += 1;
            }
            _ => {}
        }
        if name.starts_with("META-INF/") && name.ends_with(".SF") {
            signature_count += 1;
        }
        if name.starts_with("META-INF/versions/") {
            multi_release = true;
        }
        if name == "META-INF/MANIFEST.MF" {
            if let Some(text) = read_text(zip, name) {
                manifest = parse_manifest(&text);
            }
        } else if pom_group.is_none() && name.ends_with("/pom.properties") {
            if let Some(text) = read_text(zip, name) {
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(v) = line.strip_prefix("groupId=") {
                        pom_group = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("artifactId=") {
                        pom_artifact = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("version=") {
                        pom_version = Some(v.trim().to_string());
                    }
                }
            }
        }
    }

    if entry_count == 0 && manifest.is_empty() {
        return Ok(());
    }

    if !manifest.is_empty() {
        let mut obj = serde_json::Map::new();
        for (k, v) in manifest {
            obj.insert(k, JsonValue::String(v));
        }
        values.insert("jar.manifest", JsonValue::Object(obj));
    }
    if pom_group.is_some() || pom_artifact.is_some() || pom_version.is_some() {
        let mut pom = serde_json::Map::new();
        if let Some(g) = pom_group {
            pom.insert("group_id".into(), JsonValue::String(g));
        }
        if let Some(a) = pom_artifact {
            pom.insert("artifact_id".into(), JsonValue::String(a));
        }
        if let Some(v) = pom_version {
            pom.insert("version".into(), JsonValue::String(v));
        }
        values.insert("jar.pom", JsonValue::Object(pom));
    }

    let mut features: Vec<&'static str> = Vec::new();
    if signature_count > 0 {
        features.push("signed");
    }
    if multi_release {
        features.push("multi_release");
    }
    if native_libs {
        features.push("native_libs");
    }
    if embedded_jar_count > 0 {
        features.push("embedded_jars");
    }
    if !features.is_empty() {
        values.insert(
            "jar.features",
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    values.insert("jar.entry_count", json!(entry_count));
    values.insert("jar.class_count", json!(class_count));
    if embedded_jar_count > 0 {
        values.insert("jar.embedded_jar_count", json!(embedded_jar_count));
    }
    if signature_count > 0 {
        values.insert("jar.signature_count", json!(signature_count));
    }
    metrics.insert("jar.entry_count", f64::from(entry_count));
    metrics.insert("jar.class_count", f64::from(class_count));
    metrics.insert("jar.embedded_jar_count", f64::from(embedded_jar_count));
    metrics.insert("jar.signature_count", f64::from(signature_count));

    Ok(())
}

/// Decompress an entry into a `String`, capped at `MAX_TEXT_BYTES`.
/// Used for `MANIFEST.MF` and `pom.properties` — both small text
/// files in any legitimate JAR.
fn read_text<R: std::io::Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
) -> Option<String> {
    let mut entry = zip.by_name(name).ok()?;
    if entry.size() > MAX_TEXT_BYTES {
        return None;
    }
    let mut s = String::new();
    entry.read_to_string(&mut s).ok()?;
    Some(s)
}

/// Parse a `MANIFEST.MF` text body and return the tracked headers
/// keyed by their snake_case names. The JAR manifest format wraps
/// long values onto continuation lines that start with a single
/// space — handled here so `Implementation-Title: A very long…`
/// values survive intact.
fn parse_manifest(text: &str) -> BTreeMap<String, String> {
    let mut joined: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(stripped) = line.strip_prefix(' ') {
            if let Some(last) = joined.last_mut() {
                last.push_str(stripped);
                continue;
            }
        }
        joined.push(line.to_string());
    }
    let mut out = BTreeMap::new();
    for line in joined {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Some((_, snake)) = TRACKED_HEADERS
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
        {
            out.insert((*snake).to_string(), value.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn build_jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts =
                SimpleFileOptions::default().compression_method(::zip::CompressionMethod::Stored);
            for (name, body) in entries {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(body).unwrap();
            }
            zip.finish().unwrap();
        }
        buf
    }

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        if let Ok(mut zip) = crate::formats::zip::open_archive(bytes) {
            extract_from_archive(&mut zip, &mut v, &mut m).unwrap();
        }
        (v, m)
    }

    #[test]
    fn surfaces_manifest_attribution() {
        let jar = build_jar(&[(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\n\
              Created-By: Apache Maven 3.9.4\n\
              Built-By: build-host\n\
              Build-Jdk: 17.0.8\n\
              Main-Class: com.example.Main\n",
        )]);
        let (v, _) = run(&jar);
        assert_eq!(
            v.get("jar.manifest.created_by").and_then(|x| x.as_str()),
            Some("Apache Maven 3.9.4")
        );
        assert_eq!(
            v.get("jar.manifest.main_class").and_then(|x| x.as_str()),
            Some("com.example.Main")
        );
    }

    #[test]
    fn manifest_continuation_lines_join() {
        let mut text = String::new();
        text.push_str("Manifest-Version: 1.0\n");
        text.push_str("Implementation-Title: A long title that spans\n");
        text.push_str(" continuation lines per JAR spec\n");
        let jar = build_jar(&[("META-INF/MANIFEST.MF", text.as_bytes())]);
        let (v, _) = run(&jar);
        assert_eq!(
            v.get("jar.manifest.implementation_title")
                .and_then(|x| x.as_str()),
            Some("A long title that spanscontinuation lines per JAR spec")
        );
    }

    #[test]
    fn structural_features_detected() {
        let jar = build_jar(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("com/example/Foo.class", b"\xca\xfe\xba\xbe"),
            ("META-INF/SIG.SF", b"Signature-Version: 1.0\n"),
            ("lib/native.so", b"\x7fELF"),
            ("BOOT-INF/lib/dep.jar", b"PK\x03\x04"),
            (
                "META-INF/versions/11/com/example/Foo.class",
                b"\xca\xfe\xba\xbe",
            ),
        ]);
        let (v, m) = run(&jar);
        assert_eq!(m.get("jar.class_count"), Some(2.0));
        let feats = v.get("jar.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"signed"));
        assert!(names.contains(&"multi_release"));
        assert!(names.contains(&"native_libs"));
        assert!(names.contains(&"embedded_jars"));
    }

    #[test]
    fn pom_properties_surface() {
        let jar = build_jar(&[(
            "META-INF/maven/com.example/myartifact/pom.properties",
            b"version=1.2.3\n\
              groupId=com.example\n\
              artifactId=myartifact\n",
        )]);
        let (v, _) = run(&jar);
        assert_eq!(
            v.get("jar.pom.group_id").and_then(|x| x.as_str()),
            Some("com.example")
        );
        assert_eq!(
            v.get("jar.pom.artifact_id").and_then(|x| x.as_str()),
            Some("myartifact")
        );
        assert_eq!(
            v.get("jar.pom.version").and_then(|x| x.as_str()),
            Some("1.2.3")
        );
    }

    #[test]
    fn non_zip_input_is_silent() {
        let (v, _) = run(b"not a zip");
        assert!(v.get("jar.entry_count").is_none());
    }

    #[test]
    fn empty_jar_silent() {
        let jar = build_jar(&[]);
        let (v, _) = run(&jar);
        // Empty zip → entry_count would be 0 and manifest empty,
        // so the extractor short-circuits.
        assert!(v.get("jar.entry_count").is_none());
    }

    #[test]
    fn manifest_unknown_keys_dropped() {
        let jar = build_jar(&[(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\nX-Custom-Key: some-value\n",
        )]);
        let (v, _) = run(&jar);
        let manifest = v.get("jar.manifest").and_then(|x| x.as_object()).unwrap();
        // Tracked key surfaces.
        assert!(manifest.contains_key("manifest_version"));
        // Custom key is not in the allow-list → dropped.
        assert!(!manifest.contains_key("x_custom_key"));
    }

    #[test]
    fn entry_count_metric_reflects_zip_entries() {
        let jar = build_jar(&[
            ("a.class", b"\xca\xfe\xba\xbe"),
            ("b.class", b"\xca\xfe\xba\xbe"),
            ("c.txt", b"hello"),
        ]);
        let (_, m) = run(&jar);
        assert_eq!(m.get("jar.entry_count"), Some(3.0));
        assert_eq!(m.get("jar.class_count"), Some(2.0));
    }
}
