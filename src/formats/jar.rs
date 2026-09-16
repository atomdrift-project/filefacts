//! JAR / WAR / EAR / Spring Boot fat-jar extractor.
//!
//! Walks the zip central directory once and surfaces:
//!
//! - `jar.manifest.{manifest_version, main_class, created_by, built_by,
//!   build_jdk, build_jdk_spec, build_time, archiver_version,
//!   class_path, premain_class, agent_class, launcher_agent_class,
//!   boot_class_path, can_redefine_classes, can_retransform_classes,
//!   can_set_native_method_prefix, automatic_module_name, multi_release,
//!   add_exports, add_opens, enable_native_access, extension_name,
//!   implementation_*, specification_*, bundle_*, fragment_host,
//!   require_bundle, import_package, export_package, dynamic_import_package,
//!   require_capability, provide_capability, sealed, permissions,
//!   application_*, codebase, trusted_*, start_class, spring_boot_version,
//!   spring_boot_classes, spring_boot_lib}` —
//!   tracked headers from `META-INF/MANIFEST.MF` parsed with the
//!   JAR continuation-line convention (single-space prefix). Derived
//!   `section_count`, `entry_count`, `attribute_count`, `digest_count`,
//!   `digest_algorithms`, `class_path_count`, and `boot_class_path_count`
//!   describe the manifest's section structure.
//! - `jar.pom.{group_id, artifact_id, version}` — first
//!   `META-INF/maven/<g>/<a>/pom.properties` we find.
//! - `jar.features[]` — Pike-style flag array (`signed`,
//!   `multi_release`, `native_libs`, `embedded_jars`, `services`,
//!   `java_agents`, `osgi_activator`).
//! - `jar.class_count`, `jar.entry_count`, `jar.embedded_jar_count`,
//!   `jar.signature_count`, `jar.signature_block_count`,
//!   `jar.native_lib_count`, `jar.service_count`, `jar.versioned_class_count`,
//!   and `jar.index_count` — flat counts also surfaced as `metrics.jar.*`.
//!
//! The generic archive walk (`archive.members[]`,
//! `archive.compression.*`) runs on the same ZIP handle before this
//! extractor layers JAR-specific facts on top.

use crate::metric;
use serde_json::{Value as JsonValue, json};
use std::collections::{BTreeMap, BTreeSet};
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
    ("Premain-Class", "premain_class"),
    ("Agent-Class", "agent_class"),
    ("Launcher-Agent-Class", "launcher_agent_class"),
    ("Boot-Class-Path", "boot_class_path"),
    ("Can-Redefine-Classes", "can_redefine_classes"),
    ("Can-Retransform-Classes", "can_retransform_classes"),
    (
        "Can-Set-Native-Method-Prefix",
        "can_set_native_method_prefix",
    ),
    ("Automatic-Module-Name", "automatic_module_name"),
    ("Multi-Release", "multi_release"),
    ("Add-Exports", "add_exports"),
    ("Add-Opens", "add_opens"),
    ("Enable-Native-Access", "enable_native_access"),
    ("Extension-Name", "extension_name"),
    ("Implementation-URL", "implementation_url"),
    ("Specification-URL", "specification_url"),
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
    ("Bundle-ManifestVersion", "bundle_manifest_version"),
    ("Bundle-Activator", "bundle_activator"),
    ("Bundle-ActivationPolicy", "bundle_activation_policy"),
    ("Bundle-ClassPath", "bundle_class_path"),
    ("Bundle-NativeCode", "bundle_native_code"),
    (
        "Bundle-RequiredExecutionEnvironment",
        "bundle_required_execution_environment",
    ),
    ("Fragment-Host", "fragment_host"),
    ("Require-Bundle", "require_bundle"),
    ("Import-Package", "import_package"),
    ("Export-Package", "export_package"),
    ("DynamicImport-Package", "dynamic_import_package"),
    ("Require-Capability", "require_capability"),
    ("Provide-Capability", "provide_capability"),
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
    let mut native_lib_count: u32 = 0;
    let mut multi_release = false;
    let mut service_count: u32 = 0;
    let mut versioned_class_count: u32 = 0;
    let mut signature_block_count: u32 = 0;
    let mut index_count: u32 = 0;
    let mut manifest: Option<ManifestFacts> = None;
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
            Some("so" | "dll" | "dylib" | "jnilib") => native_lib_count += 1,
            Some("jar" | "war" | "ear") => {
                embedded_jar_count += 1;
            }
            _ => {}
        }
        if name.starts_with("META-INF/") && name.ends_with(".SF") {
            signature_count += 1;
        }
        if name.starts_with("META-INF/")
            && name.rsplit('.').next().is_some_and(|ext| {
                ["RSA", "DSA", "EC", "SIG"]
                    .iter()
                    .any(|sig| ext.eq_ignore_ascii_case(sig))
            })
        {
            signature_block_count += 1;
        }
        if name.starts_with("META-INF/versions/") {
            multi_release = true;
        }
        if name.starts_with("META-INF/services/") {
            service_count += 1;
        }
        if name.starts_with("META-INF/versions/") && name.ends_with(".class") {
            versioned_class_count += 1;
        }
        if name == "META-INF/INDEX.LIST" {
            index_count += 1;
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

    if entry_count == 0 && manifest.as_ref().is_none_or(ManifestFacts::is_empty) {
        return Ok(());
    }

    let class_path_count = manifest
        .as_ref()
        .and_then(|m| m.headers.get("class_path"))
        .map(|v| v.split_whitespace().count() as u32)
        .unwrap_or(0);
    let boot_class_path_count = manifest
        .as_ref()
        .and_then(|m| m.headers.get("boot_class_path"))
        .map(|v| v.split_whitespace().count() as u32)
        .unwrap_or(0);
    let has_java_agents = manifest_has_agent(manifest.as_ref());
    let has_osgi_activator = manifest
        .as_ref()
        .is_some_and(|m| m.headers.contains_key("bundle_activator"));

    if let Some(manifest) = manifest.as_ref() {
        let mut obj = serde_json::Map::new();
        for (k, v) in &manifest.headers {
            obj.insert(k.clone(), JsonValue::String(v.clone()));
        }
        if manifest.section_count > 0 {
            obj.insert("section_count".into(), json!(manifest.section_count));
        }
        if manifest.entry_count > 0 {
            obj.insert("entry_count".into(), json!(manifest.entry_count));
        }
        if manifest.attribute_count > 0 {
            obj.insert("attribute_count".into(), json!(manifest.attribute_count));
        }
        if manifest.digest_count > 0 {
            obj.insert("digest_count".into(), json!(manifest.digest_count));
            obj.insert(
                "digest_algorithms".into(),
                JsonValue::Array(
                    manifest
                        .digest_algorithms
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            );
        }
        if class_path_count > 0 {
            obj.insert("class_path_count".into(), json!(class_path_count));
        }
        if boot_class_path_count > 0 {
            obj.insert("boot_class_path_count".into(), json!(boot_class_path_count));
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
    if native_lib_count > 0 {
        features.push("native_libs");
    }
    if embedded_jar_count > 0 {
        features.push("embedded_jars");
    }
    if service_count > 0 {
        features.push("services");
    }
    if has_java_agents {
        features.push("java_agents");
    }
    if has_osgi_activator {
        features.push("osgi_activator");
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
    if signature_block_count > 0 {
        values.insert("jar.signature_block_count", json!(signature_block_count));
    }
    if native_lib_count > 0 {
        values.insert("jar.native_lib_count", json!(native_lib_count));
    }
    if service_count > 0 {
        values.insert("jar.service_count", json!(service_count));
    }
    if versioned_class_count > 0 {
        values.insert("jar.versioned_class_count", json!(versioned_class_count));
    }
    if index_count > 0 {
        values.insert("jar.index_count", json!(index_count));
    }
    metrics.insert(metric!("jar.entry_count"), f64::from(entry_count));
    metrics.insert(metric!("jar.class_count"), f64::from(class_count));
    metrics.insert(
        metric!("jar.embedded_jar_count"),
        f64::from(embedded_jar_count),
    );
    metrics.insert(metric!("jar.signature_count"), f64::from(signature_count));
    metrics.insert(
        metric!("jar.signature_block_count"),
        f64::from(signature_block_count),
    );
    metrics.insert(metric!("jar.native_lib_count"), f64::from(native_lib_count));
    metrics.insert(metric!("jar.service_count"), f64::from(service_count));
    metrics.insert(
        metric!("jar.versioned_class_count"),
        f64::from(versioned_class_count),
    );
    metrics.insert(metric!("jar.index_count"), f64::from(index_count));
    if let Some(manifest) = manifest.as_ref() {
        metrics.insert(
            metric!("jar.manifest.entry_count"),
            f64::from(manifest.entry_count),
        );
        metrics.insert(
            metric!("jar.manifest.section_count"),
            f64::from(manifest.section_count),
        );
        metrics.insert(
            metric!("jar.manifest.attribute_count"),
            f64::from(manifest.attribute_count),
        );
        metrics.insert(
            metric!("jar.manifest.digest_count"),
            f64::from(manifest.digest_count),
        );
        metrics.insert(
            metric!("jar.manifest.class_path_count"),
            f64::from(class_path_count),
        );
        metrics.insert(
            metric!("jar.manifest.boot_class_path_count"),
            f64::from(boot_class_path_count),
        );
    }

    Ok(())
}

/// Decompress an entry into a `String`, capped at `MAX_TEXT_BYTES`
/// of actual decompressed output. Trusting `entry.size()` alone is
/// unsafe — that value comes from the central-directory header and
/// can be spoofed by a zip bomb that claims a small uncompressed
/// length while inflating to gigabytes. Used for `MANIFEST.MF` and
/// `pom.properties`, both small text files in any legitimate JAR.
fn read_text<R: std::io::Read + std::io::Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
) -> Option<String> {
    let entry = zip.by_name(name).ok()?;
    let mut buf = Vec::new();
    entry.take(MAX_TEXT_BYTES + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_TEXT_BYTES {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// Facts parsed from a `MANIFEST.MF` text body. The JAR manifest format wraps
/// long values onto continuation lines that start with a single space —
/// handled here so `Implementation-Title: A very long…` values survive intact.
#[derive(Debug, Default)]
struct ManifestFacts {
    headers: BTreeMap<String, String>,
    section_count: u32,
    entry_count: u32,
    attribute_count: u32,
    digest_count: u32,
    digest_algorithms: BTreeSet<String>,
}

impl ManifestFacts {
    fn is_empty(&self) -> bool {
        self.headers.is_empty()
            && self.section_count == 0
            && self.entry_count == 0
            && self.attribute_count == 0
            && self.digest_count == 0
    }
}

fn manifest_has_agent(manifest: Option<&ManifestFacts>) -> bool {
    manifest.is_some_and(|m| {
        [
            "premain_class",
            "agent_class",
            "launcher_agent_class",
            "boot_class_path",
            "can_redefine_classes",
            "can_retransform_classes",
            "can_set_native_method_prefix",
        ]
        .iter()
        .any(|key| m.headers.contains_key(*key))
    })
}

/// Parse a `MANIFEST.MF` text body into tracked headers and structural facts.
/// A non-main section is an entry when it carries a `Name:` attribute. Digest
/// attributes are counted and their algorithm names are retained, but
/// attacker-controlled entry names are deliberately not copied into values;
/// the generic archive member table already carries those names.
fn parse_manifest(text: &str) -> Option<ManifestFacts> {
    let mut sections: Vec<Vec<String>> = Vec::new();
    let mut section: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            if !section.is_empty() {
                sections.push(std::mem::take(&mut section));
            }
            continue;
        }
        if let Some(stripped) = line.strip_prefix(' ') {
            if let Some(last) = section.last_mut() {
                last.push_str(stripped);
                continue;
            }
        }
        section.push(line.to_string());
    }
    if !section.is_empty() {
        sections.push(section);
    }

    if sections.is_empty() {
        return None;
    }

    let mut facts = ManifestFacts::default();
    facts.section_count = sections.len().saturating_sub(1) as u32;
    for (section_index, section) in sections.into_iter().enumerate() {
        let mut named = false;
        for line in section {
            let Some((key, value)) = line.trim_end().split_once(':') else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            facts.attribute_count += 1;
            if key.eq_ignore_ascii_case("Name") {
                named = true;
            }
            let digest_suffix = "-Digest";
            if key.len() > digest_suffix.len()
                && key[key.len() - digest_suffix.len()..].eq_ignore_ascii_case(digest_suffix)
            {
                facts.digest_count += 1;
                facts
                    .digest_algorithms
                    .insert(key[..key.len() - digest_suffix.len()].to_ascii_lowercase());
            }
            if let Some((_, snake)) = TRACKED_HEADERS
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
            {
                facts
                    .headers
                    .insert((*snake).to_string(), value.to_string());
            }
        }
        if section_index > 0 && named {
            facts.entry_count += 1;
        }
    }
    Some(facts)
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
    fn manifest_agent_and_signature_metadata_surface() {
        let jar = build_jar(&[(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\n\
              Premain-Class: com.example.Agent\n\
              Can-Redefine-Classes: true\n\
              Class-Path: one.jar two.jar\n\
              Boot-Class-Path: boot.jar\n\
              Bundle-Activator: com.example.Activator\n\
              \n\
              Name: com/example/Main.class\n\
              SHA-256-Digest: deadbeef\n",
        )]);
        let (v, m) = run(&jar);
        assert_eq!(
            v.get("jar.manifest.premain_class").and_then(|x| x.as_str()),
            Some("com.example.Agent")
        );
        assert_eq!(
            v.get("jar.manifest.entry_count").and_then(|x| x.as_u64()),
            Some(1)
        );
        assert_eq!(
            v.get("jar.manifest.digest_algorithms")
                .and_then(|x| x.as_array())
                .and_then(|x| x.first())
                .and_then(|x| x.as_str()),
            Some("sha-256")
        );
        assert_eq!(
            v.get("jar.manifest.bundle_activator")
                .and_then(|x| x.as_str()),
            Some("com.example.Activator")
        );
        assert_eq!(m.get("jar.manifest.attribute_count"), Some(8.0));
        assert_eq!(m.get("jar.manifest.section_count"), Some(1.0));
        assert_eq!(m.get("jar.manifest.digest_count"), Some(1.0));
        assert_eq!(m.get("jar.manifest.class_path_count"), Some(2.0));
        assert_eq!(m.get("jar.manifest.boot_class_path_count"), Some(1.0));
        let feats = v.get("jar.features").and_then(|x| x.as_array()).unwrap();
        assert!(feats.iter().any(|x| x == "java_agents"));
        assert!(feats.iter().any(|x| x == "osgi_activator"));
    }

    #[test]
    fn structural_features_detected() {
        let jar = build_jar(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("com/example/Foo.class", b"\xca\xfe\xba\xbe"),
            ("META-INF/SIG.SF", b"Signature-Version: 1.0\n"),
            ("META-INF/SIG.RSA", b"signature block"),
            ("lib/native.so", b"\x7fELF"),
            ("BOOT-INF/lib/dep.jar", b"PK\x03\x04"),
            (
                "META-INF/services/com.example.Service",
                b"com.example.Impl\n",
            ),
            ("META-INF/INDEX.LIST", b"JarIndex-Version: 1.0\n"),
            (
                "META-INF/versions/11/com/example/Foo.class",
                b"\xca\xfe\xba\xbe",
            ),
        ]);
        let (v, m) = run(&jar);
        assert_eq!(m.get("jar.class_count"), Some(2.0));
        assert_eq!(m.get("jar.signature_block_count"), Some(1.0));
        assert_eq!(m.get("jar.native_lib_count"), Some(1.0));
        assert_eq!(m.get("jar.service_count"), Some(1.0));
        assert_eq!(m.get("jar.versioned_class_count"), Some(1.0));
        assert_eq!(m.get("jar.index_count"), Some(1.0));
        let feats = v.get("jar.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"signed"));
        assert!(names.contains(&"multi_release"));
        assert!(names.contains(&"native_libs"));
        assert!(names.contains(&"embedded_jars"));
        assert!(names.contains(&"services"));
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
