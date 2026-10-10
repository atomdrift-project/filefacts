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

use crate::formats::common::{ends_with_ci, starts_with_ci};
use crate::metric;
use serde_json::{Value as JsonValue, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use crate::output::{Errors, Metrics, Stage, Values};
use crate::value_key;

/// Cap on a single text entry we'll decompress for parsing
/// (MANIFEST.MF / pom.properties). 1 MiB is generous; anything
/// larger is hostile zip-bomb input.
const MAX_TEXT_BYTES: u64 = 1024 * 1024;

/// `pom.properties` members read while looking for one with a `groupId`.
/// A jar shades a handful of Maven modules at most; each read costs up to
/// [`MAX_TEXT_BYTES`] of inflation, and a hostile jar can list any number
/// of them that never name a group.
const MAX_POM_READS: usize = 16;

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
    errors: &mut Errors,
) {
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
    let mut pom_reads = 0_usize;
    // Duplicate central-directory entries all name the one member a by-name
    // read finds, so the manifest is read once however often it is listed.
    let mut manifest_read = false;

    // An entry that will not open (corrupt local header, unsupported
    // compression or encryption) drops out of every count below. A hostile
    // jar can hold any number of them, so they are reported once, in
    // aggregate.
    let mut names: Vec<String> = Vec::with_capacity(zip.len());
    let mut unreadable = 0usize;
    let mut first_failure = None;
    for i in 0..zip.len() {
        match zip.by_index(i) {
            Ok(file) => names.push(file.name().to_string()),
            Err(e) => {
                unreadable += 1;
                first_failure.get_or_insert_with(|| format!("entry {i}: {e}"));
            }
        }
    }
    if let Some(first) = first_failure {
        errors.record_malformed(
            Stage::ZipParse,
            format!(
                "{unreadable} of {} entries unreadable and left out of the jar counts; first: {first}",
                zip.len()
            ),
        );
    }

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
        // The JDK upper-cases entry names before looking for signature files,
        // so `meta-inf/cert.sf` signs a JAR exactly as `META-INF/CERT.SF` does.
        if starts_with_ci(name, "META-INF/") && ends_with_ci(name, ".SF") {
            signature_count += 1;
        }
        if starts_with_ci(name, "META-INF/")
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
        // Class lookup is by exact name: `Foo.CLASS` is not a class file.
        if name.starts_with("META-INF/versions/")
            && name.rsplit_once('.').is_some_and(|(_, ext)| ext == "class")
        {
            versioned_class_count += 1;
        }
        if name == "META-INF/INDEX.LIST" {
            index_count += 1;
        }
        if name == "META-INF/MANIFEST.MF" {
            if !manifest_read {
                manifest_read = true;
                if let Some(text) = read_text(zip, name, errors) {
                    manifest = parse_manifest(&text);
                }
            }
        } else if pom_group.is_none()
            && pom_reads < MAX_POM_READS
            && name.ends_with("/pom.properties")
        {
            pom_reads += 1;
            if let Some(text) = read_text(zip, name, errors) {
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
        return;
    }

    let class_path_count = manifest
        .as_ref()
        .and_then(|m| m.headers.get("class_path"))
        .map(|v| crate::bytes::sat_u32(v.split_whitespace().count()))
        .unwrap_or(0);
    let boot_class_path_count = manifest
        .as_ref()
        .and_then(|m| m.headers.get("boot_class_path"))
        .map(|v| crate::bytes::sat_u32(v.split_whitespace().count()))
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
        values.insert_key(value_key!("jar.manifest"), JsonValue::Object(obj));
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
        values.insert_key(value_key!("jar.pom"), JsonValue::Object(pom));
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
        values.insert_key(
            value_key!("jar.features"),
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    values.insert_key(value_key!("jar.entry_count"), json!(entry_count));
    values.insert_key(value_key!("jar.class_count"), json!(class_count));
    if embedded_jar_count > 0 {
        values.insert_key(
            value_key!("jar.embedded_jar_count"),
            json!(embedded_jar_count),
        );
    }
    if signature_count > 0 {
        values.insert_key(value_key!("jar.signature_count"), json!(signature_count));
    }
    if signature_block_count > 0 {
        values.insert_key(
            value_key!("jar.signature_block_count"),
            json!(signature_block_count),
        );
    }
    if native_lib_count > 0 {
        values.insert_key(value_key!("jar.native_lib_count"), json!(native_lib_count));
    }
    if service_count > 0 {
        values.insert_key(value_key!("jar.service_count"), json!(service_count));
    }
    if versioned_class_count > 0 {
        values.insert_key(
            value_key!("jar.versioned_class_count"),
            json!(versioned_class_count),
        );
    }
    if index_count > 0 {
        values.insert_key(value_key!("jar.index_count"), json!(index_count));
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
    errors: &mut Errors,
) -> Option<String> {
    // Absent is normal; anything else stopped a member the JAR lists from
    // being read, and is worth stating.
    let buf = match super::zip::read_member(zip, name, MAX_TEXT_BYTES) {
        Ok(buf) => buf?,
        Err(e) => {
            errors.record_malformed(Stage::ZipParse, format!("{name}: {e}"));
            return None;
        }
    };
    String::from_utf8(buf)
        .map_err(|e| {
            errors.record_malformed(Stage::FormatExtract, format!("{name}: not UTF-8: {e}"))
        })
        .ok()
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
    facts.section_count = crate::bytes::sat_u32(sections.len().saturating_sub(1));
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
            // The key is attacker-chosen UTF-8: split with a checked boundary,
            // since `key.len() - 7` can land inside a multi-byte character.
            let digest_suffix = "-Digest";
            if let Some(split) = key
                .len()
                .checked_sub(digest_suffix.len())
                .filter(|&n| n > 0)
                && let Some((algorithm, suffix)) = key.split_at_checked(split)
                && suffix.eq_ignore_ascii_case(digest_suffix)
            {
                facts.digest_count += 1;
                facts
                    .digest_algorithms
                    .insert(algorithm.to_ascii_lowercase());
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
        let (v, m, e) = run_with_errors(bytes);
        assert!(e.is_empty(), "{e:?}");
        (v, m)
    }

    fn run_with_errors(bytes: &[u8]) -> (Values, Metrics, Errors) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut e = Errors::new();
        if let Ok(mut zip) = crate::formats::zip::open_archive(bytes) {
            extract_from_archive(&mut zip, &mut v, &mut m, &mut e);
        }
        (v, m, e)
    }

    /// Rewrite the compression method of every entry named `name`, in both
    /// its local and central-directory header, to PPMd (98), which the zip
    /// crate cannot decompress.
    fn with_unsupported_method(mut jar: Vec<u8>, name: &str) -> Vec<u8> {
        let mut at = 0;
        while let Some(off) = jar[at..]
            .windows(4)
            .position(|w| w == b"PK\x03\x04" || w == b"PK\x01\x02")
        {
            let hdr = at + off;
            let (method_at, name_len_at, name_at) = if jar[hdr + 2] == 3 {
                (hdr + 8, hdr + 26, hdr + 30)
            } else {
                (hdr + 10, hdr + 28, hdr + 46)
            };
            let name_len = u16::from_le_bytes([jar[name_len_at], jar[name_len_at + 1]]) as usize;
            if &jar[name_at..name_at + name_len] == name.as_bytes() {
                jar[method_at..method_at + 2].copy_from_slice(&98u16.to_le_bytes());
            }
            at = hdr + 4;
        }
        jar
    }

    #[test]
    fn unreadable_entries_record_one_aggregate_error() {
        let jar = build_jar(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("a/One.class", b"\xca\xfe\xba\xbe"),
            ("a/Two.class", b"\xca\xfe\xba\xbe"),
            ("a/Three.class", b"\xca\xfe\xba\xbe"),
        ]);
        let jar = with_unsupported_method(jar, "a/One.class");
        let jar = with_unsupported_method(jar, "a/Two.class");
        let (v, m, e) = run_with_errors(&jar);
        assert_eq!(e.len(), 1, "{e:?}");
        let err = &e.as_slice()[0];
        assert_eq!(
            (err.stage, err.kind),
            (Stage::ZipParse, crate::DiagnosticKind::Malformed)
        );
        assert!(
            err.message.starts_with("2 of 4 entries unreadable"),
            "{}",
            err.message
        );
        // The readable entries are still counted.
        assert_eq!(m.get("jar.class_count"), Some(1.0));
        assert!(v.get("jar.manifest.manifest_version").is_some());
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

    /// Only the first `MAX_POM_READS` pom.properties are read: a group named
    /// past them is not found.
    #[test]
    fn pom_properties_reads_are_capped() {
        let names: Vec<String> = (0..=MAX_POM_READS)
            .map(|i| format!("META-INF/maven/g/a{i}/pom.properties"))
            .collect();
        let mut entries: Vec<(&str, &[u8])> = names[..MAX_POM_READS]
            .iter()
            .map(|n| (n.as_str(), b"version=1\n".as_slice()))
            .collect();
        entries.push((&names[MAX_POM_READS], b"groupId=late\n"));
        let (v, _) = run(&build_jar(&entries));
        assert!(v.get("jar.pom.group_id").is_none());

        // The same group inside the cap is found.
        entries.swap(0, MAX_POM_READS);
        let (v, _) = run(&build_jar(&entries));
        assert_eq!(
            v.get("jar.pom.group_id").and_then(|x| x.as_str()),
            Some("late")
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

    /// A key whose `-Digest` suffix offset falls inside a multi-byte
    /// character used to panic on the str slice and lose every `jar.*` fact.
    #[test]
    fn multibyte_manifest_key_does_not_panic() {
        let jar = build_jar(&[(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n\nName: x\n\u{20ac}abcdef: v\n\u{e9}-Digest: q\n".as_bytes(),
        )]);
        let (v, m) = run(&jar);
        assert_eq!(
            v.get("jar.manifest.manifest_version")
                .and_then(|x| x.as_str()),
            Some("1.0")
        );
        assert_eq!(m.get("jar.manifest.digest_count"), Some(1.0));
        assert_eq!(
            v.get("jar.manifest.digest_algorithms")
                .and_then(|x| x.as_array())
                .and_then(|x| x.first())
                .and_then(|x| x.as_str()),
            Some("\u{e9}")
        );
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
