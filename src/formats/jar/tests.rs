use super::*;
use crate::formats::testutil::stored_zip;

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let (v, m, e) = run_with_errors(bytes);
    assert!(e.is_empty(), "{e:?}");
    (v, m)
}

#[test]
fn embedded_pom_dependencies_reach_the_typed_reference_view() {
    let jar = stored_zip(&[("META-INF/maven/g/app/pom.xml", br#"<project>
          <dependencies>
            <dependency><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId><version>2.0.20</version></dependency>
            <dependency><groupId>g</groupId><artifactId>tests</artifactId><version>1</version><scope>test</scope><optional>true</optional></dependency>
            <dependency><groupId>g</groupId><artifactId>inherited</artifactId></dependency>
          </dependencies></project>"#)]);
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("app.jar"))
        .open(&jar);
    let refs = parsed.references();
    assert_eq!(refs.len(), 2, "{refs:?}");
    assert_eq!(
        refs[0].locator,
        crate::RefLocator::Purl("pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.0.20".into())
    );
    assert_eq!(
        refs[0].context.as_ref().unwrap().scope,
        crate::DependencyScope::Runtime
    );
    assert!(
        refs[0].offset.is_none(),
        "compressed member evidence has no outer-file offset"
    );
    assert_eq!(
        refs[1].context.as_ref().unwrap().scope,
        crate::DependencyScope::Development
    );
    assert!(refs[1].context.as_ref().unwrap().optional);
    assert_eq!(
        parsed
            .values()
            .get("jar.pom.dependency_gaps")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn embedded_pom_read_budget_preserves_a_gap() {
    let names: Vec<_> = (0..MAX_POM_READS + 2)
        .map(|i| format!("META-INF/maven/g/app{i}/pom.xml"))
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"<project/>".as_slice()))
        .collect();
    let jar = stored_zip(&entries);
    let (values, _) = run(&jar);
    let gaps = values
        .get("jar.pom.dependency_gaps")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0]["reason"].as_str().unwrap().contains("read limit"));
}

fn run_with_errors(bytes: &[u8]) -> (Values, Metrics, Errors) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut e = Errors::new();
    if let Some(mut zip) = crate::formats::testutil::open_zip(bytes) {
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

/// Entries the zip crate cannot open still count: the names come from
/// the central directory.
#[test]
fn undecodable_entries_still_count() {
    let jar = stored_zip(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ("a/One.class", b"\xca\xfe\xba\xbe"),
        ("a/Two.class", b"\xca\xfe\xba\xbe"),
        ("a/Three.class", b"\xca\xfe\xba\xbe"),
    ]);
    let jar = with_unsupported_method(jar, "a/One.class");
    let jar = with_unsupported_method(jar, "a/Two.class");
    let (v, m, e) = run_with_errors(&jar);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(m.get("jar.class_count"), Some(3.0));
    assert!(v.get("jar.manifest.manifest_version").is_some());
}

#[test]
fn surfaces_manifest_attribution() {
    let jar = stored_zip(&[(
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
    let jar = stored_zip(&[("META-INF/MANIFEST.MF", text.as_bytes())]);
    let (v, _) = run(&jar);
    assert_eq!(
        v.get("jar.manifest.implementation_title")
            .and_then(|x| x.as_str()),
        Some("A long title that spanscontinuation lines per JAR spec")
    );
}

#[test]
fn manifest_agent_and_signature_metadata_surface() {
    let jar = stored_zip(&[(
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
    let jar = stored_zip(&[
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
    let jar = stored_zip(&[(
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
    let (v, _) = run(&stored_zip(&entries));
    assert!(v.get("jar.pom.group_id").is_none());

    // The same group inside the cap is found.
    entries.swap(0, MAX_POM_READS);
    let (v, _) = run(&stored_zip(&entries));
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
    let jar = stored_zip(&[]);
    let (v, _) = run(&jar);
    // Empty zip → entry_count would be 0 and manifest empty,
    // so the extractor short-circuits.
    assert!(v.get("jar.entry_count").is_none());
}

#[test]
fn manifest_unknown_keys_dropped() {
    let jar = stored_zip(&[(
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

/// A key whose `-Digest` suffix offset falls inside a multi-byte character
/// is read without slicing the character apart.
#[test]
fn multibyte_manifest_key_does_not_panic() {
    let jar = stored_zip(&[(
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
    let jar = stored_zip(&[
        ("a.class", b"\xca\xfe\xba\xbe"),
        ("b.class", b"\xca\xfe\xba\xbe"),
        ("c.txt", b"hello"),
    ]);
    let (_, m) = run(&jar);
    assert_eq!(m.get("jar.entry_count"), Some(3.0));
    assert_eq!(m.get("jar.class_count"), Some(2.0));
}
