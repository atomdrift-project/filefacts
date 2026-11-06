use std::io::Write;

#[test]
fn yaml_type_populates_mapping_and_sequence_values() {
    let mapping = crate::OpenOptions::new()
        .file_type(crate::FileType::Yaml)
        .open(b"tasks:\n  lint:\n    cmds: [go test]\n");
    assert_eq!(
        mapping.values().get("tasks.lint.cmds[0]"),
        Some(&serde_json::json!("go test"))
    );
    let sequence = crate::OpenOptions::new()
        .file_type(crate::FileType::Yaml)
        .open(b"- title: Guide\n  url: guide\n");
    assert_eq!(
        sequence.values().get("root[0].title"),
        Some(&serde_json::json!("Guide"))
    );
}

#[test]
fn inflated_cws_exposes_the_remote_movie_url() {
    let movie = b"http://cdn.example/x\x00ff.swf\x00";
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(movie).unwrap();
    let compressed = enc.finish().unwrap();
    let mut file = b"CWS\x08".to_vec();
    file.extend_from_slice(&((8 + movie.len()) as u32).to_le_bytes());
    file.extend_from_slice(&compressed);
    let opened = crate::open(&file);
    let extracted = opened.extracted();
    let text: Vec<&str> = extracted
        .strings
        .text
        .iter()
        .map(|s| s.value.as_str())
        .collect();
    assert!(
        text.iter().any(|s| s.contains("http://cdn.example/x")),
        "{text:?}"
    );
    assert!(text.iter().any(|s| s.contains("ff.swf")), "{text:?}");
}

#[test]
fn oversized_package_json_is_skipped_like_generic_json() {
    let mut manifest = br#"{"name":"pad","description":""#.to_vec();
    manifest.resize(manifest.len() + (2 << 20), b' ');
    manifest.extend_from_slice(br#""}"#);
    let parsed = crate::OpenOptions::new()
        .cache(false)
        .file_type(crate::FileType::PackageJson)
        .open(&manifest);
    let values = parsed.values();
    assert_eq!(
        values.get("json.parse.skipped"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(values.get("npm.name"), None);

    let small = crate::OpenOptions::new()
        .cache(false)
        .file_type(crate::FileType::PackageJson)
        .open(br#"{"name":"ok","maintainers":["a <a@x.org>"]}"#);
    assert_eq!(
        small.values().get("npm.name"),
        Some(&serde_json::json!("ok"))
    );
    assert_eq!(small.values().get("name"), Some(&serde_json::json!("ok")));
}
