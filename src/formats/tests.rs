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

/// A melange recipe exposes the GitHub owners its source steps read from and
/// the owner its update monitor tracks; a document `melange` key never
/// stands in for them, and other YAML gets neither.
#[test]
fn melange_recipe_exposes_source_and_update_owners() {
    let recipe = br"package:
  name: beat-exporter
  version: 0.3.0
melange:
  update_github_owner: forged
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/Fork-Owner/beat-exporter
  - uses: fetch
    with:
      uri: https://github.com/fork-owner/x/raw/main/x.tar.gz
  - uses: go/build
update:
  github:
    identifier: Trustpilot/beat-exporter
";
    let opened = crate::OpenOptions::new()
        .file_type(crate::FileType::Yaml)
        .open(recipe);
    let values = opened.values();
    assert_eq!(
        values.get("melange.source_github_owners"),
        Some(&serde_json::json!(["fork-owner"]))
    );
    assert_eq!(
        values.get("melange.update_github_owner"),
        Some(&serde_json::json!("trustpilot"))
    );

    let other = crate::OpenOptions::new()
        .file_type(crate::FileType::Yaml)
        .open(b"melange:\n  update_github_owner: forged\npipeline: []\n");
    assert_eq!(
        other.values().get("melange.update_github_owner"),
        Some(&serde_json::json!("forged"))
    );
}

#[test]
fn pe_certificate_range_reads_security_directory() {
    let mut pe_data = vec![0u8; 0x420];
    pe_data[0..2].copy_from_slice(b"MZ");
    pe_data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe_data[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
    pe_data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe_data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    pe_data[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());
    pe_data[0x80 + 24 + 92..0x80 + 24 + 96].copy_from_slice(&16u32.to_le_bytes());

    let data_directories = 0x80 + 24 + 96;
    let security_dir = data_directories + (4 * 8);
    pe_data[security_dir..security_dir + 4].copy_from_slice(&0x300u32.to_le_bytes());
    pe_data[security_dir + 4..security_dir + 8].copy_from_slice(&0x120u32.to_le_bytes());

    let section_table = 0x80 + 24 + 0xE0;
    pe_data[section_table..section_table + 5].copy_from_slice(b".text");
    pe_data[section_table + 16..section_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
    pe_data[section_table + 20..section_table + 24].copy_from_slice(&0x100u32.to_le_bytes());

    // WIN_CERTIFICATE header at the certificate table offset (0x300)
    pe_data[0x300..0x304].copy_from_slice(&0x120u32.to_le_bytes());
    pe_data[0x304..0x306].copy_from_slice(&0x0200u16.to_le_bytes());
    pe_data[0x306..0x308].copy_from_slice(&0x0002u16.to_le_bytes());

    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("synthetic.exe"))
        .open(&pe_data);
    assert_eq!(
        super::pe_certificate_range(parsed.values(), pe_data.len()),
        Some(0x300..0x420),
    );
}
