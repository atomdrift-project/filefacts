use crate::fileid::testutil::{self, zip};
use crate::{ArchiveFormat, FileId, FileType};
use std::path::Path;

fn tar(members: &[(&str, &[u8])], gzip: bool) -> Vec<u8> {
    let data = testutil::tar(members);
    if gzip { testutil::gzip(&data) } else { data }
}

fn identifies(bytes: &[u8], kind: FileType) {
    for path in ["download", "deadbeef", "artifact.tar.gz", "archive.zip"] {
        let id = FileId::from_path_and_bytes(Path::new(path), bytes);
        assert_eq!(id.file_type(), kind, "{path}");
    }
    let parsed = crate::OpenOptions::new().cache(false).open(bytes);
    assert_eq!(parsed.fileid().file_type(), kind);
    assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
    // These fields feed container fallback models independently of the
    // ecosystem-specific label.
    let container = kind.archive_format().unwrap();
    assert_eq!(
        parsed
            .values()
            .get("archive.container.archive")
            .and_then(serde_json::Value::as_str),
        Some(container.label())
    );
    let label = serde_json::to_string(&kind).unwrap();
    assert_eq!(serde_json::from_str::<FileType>(&label).unwrap(), kind);
}

#[test]
fn source_package_types_survive_renamed_downloads() {
    let cases: Vec<(FileType, Vec<u8>)> = vec![
        (FileType::Crate, tar(&[("demo-1.2.3/Cargo.toml", b"[package]\nname='demo'\nversion='1.2.3'\n")], true)),
        (FileType::Pub, tar(&[("lib/demo.dart", b"library demo;"), ("pubspec.yaml", b"name: demo\nversion: '1.2.3'\nenvironment:\n  sdk: ^3.4.0\n")], true)),
        (FileType::Cran, tar(&[("demo/DESCRIPTION", b"Package: demo\nVersion: 1.2.3\nTitle: Example\nDescription: Example package.\n")], true)),
        (FileType::Cpan, tar(&[("Demo-1.23/META.json", br#"{"name":"Demo","version":"1.23","meta-spec":{"version":2}}"#)], true)),
        (FileType::Cpan, tar(&[("Demo-1.23/META.yml", b"---\nname: Demo\nversion: '1.23'\nmeta-spec:\n  version: '1.4'\n")], true)),
        (FileType::Hackage, tar(&[("demo-0.1.2.3/demo.cabal", b"Name: demo\nVersion: 0.1.2.3\nCabal-Version: >=1.10\n")], true)),
        (FileType::Hex, tar(&[("VERSION", b"3"), ("CHECKSUM", &[b'A';64]), ("metadata.config", b"{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.2.3\">>}."), ("contents.tar.gz", b"\x1f\x8b\x08\0")], false)),
        (FileType::Composer, zip(&[("demo-main/composer.json", br#"{"name":"vendor/demo","require":{"php":">=8.0"}}"#), ("demo-main/src/Demo.php", b"<?php echo 1;")])),
        (FileType::Composer, zip(&[("composer.json", br#"{"name":"vendor/demo"}"#), ("src/Demo.php", b"<?php echo 1;")])),
    ];
    for (kind, bytes) in cases {
        identifies(&bytes, kind);
    }
}

#[test]
fn incidental_manifests_do_not_name_the_outer_archive() {
    for members in [
        vec![(
            "repo/docs/demo/Cargo.toml",
            &b"[package]\nname='demo'\nversion='1.2.3'\n"[..],
        )],
        vec![(
            "repo/Cargo.toml",
            &b"[package]\nname='demo'\nversion='1.2.3'\n"[..],
        )],
        vec![(
            "repo/sub/pubspec.yaml",
            &b"name: demo\nversion: 1.2.3\n"[..],
        )],
        vec![(
            "demo/DESCRIPTION",
            &b"Package: other\nVersion: 1.0\nTitle: x\nDescription: y\n"[..],
        )],
        vec![(
            "Demo-1.0/META.json",
            &br#"{"name":"Demo","version":"1.0"}"#[..],
        )],
        vec![("demo-1.0/demo.cabal", &b"name: other\nversion: 1.0\n"[..])],
        vec![
            ("VERSION", &b"3"[..]),
            ("CHECKSUM", &b"bad"[..]),
            ("metadata.config", &b"x"[..]),
            ("contents.tar.gz", &b"x"[..]),
        ],
        vec![
            (
                "demo-1.2.3/Cargo.toml",
                &b"[package]\nname='demo'\nversion='1.2.3'\n"[..],
            ),
            ("unrelated/payload", &b"x"[..]),
        ],
    ] {
        assert_eq!(
            FileId::from_bytes(&tar(&members, true)).file_type(),
            FileType::TarGz,
            "{members:?}"
        );
    }
    for members in [
        vec![(
            "repo/vendor/lib/composer.json",
            &br#"{"name":"vendor/lib"}"#[..],
        )],
        vec![("repo/composer.json", &b"{}"[..])],
        vec![
            ("repo/composer.json", &br#"{"name":"vendor/lib"}"#[..]),
            ("other/file", &b"x"[..]),
        ],
        vec![("repo/composer.json", &b"{broken"[..])],
    ] {
        assert_eq!(
            FileId::from_bytes(&zip(&members)).file_type(),
            FileType::Zip
        );
    }
    assert_eq!(
        FileType::Composer.archive_format(),
        Some(ArchiveFormat::Zip)
    );
}

#[test]
fn rootless_pub_manifest_may_follow_many_source_files() {
    let names: Vec<String> = (0..100).map(|i| format!("lib/source{i}.dart")).collect();
    let mut members: Vec<_> = names
        .iter()
        .map(|s| (s.as_str(), &b"library demo;"[..]))
        .collect();
    members.push(("README.md", b"documentation"));
    members.push(("pubspec.yaml", b"name: demo\nversion: 1.2.3\n"));
    identifies(&tar(&members, true), FileType::Pub);
}

#[test]
fn oversized_manifests_remain_generic() {
    let mut oversized = b"name: demo\nversion: 1.2.3\n# ".to_vec();
    oversized.resize(super::MANIFEST_LIMIT as usize + 1, b'a');
    assert_eq!(
        FileId::from_bytes(&tar(&[("pubspec.yaml", &oversized)], true)).file_type(),
        FileType::TarGz
    );
    assert_eq!(
        FileId::from_bytes(&zip(&[("composer.json", &oversized)])).file_type(),
        FileType::Zip
    );
}
