use super::*;
use crate::{ArchiveFormat, FileId, FileType};
use std::io::{Cursor, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;

fn recognized_bytes(data: &[u8]) -> bool {
    recognized(&Sniff::new(Path::new(""), data))
}

fn module_zip(names: &[&str]) -> Vec<u8> {
    let members: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (*n, &b"package hello\n"[..]))
        .collect();
    crate::fileid::testutil::zip(&members)
}

#[test]
fn go_module_downloads_have_a_stable_type_without_a_filename() {
    for prefix in [
        "example.com/hello@v1.2.3",
        "github.com/BurntSushi/toml@v1.4.0",
        "tailscale.com@v1.102.3",
        "example.com/lib/v2@v2.0.0-rc.1",
        "example.com/lib@v4.4.0+incompatible",
        "example.com/lib@v0.0.0-20260528132821-f66b8cdce5b3",
    ] {
        {
            // README alone also covers legacy releases with no go.mod.
            let data = module_zip(&[&format!("{prefix}/README.md")]);
            for filename in ["v1.2.3.zip", "download", "deadbeef", "archive.jar"] {
                let id = FileId::from_path_and_bytes(Path::new(filename), &data);
                assert_eq!(id.file_type(), FileType::GoModule, "{prefix}: {filename}");
                if filename.ends_with(".zip") {
                    assert!(!id.extension_mismatch());
                }
            }
            let parsed = crate::OpenOptions::new().cache(false).open(&data);
            assert_eq!(parsed.fileid().file_type(), FileType::GoModule);
            assert_eq!(parsed.archive_members().len(), 1);
            assert!(parsed.errors().is_empty());
            assert_eq!(
                FileType::GoModule.archive_format(),
                Some(ArchiveFormat::Zip)
            );
            let encoded = serde_json::to_string(&FileType::GoModule).unwrap();
            assert_eq!(encoded, "\"go_module\"");
            assert_eq!(
                serde_json::from_str::<FileType>(&encoded).unwrap(),
                FileType::GoModule
            );
        }
    }
}

#[test]
fn go_writer_data_descriptors_are_detected_from_the_central_directory() {
    // Produced by Go archive/zip, with zero sizes in local headers.
    let data = include_bytes!("../testdata/go-module-stream.zip");
    assert_eq!(&data[18..26], &[0; 8]);
    assert!(recognized_bytes(data));
    assert_eq!(FileId::from_bytes(data).file_type(), FileType::GoModule);
    assert!(!recognized_bytes(&data[..data.len() / 2]));
}

#[test]
fn incidental_go_files_and_mixed_roots_are_not_modules() {
    for names in [
        vec!["go.mod", "hello.go"],
        vec!["repo-main/go.mod", "repo-main/hello.go"],
        vec!["example.com/hello@v1.2.3/go.mod", "other/payload"],
        vec![
            "example.com/hello@v1.2.3/go.mod",
            "example.com/hello@v1.2.4/x.go",
        ],
        vec!["example.com/hello@v1.2.3/../escape"],
        vec!["example.com/hello@v1.2.3/a//b"],
        vec!["example.com/hello@v1.2.3/a\\b"],
        vec!["example.com/hello@latest/go.mod"],
        vec!["example.com/hello@v01.2.3/go.mod"],
        vec!["example.com/hello@v1.2.3+meta/go.mod"],
        vec!["backup/hello@v1.2.3/go.mod"],
        vec!["../example.com/hello@v1.2.3/go.mod"],
    ] {
        assert!(!recognized_bytes(&module_zip(&names)), "{names:?}");
    }
    // Marker text in a stored nested ZIP must not identify its wrapper.
    let inner = module_zip(&["example.com/hello@v1.2.3/go.mod"]);
    let mut outer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    outer
        .start_file("payload.zip", SimpleFileOptions::default())
        .unwrap();
    outer.write_all(&inner).unwrap();
    assert!(!recognized_bytes(&outer.finish().unwrap().into_inner()));
    assert!(!recognized_bytes(
        b"PK\x03\x04example.com/hello@v1.2.3/go.mod"
    ));
}
