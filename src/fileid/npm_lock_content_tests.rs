use super::{FileType, detect, detect_content};
use std::path::Path;

#[test]
fn npm_json_lock_content_versions_and_collected_names() {
    let cases: &[&[u8]] = &[
        br#"{"name":"demo","version":"1.0.0","lockfileVersion":1,"dependencies":{"x":{"version":"1.2.3"}}}"#,
        br#"{"name":"demo","version":"1.0.0","lockfileVersion":2,"packages":{"":{},"node_modules/x":{"version":"1.2.3"}},"dependencies":{}}"#,
        br#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{},"node_modules/x":{"version":"1.2.3"}}}"#,
        br#"{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.2.3"}}}"#,
        br#"{"lockfileVersion":3,"packages":{}}"#,
    ];
    for data in cases {
        assert_eq!(
            detect_content(data).unwrap().file_type,
            FileType::PackageLockJson
        );
        for name in [
            "",
            "8a1e6ad594b0",
            "package-lock.8a1e6ad594b0.json",
            "random.json",
            "npm-shrinkwrap.json",
        ] {
            let d = detect(Path::new(name), data).unwrap();
            assert_eq!(d.file_type, FileType::PackageLockJson, "{name}");
            assert!(!d.extension_mismatch(), "{name}");
        }
        let d = detect(Path::new("unrelated.py"), data).unwrap();
        assert_eq!(d.file_type, FileType::PackageLockJson);
        assert!(d.extension_mismatch());
    }
}

#[test]
fn npm_json_lock_content_bom_whitespace_and_complete_parse() {
    let data = b"\xef\xbb\xbf  \n{\"lockfileVersion\":3,\"packages\":{}} \r\n";
    assert_eq!(
        detect_content(data).unwrap().file_type,
        FileType::PackageLockJson
    );
    for data in [
        br#"{"lockfileVersion":3,"packages":{}}; process.exit(1)"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{"" : {"name":"x"}}"#.as_slice(),
        br#"[ {"lockfileVersion":3,"packages":{}} ]"#.as_slice(),
        br#"{"message":"\"lockfileVersion\":3","packages":{}}"#.as_slice(),
        br#"{"nested":{"lockfileVersion":3,"packages":{}}}"#.as_slice(),
        br#"{"lockfileVersion":"3","packages":{}}"#.as_slice(),
        br#"{"lockfileVersion":4,"packages":{}}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":[]}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{"x":"not a descriptor"}}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{},"requires":"true"}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{},"name":{}}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{},"version":7}"#.as_slice(),
        br#"{"lockfileVersion":1,"packages":{}}"#.as_slice(),
        br#"{"name":"x","version":"1","lockfileVersion":1,"dependencies":[]}"#.as_slice(),
    ] {
        assert_ne!(
            detect_content(data).map(|d| d.file_type),
            Some(FileType::PackageLockJson),
            "{data:?}"
        );
    }
}

#[test]
fn npm_json_lock_content_does_not_hide_javascript_or_binaries() {
    let script = br#"const fixture = '{"lockfileVersion":3,"packages":{}}'; console.log(fixture);"#;
    let d = detect(Path::new("sample.js"), script).unwrap();
    assert_eq!(d.file_type, FileType::JavaScript);
    assert!(!d.extension_mismatch());
    let d = detect(
        Path::new("package-lock.abc.json"),
        b"#!/bin/sh\nprintf hello\n",
    )
    .unwrap();
    assert_eq!(d.file_type, FileType::Shell);
    assert!(d.extension_mismatch());
    let d = detect(
        Path::new("other.json"),
        br#"{"name":"x","version":"1","dependencies":{}}"#,
    )
    .unwrap();
    assert_eq!(d.file_type, FileType::Json);
}
