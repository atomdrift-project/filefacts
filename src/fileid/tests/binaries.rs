//! Binaries, object code and boot sectors identified by their bytes.

use super::*;

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
    assert_eq!(id.extension_mismatch_transition(), Some(("native", "data")));
}

// ── AppleDouble (._<name>) resource forks ────────────────────────────
// A macOS resource fork (`._foo.php`) is binary metadata, not the type
// its name claims. Magic-byte detection must return Unknown so
// `is_program()` skips analysis.

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
        "AppleDouble bodies must be skipped by is_program(), not analyzed \
             as the type their name claims"
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

// ── Static libraries ─────────────────────────────────────────────

/// A real ar archive is caught by magic in stage 1 and is unaffected.
#[test]
fn real_ar_archive_still_wins() {
    let mut data = b"!<arch>\n".to_vec();
    data.extend_from_slice(&[0x20; 64]);
    assert_eq!(
        detect(Path::new("libfoo.a"), &data).map(|d| d.file_type),
        Some(FileType::StaticLib)
    );
}

/// A variant letter after a family name (`Trojan.BAT.DelAll.a`) looks like
/// an ar archive by extension while the body is a batch script. A genuine
/// `.a` always carries `!<arch>`, so the sniffer is allowed to look inside.
#[test]
fn batch_body_named_dot_a_is_batch() {
    let data = b"@echo off\r\nif not exist c:\\x.bat goto skip\r\nfor %%f in (*.bat) do call %%f\r\n:skip\r\n";
    let d = detect(Path::new("Trojan.BAT.DelAll.a"), data).expect("detected");
    assert_ne!(d.file_type, FileType::StaticLib);
    assert!(d.extension_mismatch());
}

/// An `.a` without `!<arch>` is never a static library. An 8-byte COM
/// program is still a program: `CD 21` is never valid UTF-8.
#[test]
fn dot_a_without_ar_magic_is_its_body() {
    let data = [0xe9u8, 0x12, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xc3];
    assert_eq!(
        detect(Path::new("Virus.DOS.Trivial.40.a"), &data).map(|d| d.file_type),
        Some(FileType::DosCom)
    );
    assert_eq!(
        detect(
            Path::new("Backdoor.IRC.Notes.a"),
            b"see you on the channel tonight\n"
        )
        .map(|d| d.file_type),
        Some(FileType::Text)
    );
}
