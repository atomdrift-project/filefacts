use super::*;

#[test]
fn extensionless_abap_report_is_scannable_text() {
    let source = b"REPORT demo.\nREAD REPORT name INTO src.\nLOOP AT src INTO row.\nENDLOOP.\n";
    assert_detect("opaque", source, FileType::Text);
    assert_detect("report.txt", source, FileType::Text);
}

#[test]
fn cms_rexx_exec_is_scannable_text_under_an_opaque_name() {
    let code = b"/* REXX */\nsay 'hello'\npull name\n\"EXECIO * DISKR FILE NAMES A (FIFO\"\ndo while queued() > 0\n say name\nend\n";
    assert_detect("opaque", code, FileType::Text);
    assert_detect("renamed.txt", code, FileType::Text);
    let comment = b"/*\nsay x\npull y\n\"EXECIO * DISKR\"\ndo while x\nend\n*/\n";
    assert_ne!(
        detect(Path::new("opaque"), comment).map(|d| d.file_type),
        Some(FileType::Text)
    );
}

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

/// The smallest MZ image the PE gate accepts: `e_lfanew` (0x3c) pointing
/// just past the DOS header at a `PE\0\0` signature.
fn pe_stub() -> Vec<u8> {
    let mut pe = vec![0u8; 0x44];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c] = 0x40;
    pe[0x40..].copy_from_slice(b"PE\0\0");
    pe
}

/// Assert `data` named `path` is identified as `expected`.
fn assert_detect(path: &str, data: &[u8], expected: FileType) {
    let Some(det) = detect(Path::new(path), data) else {
        panic!("expected {expected:?} for {path}, got None");
    };
    assert_eq!(det.file_type, expected, "wrong type for {path}");
}

/// Assert a type follows from the name alone.
fn assert_ext(path: &str, expected: FileType) {
    assert_detect(path, b"x = 1\n", expected);
}

#[test]
fn shimmer_fat_boot_sector_is_recovered_as_analyzable_data() {
    let shimmer = &crate::fileid::testutil::unzstd(include_bytes!(
        "../../testdata/dos-boot/shimmer-boot-sector.d.zst"
    ));
    let detection = detect(Path::new("Virus.Boot-DOS.Shimmer.d"), shimmer)
        .expect("validated FAT boot sector should be identified");
    assert_eq!(detection.file_type, FileType::FatBootSector);
    assert_eq!(detection.source, DetectionSource::Heuristic);
    assert_eq!(detection.ext_match, ExtensionMatch::Unknown);

    // The boot signature on its own is not a file type. This preserves
    // opaque handling for arbitrary 512-byte blobs that end in 55 AA.
    let mut signature_only = [0x41u8; 512];
    signature_only[510..].copy_from_slice(&[0x55, 0xAA]);
    assert!(
        detect(Path::new("opaque.d"), &signature_only)
            .is_none_or(|d| d.file_type != FileType::FatBootSector)
    );
}

mod binaries;
mod content_first;
mod documents;
mod languages;
mod names;
mod packages;
mod polyglots;
mod scripts_and_bitmaps;

/// Nothing identified is not a heuristic verdict: the source says so.
#[test]
fn an_unidentified_file_has_no_detection_source() {
    let id = FileId::from_path_and_bytes(Path::new("opaque"), b"\x01\x02\x03\x04\x05\x06\x07");
    assert_eq!(id.file_type(), FileType::Unknown);
    assert_eq!(id.source(), DetectionSource::Unidentified);
    assert!(!id.extension_mismatch());
    assert_eq!(
        serde_json::to_value(id).unwrap()["source"],
        serde_json::json!("unidentified")
    );
}

/// A Chrome extension manifest is named by its rule after the signatures,
/// which the bytes alone cannot claim.
#[test]
fn chrome_manifest() {
    let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
    assert_detect("manifest.json", data, FileType::ChromeManifest);
    assert_eq!(
        detect(Path::new("manifest.json"), data).map(|d| d.source),
        Some(DetectionSource::Filename)
    );
}

/// Content alone sees the structural signatures identification sees: a FAT
/// boot sector, a DOS COM program and shellcode need no name.
#[test]
fn detect_content_sees_structural_signatures() {
    let mut boot = [0u8; 512];
    boot[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&1u16.to_le_bytes());
    boot[16] = 2;
    boot[19..21].copy_from_slice(&2880u16.to_le_bytes());
    boot[21] = 0xF0;
    boot[22..24].copy_from_slice(&9u16.to_le_bytes());
    boot[24..26].copy_from_slice(&18u16.to_le_bytes());
    boot[26..28].copy_from_slice(&2u16.to_le_bytes());
    boot[510..].copy_from_slice(&[0x55, 0xAA]);
    assert_eq!(
        detect_content(&boot).map(|d| d.file_type),
        Some(FileType::FatBootSector)
    );
    // mov ah, 9; mov dx, msg; int 21h; int 20h; then the message.
    let com = b"\xb4\x09\xba\x09\x01\xcd\x21\xcd\x20Hello$\0\0\0\0\0\0\0\0\0\0\0";
    assert_eq!(
        detect_content(com).map(|d| d.file_type),
        Some(FileType::DosCom)
    );
}
