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
mod scripts_and_bitmaps;
