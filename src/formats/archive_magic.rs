//! What archive or compressed stream a run of bytes starts with, by magic.
//!
//! Used for the data appended past a program's image (`binary.overlay_archive`:
//! the self-extractor's payload, an AppImage's squashfs) and by callers
//! classifying a decoded blob.

/// The archive or compression format `bytes` begins with: `zip`, `7z`,
/// `rar`, `gz`, `xz`, `zst`, `bz2`, `cab`, `lzh`, `cpio`, `squashfs`, `iso`.
#[must_use]
pub fn archive_magic(bytes: &[u8]) -> Option<&'static str> {
    const STARTS: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "zip"),
        (b"7z\xBC\xAF\x27\x1C", "7z"),
        (b"Rar!\x1A\x07", "rar"),
        (b"\x1F\x8B", "gz"),
        (b"\xFD7zXZ\x00", "xz"),
        (b"\x28\xB5\x2F\xFD", "zst"),
        (b"BZh", "bz2"),
        (b"MSCF", "cab"),
        (b"-lh", "lzh"),
        (b"070701", "cpio"),
        (b"070702", "cpio"),
        (b"hsqs", "squashfs"),
        (b"sqsh", "squashfs"),
    ];
    if bytes.len() < 4 {
        return None;
    }
    if let Some((_, kind)) = STARTS.iter().find(|(magic, _)| bytes.starts_with(magic)) {
        return Some(kind);
    }
    // ISO 9660: the primary volume descriptor's identifier, 16 sectors in.
    (bytes.get(0x8001..0x8006) == Some(b"CD001")).then_some("iso")
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn known_magics() {
        for (bytes, kind) in [
            (&b"PK\x03\x04rest"[..], "zip"),
            (b"7z\xBC\xAF\x27\x1Crest", "7z"),
            (b"Rar!\x1A\x07\x00rest", "rar"),
            (b"Rar!\x1A\x07\x01\x00rest", "rar"),
            (b"\x1F\x8B\x08\x00", "gz"),
            (b"\xFD7zXZ\x00rest", "xz"),
            (b"\x28\xB5\x2F\xFDrest", "zst"),
            (b"BZh9rest", "bz2"),
            (b"MSCFrest", "cab"),
            (b"-lh5-rest", "lzh"),
            (b"070701rest", "cpio"),
            (b"hsqsrest", "squashfs"),
            (b"sqshrest", "squashfs"),
        ] {
            assert_eq!(archive_magic(bytes), Some(kind), "{kind}");
        }
    }

    #[test]
    fn iso_volume_descriptor() {
        let mut iso = vec![0u8; 0x8010];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(archive_magic(&iso), Some("iso"));
    }

    #[test]
    fn not_archives() {
        // A partial 7z magic, a PKCS#7 signature, short and empty input.
        for bytes in [&b"7z\xBC\xAFxx"[..], b"\x30\x82\x05\x00", b"PK", b""] {
            assert_eq!(archive_magic(bytes), None);
        }
    }
}
