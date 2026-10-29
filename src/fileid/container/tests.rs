use super::*;

#[test]
fn specialty_tar_packages_decompose_to_tar() {
    // Uncompressed tar at heart.
    assert_eq!(FileType::Gem.archive_format(), Some(ArchiveFormat::Tar));
    assert_eq!(
        FileType::Gem.container(),
        Some(Container {
            archive: ArchiveFormat::Tar,
            compression: Compression::None,
        })
    );
    // Gzipped tar.
    assert_eq!(
        FileType::Npm.container().map(|c| c.compression),
        Some(Compression::Gzip)
    );
    assert_eq!(
        FileType::PythonSdist.container().map(|c| c.compression),
        Some(Compression::Gzip)
    );
    // Zstd tar.
    assert_eq!(
        FileType::Xbps.container().map(|c| c.compression),
        Some(Compression::Zstd)
    );
}

#[test]
fn tar_xz_decomposes_to_tar_and_xz() {
    let c = FileType::TarXz.container().expect("tar.xz decomposes");
    assert_eq!(c.archive, ArchiveFormat::Tar);
    assert_eq!(c.compression, Compression::Xz);
    assert_eq!(c.archive.label(), "tar");
    assert_eq!(c.compression.label(), "xz");
}

#[test]
fn zip_packages_report_uncompressed_zip_container() {
    // The zip container itself is not compressed; its members are.
    for ft in [
        FileType::Whl,
        FileType::GoModule,
        FileType::Jar,
        FileType::Nupkg,
        FileType::Conda,
    ] {
        assert_eq!(
            ft.container(),
            Some(Container {
                archive: ArchiveFormat::Zip,
                compression: Compression::None,
            }),
            "{ft:?} should be an uncompressed zip container"
        );
    }
}

#[test]
fn non_archive_types_have_no_container() {
    for ft in [
        FileType::Elf,
        FileType::Pe,
        FileType::Python,
        FileType::Json,
    ] {
        assert_eq!(ft.archive_format(), None);
        assert_eq!(ft.container(), None);
    }
}

#[test]
fn pure_compression_wrappers_have_no_container() {
    // Single-file compression carries no multi-file container of its own.
    for ft in [FileType::Gz, FileType::Bz2, FileType::Xz, FileType::Zst] {
        assert_eq!(ft.archive_format(), None);
    }
}

#[test]
fn non_tar_containers_map_correctly() {
    assert_eq!(FileType::Deb.archive_format(), Some(ArchiveFormat::Ar));
    assert_eq!(
        FileType::PkgMacos.archive_format(),
        Some(ArchiveFormat::Xar)
    );
    assert_eq!(
        FileType::SevenZ.archive_format(),
        Some(ArchiveFormat::SevenZip)
    );
    assert_eq!(FileType::Asar.archive_format(), Some(ArchiveFormat::Asar));
}

#[test]
fn pkg_arch_compression_resolved_from_bytes() {
    // Declared default is zstd...
    assert_eq!(
        FileType::PkgArch.container().map(|c| c.compression),
        Some(Compression::Zstd)
    );
    // ...but the bytes win: an xz-wrapped Arch package resolves to xz.
    let xz_magic = [0xfd, b'7', b'z', b'X', b'Z', 0x00, 0x00, 0x00];
    assert_eq!(
        container_of(FileType::PkgArch, &xz_magic).map(|c| c.compression),
        Some(Compression::Xz)
    );
    // A gzip-wrapped one resolves to gzip.
    let gz_magic = [0x1f, 0x8b, 0x08, 0x00];
    assert_eq!(
        container_of(FileType::PkgArch, &gz_magic).map(|c| c.compression),
        Some(Compression::Gzip)
    );
    // Unrecognizable leading bytes fall back to the declared default.
    assert_eq!(
        container_of(FileType::PkgArch, b"not magic").map(|c| c.compression),
        Some(Compression::Zstd)
    );
}

#[test]
fn container_of_matches_static_for_unambiguous_types() {
    // For every type but PkgArch the bytes are irrelevant.
    assert_eq!(
        container_of(FileType::Npm, b"anything"),
        FileType::Npm.container()
    );
    assert_eq!(container_of(FileType::Elf, b"anything"), None);
}
