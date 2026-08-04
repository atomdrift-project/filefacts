//! Archive-container decomposition for packaged file types.
//!
//! Many ecosystem package formats are, underneath their format-specific
//! identity, just a well-known archive container wrapped in a compression
//! codec: a `.gem` is an uncompressed `tar`, a `.crate` is a gzipped `tar`,
//! a `.whl` is a `zip`. The mapping from each [`FileType`] to that pair lives
//! here, so a consumer can ask "what archive and compression underlie this
//! type?" without re-encoding the per-format knowledge.
//!
//! The decomposition has two levels:
//!
//! - [`FileType::archive_format`] — the container archive, known from the
//!   type alone and never ambiguous. This is the stable key for model
//!   selection: route to a specialist for the exact type when one exists,
//!   else fall back to the container (ignoring compression).
//! - [`FileType::container`] / [`container_of`] — the full
//!   archive-plus-compression pair. Compression is fixed by the type for every
//!   variant except Arch Linux packages ([`FileType::PkgArch`]), whose
//!   `.pkg.tar.{zst,xz,gz}` codec is not pinned by the type alone;
//!   [`container_of`] resolves that one case from the leading magic bytes.

use serde::{Deserialize, Serialize};

use crate::fileid::FileType;

/// The archive container format underlying a packaged file type.
///
/// This names the *container* — the multi-file archive structure — not any
/// per-member codec. A `zip`-family package reports [`ArchiveFormat::Zip`]
/// even though its members are individually deflated, because the container
/// itself is not compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// POSIX/GNU/pax tar — the container under gem, crate, sdist, npm, the
    /// compressed-tar distro packages, and OCI/Gentoo image bundles.
    Tar,
    /// ZIP — the container under jar, whl, nupkg, vsix, xpi, crx, conda,
    /// egg, ipa, apk (Android), odf, and bare zips.
    Zip,
    /// Unix `ar` archive — the container under a Debian `.deb`.
    Ar,
    /// Apple XAR — the container under a macOS installer `.pkg`.
    Xar,
    /// 7-Zip container.
    SevenZip,
    /// RAR container.
    Rar,
    /// Microsoft Cabinet container.
    Cab,
    /// Electron ASAR application archive.
    Asar,
    /// ISO 9660 optical-disc filesystem — the container under a `.iso`.
    /// A filesystem rather than an archive: members are stored verbatim in
    /// addressable sector runs, so there is no per-member codec.
    Iso9660,
}

impl ArchiveFormat {
    /// Stable lowercase label, matching the container vocabulary cleave emits
    /// in `archive.format.kind` (`tar`, `zip`, …).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::Zip => "zip",
            Self::Ar => "ar",
            Self::Xar => "xar",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Cab => "cab",
            Self::Asar => "asar",
            Self::Iso9660 => "iso9660",
        }
    }
}

impl std::fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// The compression codec wrapping an archive container at the top level of the
/// byte stream.
///
/// [`Compression::None`] means the container bytes are stored verbatim — which
/// is the honest answer for zip-family packages, whose members are compressed
/// individually rather than the container as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Compression {
    /// No top-level compression wrapper.
    None,
    /// gzip (`.tar.gz`, npm, crate, sdist, Alpine apk).
    Gzip,
    /// bzip2 (`.tar.bz2`).
    Bzip2,
    /// xz (`.tar.xz`).
    Xz,
    /// raw LZMA.
    Lzma,
    /// Zstandard (`.tar.zst`, FreeBSD pkg, Void xbps).
    Zstd,
}

impl Compression {
    /// Stable lowercase label (`none`, `gzip`, `bzip2`, `xz`, `lzma`, `zstd`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Zstd => "zstd",
        }
    }

    /// Whether the archive bytes carry a top-level compression wrapper.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Identify a compression codec from the leading magic bytes, when they
    /// match one of the recognized wrappers. Used to resolve the codec for
    /// types whose [`FileType`] does not pin it.
    #[must_use]
    fn sniff(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(&[0x1f, 0x8b]) {
            Some(Self::Gzip)
        } else if bytes.starts_with(b"BZh") {
            Some(Self::Bzip2)
        } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            Some(Self::Xz)
        } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Some(Self::Zstd)
        } else {
            None
        }
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// An archive container paired with the compression wrapping it — the
/// decomposition of a packaged [`FileType`] into its transport layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Container {
    /// The container archive format.
    pub archive: ArchiveFormat,
    /// The top-level compression wrapping the container.
    pub compression: Compression,
}

impl FileType {
    /// The archive container format underlying this type, or `None` when the
    /// type is not an archive-backed package.
    ///
    /// `None` covers source, binaries, and manifests, and also the pure
    /// single-file compression wrappers (`.gz`, `.bz2`, `.xz`, `.zst`): those
    /// carry no multi-file container of their own, so there is nothing to name
    /// here — a consumer decompresses them and re-identifies the inner bytes.
    ///
    /// The returned format is the stable key for model selection: prefer a
    /// specialist trained for the exact [`FileType`], and fall back to the
    /// container format (ignoring compression) when none exists.
    #[must_use]
    pub const fn archive_format(self) -> Option<ArchiveFormat> {
        use ArchiveFormat::{Ar, Asar, Cab, Iso9660, Rar, SevenZip, Tar, Xar, Zip};
        Some(match self {
            // Tar containers: plain, the compressed `.tar.*` variants, and the
            // ecosystem packages that are a tar at heart (uncompressed gem /
            // OCI / Gentoo, gzipped npm / crate / sdist / Alpine apk, zstd
            // FreeBSD / Void, and Arch's variably-compressed `.pkg.tar.*`).
            Self::Tar
            | Self::TarGz
            | Self::TarBz2
            | Self::TarXz
            | Self::TarZst
            | Self::Gem
            | Self::OciImage
            | Self::GentooBinpkg
            | Self::Npm
            | Self::Crate
            | Self::PythonSdist
            | Self::ApkAlpine
            | Self::Xbps
            | Self::PkgFreebsd
            | Self::PkgArch => Tar,
            // ZIP containers: bare zips and every zip-based package format.
            Self::Zip
            | Self::ApkAndroid
            | Self::Conda
            | Self::Egg
            | Self::Ipa
            | Self::Nupkg
            | Self::Vsix
            | Self::Xpi
            | Self::Whl
            | Self::Jar
            | Self::Odf
            | Self::Crx => Zip,
            Self::Deb => Ar,
            Self::PkgMacos => Xar,
            Self::SevenZ => SevenZip,
            Self::Rar => Rar,
            Self::Cab => Cab,
            Self::Asar => Asar,
            Self::Iso => Iso9660,
            _ => return None,
        })
    }

    /// The full archive-plus-compression decomposition of this type, derived
    /// from the type alone, or `None` for non-archive types (see
    /// [`FileType::archive_format`]).
    ///
    /// Compression is exact for every type except Arch Linux packages
    /// ([`FileType::PkgArch`]), whose `.pkg.tar.{zst,xz,gz}` codec the type
    /// does not pin; this reports its modern default ([`Compression::Zstd`]).
    /// Call [`container_of`] with the file bytes to resolve that case exactly.
    #[must_use]
    pub const fn container(self) -> Option<Container> {
        let Some(archive) = self.archive_format() else {
            return None;
        };
        Some(Container {
            archive,
            compression: self.declared_compression(),
        })
    }

    /// The compression a type's [`FileType`] declares on its own, before any
    /// byte inspection. For [`FileType::PkgArch`] this is the modern Arch
    /// default; [`container_of`] refines it from the bytes.
    const fn declared_compression(self) -> Compression {
        use Compression::{Bzip2, Gzip, None, Xz, Zstd};
        match self {
            Self::TarGz | Self::Npm | Self::Crate | Self::PythonSdist | Self::ApkAlpine => Gzip,
            Self::TarBz2 => Bzip2,
            Self::TarXz => Xz,
            // Arch packages vary across zst/xz/gz; zstd is the current default
            // and `container_of` corrects it from the leading magic bytes.
            Self::TarZst | Self::Xbps | Self::PkgFreebsd | Self::PkgArch => Zstd,
            _ => None,
        }
    }
}

/// Resolve the [`Container`] for `file_type`, consulting `bytes` to pin the
/// compression codec for types whose [`FileType`] does not determine it
/// (Arch `.pkg.tar.{zst,xz,gz}`). For every other type — and whenever the
/// bytes carry no recognizable compression magic — this equals
/// [`FileType::container`].
#[must_use]
pub fn container_of(file_type: FileType, bytes: &[u8]) -> Option<Container> {
    let mut container = file_type.container()?;
    // PkgArch is the sole type whose compression the variant doesn't fix. The
    // whole file is the compressed tar, so its leading bytes are the codec
    // magic; trust a positive sniff and keep the declared default otherwise.
    if file_type == FileType::PkgArch {
        if let Some(sniffed) = Compression::sniff(bytes) {
            container.compression = sniffed;
        }
    }
    Some(container)
}

#[cfg(test)]
mod tests {
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
    fn the_users_example_tar_xz() {
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
}
