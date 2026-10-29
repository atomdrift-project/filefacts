//! Archive-container decomposition for packaged file types.
//!
//! Many ecosystem package formats are, underneath their format-specific
//! identity, just a well-known archive container wrapped in a compression
//! codec: a `.gem` is an uncompressed `tar`, a `.crate` is a gzipped `tar`,
//! a `.whl` is a `zip`. Each [`FileType`] row declares that pair, so a
//! consumer can ask "what archive and compression underlie this type?"
//! without re-encoding the per-format knowledge.
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
    /// ASCII CPIO member stream, without a compression wrapper.
    Cpio,
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
    /// Ren'Py RPA container, with a compressed pickle index and stored members.
    Rpa,
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
    /// Stable lowercase label (`tar`, `zip`, …).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::Cpio => "cpio",
            Self::Zip => "zip",
            Self::Ar => "ar",
            Self::Xar => "xar",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Rpa => "rpa",
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
mod tests;
