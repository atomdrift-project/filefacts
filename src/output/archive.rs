//! Typed archive member index.
//!
//! One [`ArchiveMember`] per entry of an archive's member table. Its serde
//! form is the `archive.members[]` value: every group below is flattened into
//! the member object and every unset field is left out, so the typed index
//! and the values tree cannot drift apart.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One member entry from an archive central directory or header table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ArchiveMember {
    /// Member path as stored in the archive index.
    pub path: String,
    /// Uncompressed member size in bytes.
    pub size_bytes: u64,
    /// What kind of entry the archive records.
    pub entry_type: EntryType,
    /// Last-modified timestamp as Unix seconds, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_unix: Option<i64>,
    /// Symlink target or hardlink target, when stored in the archive header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkname: Option<String>,
    /// Host operating system recorded by the archive format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_os: Option<String>,
    /// CRC-32 recorded for the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crc32: Option<u32>,
    /// Whether the member is marked encrypted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub encrypted: bool,
    /// Compressed extent and compression method, as far as the format
    /// records them.
    #[serde(flatten)]
    pub compression: ArchiveCompression,
    /// POSIX-style ownership and mode, populated for tar, cpio, rpm and the
    /// other formats that record it.
    #[serde(flatten)]
    pub ownership: ArchiveOwnership,
    /// Byte-offset locations of the member's headers and payload, when
    /// addressable within the input bytes.
    #[serde(flatten)]
    pub offsets: ArchiveOffsets,
}

impl ArchiveMember {
    /// A member with only its identity fields set.
    pub(crate) fn new(path: String, size_bytes: u64, entry_type: EntryType) -> Self {
        Self {
            path,
            size_bytes,
            entry_type,
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: ArchiveCompression::default(),
            ownership: ArchiveOwnership::default(),
            offsets: ArchiveOffsets::default(),
        }
    }
}

/// The kind of entry an archive records for a member, in filefacts' one
/// vocabulary across formats. Serialized in kebab case (`char-device`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EntryType {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A hard link to another member.
    Hardlink,
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
    /// A named pipe.
    Fifo,
    /// A Unix domain socket.
    Socket,
    /// A tar contiguous file.
    Continuous,
    /// A GNU tar long-name record.
    GnuLongname,
    /// A GNU tar long-link record.
    GnuLonglink,
    /// A GNU tar sparse file.
    GnuSparse,
    /// A pax global extended header.
    PaxGlobal,
    /// A pax per-file extended header.
    PaxHeader,
    /// An NTFS alternate data stream of another member.
    NtfsStream,
    /// A 7z anti-item: a deletion marker in an update archive.
    AntiItem,
    /// An El Torito boot image of an ISO 9660 volume.
    BootImage,
    /// A partition of a disk image.
    Partition,
    /// Bytes past the last extent a disk image's filesystem accounts for.
    Trailing,
    /// Bytes between extents that a disk image's filesystem does not name.
    Slack,
    /// A type the format records that has no name here.
    Other,
}

impl EntryType {
    /// The serialized name, as `archive.format.entry_types` lists it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Hardlink => "hardlink",
            Self::CharDevice => "char-device",
            Self::BlockDevice => "block-device",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::Continuous => "continuous",
            Self::GnuLongname => "gnu-longname",
            Self::GnuLonglink => "gnu-longlink",
            Self::GnuSparse => "gnu-sparse",
            Self::PaxGlobal => "pax-global",
            Self::PaxHeader => "pax-header",
            Self::NtfsStream => "ntfs-stream",
            Self::AntiItem => "anti-item",
            Self::BootImage => "boot-image",
            Self::Partition => "partition",
            Self::Trailing => "trailing",
            Self::Slack => "slack",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compressed-size and compression-method metadata. Both fields are
/// `Option` because some archive formats record only one.
///
/// The method stays a string: its vocabulary is the format's own (a 7z coder
/// chain such as `lzma2+aes256sha256`, a CAB `lzx:21` window, a RAR
/// version), so a closed enum would either drop detail or wrap a string.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ArchiveCompression {
    /// Compressed member size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<u64>,
    /// Compression method name in filefacts' stable lowercase vocabulary
    /// (`stored`, `deflate`, `bzip2`, `lzma`, `zstd`, …).
    #[serde(
        default,
        rename = "compression_method",
        skip_serializing_if = "Option::is_none"
    )]
    pub method: Option<String>,
}

impl ArchiveCompression {
    /// Both fields at once.
    pub(crate) fn new(compressed_size: Option<u64>, method: Option<String>) -> Self {
        Self {
            compressed_size,
            method,
        }
    }
}

/// POSIX-style ownership and mode bits. Every field is `Option`
/// because tar headers may carry numeric ids without names, or names
/// without ids, depending on the variant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ArchiveOwnership {
    /// Unix mode bits, including file-type bits when the archive records them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_octal: Option<u32>,
    /// Numeric owner user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    /// Numeric owner group id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u64>,
    /// Owner user name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uname: Option<String>,
    /// Owner group name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gname: Option<String>,
}

impl ArchiveOwnership {
    /// Mode bits only.
    pub(crate) fn mode(mode: u32) -> Self {
        Self {
            mode_octal: Some(mode),
            ..Self::default()
        }
    }
}

/// Byte-offset locations of a member's headers and payload within the
/// archive bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ArchiveOffsets {
    /// Offset of the member local header, when addressable.
    #[serde(
        default,
        rename = "header_offset",
        skip_serializing_if = "Option::is_none"
    )]
    pub header: Option<u64>,
    /// Offset of the member data payload, when addressable.
    #[serde(
        default,
        rename = "data_offset",
        skip_serializing_if = "Option::is_none"
    )]
    pub data: Option<u64>,
    /// Offset of the central-directory header, when the archive has one.
    #[serde(
        default,
        rename = "central_header_offset",
        skip_serializing_if = "Option::is_none"
    )]
    pub central_header: Option<u64>,
}

#[cfg(test)]
mod tests;
