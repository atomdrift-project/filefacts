//! Typed archive member index.
//!
//! Mirrors the public `archive.members[]` values tree without forcing
//! downstream callers to re-read JSON for hot archive paths.
//!
//! The header carries the identity fields (path, size, type, encryption);
//! the rarely-populated groups — compressed-size + method, POSIX
//! ownership, byte-offset locations — live behind `Option` sub-structs
//! so the common case (a regular file from a zip) constructs cleanly
//! without spelling `None` ten times.

/// One member entry from an archive central directory or header table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveMember {
    /// Member path as stored in the archive index.
    pub path: String,
    /// Uncompressed member size in bytes.
    pub size_bytes: u64,
    /// Entry kind such as `regular`, `directory`, or `symlink`.
    pub entry_type: Option<String>,
    /// Last-modified timestamp as Unix seconds, when present.
    pub mtime_unix: Option<i64>,
    /// Symlink target or hardlink target, when stored in the archive header.
    pub linkname: Option<String>,
    /// Host operating system recorded by the archive format.
    pub host_os: Option<String>,
    /// CRC-32 recorded for the member.
    pub crc32: Option<u32>,
    /// Whether the member is marked encrypted.
    pub encrypted: bool,
    /// Compressed extent and compression method — present when the
    /// archive format records both.
    pub compression: Option<ArchiveCompression>,
    /// POSIX-style ownership and mode — populated for tar / cpio /
    /// rpm; absent for zip-family formats that record neither.
    pub ownership: Option<ArchiveOwnership>,
    /// Byte-offset locations of the member's headers and payload,
    /// when addressable within the input bytes.
    pub offsets: ArchiveOffsets,
}

/// Compressed-size and compression-method metadata. Both fields are
/// `Option` because some archive formats record only one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ArchiveCompression {
    /// Compressed member size in bytes.
    pub compressed_size: Option<u64>,
    /// Compression method name using filefacts' stable lowercase
    /// vocabulary (`stored`, `deflated`, `bzip2`, `lzma`, `zstd`, …).
    pub method: Option<String>,
}

/// POSIX-style ownership and mode bits. Every field is `Option`
/// because tar headers may carry numeric ids without names, or names
/// without ids, depending on the variant.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ArchiveOwnership {
    /// Unix mode bits, including file-type bits when the archive records them.
    pub mode_octal: Option<u32>,
    /// Numeric owner user id.
    pub uid: Option<u64>,
    /// Numeric owner group id.
    pub gid: Option<u64>,
    /// Owner user name.
    pub uname: Option<String>,
    /// Owner group name.
    pub gname: Option<String>,
}

/// Byte-offset locations of a member's headers and payload within the
/// archive bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ArchiveOffsets {
    /// Offset of the member local header, when addressable.
    pub header: Option<u64>,
    /// Offset of the member data payload, when addressable.
    pub data: Option<u64>,
    /// Offset of the central-directory header, when the archive has one.
    pub central_header: Option<u64>,
}
