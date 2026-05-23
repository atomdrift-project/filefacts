//! Typed archive member index.
//!
//! This mirrors the public `archive.members[]` values tree without forcing
//! downstream callers to re-read JSON for hot archive paths.

/// One member entry from an archive central directory or header table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    /// Member path as stored in the archive index.
    pub path: String,
    /// Uncompressed member size in bytes.
    pub size_bytes: u64,
    /// Compressed member size in bytes, when the archive format records it.
    pub compressed_size: Option<u64>,
    /// Compression method name using filefacts stable lowercase vocabulary.
    pub compression_method: Option<String>,
    /// Last-modified timestamp as Unix seconds, when present.
    pub mtime_unix: Option<i64>,
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
    /// Entry kind such as `regular`, `directory`, or `symlink`.
    pub entry_type: Option<String>,
    /// Symlink target or hardlink target, when stored in the archive header.
    pub linkname: Option<String>,
    /// Host operating system recorded by the archive format.
    pub host_os: Option<String>,
    /// Offset of the member local header, when addressable in the input bytes.
    pub header_offset: Option<u64>,
    /// Offset of the member data payload, when addressable in the input bytes.
    pub data_offset: Option<u64>,
    /// Offset of the central-directory header, when the archive has one.
    pub central_header_offset: Option<u64>,
    /// CRC-32 recorded for the member.
    pub crc32: Option<u32>,
    /// Whether the member is marked encrypted.
    pub encrypted: bool,
}
