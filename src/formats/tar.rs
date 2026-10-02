//! TAR archive-index extractor.
//!
//! Reads tar headers (POSIX ustar, GNU, or pax) and reports the member
//! listing plus per-entry forensic fields. Like the ZIP extractor, this
//! never decompresses entry content — it walks headers and skips over
//! the data blocks via stream-position arithmetic.
//!
//! Only uncompressed tars are walked: plain `.tar` and the packages built on
//! one (gem, OCI image, Gentoo binpkg). The gzip/bzip2/xz/zstd-wrapped
//! variants and the packages built on them (npm, crate, sdist, Alpine apk,
//! FreeBSD/Arch pkg, xbps) get the `archive.format.kind` label and nothing
//! else: cleave decompresses them and re-submits the inner tar, which is
//! walked then. Package identity for the gzipped ones is read by their own
//! modules, not here.

use serde_json::Value as JsonValue;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, ArchiveOffsets, ArchiveOwnership, Metrics, Values};
use crate::value_key;

/// The shared aggregates a tar reports. Only regular entries are files, and
/// only their sizes are summed. Tar has no per-entry compression, encryption
/// or comment field, so those aggregates are not reported.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::DirectoryCount,
    Agg::UncompressedSize(Scope::Files),
    Agg::EntryTypes,
    Agg::BuilderNames,
    Agg::ModeBits,
    Agg::SymlinkCount,
    Agg::MaxFilenameLength,
    Agg::HiddenFiles,
    Agg::PathTraversal(Scope::All),
    Agg::SymlinkEscapes,
    Agg::Executables,
    Agg::Scripts,
    Agg::NameTricks,
    Agg::NestedArchives,
    Agg::MisplacedExecutables,
    Agg::MtimeRange,
];

/// A tar member's published value has never carried its byte offsets; they
/// are on the typed member only.
const SHAPE: Shape = Shape {
    offsets: false,
    ..Shape::FULL
};

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String(format_label(file_type).into()),
    );

    // A compressed variant is reported by label only (see the module doc).
    // That is the designed outcome for a well-formed file, not a parse
    // failure, so it returns Ok rather than an error the caller would record.
    if crate::fileid::container_of(file_type, bytes)
        .is_some_and(|c| c.compression != crate::fileid::Compression::None)
    {
        return Ok(());
    }

    let mut archive = tar::Archive::new(bytes);
    let mut members: Vec<JsonValue> = Vec::new();
    let mut stats = ArchiveStats::new(AGGS);

    for entry in archive
        .entries()
        .map_err(|e| Error::malformed_with_source("tar", e.to_string(), e))?
    {
        let entry = entry.map_err(|e| Error::malformed_with_source("tar", e.to_string(), e))?;
        let header = entry.header();
        let kind = header.entry_type();

        let named = |name: Option<&str>| name.filter(|n| !n.is_empty()).map(str::to_string);
        let mode_octal = header.mode().ok();
        let uid = header.uid().ok();
        let gid = header.gid().ok();
        let uname = named(header.username().ok().flatten());
        let gname = named(header.groupname().ok().flatten());
        let ownership = (mode_octal.is_some()
            || uid.is_some()
            || gid.is_some()
            || uname.is_some()
            || gname.is_some())
        .then_some(ArchiveOwnership {
            mode_octal,
            uid,
            gid,
            uname,
            gname,
        });
        let linkname = if kind.is_symlink() || kind.is_hard_link() {
            header
                .link_name()
                .ok()
                .flatten()
                .map(|target| target.to_string_lossy().into_owned())
        } else {
            None
        };
        // Offsets index the bytes handed in, which is the tar itself only
        // for a plain tar.
        let (header_offset, data_offset) = if file_type == FileType::Tar {
            (
                Some(entry.raw_header_position()),
                Some(entry.raw_file_position()),
            )
        } else {
            (None, None)
        };
        let member = ArchiveMember {
            path: entry
                .path()
                .ok()
                .map_or_else(String::new, |p| p.to_string_lossy().into_owned()),
            size_bytes: header.size().unwrap_or(0),
            entry_type: Some(tar_entry_type(kind).into()),
            mtime_unix: header.mtime().ok().map(|m| m as i64),
            linkname,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership,
            offsets: ArchiveOffsets {
                header: header_offset,
                data: data_offset,
                central_header: None,
            },
        };

        let mut reading = Reading::of(&member);
        reading.file = kind == tar::EntryType::Regular;
        reading.exec_mode = mode_octal.is_some_and(|m| m & 0o111 != 0);
        stats.observe(&member, &reading);
        members.push(JsonValue::Object(member_value(&member, SHAPE)));
        archive_members.push(member);
    }

    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    stats.emit(values, metrics);
    Ok(())
}

fn format_label(file_type: FileType) -> &'static str {
    match file_type {
        FileType::TarGz => "tar.gz",
        FileType::TarBz2 => "tar.bz2",
        FileType::TarXz => "tar.xz",
        FileType::TarZst => "tar.zst",
        FileType::ApkAlpine => "apk",
        FileType::Gem => "gem",
        FileType::Npm => "npm",
        FileType::Crate => "crate",
        FileType::PkgFreebsd | FileType::PkgArch => "pkg",
        FileType::PythonSdist => "sdist",
        FileType::OciImage => "oci",
        FileType::Xbps => "xbps",
        FileType::GentooBinpkg => "gpkg",
        // Plain `Tar` and any catch-all the dispatcher routes here.
        _ => "tar",
    }
}

fn tar_entry_type(t: tar::EntryType) -> &'static str {
    use tar::EntryType;
    match t {
        EntryType::Regular => "regular",
        EntryType::Link => "hardlink",
        EntryType::Symlink => "symlink",
        EntryType::Char => "char-device",
        EntryType::Block => "block-device",
        EntryType::Directory => "directory",
        EntryType::Fifo => "fifo",
        EntryType::Continuous => "continuous",
        EntryType::GNULongName => "gnu-longname",
        EntryType::GNULongLink => "gnu-longlink",
        EntryType::GNUSparse => "gnu-sparse",
        EntryType::XGlobalHeader => "pax-global",
        EntryType::XHeader => "pax-header",
        _ => "other",
    }
}

#[cfg(test)]
mod tests;
