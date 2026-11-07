//! TAR archive-index extractor.
//!
//! Reads tar headers (POSIX ustar, GNU, or pax) and reports the member
//! listing plus per-entry forensic fields. Like the ZIP extractor, this
//! never decompresses entry content — it walks headers and skips over
//! the data blocks via stream-position arithmetic.
//!
//! Plain `.tar` and the packages built on one (gem, OCI image, Gentoo
//! binpkg) are walked in place. A bare `.tar.gz`/`.tar.xz`/`.tar.zst` is
//! walked through a bounded decoder ([`MAX_TARGZ_SEARCH`] inflated bytes)
//! so its member listing and `archive.*` aggregates exist on the archive
//! itself: callers unpack those members without resubmitting the inner tar,
//! which left archive-scope rules blind to them. Tar headers are read and
//! data blocks skipped; nothing is decoded beyond the stream inflation.
//! `.tar.bz2` (no bzip2 decoder) and the packages built on a compressed tar
//! (npm, crate, sdist, Alpine apk, FreeBSD/Arch pkg, xbps) keep the
//! `archive.format.kind` label only; their identity is read by their own
//! modules.

use std::io::Read;

use serde_json::Value as JsonValue;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, member_value};
use super::bounded::{Limits, MAX_ARCHIVE_MEMBERS, MAX_TARGZ_SEARCH, xz_decoder, zstd_decoder};
use crate::error::Error;
use crate::fileid::FileType;
use crate::metric;
use crate::output::{ArchiveMember, ArchiveOffsets, ArchiveOwnership, EntryType, Metrics, Values};
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

    use crate::fileid::Compression;
    let compression = crate::fileid::container_of(file_type, bytes)
        .map_or(Compression::None, |c| c.compression);
    if compression == Compression::None {
        let mut limits = Limits::default();
        let result = walk_entries(
            &mut tar::Archive::new(bytes),
            file_type,
            values,
            metrics,
            archive_members,
            &mut limits,
        );
        limits.emit(values, value_key!("tar.limits"));
        return result;
    }
    // Only the bare compressed tars are inflated (see the module doc); every
    // other compressed variant is reported by label. That is the designed
    // outcome for a well-formed file, so it returns Ok, not an error.
    let decoder: Box<dyn Read + '_> = match (file_type, compression) {
        (FileType::TarGz, Compression::Gzip) => Box::new(flate2::read::GzDecoder::new(bytes)),
        (FileType::TarXz, Compression::Xz) => Box::new(xz_decoder(bytes)),
        (FileType::TarZst, Compression::Zstd) => match zstd_decoder(bytes) {
            Ok(decoder) => Box::new(decoder),
            Err(e) => {
                tracing::debug!(target: "filefacts::tar", stage = "open", error = %e, "zstd decoder setup failed; label only");
                return Ok(());
            }
        },
        _ => return Ok(()),
    };
    let mut archive = tar::Archive::new(decoder.take(MAX_TARGZ_SEARCH));
    let mut limits = Limits::default();
    let result = walk_entries(
        &mut archive,
        file_type,
        values,
        metrics,
        archive_members,
        &mut limits,
    );
    // The `Take` running dry means the walk stopped at the inflate budget,
    // not at the tar's end: the listing is a prefix.
    if archive.into_inner().limit() == 0 {
        limits.push(
            "inflate-cap",
            format!("walked the first {MAX_TARGZ_SEARCH} inflated bytes"),
        );
    }
    limits.emit(values, value_key!("tar.limits"));
    result
}

/// Walk `archive`'s headers into the member listing and aggregates. A
/// damaged header ends the walk; the members before it are still reported
/// and the error is returned after them.
fn walk_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    limits: &mut Limits,
) -> Result<(), Error> {
    let mut members: Vec<JsonValue> = Vec::new();
    let mut stats = ArchiveStats::new(AGGS);
    // Entries past the cap are counted, not listed: each listed one costs a
    // JSON member and an `ArchiveMember`, and a tar of empty files holds one
    // per 512 bytes.
    let mut unlisted: u64 = 0;
    // A damaged header ends the walk, but the members before it are still
    // reported; the error is returned after them.
    let mut walk_error = None;

    for entry in archive
        .entries()
        .map_err(|e| Error::malformed_caused_by("tar", e))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                tracing::debug!(target: "filefacts::tar", stage = "entries", listed = members.len(), error = %e, "tar walk stopped at a damaged header");
                walk_error = Some(Error::malformed_caused_by("tar", e));
                break;
            }
        };
        if members.len() >= MAX_ARCHIVE_MEMBERS {
            unlisted += 1;
            continue;
        }
        let header = entry.header();
        let kind = header.entry_type();

        let named = |name: Option<&str>| name.filter(|n| !n.is_empty()).map(str::to_string);
        let mode_octal = header.mode().ok();
        let ownership = ArchiveOwnership {
            mode_octal,
            uid: header.uid().ok(),
            gid: header.gid().ok(),
            uname: named(header.username().ok().flatten()),
            gname: named(header.groupname().ok().flatten()),
        };
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
        let path = entry
            .path()
            .ok()
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned());
        let member = ArchiveMember {
            mtime_unix: header.mtime().ok().map(u64::cast_signed),
            linkname,
            ownership,
            offsets: ArchiveOffsets {
                header: header_offset,
                data: data_offset,
                central_header: None,
            },
            ..ArchiveMember::new(path, header.size().unwrap_or(0), tar_entry_type(kind))
        };

        let mut reading = Reading::of(&member);
        reading.file = kind == tar::EntryType::Regular;
        reading.exec_mode = mode_octal.is_some_and(|m| m & 0o111 != 0);
        stats.observe(&member, &reading);
        members.push(JsonValue::Object(member_value(&member)));
        archive_members.push(member);
    }

    let listed = members.len();
    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    stats.emit(values, metrics);
    if unlisted > 0 {
        let total = listed as u64 + unlisted;
        metrics.insert(metric!("archive.member_count"), total as f64);
        limits.push("member-cap", format!("listed {listed} of {total} members"));
    }
    walk_error.map_or(Ok(()), Err)
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
        FileType::Hex => "hex",
        FileType::Pub => "pub",
        FileType::Cran => "cran",
        FileType::Cpan => "cpan",
        FileType::Hackage => "hackage",
        FileType::PkgFreebsd | FileType::PkgArch => "pkg",
        FileType::PythonSdist => "sdist",
        FileType::OciImage => "oci",
        FileType::Xbps => "xbps",
        FileType::GentooBinpkg => "gpkg",
        // Plain `Tar` and any catch-all the dispatcher routes here.
        _ => "tar",
    }
}

fn tar_entry_type(t: tar::EntryType) -> EntryType {
    use tar::EntryType as T;
    match t {
        T::Regular => EntryType::Regular,
        T::Link => EntryType::Hardlink,
        T::Symlink => EntryType::Symlink,
        T::Char => EntryType::CharDevice,
        T::Block => EntryType::BlockDevice,
        T::Directory => EntryType::Directory,
        T::Fifo => EntryType::Fifo,
        T::Continuous => EntryType::Continuous,
        T::GNULongName => EntryType::GnuLongname,
        T::GNULongLink => EntryType::GnuLonglink,
        T::GNUSparse => EntryType::GnuSparse,
        T::XGlobalHeader => EntryType::PaxGlobal,
        T::XHeader => EntryType::PaxHeader,
        _ => EntryType::Other,
    }
}

#[cfg(test)]
mod tests;
