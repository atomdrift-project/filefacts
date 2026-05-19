//! TAR archive-index extractor.
//!
//! Reads tar headers (POSIX ustar, GNU, or pax) and reports the member
//! listing plus per-entry forensic fields. Like the ZIP extractor, this
//! never decompresses entry content — it walks headers and skips over
//! the data blocks via stream-position arithmetic.
//!
//! Handles plain `.tar`, plus the gzip/bzip2/xz/zstd-wrapped variants —
//! the wrapper is identified by the [`FileType`] and a streaming
//! decompressor is wrapped around the cursor before walking. *Only* the
//! header bytes are decompressed; entry data is skipped.

use std::io::{self, Read};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    values.insert("archive.format", JsonValue::String(format_label(file_type).into()));

    let mut archive = open_archive(bytes, file_type)?;
    let mut members: Vec<JsonValue> = Vec::new();
    let mut entry_type_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut unames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut gnames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut mtimes: Vec<i64> = Vec::new();
    let mut setuid = 0u64;
    let mut setgid = 0u64;
    let mut sticky = 0u64;
    let mut world_writable = 0u64;
    let mut symlinks = 0u64;

    for entry in archive
        .entries()
        .map_err(|e| Error::malformed("tar", e.to_string()))?
    {
        let entry = entry.map_err(|e| Error::malformed("tar", e.to_string()))?;
        let header = entry.header();
        let path = entry
            .path()
            .ok()
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned());

        let entry_type_label = tar_entry_type(header.entry_type());
        let size = header.size().unwrap_or(0);

        let mut obj = serde_json::Map::new();
        obj.insert("path".into(), JsonValue::String(path));
        obj.insert("size_bytes".into(), JsonValue::Number(size.into()));
        obj.insert(
            "entry_type".into(),
            JsonValue::String(entry_type_label.into()),
        );

        if let Ok(mode) = header.mode() {
            obj.insert("mode_octal".into(), JsonValue::Number(u64::from(mode).into()));
            if mode & 0o4000 != 0 {
                setuid += 1;
            }
            if mode & 0o2000 != 0 {
                setgid += 1;
            }
            if mode & 0o1000 != 0 {
                sticky += 1;
            }
            if mode & 0o002 != 0 {
                world_writable += 1;
            }
        }
        if let Ok(uid) = header.uid() {
            obj.insert("uid".into(), JsonValue::Number(uid.into()));
        }
        if let Ok(gid) = header.gid() {
            obj.insert("gid".into(), JsonValue::Number(gid.into()));
        }
        if let Ok(Some(name)) = header.username() {
            if !name.is_empty() {
                obj.insert("uname".into(), JsonValue::String(name.to_string()));
                unames.insert(name.to_string());
            }
        }
        if let Ok(Some(name)) = header.groupname() {
            if !name.is_empty() {
                obj.insert("gname".into(), JsonValue::String(name.to_string()));
                gnames.insert(name.to_string());
            }
        }
        if let Ok(m) = header.mtime() {
            // tar stores mtime as unsigned seconds since the epoch.
            // `as i64` is safe for the realistic range.
            obj.insert("mtime_unix".into(), JsonValue::Number((m as i64).into()));
            mtimes.push(m as i64);
        }
        if header.entry_type().is_symlink() || header.entry_type().is_hard_link() {
            if let Ok(Some(linkname)) = header.link_name() {
                obj.insert(
                    "linkname".into(),
                    JsonValue::String(linkname.to_string_lossy().into_owned()),
                );
            }
            symlinks += u64::from(header.entry_type().is_symlink());
        }

        *entry_type_counts.entry(entry_type_label.into()).or_insert(0) += 1;
        members.push(JsonValue::Object(obj));
    }

    let member_count = members.len();
    values.insert("archive.members", JsonValue::Array(members));

    let entry_types: Vec<JsonValue> = entry_type_counts
        .keys()
        .map(|k| JsonValue::String(k.clone()))
        .collect();
    values.insert("archive.format.entry_types", JsonValue::Array(entry_types));

    if !unames.is_empty() {
        let u: Vec<JsonValue> = unames.iter().map(|s| JsonValue::String(s.clone())).collect();
        values.insert("archive.builder.unames", JsonValue::Array(u));
    }
    if !gnames.is_empty() {
        let g: Vec<JsonValue> = gnames.iter().map(|s| JsonValue::String(s.clone())).collect();
        values.insert("archive.builder.gnames", JsonValue::Array(g));
    }

    metrics.insert("archive.member_count", member_count as f64);
    for (t, c) in &entry_type_counts {
        metrics.insert(format!("archive.format.{}_count", t.replace('-', "_")), *c as f64);
    }
    metrics.insert("archive.security.setuid_count", setuid as f64);
    metrics.insert("archive.security.setgid_count", setgid as f64);
    metrics.insert("archive.security.sticky_count", sticky as f64);
    metrics.insert("archive.security.world_writable_count", world_writable as f64);
    metrics.insert("archive.security.symlink_count", symlinks as f64);

    if !mtimes.is_empty() {
        let min = *mtimes.iter().min().unwrap_or(&0);
        let max = *mtimes.iter().max().unwrap_or(&0);
        values.insert("archive.timing.mtime_min", JsonValue::Number(min.into()));
        values.insert("archive.timing.mtime_max", JsonValue::Number(max.into()));
        metrics.insert(
            "archive.timing.mtime_spread_seconds",
            (max - min) as f64,
        );
        let unique: std::collections::BTreeSet<i64> = mtimes.iter().copied().collect();
        metrics.insert("archive.timing.mtime_unique_count", unique.len() as f64);
    }

    Ok(())
}

fn format_label(file_type: FileType) -> &'static str {
    match file_type {
        FileType::TarGz => "tar.gz",
        FileType::TarBz2 => "tar.bz2",
        FileType::TarXz => "tar.xz",
        FileType::TarZst => "tar.zst",
        // Plain `Tar` and any catch-all the dispatcher routes here.
        _ => "tar",
    }
}

/// Wrap the input bytes in a tar::Archive over the appropriate
/// decompressor. We don't decompress the *content* of any entry — only
/// the small fraction of stream bytes the tar walker reads to consume
/// each entry's header — but the wrapper still has to handle the
/// compressed stream so headers land in the right place.
fn open_archive(
    bytes: &[u8],
    file_type: FileType,
) -> Result<tar::Archive<Box<dyn Read + '_>>, Error> {
    let cursor = io::Cursor::new(bytes);
    // Compressed wrappers. expose doesn't take a dep on the compressor
    // crates yet; for now we report the format label and decline to walk
    // entries when the bytes are compressed. (Cleave can hand expose
    // the *decompressed* tar bytes and get the full member listing.)
    if matches!(
        file_type,
        FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst
    ) {
        return Err(Error::malformed(
            "tar",
            format!(
                "compressed tar variants are reported by format only; \
                 decompress the wrapper before passing to expose (variant={file_type:?})"
            ),
        ));
    }
    let reader: Box<dyn Read + '_> = Box::new(cursor);
    Ok(tar::Archive::new(reader))
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
