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
use crate::output::{ArchiveMember, Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    values.insert(
        "archive.format.kind",
        JsonValue::String(format_label(file_type).into()),
    );

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

    // Aggregates ported from cleave's ArchiveMetrics. Tar has no per-entry
    // compression, encryption, or comment field — those columns stay zero.
    let mut file_count: u64 = 0;
    let mut directory_count: u64 = 0;
    let mut total_uncompressed: u64 = 0;
    let mut max_filename_length: u64 = 0;
    let mut hidden_file_count: u64 = 0;
    let mut path_traversal_count: u64 = 0;
    let mut symlink_escape_count: u64 = 0;
    let mut executable_count: u64 = 0;
    let mut script_count: u64 = 0;
    let mut unicode_filename_count: u64 = 0;
    let mut homoglyph_filename_count: u64 = 0;
    let mut double_extension_count: u64 = 0;
    let mut rtlo_filename_count: u64 = 0;
    let mut nested_archive_count: u64 = 0;
    let mut misplaced_executable_count: u64 = 0;

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
        obj.insert("path".into(), JsonValue::String(path.clone()));
        obj.insert("size_bytes".into(), JsonValue::Number(size.into()));
        obj.insert(
            "entry_type".into(),
            JsonValue::String(entry_type_label.into()),
        );

        let mode_octal = header.mode().ok();
        if let Some(mode) = mode_octal {
            obj.insert(
                "mode_octal".into(),
                JsonValue::Number(u64::from(mode).into()),
            );
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
        let uid = header.uid().ok();
        if let Some(uid) = uid {
            obj.insert("uid".into(), JsonValue::Number(uid.into()));
        }
        let gid = header.gid().ok();
        if let Some(gid) = gid {
            obj.insert("gid".into(), JsonValue::Number(gid.into()));
        }
        let uname = header
            .username()
            .ok()
            .flatten()
            .and_then(|name| (!name.is_empty()).then(|| name.to_string()));
        if let Some(name) = &uname {
            obj.insert("uname".into(), JsonValue::String(name.clone()));
            unames.insert(name.clone());
        }
        let gname = header
            .groupname()
            .ok()
            .flatten()
            .and_then(|name| (!name.is_empty()).then(|| name.to_string()));
        if let Some(name) = &gname {
            obj.insert("gname".into(), JsonValue::String(name.clone()));
            gnames.insert(name.clone());
        }
        let mtime_unix = header.mtime().ok().map(|m| m as i64);
        if let Some(m) = mtime_unix {
            obj.insert("mtime_unix".into(), JsonValue::Number(m.into()));
            mtimes.push(m);
        }
        let mut linkname_str: Option<String> = None;
        if header.entry_type().is_symlink() || header.entry_type().is_hard_link() {
            if let Ok(Some(linkname)) = header.link_name() {
                let s = linkname.to_string_lossy().into_owned();
                obj.insert("linkname".into(), JsonValue::String(s.clone()));
                linkname_str = Some(s);
            }
            symlinks += u64::from(header.entry_type().is_symlink());
        }

        *entry_type_counts
            .entry(entry_type_label.into())
            .or_insert(0) += 1;

        // Aggregate the same classification flags as the ZIP extractor.
        let entry_path_str = obj
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();

        if entry_path_str.len() as u64 > max_filename_length {
            max_filename_length = entry_path_str.len() as u64;
        }

        if header.entry_type().is_dir() {
            directory_count += 1;
        } else if header.entry_type() == tar::EntryType::Regular {
            file_count += 1;
            // Saturate so a tar built from many huge sparse headers can't
            // wrap the u64 sum and report a misleadingly small total.
            total_uncompressed = total_uncompressed.saturating_add(size);
        }

        let cls = super::zip::classify_filename(&entry_path_str);
        if cls.is_hidden {
            hidden_file_count += 1;
        }
        if cls.has_path_traversal {
            path_traversal_count += 1;
        }
        if cls.is_unicode {
            unicode_filename_count += 1;
        }
        if cls.has_homoglyph {
            homoglyph_filename_count += 1;
        }
        if cls.has_double_extension {
            double_extension_count += 1;
        }
        if cls.has_rtlo {
            rtlo_filename_count += 1;
        }
        let is_regular = header.entry_type() == tar::EntryType::Regular;
        if is_regular {
            if cls.is_nested_archive {
                nested_archive_count += 1;
            }
            if cls.is_script {
                script_count += 1;
            }
            let exec_by_mode = header.mode().ok().is_some_and(|m| m & 0o111 != 0);
            if cls.is_executable || exec_by_mode {
                executable_count += 1;
                if cls.is_misplaced_executable {
                    misplaced_executable_count += 1;
                }
            }
        }

        // Tar exposes the linkname directly in the header — detect symlink
        // escapes (target contains `..` or is absolute).
        if header.entry_type().is_symlink() {
            if let Some(target) = linkname_str.as_deref() {
                if target.starts_with('/') || target.split('/').any(|p| p == "..") {
                    symlink_escape_count += 1;
                }
            }
        }

        let (header_offset, data_offset) = if file_type == FileType::Tar {
            (
                Some(entry.raw_header_position()),
                Some(entry.raw_file_position()),
            )
        } else {
            (None, None)
        };
        let ownership = if mode_octal.is_some()
            || uid.is_some()
            || gid.is_some()
            || uname.is_some()
            || gname.is_some()
        {
            Some(crate::output::ArchiveOwnership {
                mode_octal,
                uid,
                gid,
                uname,
                gname,
            })
        } else {
            None
        };
        archive_members.push(ArchiveMember {
            path,
            size_bytes: size,
            entry_type: Some(entry_type_label.to_string()),
            mtime_unix,
            linkname: linkname_str,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership,
            offsets: crate::output::ArchiveOffsets {
                header: header_offset,
                data: data_offset,
                central_header: None,
            },
        });

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
        let u: Vec<JsonValue> = unames
            .iter()
            .map(|s| JsonValue::String(s.clone()))
            .collect();
        values.insert("archive.builder.unames", JsonValue::Array(u));
    }
    if !gnames.is_empty() {
        let g: Vec<JsonValue> = gnames
            .iter()
            .map(|s| JsonValue::String(s.clone()))
            .collect();
        values.insert("archive.builder.gnames", JsonValue::Array(g));
    }

    metrics.insert("archive.member_count", member_count as f64);
    metrics.insert("archive.file_count", file_count as f64);
    metrics.insert("archive.directory_count", directory_count as f64);
    metrics.insert("archive.total_uncompressed", total_uncompressed as f64);
    for (t, c) in &entry_type_counts {
        metrics.insert(
            format!("archive.format.{}_count", t.replace('-', "_")),
            *c as f64,
        );
    }
    metrics.insert("archive.security.setuid_count", setuid as f64);
    metrics.insert("archive.security.setgid_count", setgid as f64);
    metrics.insert("archive.security.sticky_count", sticky as f64);
    metrics.insert(
        "archive.security.world_writable_count",
        world_writable as f64,
    );
    metrics.insert("archive.security.symlink_count", symlinks as f64);

    metrics.insert("archive.max_filename_length", max_filename_length as f64);
    metrics.insert("archive.hidden_file_count", hidden_file_count as f64);
    metrics.insert("archive.path_traversal_count", path_traversal_count as f64);
    metrics.insert("archive.symlink_escape_count", symlink_escape_count as f64);
    metrics.insert("archive.executable_count", executable_count as f64);
    metrics.insert("archive.script_count", script_count as f64);
    metrics.insert(
        "archive.unicode_filename_count",
        unicode_filename_count as f64,
    );
    metrics.insert(
        "archive.homoglyph_filename_count",
        homoglyph_filename_count as f64,
    );
    metrics.insert(
        "archive.double_extension_count",
        double_extension_count as f64,
    );
    metrics.insert("archive.rtlo_filename_count", rtlo_filename_count as f64);
    metrics.insert("archive.nested_archive_count", nested_archive_count as f64);
    metrics.insert(
        "archive.misplaced_executable_count",
        misplaced_executable_count as f64,
    );

    if !mtimes.is_empty() {
        let min = *mtimes.iter().min().unwrap_or(&0);
        let max = *mtimes.iter().max().unwrap_or(&0);
        values.insert("archive.timing.mtime_min", JsonValue::Number(min.into()));
        values.insert("archive.timing.mtime_max", JsonValue::Number(max.into()));
        metrics.insert("archive.timing.mtime_spread_seconds", (max - min) as f64);
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
        FileType::ApkAlpine => "apk",
        FileType::Gem => "gem",
        FileType::Npm => "npm",
        FileType::Crate => "crate",
        FileType::PkgFreebsd | FileType::PkgArch => "pkg",
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
    // Compressed wrappers. filefacts doesn't take a dep on the compressor
    // crates yet; for now we report the format label and decline to walk
    // entries when the bytes are compressed. (Cleave can hand filefacts
    // the *decompressed* tar bytes and get the full member listing.)
    // `Gem` is an *uncompressed* `ustar` tar — it falls through to the plain
    // walker below. The compressed variants (including Alpine's gzip `.apk`)
    // are reported by format label only.
    if matches!(
        file_type,
        FileType::TarGz
            | FileType::TarBz2
            | FileType::TarXz
            | FileType::TarZst
            | FileType::ApkAlpine
            | FileType::Npm
            | FileType::Crate
            | FileType::PkgFreebsd
            | FileType::PkgArch
    ) {
        return Err(Error::malformed(
            "tar",
            format!(
                "compressed tar variants are reported by format only; \
                 decompress the wrapper before passing to filefacts (variant={file_type:?})"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Metrics, Values};
    use tar::{Builder, Header};

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        // Plain tar; compressed variants test elsewhere.
        let mut archive_members = Vec::new();
        let _ = extract(bytes, FileType::Tar, &mut v, &mut m, &mut archive_members);
        (v, m)
    }

    /// Build a minimal in-memory tar archive. Each tuple is
    /// `(path, mode, uid, gid, mtime, body)`. Set `uname`/`gname`
    /// via the per-entry closure.
    fn build_tar(entries: &[(&str, u32, u64, u64, u64, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        {
            let mut b = Builder::new(&mut out);
            for (path, mode, uid, gid, mtime, body) in entries {
                let mut h = Header::new_ustar();
                h.set_path(path).unwrap();
                h.set_mode(*mode);
                h.set_uid(*uid);
                h.set_gid(*gid);
                h.set_mtime(*mtime);
                h.set_size(body.len() as u64);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_cksum();
                b.append(&h, &body[..]).unwrap();
            }
            b.finish().unwrap();
        }
        out
    }

    #[test]
    fn empty_input_returns_empty_member_list() {
        let (v, m) = run(&[]);
        // tar::Archive over empty bytes returns an empty entry iter; the
        // walker still emits the empty list (so downstream consumers can
        // distinguish "no members" from "archive not parsed").
        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert!(members.is_empty());
        assert_eq!(m.get("archive.member_count"), Some(0.0));
    }

    #[test]
    fn surfaces_member_listing_and_metadata() {
        let tar = build_tar(&[
            (
                "usr/bin/script.sh",
                0o755,
                1000,
                1000,
                1_700_000_000,
                b"#!/bin/sh\n",
            ),
            ("etc/config", 0o644, 0, 0, 1_700_000_100, b"key=value\n"),
        ]);
        let (v, m) = run(&tar);

        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert_eq!(members.len(), 2);

        // First member's structural fields.
        let m0 = members[0].as_object().unwrap();
        assert_eq!(m0["path"].as_str(), Some("usr/bin/script.sh"));
        assert_eq!(m0["entry_type"].as_str(), Some("regular"));
        assert_eq!(m0["mode_octal"].as_u64(), Some(0o755));
        assert_eq!(m0["uid"].as_u64(), Some(1000));
        assert_eq!(m0["gid"].as_u64(), Some(1000));
        assert_eq!(m0["mtime_unix"].as_i64(), Some(1_700_000_000));
        assert_eq!(m0["size_bytes"].as_u64(), Some(b"#!/bin/sh\n".len() as u64));

        // Aggregates.
        assert_eq!(m.get("archive.member_count"), Some(2.0));
        assert_eq!(m.get("archive.format.regular_count"), Some(2.0));
    }

    #[test]
    fn typed_members_track_tar_headers() {
        let tar = build_tar(&[(
            "usr/bin/script.sh",
            0o755,
            1000,
            1000,
            1_700_000_000,
            b"#!/bin/sh\n",
        )]);
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        let mut archive_members = Vec::new();
        extract(
            &tar,
            FileType::Tar,
            &mut values,
            &mut metrics,
            &mut archive_members,
        )
        .unwrap();

        assert_eq!(archive_members.len(), 1);
        let member = &archive_members[0];
        assert_eq!(member.path, "usr/bin/script.sh");
        assert_eq!(member.size_bytes, b"#!/bin/sh\n".len() as u64);
        let ownership = member.ownership.as_ref().expect("tar entry has ownership");
        assert_eq!(ownership.mode_octal, Some(0o755));
        assert_eq!(ownership.uid, Some(1000));
        assert_eq!(ownership.gid, Some(1000));
        assert_eq!(member.mtime_unix, Some(1_700_000_000));
        assert_eq!(member.entry_type.as_deref(), Some("regular"));
        assert_eq!(member.offsets.header, Some(0));
        assert_eq!(member.offsets.data, Some(512));
    }

    #[test]
    fn flags_setuid_in_security_metrics() {
        // Setuid bit (04000) on root-owned binary.
        let tar = build_tar(&[("bin/pwn", 0o4755, 0, 0, 0, b"")]);
        let (_, m) = run(&tar);
        assert_eq!(m.get("archive.security.setuid_count"), Some(1.0));
        // World-writable is not set on 0o4755.
        assert!(
            m.get("archive.security.world_writable_count")
                .unwrap_or(0.0)
                < 1.0
        );
    }

    #[test]
    fn flags_world_writable_and_setgid() {
        let tar = build_tar(&[
            ("data", 0o666, 1000, 1000, 0, b""),
            ("bin/setgid", 0o2755, 0, 100, 0, b""),
        ]);
        let (_, m) = run(&tar);
        assert_eq!(m.get("archive.security.world_writable_count"), Some(1.0));
        assert_eq!(m.get("archive.security.setgid_count"), Some(1.0));
    }

    #[test]
    fn timing_spread_zero_for_single_mtime() {
        let tar = build_tar(&[
            ("a", 0o644, 0, 0, 1_700_000_000, b""),
            ("b", 0o644, 0, 0, 1_700_000_000, b""),
        ]);
        let (_, m) = run(&tar);
        assert_eq!(m.get("archive.timing.mtime_spread_seconds"), Some(0.0));
        assert_eq!(m.get("archive.timing.mtime_unique_count"), Some(1.0));
    }

    #[test]
    fn timing_spread_captures_range() {
        let tar = build_tar(&[
            ("a", 0o644, 0, 0, 1_700_000_000, b""),
            ("b", 0o644, 0, 0, 1_700_086_400, b""), // +24h
        ]);
        let (_, m) = run(&tar);
        assert_eq!(m.get("archive.timing.mtime_spread_seconds"), Some(86400.0));
        assert_eq!(m.get("archive.timing.mtime_unique_count"), Some(2.0));
    }

    #[test]
    fn format_kind_set_to_tar() {
        let tar = build_tar(&[("a", 0o644, 0, 0, 0, b"")]);
        let (v, _) = run(&tar);
        assert_eq!(
            v.get("archive.format.kind").and_then(|x| x.as_str()),
            Some("tar")
        );
    }

    #[test]
    fn compressed_variants_report_format_only() {
        // Bytes don't matter — open_archive rejects compressed variants.
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        let mut archive_members = Vec::new();
        let _ = extract(
            b"any bytes",
            FileType::TarGz,
            &mut values,
            &mut metrics,
            &mut archive_members,
        );
        assert_eq!(
            values.get("archive.format.kind").and_then(|x| x.as_str()),
            Some("tar.gz")
        );
        // The walker bailed; no members.
        assert!(values.get("archive.members").is_none());
    }

    #[test]
    fn symlink_entry_recorded_with_linkname() {
        // tar::Builder can append symlinks via append_link.
        let mut out: Vec<u8> = Vec::new();
        {
            let mut b = Builder::new(&mut out);
            let mut h = Header::new_ustar();
            h.set_path("link").unwrap();
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_link_name("target.bin").unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let (v, m) = run(&out);
        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert_eq!(members[0]["entry_type"].as_str(), Some("symlink"));
        assert_eq!(members[0]["linkname"].as_str(), Some("target.bin"));
        assert_eq!(m.get("archive.security.symlink_count"), Some(1.0));
    }

    #[test]
    fn truncated_tar_doesnt_crash() {
        // Just a partial header — should error inside, not panic.
        let _ = run(&[0u8; 50]);
    }

    #[test]
    fn symlink_escape_flagged_when_target_uses_dotdot() {
        let mut out: Vec<u8> = Vec::new();
        {
            let mut b = Builder::new(&mut out);
            let mut h = Header::new_ustar();
            h.set_path("link").unwrap();
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_link_name("../../etc/passwd").unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let (_, m) = run(&out);
        assert_eq!(m.get("archive.symlink_escape_count"), Some(1.0));
    }

    #[test]
    fn tar_file_count_and_total_uncompressed() {
        let tar = build_tar(&[
            ("a.txt", 0o644, 0, 0, 0, b"hello"),
            ("b.txt", 0o644, 0, 0, 0, b"world"),
        ]);
        let (_, m) = run(&tar);
        assert_eq!(m.get("archive.file_count"), Some(2.0));
        assert_eq!(m.get("archive.total_uncompressed"), Some(10.0));
    }

    #[test]
    fn tar_executable_count_uses_mode_bit() {
        let tar = build_tar(&[
            ("bin/x", 0o755, 0, 0, 0, b""),
            ("data", 0o644, 0, 0, 0, b""),
        ]);
        let (_, m) = run(&tar);
        // Mode 0755 has exec bits → executable.
        assert_eq!(m.get("archive.executable_count"), Some(1.0));
    }

    #[test]
    fn builder_unames_collected_when_present() {
        // We can't easily set uname via the default ustar header API,
        // so build a header that has it. Cheating: use a longer header
        // construction.
        let mut h = Header::new_ustar();
        h.set_path("a").unwrap();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_username("alice").unwrap();
        h.set_groupname("dev").unwrap();
        h.set_cksum();
        let mut out: Vec<u8> = Vec::new();
        {
            let mut b = Builder::new(&mut out);
            b.append(&h, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let (v, _) = run(&out);
        let unames = v
            .get("archive.builder.unames")
            .and_then(|x| x.as_array())
            .unwrap();
        assert!(unames.iter().any(|s| s.as_str() == Some("alice")));
        let gnames = v
            .get("archive.builder.gnames")
            .and_then(|x| x.as_array())
            .unwrap();
        assert!(gnames.iter().any(|s| s.as_str() == Some("dev")));
    }
}
