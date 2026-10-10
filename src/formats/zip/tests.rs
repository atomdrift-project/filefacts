use super::*;
use crate::output::{Metrics, Values};
use std::io::Cursor;
use std::io::Write;
use zip::write::{SimpleFileOptions, ZipWriter};

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut archive_members = Vec::new();
    let mut errors = Errors::new();
    let _ = extract(bytes, &mut v, &mut m, &mut archive_members, &mut errors);
    (v, m)
}

/// Build an in-memory zip with the given members. Each tuple:
/// `(path, body, compression_method, last_modified_unix)`.
fn build_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        for (path, body, method) in entries {
            let opts = SimpleFileOptions::default()
                .compression_method(*method)
                .unix_permissions(0o644);
            w.start_file(*path, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

/// The member walk stops at the cap and says so; the uncapped count stays
/// in `archive.member_count`.
#[test]
fn member_walk_stops_at_cap_and_records_limit() {
    let z = build_zip(&[
        ("a.txt", b"a", CompressionMethod::Stored),
        ("b.txt", b"b", CompressionMethod::Stored),
        ("c.txt", b"c", CompressionMethod::Stored),
    ]);
    let mut archive = open_archive(&z).unwrap();
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut typed = Vec::new();
    walk_archive(&mut archive, &z, &mut v, &mut m, &mut typed, 2).unwrap();

    let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(typed.len(), 2);
    assert_eq!(m.get("archive.file_count"), Some(2.0));
    assert_eq!(m.get("archive.member_count"), Some(3.0));
    let limits = v.get("zip.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("member-cap"));

    // Under the cap, nothing is recorded.
    let (v, _) = run(&z);
    assert!(v.get("zip.limits").is_none());
}

#[test]
fn compression_names_are_stable() {
    assert_eq!(compression_method_name(CompressionMethod::Stored), "stored");
    assert_eq!(
        compression_method_name(CompressionMethod::Deflated),
        "deflate"
    );
}

#[test]
fn surfaces_member_listing_and_per_member_fields() {
    let z = build_zip(&[
        ("file.txt", b"hello world", CompressionMethod::Stored),
        (
            "nested/file.bin",
            b"\x00\x01\x02\x03",
            CompressionMethod::Deflated,
        ),
    ]);
    let (v, m) = run(&z);
    let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
    assert_eq!(members.len(), 2);
    let m0 = members[0].as_object().unwrap();
    assert_eq!(m0["path"].as_str(), Some("file.txt"));
    assert_eq!(m0["compression_method"].as_str(), Some("stored"));
    assert_eq!(m0["entry_type"].as_str(), Some("regular"));
    assert_eq!(m.get("archive.member_count"), Some(2.0));
}

#[test]
fn format_kind_set_to_zip() {
    let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
    let (v, _) = run(&z);
    assert_eq!(
        v.get("archive.format.kind").and_then(|x| x.as_str()),
        Some("zip")
    );
}

#[test]
fn compression_methods_array_unique() {
    let z = build_zip(&[
        ("a", b"x", CompressionMethod::Stored),
        ("b", b"y", CompressionMethod::Stored),
        ("c", b"z", CompressionMethod::Deflated),
    ]);
    let (v, _) = run(&z);
    let methods = v
        .get("archive.compression.methods")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = methods.iter().filter_map(|x| x.as_str()).collect();
    // BTreeMap iteration order is alphabetical: deflate, stored.
    assert_eq!(names, vec!["deflate", "stored"]);
}

#[test]
fn compression_ratio_present_when_uncompressed_nonzero() {
    let z = build_zip(&[(
        "big.txt",
        &b"abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij".repeat(20),
        CompressionMethod::Deflated,
    )]);
    let (_, m) = run(&z);
    let r = m.get("archive.compression.ratio").unwrap();
    assert!(r > 0.0 && r < 1.0, "expected ratio in (0,1), got {r}");
}

#[test]
fn jar_signed_shape_detected() {
    let z = build_zip(&[
        (
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\n",
            CompressionMethod::Stored,
        ),
        ("META-INF/CERT.SF", b"sigfile", CompressionMethod::Stored),
        ("META-INF/CERT.RSA", b"\x00\x01", CompressionMethod::Stored),
        ("Main.class", b"\xca\xfe\xba\xbe", CompressionMethod::Stored),
    ]);
    let (v, _) = run(&z);
    assert_eq!(
        v.get("archive.signing.jar_signed_shape")
            .and_then(|x| x.as_bool()),
        Some(true)
    );
    // mozilla-extension shape needs cose.manifest + cose.sig; not set here.
    assert!(v.get("archive.signing.mozilla_extension_shape").is_none());
}

#[test]
fn mozilla_extension_shape_detected() {
    let z = build_zip(&[
        (
            "META-INF/cose.manifest",
            b"mozcose",
            CompressionMethod::Stored,
        ),
        ("META-INF/cose.sig", b"\xde\xad", CompressionMethod::Stored),
        ("manifest.json", b"{}", CompressionMethod::Stored),
    ]);
    let (v, _) = run(&z);
    assert_eq!(
        v.get("archive.signing.mozilla_extension_shape")
            .and_then(|x| x.as_bool()),
        Some(true)
    );
}

#[test]
fn empty_zip_emits_empty_member_list() {
    let z = build_zip(&[]);
    let (v, m) = run(&z);
    let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
    assert!(members.is_empty());
    assert_eq!(m.get("archive.member_count"), Some(0.0));
}

#[test]
fn non_zip_input_rejected_silently() {
    // Bytes that don't start with PK\x03\x04 — extract returns Err
    // (which filefacts' dispatcher swallows). Values left empty.
    let (v, _) = run(b"not a zip");
    assert!(v.get("archive.members").is_none());
}

#[test]
fn aggregate_method_counts_per_compression() {
    let z = build_zip(&[
        ("a", b"x", CompressionMethod::Stored),
        ("b", b"y", CompressionMethod::Deflated),
        ("c", b"z", CompressionMethod::Deflated),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.compression.method_counts.stored"), Some(1.0));
    assert_eq!(
        m.get("archive.compression.method_counts.deflate"),
        Some(2.0)
    );
}

#[test]
fn truncated_zip_doesnt_crash() {
    // Take a valid zip and chop most of it off.
    let z = build_zip(&[("a", b"hello", CompressionMethod::Stored)]);
    let truncated = &z[..z.len() / 2];
    let (_, _) = run(truncated);
    // No assertions — we only care that it didn't panic.
}

// ---- Ported `ArchiveMetrics` aggregates ----

#[test]
fn file_and_directory_counts_track_member_kinds() {
    // ZipWriter::add_directory creates a real directory entry.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        w.add_directory("dir/", opts).unwrap();
        w.start_file("dir/a", opts).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("dir/b", opts).unwrap();
        w.write_all(b"y").unwrap();
        w.finish().unwrap();
    }
    let (_, m) = run(&buf.into_inner());
    assert_eq!(m.get("archive.file_count"), Some(2.0));
    assert_eq!(m.get("archive.directory_count"), Some(1.0));
}

#[test]
fn totals_and_compression_ratio() {
    let z = build_zip(&[
        ("a", b"abcdefghij", CompressionMethod::Stored),
        ("b", b"klmnop", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.uncompressed_size"), Some(16.0));
    assert!(m.get("archive.compressed_size").unwrap() >= 16.0);
    // Canonical nested namespace only — flat `archive.compression_ratio`
    // alias retired.
    assert!(m.get("archive.compression.ratio").is_some());
}

#[test]
fn hidden_file_count_includes_dotfiles_anywhere_in_path() {
    let z = build_zip(&[
        (".hidden", b"x", CompressionMethod::Stored),
        ("normal", b"x", CompressionMethod::Stored),
        ("nested/.dot/file", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.hidden_file_count"), Some(2.0));
}

#[test]
fn path_traversal_count_flags_dotdot_components() {
    let z = build_zip(&[
        ("../escape", b"x", CompressionMethod::Stored),
        ("ok/file", b"x", CompressionMethod::Stored),
        ("/absolute", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.path_traversal_count"), Some(2.0));
}

#[test]
fn script_and_executable_counts() {
    let z = build_zip(&[
        ("run.sh", b"#!/bin/sh\n", CompressionMethod::Stored),
        ("setup.py", b"x", CompressionMethod::Stored),
        ("payload.exe", b"x", CompressionMethod::Stored),
        ("readme.txt", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.script_count"), Some(2.0));
    assert_eq!(m.get("archive.executable_count"), Some(1.0));
}

#[test]
fn unicode_and_rtlo_filename_flags() {
    // U+202E is RIGHT-TO-LEFT OVERRIDE; payload.exe rendered as fxe.daolyap.
    let rtlo_name = "payload\u{202e}fdp.exe";
    let z = build_zip(&[
        ("résumé.pdf", b"x", CompressionMethod::Stored),
        (rtlo_name, b"x", CompressionMethod::Stored),
        ("ascii.txt", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.unicode_filename_count"), Some(2.0));
    assert_eq!(m.get("archive.rtlo_filename_count"), Some(1.0));
}

#[test]
fn double_extension_flag() {
    let z = build_zip(&[
        ("invoice.pdf.exe", b"x", CompressionMethod::Stored),
        ("photo.jpg.scr", b"x", CompressionMethod::Stored),
        ("ok.tar.gz", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    // pdf+exe and jpg+scr both match; tar+gz doesn't (gz isn't executable).
    assert_eq!(m.get("archive.double_extension_count"), Some(2.0));
}

#[test]
fn nested_archive_count() {
    let z = build_zip(&[
        ("inner.zip", b"PK\x05\x06", CompressionMethod::Stored),
        ("payload.tar.gz", b"x", CompressionMethod::Stored),
        ("readme.txt", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.nested_archive_count"), Some(2.0));
}

#[test]
fn has_comment_flag_when_archive_has_global_comment() {
    // Build a zip with a comment.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        w.set_raw_comment(b"hello world".to_vec().into_boxed_slice());
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        w.start_file("a", opts).unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
    }
    let (_, m) = run(&buf.into_inner());
    assert_eq!(m.get("archive.has_comment"), Some(1.0));
}

/// Canonical key list emitted by the ZIP extractor. The test fails
/// loudly when filefacts stops emitting any of these keys for a
/// realistic archive — protects traits referencing them from
/// silent disappearance.
#[test]
fn full_archive_key_set_emitted_for_realistic_zip() {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        w.set_raw_comment(b"build comment".to_vec().into_boxed_slice());
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644)
            .last_modified_time(zip::DateTime::default());
        w.add_directory("dir/", opts).unwrap();
        w.start_file("dir/a.txt", opts).unwrap();
        w.write_all(b"hello world").unwrap();
        w.start_file("dir/script.sh", opts.unix_permissions(0o755))
            .unwrap();
        w.write_all(b"#!/bin/sh\n").unwrap();
        w.start_file("payload.exe", opts).unwrap();
        w.write_all(b"\x4d\x5a").unwrap();
        w.finish().unwrap();
    }
    let (_, m) = run(&buf.into_inner());

    // Every key listed here must remain present — adding new keys is fine;
    // dropping one is a breaking change requiring a trait/comment update.
    for key in [
        "archive.member_count",
        "archive.file_count",
        "archive.directory_count",
        "archive.uncompressed_size",
        "archive.compressed_size",
        "archive.compression.ratio",
        "archive.max_filename_length",
        "archive.hidden_file_count",
        "archive.path_traversal_count",
        "archive.symlink_escape_count",
        "archive.executable_count",
        "archive.script_count",
        "archive.unicode_filename_count",
        "archive.homoglyph_filename_count",
        "archive.double_extension_count",
        "archive.rtlo_filename_count",
        "archive.nested_archive_count",
        "archive.misplaced_executable_count",
        "archive.extra_field_size",
        "archive.security.setuid_count",
        "archive.security.setgid_count",
        "archive.security.sticky_count",
        "archive.security.world_writable_count",
        "archive.security.symlink_count",
        "archive.security.encrypted_count",
        "archive.has_comment",
    ] {
        assert!(
            m.get(key).is_some(),
            "missing required archive metric key: {key}"
        );
    }
}

#[test]
fn max_filename_length_tracks_longest_entry() {
    let long = "a".repeat(120);
    let z = build_zip(&[
        ("short", b"x", CompressionMethod::Stored),
        (long.as_str(), b"y", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.max_filename_length"), Some(120.0));
}

// ---- Extra-field tag enumeration (task 3) ----

#[test]
fn enumerate_extra_tags_handles_known_tlv_stream() {
    // Two well-formed TLVs back-to-back: Unicode Path (0x7075) with 3
    // bytes of body, followed by NTFS times (0x000a) with 4 bytes.
    let extra = &[
        0x75, 0x70, 0x03, 0x00, b'a', b'b', b'c', 0x0a, 0x00, 0x04, 0x00, 1, 2, 3, 4,
    ];
    let tags = enumerate_extra_tags(extra);
    assert!(tags.contains(&0x7075));
    assert!(tags.contains(&0x000a));
    assert_eq!(tags.len(), 2);
}

#[test]
fn enumerate_extra_tags_stops_on_overrun() {
    // Header claims 100 bytes of body but only 2 are present —
    // walker must stop without panic and report the single tag it
    // managed to read (the tag header itself is intact).
    let extra = &[0x01, 0x00, 100, 0x00, 0xde, 0xad];
    let tags = enumerate_extra_tags(extra);
    assert!(tags.contains(&0x0001));
    assert_eq!(tags.len(), 1);
}

#[test]
fn enumerate_extra_tags_empty_input_is_empty() {
    assert!(enumerate_extra_tags(&[]).is_empty());
}

// ---- Out-of-band smuggling detectors (task 4) ----

#[test]
fn comment_size_emitted_when_archive_has_comment() {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        w.set_raw_comment(b"hello".to_vec().into_boxed_slice());
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        w.start_file("a", opts).unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
    }
    let (_, m) = run(&buf.into_inner());
    assert_eq!(m.get("archive.comment_size"), Some(5.0));
}

#[test]
fn prefix_bytes_detected_for_polyglot_with_leading_payload() {
    let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
    // Prepend a 16-byte stub before the first local file header.
    let mut polyglot = b"\x00".repeat(16);
    polyglot.extend_from_slice(&z);
    let (_, m) = run(&polyglot);
    assert_eq!(m.get("archive.leading_bytes"), Some(16.0));
}

#[test]
fn trailing_bytes_detected_for_appended_payload() {
    let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
    let mut tampered = z.clone();
    tampered.extend_from_slice(b"appended-data-here");
    let (_, m) = run(&tampered);
    assert_eq!(m.get("archive.trailing_bytes"), Some(18.0));
}

#[test]
fn no_prefix_or_trailing_for_clean_archive() {
    let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
    let (_, m) = run(&z);
    assert!(m.get("archive.leading_bytes").is_none());
    assert!(m.get("archive.trailing_bytes").is_none());
}

/// Build a minimal hand-rolled ZIP with two CDH entries pointing at
/// the *same* local-file body and the same on-disk name. ZipWriter
/// rejects duplicate names, so this exercises the duplicate-name
/// detector with raw bytes — exactly the ZIP-confusion attack
/// shape (one CDH-only, one LFH+CDH, two paths winning).
fn build_duplicate_name_zip() -> Vec<u8> {
    let mut out = Vec::new();
    let name = b"dup.txt";
    let body = b"hello";
    let crc = crc32fast::hash(body);

    // Single local file header + body.
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method = stored
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&crc.to_le_bytes()); // crc
    out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // csize
    out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // usize
    out.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(name);
    out.extend_from_slice(body);

    let lfh_offset: u32 = 0;
    let cd_start = out.len() as u32;

    // Two central-directory entries pointing at the same LFH.
    for _ in 0..2 {
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&0x031Eu16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&lfh_offset.to_le_bytes());
        out.extend_from_slice(name);
    }

    let cd_size = (out.len() as u32) - cd_start;

    // EOCD
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk start
    out.extend_from_slice(&2u16.to_le_bytes()); // entries on disk
    out.extend_from_slice(&2u16.to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    out
}

#[test]
fn duplicate_member_count_detects_zip_confusion() {
    let z = build_duplicate_name_zip();
    let (v, m) = run(&z);
    // Two CDH entries with the same name → one duplicate beyond the first.
    assert_eq!(m.get("archive.duplicate_member_count"), Some(1.0));
    let names = v
        .get("archive.duplicate_member_names")
        .and_then(|x| x.as_array())
        .expect("duplicate names emitted");
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].as_str(), Some("dup.txt"));
}

#[test]
fn crc_collision_count_detects_identical_bodies() {
    // Two files with identical bodies → identical CRC32.
    let z = build_zip(&[
        ("one.txt", b"identical body", CompressionMethod::Stored),
        ("two.txt", b"identical body", CompressionMethod::Stored),
        ("three.txt", b"different", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.crc_collision_count"), Some(1.0));
}

/// A Zip64 archive whose entries declare `sizes` (both compressed and
/// uncompressed). The sizes are never backed by data; the central
/// directory is all the extractor reads.
fn zip64_with_sizes(sizes: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (i, &size) in sizes.iter().enumerate() {
        let name = format!("f{i}.bin");
        let lfh = out.len() as u64;
        out.extend_from_slice(b"PK\x03\x04");
        for v in [45u16, 0, 0, 0, 0x21] {
            out.extend(v.to_le_bytes());
        }
        for v in [0u32, u32::MAX, u32::MAX] {
            out.extend(v.to_le_bytes());
        }
        out.extend((name.len() as u16).to_le_bytes());
        out.extend(20u16.to_le_bytes());
        out.extend(name.as_bytes());
        for v in [1u16, 16] {
            out.extend(v.to_le_bytes());
        }
        out.extend(size.to_le_bytes());
        out.extend(size.to_le_bytes());

        cd.extend_from_slice(b"PK\x01\x02");
        for v in [0x032Du16, 45, 0, 0, 0, 0x21] {
            cd.extend(v.to_le_bytes());
        }
        for v in [0u32, u32::MAX, u32::MAX] {
            cd.extend(v.to_le_bytes());
        }
        for v in [name.len() as u16, 28, 0, 0, 0] {
            cd.extend(v.to_le_bytes());
        }
        for v in [0u32, u32::MAX] {
            cd.extend(v.to_le_bytes());
        }
        cd.extend(name.as_bytes());
        for v in [1u16, 24] {
            cd.extend(v.to_le_bytes());
        }
        for v in [size, size, lfh] {
            cd.extend(v.to_le_bytes());
        }
    }
    let cd_offset = out.len() as u64;
    out.extend(&cd);
    let eocd64 = out.len() as u64;
    out.extend_from_slice(b"PK\x06\x06");
    out.extend(44u64.to_le_bytes());
    for v in [45u16, 45] {
        out.extend(v.to_le_bytes());
    }
    for v in [0u32, 0] {
        out.extend(v.to_le_bytes());
    }
    for v in [
        sizes.len() as u64,
        sizes.len() as u64,
        cd.len() as u64,
        cd_offset,
    ] {
        out.extend(v.to_le_bytes());
    }
    out.extend_from_slice(b"PK\x06\x07");
    out.extend(0u32.to_le_bytes());
    out.extend(eocd64.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend_from_slice(b"PK\x05\x06");
    for v in [0u16, 0, u16::MAX, u16::MAX] {
        out.extend(v.to_le_bytes());
    }
    for v in [u32::MAX, u32::MAX] {
        out.extend(v.to_le_bytes());
    }
    out.extend(0u16.to_le_bytes());
    out
}

/// Declared Zip64 sizes summing past `u64::MAX` overflowed the size
/// totals: a panic in builds with overflow checks, a wrapped total
/// otherwise.
#[test]
fn zip64_size_totals_saturate() {
    let z = zip64_with_sizes(&[1 << 63, 1 << 63]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.member_count"), Some(2.0));
    assert_eq!(m.get("archive.uncompressed_size"), Some(u64::MAX as f64));
    assert_eq!(m.get("archive.compressed_size"), Some(u64::MAX as f64));
}

#[test]
fn crc_collision_ignores_zero_size_entries() {
    // Two empty files share CRC32=0 but aren't a real collision.
    let z = build_zip(&[
        ("empty1", b"", CompressionMethod::Stored),
        ("empty2", b"", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.crc_collision_count"), Some(0.0));
}

#[test]
fn find_eocd_locates_signature_at_end_of_clean_zip() {
    let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
    let offset = find_eocd(&z).unwrap();
    assert_eq!(&z[offset..offset + 4], b"PK\x05\x06");
    // Clean zip → EOCD sits exactly 22 bytes from the end.
    assert_eq!(offset, z.len() - 22);
}

#[test]
fn find_eocd_returns_none_for_too_short_input() {
    assert!(find_eocd(b"PK").is_none());
}

// ---- Timestamp anomalies (task 5) ----

#[test]
fn sentinel_mtime_count_counts_unparseable_dates() {
    // ZipWriter always emits a valid DateTime, so we hand-roll a
    // zip with mod_date=0 mod_time=0 (day=0 month=0 → unparseable,
    // matching the Mozilla "(1980, 0, 0) no recorded timestamp"
    // shape that filefacts treats as a sentinel).
    let z = build_duplicate_name_zip();
    let (_, m) = run(&z);
    // The hand-rolled archive has 2 CDH entries both at the sentinel.
    assert_eq!(m.get("archive.timing.sentinel_mtime_count"), Some(2.0));
}

#[test]
fn dominant_mtime_outlier_detected_for_supply_chain_drop() {
    // Three files at sentinel + one file with a real future mtime —
    // the classic "attacker dropped one extra entry" signal.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        w.start_file("a", opts).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("b", opts).unwrap();
        w.write_all(b"y").unwrap();
        w.start_file("c", opts).unwrap();
        w.write_all(b"z").unwrap();
        let real = zip::DateTime::from_date_and_time(2025, 6, 15, 12, 0, 0).unwrap();
        w.start_file("payload.dropped", opts.last_modified_time(real))
            .unwrap();
        w.write_all(b"!").unwrap();
        w.finish().unwrap();
    }
    let (v, m) = run(&buf.into_inner());
    // Three of four entries share the sentinel bucket → fraction = 0.75.
    let fraction = m.get("archive.timing.mtime_dominant_ratio").unwrap();
    assert!(
        (fraction - 0.75).abs() < 1e-9,
        "expected ~0.75, got {fraction}"
    );
    assert_eq!(m.get("archive.timing.mtime_outlier_count"), Some(1.0));
    let outliers = v
        .get("archive.timing.mtime_outlier_members")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(outliers.len(), 1);
    assert_eq!(outliers[0].as_str(), Some("payload.dropped"));
}

#[test]
fn no_outliers_emitted_when_no_dominant_majority() {
    // Two distinct buckets, 1 entry each — neither is a majority.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let d1 = zip::DateTime::from_date_and_time(2020, 1, 1, 0, 0, 0).unwrap();
        let d2 = zip::DateTime::from_date_and_time(2025, 1, 1, 0, 0, 0).unwrap();
        w.start_file("a", opts.last_modified_time(d1)).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("b", opts.last_modified_time(d2)).unwrap();
        w.write_all(b"y").unwrap();
        w.finish().unwrap();
    }
    let (v, m) = run(&buf.into_inner());
    // Dominant fraction is 0.5, not strictly greater → no outliers.
    assert_eq!(m.get("archive.timing.mtime_dominant_ratio"), Some(0.5));
    assert!(m.get("archive.timing.mtime_outlier_count").is_none());
    assert!(v.get("archive.timing.mtime_outlier_members").is_none());
}

#[test]
fn mtime_unique_ratio_one_when_all_distinct() {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let d1 = zip::DateTime::from_date_and_time(2020, 1, 1, 0, 0, 0).unwrap();
        let d2 = zip::DateTime::from_date_and_time(2021, 1, 1, 0, 0, 0).unwrap();
        w.start_file("a", opts.last_modified_time(d1)).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("b", opts.last_modified_time(d2)).unwrap();
        w.write_all(b"y").unwrap();
        w.finish().unwrap();
    }
    let (_, m) = run(&buf.into_inner());
    assert_eq!(m.get("archive.timing.mtime_unique_ratio"), Some(1.0));
}

#[test]
fn future_mtime_count_flags_year_2100_plus() {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut w = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let future = zip::DateTime::from_date_and_time(2107, 12, 31, 23, 59, 58).unwrap();
        w.start_file("a", opts.last_modified_time(future)).unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
    }
    let (_, m) = run(&buf.into_inner());
    assert_eq!(m.get("archive.timing.future_mtime_count"), Some(1.0));
}

// ---- Noise files + Chrome web-store shape (task 6) ----

#[test]
fn noise_file_count_tracks_developer_detritus() {
    let z = build_zip(&[
        ("__MACOSX/foo", b"x", CompressionMethod::Stored),
        ("subdir/.DS_Store", b"x", CompressionMethod::Stored),
        ("Thumbs.db", b"x", CompressionMethod::Stored),
        ("desktop.ini", b"x", CompressionMethod::Stored),
        ("clean.txt", b"x", CompressionMethod::Stored),
    ]);
    let (_, m) = run(&z);
    assert_eq!(m.get("archive.noise_file_count"), Some(4.0));
}

#[test]
fn chrome_webstore_shape_detected() {
    let z = build_zip(&[
        (
            "_metadata/verified_contents.json",
            b"{}",
            CompressionMethod::Stored,
        ),
        ("manifest.json", b"{}", CompressionMethod::Stored),
    ]);
    let (v, _) = run(&z);
    assert_eq!(
        v.get("archive.signing.chrome_webstore_shape")
            .and_then(|x| x.as_bool()),
        Some(true)
    );
}

// ---- Per-entry extra_tags surface ----

#[test]
fn extra_field_tags_aggregated_at_archive_level() {
    // ZipWriter at default settings doesn't synthesize Unicode-path
    // extras, but Mach-O and NTFS-times extras are sometimes added
    // by Info-ZIP. Building a clean archive: extra_field_tags is
    // either absent or contains tags the writer chose to emit. The
    // important invariant is that *when* extras exist, they parse
    // to a deduped sorted u16 set — already covered by
    // enumerate_extra_tags_handles_known_tlv_stream.
    let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
    let (v, _) = run(&z);
    // Either absent (no extras) or a JSON array of numbers.
    if let Some(arr) = v.get("archive.extra_field_tags").and_then(|x| x.as_array()) {
        for item in arr {
            assert!(item.as_u64().is_some());
        }
    }
}

#[test]
fn unreadable_archive_keeps_its_text_and_exposes_the_zip_error() {
    use std::error::Error as _;
    let Err(err) = open_archive(b"PK\x03\x04garbage-not-a-zip-at-all") else {
        panic!("garbage opened as a zip");
    };
    assert_eq!(err.to_string(), "malformed zip");
    assert_eq!(
        crate::error::display_chain(&err),
        "malformed zip: invalid Zip archive: Could not find EOCD"
    );
    let source = err.source().expect("zip source");
    assert!(source.downcast_ref::<zip::result::ZipError>().is_some());
}

/// Offsets of every local file header, in member order.
fn local_header_offsets(z: &[u8]) -> Vec<usize> {
    memchr::memmem::find_iter(z, b"PK\x03\x04").collect()
}

/// One corrupted local-header signature made the `zip` crate refuse the
/// whole archive, so an APK hid every member (and its manifest) while
/// Android, which reads the central directory, installed it. The header is
/// repaired, the members are listed and readable, and the mismatch is a
/// recorded fact.
#[test]
fn corrupted_local_header_signature_still_lists_and_reads_members() {
    let mut z = build_zip(&[
        (
            "AndroidManifest.xml",
            b"manifest",
            CompressionMethod::Stored,
        ),
        ("classes.dex", b"dex\n035", CompressionMethod::Deflated),
    ]);
    let second = local_header_offsets(&z)[1];
    z[second..second + 4].copy_from_slice(b"XX\x03\x04");
    assert!(ZipArchive::new(Cursor::new(&z[..])).is_err());

    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut members = Vec::new();
    let mut errors = Errors::new();
    let mut archive = open_and_walk(&z, &mut v, &mut m, &mut members, &mut errors)
        .unwrap()
        .expect("repaired archive");
    assert_eq!(members.len(), 2);
    assert_eq!(m.get("archive.local_header_mismatch_count"), Some(1.0));
    assert_eq!(errors.len(), 1);
    assert_eq!(
        read_member(&mut archive, "classes.dex", 64)
            .unwrap()
            .as_deref(),
        Some(&b"dex\n035"[..])
    );
}

/// When even a repaired copy will not open, the member listing still comes
/// from the raw central directory.
#[test]
fn unopenable_archive_lists_members_from_the_raw_central_directory() {
    let mut z = build_zip(&[
        ("a.txt", b"a", CompressionMethod::Stored),
        ("b.txt", b"b", CompressionMethod::Stored),
    ]);
    // An extra-field length that runs the data start past the central
    // directory: the `zip` crate refuses it with or without a signature.
    let first = local_header_offsets(&z)[0];
    z[first + 28..first + 30].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(ZipArchive::new(Cursor::new(&z[..])).is_err());

    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut members = Vec::new();
    let mut errors = Errors::new();
    let archive = open_and_walk(&z, &mut v, &mut m, &mut members, &mut errors).unwrap();
    assert!(archive.is_none());
    let listed = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
    let paths: Vec<&str> = listed.iter().filter_map(|e| e["path"].as_str()).collect();
    assert_eq!(paths, ["a.txt", "b.txt"]);
    assert_eq!(m.get("archive.member_count"), Some(2.0));
    assert_eq!(errors.len(), 1);
}

/// A member past the read cap is refused rather than returned truncated.
#[test]
fn read_member_refuses_a_member_past_the_cap() {
    let z = build_zip(&[("big", &[b'x'; 100], CompressionMethod::Deflated)]);
    let mut archive = open_archive(&z).unwrap();
    assert!(matches!(
        read_member(&mut archive, "big", 99),
        Err(MemberError::TooLarge { max: 99 })
    ));
    assert_eq!(
        read_member(&mut archive, "big", 100)
            .unwrap()
            .unwrap()
            .len(),
        100
    );
    assert!(read_member(&mut archive, "absent", 100).unwrap().is_none());
    let prefix = read_member_prefix(&mut archive, "big", 10)
        .unwrap()
        .unwrap();
    assert_eq!(prefix.bytes.len(), 10);
    assert!(prefix.truncated);
}

/// An input packed with end-of-central-directory records that each point at
/// a directory that is not there. The `zip` crate tries every one and rescans
/// toward the start of the file for each, which took quadratic time (24 s for
/// 1 MiB); its reads are now budgeted, so the open fails promptly.
#[test]
fn failing_end_record_candidates_exhaust_the_open_budget() {
    let mut record = [0_u8; 22];
    record[..4].copy_from_slice(b"PK\x05\x06");
    record[8..10].copy_from_slice(&1_u16.to_le_bytes());
    record[10..12].copy_from_slice(&1_u16.to_le_bytes());
    let bytes = record.repeat((512 << 10) / record.len());

    let start = std::time::Instant::now();
    let Err(ZipError::Io(e)) = open_crate(Cow::Borrowed(&bytes)) else {
        panic!("the open read budget was not what stopped the open");
    };
    assert!(e.to_string().contains("budget"), "{e}");
    assert!(open_archive(&bytes).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(5));

    // A well-formed archive opens, and its members read past the open
    // budget, which is lifted once the archive is open.
    let body = vec![b'x'; 3 << 20];
    let z = build_zip(&[("big.bin", &body, CompressionMethod::Stored)]);
    let mut archive = open_archive(&z).unwrap();
    assert_eq!(
        read_member(&mut archive, "big.bin", 4 << 20)
            .unwrap()
            .unwrap(),
        body
    );
}
