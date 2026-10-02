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
    // Bytes don't matter — compressed variants are never walked here.
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut archive_members = Vec::new();
    let result = extract(
        b"any bytes",
        FileType::TarGz,
        &mut values,
        &mut metrics,
        &mut archive_members,
    );
    assert!(result.is_ok(), "label-only is not a parse failure");
    assert_eq!(
        values.get("archive.format.kind").and_then(|x| x.as_str()),
        Some("tar.gz")
    );
    assert!(values.get("archive.members").is_none());
}

/// A well-formed `.tar.gz` used to come back with a `malformed` error,
/// because declining to walk the compressed stream was reported as a
/// failed parse.
#[test]
fn valid_tar_gz_opens_without_errors() {
    use std::io::Write;
    let tar = build_tar(&[("pkg/README", 0o644, 0, 0, 1_700_000_000, b"hello\n")]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    let bytes = gz.finish().unwrap();

    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("pkg.tar.gz"))
        .open(&bytes);
    assert_eq!(parsed.fileid().file_type(), FileType::TarGz);
    assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
    assert_eq!(
        parsed
            .values()
            .get("archive.format.kind")
            .and_then(|x| x.as_str()),
        Some("tar.gz")
    );
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

/// A GNU base-256 mtime of 2^63 reads back as `i64::MIN`. Its spread
/// against an ordinary mtime overflowed `max - min`, a panic in builds
/// with overflow checks and a wrapped, negative spread otherwise.
#[test]
fn base256_mtime_spread_does_not_overflow() {
    let mut out: Vec<u8> = Vec::new();
    {
        let mut b = Builder::new(&mut out);
        for (name, mtime) in [("old", 1u64 << 63), ("new", 1_700_000_000)] {
            let mut h = Header::new_gnu();
            h.set_path(name).unwrap();
            h.set_size(1);
            h.set_mtime(mtime);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, &b"x"[..]).unwrap();
        }
        b.finish().unwrap();
    }
    let (v, m) = run(&out);
    assert_eq!(
        v.get("archive.timing.mtime_min").and_then(|x| x.as_i64()),
        Some(i64::MIN)
    );
    assert_eq!(
        m.get("archive.timing.mtime_spread_seconds"),
        Some((1_700_000_000u64 + (1u64 << 63)) as f64)
    );
}

#[test]
fn tar_file_count_and_total_uncompressed() {
    let tar = build_tar(&[
        ("a.txt", 0o644, 0, 0, 0, b"hello"),
        ("b.txt", 0o644, 0, 0, 0, b"world"),
    ]);
    let (_, m) = run(&tar);
    assert_eq!(m.get("archive.file_count"), Some(2.0));
    assert_eq!(m.get("archive.uncompressed_size"), Some(10.0));
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
