use super::*;
use crate::output::{Metrics, Values};

fn vint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

fn rar5_block(
    htype: u64,
    hflags: u64,
    extra_size: u64,
    data_size: Option<u64>,
    specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut after_size = Vec::new();
    after_size.extend(vint(htype));
    after_size.extend(vint(hflags));
    if hflags & HFL_EXTRA != 0 {
        after_size.extend(vint(extra_size));
    }
    if hflags & HFL_DATA != 0 {
        after_size.extend(vint(data_size.unwrap_or(data.len() as u64)));
    }
    after_size.extend_from_slice(specific);
    after_size.extend_from_slice(extra);
    let header_size = after_size.len() as u64;
    let mut sized = vint(header_size);
    sized.extend(after_size);
    let crc = crc32fast::hash(&sized);
    let mut out = Vec::new();
    out.extend(crc.to_le_bytes());
    out.extend(sized);
    out.extend_from_slice(data);
    out
}

fn rar5_main() -> Vec<u8> {
    let mut specific = Vec::new();
    specific.extend(vint(0));
    rar5_block(HEAD5_MAIN, 0, 0, None, &specific, &[], &[])
}

fn rar5_end() -> Vec<u8> {
    rar5_block(HEAD5_END, 0, 0, None, &vint(0), &[], &[])
}

fn rar5_file(path: &str, payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut flags = HFL_DATA;
    if !extra.is_empty() {
        flags |= HFL_EXTRA;
    }
    let mut specific = Vec::new();
    specific.extend(vint(LHFL_CRC32 | LHFL_UTIME));
    specific.extend(vint(payload.len() as u64));
    specific.extend(vint(0));
    specific.extend(1_700_000_000u32.to_le_bytes());
    specific.extend(crc32fast::hash(payload).to_le_bytes());
    specific.extend(vint(0));
    specific.extend(vint(1));
    let name = path.as_bytes();
    specific.extend(vint(name.len() as u64));
    specific.extend_from_slice(name);
    rar5_block(
        HEAD5_FILE,
        flags,
        extra.len() as u64,
        Some(payload.len() as u64),
        &specific,
        extra,
        payload,
    )
}

fn archive(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = SIG5.to_vec();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn run(bytes: &[u8]) -> (Values, Metrics, Vec<ArchiveMember>) {
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    let mut typed = Vec::new();
    extract(bytes, &mut values, &mut metrics, &mut typed).unwrap();
    (values, metrics, typed)
}

/// Packed data declared past the end of the file stops the walk there.
/// Before, a failed skip left the cursor at the header's end, so the
/// payload bytes were parsed as further headers -- here, a planted
/// `ghost.exe` member.
#[test]
fn data_past_end_of_file_is_not_parsed_as_headers() {
    let mut specific = Vec::new();
    specific.extend(vint(0)); // file flags
    specific.extend(vint(0)); // unpacked size
    specific.extend(vint(0)); // attributes
    specific.extend(vint(0)); // compression info
    specific.extend(vint(1)); // host OS
    specific.extend(vint(MAX_NAME as u64 + 1)); // name over the cap
    let ghost = [rar5_file("ghost.exe", b"x", &[]), rar5_end()].concat();
    let declared = ghost.len() as u64 + 4096;
    let long_name = rar5_block(
        HEAD5_FILE,
        HFL_DATA,
        0,
        Some(declared),
        &specific,
        &[],
        &ghost,
    );
    let (values, _, typed) = run(&archive(&[&rar5_main(), &long_name]));

    assert!(typed.iter().all(|m| m.path != "ghost.exe"), "{typed:?}");
    let limits = values
        .get("rar.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert!(limits.iter().any(|l| l["stage"] == "data"), "{limits:?}");
}

#[test]
fn stored_member_name_is_not_overread() {
    let payload = b"not an executable";
    let bytes = archive(&[
        &rar5_main(),
        &rar5_file("Setup.exe", payload, &[]),
        &rar5_end(),
    ]);
    let (values, metrics, typed) = run(&bytes);

    let members = values.get("archive.members").unwrap().as_array().unwrap();
    assert_eq!(
        values.get("rar.members").unwrap().as_array().unwrap().len(),
        1
    );
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["path"].as_str(), Some("Setup.exe"));
    assert_eq!(
        members[0]["size_bytes"].as_u64(),
        Some(payload.len() as u64)
    );
    assert_eq!(members[0]["compression_method"].as_str(), Some("stored"));
    assert_eq!(members[0]["host_os"].as_str(), Some("unix"));
    assert_eq!(typed.len(), 1);
    assert!(!typed[0].path.ends_with('0'));
    assert_eq!(metrics.get("archive.file_count"), Some(1.0));
    assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
    assert_eq!(metrics.get("archive.security.encrypted_count"), Some(0.0));
    assert_eq!(
        values
            .get("archive.format.kind")
            .and_then(JsonValue::as_str),
        Some("rar")
    );
    assert_eq!(
        values.get("rar.version").and_then(JsonValue::as_str),
        Some("5")
    );
    assert_eq!(metrics.get("rar.end_present"), Some(1.0));
}

#[test]
fn encryption_extra_marks_the_member_without_reading_payload() {
    let mut extra_rec = Vec::new();
    let mut body = Vec::new();
    body.extend(vint(0x01));
    body.extend(vint(0));
    body.extend(vint(0x0001));
    body.push(15);
    body.extend([0u8; 16]);
    body.extend([1u8; 16]);
    extra_rec.extend(vint(body.len() as u64));
    extra_rec.extend(body);

    let bytes = archive(&[
        &rar5_main(),
        &rar5_file("Aigoogle 1.0/Setup.msi", b"xxxx", &extra_rec),
        &rar5_end(),
    ]);
    let (values, metrics, typed) = run(&bytes);
    let members = values.get("archive.members").unwrap().as_array().unwrap();
    assert_eq!(members[0]["path"].as_str(), Some("Aigoogle 1.0/Setup.msi"));
    assert_eq!(members[0]["encrypted"].as_bool(), Some(true));
    assert_eq!(members[0]["kdf_count"].as_u64(), Some(15));
    assert!(typed[0].encrypted);
    assert_eq!(metrics.get("archive.security.encrypted_count"), Some(1.0));
}

#[test]
fn original_name_and_comment_are_archive_identity() {
    // Flags carry only 0x0001 (name present) | 0x0002 (time present):
    // 0x0004 (unix time) is deliberately left unset, so the creation
    // time is an 8-byte Windows FILETIME — the common shape for an
    // archive built on Windows, and the exact combination the metadata
    // record's own flags (not the File-time record's 0x0001/0x0010) must
    // be consulted to decode correctly.
    let mut meta_body = Vec::new();
    meta_body.extend(vint(0x02));
    meta_body.extend(vint(0x0001 | 0x0002));
    let name = b"campaign.rar";
    meta_body.extend(vint(name.len() as u64));
    meta_body.extend_from_slice(name);
    meta_body.extend(132_444_736_000_000_000u64.to_le_bytes());
    let mut extra = vint(meta_body.len() as u64);
    extra.extend(meta_body);
    let specific = vint(0);
    let main = rar5_block(
        HEAD5_MAIN,
        HFL_EXTRA,
        extra.len() as u64,
        None,
        &specific,
        &extra,
        &[],
    );

    let comment = b"packed dropper";
    let mut cmt_specific = Vec::new();
    cmt_specific.extend(vint(LHFL_CRC32));
    cmt_specific.extend(vint(comment.len() as u64));
    cmt_specific.extend(vint(0));
    cmt_specific.extend(crc32fast::hash(comment).to_le_bytes());
    cmt_specific.extend(vint(0));
    cmt_specific.extend(vint(1));
    cmt_specific.extend(vint(3));
    cmt_specific.extend(b"CMT");
    let cmt = rar5_block(
        HEAD5_SERVICE,
        HFL_DATA,
        0,
        Some(comment.len() as u64),
        &cmt_specific,
        &[],
        comment,
    );

    let bytes = archive(&[&main, &cmt, &rar5_file("a.txt", b"hi", &[]), &rar5_end()]);
    let (values, _, _) = run(&bytes);
    assert_eq!(
        values.get("rar.original_name").and_then(JsonValue::as_str),
        Some("campaign.rar")
    );
    assert_eq!(
        values.get("rar.created_unix").and_then(JsonValue::as_i64),
        Some(1_600_000_000)
    );
    assert_eq!(
        values.get("rar.comment").and_then(JsonValue::as_str),
        Some("packed dropper")
    );
}

#[test]
fn trailing_bytes_and_sfx_prefix_are_counted() {
    let mut bytes = vec![0x4d, 0x5a, 0x00, 0x00];
    bytes.extend(archive(&[
        &rar5_main(),
        &rar5_file("a.txt", b"hi", &[]),
        &rar5_end(),
    ]));
    let end = bytes.len();
    bytes.extend_from_slice(&[0x41; 32]);
    let (_, metrics, _) = run(&bytes);
    assert_eq!(metrics.get("archive.leading_bytes"), Some(4.0));
    assert_eq!(metrics.get("rar.sfx_bytes"), Some(4.0));
    assert_eq!(metrics.get("archive.trailing_bytes"), Some(32.0));
    assert!(end > 4);
}

#[test]
fn ntfs_stream_is_tied_to_the_preceding_file() {
    let mut stm_specific = Vec::new();
    stm_specific.extend(vint(0));
    stm_specific.extend(vint(3));
    stm_specific.extend(vint(0));
    stm_specific.extend(vint(0));
    stm_specific.extend(vint(1));
    stm_specific.extend(vint(3));
    stm_specific.extend(b"STM");
    let mut rec = Vec::new();
    rec.extend(vint(0x07));
    rec.extend(b"Zone.Identifier");
    let mut extra = vint(rec.len() as u64);
    extra.extend(rec);
    let stm = rar5_block(
        HEAD5_SERVICE,
        HFL_EXTRA | HFL_DATA | HFL_CHILD,
        extra.len() as u64,
        Some(3),
        &stm_specific,
        &extra,
        b"xyz",
    );
    let bytes = archive(&[
        &rar5_main(),
        &rar5_file("invoice.txt", b"lure", &[]),
        &stm,
        &rar5_end(),
    ]);
    let (values, metrics, typed) = run(&bytes);
    assert_eq!(metrics.get("rar.ntfs_stream_count"), Some(1.0));
    assert!(
        typed
            .iter()
            .any(|m| m.path == "invoice.txt:Zone.Identifier"),
        "{typed:?}"
    );
    assert_eq!(
        values
            .get("rar.ntfs_streams[0].stream")
            .and_then(JsonValue::as_str),
        Some("Zone.Identifier")
    );
}

#[test]
fn symlink_and_unix_owner_land_on_the_member() {
    let mut recs = Vec::new();
    let mut redir = Vec::new();
    redir.extend(vint(0x05));
    redir.extend(vint(1));
    redir.extend(vint(0));
    redir.extend(vint(11));
    redir.extend(b"/etc/passwd");
    recs.extend(vint(redir.len() as u64));
    recs.extend(redir);
    let mut extra_only = Extra::default();
    parse_extra(&recs, &mut extra_only);
    assert_eq!(
        extra_only.linkname.as_deref(),
        Some("/etc/passwd"),
        "extra-only {recs:?}"
    );

    let mut owner = Vec::new();
    owner.extend(vint(0x06));
    owner.extend(vint(0x0001 | 0x0004));
    owner.extend(vint(4));
    owner.extend(b"root");
    owner.extend(vint(0));
    recs.extend(vint(owner.len() as u64));
    recs.extend(owner);

    let bytes = archive(&[&rar5_main(), &rar5_file("link", b"", &recs), &rar5_end()]);
    let (values, metrics, typed) = run(&bytes);
    let m = &values.get("archive.members").unwrap().as_array().unwrap()[0];
    assert_eq!(m["linkname"].as_str(), Some("/etc/passwd"));
    assert_eq!(m["redir_type"].as_str(), Some("unix-symlink"));
    assert_eq!(m["uname"].as_str(), Some("root"));
    assert_eq!(typed[0].linkname.as_deref(), Some("/etc/passwd"));
    assert_eq!(metrics.get("archive.security.symlink_count"), Some(1.0));
}

#[test]
fn unix_nanosecond_timestamps_do_not_desync_ctime() {
    // Per the RAR5 technote, the Time extra record (type 0x03) lays out
    // flags, then mtime/ctime/atime (each present per its own flag bit),
    // and only after all three, trailing per-field nanosecond
    // refinements gated by 0x0010. mtime must not swallow ctime's bytes.
    let mtime_secs: u32 = 1_700_000_111;
    let ctime_secs: u32 = 1_600_000_222;
    let mut body = Vec::new();
    body.extend(vint(0x0001 | 0x0002 | 0x0004 | 0x0010));
    body.extend(mtime_secs.to_le_bytes());
    body.extend(ctime_secs.to_le_bytes());
    body.extend(123_456_789u32.to_le_bytes()); // mtime nanoseconds
    body.extend(987_654_321u32.to_le_bytes()); // ctime nanoseconds

    let mut rec = vint(0x03);
    rec.extend(body);
    let mut recs = vint(rec.len() as u64);
    recs.extend(rec);

    let mut extra = Extra::default();
    parse_extra(&recs, &mut extra);
    assert_eq!(extra.mtime, Some(i64::from(mtime_secs)));
    assert_eq!(extra.ctime, Some(i64::from(ctime_secs)));
    assert_eq!(extra.atime, None);
}

fn rar4_block(htype: u8, flags: u16, rest: &[u8]) -> Vec<u8> {
    let head_size = 7 + rest.len();
    let mut body = Vec::new();
    body.push(htype);
    body.extend(flags.to_le_bytes());
    body.extend((head_size as u16).to_le_bytes());
    body.extend_from_slice(rest);
    let crc = crc32fast::hash(&body) as u16;
    let mut out = Vec::new();
    out.extend(crc.to_le_bytes());
    out.extend(body);
    out
}

#[test]
fn rar4_stored_member_and_password_flag() {
    let payload = b"hello";
    let mut main_rest = Vec::new();
    main_rest.extend(0u16.to_le_bytes());
    main_rest.extend(0u32.to_le_bytes());
    let main = rar4_block(R4_MAIN, 0, &main_rest);

    let name = b"payload.exe";
    let mut file_rest = Vec::new();
    file_rest.extend((payload.len() as u32).to_le_bytes());
    file_rest.extend((payload.len() as u32).to_le_bytes());
    file_rest.push(2);
    file_rest.extend(crc32fast::hash(payload).to_le_bytes());
    file_rest.extend(0u32.to_le_bytes());
    file_rest.push(20);
    file_rest.push(0x30);
    file_rest.extend((name.len() as u16).to_le_bytes());
    file_rest.extend(0x20u32.to_le_bytes());
    file_rest.extend_from_slice(name);
    let mut file = rar4_block(R4_FILE, R4_LONG_BLOCK | R4_LHD_PASSWORD, &file_rest);
    file.extend_from_slice(payload);

    let end = rar4_block(R4_END, 0, &[]);
    let mut bytes = SIG4.to_vec();
    bytes.extend(main);
    bytes.extend(file);
    bytes.extend(end);

    let (values, metrics, typed) = run(&bytes);
    assert_eq!(
        values.get("rar.version").and_then(JsonValue::as_str),
        Some("4")
    );
    assert_eq!(
        values
            .get("archive.members[0].path")
            .and_then(JsonValue::as_str),
        Some("payload.exe")
    );
    assert_eq!(
        values
            .get("archive.members[0].encrypted")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(typed[0].host_os.as_deref(), Some("windows"));
    assert_eq!(metrics.get("archive.security.encrypted_count"), Some(1.0));
    assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
}

#[test]
fn missing_signature_is_malformed() {
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    let mut typed = Vec::new();
    let err = extract(b"not a rar", &mut values, &mut metrics, &mut typed).unwrap_err();
    assert!(matches!(err, Error::Malformed { format: "rar", .. }));
}
