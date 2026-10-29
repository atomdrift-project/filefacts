use super::*;

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    let mut image_end = None;
    extract(bytes, &mut v, &mut s, &mut m, &mut image_end);
    (v, m)
}

#[test]
fn rejects_non_chm() {
    let (v, _) = run(b"not a chm");
    assert!(v.get("chm.itsf").is_none());
}

#[test]
fn surfaces_itsf_header() {
    // Minimal ITSF v3 header with no directory content; we just want
    // to confirm itsf.* surfaces and the parser doesn't crash on a
    // missing/empty directory section.
    let mut buf = vec![0u8; 0x60];
    buf[..4].copy_from_slice(b"ITSF");
    buf[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
    buf[0x10..0x14].copy_from_slice(&42u32.to_le_bytes()); // timestamp_counter
    buf[0x14..0x18].copy_from_slice(&0x0409u32.to_le_bytes()); // lcid = en-US
    // section1 offset/length point past end → empty directory
    buf[0x48..0x50].copy_from_slice(&0u64.to_le_bytes());
    buf[0x50..0x58].copy_from_slice(&0u64.to_le_bytes());
    buf[0x58..0x60].copy_from_slice(&0u64.to_le_bytes());
    let (v, _m) = run(&buf);
    let itsf = v.get("chm.itsf").and_then(|x| x.as_object()).unwrap();
    assert_eq!(itsf.get("version").and_then(|x| x.as_u64()), Some(3));
    assert_eq!(itsf.get("lcid").and_then(|x| x.as_u64()), Some(0x0409));
    assert_eq!(
        itsf.get("timestamp_counter").and_then(|x| x.as_u64()),
        Some(42)
    );
    // LCID is reachable via the nested `chm.itsf.lcid` value
    // surfaced above; no flat `chm.itsf_lcid` metric is emitted.
}

#[test]
fn encint_decodes_single_and_multi_byte() {
    // Single-byte ENCINT (high bit clear).
    assert_eq!(read_encint(&[0x42]), Some((0x42, 1)));
    // Two-byte ENCINT: 0x81 = 1<<7|1, encoded high bits first
    // with the continuation marker on the leading byte.
    assert_eq!(read_encint(&[0x81, 0x01]), Some((0x81, 2)));
    // Empty or all-continuation inputs return None.
    assert_eq!(read_encint(&[]), None);
}

#[test]
fn control_name_classifier() {
    assert!(is_control_name("$OBJINST"));
    assert!(is_control_name("#SYSTEM"));
    assert!(is_control_name("::DataSpace/NameList"));
    assert!(!is_control_name("help/topic.html"));
    assert!(!is_control_name("toc.hhc"));
}

#[test]
fn rejects_wrong_version() {
    // Version 2 (only 3 is supported).
    let mut buf = vec![0u8; 0x60];
    buf[..4].copy_from_slice(b"ITSF");
    buf[0x04..0x08].copy_from_slice(&2u32.to_le_bytes());
    let (v, _) = run(&buf);
    assert!(v.get("chm.itsf").is_none());
}

#[test]
fn truncated_header_doesnt_crash() {
    let (v, _) = run(b"ITSF\x03\0\0\0short");
    assert!(v.get("chm.itsf").is_none());
}

#[test]
fn empty_input_is_silent() {
    let (v, _) = run(&[]);
    assert!(v.get("chm.itsf").is_none());
}

#[test]
fn parse_namelist_handles_known_sections() {
    // u16 reserved + u16 count + 2 entries.
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&2u16.to_le_bytes()); // count
    for name in &["Uncompressed", "MSCompressed"] {
        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for c in name.encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes()); // trailing NUL
    }
    let names = parse_namelist(&buf);
    assert_eq!(names, vec!["Uncompressed", "MSCompressed"]);
}

#[test]
fn control_data_parser_recognizes_lzxc() {
    let mut buf = vec![0u8; 0x1c];
    buf[4..8].copy_from_slice(b"LZXC");
    buf[0x0c..0x10].copy_from_slice(&2u32.to_le_bytes()); // reset_interval_chunks
    buf[0x10..0x14].copy_from_slice(&32u32.to_le_bytes()); // window_chunks (1 MiB)
    let cd = parse_control_data(&buf).unwrap();
    assert_eq!(cd.reset_interval_chunks, 2);
    assert_eq!(cd.window_bytes, 32 * 0x8000);
}

#[test]
fn control_data_rejects_wrong_signature() {
    let mut buf = vec![0u8; 0x1c];
    buf[4..8].copy_from_slice(b"XXXX");
    assert!(parse_control_data(&buf).is_none());
}

#[test]
fn reset_table_rejects_wrong_entry_size() {
    let mut buf = vec![0u8; 0x28];
    // entry_size = 4 instead of expected 8
    buf[0x08..0x0c].copy_from_slice(&4u32.to_le_bytes());
    buf[0x20..0x28].copy_from_slice(&100u64.to_le_bytes()); // block_len
    assert!(parse_reset_table(&buf).is_none());
}

/// A directory of minimal four-byte entries stops at the entry cap and
/// says so.
#[test]
fn directory_entries_stop_at_the_cap() {
    const ITSP_LEN: usize = 0x54;
    for (count, truncated) in [(MAX_DIR_ENTRIES, false), (MAX_DIR_ENTRIES + 1, true)] {
        let chunk_size = 0x14 + count * 4;
        let mut section = vec![0u8; ITSP_LEN];
        section[..4].copy_from_slice(b"ITSP");
        section[0x08..0x0C].copy_from_slice(&(ITSP_LEN as u32).to_le_bytes());
        section[0x10..0x14].copy_from_slice(&(chunk_size as u32).to_le_bytes());
        section[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        // Empty name, section 0, offset 0, length 0: four zero bytes each.
        let mut chunk = vec![0u8; chunk_size];
        chunk[..4].copy_from_slice(b"PMGL");
        section.extend_from_slice(&chunk);
        let (entries, capped) = parse_directory(&section);
        assert_eq!(entries.len(), MAX_DIR_ENTRIES);
        assert_eq!(capped, truncated);
    }
}

/// An ENCINT that decodes to `u64::MAX`: nine continuation bytes and a
/// final `0x7F`.
const HUGE_ENCINT: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];

/// A directory entry whose name length is `u64::MAX` overflowed
/// `pos + name_len` and panicked (a reversed slice range in release
/// builds). It is a malformed entry: parsing stops there, and the
/// entries before it are kept.
#[test]
fn a_huge_entry_name_length_does_not_panic() {
    assert_eq!(read_encint(&HUGE_ENCINT), Some((u64::MAX, 10)));
    let mut entry = HUGE_ENCINT.to_vec();
    entry.extend_from_slice(b"rest of the chunk");
    assert!(parse_entry(&entry).is_none());

    // The same entry reached through a whole file.
    const CHUNK: usize = 0x200;
    const ITSP_LEN: usize = 0x54;
    let mut chunk = vec![0u8; CHUNK];
    chunk[..4].copy_from_slice(b"PMGL");
    let mut entries = vec![7u8];
    entries.extend_from_slice(b"/a.html");
    entries.extend_from_slice(&[0, 0, 1]); // section 0, offset 0, length 1
    entries.extend_from_slice(&HUGE_ENCINT);
    chunk[0x14..0x14 + entries.len()].copy_from_slice(&entries);
    let mut itsp = vec![0u8; ITSP_LEN];
    itsp[..4].copy_from_slice(b"ITSP");
    itsp[0x08..0x0C].copy_from_slice(&(ITSP_LEN as u32).to_le_bytes());
    itsp[0x10..0x14].copy_from_slice(&(CHUNK as u32).to_le_bytes());
    itsp[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
    let mut buf = vec![0u8; 0x60];
    buf[..4].copy_from_slice(b"ITSF");
    buf[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
    buf[0x48..0x50].copy_from_slice(&0x60u64.to_le_bytes());
    buf[0x50..0x58].copy_from_slice(&((ITSP_LEN + CHUNK) as u64).to_le_bytes());
    buf[0x58..0x60].copy_from_slice(&((0x60 + ITSP_LEN + CHUNK) as u64).to_le_bytes());
    buf.extend_from_slice(&itsp);
    buf.extend_from_slice(&chunk);
    buf.push(b'x');
    let (v, m) = run(&buf);
    assert_eq!(v.get("chm.entries"), Some(&serde_json::json!(["/a.html"])));
    assert_eq!(m.get("chm.user_entry_count"), Some(1.0));
}
