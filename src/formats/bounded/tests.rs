use super::*;
use std::io::Write;

/// A gzipped tar holding the given members.
fn targz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, body) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *body).unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

#[test]
fn finds_the_member_and_caps_it() {
    let bytes = targz(&[("pkg/a", b"skip"), ("pkg/manifest", b"0123456789")]);
    let found = find_targz_member(&bytes, |p| p == "pkg/manifest", 4).unwrap();
    let TarGzSearch::Found { path, prefix } = found else {
        panic!("member not found");
    };
    assert_eq!(path, "pkg/manifest");
    assert_eq!(prefix.bytes, b"0123");
    assert!(prefix.truncated);
}

#[test]
fn absent_member_is_not_an_error() {
    let bytes = targz(&[("pkg/a", b"x")]);
    let found = find_targz_member(&bytes, |p| p == "pkg/manifest", 64).unwrap();
    assert!(matches!(found, TarGzSearch::Absent));
}

/// A tarball whose manifest sits behind more inflated bytes than the
/// budget stops at the budget instead of inflating the whole stream.
#[test]
fn search_stops_at_the_inflate_budget() {
    let padding = vec![0_u8; 1 << 20];
    let bytes = targz(&[("pkg/pad", &padding), ("pkg/manifest", b"{}")]);
    let found = find_targz_member_within(&bytes, |p| p == "pkg/manifest", 64, 64 << 10).unwrap();
    assert!(matches!(found, TarGzSearch::InflateCapped));
    // With room, the same tarball yields the manifest.
    let found = find_targz_member_within(&bytes, |p| p == "pkg/manifest", 64, 4 << 20).unwrap();
    assert!(matches!(found, TarGzSearch::Found { .. }));
}

#[test]
fn utf8_prefix_drops_a_character_cut_by_the_cap() {
    let cut = MemberPrefix {
        bytes: "aé".as_bytes()[..2].to_vec(),
        truncated: true,
    };
    assert_eq!(utf8_prefix(cut).unwrap(), "a");
    let invalid = MemberPrefix {
        bytes: vec![b'a', 0xff, b'b'],
        truncated: true,
    };
    assert!(utf8_prefix(invalid).is_err());
    let whole_but_cut = MemberPrefix {
        bytes: "aé".as_bytes()[..2].to_vec(),
        truncated: false,
    };
    assert!(utf8_prefix(whole_but_cut).is_err());
}

#[test]
fn limits_emit_in_order_and_only_when_hit() {
    let mut values = Values::new();
    let key = crate::value_key!("pdf.limits");
    Limits::default().emit(&mut values, key);
    assert!(values.get_key(key).is_none());
    let mut limits = Limits::default();
    limits.push("a", "first");
    limits.push("b", "second");
    limits.emit(&mut values, key);
    let list = values.get_key(key).and_then(JsonValue::as_array).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[1]["stage"].as_str(), Some("b"));
    assert_eq!(list[1]["reason"].as_str(), Some("second"));
}

#[test]
fn inflate_capped_marks_a_member_past_the_cap() {
    let exact = inflate_capped(&b"abcd"[..], 4).unwrap();
    assert_eq!(exact.bytes, b"abcd");
    assert!(!exact.truncated);
    let over = inflate_capped(&b"abcde"[..], 4).unwrap();
    assert_eq!(over.bytes, b"abcd");
    assert!(over.truncated);
}

/// A zstd frame whose header asks for a `2^window_log` window: no content
/// size, one raw block holding "hello".
fn zstd_frame(window_log: u32) -> Vec<u8> {
    let exponent = u8::try_from(window_log - 10).unwrap();
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, exponent << 3];
    // Last block, raw, five bytes.
    frame.extend_from_slice(&[1 | (5 << 3), 0, 0]);
    frame.extend_from_slice(b"hello");
    frame
}

/// An xz stream holding "hello" whose LZMA2 filter declares the
/// dictionary `dict_prop` encodes (40 is the largest, 4 GiB).
fn xz_stream(dict_prop: Option<u8>) -> Vec<u8> {
    let mut xz =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    std::io::Write::write_all(&mut xz, b"hello").unwrap();
    let mut bytes = xz.finish().unwrap();
    if let Some(prop) = dict_prop {
        // The block header follows the 12-byte stream header; its filter
        // flags read `21 01 <dict>` and it ends in its own CRC-32.
        let len = (usize::from(bytes[12]) + 1) * 4;
        let header = 12..12 + len;
        let at = bytes[header.clone()]
            .windows(2)
            .position(|w| w == [0x21, 0x01])
            .unwrap();
        bytes[12 + at + 2] = prop;
        let crc = crc32fast::hash(&bytes[12..header.end - 4]);
        bytes[header.end - 4..header.end].copy_from_slice(&crc.to_le_bytes());
    }
    bytes
}

/// A stream whose header asks for a dictionary past the cap is refused
/// before the decoder allocates it; one at the cap decodes.
#[test]
fn oversized_dictionaries_are_refused() {
    let mut out = Vec::new();
    let refused = zstd_decoder(&zstd_frame(MAX_DICTIONARY_LOG + 1)[..])
        .and_then(|mut d| d.read_to_end(&mut out));
    assert!(refused.is_err());
    let mut out = Vec::new();
    zstd_decoder(&zstd_frame(MAX_DICTIONARY_LOG)[..])
        .and_then(|mut d| d.read_to_end(&mut out))
        .unwrap();
    assert_eq!(out, b"hello");

    let mut out = Vec::new();
    assert!(
        xz_decoder(&xz_stream(Some(40))[..])
            .read_to_end(&mut out)
            .is_err()
    );
    let mut out = Vec::new();
    xz_decoder(&xz_stream(None)[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, b"hello");
}

/// A tarball that is not gzip fails the walk; the recorded line names
/// the member sought, and the failure keeps the I/O error as its source.
#[test]
fn member_failures_keep_their_source_and_record_one_line() {
    let Err(walk) = find_targz_member(b"not gzip", |_| true, 1024) else {
        panic!("a tarball that is not gzip fails the walk");
    };
    let failure = walk.into_failure(Stage::TarParse, "<root>/PKG-INFO");
    assert!(std::error::Error::source(&failure).is_some());
    let mut errors = Errors::new();
    failure.record(&mut errors);
    let recorded = errors.iter().next().unwrap();
    assert_eq!(recorded.stage, Stage::TarParse);
    assert!(
        recorded
            .message
            .starts_with("tarball unreadable before <root>/PKG-INFO: "),
        "{}",
        recorded.message
    );
}
