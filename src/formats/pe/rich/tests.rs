use super::*;

#[test]
fn no_rich_header_is_silent() {
    // A minimal "PE-ish" buffer with no Rich marker.
    let mut buf = vec![0u8; 0x80];
    // PE signature offset.
    buf[0x3c] = 0x40;
    let mut v = Values::new();
    extract(&buf, &mut v);
    assert!(v.is_empty());
}

/// `extract` decodes the table `locate` finds; a marker with none is one
/// goblin rejects, so `goblin_safe` clears it.
#[test]
fn locate_drives_extract_and_the_goblin_neutraliser() {
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture");
    let rich = locate(&bytes).expect("MSVC fixture has a Rich header");
    let dans = rich.dans_pos.expect("and a decodable table");
    assert_eq!(rich.key, 110_128_735);
    assert!(matches!(
        crate::formats::goblin_safe::prepare_pe(&bytes).bytes,
        std::borrow::Cow::Borrowed(_)
    ));

    // Break the DanS marker: the magic stays, the table is gone.
    let mut broken = bytes.clone();
    broken[dans] ^= 0xff;
    let rich = locate(&broken).expect("marker still present");
    assert_eq!(rich.dans_pos, None);
    let mut v = Values::new();
    extract(&broken, &mut v);
    assert!(v.is_empty(), "no table, no facts");
    let std::borrow::Cow::Owned(patched) = crate::formats::goblin_safe::prepare_pe(&broken).bytes
    else {
        panic!("goblin would reject it, so the marker is cleared on a copy");
    };
    assert_eq!(&patched[rich.rich_pos..rich.rich_pos + 4], &[0, 0, 0, 0]);
    assert!(locate(&patched).is_none_or(|r| r.rich_pos != rich.rich_pos));
}

#[test]
fn locate_takes_the_last_marker_in_the_stub() {
    let mut buf = vec![0u8; 0x80];
    buf[0x3c] = 0x60;
    buf[20..24].copy_from_slice(b"Rich");
    buf[40..44].copy_from_slice(b"Rich");
    buf[0x60..0x64].copy_from_slice(b"Rich");
    assert_eq!(locate(&buf).map(|rich| rich.rich_pos), Some(40));
}

/// End-to-end Rich header decode for the canonical `test.exe`
/// fixture. Pinning the key, the canonical MD5, and the first
/// entry's `(product_id, build_id, use_count)` guards against
/// silent drift in the XOR-key recovery, tuple walker, or hash
/// computation. Regenerate values by running
/// `cargo run --bin filefacts -- tests/fixtures/test.exe`.
#[test]
fn rich_header_decodes_test_exe_to_known_values() {
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture is required");
    let mut v = Values::new();
    extract(&bytes, &mut v);

    assert_eq!(
        v.get("pe.rich.key").and_then(|x| x.as_u64()),
        Some(110_128_735),
    );
    assert_eq!(
        v.get("pe.rich.hash").and_then(|x| x.as_str()),
        Some("d7fdfa1db9e0bba7aef35f999a032c9a"),
    );
    let entries = v
        .get("pe.rich.entries")
        .and_then(|x| x.as_array())
        .expect("entries populated for a Rich-header PE");
    assert_eq!(entries.len(), 10);
    let first = &entries[0];
    assert_eq!(
        first.get("product_id").and_then(|x| x.as_u64()),
        Some(30729),
    );
    assert_eq!(first.get("build_id").and_then(|x| x.as_u64()), Some(147));
    assert_eq!(first.get("use_count").and_then(|x| x.as_u64()), Some(10));
}

/// A DOS stub of `pairs` Rich entries under key 0x01020304, `e_lfanew`
/// just past the key.
fn stub_with_rich_entries(pairs: usize) -> Vec<u8> {
    let key = 0x0102_0304_u32;
    let mut buf = vec![0u8; 0x80];
    let word = |w: u32| (w ^ key).to_le_bytes();
    buf.extend_from_slice(&word(DANS_MARKER));
    for _ in 0..3 {
        buf.extend_from_slice(&word(0));
    }
    for i in 0..pairs {
        buf.extend_from_slice(&word(0x0001_0000 | i as u32));
        buf.extend_from_slice(&word(1));
    }
    buf.extend_from_slice(b"Rich");
    buf.extend_from_slice(&key.to_le_bytes());
    let end = buf.len() as u32;
    buf[0x3c..0x40].copy_from_slice(&end.to_le_bytes());
    buf
}

/// Every eight bytes of a table become a JSON object some thirty times
/// their size, and the stub runs as far as `e_lfanew` says. The entry list
/// is capped; the hash still covers the whole table.
#[test]
fn rich_entries_are_capped() {
    let entries = |v: &Values| {
        v.get("pe.rich.entries")
            .and_then(JsonValue::as_array)
            .map(Vec::len)
    };
    let mut v = Values::new();
    extract(&stub_with_rich_entries(3), &mut v);
    assert_eq!(entries(&v), Some(3));

    let big = stub_with_rich_entries(MAX_RICH_ENTRIES * 4);
    let mut v = Values::new();
    extract(&big, &mut v);
    assert_eq!(entries(&v), Some(MAX_RICH_ENTRIES));
    assert!(v.get("pe.rich.hash").is_some());
}
