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

#[test]
fn rich_md5_is_deterministic() {
    let bytes = b"hello world here is some data";
    let h1 = rich_md5(bytes, 0xdead_beef);
    let h2 = rich_md5(bytes, 0xdead_beef);
    assert_eq!(h1, h2);
    // Different key changes the digest.
    let h3 = rich_md5(bytes, 0xcafe_babe);
    assert_ne!(h1, h3);
}

/// `locate` is the one Rich scan: `extract` decodes a located table and
/// `goblin_safe` neutralises a marker that has none.
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
fn find_rich_marker_locates_last_occurrence() {
    let mut buf = vec![0u8; 64];
    buf[20..24].copy_from_slice(b"Rich");
    buf[40..44].copy_from_slice(b"Rich");
    assert_eq!(find_rich_marker(&buf), Some(40));
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
