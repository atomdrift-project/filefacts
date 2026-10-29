use super::*;
#[test]
fn calli_operands_are_not_rescanned() {
    let b = [
        (10 << 2) | 2,
        0x20,
        0x29,
        0x29,
        0x29,
        0x29,
        0x29,
        1,
        0,
        0,
        0,
    ];
    let r = il_body(&b, 0, 100);
    assert!(r.valid);
    assert_eq!(r.calli, 1);
    assert_eq!(r.instructions, 2);
}
#[test]
fn malformed_switch_is_bounded() {
    let b = [(5 << 2) | 2, 0x45, 255, 255, 255, 255];
    let r = il_body(&b, 0, 100);
    assert!(!r.valid);
    assert_eq!(r.calli, 0);
}
#[test]
fn budget_stops_nops() {
    let b = [(4 << 2) | 2, 0, 0, 0, 0];
    let r = il_body(&b, 0, 2);
    assert_eq!(r.instructions, 2);
    assert!(!r.valid);
}
#[test]
fn truncated_headers_and_operands() {
    for b in [
        &[3, 0][..],
        &[(2 << 2) | 2, 0x28, 0][..],
        &[(1 << 2) | 2, 0xfe][..],
    ] {
        assert!(!il_body(b, 0, 100).valid);
    }
}
#[test]
fn valid_empty_metadata_tables_are_accepted() {
    // Three heaps, no table rows. The valid mask has 64 bits, but ECMA
    // table layouts are supported only through GenericParamConstraint.
    let mut root = vec![0u8; 106];
    root[..4].copy_from_slice(b"BSJB");
    root[12..16].copy_from_slice(&4u32.to_le_bytes());
    root[16..20].copy_from_slice(b"v4\0\0");
    root[22..24].copy_from_slice(&3u16.to_le_bytes());
    for (p, offset, len, name) in [
        (24usize, 80u32, 24u32, b"#~".as_slice()),
        (36, 104, 1, b"#Strings".as_slice()),
        (56, 105, 1, b"#Blob".as_slice()),
    ] {
        root[p..p + 4].copy_from_slice(&offset.to_le_bytes());
        root[p + 4..p + 8].copy_from_slice(&len.to_le_bytes());
        root[p + 8..p + 8 + name.len()].copy_from_slice(name);
    }
    assert!(Tables::new(&root, 0).is_some());
    let analysis = analyze(&root, 0, &root, |_| None);
    assert!(analysis.is_some());
    assert_eq!(analysis.map(|a| a.method_count), Some(0));
}
#[test]
fn metadata_empty_and_truncated() {
    for b in [
        b"".as_slice(),
        b"BSJB".as_slice(),
        b"BSJB\0\0\0\0\0\0\0\0\xff\xff\xff\xff".as_slice(),
    ] {
        assert!(Tables::new(b, 0).is_none());
    }
}
