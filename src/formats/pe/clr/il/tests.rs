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

/// Metadata of one type and `methods` methods, every name the same
/// `name_len`-byte string, each method's IL a lone `ret` at offset 0.
fn metadata_with_long_names(methods: usize, name_len: usize) -> Vec<u8> {
    let strings_len = name_len + 2;
    let tables_len = 32 + 14 + 14 * methods;
    let (tables, strings) = (80, 80 + tables_len);
    let blob = strings + strings_len;
    let mut root = vec![0u8; blob + 1];
    root[..4].copy_from_slice(b"BSJB");
    root[12..16].copy_from_slice(&4u32.to_le_bytes());
    root[16..20].copy_from_slice(b"v4\0\0");
    root[22..24].copy_from_slice(&3u16.to_le_bytes());
    for (p, offset, len, name) in [
        (24usize, tables, tables_len, b"#~".as_slice()),
        (36, strings, strings_len, b"#Strings".as_slice()),
        (56, blob, 1, b"#Blob".as_slice()),
    ] {
        root[p..p + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        root[p + 4..p + 8].copy_from_slice(&(len as u32).to_le_bytes());
        root[p + 8..p + 8 + name.len()].copy_from_slice(name);
    }
    // Tables: TypeDef (2) and MethodDef (6), all indexes two bytes wide.
    let valid = (1u64 << 2) | (1 << 6);
    root[tables + 8..tables + 16].copy_from_slice(&valid.to_le_bytes());
    root[tables + 24..tables + 28].copy_from_slice(&1u32.to_le_bytes());
    root[tables + 28..tables + 32].copy_from_slice(&(methods as u32).to_le_bytes());
    let typedef = tables + 32;
    root[typedef + 4..typedef + 6].copy_from_slice(&1u16.to_le_bytes()); // name
    root[typedef + 12..typedef + 14].copy_from_slice(&1u16.to_le_bytes()); // method list
    for i in 0..methods {
        let row = typedef + 14 + 14 * i;
        root[row..row + 4].copy_from_slice(&1u32.to_le_bytes()); // RVA
        root[row + 8..row + 10].copy_from_slice(&1u16.to_le_bytes()); // name
    }
    root[strings + 1..strings + 1 + name_len].fill(b'a');
    root
}

/// A few hundred kilobytes of rows may name one long string thousands of
/// times over, and each name is copied into several views. The copies stay
/// within a budget, and an analysis that reaches it says it was cut short.
#[test]
fn name_copies_are_budgeted() {
    let ret = [(1 << 2) | 2, 0x2a];
    let small = metadata_with_long_names(4, 16);
    let analysis = analyze(&small, 0, &ret, |_| Some(0)).expect("parses");
    assert!(!analysis.truncated);
    assert_eq!(analysis.methods.len(), 4);
    assert_eq!(analysis.methods[0].name, format!("{0}.{0}", "a".repeat(16)));

    let forged = metadata_with_long_names(20_000, 4000);
    let analysis = analyze(&forged, 0, &ret, |_| Some(0)).expect("parses");
    assert!(analysis.truncated);
    let copied: usize = analysis.methods.iter().map(|m| m.name.len()).sum();
    assert!(copied <= MAX_NAME_BYTES);
}
