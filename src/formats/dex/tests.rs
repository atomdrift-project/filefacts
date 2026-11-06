use super::*;
fn observed(code: &[u16], literal_budget: usize) -> (Vec<Symbol>, Literals) {
    let mut bytes = vec![0; 16];
    bytes[12..16].copy_from_slice(&(code.len() as u32).to_le_bytes());
    for unit in code {
        bytes.extend(unit.to_le_bytes());
    }
    let dex = Dex {
        bytes: &bytes,
        strings: vec![Some("/data/".to_owned())],
        classes: Table::default(),
        methods: vec![
            Some(Method {
                name: "LExample;->run".to_owned(),
                params: vec![],
                external: false,
            }),
            Some(Method {
                name: "Landroid/net/wifi/WifiManager;->setWifiEnabled".to_owned(),
                params: vec![false],
                external: true,
            }),
            Some(Method {
                name: "LExample;->remove".to_owned(),
                params: vec![false],
                external: false,
            }),
        ],
    };
    let mut result = Symbols::new();
    let mut budget = Budget {
        code: 1000,
        literals: literal_budget,
        names: MAX_SYMBOL_NAME_BYTES,
    };
    let mut literals = Literals::new();
    inspect(&dex, 0, 0, &mut result, &mut literals, &mut budget).unwrap();
    let calls = result
        .iter()
        .filter(|s| matches!(s, Symbol::Call { .. }))
        .cloned()
        .collect();
    (calls, literals)
}
fn calls(code: &[u16]) -> Vec<Symbol> {
    observed(code, 8192).0
}
#[test]
fn only_referenced_constants_become_literals() {
    assert!(observed(&[0x000e], 8192).1.is_empty());
    let (_, literals) = observed(&[0x001a, 0, 0x000e], 8192);
    assert_eq!(literals.len(), 1);
    assert_eq!(literals.as_slice()[0].value, "/data/");
    assert_eq!(literals.as_slice()[0].offset, 16);
    assert!(observed(&[0x001a, 0, 0x000e], 2).1.is_empty());
}
#[test]
fn jumbo_string_reference_becomes_literal() {
    let (_, literals) = observed(&[0x001b, 0, 0, 0x000e], 8192);
    assert_eq!(literals.as_slice()[0].value, "/data/");
}
#[test]
fn distinguishes_true_and_false() {
    for value in [0, 1] {
        let out = calls(&[(value << 12) | 0x0112, 0x206e, 1, 0x0010, 0x000e]);
        assert!(
            matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Number{value:v,..} if *v==i64::from(value)))
        );
    }
}
#[test]
fn signed_constants_retain_their_values() {
    for (mut code, expected) in [
        (vec![0x8112], -8),
        (vec![0x7112], 7),
        (vec![0x0113, 0x8000], i64::from(i16::MIN)),
        (vec![0x0113, 0x7fff], i64::from(i16::MAX)),
        (vec![0x0114, 0, 0x8000], i64::from(i32::MIN)),
        (vec![0x0114, 0xffff, 0x7fff], i64::from(i32::MAX)),
    ] {
        code.extend([0x1071, 2, 1, 0x000e]);
        let out = calls(&code);
        assert!(matches!(&out[0], Symbol::Call { args, .. }
                if matches!(&args[0], Arg::Number { value, .. } if *value == expected)));
    }
}
#[test]
fn branch_offsets_retain_their_sign() {
    for code in [
        vec![0x0128, 0xff28],
        vec![0x0000, 0x0029, 0xffff],
        vec![0x0000, 0x002a, 0xffff, 0xffff],
    ] {
        assert!(targets(&code).unwrap().contains(&0));
    }
    assert_eq!(relative(0, -1, 10), None);
    assert_eq!(relative(5, 5, 10), None);
    assert_eq!(relative(5, -5, 10), Some(0));
    assert_eq!(relative(usize::MAX, 1, usize::MAX), None);
    assert_eq!(
        relative(usize::MAX - 1, -1, usize::MAX),
        Some(usize::MAX - 2)
    );
}
#[test]
fn string_argument_and_moved_register() {
    let out = calls(&[0x001a, 0, 0x0107, 0x1071, 2, 0x0001, 0x000e]);
    assert!(
        matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::String{value} if value=="/data/"))
    );
}
#[test]
fn range_invoke_argument() {
    let out = calls(&[0x011a, 0, 0x0177, 2, 1, 0x000e]);
    assert!(
        matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::String{value} if value=="/data/"))
    );
}
#[test]
fn branch_target_drops_stale_constant() {
    let out = calls(&[0x0112, 0x0038, 2, 0x206e, 1, 0x0010, 0x000e]);
    assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
}
#[test]
fn unknown_write_drops_literal() {
    let out = calls(&[0x011a, 0, 0x0122, 0, 0x0177, 2, 1, 0x000e]);
    assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
}
#[test]
fn unrelated_field_read_preserves_literal() {
    let out = calls(&[0x011a, 0, 0x2054, 0, 0x0177, 2, 1, 0x000e]);
    assert!(
        matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::String{value} if value=="/data/"))
    );
}
#[test]
fn field_destination_discards_literal() {
    let out = calls(&[0x011a, 0, 0x2154, 0, 0x0177, 2, 1, 0x000e]);
    assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
}
#[test]
fn wide_write_discards_second_register() {
    let out = calls(&[0x011a, 0, 0x0016, 0, 0x0177, 2, 1, 0x000e]);
    assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
}
#[test]
fn truncated_instructions_and_headers_do_not_panic() {
    for code in [
        vec![0x1a],
        vec![0x0100],
        vec![0x0300, 0xffff, 0xffff, 0xffff],
        vec![0xff],
    ] {
        assert!(calls(&code).is_empty());
    }
    for n in 0..112 {
        assert!(Dex::parse(&vec![0; n]).is_none());
    }
}
#[test]
fn modified_utf8_retains_nul_and_surrogate_pair() {
    assert_eq!(
        mutf8(b"A\xc0\x80\xed\xa0\xbd\xed\xb8\x80"),
        Some("A\0😀".to_owned())
    );
    assert!(mutf8(b"\xed\xa0\xbd").is_none());
    assert!(mutf8(b"\xc1\x81").is_none());
}

/// A DEX file of `methods` `method_id_item`s that all name one class of
/// `len` bytes and one method name of `len` bytes, and `classes` classes
/// that each declare every method over one `code_item` of `body` code units.
fn dex_of_long_names(len: usize, methods: usize, classes: usize, body: &[u16]) -> Vec<u8> {
    let mut b = vec![0u8; HEADER_LEN];
    b[..8].copy_from_slice(b"dex\n035\0");
    b[ENDIAN_TAG_AT..ENDIAN_TAG_AT + 4].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes());
    let table = |b: &mut Vec<u8>, at: usize, len: usize, entries: &[u8]| {
        let off = b.len();
        b[at..at + 4].copy_from_slice(&(len as u32).to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&(off as u32).to_le_bytes());
        b.extend_from_slice(entries);
    };
    // Two strings, `L<x…>;` and `<y…>`, each `len` bytes.
    let strings_at = b.len() + 8 + 4 + 12 + methods * 8;
    let first = strings_at;
    let second = first + 2 + len + 1;
    let ids: Vec<u8> = [first as u32, second as u32]
        .iter()
        .flat_map(|o| o.to_le_bytes())
        .collect();
    table(&mut b, STRING_IDS_AT, 2, &ids);
    table(&mut b, TYPE_IDS_AT, 1, &0u32.to_le_bytes());
    table(&mut b, PROTO_IDS_AT, 1, &[0; PROTO_ID_LEN]);
    let method_ids: Vec<u8> = (0..methods)
        .flat_map(|_| [0u8, 0, 0, 0, 1, 0, 0, 0])
        .collect();
    table(&mut b, METHOD_IDS_AT, methods, &method_ids);
    assert_eq!(b.len(), strings_at);
    let mut class_name = format!("L{};", "x".repeat(len - 2)).into_bytes();
    let mut method_name = "y".repeat(len).into_bytes();
    for text in [&mut class_name, &mut method_name] {
        b.extend_from_slice(&[0x80 | (len & 0x7f) as u8, (len >> 7) as u8]);
        b.append(text);
        b.push(0);
    }
    // One code item, then one class_data_item every class shares.
    let code_at = b.len();
    b.extend_from_slice(&[0; INSNS_SIZE_AT]);
    b.extend_from_slice(&(body.len() as u32).to_le_bytes());
    b.extend(body.iter().flat_map(|u| u.to_le_bytes()));
    let data_at = b.len();
    let uleb = |b: &mut Vec<u8>, mut v: usize| loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            b.push(byte);
            break;
        }
        b.push(byte | 0x80);
    };
    for v in [0, 0, methods, 0] {
        uleb(&mut b, v);
    }
    for i in 0..methods {
        uleb(&mut b, usize::from(i != 0));
        uleb(&mut b, 1);
        uleb(&mut b, code_at);
    }
    let class_defs: Vec<u8> = (0..classes)
        .flat_map(|_| {
            let mut def = [0u8; CLASS_DEF_LEN];
            // A class index no method names, so every method is external.
            def[..4].copy_from_slice(&1u32.to_le_bytes());
            def[CLASS_DATA_OFF_AT..CLASS_DATA_OFF_AT + 4]
                .copy_from_slice(&(data_at as u32).to_le_bytes());
            def
        })
        .collect();
    table(&mut b, CLASS_DEFS_AT, classes, &class_defs);
    b
}

/// Every method named by one long class and one long method name: the method
/// table, the imports and every call and callee repeat that name. Copied
/// whole, a file of a few hundred KiB built gigabytes of names.
#[test]
fn repeated_long_method_names_stop_at_the_name_budget() {
    let methods = 1 << 14;
    // invoke-static {}, method@0, then return-void.
    let body = [0x0071, 0, 0, 0x000e];
    let bytes = dex_of_long_names(8000, methods, 8, &body);
    assert!(bytes.len() < 1 << 20);
    let mut symbols = Symbols::new();
    let mut literals = Literals::new();
    let mut values = Values::new();
    extract(&bytes, &mut symbols, &mut literals, &mut values);
    let copied: usize = symbols
        .iter()
        .map(|s| match s {
            Symbol::Import { name, .. } => name.len(),
            Symbol::Call { target, .. } => target.as_ref().map_or(0, String::len),
            Symbol::Function { name, callees, .. } => {
                name.len() + callees.iter().map(String::len).sum::<usize>()
            }
            _ => 0,
        })
        .sum();
    assert!(
        copied <= MAX_SYMBOL_NAME_BYTES,
        "{copied} name bytes copied"
    );
    assert_eq!(
        values.get("dex.limits"),
        Some(&serde_json::json!({"name_budget": true}))
    );
    // The method table itself holds at most its own budget of names.
    let dex = Dex::parse(&bytes).unwrap();
    let table: usize = dex.methods.iter().flatten().map(|m| m.name.len()).sum();
    assert!(table <= MAX_METHOD_NAME_BYTES, "{table} method-table bytes");
    assert!(dex.methods.iter().any(Option::is_none));
}

/// Short names still resolve and are copied whole.
#[test]
fn ordinary_method_names_are_all_copied() {
    let body = [0x0071, 0, 0, 0x000e];
    let bytes = dex_of_long_names(8, 4, 1, &body);
    let mut symbols = Symbols::new();
    let mut literals = Literals::new();
    let mut values = Values::new();
    extract(&bytes, &mut symbols, &mut literals, &mut values);
    assert!(values.get("dex.limits").is_none());
    let imports = symbols
        .iter()
        .filter(|s| matches!(s, Symbol::Import { .. }))
        .count();
    assert_eq!(imports, 4);
    assert!(
        symbols.iter().any(
            |s| matches!(s, Symbol::Call { target: Some(t), .. } if t == "Lxxxxxx;->yyyyyyyy")
        )
    );
}

/// Thousands of `packed-switch` instructions naming one payload of
/// thousands of targets: the payload is read once, and no body reads more
/// targets than it has code units.
#[test]
fn a_shared_switch_payload_is_read_once() {
    let switches = 4000;
    let size = 4000;
    let payload_at = switches * 3;
    let mut code = Vec::new();
    for i in 0..switches {
        let pc = i * 3;
        let off = (payload_at - pc) as u32;
        code.extend_from_slice(&[0x002b, off as u16, (off >> 16) as u16]);
    }
    code.extend_from_slice(&[0x0100, size as u16, 0, 0]);
    for j in 0..size {
        // Each target is the switch instruction `j` of the body.
        let target = (j % switches * 3) as u32;
        code.extend_from_slice(&[target as u16, (target >> 16) as u16]);
    }
    let labels = targets(&code).expect("one payload's targets fit the body");
    assert_eq!(labels.len(), size.min(switches));
    // A payload claiming more targets than the body has units is refused.
    let mut short = vec![0x002b, 3, 0, 0x0100, 0xffff, 0, 0];
    short.extend(std::iter::repeat_n(0, 16));
    assert!(targets(&short).is_none());
}
