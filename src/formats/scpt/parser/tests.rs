use super::*;

fn header(kind: u8, id: i16, size: u16) -> Vec<u8> {
    let mut b = vec![kind];
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&size.to_be_bytes());
    b
}

fn stream(body: &[u8]) -> Vec<u8> {
    let mut b = b"FasdUAS 1.101.10".to_vec();
    b.extend_from_slice(body);
    b
}

fn vector(kind: u8, id: i16, tag: Option<u8>, refs: &[i16]) -> Vec<u8> {
    let mut b = header(kind, id, refs.len() as u16);
    b.extend(tag);
    for r in refs {
        b.extend_from_slice(&r.to_be_bytes());
    }
    b
}

fn items(parsed: &Parsed, node: usize) -> &[usize] {
    match &parsed.nodes[node].value {
        Value::Vector { items, .. } => items,
        value => panic!("expected vector, found {value:?}"),
    }
}

fn valid_offsets(parsed: &Parsed, bytes: &[u8]) {
    assert!(parsed.root < parsed.nodes.len());
    for node in &parsed.nodes {
        assert!(node.offset <= bytes.len());
        match &node.value {
            Value::Bytes { data, .. } => {
                assert_eq!(
                    bytes.get(node.offset..node.offset + data.len()),
                    Some(data.as_slice())
                );
            }
            Value::Vector { items, .. } => {
                assert!(items.iter().all(|&i| i < parsed.nodes.len()))
            }
            _ => assert!(node.offset < bytes.len()),
        }
    }
}

fn assert_error(bytes: &[u8], message: &str) {
    let error = parse(bytes).unwrap_err().to_string();
    assert!(
        error.contains(message),
        "expected {message:?}, got {error:?}"
    );
    assert!(error.starts_with("FAS at 0x"));
}

fn code_blocks(p: &Parsed) -> Vec<usize> {
    p.nodes
        .iter()
        .filter_map(|n| match &n.value {
            Value::Vector {
                tag: Some(16),
                items,
            } if items.len() >= 7 => {
                matches!(&p.nodes[items[6]].value, Value::Bytes { .. }).then_some(items[6])
            }
            _ => None,
        })
        .collect()
}

#[test]
fn portable_compiler_fixture_preserves_signedness_and_function_layout() {
    let bytes = test_fixture();
    let p = parse(&bytes).unwrap();
    valid_offsets(&p, &bytes);
    assert_eq!(code_blocks(&p).len(), 2);
    assert!(
        p.nodes
            .iter()
            .any(|n| n.value == Value::Name("greet".into()))
    );
    assert!(
        p.nodes
            .iter()
            .any(|n| n.value == Value::Event("aevt.oapp".into()))
    );
    for (value, kind) in [(-123, 3), (32767, 3), (32768, 7), (65535, 7)] {
        let n = p
            .nodes
            .iter()
            .find(|n| n.value == Value::Int(value))
            .unwrap();
        assert_eq!(bytes[n.offset], kind);
    }
    let expected: Vec<u8> = "Hello World"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    assert!(
        p.nodes.iter().any(|n| matches!(&n.value,
            Value::Vector { tag: Some(177), items }
            if matches!(&p.nodes[items[0]].value, Value::Bytes { data, .. } if data == &expected)))
    );
    let root = items(&p, p.root);
    let functions = items(&p, *root.last().unwrap());
    let function = items(&p, functions[2]);
    assert_eq!(p.nodes[function[0]].value, Value::Name("greet".into()));
    assert!(matches!(&p.nodes[function[2]].value, Value::Vector { .. }));
    let literals = items(&p, function[5]);
    assert_eq!(p.nodes[literals[0]].value, Value::Int(-123));
    assert!(
        matches!(&p.nodes[function[6]].value, Value::Bytes { tag: None, data } if !data.is_empty())
    );
}

#[test]
fn short_integer_boundaries() {
    for value in [i16::MIN, -123, -1, 0, 1, i16::MAX] {
        let p = parse(&stream(&header(3, 0, value as u16))).unwrap();
        assert_eq!(p.nodes[0].value, Value::Int(i64::from(value)));
    }
}

#[test]
fn versions_shebang_and_trailer() {
    for version in ["0.98", "0.99", "1.00", "1.09", "1.10"] {
        let mut b = b"#!/usr/bin/osascript\nFasdUAS ".to_vec();
        b.extend_from_slice(version.as_bytes());
        if version == "1.10" {
            b.extend_from_slice(version.as_bytes());
        }
        let start = b.len();
        b.extend(header(1, 0, 0));
        b.extend_from_slice(b"ascr\0\x01\0\x0c\xfa\xde\xde\xad");
        let p = parse(&b).unwrap();
        assert_eq!(p.version, version);
        assert_eq!(p.nodes[p.root].offset, start);
    }
    for bad in [b"FasdUAS 0.97".as_slice(), b"FasdUAS 1.101.11"] {
        assert_error(bad, "unsupported effective version");
    }
    for bad in [b"FasdUAS x.xx".as_slice(), b"FasdUAS 1.101.x0"] {
        assert_error(bad, "malformed version");
    }
    assert_error(b"#!unterminated", "unterminated shebang");
    assert_error(b"not a script", "magic");
}

#[test]
fn unknown_and_invalid_framing() {
    assert_error(&stream(&header(5, 0, 0)), "unknown record kind");
    for (kind, size) in [(2, 1), (6, 4), (6, 2), (7, 8), (8, 4)] {
        assert_error(&stream(&header(kind, 0, size)), "invalid");
    }
    let mut b = header(15, 0, 93);
    b.push(8);
    assert_error(&stream(&b), "descriptor shorter");
    for (tag, size) in [(11, 7), (10, 8), (47, 24), (46, 4), (255, 0)] {
        let mut b = header(10, 0, size);
        b.push(tag);
        assert_error(&stream(&b), "code identifier");
    }
}

#[test]
fn mismatched_missing_and_extreme_references() {
    assert_error(&stream(&header(1, 1, 0)), "reference mismatch");
    for id in [-32768, -1, 1, 32767] {
        let mut b = vector(16, 0, None, &[id]);
        assert_error(&stream(&b), "truncated");
        b.extend(header(1, id, 0));
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(p.nodes.len(), 2);
    }
    let mut b = vector(16, 0, None, &[7]);
    b.extend(header(1, 8, 0));
    assert_error(&stream(&b), "expected 7, found 8");
    // Reusing a negative ID still requires a new record at each use.
    let mut b = vector(16, 0, None, &[-1, -1]);
    b.extend(header(1, -1, 0));
    assert_error(&stream(&b), "truncated");
}

#[test]
fn list_and_binding_chains_and_cycles() {
    for (kind, empty_size, count) in [(2, 0, 2), (6, 0, 3), (6, 1, 3)] {
        let mut refs = vec![-1; count];
        refs[count - 1] = 1;
        let mut b = vector(kind, 0, None, &refs);
        for _ in 0..count - 1 {
            b.extend(header(3, -1, 42));
        }
        b.extend(header(kind, 1, empty_size));
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(items(&p, 0).len(), count);
        assert!(items(&p, *items(&p, 0).last().unwrap()).is_empty());
        let p = parse(&stream(&vector(kind, 0, None, &vec![0; count]))).unwrap();
        assert_eq!(items(&p, 0), vec![0; count]);
    }
    // A binding tail may be another object kind, not only an empty binding.
    let mut b = vector(6, 0, None, &[0, 0, -1]);
    b.extend(header(1, -1, 0));
    let p = parse(&stream(&b)).unwrap();
    assert_eq!(items(&p, 0), [0, 0, 1]);
    assert_eq!(p.nodes[1].value, Value::Unknown);
}

#[test]
fn names_choose_alternate_and_preserve_non_utf8_bytes() {
    for (a, b, expected) in [
        (b"name".as_slice(), b"".as_slice(), "name"),
        (b"name", b"Name", "Name"),
        (&[0x80, 0xff], b"", "\u{80}\u{ff}"),
    ] {
        let mut data = header(11, 0, 0);
        data.push(48);
        data.extend_from_slice(&(a.len() as u16).to_be_bytes());
        data.extend_from_slice(a);
        data.extend_from_slice(&(b.len() as u16).to_be_bytes());
        data.extend_from_slice(b);
        let data = stream(&data);
        let p = parse(&data).unwrap();
        assert_eq!(p.nodes[0].value, Value::Name(expected.into()));
        assert_eq!(p.nodes[0].offset, 16);
        for cut in 16..data.len() {
            assert_error(&data[..cut], "truncated");
        }
    }
    let mut b = header(11, 0, 0);
    b.extend_from_slice(&[48, 1, 0]);
    assert_error(&stream(&b), "length exceeds");
    let mut b = header(11, 0, 0);
    b.push(0);
    assert_error(&stream(&b), "tag must be 48");
}

#[test]
fn events_constants_integers_and_floats() {
    let mut b = header(10, 0, 24);
    b.push(46);
    b.extend_from_slice(b"aaaaBBBBccccDDDDeeeeFFFF");
    let p = parse(&stream(&b)).unwrap();
    assert_eq!(p.nodes[0].value, Value::Event("aaaa.BBBB".into()));
    b[6] = b'.';
    b[7] = 0;
    b[8] = b'\\';
    b[9] = 0xff;
    let p = parse(&stream(&b)).unwrap();
    assert_eq!(
        p.nodes[0].value,
        Value::Event("\\x2e\\x00\\x5c\\xff.BBBB".into())
    );
    for tag in [10, 11, 47] {
        let size = if tag == 11 { 8 } else { 4 };
        let mut b = header(10, 0, size);
        b.push(tag);
        b.extend(vec![0xff; usize::from(size)]);
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(
            p.nodes[0].value,
            Value::Constant(if tag == 11 {
                u64::MAX
            } else {
                u64::from(u32::MAX)
            })
        );
    }
    let mut b = header(1, 0, 1);
    b.extend_from_slice(&123_u64.to_be_bytes());
    assert_eq!(
        parse(&stream(&b)).unwrap().nodes[0].value,
        Value::Constant(123)
    );
    let mut b = header(7, 0, 4);
    b.extend_from_slice(&i32::MIN.to_be_bytes());
    assert_eq!(
        parse(&stream(&b)).unwrap().nodes[0].value,
        Value::Int(i64::from(i32::MIN))
    );
    let mut b = header(8, 0, 8);
    b.extend_from_slice(&f64::NAN.to_be_bytes());
    let b = stream(&b);
    let p = parse(&b).unwrap();
    assert!(matches!(&p.nodes[0].value, Value::Bytes { tag: None, data } if data.len() == 8));
    valid_offsets(&p, &b);
}

#[test]
fn unicode_text_and_style_and_command_metadata() {
    let mut b = header(12, 0, 0);
    b.extend_from_slice(&[0, 4, 0, b'H', 0, b'i', 0, 2, 0xaa, 0xbb]);
    let b = stream(&b);
    let p = parse(&b).unwrap();
    assert_eq!(
        p.nodes[0].value,
        Value::Vector {
            tag: Some(177),
            items: vec![1, 2]
        }
    );
    assert_eq!(p.nodes[1].offset, 23);
    assert_eq!(p.nodes[2].offset, 29);
    valid_offsets(&p, &b);
    for cut in 0..b.len() {
        assert!(parse(&b[..cut]).is_err());
    }
    let mut b = header(13, 0, 1);
    b.extend_from_slice(&[0x6c, 0, 7, 0, 10, 0, 20, 0, 0]);
    let b = stream(&b);
    let p = parse(&b).unwrap();
    assert_eq!(
        p.nodes[0].value,
        Value::Vector {
            tag: Some(0x6c),
            items: vec![1, 2, 3, 0]
        }
    );
    for (i, value) in [(1, 7), (2, 10), (3, 20)] {
        assert_eq!(p.nodes[i].value, Value::Int(value));
        assert_eq!(p.nodes[i].offset, 16);
    }
    valid_offsets(&p, &b);
}

#[test]
fn nesting_is_bounded_without_recursive_stack_use() {
    let mut b = vector(16, 0, None, &[-1]);
    for _ in 1..MAX_DEPTH {
        b.extend(vector(16, -1, None, &[-1]));
    }
    let mut valid = b.clone();
    valid.extend(header(1, -1, 0));
    let p = parse(&stream(&valid)).unwrap();
    assert_eq!(p.nodes.len(), MAX_DEPTH + 1);
    assert!(p.truncated.is_none());
    b.extend(vector(16, -1, None, &[-1]));
    b.extend(header(1, -1, 0));
    // Past the ceiling the walk stops but the file still parses: the nodes
    // built before the stop are kept and the reason is reported, rather
    // than the whole extraction failing and reporting nothing.
    let over = parse(&stream(&b)).unwrap();
    assert!(
        over.truncated
            .as_deref()
            .is_some_and(|r| r.contains("nesting limit")),
        "{:?}",
        over.truncated
    );
    assert!(over.nodes.len() > MAX_DEPTH, "partial nodes retained");
}

#[test]
fn oversized_and_truncated_long_data() {
    for kind in [18, 19] {
        let mut b = header(kind, 0, 0);
        if kind == 18 {
            b.push(0);
        }
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_error(&stream(&b), "truncated");
    }
    let mut b = stream(&header(19, 0, 0));
    b.extend_from_slice(&((MAX_DATA + 1) as u32).to_be_bytes());
    b.resize(b.len() + MAX_DATA + 1, 0);
    assert_error(&b, "owned data limit");
    b.resize(MAX_INPUT + 1, 0);
    assert_error(&b, "input limit");
}

#[test]
fn aggregate_edges_are_bounded_even_when_all_shared() {
    let mut b = vector(16, 0, None, &[-1; 17]);
    for _ in 0..17 {
        b.extend(vector(16, -1, None, &vec![0; 65535]));
    }
    // Bounded, and reported: the walk stops at the ceiling and says so
    // rather than discarding the nodes it already built.
    let p = parse(&stream(&b)).unwrap();
    assert!(
        p.truncated
            .as_deref()
            .is_some_and(|r| r.contains("edge limit")),
        "{:?}",
        p.truncated
    );
    assert!(p.nodes.len() <= MAX_NODES);
}

/// Recovery keys on the variant, so a ceiling must be a `Budget` and
/// structural damage a `Malformed`, each keeping its message text.
#[test]
fn budget_and_malformed_errors_are_typed_and_keep_their_text() {
    let error = parse(&vec![0; MAX_INPUT + 1]).unwrap_err();
    assert!(matches!(error, ParseError::Budget { .. }), "{error:?}");
    assert_eq!(error.to_string(), "FAS at 0x0: input limit exceeded");
    for (limit, text) in [
        ("object", "FAS at 0x2a: object limit exceeded"),
        ("owned data", "FAS at 0x2a: owned data limit exceeded"),
        ("edge", "FAS at 0x2a: edge limit exceeded"),
        ("nesting", "FAS at 0x2a: nesting limit exceeded"),
    ] {
        let error = ParseError::Budget { offset: 42, limit };
        assert_eq!(error.to_string(), text);
    }
    let error = parse(&stream(&header(5, 0, 0))).unwrap_err();
    assert!(matches!(error, ParseError::Malformed { .. }), "{error:?}");
    assert_eq!(error.to_string(), "FAS at 0x10: unknown record kind 5");
}

#[test]
fn object_count_is_bounded_even_for_tiny_inline_scalars() {
    let mut b = vector(16, 0, None, &[-1; 4]);
    for _ in 0..4 {
        b.extend(vector(16, -1, None, &vec![-1; 65535]));
        for _ in 0..65535 {
            b.extend(header(1, -1, 0));
        }
    }
    let p = parse(&stream(&b)).unwrap();
    assert!(
        p.truncated
            .as_deref()
            .is_some_and(|r| r.contains("object limit")),
        "{:?}",
        p.truncated
    );
    assert!(p.nodes.len() <= MAX_NODES);
}

#[test]
fn shared_and_negative_inline_references() {
    let mut b = vector(14, 0, Some(15), &[1, 1, -1, -1]);
    b.extend(header(3, 1, 65535));
    b.extend(header(9, -1, 1));
    b.extend(header(9, -1, 0));
    let b = stream(&b);
    let p = parse(&b).unwrap();
    assert_eq!(p.nodes.len(), 4);
    assert_eq!(items(&p, p.root), [1, 1, 2, 3]);
    assert_eq!(p.nodes[1].value, Value::Int(-1));
    assert_eq!(p.nodes[2].value, Value::Bool(true));
    assert_eq!(p.nodes[3].value, Value::Bool(false));
    valid_offsets(&p, &b);
}

#[test]
fn self_and_mutual_cycles() {
    for kind in [4, 14, 16] {
        let tag = (kind != 16).then_some(15);
        let b = stream(&vector(kind, 0, tag, &[0]));
        let p = parse(&b).unwrap();
        assert_eq!(items(&p, 0), [0]);
        let mut b = vector(kind, 0, tag, &[1]);
        b.extend(vector(kind, 1, tag, &[0]));
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(items(&p, 0), [1]);
        assert_eq!(items(&p, 1), [0]);
    }
}

#[test]
fn bytes_keep_tags_and_payload_offsets() {
    for (kind, tag) in [
        (15, Some(0)),
        (15, Some(13)),
        (15, Some(0xfe)),
        (17, None),
        (18, Some(13)),
        (19, None),
    ] {
        let mut b = header(kind, 0, 3);
        b.extend(tag);
        if kind >= 18 {
            b.extend_from_slice(&3_u32.to_be_bytes());
        }
        let offset = 16 + b.len();
        b.extend_from_slice(&[0, 0xff, 0x42]);
        let b = stream(&b);
        let p = parse(&b).unwrap();
        assert_eq!(p.nodes[0].offset, offset);
        assert_eq!(
            p.nodes[0].value,
            Value::Bytes {
                tag,
                data: vec![0, 0xff, 0x42]
            }
        );
        valid_offsets(&p, &b);
        for cut in 0..b.len() {
            assert!(parse(&b[..cut]).is_err(), "kind {kind}, cut {cut}");
        }
    }
}

#[test]
fn real_sample() {
    let bytes = include_bytes!("../../../../tests/fixtures/stage4.scpt");
    let p = parse(bytes).unwrap();
    assert_eq!(p.version, "1.10");
    valid_offsets(&p, bytes);
    let code = code_blocks(&p).len();
    let names = p
        .nodes
        .iter()
        .filter(|n| matches!(&n.value, Value::Name(_)))
        .count();
    assert!(code > 0 && names > 0);
    assert_eq!(p.nodes.len(), 10677);
    assert_eq!(code, 48);
    assert_eq!(names, 1509);
    println!(
        "sample: {} bytes, {} nodes, {} function code blocks, {} names",
        bytes.len(),
        p.nodes.len(),
        code,
        names
    );
    // The sample ends with a 12-byte container trailer, outside the root.
    let end = p
        .nodes
        .iter()
        .filter_map(|n| match &n.value {
            Value::Bytes { data, .. } => Some(n.offset + data.len()),
            _ => None,
        })
        .max()
        .unwrap();
    assert_eq!(end, bytes.len() - 12);
    assert!(parse(&bytes[..end]).is_ok());
    for cut in (0..end).step_by(end.div_ceil(256)).chain([end - 1]) {
        assert!(
            parse(&bytes[..cut]).is_err(),
            "accepted truncated sample at {cut}"
        );
    }
}

#[test]
fn real_compiled_fixtures() {
    let Some(dir) = std::env::var_os("SCPT_FIXTURES") else {
        return;
    };
    for (file, nodes, literal, event) in [
        ("simple.scpt", 143, "Hello World", "syso.dlog"),
        ("shell_script.scpt", 219, "whoami", "syso.exec"),
        ("tell_app.scpt", 174, "", "core.cnte"),
    ] {
        let bytes = std::fs::read(std::path::Path::new(&dir).join(file)).unwrap();
        let p = parse(&bytes).unwrap();
        assert_eq!(p.nodes.len(), nodes, "{file}");
        assert_eq!(code_blocks(&p).len(), 1, "{file}");
        assert!(
            p.nodes
                .iter()
                .any(|n| matches!(&n.value, Value::Event(e) if e.starts_with(event)))
        );
        if !literal.is_empty() {
            let expected: Vec<u8> = literal.encode_utf16().flat_map(u16::to_be_bytes).collect();
            assert!(p.nodes.iter().any(|n| matches!(&n.value,
                    Value::Vector { tag: Some(177), items }
                    if matches!(&p.nodes[items[0]].value, Value::Bytes { data, .. } if data == &expected))));
        }
        valid_offsets(&p, &bytes);
        // Validate complete stream consumption separately from its trailer.
        // Public parse already checks graph structure; code ends the root
        // in these compiler fixtures, making its last byte a useful bound.
        let code = &p.nodes[code_blocks(&p)[0]];
        let Value::Bytes { data, .. } = &code.value else {
            unreachable!()
        };
        let end = code.offset + data.len();
        assert!(parse(&bytes[..end]).is_ok());
        for cut in (0..end).step_by(end.div_ceil(128)).chain([end - 1]) {
            assert!(parse(&bytes[..cut]).is_err(), "{file}: prefix {cut}");
        }
        println!(
            "{file}: {} bytes, {nodes} nodes; sampled prefixes before {end} rejected",
            bytes.len()
        );
    }
}

#[test]
fn deterministic_mutations_do_not_panic_or_make_invalid_edges() {
    let mut base = vector(14, 0, Some(177), &[1, 1, 0, -1]);
    base.extend(header(17, 1, 4));
    base.extend_from_slice(&[0, b'o', 0, b'k']);
    base.extend(header(3, -1, 42));
    let base = stream(&base);
    let mut state = 0x0ace_5eed_u32;
    for _ in 0..2048 {
        let mut b = base.clone();
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let at = state as usize % b.len();
        b[at] ^= (state >> 16) as u8;
        if let Ok(p) = parse(&b) {
            valid_offsets(&p, &b);
        }
    }
}

#[test]
fn installed_compiled_corpus() {
    let Some(dir) = std::env::var_os("SCPT_CORPUS") else {
        return;
    };
    let mut dirs = vec![std::path::PathBuf::from(dir)];
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() && entry.path().extension().is_some_and(|e| e == "scpt") {
                files.push(entry.path());
            }
        }
    }
    assert!(!files.is_empty());
    files.sort();
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        let p = parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        valid_offsets(&p, &bytes);
        assert!(!code_blocks(&p).is_empty(), "{}", path.display());
    }
    println!("installed corpus: {} compiled scripts passed", files.len());
}
