use super::super::parser::Node;
use super::*;

#[test]
fn legacy_text_is_unknown_but_native_unicode_is_known() {
    let legacy =
        super::super::parser::parse(b"FasdUAS 1.101.10\x0c\0\0\0\0\0\x04ABCD\0\0").unwrap();
    assert_eq!(literal(&legacy, legacy.root), Known::Unknown);
    let child = vector(&legacy, legacy.root).unwrap()[0];
    assert_eq!(literal(&legacy, child), Known::Unknown);
    let mut native = arena();
    let id = text(&mut native, "Hello \u{1f30d}");
    assert_eq!(
        literal(&native, id),
        Known::String("Hello \u{1f30d}".into(), false)
    );
}

fn arena() -> Parsed {
    Parsed {
        nodes: vec![Node {
            offset: 0,
            value: Value::Vector {
                tag: None,
                items: Vec::new(),
            },
        }],
        root: 0,
        version: "1.10".into(),
        truncated: None,
    }
}

fn node(p: &mut Parsed, value: Value, offset: usize) -> usize {
    let id = p.nodes.len();
    p.nodes.push(Node { offset, value });
    id
}

fn text(p: &mut Parsed, s: &str) -> usize {
    let bytes = s.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let data = node(
        p,
        Value::Bytes {
            tag: None,
            data: bytes,
        },
        0,
    );
    node(
        p,
        Value::Vector {
            tag: Some(177),
            items: vec![data],
        },
        0,
    )
}

fn handler(
    p: &mut Parsed,
    name: &str,
    code: Vec<u8>,
    literals: Vec<usize>,
    arity: i64,
    base: usize,
) -> usize {
    let name = node(p, Value::Name(name.into()), base - 100);
    let n = node(p, Value::Int(arity), 0);
    let args = node(
        p,
        Value::Vector {
            tag: Some(4),
            items: vec![n],
        },
        0,
    );
    let locals = node(p, Value::Unknown, 0);
    let lits = node(
        p,
        Value::Vector {
            tag: None,
            items: literals,
        },
        0,
    );
    let code = node(
        p,
        Value::Bytes {
            tag: Some(13),
            data: code,
        },
        base,
    );
    let id = node(
        p,
        Value::Vector {
            tag: Some(16),
            items: vec![name, locals, args, locals, locals, lits, code],
        },
        base - 110,
    );
    if let Value::Vector { items, .. } = &mut p.nodes[0].value {
        items.push(id);
    }
    id
}

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).expect("ASCII hex"), 16).unwrap())
        .collect()
}

fn add_decoder(p: &mut Parsed, index: usize, name: &str) -> usize {
    let (body, _, arity, constants) = DECODER_BODIES[index];
    let empty = text(p, "");
    let event = node(p, Value::Event("core.cnte".into()), 0);
    let mut lits = vec![empty, event];
    for c in constants {
        lits.push(node(
            p,
            if *c == 9999 {
                Value::Int(9999)
            } else {
                Value::Constant(*c)
            },
            0,
        ));
    }
    handler(p, name, hex(body), lits, arity, 0x1000 + index * 0x100)
}

fn push_literal(code: &mut Vec<u8>, index: usize) {
    code.push(97);
    code.extend_from_slice(&(index as u16).to_be_bytes());
}

fn push_number(p: &mut Parsed, code: &mut Vec<u8>, lits: &mut Vec<usize>, n: i64) {
    let id = node(p, Value::Int(n), 0);
    push_literal(code, lits.len());
    lits.push(id);
}

fn push_array(p: &mut Parsed, code: &mut Vec<u8>, lits: &mut Vec<usize>, array: &[i64]) {
    for n in array {
        push_number(p, code, lits, *n);
    }
    push_number(p, code, lits, array.len() as i64);
    code.push(118);
}

fn fixture(index: usize, s: &str) -> (Parsed, usize, usize) {
    let mut p = arena();
    // Deliberately unrelated names: names are lookup keys, never signatures.
    add_decoder(&mut p, index, "arbitrary_handler");
    let mut code = vec![42];
    let mut lits = Vec::new();
    let (_, decoder, arity, _) = DECODER_BODIES[index];
    let a: Vec<i64> = s
        .bytes()
        .map(|c| match decoder {
            Decoder::AddArrays => 42,
            Decoder::SubtractArrays => i64::from(c) + 42,
            Decoder::SubtractArraysAndScalar => i64::from(c) + 55,
            Decoder::SubtractScalar => i64::from(c) + 13,
        })
        .collect();
    push_array(&mut p, &mut code, &mut lits, &a);
    match decoder {
        Decoder::SubtractScalar => push_number(&mut p, &mut code, &mut lits, 13),
        _ => {
            let b: Vec<i64> = s
                .bytes()
                .map(|c| {
                    if matches!(decoder, Decoder::AddArrays) {
                        i64::from(c) - 42
                    } else {
                        42
                    }
                })
                .collect();
            push_array(&mut p, &mut code, &mut lits, &b);
            if arity == 3 {
                push_number(&mut p, &mut code, &mut lits, 13);
            }
        }
    }
    push_number(&mut p, &mut code, &mut lits, arity);
    let call_pc = code.len();
    code.push(43);
    code.extend_from_slice(&(lits.len() as u16).to_be_bytes());
    lits.push(node(&mut p, Value::Name("arbitrary_handler".into()), 0));
    code.push(106);
    let exec_pc = code.len();
    code.push(12);
    code.extend_from_slice(&(lits.len() as u16).to_be_bytes());
    lits.push(node(&mut p, Value::Event("syso.exec".into()), 0));
    code.push(15);
    handler(&mut p, "caller", code, lits, 0, 0x4000);
    (p, 0x4000 + call_pc, 0x4000 + exec_pc)
}

#[test]
fn all_verified_bodies_recover_with_unrelated_names_and_exact_offsets() {
    for index in 0..5 {
        let expected = "security find-generic-password -w -s 'Chrome Safe Storage'";
        let (p, call, exec) = fixture(index, expected);
        let a = analyze(&p);
        let f = a.functions.iter().find(|f| f.name == "caller").unwrap();
        assert_eq!(f.calls.len(), 2);
        assert_eq!(f.calls[0].offset, call);
        assert_eq!(f.calls[1].offset, exec);
        assert_eq!(f.calls[1].target, "syso.exec");
        assert_eq!(f.calls[1].args, [Argument::String(expected.into())]);
        assert_eq!(f.decoded.len(), 2);
        assert_eq!(
            (f.decoded[0].text.as_str(), f.decoded[0].offset),
            (expected, call)
        );
        assert_eq!(
            (f.decoded[1].text.as_str(), f.decoded[1].offset),
            (expected, exec)
        );
    }
}

#[test]
fn body_literal_arity_and_name_collisions_are_checked() {
    for mutation in 0..4 {
        let (mut p, _, _) = fixture(0, "hello");
        let h = handlers(&p).0[0].offset;
        let index = p.nodes.iter().position(|n| n.offset == h).unwrap();
        let items = vector(&p, index).unwrap().to_vec();
        match mutation {
            0 => {
                if let Value::Bytes { data, .. } = &mut p.nodes[items[6]].value {
                    data[0] = 107;
                }
            }
            1 => {
                let lit = vector(&p, items[5]).unwrap()[2];
                p.nodes[lit].value = Value::Constant(0x63686120);
            }
            2 => {
                let n = vector(&p, items[2]).unwrap()[0];
                p.nodes[n].value = Value::Int(3);
            }
            _ => {
                add_decoder(&mut p, 1, "arbitrary_handler");
            }
        }
        let a = analyze(&p);
        let f = a.functions.iter().find(|f| f.name == "caller").unwrap();
        assert!(f.decoded.is_empty(), "mutation {mutation}");
        assert_eq!(f.calls[1].args, [Argument::Unknown]);
    }
}

fn shell(code: Vec<u8>) -> Analysis {
    let mut p = arena();
    let a = text(&mut p, "security ");
    let b = text(&mut p, "find-generic-password");
    let event = node(&mut p, Value::Event("syso.exec".into()), 0);
    handler(&mut p, "caller", code, vec![a, b, event], 0, 0x1000);
    analyze(&p)
}

#[test]
fn constant_concatenation_is_recovered_at_callsite() {
    let a = shell(vec![224, 225, 37, 106, 12, 0, 2]);
    let f = &a.functions[0];
    assert_eq!(
        f.calls[0].args,
        [Argument::String("security find-generic-password".into())]
    );
    assert_eq!(f.decoded[0].offset, 0x1002);
    assert_eq!(f.decoded[0].text, "security find-generic-password");
    assert_eq!(f.decoded[1].offset, 0x1004);
    let raw = shell(vec![224, 106, 12, 0, 2]);
    assert!(raw.functions[0].decoded.is_empty());
}

#[test]
fn dynamic_concatenation_does_not_claim_a_command() {
    let a = shell(vec![224, 160, 37, 106, 12, 0, 2]);
    assert_eq!(a.functions[0].calls[0].args, [Argument::Unknown]);
    assert!(a.functions[0].decoded.is_empty());
    let b = shell(vec![224, 225, 37, 160, 37, 106, 12, 0, 2]);
    assert_eq!(b.functions[0].calls[0].args, [Argument::Unknown]);
    assert_eq!(b.functions[0].decoded.len(), 1);
    assert_eq!(
        b.functions[0].decoded[0].text,
        "security find-generic-password"
    );
    assert_eq!(b.functions[0].decoded[0].offset, 0x1002);
}

#[test]
fn unknown_and_truncated_opcodes_stop_before_embedded_calls() {
    for prefix in [vec![114], vec![97, 12], vec![98, 12, 0, 2]] {
        let a = shell(prefix);
        assert!(a.functions[0].calls.is_empty());
        assert!(
            a.functions[0]
                .limitations
                .iter()
                .any(|s| s.contains("stopped"))
        );
    }
    let a = shell(vec![114, 224, 106, 12, 0, 2]);
    assert!(a.functions[0].calls.is_empty());
}

#[test]
fn operand_bytes_are_not_opcodes() {
    // RepeatInCollection's 0x000c variable operand is not MessageSend.
    let a = shell(vec![27, 0, 12, 224, 106, 12, 0, 2]);
    assert_eq!(a.functions[0].calls.len(), 1);
    assert_eq!(a.functions[0].calls[0].offset, 0x1005);
    // Parent-variable operands occupy four bytes, including these 0x0c bytes.
    let b = shell(vec![98, 12, 0, 12, 0, 224, 106, 12, 0, 2]);
    assert_eq!(b.functions[0].calls.len(), 1);
    assert_eq!(b.functions[0].calls[0].offset, 0x1007);
}

#[test]
fn branch_displacements_land_on_real_boundaries() {
    let a = shell(vec![23, 0, 5, 89, 0xff, 0xff, 224, 106, 12, 0, 2]);
    assert_eq!(a.functions[0].calls.len(), 1);
    assert!(
        !a.functions[0]
            .limitations
            .iter()
            .any(|s| s.contains("invalid branch"))
    );
    let invalid = shell(vec![89, 0, 1, 224, 106, 12, 0, 2]);
    assert!(invalid.functions[0].calls.is_empty());
    assert!(
        invalid.functions[0]
            .limitations
            .iter()
            .any(|s| s.contains("invalid branch"))
    );
}

#[test]
fn control_joins_clear_values_from_the_linear_predecessor() {
    // Jump reaches pc=6. The linear scan sees the other predecessor's local
    // assignment at pc=4; that value must be discarded at the join.
    let a = shell(vec![89, 0, 5, 224, 176, 79, 160, 106, 12, 0, 2]);
    assert_eq!(a.functions[0].calls[0].args, [Argument::Unknown]);
    // A backedge also makes pc=3 a join, despite the prior local assignment.
    let b = shell(vec![224, 176, 79, 160, 106, 12, 0, 2, 89, 0xff, 0xfa]);
    assert_eq!(b.functions[0].calls[0].args, [Argument::Unknown]);
}

#[test]
fn calls_and_unmodeled_effects_invalidate_locals() {
    for effect in [vec![92], vec![70], vec![208], vec![104, 106, 12, 0, 2]] {
        let mut code = vec![224, 176, 79];
        code.extend(effect);
        code.extend([160, 106, 12, 0, 2]);
        let a = shell(code);
        assert_eq!(
            a.functions[0].calls.last().unwrap().args,
            [Argument::Unknown]
        );
    }
}

#[test]
fn numeric_recovery_rejects_bounds_mismatch_and_overflow() {
    assert_eq!(
        recover(
            Decoder::AddArrays,
            &[Known::Array(vec![232]), Known::Array(vec![-123])]
        ),
        Some("m".into())
    );
    assert!(
        recover(
            Decoder::SubtractArrays,
            &[Known::Array(vec![100]), Known::Array(vec![])]
        )
        .is_none()
    );
    assert!(
        recover(
            Decoder::SubtractScalar,
            &[Known::Array(vec![i64::MAX]), Known::Number(-1)]
        )
        .is_none()
    );
    assert!(
        recover(
            Decoder::SubtractScalar,
            &[Known::Array(vec![128]), Known::Number(0)]
        )
        .is_none()
    );
    assert!(
        recover(
            Decoder::SubtractScalar,
            &[Known::Array(vec![65; MAX_ARRAY + 1]), Known::Number(0)]
        )
        .is_none()
    );
    assert_eq!(
        calculate(30, Known::Number(i64::MAX), Known::Number(1)),
        Known::Unknown
    );
    assert_eq!(
        calculate(35, Known::Number(1), Known::Number(0)),
        Known::Unknown
    );
}

#[test]
fn data_is_only_text_in_a_verified_text_container() {
    let mut p = arena();
    let raw = node(
        &mut p,
        Value::Bytes {
            tag: None,
            data: b"AB".to_vec(),
        },
        0,
    );
    assert_eq!(literal(&p, raw), Known::Unknown);
    let bad = node(
        &mut p,
        Value::Bytes {
            tag: Some(177),
            data: vec![0xd8, 0],
        },
        0,
    );
    assert_eq!(literal(&p, bad), Known::Unknown);
    let good = text(&mut p, "A\u{1f600}");
    assert_eq!(literal(&p, good), Known::String("A\u{1f600}".into(), false));
}

#[test]
fn cyclic_graphs_and_budget_limits_terminate() {
    let mut p = arena();
    if let Value::Vector { items, .. } = &mut p.nodes[0].value {
        items.push(0);
    }
    assert!(analyze(&p).functions.is_empty());
    let mut out = Function {
        name: "budget".into(),
        offset: 0,
        calls: vec![],
        decoded: vec![],
        limitations: vec![],
    };
    let (instructions, _) = decode(&[106, 106, 12, 0, 0], 100, &mut 2, &mut out);
    assert_eq!(instructions.len(), 2);
    assert!(out.limitations.iter().any(|s| s.contains("budget")));
    let mut state = State::default();
    assert!(!state.push(Known::String("too large".into(), false), &mut 1));
}
