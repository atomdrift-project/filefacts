use super::*;

const ENCODED: &str = "cHJpbnRmICclc1xuJyAnU0NQVF9CQVNFNjRfT0sn";
const COMMAND: &str = "printf '%s\\n' 'SCPT_BASE64_OK'";

fn literal(text: &str, offset: u64, method: LiteralMethod) -> Literal {
    Literal::new(text, offset).with_method(method)
}

#[test]
fn stored_and_reconstructed_base64_keep_their_anchor() {
    for source in [LiteralMethod::ScptLiteral, LiteralMethod::ScptConstant] {
        let mut literals = Literals::new();
        literals.push(literal(ENCODED, 100, source));
        assert_eq!(recover(&mut literals), (1, false));
        assert!(
            literals
                .iter()
                .any(|s| s.value == ENCODED && s.method == Some(source))
        );
        assert!(literals.iter().any(|s| s.value == COMMAND
            && s.offset == 100
            && s.method == Some(LiteralMethod::ScptBase64)));
        assert_eq!(
            recover(&mut literals),
            (0, false),
            "no duplicate decoded rows"
        );
    }
}

#[test]
fn embedded_tokens_map_to_each_parent_not_utf8_displacements() {
    let mut literals = Literals::new();
    for anchor in [500, 10] {
        literals.push(literal(
            &format!("echo {ENCODED} | base64 -D"),
            anchor,
            LiteralMethod::ScptLiteral,
        ));
    }
    recover(&mut literals);
    let anchors: BTreeSet<_> = literals
        .iter()
        .filter(|s| s.value == COMMAND)
        .map(|s| s.offset)
        .collect();
    assert_eq!(anchors, BTreeSet::from([10, 500]));
}

#[test]
fn ordinary_and_invalid_literals_do_not_become_commands() {
    let mut ordinary = Literals::new();
    ordinary.push(literal("Hello World", 100, LiteralMethod::ScptLiteral));
    ordinary.push(literal(
        "!!!!!not base64!!!!!",
        200,
        LiteralMethod::ScptLiteral,
    ));
    assert_eq!(recover(&mut ordinary), (0, false));
    assert_eq!(ordinary.len(), 2);
}

#[test]
fn decoder_inputs_are_bounded_and_deduplicated() {
    let mut literals = Literals::new();
    for _ in 0..100 {
        literals.push(literal(ENCODED, 100, LiteralMethod::ScptLiteral));
    }
    let (rows, _, limited) = inputs(&literals, ENCODED.len());
    assert_eq!(rows.len(), 1);
    assert!(!limited);
    literals.push(literal(ENCODED, 200, LiteralMethod::ScptLiteral));
    assert!(inputs(&literals, ENCODED.len()).2);
    let mut large = Literals::new();
    large.push(literal(
        &"A".repeat(MAX_STRING + 1),
        300,
        LiteralMethod::ScptLiteral,
    ));
    assert!(inputs(&large, MAX_BYTES).0.is_empty());
    assert!(inputs(&large, MAX_BYTES).2);
    let mut many = Literals::new();
    for anchor in 0..=MAX_STRINGS {
        many.push(literal(ENCODED, anchor as u64, LiteralMethod::ScptLiteral));
    }
    let (rows, _, limited) = inputs(&many, MAX_BYTES);
    assert_eq!(rows.len(), MAX_STRINGS);
    assert!(limited);
}
