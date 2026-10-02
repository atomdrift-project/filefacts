//! Decode parsed text with stng without treating text positions as file offsets.

use std::collections::BTreeSet;

use crate::output::{Literal, LiteralEncoding, LiteralMethod, Literals};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRING: usize = 256 * 1024;
const MAX_STRINGS: usize = 4096;

struct Origin {
    start: u64,
    end: u64,
    anchor: u64,
}

fn inputs(literals: &Literals, budget: usize) -> (Vec<stng::ExtractedString>, Vec<Origin>, bool) {
    let mut rows = Vec::new();
    let mut origins = Vec::new();
    let mut remaining = budget;
    let mut cursor = 0;
    let mut limited = false;
    let mut seen = BTreeSet::new();
    for literal in literals.iter() {
        if !matches!(
            literal.method,
            Some(LiteralMethod::ScptLiteral | LiteralMethod::ScptConstant)
        ) || literal.text.is_empty()
            || !seen.insert((literal.offset, literal.text.as_str()))
        {
            continue;
        }
        let len = literal.text.len();
        if len > MAX_STRING || len > remaining || rows.len() >= MAX_STRINGS {
            limited = true;
            continue;
        }
        remaining -= len;
        // stng locates embedded tokens within UTF-8 input. Give each input a
        // disjoint virtual range, then map results back to the parent anchor.
        // Neither UTF-16 storage nor bytecode reconstruction is byte-identical.
        origins.push(Origin {
            start: cursor,
            end: cursor + len as u64,
            anchor: literal.offset,
        });
        rows.push(stng::ExtractedString {
            value: literal.text.clone(),
            data_offset: cursor,
            kind: stng::classify_string(&literal.text),
            ..Default::default()
        });
        cursor += len as u64 + 1;
    }
    (rows, origins, limited)
}

fn method(method: stng::StringMethod) -> Option<LiteralMethod> {
    use stng::StringMethod as M;
    Some(match method {
        M::Base64Decode => LiteralMethod::ScptBase64,
        M::Base64ObfuscatedDecode => LiteralMethod::ScptBase64Obf,
        M::HexDecode => LiteralMethod::ScptHex,
        M::UrlDecode => LiteralMethod::ScptUrl,
        M::UnicodeEscapeDecode => LiteralMethod::ScptUnicodeEscape,
        M::Base32Decode => LiteralMethod::ScptBase32,
        M::Base85Decode => LiteralMethod::ScptBase85,
        M::Rot13Base64Decode => LiteralMethod::ScptRot13Base64,
        _ => return None,
    })
}

/// One bounded pass; decoding is evidence, not interpreter evaluation.
pub(super) fn recover(literals: &mut Literals) -> (usize, bool) {
    let (rows, origins, mut limited) = inputs(literals, MAX_BYTES);
    if rows.is_empty() {
        return (0, limited);
    }
    let mut seen: BTreeSet<_> = literals
        .iter()
        .map(|s| (s.offset, s.text.clone()))
        .collect();
    let mut remaining = MAX_BYTES;
    let mut count = 0;
    for decoded in stng::decode_encoded_strings(&rows) {
        let Some(method) = method(decoded.method) else {
            continue;
        };
        let i = origins.partition_point(|origin| origin.start <= decoded.data_offset);
        let Some(origin) = i.checked_sub(1).and_then(|i| origins.get(i)) else {
            continue;
        };
        if decoded.data_offset >= origin.end || decoded.value.is_empty() {
            continue;
        }
        if decoded.value.len() > remaining || count >= MAX_STRINGS {
            limited = true;
            continue;
        }
        if !seen.insert((origin.anchor, decoded.value.clone())) {
            continue;
        }
        remaining -= decoded.value.len();
        count += 1;
        literals.push(
            Literal::new(decoded.value, origin.anchor)
                .with_method(method)
                .with_encoding(LiteralEncoding::Utf8),
        );
    }
    (count, limited)
}

#[cfg(test)]
mod tests {
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
                    .any(|s| s.text == ENCODED && s.method == Some(source))
            );
            assert!(literals.iter().any(|s| s.text == COMMAND
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
            .filter(|s| s.text == COMMAND)
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
}
