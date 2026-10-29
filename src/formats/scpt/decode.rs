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
        ) || literal.value.is_empty()
            || !seen.insert((literal.offset, literal.value.as_str()))
        {
            continue;
        }
        let len = literal.value.len();
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
        rows.push(
            stng::ExtractedString::new(literal.value.clone(), cursor, stng::StringMethod::RawScan)
                .with_kind(stng::classify_string(&literal.value)),
        );
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
        .map(|s| (s.offset, s.value.clone()))
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
mod tests;
