//! Compiled AppleScript facts, extracted without invoking OSA or AppleEvents.
//!
//! Literals and decoded constants share the normal literal view. Calls carry
//! byte offsets and only arguments established by the bytecode analysis.
//! Unsupported instructions are reported in `scpt.limits`; their absence
//! never establishes runtime reachability or a complete decompilation.

mod bytecode;
mod decode;
#[cfg(test)]
mod fixture;
mod parser;

use std::collections::BTreeSet;

use crate::Error;
use crate::metric;
use crate::output::{
    Arg, Literal, LiteralEncoding, LiteralMethod, Metrics, Strings, Symbol, Symbols, Values,
};
use crate::value_key;
use parser::Value;
use serde_json::json;

const MAX_LITERAL_BYTES: usize = 8 * 1024 * 1024;

struct TextReader {
    seen: BTreeSet<usize>,
    remaining: usize,
    limited: bool,
}

impl TextReader {
    fn new(budget: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            remaining: budget,
            limited: false,
        }
    }

    fn read(&mut self, parsed: &parser::Parsed, items: &[usize]) -> Option<(usize, String)> {
        if !matches!(items.len(), 1 | 2) {
            return None;
        }
        let id = *items.first()?;
        let node = parsed.nodes.get(id)?;
        // FAS-12 legacy text/style records have a child tagged 177. Only
        // untyped children of native Unicode vectors establish UTF-16BE here.
        let Value::Bytes { tag: None, data } = &node.value else {
            return None;
        };
        // Deduplicate before allocating or decoding, including failed decodes.
        if !self.seen.insert(id) || !data.len().is_multiple_of(2) {
            return None;
        }
        if data.len() > self.remaining {
            self.limited = true;
            return None;
        }
        self.remaining -= data.len();
        crate::bytes::utf16_strict(data, crate::bytes::Endian::Big).map(|text| (node.offset, text))
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    symbols: &mut Symbols,
) -> Result<(), Error> {
    // Plaintext AppleScript retains the generic extraction path. A compiled
    // script may carry a `#!/usr/bin/osascript` line ahead of its magic; the
    // parser skips it, so only the gate needs to look past it.
    let body = match bytes.strip_prefix(b"#!") {
        Some(rest) => memchr::memchr(b'\n', rest)
            .and_then(|nl| rest.get(nl + 1..))
            .unwrap_or_default(),
        None => bytes,
    };
    if !body.starts_with(b"Fasd") {
        return Ok(());
    }
    let parsed = parser::parse(bytes).map_err(|e| Error::malformed_caused_by("scpt", e))?;
    values.insert_key(value_key!("scpt.version"), json!(parsed.version));
    let mut seen_literals = BTreeSet::new();
    let mut text_reader = TextReader::new(MAX_LITERAL_BYTES);
    let mut imports = BTreeSet::new();
    for node in &parsed.nodes {
        match &node.value {
            Value::Event(name) if imports.insert(name.as_str()) => {
                symbols.push(Symbol::Import {
                    name: name.clone(),
                    alias: None,
                    library: Some("AppleEvents".into()),
                    offset: Some(node.offset as u64),
                    ordinal: None,
                });
            }
            Value::Vector {
                tag: Some(0xb1),
                items,
            } => {
                if let Some((offset, text)) = text_reader.read(&parsed, items)
                    && seen_literals.insert((offset, text.clone()))
                {
                    strings.literals.push(
                        Literal::new(text, offset as u64)
                            .with_method(LiteralMethod::ScptLiteral)
                            .with_encoding(LiteralEncoding::Utf16be),
                    );
                }
            }
            _ => {}
        }
    }
    let analysis = bytecode::analyze(&parsed);
    let handler_count = analysis.functions.len();
    let mut call_count = 0;
    let mut decoded_count = 0;
    let mut limitations = Vec::new();
    if let Some(reason) = &parsed.truncated {
        tracing::debug!(
            target: "filefacts::scpt",
            format = "scpt",
            stage = "parse",
            nodes = parsed.nodes.len(),
            reason = %reason,
            "compiled script walk stopped at a budget; keeping the nodes built so far",
        );
        limitations.push(json!({"reason": reason, "stage": "parse"}));
    }
    if text_reader.limited {
        tracing::debug!(
            target: "filefacts::scpt",
            format = "scpt",
            stage = "literals",
            budget = MAX_LITERAL_BYTES,
            "stored text budget reached; later text records were not decoded",
        );
        limitations.push(json!({"reason": "stored text work limit reached"}));
    }
    // The analysis is consumed: its owned names and recovered text move into
    // the symbol and literal views rather than being copied into them.
    for function in analysis.functions {
        symbols.push(Symbol::Function {
            name: function.name.clone(),
            offset: Some(function.offset as u64),
            complexity: None,
            callees: function
                .calls
                .iter()
                .map(|c| c.target.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        });
        for call in function.calls {
            call_count += 1;
            symbols.push(Symbol::Call {
                target: Some(call.target),
                offset: Some(call.offset as u64),
                args: call
                    .args
                    .into_iter()
                    .map(|arg| match arg {
                        bytecode::Argument::String(value) => Arg::String { value },
                        bytecode::Argument::Number(value) => Arg::Number {
                            text: value.to_string(),
                            value,
                            radix: 10,
                        },
                        bytecode::Argument::Bool(value) => Arg::Bool { value },
                        bytecode::Argument::Unknown => Arg::Expression,
                    })
                    .collect(),
            });
        }
        for decoded in function.decoded {
            if seen_literals.insert((decoded.offset, decoded.text.clone())) {
                decoded_count += 1;
                strings.literals.push(
                    Literal::new(decoded.text, decoded.offset as u64)
                        .with_method(LiteralMethod::ScptConstant),
                );
            }
        }
        for reason in function.limitations {
            limitations.push(json!({"handler": function.name, "reason": reason}));
        }
    }
    let (decoded, limited) = decode::recover(&mut strings.literals);
    decoded_count += decoded;
    if limited {
        tracing::debug!(
            target: "filefacts::scpt",
            format = "scpt",
            stage = "decode",
            "literal decode budget reached; later encoded literals were not decoded",
        );
        limitations.push(json!({"reason": "literal decode limit reached"}));
    }
    values.insert_key(value_key!("scpt.limits"), json!(limitations));
    metrics.insert(metric!("scpt.handler_count"), handler_count as f64);
    metrics.insert(metric!("scpt.call_count"), f64::from(call_count));
    metrics.insert(metric!("scpt.decoded_count"), decoded_count as f64);
    // Distinct Apple Events the script reaches for. The individual events are
    // already imports, but the count is what separates a one-shot dialog from
    // a script driving the shell, the loader and the delay timer at once.
    metrics.insert(metric!("scpt.event_count"), imports.len() as f64);
    // The walk stopped at one of the parser's ceilings. Worth its own metric
    // rather than living only in `scpt.limits` prose: a compiled AppleScript
    // built deep enough to exhaust a static parser is itself the signal, and
    // a rule should not have to parse the limits text to see it.
    metrics.insert(
        metric!("scpt.truncated"),
        f64::from(u8::from(parsed.truncated.is_some())),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
