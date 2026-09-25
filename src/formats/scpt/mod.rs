//! Compiled AppleScript facts, extracted without invoking OSA or AppleEvents.
//!
//! Literals and decoded constants share the normal literal view. Calls carry
//! byte offsets and only arguments established by the bytecode analysis.
//! Unsupported instructions are reported in `scpt.limits`; their absence
//! never establishes runtime reachability or a complete decompilation.

mod bytecode;
mod decode;
mod parser;

use std::collections::BTreeSet;

use crate::Error;
use crate::metric;
use crate::output::{Arg, ExtractedString, Metrics, Strings, Symbol, Symbols, Values};
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
        let units: Vec<_> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        String::from_utf16(&units)
            .ok()
            .map(|text| (node.offset, text))
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
        Some(rest) => memchr::memchr(b'\n', rest).map_or(&[][..], |nl| &rest[nl + 1..]),
        None => bytes,
    };
    if !body.starts_with(b"Fasd") {
        return Ok(());
    }
    let parsed = parser::parse(bytes).map_err(|e| Error::malformed("scpt", e))?;
    values.insert("scpt.version", json!(parsed.version));
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
                    strings.literals.push(ExtractedString {
                        text,
                        offset,
                        method: Some("scpt-literal".into()),
                        encoding: Some("utf16be".into()),
                        ..Default::default()
                    });
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
        limitations.push(json!({"reason": reason, "stage": "parse"}));
    }
    if text_reader.limited {
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
                strings.literals.push(ExtractedString {
                    text: decoded.text,
                    offset: decoded.offset,
                    method: Some("scpt-constant".into()),
                    ..Default::default()
                });
            }
        }
        for reason in function.limitations {
            limitations.push(json!({"handler": function.name, "reason": reason}));
        }
    }
    let (decoded, limited) = decode::recover(&mut strings.literals);
    decoded_count += decoded;
    if limited {
        limitations.push(json!({"reason": "literal decode limit reached"}));
    }
    values.insert("scpt.limits", json!(limitations));
    metrics.insert(metric!("scpt.handlers"), handler_count as f64);
    metrics.insert(metric!("scpt.calls"), call_count as f64);
    metrics.insert(metric!("scpt.decoded"), decoded_count as f64);
    // Distinct Apple Events the script reaches for. The individual events are
    // already imports, but the count is what separates a one-shot dialog from
    // a script driving the shell, the loader and the delay timer at once.
    metrics.insert(metric!("scpt.events"), imports.len() as f64);
    // The walk stopped at one of the parser's ceilings. Worth its own metric
    // rather than living only in `scpt.limits` prose: a compiled AppleScript
    // built deep enough to exhaust a static parser is itself the signal, and
    // it used to be indistinguishable from a clean parse because the whole
    // extraction failed and reported nothing at all.
    metrics.insert(
        metric!("scpt.truncated"),
        f64::from(u8::from(parsed.truncated.is_some())),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_base64_exposes_decoded_text_without_changing_call_arguments() {
        let bytes = include_bytes!("../../../tests/fixtures/base64.scpt");
        let parsed = crate::open(bytes).unwrap();
        let literals = parsed.literals();
        let encoded = literals
            .iter()
            .find(|s| s.text == "cHJpbnRmICclc1xuJyAnU0NQVF9CQVNFNjRfT0sn")
            .unwrap();
        let decoded = literals
            .iter()
            .find(|s| s.text == "printf '%s\\n' 'SCPT_BASE64_OK'")
            .unwrap();
        assert_eq!(decoded.offset, encoded.offset);
        assert_eq!(encoded.encoding.as_deref(), Some("utf16be"));
        assert_eq!(decoded.method.as_deref(), Some("scpt-base64"));
        assert!(parsed.symbols().iter().any(|s| matches!(s,
            Symbol::Call { target: Some(name), args, .. }
            if name == "syso.exec" && matches!(args.as_slice(), [Arg::Expression]))));
        assert!(parsed.errors().is_empty());
        let restored: crate::output::Literals =
            serde_json::from_str(&serde_json::to_string(literals).unwrap()).unwrap();
        assert!(restored.iter().any(|s| s.text == decoded.text
            && s.offset == encoded.offset
            && s.method.as_deref() == Some("scpt-base64")));
    }

    #[test]
    fn legacy_text_is_skipped_and_native_unicode_is_kept() {
        // FAS-12 stores single-byte text here; even byte length proves nothing.
        let bytes = b"FasdUAS 1.101.10\x0c\0\0\0\0\0\x04ABCD\0\0";
        let parsed = crate::open(bytes).unwrap();
        assert!(
            !parsed
                .literals()
                .iter()
                .any(|s| s.method.as_deref() == Some("scpt-literal"))
        );
        let bytes = parser::test_fixture();
        let parsed = crate::open(&bytes).unwrap();
        assert!(parsed.literals().iter().any(|s| s.text == "Hello World"
            && s.method.as_deref() == Some("scpt-literal")
            && s.encoding.as_deref() == Some("utf16be")));
    }

    #[test]
    fn shared_payloads_and_invalid_text_are_decoded_at_most_once() {
        let mut parsed = parser::Parsed {
            nodes: vec![parser::Node {
                offset: 100,
                value: Value::Bytes {
                    tag: None,
                    data: vec![0, b'A', 0, b'B'],
                },
            }],
            root: 0,
            version: "1.10".into(),
            truncated: None,
        };
        let mut reader = TextReader::new(6);
        assert_eq!(reader.read(&parsed, &[0]), Some((100, "AB".into())));
        for _ in 0..4096 {
            assert!(reader.read(&parsed, &[0]).is_none());
        }
        assert_eq!(reader.remaining, 2);
        assert!(!reader.limited);
        parsed.nodes.push(parser::Node {
            offset: 200,
            value: Value::Bytes {
                tag: None,
                data: vec![0xd8, 0], // Unpaired UTF-16 surrogate.
            },
        });
        assert!(reader.read(&parsed, &[1]).is_none());
        assert_eq!(reader.remaining, 0);
        assert!(reader.read(&parsed, &[1]).is_none());
        assert!(!reader.limited);
        parsed.nodes.push(parser::Node {
            offset: 300,
            value: Value::Bytes {
                tag: None,
                data: vec![0, b'C'],
            },
        });
        assert!(reader.read(&parsed, &[2]).is_none());
        assert!(reader.limited);
        assert_eq!(reader.remaining, 0);
    }

    #[test]
    fn stored_text_budget_is_reported() {
        let size = MAX_LITERAL_BYTES + 2;
        // Native Unicode vector referencing a long untyped data record.
        let mut bytes = b"FasdUAS 1.101.10\x0e\0\0\0\x01\xb1\0\x01\x13\0\x01\0\0".to_vec();
        bytes.extend_from_slice(&(size as u32).to_be_bytes());
        bytes.resize(bytes.len() + size, 0);
        let mut values = Values::new();
        let mut strings = Strings::default();
        let mut metrics = Metrics::new();
        let mut symbols = Symbols::new();
        extract(
            &bytes,
            &mut values,
            &mut strings,
            &mut metrics,
            &mut symbols,
        )
        .unwrap();
        assert!(strings.literals.is_empty());
        assert_eq!(
            values.get("scpt.limits"),
            Some(&json!([
                {"reason": "stored text work limit reached"}
            ]))
        );
    }

    #[test]
    fn shebang_prefixed_compiled_script_is_extracted() {
        let mut bytes = b"#!/usr/bin/osascript\n".to_vec();
        bytes.extend_from_slice(&parser::test_fixture());
        let parsed = crate::open(&bytes).unwrap();
        assert_eq!(parsed.fileid().file_type(), crate::FileType::AppleScript);
        assert!(
            parsed
                .literals()
                .iter()
                .any(|s| s.text == "Hello World" && s.method.as_deref() == Some("scpt-literal"))
        );
    }

    #[test]
    fn shebang_prefixed_plaintext_is_not_parsed() {
        let bytes = b"#!/usr/bin/osascript\ndo shell script \"id\"\n";
        let parsed = crate::open(bytes).unwrap();
        assert_eq!(parsed.fileid().file_type(), crate::FileType::AppleScript);
        assert!(parsed.errors().is_empty());
    }

    #[test]
    fn compiler_fixture_exposes_literals_calls_and_no_variable_imports() {
        let bytes = parser::test_fixture();
        let parsed = crate::open(&bytes).unwrap();
        assert!(parsed.literals().iter().any(|s| s.text == "Hello World"));
        assert!(parsed.symbols().iter().any(|s| matches!(s,
            Symbol::Call { target: Some(name), args, .. }
            if name == "greet" && matches!(args.as_slice(), [Arg::Number { value: 1, .. }]))));
        assert!(!parsed.symbols().iter().any(|s| matches!(s,
            Symbol::Import { name, .. } if name == "x" || name == "greet")));
        assert!(parsed.errors().is_empty());
    }

    #[test]
    fn obfuscated_stealer_exposes_commands_and_stored_targets() {
        let bytes = include_bytes!("../../../tests/fixtures/stage4.scpt");
        let parsed = crate::open(bytes).unwrap();
        let literals = parsed.literals();
        assert!(literals.iter().any(|s| s.text == "Cookies.binarycookies"));
        assert!(literals.iter().any(|s| s.text == "NoteStore.sqlite"));
        assert!(
            literals
                .iter()
                .any(|s| s.text.contains("ditto -c -k --sequesterRsrc"))
        );
        assert!(
            literals
                .iter()
                .any(|s| s.text.contains("com.apple.quarantine"))
        );
        assert!(
            literals
                .iter()
                .filter(|s| s.method.as_deref() == Some("scpt-constant"))
                .count()
                >= 839
        );
        assert!(literals.iter().all(|s| s.offset < bytes.len()));
        assert!(parsed.symbols().iter().any(|s| matches!(s,
            Symbol::Call { target: Some(name), args, offset: Some(offset) }
            if name == "syso.exec" && *offset < bytes.len() as u64 && matches!(args.first(),
                Some(Arg::String { value }) if value == "security find-generic-password -w -s 'Chrome Safe Storage' 2>/dev/null"))));
        assert!(parsed.errors().is_empty());
    }
}
