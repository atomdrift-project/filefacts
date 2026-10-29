use super::*;

#[test]
fn compiled_base64_exposes_decoded_text_without_changing_call_arguments() {
    let bytes = include_bytes!("../../../tests/fixtures/base64.scpt");
    let parsed = crate::open(bytes);
    let literals = parsed.literals();
    let encoded = literals
        .iter()
        .find(|s| s.value == "cHJpbnRmICclc1xuJyAnU0NQVF9CQVNFNjRfT0sn")
        .unwrap();
    let decoded = literals
        .iter()
        .find(|s| s.value == "printf '%s\\n' 'SCPT_BASE64_OK'")
        .unwrap();
    assert_eq!(decoded.offset, encoded.offset);
    assert_eq!(encoded.encoding, Some(LiteralEncoding::Utf16be));
    assert_eq!(decoded.method, Some(LiteralMethod::ScptBase64));
    assert!(parsed.symbols().iter().any(|s| matches!(s,
        Symbol::Call { target: Some(name), args, .. }
        if name == "syso.exec" && matches!(args.as_slice(), [Arg::Expression]))));
    assert!(parsed.errors().is_empty());
    let restored: crate::output::Literals =
        serde_json::from_str(&serde_json::to_string(literals).unwrap()).unwrap();
    assert!(restored.iter().any(|s| s.value == decoded.value
        && s.offset == encoded.offset
        && s.method == Some(LiteralMethod::ScptBase64)));
}

#[test]
fn legacy_text_is_skipped_and_native_unicode_is_kept() {
    // FAS-12 stores single-byte text here; even byte length proves nothing.
    let bytes = b"FasdUAS 1.101.10\x0c\0\0\0\0\0\x04ABCD\0\0";
    let parsed = crate::open(bytes);
    assert!(
        !parsed
            .literals()
            .iter()
            .any(|s| s.method == Some(LiteralMethod::ScptLiteral))
    );
    let bytes = fixture::compiled();
    let parsed = crate::open(&bytes);
    assert!(parsed.literals().iter().any(|s| s.value == "Hello World"
        && s.method == Some(LiteralMethod::ScptLiteral)
        && s.encoding == Some(LiteralEncoding::Utf16be)));
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
    bytes.extend_from_slice(&fixture::compiled());
    let parsed = crate::open(&bytes);
    assert_eq!(parsed.fileid().file_type(), crate::FileType::AppleScript);
    assert!(
        parsed
            .literals()
            .iter()
            .any(|s| s.value == "Hello World" && s.method == Some(LiteralMethod::ScptLiteral))
    );
}

#[test]
fn shebang_prefixed_plaintext_is_not_parsed() {
    let bytes = b"#!/usr/bin/osascript\ndo shell script \"id\"\n";
    let parsed = crate::open(bytes);
    assert_eq!(parsed.fileid().file_type(), crate::FileType::AppleScript);
    assert!(parsed.errors().is_empty());
}

#[test]
fn compiler_fixture_exposes_literals_calls_and_no_variable_imports() {
    let bytes = fixture::compiled();
    let parsed = crate::open(&bytes);
    assert!(parsed.literals().iter().any(|s| s.value == "Hello World"));
    assert!(parsed.symbols().iter().any(|s| matches!(s,
        Symbol::Call { target: Some(name), args, .. }
        if name == "greet" && matches!(args.as_slice(), [Arg::Number { value: 1, .. }]))));
    assert!(!parsed.symbols().iter().any(|s| matches!(s,
        Symbol::Import { name, .. } if name == "x" || name == "greet")));
    assert!(parsed.errors().is_empty());
}

#[test]
fn obfuscated_stealer_exposes_commands_and_stored_targets() {
    let bytes = zstd::decode_all(&include_bytes!("../../../tests/fixtures/stage4.scpt.zst")[..])
        .expect("fixture decompresses");
    let parsed = crate::open(&bytes);
    let literals = parsed.literals();
    assert!(literals.iter().any(|s| s.value == "Cookies.binarycookies"));
    assert!(literals.iter().any(|s| s.value == "NoteStore.sqlite"));
    assert!(
        literals
            .iter()
            .any(|s| s.value.contains("ditto -c -k --sequesterRsrc"))
    );
    assert!(
        literals
            .iter()
            .any(|s| s.value.contains("com.apple.quarantine"))
    );
    assert!(
        literals
            .iter()
            .filter(|s| s.method == Some(LiteralMethod::ScptConstant))
            .count()
            >= 839
    );
    assert!(literals.iter().all(|s| s.offset < bytes.len() as u64));
    assert!(parsed.symbols().iter().any(|s| matches!(s,
        Symbol::Call { target: Some(name), args, offset: Some(offset) }
        if name == "syso.exec" && *offset < bytes.len() as u64 && matches!(args.first(),
            Some(Arg::String { value }) if value == "security find-generic-password -w -s 'Chrome Safe Storage' 2>/dev/null"))));
    assert!(parsed.errors().is_empty());
}
