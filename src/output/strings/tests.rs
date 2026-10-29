use super::*;

#[test]
fn text_spans_locate_each_string_kind_correctly() {
    let text_rows: std::sync::Arc<[stng::ExtractedString]> = vec![
        // StackString: source is scattered across instructions, so the span
        // anchors at the first fragment — NOT the (non-contiguous) data_offset.
        stng::ExtractedString::new("STACKSTR", 9999, stng::StringMethod::StackString)
            .with_fragments(vec![
                stng::StringFragment {
                    offset: 0x100,
                    length: 4,
                },
                stng::StringFragment {
                    offset: 0x200,
                    length: 4,
                },
            ]),
        // Plain byte-scan literal: span at its file offset.
        stng::ExtractedString::new("plain", 0x10, stng::StringMethod::RawScan),
    ]
    .into();
    let literals = Literals(vec![
        Literal::new("decoded", 0x500).with_method(LiteralMethod::ScptBase64),
        Literal::new("lit", 0x40),
    ]);
    let strings = Strings {
        text: Text::from_rows(text_rows),
        literals,
        comments: Comments::new(),
    };
    let spans: Vec<(Span, &str)> = strings.text_spans().collect();
    assert_eq!(
        spans,
        vec![
            (Span::new(0x100, 4), "STACKSTR"), // first fragment, not (9999, 8)
            (Span::new(0x10, 5), "plain"),
            (Span::new(0x500, 7), "decoded"),
            (Span::new(0x40, 3), "lit"),
        ]
    );
}

#[test]
fn text_iter_walks_both_encodings() {
    let rows: std::sync::Arc<[stng::ExtractedString]> = vec![
        stng::ExtractedString::new("Mozilla/5.0", 100, stng::StringMethod::RawScan),
        stng::ExtractedString::new("RegOpenKeyExW", 200, stng::StringMethod::WideString),
    ]
    .into();
    let t = Text::from_rows(rows);
    let texts: Vec<&str> = t.iter().map(|s| s.value.as_str()).collect();
    assert_eq!(texts, vec!["Mozilla/5.0", "RegOpenKeyExW"]);
    assert_eq!(t.len(), 2);
    assert_eq!(t.ascii().count(), 1);
    assert_eq!(t.utf16le().count(), 1);
}

#[test]
fn literals_is_flat_serde_array() {
    let mut lits = Literals::new();
    lits.push(Literal::new("https://example/", 1024));
    lits.push(
        Literal::new("Hello", 7)
            .with_method(LiteralMethod::ScptLiteral)
            .with_encoding(LiteralEncoding::Utf16be),
    );
    let json = serde_json::to_string(&lits).unwrap();
    assert!(json.starts_with('['), "literals serialises as bare array");
    assert!(
        json.contains(r#""method":"scpt-literal","encoding":"utf16be""#),
        "{json}"
    );
    let back: Literals = serde_json::from_str(&json).unwrap();
    assert_eq!(back.as_slice(), lits.as_slice());
}

/// The serialized label and `as_str` agree for every method.
#[test]
fn literal_method_labels_match_serde() {
    for method in [
        LiteralMethod::ScptLiteral,
        LiteralMethod::ScptConstant,
        LiteralMethod::ScptBase64,
        LiteralMethod::ScptBase64Obf,
        LiteralMethod::ScptHex,
        LiteralMethod::ScptUrl,
        LiteralMethod::ScptUnicodeEscape,
        LiteralMethod::ScptBase32,
        LiteralMethod::ScptBase85,
        LiteralMethod::ScptRot13Base64,
        LiteralMethod::NibString,
    ] {
        assert_eq!(
            serde_json::to_value(method).unwrap(),
            serde_json::Value::from(method.as_str())
        );
    }
}

/// A source-extractor row keeps its text and offset through the push.
#[test]
fn producer_rows_convert_on_push() {
    let mut lits = Literals::new();
    lits.push(ExtractedString {
        value: "x".into(),
        offset: 9,
        ..ExtractedString::default()
    });
    assert_eq!(lits.as_slice(), &[Literal::new("x", 9)]);
}

/// Rows serialize their string as `value`, like stng's text rows.
#[test]
fn literal_rows_name_their_string_value() {
    let row = Literal::new("x", 9);
    assert_eq!(
        serde_json::to_value(&row).unwrap(),
        serde_json::json!({"value": "x", "offset": 9})
    );
    let back: Literal = serde_json::from_str(r#"{"value":"x","offset":9}"#).unwrap();
    assert_eq!(back, row);
}
