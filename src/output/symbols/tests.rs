use super::*;

#[test]
fn symbol_kind_discriminator_round_trips_through_serde() {
    let s = Symbol::Import {
        name: "CreateFileW".into(),
        library: Some("kernel32".into()),
        alias: None,
        offset: Some(0x1234),
        ordinal: None,
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"kind\":\"import\""));
    let back: Symbol = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind(), SymbolKind::Import);
    assert_eq!(back.name(), Some("CreateFileW"));
}

#[test]
fn function_cfg_fields_round_trip() {
    let s = Symbol::Function {
        name: "_get_cpuid".into(),
        offset: Some(0x4080),
        complexity: Some(7),
        callees: vec!["_resolve".into(), "_lzma_crc32".into()],
    };
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["kind"], "function");
    assert_eq!(json["complexity"], 7);
    assert_eq!(json["callees"][0], "_resolve");
    let back: Symbol = serde_json::from_value(json).unwrap();
    if let Symbol::Function { callees, .. } = back {
        assert_eq!(callees, vec!["_resolve", "_lzma_crc32"]);
    } else {
        panic!("expected Function variant");
    }
}

#[test]
fn function_optional_fields_elide_from_json() {
    let s = Symbol::Function {
        name: "CreateFileW".into(),
        offset: Some(0x1000),
        complexity: None,
        callees: Vec::new(),
    };
    let json = serde_json::to_value(&s).unwrap();
    let obj = json.as_object().unwrap();
    for key in ["complexity", "callees"] {
        assert!(!obj.contains_key(key), "expected {key} elided when absent");
    }
}

#[test]
fn call_record_round_trips() {
    let s = Symbol::Call {
        target: Some("fetch".into()),
        args: vec![Arg::String {
            value: "https://example.com".into(),
        }],
        offset: Some(42),
    };
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["kind"], "call");
    assert_eq!(json["target"], "fetch");
    assert_eq!(json["args"][0]["shape"], "string");
    assert_eq!(json["args"][0]["value"], "https://example.com");
    let back: Symbol = serde_json::from_value(json).unwrap();
    assert_eq!(back.name(), Some("fetch"));
}

#[test]
fn dynamic_call_serializes_without_target() {
    let s = Symbol::Call {
        target: None,
        args: vec![Arg::Identifier {
            name: "callback".into(),
        }],
        offset: None,
    };
    let json = serde_json::to_value(&s).unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("target"));
}

#[test]
fn numeric_arg_carries_text_value_and_radix() {
    // chmod(file, 0o777) — the canonical example. Verifies the
    // Number variant serializes with all three fields so authors
    // can match on parsed value + source-written radix.
    let s = Symbol::Call {
        target: Some("chmod".into()),
        args: vec![
            Arg::String {
                value: "/tmp/x".into(),
            },
            Arg::Number {
                text: "0o777".into(),
                value: 511,
                radix: 8,
            },
        ],
        offset: Some(0),
    };
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["args"][1]["shape"], "number");
    assert_eq!(json["args"][1]["text"], "0o777");
    assert_eq!(json["args"][1]["value"], 511);
    assert_eq!(json["args"][1]["radix"], 8);
    let back: Symbol = serde_json::from_value(json).unwrap();
    let Symbol::Call { args, .. } = back else {
        panic!("expected Call");
    };
    assert_eq!(args.len(), 2);
    assert!(matches!(args[0], Arg::String { ref value } if value == "/tmp/x"));
    assert!(matches!(
        args[1],
        Arg::Number {
            value: 511,
            radix: 8,
            ..
        }
    ));
}

#[test]
fn collection_is_transparent_array() {
    let mut syms = Symbols::new();
    syms.push(Symbol::Import {
        name: "Foo".into(),
        library: Some("bar".into()),
        alias: None,
        offset: None,
        ordinal: None,
    });
    let json = serde_json::to_string(&syms).unwrap();
    assert!(json.starts_with('['));
    assert!(json.contains("\"kind\":\"import\""));
}

#[test]
fn iter_mut_rewrites_in_place() {
    let mut syms = Symbols::new();
    syms.push(Symbol::Identifier {
        name: "a".into(),
        offset: None,
    });
    for symbol in syms.iter_mut() {
        if let Symbol::Identifier { name, .. } = symbol {
            name.push('b');
        }
    }
    assert_eq!(syms.iter().next().and_then(Symbol::name), Some("ab"));
}

#[test]
fn iter_kind_filters() {
    let mut syms = Symbols::new();
    syms.push(Symbol::Import {
        name: "Foo".into(),
        library: None,
        alias: None,
        offset: None,
        ordinal: None,
    });
    syms.push(Symbol::Export {
        name: "Bar".into(),
        offset: None,
        ordinal: None,
        forward_to: None,
    });
    syms.push(Symbol::Import {
        name: "Baz".into(),
        library: None,
        alias: None,
        offset: None,
        ordinal: None,
    });
    let imports: Vec<&str> = syms
        .iter_kind(SymbolKind::Import)
        .map(|s| s.name().unwrap())
        .collect();
    assert_eq!(imports, vec!["Foo", "Baz"]);
}
