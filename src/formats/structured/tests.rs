use super::*;

#[test]
fn json_object_is_promoted() {
    let mut v = Values::new();
    extract_json(br#"{"name":"x","version":"1.0"}"#, &mut v).unwrap();
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
    assert_eq!(v.get("version").and_then(|x| x.as_str()), Some("1.0"));
}

#[test]
fn json_array_root_lands_under_root_key() {
    let mut v = Values::new();
    extract_json(b"[1,2,3]", &mut v).unwrap();
    assert!(v.get("root").and_then(|x| x.as_array()).is_some());
}

#[test]
fn json_malformed_returns_error() {
    let mut v = Values::new();
    let err = extract_json(b"{ not json", &mut v).unwrap_err();
    assert!(matches!(err, Error::Malformed { format: "json", .. }));
}

#[test]
fn toml_basic() {
    let mut v = Values::new();
    extract_toml(b"[package]\nname = \"x\"\n", &mut v).unwrap();
    assert_eq!(v.get("package.name").and_then(|x| x.as_str()), Some("x"));
}

#[test]
fn yaml_basic() {
    let mut v = Values::new();
    extract_yaml(b"name: x\non:\n  push:\n    branches: [main]\n", &mut v).unwrap();
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
}

fn yaml(text: &str) -> JsonValue {
    parse_yaml(text.as_bytes()).unwrap()
}

/// Plain scalars resolve as serde_yaml 0.9 resolved them, so values rules
/// match as strings (`0755`, `1_000`, `yes`) stay strings.
#[test]
fn yaml_plain_scalars_resolve_as_serde_yaml_did() {
    let v = yaml(
        "on: push\nwords: [yes, no, on, off, y, n]\nbools: [true, True, FALSE]\n\
             odd: [tRuE, nUlL, 0755, 007, 1_000, 1e999, +.nan]\n\
             nulls: [~, null, Null, NULL]\nempty:\nnonfinite: [.inf, -.inf, .nan, .NaN]\n\
             nums: [42, -7, 0x1F, -0x1F, 0o17, 0b101, +12, 3.5, 1e3, .5]\n\
             wide: [18446744073709551616, -9223372036854775809]\n\
             quoted: ['true', \"1\"]\nblock: |\n  0755\n",
    );
    assert_eq!(v["on"], "push");
    assert_eq!(
        v["words"],
        serde_json::json!(["yes", "no", "on", "off", "y", "n"])
    );
    assert_eq!(v["bools"], serde_json::json!([true, true, false]));
    assert_eq!(
        v["odd"],
        serde_json::json!(["tRuE", "nUlL", "0755", "007", "1_000", "1e999", "+.nan"])
    );
    assert_eq!(v["nulls"], serde_json::json!([null, null, null, null]));
    assert_eq!(v["empty"], JsonValue::Null);
    assert_eq!(v["nonfinite"], serde_json::json!([null, null, null, null]));
    assert_eq!(
        v["nums"],
        serde_json::json!([42, -7, 31, -31, 15, 5, 12, 3.5, 1000.0, 0.5])
    );
    // Wider than 64 bits: kept as digits, never a float.
    assert_eq!(
        v["wide"],
        serde_json::json!(["18446744073709551616", "-9223372036854775809"])
    );
    assert_eq!(v["quoted"], serde_json::json!(["true", "1"]));
    assert_eq!(v["block"], "0755\n");
}

/// `!!bool`/`!!int`/`!!float`/`!!null` convert or fail, other `!!` tags
/// leave a string, and a local tag is dropped with its plain scalar
/// resolved as untagged.
#[test]
fn yaml_tags_resolve_as_serde_yaml_did() {
    let v = yaml(
        "int: !!int \"42\"\nfloat: !!float 1\nstr: !!str 0x1F\nts: !!timestamp 2001-12-14\n\
             bin: !!binary aGVsbG8=\nlocal: !custom 12\nlocal_zero: !custom 0755\n\
             local_quoted: !custom \"12\"\nglobal: !<tag:example.com,2000:x> 7\n\
             spec: !ruby/object:Gem::Specification\n  name: x\nset: !!set {a, b}\n",
    );
    assert_eq!(v["int"], 42);
    assert_eq!(v["float"], 1.0);
    assert_eq!(v["str"], "0x1F");
    assert_eq!(v["ts"], "2001-12-14");
    assert_eq!(v["bin"], "aGVsbG8=");
    assert_eq!(v["local"], 12);
    assert_eq!(v["local_zero"], "0755");
    assert_eq!(v["local_quoted"], "12");
    assert_eq!(v["global"], "7");
    assert_eq!(v["spec"], serde_json::json!({"name": "x"}));
    assert_eq!(v["set"], serde_json::json!({"a": null, "b": null}));
    for bad in ["a: !!int abc\n", "a: !!bool yes\n", "a: !!null \"\"\n"] {
        assert!(parse_yaml(bad.as_bytes()).is_err(), "{bad}");
    }
}

/// A key that is not a string keeps the spelling serde_yaml gave it.
#[test]
fn yaml_non_string_keys_are_spelled_by_value() {
    let v = yaml(
        "1: int\n0x1F: hex\ntrue: bool\n~: nil\n1.5: float\n1e20: exp\n.inf: inf\n\
             0755: zero\n? [a, b]\n: seq\n? {x: 1}\n: map\n? [yes, '1', [2, 3]]\n: nested\n\
             !t tagged: tag\n",
    );
    for (key, value) in [
        ("1", "int"),
        ("31", "hex"),
        ("true", "bool"),
        ("null", "nil"),
        ("1.5", "float"),
        ("1e20", "exp"),
        (".inf", "inf"),
        ("0755", "zero"),
        ("- a\n- b", "seq"),
        ("x: 1", "map"),
        ("- yes\n- '1'\n- - 2\n  - 3", "nested"),
        ("!t tagged", "tag"),
    ] {
        assert_eq!(v[key], value, "{key:?} in {v}");
    }
}

/// Aliases expand, and `<<` stays an ordinary key.
#[test]
fn yaml_anchors_aliases_and_merge_keys() {
    let v =
        yaml("base: &b {k: 1}\ncopy: *b\nmerged:\n  <<: *b\n  j: 2\nzero: &z 0755\nagain: *z\n");
    assert_eq!(v["copy"], serde_json::json!({"k": 1}));
    assert_eq!(v["merged"], serde_json::json!({"<<": {"k": 1}, "j": 2}));
    assert_eq!(v["again"], "0755");
}

/// A billion laughs stops at serde_yaml's alias rule, and reusing one big
/// anchor stops at the replay budget, both quickly and without building
/// the expansion. Three levels (1,110 replayed events) are ordinary reuse.
#[test]
fn yaml_alias_bombs_are_rejected_quickly() {
    let mut laughs = String::from("a0: &a0 lol\n");
    for level in 1..=9 {
        let refs = vec![format!("*a{}", level - 1); 10].join(", ");
        laughs.push_str(&format!("a{level}: &a{level} [{refs}]\n"));
    }
    let items: Vec<String> = (0..2_000).map(|i| i.to_string()).collect();
    let reuse = format!(
        "big: &big [{}]\nuses: [{}]\n",
        items.join(", "),
        vec!["*big"; 2_000].join(", ")
    );
    let start = std::time::Instant::now();
    let err = parse_yaml(laughs.as_bytes()).unwrap_err().to_string();
    assert!(err.contains("alias repetition limit"), "{err}");
    let err = parse_yaml(reuse.as_bytes()).unwrap_err().to_string();
    assert!(err.contains("aliases expand past"), "{err}");
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    let small: String = laughs.lines().take(4).map(|l| format!("{l}\n")).collect();
    assert!(parse_yaml(small.as_bytes()).is_ok());
}

/// Aliases of one large scalar replay a single event each, so the event
/// budget let a megabyte string aliased from four bytes apiece build
/// gigabytes. Replayed scalar bytes have their own budget.
#[test]
fn yaml_alias_scalar_bytes_are_bounded() {
    let big = "x".repeat(64 << 10);
    let bomb = format!(
        "big: &big {big}\nuses: [{}]\n",
        vec!["*big"; 1_000].join(", ")
    );
    let err = parse_yaml(bomb.as_bytes()).unwrap_err().to_string();
    assert!(err.contains("scalar bytes"), "{err}");
    let ok = format!(
        "big: &big {big}\nuses: [{}]\n",
        vec!["*big"; 100].join(", ")
    );
    assert_eq!(yaml(&ok)["uses"].as_array().map(Vec::len), Some(100));
}

/// Nesting is capped at serde_yaml's 128 levels, in flow and block style,
/// through aliases too, and an absurdly deep document fails fast.
#[test]
fn yaml_nesting_depth_is_bounded() {
    let flow = |n: usize| format!("a: {}{}\n", "[".repeat(n), "]".repeat(n));
    let block = |n: usize| {
        let mut doc: String = (0..n)
            .map(|i| format!("{}k{i}:\n", "  ".repeat(i)))
            .collect();
        doc.push_str(&format!("{}leaf\n", "  ".repeat(n)));
        doc
    };
    // The document's own mapping is the first level.
    assert!(parse_yaml(flow(127).as_bytes()).is_ok());
    assert!(parse_yaml(flow(128).as_bytes()).is_err());
    assert!(parse_yaml(block(128).as_bytes()).is_ok());
    assert!(parse_yaml(block(129).as_bytes()).is_err());
    // 64 levels under an anchor, replayed 64 levels deep: 129 in all.
    let deep = format!(
        "a: &x {}{}\nb: {}*x{}\n",
        "[".repeat(64),
        "]".repeat(64),
        "[".repeat(64),
        "]".repeat(64)
    );
    assert!(parse_yaml(deep.as_bytes()).is_err());
    assert!(parse_yaml(b"a: &a [1, *a]\n").is_err());
    let start = std::time::Instant::now();
    assert!(parse_yaml(flow(100_000).as_bytes()).is_err());
    assert!(parse_yaml(block(5_000).as_bytes()).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
}

/// The per-event budgets grow with the input, so a lockfile larger than
/// serde-saphyr's default node budget still parses.
#[test]
fn yaml_large_document_parses() {
    let doc: String = (0..300_000).map(|i| format!("- {i}\n")).collect();
    let v = parse_yaml(doc.as_bytes()).unwrap();
    assert_eq!(v.as_array().map(Vec::len), Some(300_000));
}

#[test]
fn yaml_streams_duplicates_and_bad_bytes_are_malformed() {
    for bad in [
        &b"a: 1\n---\nb: 2\n"[..],
        b"a: 1\na: 2\n",
        b"true: 1\nTrue: 2\n",
        b"a: \xff\n",
        b"a: [1, 2\n",
    ] {
        let mut v = Values::new();
        let err = extract_yaml(bad, &mut v).unwrap_err();
        assert!(matches!(err, Error::Malformed { format: "yaml", .. }));
    }
    assert_eq!(yaml(""), JsonValue::Null);
    assert_eq!(yaml("\u{feff}a: 1\n")["a"], 1);
}

/// The same dictionary written as a binary plist and as an XML plist
/// lands in `values` identically: the binary reader is chosen from the
/// `bplist00` magic, not from anything the caller passes.
#[test]
fn binary_plist_matches_xml_plist() {
    let mut dict = plist::Dictionary::new();
    dict.insert("CFBundleIdentifier".into(), "com.example.dropper".into());
    dict.insert("LSUIElement".into(), true.into());
    dict.insert("Count".into(), 42.into());
    dict.insert("Ratio".into(), 0.5.into());
    dict.insert("Blob".into(), plist::Value::Data(b"Man".to_vec()));
    dict.insert(
        "Args".into(),
        plist::Value::Array(vec!["-c".into(), "curl http://x".into()]),
    );
    let root = plist::Value::Dictionary(dict);

    let mut binary = Vec::new();
    root.to_writer_binary(&mut binary).unwrap();
    assert!(binary.starts_with(b"bplist00"));
    let mut xml = Vec::new();
    root.to_writer_xml(&mut xml).unwrap();

    let mut from_binary = Values::new();
    extract_plist(&binary, &mut from_binary).unwrap();
    let mut from_xml = Values::new();
    extract_plist(&xml, &mut from_xml).unwrap();
    assert_eq!(from_binary.as_json(), from_xml.as_json());

    assert_eq!(
        from_binary.get("CFBundleIdentifier").unwrap(),
        "com.example.dropper"
    );
    assert_eq!(from_binary.get("LSUIElement").unwrap(), true);
    assert_eq!(from_binary.get("Count").unwrap(), 42);
    assert_eq!(from_binary.get("Ratio").unwrap(), 0.5);
    assert_eq!(from_binary.get("Blob").unwrap(), "TWFu");
    assert_eq!(from_binary.get("Args[1]").unwrap(), "curl http://x");
}

/// NSKeyedArchiver output is the common binary-only plist. Its `$class`
/// object references decode to `CF$UID` dictionaries instead of nulls.
#[test]
fn binary_plist_keyed_archive_uids_are_preserved() {
    let mut class = plist::Dictionary::new();
    class.insert("$classname".into(), "NSMutableDictionary".into());
    let mut object = plist::Dictionary::new();
    object.insert("$class".into(), plist::Value::Uid(plist::Uid::new(2)));
    let mut root = plist::Dictionary::new();
    root.insert("$archiver".into(), "NSKeyedArchiver".into());
    root.insert(
        "$objects".into(),
        plist::Value::Array(vec![
            "$null".into(),
            plist::Value::Dictionary(object),
            plist::Value::Dictionary(class),
        ]),
    );
    let mut binary = Vec::new();
    plist::Value::Dictionary(root)
        .to_writer_binary(&mut binary)
        .unwrap();

    let mut values = Values::new();
    extract_plist(&binary, &mut values).unwrap();
    assert_eq!(values.get("$archiver").unwrap(), "NSKeyedArchiver");
    assert_eq!(values.get("$objects[1].$class.CF$UID").unwrap(), 2);
    assert_eq!(
        values.get("$objects[2].$classname").unwrap(),
        "NSMutableDictionary"
    );
}

/// Run `f` on a thread with a 2 MiB stack, the size of a rayon worker's, so a
/// recursion that only fits the 8 MiB main stack fails here.
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

fn nested_xml_plist(levels: usize) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><plist version=\"1.0\">{}<string>x</string>{}</plist>",
        "<array>".repeat(levels),
        "</array>".repeat(levels)
    )
    .into_bytes()
}

/// A 20k-deep `<array>` nest built the whole `plist::Value` and then recursed
/// through it, overflowing the stack. The cap now applies as events stream in.
#[test]
fn plist_nesting_depth_is_bounded() {
    let (deep, at_cap, past_cap) = on_small_stack(|| {
        let mut values = Values::new();
        let deep = extract_plist(&nested_xml_plist(20_000), &mut values);
        let at_cap = extract_plist(&nested_xml_plist(PLIST_MAX_DEPTH), &mut values);
        let past_cap = extract_plist(&nested_xml_plist(PLIST_MAX_DEPTH + 1), &mut values);
        (
            deep.map_err(|e| e.to_string()),
            at_cap.map_err(|e| e.to_string()),
            past_cap.map_err(|e| e.to_string()),
        )
    });
    assert!(deep.unwrap_err().contains("deeper than"));
    assert!(at_cap.is_ok());
    assert!(past_cap.is_err());
}

/// A binary plist may reference one collection from many places, so a few
/// hundred bytes can describe billions of values. Each level here is an
/// array of 14 references to the next level.
#[test]
fn binary_plist_reference_reuse_is_bounded() {
    const LEVELS: usize = 8;
    let mut bytes = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for level in 0..LEVELS {
        offsets.push(bytes.len() as u8);
        // An array marker with its count, 14, in the low nibble.
        bytes.push(0xA0 | 0x0E);
        bytes.extend(std::iter::repeat_n(level as u8 + 1, 14));
    }
    offsets.push(bytes.len() as u8);
    bytes.extend([0x10, 0x00]);
    let table = bytes.len() as u64;
    bytes.extend(&offsets);
    bytes.extend([0u8; 6]);
    bytes.extend([1, 1]);
    bytes.extend((offsets.len() as u64).to_be_bytes());
    bytes.extend(0u64.to_be_bytes());
    bytes.extend(table.to_be_bytes());

    let start = std::time::Instant::now();
    let err = extract_plist(&bytes, &mut Values::new()).unwrap_err();
    assert!(err.to_string().contains("expand past"), "{err}");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn plist_structure_errors_are_malformed() {
    for bad in [
        // A dictionary key that is not a string.
        "<plist><dict><integer>1</integer><string>v</string></dict></plist>",
        // Unterminated.
        "<plist><array><string>v</string></plist>",
    ] {
        let err = extract_plist(bad.as_bytes(), &mut Values::new()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Malformed {
                    format: "plist",
                    ..
                }
            ),
            "{bad}"
        );
    }
}

#[test]
fn yaml_scanner_errors_keep_their_source() {
    use std::error::Error as _;
    let err = extract_yaml(b"a: [1, 2\n", &mut Values::new()).unwrap_err();
    assert!(err.source().is_some(), "{err}");
    let err = extract_yaml(b"a: 1\n---\nb: 2\n", &mut Values::new()).unwrap_err();
    assert!(matches!(err, Error::Malformed { format: "yaml", .. }));
}

#[test]
fn binary_plist_truncated_is_an_error() {
    let mut dict = plist::Dictionary::new();
    dict.insert("k".into(), "v".into());
    let mut binary = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_binary(&mut binary)
        .unwrap();
    let mut values = Values::new();
    assert!(extract_plist(&binary[..binary.len() / 2], &mut values).is_err());
    assert!(extract_plist(b"bplist00", &mut values).is_err());
}

#[test]
fn pkginfo_simple() {
    let mut v = Values::new();
    let input = b"Metadata-Version: 2.1\nName: foo\nVersion: 1.2.3\n";
    extract_pkginfo(input, &mut v).unwrap();
    assert_eq!(
        v.get("metadata-version").and_then(|x| x.as_str()),
        Some("2.1")
    );
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("foo"));
}

#[test]
fn pkginfo_keys_are_lowercase() {
    let mut v = Values::new();
    let input = b"Summary: Dependency confusion PoC\nAuthor-email: a@example.com\n";
    extract_pkginfo(input, &mut v).unwrap();
    assert_eq!(
        v.get("summary").and_then(|x| x.as_str()),
        Some("Dependency confusion PoC")
    );
    assert_eq!(
        v.get("author-email").and_then(|x| x.as_str()),
        Some("a@example.com")
    );
}

#[test]
fn pkginfo_multi_value_becomes_array() {
    let mut v = Values::new();
    let input = b"Classifier: A\nClassifier: B\nClassifier: C\n";
    extract_pkginfo(input, &mut v).unwrap();
    let arr = v.get("classifier").and_then(|x| x.as_array()).unwrap();
    assert_eq!(arr.len(), 3);
}

#[test]
fn base64_encodes_known_vectors() {
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn generic_json_strict_path_leaves_no_lenient_marker() {
    let json = br#"{"version":"2.0.0","tasks":[{"command":"node ./x.js"}]}"#;
    let mut v = Values::new();
    let mut m = Metrics::new();
    extract_generic_json(json, &mut v, &mut m).unwrap();
    assert_eq!(
        v.get("tasks[0].command").and_then(|x| x.as_str()),
        Some("node ./x.js")
    );
    assert!(m.get("json.parse_lenient").is_none());
}

#[test]
fn generic_json_trailing_comma_still_yields_the_task_tree() {
    // The PolinRider tasks.json shape: a trailing comma after the last
    // task object. VS Code runs it; strict JSON rejects it, and before
    // the fallback no `tasks[*].command` value existed to match.
    let json = br#"{
          "version": "2.0.0",
          "tasks": [
            {
              "label": "eslint-check",
              "type": "shell",
              "command": "node ./public/fonts/fa-solid-300.llf",
              "hide": true,
              "runOptions": { "runOn": "folderOpen" }
            },
          ]
        }"#;
    let mut v = Values::new();
    let mut m = Metrics::new();
    extract_generic_json(json, &mut v, &mut m).unwrap();
    assert_eq!(
        v.get("tasks[0].command").and_then(|x| x.as_str()),
        Some("node ./public/fonts/fa-solid-300.llf")
    );
    assert_eq!(
        v.get("tasks[0].runOptions.runOn").and_then(|x| x.as_str()),
        Some("folderOpen")
    );
    assert_eq!(m.get("json.parse_lenient"), Some(1.0));
}

#[test]
fn generic_json_line_and_block_comments_are_trivia() {
    // A settings.json as VS Code users actually write it. A `//` inside a
    // string value must survive as content, not open a comment.
    let json = br#"{
          // Automatically saves files after a delay
          "files.autoSave": "off",
          /* hide the terminal */ "terminal.integrated.hideOnStartup": "always",
          "url": "https://example.com/a", // trailing comment
        }"#;
    let mut v = Values::new();
    let mut m = Metrics::new();
    extract_generic_json(json, &mut v, &mut m).unwrap();
    // Dotted setting names are literal keys, so read the tree directly
    // rather than through the path-splitting `get`.
    let root = v.as_json();
    assert_eq!(root["files.autoSave"].as_str(), Some("off"));
    assert_eq!(
        root["terminal.integrated.hideOnStartup"].as_str(),
        Some("always")
    );
    assert_eq!(root["url"].as_str(), Some("https://example.com/a"));
    assert_eq!(m.get("json.parse_lenient"), Some(1.0));
}

#[test]
fn generic_json_garbage_and_unterminated_comment_fail_cleanly() {
    let mut v = Values::new();
    let mut m = Metrics::new();
    assert!(extract_generic_json(b"{ this is not json }", &mut v, &mut m).is_err());
    assert!(extract_generic_json(b"{ /* open forever \"a\": 1 }", &mut v, &mut m).is_err());
    // gyp's `#` comments are not JSONC comments.
    assert!(extract_generic_json(b"{ # nope\n \"a\": 1 }", &mut v, &mut m).is_err());
    assert!(v.get("a").is_none());
}

#[test]
fn gyp_plain_json_uses_the_strict_path() {
    // A conventional binding.gyp is valid JSON; it must parse without the
    // lenient fallback and land its value paths.
    let gyp = br#"{"targets":[{"target_name":"addon","sources":["addon.c"]}]}"#;
    let mut v = Values::new();
    let mut m = Metrics::new();
    extract_gyp(gyp, &mut v, &mut m).unwrap();
    assert_eq!(
        v.get("targets[0].target_name").and_then(|x| x.as_str()),
        Some("addon")
    );
    assert!(m.get("gyp.parse_lenient").is_none());
}

#[test]
fn gyp_lenient_decodes_byte_escaped_target_and_sources() {
    // The openapi-react-query-codegen wave's binding.gyp shape: trailing
    // commas, a `<(var)` target name, and a `\x`-escaped `type` that reads
    // as "none" only after decoding. Strict JSON rejects all of it.
    let gyp = br#"{
            "variables": { "var": "Frot", },
            "targets": [ {
                "target_name": "<(var)",
                "type":"\x6e\x6f\x6e\x65",
                "sources": ["dog.c"],
            } ],
        }"#;
    let mut v = Values::new();
    let mut m = Metrics::new();
    extract_gyp(gyp, &mut v, &mut m).unwrap();
    assert_eq!(
        v.get("variables.var").and_then(|x| x.as_str()),
        Some("Frot")
    );
    assert_eq!(
        v.get("targets[0].target_name").and_then(|x| x.as_str()),
        Some("<(var)")
    );
    // The concealment is undone: type is the plaintext keyword.
    assert_eq!(
        v.get("targets[0].type").and_then(|x| x.as_str()),
        Some("none")
    );
    assert_eq!(
        v.get("targets[0].sources[0]").and_then(|x| x.as_str()),
        Some("dog.c")
    );
    assert_eq!(m.get("gyp.parse_lenient"), Some(1.0));
}

#[test]
fn gyp_unicode_escape_recovers_the_command_string() {
    // \U00.. escapes reassemble a command hidden from a plaintext scan.
    let gyp = br#"{"targets":[{"conditions":[["\U0000006e\U0000006f\U00000064\U00000065", {}]]}]}"#;
    let mut v = Values::new();
    let mut m = Metrics::new();
    extract_gyp(gyp, &mut v, &mut m).unwrap();
    // conditions is an array of `[expr, {}]` pairs — nested arrays, which
    // the dotted `get` path can't index in one segment, so assert on the
    // JSON tree directly.
    assert_eq!(
        v.as_json()
            .pointer("/targets/0/conditions/0/0")
            .and_then(|x| x.as_str()),
        Some("node")
    );
}

#[test]
fn gyp_garbage_fails_cleanly() {
    // Neither JSON nor gyp: no tree, so the caller falls through to a scan.
    let mut v = Values::new();
    let mut m = Metrics::new();
    assert!(extract_gyp(b"\x00\x01 not a manifest", &mut v, &mut m).is_err());
}

/// The parser error behind a `Malformed` is its `source()`, not repeated in
/// its `Display`; the rendered chain, which lands in the errors view, keeps
/// the exact wording.
#[test]
fn malformed_errors_keep_their_text_and_expose_the_parser_error() {
    use std::error::Error as _;
    let mut v = Values::new();

    let err = extract_toml(b"name = \"x\"\nversion = \n", &mut v).unwrap_err();
    assert_eq!(err.to_string(), "malformed toml");
    assert_eq!(
        crate::error::display_chain(&err),
        "malformed toml: TOML parse error at line 2, column 11\n  |\n2 | version = \n  |           ^\ninvalid string\nexpected `\"`, `'`\n"
    );
    let source = err.source().expect("toml source");
    assert!(source.downcast_ref::<toml::de::Error>().is_some());

    let err = extract_toml(b"\xff\xfe = 1\n", &mut v).unwrap_err();
    assert_eq!(err.to_string(), "malformed toml: input is not utf-8");
    assert_eq!(
        crate::error::display_chain(&err),
        "malformed toml: input is not utf-8: invalid utf-8 sequence of 1 bytes from index 0"
    );
    let source = err.source().expect("utf-8 source");
    assert!(source.downcast_ref::<std::str::Utf8Error>().is_some());

    let err = extract_json(br#"{"a":"#, &mut v).unwrap_err();
    assert_eq!(err.to_string(), "malformed json");
    assert_eq!(
        crate::error::display_chain(&err),
        "malformed json: EOF while parsing a value at line 1 column 5"
    );
    let source = err.source().expect("json source");
    assert!(source.downcast_ref::<serde_json::Error>().is_some());

    // Structural checks of our own carry no cause.
    let mut m = Metrics::new();
    let err = extract_gyp(b"\x00\x01 not a manifest", &mut v, &mut m).unwrap_err();
    assert_eq!(
        err.to_string(),
        "malformed gyp: not valid JSON or gyp Python-literal syntax"
    );
    assert!(err.source().is_none());
}

#[test]
fn native_entitlement_requests_require_top_level_boolean_true() {
    for value in [
        plist::Value::Boolean(true),
        plist::Value::Boolean(false),
        plist::Value::String("true".into()),
        plist::Value::Integer(1.into()),
    ] {
        let expected = if value == plist::Value::Boolean(true) {
            1.0
        } else {
            0.0
        };
        let mut dict = plist::Dictionary::new();
        dict.insert("com.apple.security.cs.allow-jit".into(), value.clone());
        dict.insert(
            "com.apple.security.cs.allow-unsigned-executable-memory".into(),
            value,
        );
        let root = plist::Value::Dictionary(dict);
        for binary in [false, true] {
            let mut bytes = Vec::new();
            if binary {
                root.to_writer_binary(&mut bytes).unwrap();
            } else {
                root.to_writer_xml(&mut bytes).unwrap();
            }
            let mut values = Values::new();
            extract_plist(&bytes, &mut values).unwrap();
            let mut metrics = Metrics::new();
            plist_entitlement_metrics(&values, &mut metrics);
            assert_eq!(
                metrics.get("plist.jit_entitlement_requested"),
                Some(expected)
            );
            assert_eq!(
                metrics.get("plist.unsigned_executable_memory_entitlement_requested"),
                Some(expected)
            );
        }
    }
    let mut values = Values::new();
    extract_plist(br#"<?xml version="1.0"?><plist><dict><key>nested</key><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></dict></plist>"#, &mut values).unwrap();
    let mut metrics = Metrics::new();
    plist_entitlement_metrics(&values, &mut metrics);
    assert_eq!(metrics.get("plist.jit_entitlement_requested"), Some(0.0));
}
