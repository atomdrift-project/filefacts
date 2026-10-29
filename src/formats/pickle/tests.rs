use super::*;

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    extract(bytes, &mut v, &mut s, &mut m);
    (v, m)
}

#[test]
fn oversized_binbytes8_length_ends_the_scan() {
    // PROTO 4, then BINBYTES8 whose length makes `1 + 8 + len` wrap to 0.
    let data = [
        0x80, 4, 0x8D, 0xF7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    let (_, m) = run(&data);
    assert_eq!(m.get("pickle.protocol"), Some(4.0));
}

#[test]
fn surfaces_protocol_and_global() {
    let mut data = vec![0x80, 4, b'c'];
    data.extend_from_slice(b"os\nsystem\n");
    data.extend_from_slice(&[b'R', b'.']);
    let (v, m) = run(&data);
    assert_eq!(m.get("pickle.protocol"), Some(4.0));
    let mods = v.get("pickle.modules").and_then(|x| x.as_array()).unwrap();
    assert_eq!(mods[0].as_str(), Some("os"));
    let globals = v.get("pickle.globals").and_then(|x| x.as_array()).unwrap();
    assert!(
        globals.iter().any(|g| g.as_str() == Some("os.system")),
        "GLOBAL should resolve the module.attr callable: {globals:?}"
    );
    let danger = v
        .get("pickle.dangerous_opcodes")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = danger.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"reduce"));
    assert!(names.contains(&"global"));
}

#[test]
fn surfaces_stack_global() {
    let mut data = vec![0x80, 5, 0x95, 0, 0, 0, 0, 0, 0, 0, 0];
    data.push(0x8C);
    data.push(10);
    data.extend_from_slice(b"subprocess");
    data.push(0x94);
    data.push(0x8C);
    data.push(5);
    data.extend_from_slice(b"Popen");
    data.push(0x94);
    data.push(0x93);
    data.push(b'.');
    let (v, _) = run(&data);
    let mods = v.get("pickle.modules").and_then(|x| x.as_array()).unwrap();
    assert!(mods.iter().any(|v| v.as_str() == Some("subprocess")));
    let globals = v.get("pickle.globals").and_then(|x| x.as_array()).unwrap();
    assert!(
        globals
            .iter()
            .any(|g| g.as_str() == Some("subprocess.Popen")),
        "STACK_GLOBAL should resolve module.attr: {globals:?}"
    );
}

#[test]
fn stack_global_uses_pickle_stack_and_memo_not_recent_strings() {
    let mut data = vec![0x80, 4];
    let short_unicode = |data: &mut Vec<u8>, value: &[u8]| {
        data.extend_from_slice(&[0x8C, value.len() as u8]);
        data.extend_from_slice(value);
    };

    // Memo 0 holds the module. Resolve one class, then discard it.
    short_unicode(&mut data, b"docutils.nodes");
    data.push(0x94);
    short_unicode(&mut data, b"section");
    data.extend_from_slice(&[0x94, 0x93, b'0']);

    // Identifier-shaped document strings a rolling string window would
    // pair into `section.title`.
    short_unicode(&mut data, b"arbitrary.document.text");
    data.push(b'0');

    // Reload the real module through a LONG_BINGET and resolve the second
    // class. The opcode walker must consume all four index bytes.
    data.extend_from_slice(&[b'j', 0, 0, 0, 0]);
    short_unicode(&mut data, b"title");
    data.extend_from_slice(&[0x93, b'.']);

    let (values, metrics) = run(&data);
    assert_eq!(metrics.get("pickle.protocol"), Some(4.0));
    assert_eq!(
        values.get("pickle.modules"),
        Some(&serde_json::json!(["docutils.nodes"]))
    );
    assert_eq!(
        values.get("pickle.globals"),
        Some(&serde_json::json!([
            "docutils.nodes.section",
            "docutils.nodes.title"
        ]))
    );
}

#[test]
fn torch_legacy_storage_is_not_an_opcode_stream() {
    let bytes = include_bytes!("../../testdata/pickle/torch-protocol2-float-tensor.pt");
    let (values, metrics) = run(bytes);
    assert_eq!(metrics.get("pickle.protocol"), Some(2.0));
    assert_eq!(
        values.get("pickle.globals"),
        Some(&serde_json::json!([
            "collections.OrderedDict",
            "torch.FloatStorage",
            "torch._utils._rebuild_tensor_v2"
        ]))
    );
    let ops = values.get("pickle.opcodes").unwrap().as_array().unwrap();
    assert!(!ops.contains(&serde_json::json!("POP")));
    let mut extended = bytes.to_vec();
    extended.extend_from_slice(b"\x80\x29cos\nsystem\nR.");
    assert_eq!(
        serde_json::to_value(run(&extended).0).unwrap(),
        serde_json::to_value(values).unwrap()
    );
}

#[test]
fn raw_bytes_operands_and_trailing_bytes_do_not_declare_globals() {
    let payload = b"\x80\x29cos\nsystem\nR";
    for op in [b'B', b'C', 0x8e] {
        let mut bytes = vec![0x80, 4, op];
        match op {
            b'B' => bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes()),
            b'C' => bytes.push(payload.len() as u8),
            _ => bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes()),
        }
        bytes.extend_from_slice(payload);
        bytes.push(b'.');
        bytes.extend_from_slice(b"cos\nsystem\nR");
        let (values, metrics) = run(&bytes);
        assert_eq!(metrics.get("pickle.protocol"), Some(4.0));
        assert!(values.get("pickle.globals").is_none());
        assert!(values.get("pickle.dangerous_opcodes").is_none());
    }
}

#[test]
fn invalid_proto_and_corrupt_legacy_headers_do_not_scan_storage() {
    let (values, metrics) = run(b"\x80\x29cos\nsystem\nR.");
    assert!(values.get("pickle.globals").is_none());
    assert!(metrics.get("pickle.protocol").is_none());
    let mut bytes =
        include_bytes!("../../testdata/pickle/torch-protocol2-float-tensor.pt").to_vec();
    bytes[4] ^= 1;
    assert!(run(&bytes).0.get("pickle.globals").is_none());
    let mut short = vec![0x80, 4, b'B'];
    short.extend_from_slice(&u32::MAX.to_le_bytes());
    short.extend_from_slice(b"cos\nsystem\nR.");
    assert!(run(&short).0.get("pickle.globals").is_none());
}

/// STACK_GLOBALs whose operands are reloaded from the memo name the same
/// strings; each must not copy and compare a multi-megabyte module name
/// again, or a few megabytes of input take hours to scan.
#[test]
fn repeated_stack_global_is_linear() {
    let module = "m".repeat(1 << 20);
    let mut data = vec![0x80, 4, b'X'];
    data.extend_from_slice(&(module.len() as u32).to_le_bytes());
    data.extend_from_slice(module.as_bytes());
    data.extend_from_slice(&[b'q', 0, 0x8C, 1, b'f', b'q', 1, 0x93]);
    // Unfixed, these 64 Ki operations copy about 200 GB.
    for _ in 0..64 << 10 {
        data.extend_from_slice(&[b'h', 0, b'h', 1, 0x93]);
    }
    data.push(b'.');
    let (v, _) = run(&data);
    let globals = v.get("pickle.globals").and_then(|x| x.as_array()).unwrap();
    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].as_str(), Some(format!("{module}.f").as_str()));
}

/// Memo GETs can pair every one of a few large strings with every other;
/// the recorded names must stay bounded by the scan size, not grow with
/// the square of the string count.
#[test]
fn memo_paired_stack_globals_are_bounded() {
    const STRINGS: u8 = 64;
    let mut data = vec![0x80, 4];
    for k in 0..STRINGS {
        let name = format!("m{k}{}", "a".repeat(64 << 10));
        data.push(b'X');
        data.extend_from_slice(&(name.len() as u32).to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&[b'q', k, b'0']);
    }
    // Unbounded, these 4 Ki pairs record about 512 MB of names.
    for module in 0..STRINGS {
        for attr in 0..STRINGS {
            data.extend_from_slice(&[b'h', module, b'h', attr, 0x93, b'0']);
        }
    }
    data.push(b'.');
    let (v, _) = run(&data);
    let globals = v.get("pickle.globals").and_then(|x| x.as_array()).unwrap();
    let bytes: usize = globals
        .iter()
        .filter_map(|g| g.as_str())
        .map(str::len)
        .sum();
    assert!(!globals.is_empty());
    assert!(bytes <= MAX_BYTES_SCANNED, "{bytes} bytes of globals");
}

#[test]
fn empty_is_silent() {
    let (v, _) = run(&[]);
    assert!(v.get("pickle.protocol").is_none());
}

#[test]
fn truncated_length_prefix_doesnt_crash() {
    // SHORT_BINUNICODE with length=10 but only 3 bytes follow.
    let data = vec![0x80, 5, 0x8C, 10, b'a', b'b', b'c'];
    let (_, _) = run(&data);
    // Just confirm no panic.
}

#[test]
fn dangerous_opcodes_recognized() {
    // Protocol 0 GLOBAL+REDUCE — classic RCE pattern.
    let mut data = vec![b'c'];
    data.extend_from_slice(b"subprocess\nPopen\n");
    data.push(b'R');
    data.push(b'.');
    let (v, _) = run(&data);
    let danger = v
        .get("pickle.dangerous_opcodes")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = danger.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"global"));
    assert!(names.contains(&"reduce"));
}

#[test]
fn non_pickle_input_is_silent() {
    // Random binary that doesn't match any opcode pattern.
    let (v, _) = run(b"this is some random text that won't match much");
    // It might match a few stray opcodes (chars like '.', 'c'),
    // but should not report a protocol or modules.
    assert!(v.get("pickle.modules").is_none() || v.get("pickle.protocol").is_none());
}

#[test]
fn protocol_5_recognized() {
    // PROTO 5 + STOP.
    let data = vec![0x80, 5, b'.'];
    let (_, m) = run(&data);
    assert_eq!(m.get("pickle.protocol"), Some(5.0));
}
