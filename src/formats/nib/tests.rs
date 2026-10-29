use super::*;

const NIBARCHIVE: &[u8] = include_bytes!("../../../tests/fixtures/dropper.nib");
const KEYED: &[u8] = include_bytes!("../../../tests/fixtures/dropper-keyed.nib");

fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
    let mut values = Values::new();
    let mut strings = Strings::default();
    let mut metrics = Metrics::default();
    extract(bytes, &mut values, &mut strings, &mut metrics).unwrap();
    (values, strings, metrics)
}

fn list(values: &Values, path: &str) -> Vec<String> {
    values
        .get(path)
        .and_then(JsonValue::as_array)
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Both compiled forms of the same `Dropper.xib` expose the same graph.
fn assert_dropper_facts(values: &Values, strings: &Strings) {
    // The File's Owner is the custom class, in plain and Swift-mangled
    // form; the placeholders keep their framework names.
    assert_eq!(
        list(values, "nib.class_names"),
        [
            "DropperController",
            "NSApplication",
            "NSObject",
            "_TtC7Dropper17DropperController"
        ]
    );
    assert_eq!(list(values, "nib.modules"), ["Dropper"]);
    assert_eq!(list(values, "nib.actions"), ["runPayload:"]);
    assert_eq!(list(values, "nib.outlets"), ["window"]);
    let classes = list(values, "nib.classes");
    for class in [
        "NSButtonCell",
        "NSCustomObject",
        "NSWindowTemplate",
        "IBClassReference",
    ] {
        assert!(classes.contains(&class.to_string()), "missing {class}");
    }
    let literals: Vec<&str> = strings.literals.iter().map(|s| s.value.as_str()).collect();
    for text in [
        "Run Payload",
        "Installer",
        "DropperController",
        "runPayload:",
    ] {
        assert!(
            literals.contains(&text),
            "missing literal {text}: {literals:?}"
        );
    }
    assert!(
        strings.literals.iter().all(|s| s.offset > 0),
        "every literal is located in the file"
    );
}

#[test]
fn nibarchive_fixture() {
    let (values, strings, metrics) = run(NIBARCHIVE);
    assert_eq!(values.get("nib.format").unwrap(), "nibarchive");
    assert_eq!(values.get("nib.format_version").unwrap(), 10);
    assert_dropper_facts(&values, &strings);
    assert!(metrics.get("nib.object_count").unwrap() > 10.0);
    assert_eq!(metrics.get("nib.class_name_count").unwrap(), 4.0);
    assert_eq!(metrics.get("nib.connection_count").unwrap(), 2.0);
    // The literal offsets point at the string bytes themselves.
    let run_payload = strings
        .literals
        .iter()
        .find(|s| s.value == "Run Payload")
        .unwrap();
    assert_eq!(
        &NIBARCHIVE[run_payload.offset as usize..run_payload.offset as usize + 11],
        b"Run Payload"
    );
}

#[test]
fn keyed_archive_fixture() {
    let (values, strings, metrics) = run(KEYED);
    assert_eq!(values.get("nib.format").unwrap(), "keyed_archive");
    assert_eq!(values.get("nib.archiver").unwrap(), "NSKeyedArchiver");
    assert_dropper_facts(&values, &strings);
    assert_eq!(metrics.get("nib.connection_count").unwrap(), 2.0);
    // Archiver bookkeeping is not a string the nib carries.
    assert!(strings.literals.iter().all(|s| s.value != "NSCustomObject"));
    // Each literal's offset lands on its own bytes, so the short module
    // name is not confused with the front of the longer class name.
    for literal in &strings.literals {
        let start = literal.offset as usize;
        let end = start + literal.value.len();
        assert_eq!(
            &KEYED[start..end],
            literal.value.as_bytes(),
            "offset of {:?}",
            literal.value
        );
    }
}

#[test]
fn locate_matches_whole_binary_plist_strings() {
    let mut dict = plist::Dictionary::new();
    dict.insert("a".into(), "Dropper".into());
    dict.insert("b".into(), "DropperController".into());
    dict.insert("c".into(), "façade".into());
    let mut bytes = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_binary(&mut bytes)
        .unwrap();
    let at = locate(&bytes, "Dropper");
    assert_eq!(&bytes[at..at + 7], b"Dropper");
    assert_ne!(
        bytes[at + 7],
        b'C',
        "matched the short string, not the prefix"
    );
    let at = locate(&bytes, "façade");
    assert_eq!(bytes[at], 0x00, "UTF-16BE body starts with a high byte");
    assert_eq!(bytes[at + 1], b'f');
    assert_eq!(locate(&bytes, "absent"), 0);
}

#[test]
fn varint_spans_bytes() {
    // 300 = 0b10_0101100: low seven bits first, high bit marks the end.
    let mut cursor = Reader::new(&[0x2c, 0x82, 0x81]);
    assert_eq!(cursor.varint(), Some(300));
    assert_eq!(cursor.varint(), Some(1));
    assert_eq!(cursor.varint(), None);
}

#[test]
fn oversized_table_is_rejected_before_allocation() {
    let mut data = NIBARCHIVE[..HEADER_LEN].to_vec();
    // Object count field: claim more objects than there are bytes.
    data[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
    let err = Archive::parse(&data).unwrap_err();
    assert!(err.to_string().contains("object table"), "{err}");
}

/// A NIBArchive of `objects` (class, first value, value count), each
/// value an int8 under key 0 (`NS.bytes`), and one class name.
fn archive(objects: &[[u8; 3]], values: usize) -> Vec<u8> {
    let objects_at = HEADER_LEN;
    let keys_at = objects_at + 3 * objects.len();
    let values_at = keys_at + 9;
    let classes_at = values_at + 3 * values;
    let mut data = MAGIC.to_vec();
    for word in [
        1,
        10,
        objects.len(),
        objects_at,
        1,
        keys_at,
        values,
        values_at,
        1,
        classes_at,
    ] {
        data.extend((word as u32).to_le_bytes());
    }
    for object in objects {
        data.extend(object.map(|n| n | 0x80));
    }
    data.extend(b"\x88NS.bytes");
    for _ in 0..values {
        data.extend([0x80, 0, 7]);
    }
    data.extend(b"\x89\x80NSString\0");
    data
}

/// Objects own disjoint runs of the value table; a crafted archive in
/// which every object claims the whole table would make each lookup
/// scan it, and is refused.
#[test]
fn objects_sharing_values_are_refused() {
    assert!(Archive::parse(&archive(&[[0, 0, 1], [0, 1, 1]], 2)).is_ok());
    let err = Archive::parse(&archive(&[[0, 0, 2], [0, 1, 1]], 2)).unwrap_err();
    assert!(err.to_string().contains("share value table"), "{err}");
}

/// Locating keyed-archive strings shares one scan budget, so a file
/// packed with distinct strings cannot make each one search the whole
/// file; once it is spent, literals report offset zero.
#[test]
fn string_search_is_budgeted() {
    let mut bytes = vec![0u8; 100];
    bytes.extend(b"\x57Dropper");
    let mut search = Search {
        bytes: &bytes,
        budget: 1 << 10,
    };
    assert_eq!(search.locate("Dropper"), 101);
    assert_eq!(search.budget, (1 << 10) - 101);
    let mut spent = Search {
        bytes: &bytes,
        budget: 100,
    };
    assert_eq!(spent.locate("Dropper"), 0);
    assert_eq!(spent.budget, 0);
}

#[test]
fn truncated_archive_is_an_error() {
    assert!(Archive::parse(&NIBARCHIVE[..HEADER_LEN + 20]).is_err());
    assert!(Archive::parse(b"NIBArchive").is_err());
}

#[test]
fn other_bytes_are_rejected() {
    let mut values = Values::new();
    let mut strings = Strings::default();
    let mut metrics = Metrics::default();
    assert!(
        extract(
            b"<?xml version=\"1.0\"?>",
            &mut values,
            &mut strings,
            &mut metrics
        )
        .is_err()
    );
}

/// A keyed-archive nib nested past the plist depth cap is a malformed
/// error, not a stack overflow on a worker-sized stack.
#[test]
fn deep_keyed_archive_is_refused() {
    let result = crate::formats::plist_guard::on_small_stack(|| {
        let deep = crate::formats::plist_guard::nested_xml(20_000);
        collect_keyed(&deep, &mut Facts::default(), &mut Strings::default())
            .map_err(|e| e.to_string())
    });
    assert!(result.unwrap_err().contains("deeper than"));
}
