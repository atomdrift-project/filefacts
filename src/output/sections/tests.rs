use super::*;

fn pe_text(vaddr: u64) -> Section {
    Section {
        name: ".text".into(),
        vaddr,
        vsize: 0x1000,
        file_offset: 0x400,
        file_size: 0x1000,
        flags: vec![
            SectionFlag::Code,
            SectionFlag::Executable,
            SectionFlag::Readable,
        ],
        flags_raw: Some(0x6000_0020),
        entropy: Some(6.10),
    }
}

#[test]
fn empty_sections_default_is_zero_length() {
    let s = Sections::new();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
    assert!(s.as_slice().is_empty());
    assert_eq!(s.iter().count(), 0);
}

/// `FromIterator` preserves the iterator order — the format
/// extractors emit sections in load-table order, and aggregate
/// metrics (size-weighted code/data entropy) depend on that order
/// matching the layout.
#[test]
fn from_iter_preserves_insertion_order() {
    let mut a = pe_text(0x1000);
    a.name = ".text".into();
    let mut b = pe_text(0x2000);
    b.name = ".data".into();
    let mut c = pe_text(0x3000);
    c.name = ".rsrc".into();
    let sections = Sections::from_iter([a, b, c]);
    let names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec![".text", ".data", ".rsrc"]);
}

/// Both `iter()` and `IntoIterator for &Sections` must walk the
/// same elements in the same order. Several call sites in the
/// PE/ELF/Mach-O analyzers use `&sections` inside `for` loops
/// (which expands to the `IntoIterator` impl).
#[test]
fn iter_and_into_iter_agree() {
    let sections = Sections::from_iter([pe_text(0x1000), pe_text(0x2000)]);
    let via_iter: Vec<u64> = sections.iter().map(|s| s.vaddr).collect();
    let via_into: Vec<u64> = (&sections).into_iter().map(|s| s.vaddr).collect();
    assert_eq!(via_iter, via_into);
}

/// Section flags survive a JSON round-trip — they're the
/// load-bearing field for trait composites that match
/// `flags[*] contains "executable"`. Order should match insertion
/// so traits authoring against `flags[0]` get a stable position.
#[test]
fn json_round_trip_preserves_section_fields() {
    let sections = Sections::from_iter([pe_text(0x1000)]);
    let json = serde_json::to_value(&sections).unwrap();
    let arr = json
        .as_array()
        .expect("Sections is `#[serde(transparent)]` Vec");
    assert_eq!(arr.len(), 1);
    let s = &arr[0];
    assert_eq!(s["name"], ".text");
    assert_eq!(s["vaddr"], 0x1000);
    assert_eq!(s["vsize"], 0x1000);
    assert_eq!(s["file_offset"], 0x400);
    assert_eq!(s["file_size"], 0x1000);
    let flags: Vec<&str> = s["flags"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(flags, vec!["code", "executable", "readable"]);
    assert_eq!(s["flags_raw"], 0x6000_0020_u64);
    assert!((s["entropy"].as_f64().unwrap() - 6.10).abs() < 1e-9);
    let back: Sections = serde_json::from_value(json).unwrap();
    assert_eq!(back.as_slice()[0].flags, sections.as_slice()[0].flags);
}

/// Every flag serializes as its `as_str` name, and the per-format
/// spellings are not part of the vocabulary.
#[test]
fn flag_names_are_the_shared_vocabulary() {
    for flag in [
        SectionFlag::Readable,
        SectionFlag::Writable,
        SectionFlag::Executable,
        SectionFlag::Code,
        SectionFlag::Data,
        SectionFlag::InitializedData,
        SectionFlag::UninitializedData,
        SectionFlag::Alloc,
        SectionFlag::Merge,
        SectionFlag::Strings,
        SectionFlag::InfoLink,
        SectionFlag::Tls,
    ] {
        assert_eq!(
            serde_json::to_value(flag).unwrap(),
            serde_json::Value::from(flag.as_str())
        );
    }
    for spelling in [r#""write""#, r#""execinstr""#, r#""read""#] {
        assert!(
            serde_json::from_str::<SectionFlag>(spelling).is_err(),
            "{spelling}"
        );
    }
}

#[test]
fn code_excludes_data_in_an_executable_segment() {
    let mut s = pe_text(0x1000);
    assert!(s.is_executable() && s.is_code() && !s.is_writable());
    s.flags = vec![SectionFlag::Executable, SectionFlag::Data];
    assert!(s.is_executable() && !s.is_code());
}

/// `#[serde(transparent)]` means the wrapper struct doesn't add
/// nesting — `Sections([...])` serializes as the bare array
/// `[{...}]`. This is what kv-path consumers expect when they
/// navigate `sections[0].name`.
#[test]
fn sections_serializes_as_bare_array_not_wrapped_object() {
    let sections = Sections::from_iter([pe_text(0x1000)]);
    let json = serde_json::to_value(&sections).unwrap();
    assert!(
        json.is_array(),
        "Sections must serialize as an array, got {json}",
    );
}
