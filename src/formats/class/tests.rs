use super::*;

/// Build a minimal class file with a fixed constant pool layout:
///   1 = Utf8("MyClass")
///   2 = Utf8("java/lang/Object")
///   3 = Utf8("SourceFile")
///   4 = Utf8("MyClass.java")
///   5 = Class(1)
///   6 = Class(2)
fn build_class(major: u16, with_source: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&major.to_be_bytes());
    out.extend_from_slice(&7u16.to_be_bytes()); // cp_count
    // 1 Utf8 "MyClass"
    out.push(CP_UTF8);
    out.extend_from_slice(&7u16.to_be_bytes());
    out.extend_from_slice(b"MyClass");
    // 2 Utf8 "java/lang/Object"
    out.push(CP_UTF8);
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(b"java/lang/Object");
    // 3 Utf8 "SourceFile"
    out.push(CP_UTF8);
    out.extend_from_slice(&10u16.to_be_bytes());
    out.extend_from_slice(b"SourceFile");
    // 4 Utf8 "MyClass.java"
    out.push(CP_UTF8);
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(b"MyClass.java");
    // 5 Class -> 1
    out.push(CP_CLASS);
    out.extend_from_slice(&1u16.to_be_bytes());
    // 6 Class -> 2
    out.push(CP_CLASS);
    out.extend_from_slice(&2u16.to_be_bytes());

    // PUBLIC=0x0001 | SUPER=0x0020
    out.extend_from_slice(&0x0021u16.to_be_bytes());
    out.extend_from_slice(&5u16.to_be_bytes()); // this_class
    out.extend_from_slice(&6u16.to_be_bytes()); // super_class
    out.extend_from_slice(&0u16.to_be_bytes()); // interfaces_count
    out.extend_from_slice(&0u16.to_be_bytes()); // fields_count
    out.extend_from_slice(&0u16.to_be_bytes()); // methods_count

    if with_source {
        out.extend_from_slice(&1u16.to_be_bytes()); // attributes_count
        out.extend_from_slice(&3u16.to_be_bytes()); // name_index = SourceFile
        out.extend_from_slice(&2u32.to_be_bytes()); // length
        out.extend_from_slice(&4u16.to_be_bytes()); // sourcefile_index
    } else {
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    out
}

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    let mut symbols = crate::Symbols::new();
    extract(bytes, &mut v, &mut s, &mut m, &mut symbols);
    (v, m)
}

fn run_full(bytes: &[u8]) -> (Values, Metrics, crate::Symbols) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    let mut symbols = crate::Symbols::new();
    extract(bytes, &mut v, &mut s, &mut m, &mut symbols);
    (v, m, symbols)
}

#[test]
fn rejects_non_class() {
    let (v, _) = run(b"not a class");
    assert!(v.get("class.major_version").is_none());
}

#[test]
fn emits_constant_pool_class_refs_and_strings() {
    let bytes = build_class(52, true);
    let (v, _) = run(&bytes);
    let refs: Vec<&str> = v
        .get("class.class_refs")
        .and_then(|x| x.as_array())
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str())
        .collect();
    assert_eq!(refs, vec!["MyClass", "java/lang/Object"]);
    let strings: Vec<&str> = v
        .get("class.strings")
        .and_then(|x| x.as_array())
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str())
        .collect();
    // Every CONSTANT_Utf8 entry, sorted + deduped.
    assert_eq!(
        strings,
        vec!["MyClass", "MyClass.java", "SourceFile", "java/lang/Object"]
    );
}

#[test]
fn surfaces_version_and_hierarchy() {
    let bytes = build_class(65, true);
    let (v, m) = run(&bytes);
    assert_eq!(
        v.get("class.major_version").and_then(|x| x.as_u64()),
        Some(65)
    );
    assert_eq!(
        v.get("class.java_version").and_then(|x| x.as_str()),
        Some("21")
    );
    let flags = v
        .get("class.access_flags")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = flags.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"public"));
    assert!(names.contains(&"super"));
    assert_eq!(
        v.get("class.this_class").and_then(|x| x.as_str()),
        Some("MyClass")
    );
    assert_eq!(
        v.get("class.super_class").and_then(|x| x.as_str()),
        Some("java/lang/Object")
    );
    assert_eq!(
        v.get("class.source_file").and_then(|x| x.as_str()),
        Some("MyClass.java")
    );
    assert_eq!(m.get("class.major_version"), Some(65.0));
}

#[test]
fn omits_source_file_when_attribute_absent() {
    let bytes = build_class(52, false);
    let (v, _) = run(&bytes);
    assert_eq!(
        v.get("class.java_version").and_then(|x| x.as_str()),
        Some("8")
    );
    assert!(v.get("class.source_file").is_none());
}

#[test]
fn unknown_major_version_omits_label() {
    // Java 99 — not in our mapping table.
    let bytes = build_class(99, false);
    let (v, m) = run(&bytes);
    assert_eq!(
        v.get("class.major_version").and_then(|x| x.as_u64()),
        Some(99)
    );
    assert!(v.get("class.java_version").is_none());
    assert_eq!(m.get("class.major_version"), Some(99.0));
}

/// `populate_imports` surfaces every external CONSTANT_Class_info
/// entry except the class's own `this_class`. A minimal class
/// with `super_class = java/lang/Object` always has at least one
/// external-class import.
#[test]
fn external_class_refs_emit_typed_imports() {
    let bytes = build_class(52, false);
    let (_, m, symbols) = run_full(&bytes);
    // `java/lang/Object` shows up as a `java-class` import; the
    // class's own `MyClass` self-reference does not.
    let names: Vec<&str> = symbols
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        names.contains(&"java/lang/Object"),
        "expected super-class as java-class import, got {names:?}",
    );
    assert!(
        !names.contains(&"MyClass"),
        "this_class must not leak as import"
    );
    for sym in symbols.iter_kind(crate::SymbolKind::Import) {
        let crate::Symbol::Import { library, .. } = sym else {
            unreachable!();
        };
        assert!(library.is_none(), "java-class imports carry no library");
    }
    assert_eq!(m.get("class.external_class_count"), Some(1.0));
    // No methods were declared by the builder. (Method counts surface as
    // `functions.count`, derived from these symbols by the caller.)
    assert_eq!(symbols.iter_kind(crate::SymbolKind::Function).count(), 0);
}

#[test]
fn class_imports_carry_constant_pool_offset() {
    let bytes = build_class(52, false);
    let (_, _, symbols) = run_full(&bytes);
    let offset = symbols
        .iter_kind(crate::SymbolKind::Import)
        .find_map(|s| match s {
            crate::Symbol::Import { name, offset, .. } if name == "java/lang/Object" => {
                Some(*offset)
            }
            _ => None,
        })
        .expect("java/lang/Object import present");
    // Anchors at the Utf8 string data for the class name in the constant pool.
    let want = bytes
        .windows("java/lang/Object".len())
        .position(|w| w == b"java/lang/Object")
        .map(|p| p as u64);
    assert!(want.is_some(), "fixture should contain the class name");
    assert_eq!(
        offset, want,
        "class import must anchor at its CP Utf8 offset"
    );
}

#[test]
fn truncated_constant_pool_doesnt_crash() {
    // Valid magic + version + cp_count = 7, but no entries.
    // We bail before emitting the typed kv (since CP parsing
    // failed); the test just confirms no panic.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&65u16.to_be_bytes());
    bytes.extend_from_slice(&7u16.to_be_bytes());
    let (v, _) = run(&bytes);
    // CP parsing bailed → no this_class.
    assert!(v.get("class.this_class").is_none());
}

#[test]
fn access_flags_decompose_to_array() {
    // ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT.
    let bytes = build_class_with_flags(52, 0x0001 | 0x0010 | 0x0200 | 0x0400);
    let (v, _) = run(&bytes);
    let flags = v
        .get("class.access_flags")
        .and_then(|x| x.as_array())
        .unwrap();
    let names: Vec<&str> = flags.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"public"));
    assert!(names.contains(&"final"));
    assert!(names.contains(&"interface"));
    assert!(names.contains(&"abstract"));
}

#[test]
fn empty_buffer_is_silent() {
    let (v, m) = run(&[]);
    assert!(v.get("class.major_version").is_none());
    assert_eq!(m.get("class.major_version"), None);
}

#[test]
fn wrong_magic_is_silent() {
    let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 65, 0, 1];
    let (v, _) = run(&bytes);
    assert!(v.get("class.major_version").is_none());
}

/// Build a class file with:
///   - one declared method `compute()V`
///   - one Methodref pointing at `java/lang/System.exit(I)V`
///
/// Layout:
///   1 Utf8 "Demo"
///   2 Utf8 "java/lang/Object"
///   3 Utf8 "java/lang/System"
///   4 Utf8 "exit"
///   5 Utf8 "(I)V"
///   6 Utf8 "compute"
///   7 Utf8 "()V"
///   8 Class -> 1 (Demo)
///   9 Class -> 2 (Object)
///  10 Class -> 3 (System)
///  11 NameAndType -> (4, 5)   exit:(I)V
///  12 Methodref -> (10, 11)   System.exit(I)V
fn build_class_with_methodref_and_method() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&52u16.to_be_bytes()); // major (Java 8)
    out.extend_from_slice(&13u16.to_be_bytes()); // cp_count = 13 (indices 1..=12)

    fn push_utf8(out: &mut Vec<u8>, s: &str) {
        out.push(CP_UTF8);
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    push_utf8(&mut out, "Demo");
    push_utf8(&mut out, "java/lang/Object");
    push_utf8(&mut out, "java/lang/System");
    push_utf8(&mut out, "exit");
    push_utf8(&mut out, "(I)V");
    push_utf8(&mut out, "compute");
    push_utf8(&mut out, "()V");
    // Class entries (idx 8, 9, 10)
    out.push(CP_CLASS);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.push(CP_CLASS);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.push(CP_CLASS);
    out.extend_from_slice(&3u16.to_be_bytes());
    // NameAndType (idx 11)
    out.push(CP_NAME_AND_TYPE);
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&5u16.to_be_bytes());
    // Methodref (idx 12)
    out.push(CP_METHODREF);
    out.extend_from_slice(&10u16.to_be_bytes());
    out.extend_from_slice(&11u16.to_be_bytes());

    out.extend_from_slice(&0x0021u16.to_be_bytes()); // access flags
    out.extend_from_slice(&8u16.to_be_bytes()); // this_class -> Demo
    out.extend_from_slice(&9u16.to_be_bytes()); // super_class -> Object
    out.extend_from_slice(&0u16.to_be_bytes()); // interfaces_count
    out.extend_from_slice(&0u16.to_be_bytes()); // fields_count

    // methods[1]: compute()V — public, no attributes.
    out.extend_from_slice(&1u16.to_be_bytes()); // methods_count
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // ACC_PUBLIC
    out.extend_from_slice(&6u16.to_be_bytes()); // name -> "compute"
    out.extend_from_slice(&7u16.to_be_bytes()); // descriptor -> "()V"
    out.extend_from_slice(&0u16.to_be_bytes()); // attributes_count

    // class-level attributes_count = 0
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[test]
fn imports_come_out_in_constant_pool_order() {
    // The pool was walked through HashMaps, so import order changed from
    // one parse to the next.
    let bytes = build_class_with_methodref_and_method();
    let imports = |symbols: &crate::Symbols| -> Vec<String> {
        symbols
            .iter_kind(crate::SymbolKind::Import)
            .filter_map(|s| s.name().map(str::to_string))
            .collect()
    };
    let first = imports(&run_full(&bytes).2);
    assert!(first.len() > 1, "{first:?}");
    for _ in 0..20 {
        assert_eq!(imports(&run_full(&bytes).2), first);
    }
}

#[test]
fn methodref_resolves_to_java_methodref_import() {
    let bytes = build_class_with_methodref_and_method();
    let (_, m, symbols) = run_full(&bytes);
    // Methodref imports are the ones carrying a resolved library
    // (owning class); plain external-class refs carry none.
    let methodref: Vec<(&str, Option<&str>)> = symbols
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import {
                name,
                library: Some(lib),
                ..
            } => Some((name.as_str(), Some(lib.as_str()))),
            _ => None,
        })
        .collect();
    assert_eq!(methodref.len(), 1);
    assert_eq!(methodref[0].0, "exit");
    assert_eq!(methodref[0].1, Some("java/lang/System"));
    assert_eq!(m.get("class.method_ref_count"), Some(1.0));
    // Three classes referenced: Object, System, Demo (self).
    // populate_imports excludes Demo (this_class), so 2 stay.
    assert_eq!(m.get("class.external_class_count"), Some(2.0));
}

#[test]
fn declared_methods_emit_typed_functions() {
    let bytes = build_class_with_methodref_and_method();
    let (_, m, symbols) = run_full(&bytes);
    let funcs: Vec<&str> = symbols
        .iter_kind(crate::SymbolKind::Function)
        .filter_map(|s| match s {
            crate::Symbol::Function { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0], "compute");
    let compute_offset = symbols
        .iter_kind(crate::SymbolKind::Function)
        .find_map(|s| match s {
            crate::Symbol::Function { name, offset, .. } if name == "compute" => *offset,
            _ => None,
        });
    let want = bytes
        .windows("compute".len())
        .position(|w| w == b"compute")
        .map(|p| p as u64);
    assert_eq!(
        compute_offset, want,
        "method must anchor at its CP Utf8 offset"
    );
    assert_eq!(m.get("class.method_count"), None);
}

fn build_class_with_flags(major: u16, flags: u16) -> Vec<u8> {
    let mut out = build_class(major, false);
    // The access-flags u16 sits right after the constant pool —
    // we know our build_class layout so the index is deterministic:
    // 10-byte header + 1+9+1+18+1+12+1+14+3+3 = …
    // Easier: locate the value by rewriting the access_flags slot
    // (the only u16 after the CP that build_class sets to 0x0021).
    let needle = 0x0021u16.to_be_bytes();
    if let Some(pos) = out.windows(2).position(|w| w == needle) {
        out[pos..pos + 2].copy_from_slice(&flags.to_be_bytes());
    }
    out
}

/// InnerClasses entries repeated within and across attributes list each
/// inner class once, in first-seen order.
#[test]
fn inner_classes_are_deduplicated_across_attributes() {
    let mut cp = ConstantPool::default();
    for (idx, name) in [(1, "InnerClasses"), (2, "Outer$A"), (3, "Outer$B")] {
        cp.utf8.insert(idx, name.to_string());
    }
    cp.class.insert(10, 2);
    cp.class.insert(11, 3);
    let entry = |class: u16| [class.to_be_bytes().as_slice(), &[0; 6]].concat();
    let attribute = |classes: &[u16]| {
        let mut body = (classes.len() as u16).to_be_bytes().to_vec();
        for &class in classes {
            body.extend(entry(class));
        }
        let mut out = 1u16.to_be_bytes().to_vec();
        out.extend((body.len() as u32).to_be_bytes());
        out.extend(body);
        out
    };
    let mut bytes = 3u16.to_be_bytes().to_vec();
    bytes.extend(attribute(&[10, 11, 10]));
    bytes.extend(attribute(&[11, 10]));
    bytes.extend(attribute(&[10]));
    let attrs = parse_attributes(&mut Reader::at(&bytes, 0), &cp);
    assert_eq!(attrs.inner_classes, ["Outer$A", "Outer$B"]);
}
