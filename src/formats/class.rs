//! Java `.class` extractor.
//!
//! Walks the JVM class file header per the JVM Spec §4. Pulls the
//! version, decomposed access flags, constant-pool size, class
//! hierarchy (`this_class`, `super_class`, `interfaces[]`), and
//! the class-level attributes (`SourceFile`, `Signature`,
//! `InnerClasses`). Member tables (fields[], methods[]) are
//! skipped without parsing — class-level kv doesn't need them.
//!
//! Schema:
//!
//! - `class.major_version`, `class.minor_version` — raw JVM
//!   version words.
//! - `class.java_version` — derived release label
//!   (`"1.4"` … `"21"`) for analyst readability.
//! - `class.access_flags[]` — Pike-style array of class-level
//!   `ACC_*` names (`public`, `final`, `super`, `interface`,
//!   `abstract`, `synthetic`, `annotation`, `enum`, `module`).
//! - `class.this_class`, `class.super_class` — fully-qualified
//!   internal names (e.g. `java/lang/Object`).
//! - `class.interfaces[]` — internal names.
//! - `class.source_file`, `class.signature` — `SourceFile` /
//!   `Signature` attribute values.
//! - `class.inner_classes[]` — distinct inner-class internal
//!   names from the `InnerClasses` attribute.
//! - `class.constant_pool_size` — metric also surfaced as
//!   `metrics.class.constant_pool_size`.

use serde_json::Value as JsonValue;
use std::collections::HashMap;

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str, put_u64};
use crate::output::{Metrics, Strings, Values};

const CP_UTF8: u8 = 1;
const CP_INTEGER: u8 = 3;
const CP_FLOAT: u8 = 4;
const CP_LONG: u8 = 5;
const CP_DOUBLE: u8 = 6;
const CP_CLASS: u8 = 7;
const CP_STRING: u8 = 8;
const CP_FIELDREF: u8 = 9;
const CP_METHODREF: u8 = 10;
const CP_INTERFACE_METHODREF: u8 = 11;
const CP_NAME_AND_TYPE: u8 = 12;
const CP_METHOD_HANDLE: u8 = 15;
const CP_METHOD_TYPE: u8 = 16;
const CP_DYNAMIC: u8 = 17;
const CP_INVOKE_DYNAMIC: u8 = 18;
const CP_MODULE: u8 = 19;
const CP_PACKAGE: u8 = 20;

#[derive(Default)]
struct ConstantPool {
    utf8: HashMap<u16, String>,
    class: HashMap<u16, u16>,
    /// `CONSTANT_NameAndType_info` -> (name_idx, descriptor_idx).
    /// Needed to resolve methodref / fieldref entries to readable
    /// names.
    name_and_type: HashMap<u16, (u16, u16)>,
    /// `CONSTANT_Methodref_info` and friends -> (class_idx,
    /// name_and_type_idx). One map covers Methodref,
    /// InterfaceMethodref, and Fieldref — consumers can ignore the
    /// kind for forensic purposes.
    methodref: HashMap<u16, (u16, u16)>,
}

impl ConstantPool {
    fn class_name(&self, class_idx: u16) -> Option<&str> {
        let name_idx = *self.class.get(&class_idx)?;
        self.utf8.get(&name_idx).map(String::as_str)
    }

    /// Resolve a methodref-like CP entry to `(owning_class, name,
    /// descriptor)` strings. Returns `None` when any link in the
    /// chain is missing or malformed.
    fn methodref_resolve(&self, idx: u16) -> Option<(&str, &str, &str)> {
        let (class_idx, nat_idx) = *self.methodref.get(&idx)?;
        let class = self.class_name(class_idx)?;
        let (name_idx, desc_idx) = *self.name_and_type.get(&nat_idx)?;
        let name = self.utf8.get(&name_idx).map(String::as_str)?;
        let desc = self.utf8.get(&desc_idx).map(String::as_str)?;
        Some((class, name, desc))
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    if bytes.len() < 10
        || u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0xCAFE_BABE
    {
        return Ok(());
    }
    let minor_version = u16::from_be_bytes([bytes[4], bytes[5]]);
    let major_version = u16::from_be_bytes([bytes[6], bytes[7]]);
    let cp_count = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;

    let mut pos = 10usize;
    let Some(cp) = parse_constant_pool(bytes, &mut pos, cp_count) else {
        return Ok(());
    };
    let Some(access_flags) = read_u16(bytes, &mut pos) else {
        return Ok(());
    };
    let Some(this_idx) = read_u16(bytes, &mut pos) else {
        return Ok(());
    };
    let Some(super_idx) = read_u16(bytes, &mut pos) else {
        return Ok(());
    };
    let Some(interfaces_count) = read_u16(bytes, &mut pos) else {
        return Ok(());
    };
    let mut interface_idx: Vec<u16> = Vec::with_capacity(interfaces_count as usize);
    for _ in 0..interfaces_count {
        let Some(idx) = read_u16(bytes, &mut pos) else {
            return Ok(());
        };
        interface_idx.push(idx);
    }
    // Skip fields[]; parse methods[] for the typed Functions view.
    if skip_member_table(bytes, &mut pos).is_none() {
        return Ok(());
    }
    let method_count = parse_methods(bytes, &mut pos, &cp, symbols_out).unwrap_or(0);
    let attrs = parse_attributes(bytes, &mut pos, &cp);

    // Surface external class references and methodref-resolved
    // imports. `this_class` is the class's own self-reference and
    // must not show up as an import.
    populate_imports(&cp, this_idx, symbols_out, metrics);
    metrics.insert("class.method_count", f64::from(method_count));

    put_u64(values, "class.major_version", u64::from(major_version));
    put_u64(values, "class.minor_version", u64::from(minor_version));
    if let Some(jv) = java_version(major_version) {
        put_str(values, "class.java_version", jv);
    }
    let flags = decode_access_flags(access_flags);
    if !flags.is_empty() {
        values.insert(
            "class.access_flags",
            JsonValue::Array(
                flags
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
    if let Some(name) = cp.class_name(this_idx) {
        put_str(values, "class.this_class", name.to_string());
    }
    if let Some(name) = cp.class_name(super_idx) {
        put_str(values, "class.super_class", name.to_string());
    }
    let interfaces: Vec<JsonValue> = interface_idx
        .iter()
        .filter_map(|i| cp.class_name(*i).map(|s| JsonValue::String(s.to_string())))
        .collect();
    if !interfaces.is_empty() {
        values.insert("class.interfaces", JsonValue::Array(interfaces));
    }
    if let Some(s) = attrs.source_file {
        put_str(values, "class.source_file", s);
    }
    if let Some(s) = attrs.signature {
        put_str(values, "class.signature", s);
    }
    if !attrs.inner_classes.is_empty() {
        values.insert(
            "class.inner_classes",
            JsonValue::Array(
                attrs
                    .inner_classes
                    .into_iter()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    put_u64(values, "class.constant_pool_size", cp_count as u64);
    metrics.insert("class.constant_pool_size", cp_count as f64);
    metrics.insert("class.interface_count", f64::from(interfaces_count));
    metrics.insert("class.major_version", f64::from(major_version));

    Ok(())
}

/// Map a JVM class-file `major_version` to its Java release name.
/// `45..=48` cover the legacy 1.0/1.1/1.2/1.3/1.4 era; `49+`
/// follow the 1:1 (`major - 44`) mapping.
fn java_version(major: u16) -> Option<&'static str> {
    match major {
        45 => Some("1.1"),
        46 => Some("1.2"),
        47 => Some("1.3"),
        48 => Some("1.4"),
        49 => Some("5"),
        50 => Some("6"),
        51 => Some("7"),
        52 => Some("8"),
        53 => Some("9"),
        54 => Some("10"),
        55 => Some("11"),
        56 => Some("12"),
        57 => Some("13"),
        58 => Some("14"),
        59 => Some("15"),
        60 => Some("16"),
        61 => Some("17"),
        62 => Some("18"),
        63 => Some("19"),
        64 => Some("20"),
        65 => Some("21"),
        66 => Some("22"),
        67 => Some("23"),
        68 => Some("24"),
        69 => Some("25"),
        _ => None,
    }
}

/// Decompose a class-level `access_flags` field per JVM Spec §4.1
/// Table 4.1-B.
fn decode_access_flags(flags: u16) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0001 != 0 {
        out.push("public");
    }
    if flags & 0x0010 != 0 {
        out.push("final");
    }
    if flags & 0x0020 != 0 {
        out.push("super");
    }
    if flags & 0x0200 != 0 {
        out.push("interface");
    }
    if flags & 0x0400 != 0 {
        out.push("abstract");
    }
    if flags & 0x1000 != 0 {
        out.push("synthetic");
    }
    if flags & 0x2000 != 0 {
        out.push("annotation");
    }
    if flags & 0x4000 != 0 {
        out.push("enum");
    }
    if flags & 0x8000 != 0 {
        out.push("module");
    }
    out
}

#[derive(Default)]
struct ClassAttributes {
    source_file: Option<String>,
    signature: Option<String>,
    inner_classes: Vec<String>,
}

fn parse_attributes(bytes: &[u8], pos: &mut usize, cp: &ConstantPool) -> ClassAttributes {
    let mut out = ClassAttributes::default();
    let Some(count) = read_u16(bytes, pos) else {
        return out;
    };
    for _ in 0..count {
        let Some(name_idx) = read_u16(bytes, pos) else {
            return out;
        };
        let Some(length) = read_u32(bytes, pos).map(|v| v as usize) else {
            return out;
        };
        let body_start = *pos;
        let Some(body_end) = body_start.checked_add(length).filter(|&e| e <= bytes.len()) else {
            return out;
        };
        let body = &bytes[body_start..body_end];
        let attr_name = cp.utf8.get(&name_idx).map(String::as_str).unwrap_or("");
        match attr_name {
            "SourceFile" if body.len() >= 2 => {
                let idx = u16::from_be_bytes([body[0], body[1]]);
                if let Some(s) = cp.utf8.get(&idx) {
                    out.source_file = Some(s.clone());
                }
            }
            "Signature" if body.len() >= 2 => {
                let idx = u16::from_be_bytes([body[0], body[1]]);
                if let Some(s) = cp.utf8.get(&idx) {
                    out.signature = Some(s.clone());
                }
            }
            "InnerClasses" if body.len() >= 2 => {
                let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                let mut p = 2;
                for _ in 0..n {
                    if p + 8 > body.len() {
                        break;
                    }
                    let inner_class_info_idx = u16::from_be_bytes([body[p], body[p + 1]]);
                    if let Some(name) = cp.class_name(inner_class_info_idx) {
                        let owned = name.to_string();
                        if !out.inner_classes.contains(&owned) {
                            out.inner_classes.push(owned);
                        }
                    }
                    p += 8;
                }
            }
            _ => {}
        }
        *pos = body_end;
    }
    out
}

/// Walk the `methods[]` array, push each declared method into the
/// typed `Functions` view, and return the count. Field structure
/// per JVM Spec §4.6: `access_flags u2; name_index u2;
/// descriptor_index u2; attributes_count u2; attributes[]`.
///
/// We don't parse the per-method `Code` attribute — only the
/// declaration matters for the symbol surface. Attributes are
/// length-skipped.
fn parse_methods(
    bytes: &[u8],
    pos: &mut usize,
    cp: &ConstantPool,
    symbols_out: &mut crate::Symbols,
) -> Option<u32> {
    let count = read_u16(bytes, pos)?;
    for _ in 0..count {
        let access_flags = read_u16(bytes, pos)?;
        let name_idx = read_u16(bytes, pos)?;
        let _descriptor_idx = read_u16(bytes, pos)?;
        let attrs = read_u16(bytes, pos)?;
        for _ in 0..attrs {
            *pos = pos.checked_add(2)?;
            let len = read_u32(bytes, pos)? as usize;
            *pos = pos.checked_add(len)?;
            if *pos > bytes.len() {
                return None;
            }
        }
        let Some(name) = cp.utf8.get(&name_idx) else {
            continue;
        };
        // Class-file method decl tags: `<init>` is the JVM's name for
        // a constructor, `<clinit>` for the static initialiser. Real
        // method declarations get the generic `"method"` tag.
        let decl = Some(match name.as_str() {
            "<init>" => "constructor".to_string(),
            "<clinit>" => "initializer".to_string(),
            _ => "method".to_string(),
        });
        // Static methods are interesting for entry-point detection
        // (`public static void main(String[])`). We don't yet emit
        // the access-flag decomposition per function — that lives
        // in the kv tree only.
        let _ = access_flags;
        symbols_out.push(crate::Symbol::Function {
            name: name.clone(),
            source: "java-class".into(),
            offset: None,
            decl,
            complexity: None,
            basic_blocks: None,
            edges: None,
            instructions: None,
            stack_frame: None,
            recursive: None,
            noreturn: None,
            is_linear: None,
            callees: Vec::new(),
        });
    }
    Some(u32::from(count))
}

/// Push two flavours of typed `Import` entries discovered through
/// the constant pool: external-class references (the JVM's import
/// system at compile time) and methodref-resolved foreign-method
/// references.
fn populate_imports(
    cp: &ConstantPool,
    this_idx: u16,
    symbols_out: &mut crate::Symbols,
    metrics: &mut Metrics,
) {
    // Distinct external class references — every CONSTANT_Class_info
    // entry except the class's own `this_class`. The class's
    // super-class is included because depending on it is a real
    // import; tooling matching against superclass-of-X queries gets
    // the data through the same view.
    let mut class_count: u32 = 0;
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (&idx, _) in &cp.class {
        if idx == this_idx {
            continue;
        }
        let Some(name) = cp.class_name(idx) else {
            continue;
        };
        if !seen.insert(name) {
            continue;
        }
        symbols_out.push(crate::Symbol::Import {
            name: name.to_string(),
            alias: None,
            library: None,
            source: "java-class".into(),
            offset: None,
            ordinal: None,
        });
        class_count = class_count.saturating_add(1);
    }
    metrics.insert("class.external_class_count", f64::from(class_count));

    // Methodref / InterfaceMethodref / Fieldref — surface only the
    // ones we can fully resolve to (class, name, descriptor). The
    // owning-class name carries the library identity; the symbol
    // name is the method name. Descriptor is not stored on Import
    // today — `<non-literal>` style overloading collisions are
    // rare enough that consumers can re-walk the kv tree if they
    // need the signature.
    let mut method_ref_count: u32 = 0;
    for (&idx, _) in &cp.methodref {
        let Some((owner, name, _desc)) = cp.methodref_resolve(idx) else {
            continue;
        };
        symbols_out.push(crate::Symbol::Import {
            name: name.to_string(),
            alias: None,
            library: Some(owner.to_string()),
            source: "java-methodref".into(),
            offset: None,
            ordinal: None,
        });
        method_ref_count = method_ref_count.saturating_add(1);
    }
    metrics.insert("class.method_ref_count", f64::from(method_ref_count));
}

fn skip_member_table(bytes: &[u8], pos: &mut usize) -> Option<()> {
    let count = read_u16(bytes, pos)?;
    for _ in 0..count {
        *pos = pos.checked_add(6)?;
        if *pos > bytes.len() {
            return None;
        }
        let attrs = read_u16(bytes, pos)?;
        for _ in 0..attrs {
            *pos = pos.checked_add(2)?;
            let len = read_u32(bytes, pos)? as usize;
            *pos = pos.checked_add(len)?;
            if *pos > bytes.len() {
                return None;
            }
        }
    }
    Some(())
}

fn parse_constant_pool(bytes: &[u8], pos: &mut usize, count: usize) -> Option<ConstantPool> {
    let mut cp = ConstantPool::default();
    let mut i = 1usize;
    while i < count {
        let tag = *bytes.get(*pos)?;
        *pos += 1;
        match tag {
            CP_UTF8 => {
                let len = read_u16(bytes, pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > bytes.len() {
                    return None;
                }
                let s = String::from_utf8_lossy(&bytes[*pos..end]).into_owned();
                cp.utf8.insert(i as u16, s);
                *pos = end;
            }
            CP_CLASS => {
                let idx = read_u16(bytes, pos)?;
                cp.class.insert(i as u16, idx);
            }
            CP_STRING | CP_METHOD_TYPE | CP_MODULE | CP_PACKAGE => {
                *pos = pos.checked_add(2)?;
            }
            CP_LONG | CP_DOUBLE => {
                *pos = pos.checked_add(8)?;
                i += 1; // longs/doubles take two CP slots
            }
            CP_FIELDREF | CP_METHODREF | CP_INTERFACE_METHODREF => {
                // (class_index, name_and_type_index) — both u16,
                // big-endian. Captured so we can resolve method
                // references to (owning_class, name, descriptor)
                // triples later.
                let class_idx = read_u16(bytes, pos)?;
                let nat_idx = read_u16(bytes, pos)?;
                cp.methodref.insert(i as u16, (class_idx, nat_idx));
            }
            CP_NAME_AND_TYPE => {
                let name_idx = read_u16(bytes, pos)?;
                let desc_idx = read_u16(bytes, pos)?;
                cp.name_and_type.insert(i as u16, (name_idx, desc_idx));
            }
            CP_INTEGER | CP_FLOAT | CP_DYNAMIC | CP_INVOKE_DYNAMIC => {
                *pos = pos.checked_add(4)?;
            }
            CP_METHOD_HANDLE => {
                *pos = pos.checked_add(3)?;
            }
            _ => return None,
        }
        i += 1;
    }
    Some(cp)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let b = bytes.get(*pos..*pos + 2)?.try_into().ok()?;
    *pos += 2;
    Some(u16::from_be_bytes(b))
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let b = bytes.get(*pos..*pos + 4)?.try_into().ok()?;
    *pos += 4;
    Some(u32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
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
        extract(bytes, &mut v, &mut s, &mut m, &mut symbols).unwrap();
        (v, m)
    }

    fn run_full(bytes: &[u8]) -> (Values, Metrics, crate::Symbols) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut symbols = crate::Symbols::new();
        extract(bytes, &mut v, &mut s, &mut m, &mut symbols).unwrap();
        (v, m, symbols)
    }

    #[test]
    fn rejects_non_class() {
        let (v, _) = run(b"not a class");
        assert!(v.get("class.major_version").is_none());
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
            let crate::Symbol::Import {
                source, library, ..
            } = sym
            else {
                unreachable!();
            };
            assert_eq!(source, "java-class");
            assert!(library.is_none(), "java-class imports carry no library");
        }
        assert_eq!(m.get("class.external_class_count"), Some(1.0));
        // No methods were declared by the builder.
        assert_eq!(m.get("class.method_count"), Some(0.0));
        assert_eq!(symbols.iter_kind(crate::SymbolKind::Function).count(), 0);
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
    fn methodref_resolves_to_java_methodref_import() {
        let bytes = build_class_with_methodref_and_method();
        let (_, m, symbols) = run_full(&bytes);
        let methodref: Vec<(&str, Option<&str>)> = symbols
            .iter_kind(crate::SymbolKind::Import)
            .filter_map(|s| match s {
                crate::Symbol::Import {
                    name,
                    library,
                    source,
                    ..
                } if source == "java-methodref" => Some((name.as_str(), library.as_deref())),
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
        let funcs: Vec<(&str, &str, Option<&str>)> = symbols
            .iter_kind(crate::SymbolKind::Function)
            .filter_map(|s| match s {
                crate::Symbol::Function {
                    name, source, decl, ..
                } => Some((name.as_str(), source.as_str(), decl.as_deref())),
                _ => None,
            })
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].0, "compute");
        assert_eq!(funcs[0].1, "java-class");
        assert_eq!(funcs[0].2, Some("method"));
        assert_eq!(m.get("class.method_count"), Some(1.0));
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
}
