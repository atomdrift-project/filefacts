//! Java `.class` extractor.
//!
//! Walks the JVM class file header per the JVM Spec §4. Pulls the
//! version, decomposed access flags, constant-pool size, class
//! hierarchy (`this_class`, `super_class`, `interfaces[]`), and
//! the class-level attributes (`SourceFile`, `Signature`,
//! `InnerClasses`). `fields[]` is skipped; `methods[]` is walked for the
//! declared method names, which become function symbols. Constant-pool
//! class and method references become imports.
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
//! - `class.constant_pool_count` — metric also surfaced as
//!   `metrics.class.constant_pool_count`.

use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, HashMap};

use crate::bytes::Reader;
use crate::formats::common::{XorScan, extract_binary_strings, put_str, put_u64};
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

/// Upper bound on the number of `class.class_refs` / `class.strings`
/// entries emitted, so a hostile constant pool can't bloat the output.
/// Real classes carry far fewer distinct entries than this.
const MAX_CP_FACTS: usize = 8192;

/// Upper bound on the method and methodref name bytes copied out of the
/// constant pool into symbols. Both name their strings by index, so without
/// it one 64 KiB `CONSTANT_Utf8` entry named by 65535 methods or methodrefs
/// copies 4 GiB out of a file under 600 KiB. Real classes copy a few KiB.
const MAX_SYMBOL_NAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct ConstantPool {
    utf8: HashMap<u16, String>,
    /// Byte offset of each `CONSTANT_Utf8_info` entry's string data, so
    /// constant-pool-derived imports can anchor where the name physically sits.
    utf8_offset: HashMap<u16, u64>,
    class: BTreeMap<u16, u16>,
    /// `CONSTANT_NameAndType_info` -> (name_idx, descriptor_idx).
    /// Needed to resolve methodref / fieldref entries to readable
    /// names.
    name_and_type: HashMap<u16, (u16, u16)>,
    /// `CONSTANT_Methodref_info` and friends -> (class_idx,
    /// name_and_type_idx). One map covers Methodref,
    /// InterfaceMethodref, and Fieldref — consumers can ignore the
    /// kind for forensic purposes.
    methodref: BTreeMap<u16, (u16, u16)>,
}

impl ConstantPool {
    fn class_name(&self, class_idx: u16) -> Option<&str> {
        let name_idx = *self.class.get(&class_idx)?;
        self.utf8.get(&name_idx).map(String::as_str)
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    let abandon = |stage: &str, offset: usize| {
        tracing::debug!(
            target: "filefacts::class",
            stage,
            offset,
            len = bytes.len(),
            "class file truncated or malformed; no class facts"
        );
    };
    let Some(&[m0, m1, m2, m3, n0, n1, j0, j1, c0, c1]) = bytes.first_chunk::<10>() else {
        abandon("magic", 0);
        return;
    };
    if u32::from_be_bytes([m0, m1, m2, m3]) != 0xCAFE_BABE {
        abandon("magic", 0);
        return;
    }
    let minor_version = u16::from_be_bytes([n0, n1]);
    let major_version = u16::from_be_bytes([j0, j1]);
    let cp_count = u16::from_be_bytes([c0, c1]) as usize;

    let mut r = Reader::at(bytes, 10);
    let Some(cp) = parse_constant_pool(&mut r, cp_count) else {
        abandon("constant_pool", r.pos());
        return;
    };
    // access_flags, this_class, super_class, then the interface table.
    let header = (|| {
        let fields = [r.u16_be()?, r.u16_be()?, r.u16_be()?, r.u16_be()?];
        let interfaces = (0..fields[3])
            .map(|_| r.u16_be())
            .collect::<Option<Vec<u16>>>()?;
        Some((fields, interfaces))
    })();
    let Some(([access_flags, this_idx, super_idx, interfaces_count], interface_idx)) = header
    else {
        abandon("header", r.pos());
        return;
    };
    // Skip fields[] (`access_flags u2; name_index u2; descriptor_index u2;
    // attributes` per entry); parse methods[] for the typed Functions view.
    let fields = (|| {
        for _ in 0..r.u16_be()? {
            r.skip(6)?;
            skip_attributes(&mut r)?;
        }
        Some(())
    })();
    if fields.is_none() {
        abandon("fields", r.pos());
        return;
    }
    // The class attributes follow methods[], so a truncated method table
    // leaves them unreachable.
    let mut name_budget = MAX_SYMBOL_NAME_BYTES;
    let attrs = match parse_methods(&mut r, &cp, symbols_out, &mut name_budget) {
        Some(()) => parse_attributes(&mut r, &cp),
        None => {
            abandon("methods", r.pos());
            ClassAttributes::default()
        }
    };

    // Surface external class references and methodref-resolved
    // imports. `this_class` is the class's own self-reference and
    // must not show up as an import.
    populate_imports(&cp, this_idx, symbols_out, metrics, &mut name_budget);

    // Complete CONSTANT_Class name set and CONSTANT_Utf8 string table.
    // Consumers run constant-pool class/string heuristics directly off
    // these facts rather than re-parsing the class. Both are bounded so a
    // hostile constant pool can't bloat the output unboundedly.
    let mut class_refs: Vec<&str> = cp
        .class
        .keys()
        .filter_map(|idx| cp.class_name(*idx))
        .collect();
    class_refs.sort_unstable();
    class_refs.dedup();
    if !class_refs.is_empty() {
        values.insert_key(
            value_key!("class.class_refs"),
            JsonValue::Array(
                class_refs
                    .into_iter()
                    .take(MAX_CP_FACTS)
                    .map(|s| JsonValue::String(s.to_string()))
                    .collect(),
            ),
        );
    }
    let mut utf8: Vec<&str> = cp.utf8.values().map(String::as_str).collect();
    utf8.sort_unstable();
    utf8.dedup();
    if !utf8.is_empty() {
        values.insert_key(
            value_key!("class.strings"),
            JsonValue::Array(
                utf8.into_iter()
                    .take(MAX_CP_FACTS)
                    .map(|s| JsonValue::String(s.to_string()))
                    .collect(),
            ),
        );
    }

    put_u64(
        values,
        value_key!("class.major_version"),
        u64::from(major_version),
    );
    put_u64(
        values,
        value_key!("class.minor_version"),
        u64::from(minor_version),
    );
    if let Some(jv) = java_version(major_version) {
        put_str(values, value_key!("class.java_version"), jv);
    }
    let flags = decode_access_flags(access_flags);
    if !flags.is_empty() {
        values.insert_key(
            value_key!("class.access_flags"),
            JsonValue::Array(
                flags
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
    if let Some(name) = cp.class_name(this_idx) {
        put_str(values, value_key!("class.this_class"), name.to_string());
    }
    if let Some(name) = cp.class_name(super_idx) {
        put_str(values, value_key!("class.super_class"), name.to_string());
    }
    let interfaces: Vec<JsonValue> = interface_idx
        .iter()
        .filter_map(|i| cp.class_name(*i).map(|s| JsonValue::String(s.to_string())))
        .collect();
    if !interfaces.is_empty() {
        values.insert_key(value_key!("class.interfaces"), JsonValue::Array(interfaces));
    }
    if let Some(s) = attrs.source_file {
        put_str(values, value_key!("class.source_file"), s);
    }
    if let Some(s) = attrs.signature {
        put_str(values, value_key!("class.signature"), s);
    }
    if !attrs.inner_classes.is_empty() {
        values.insert_key(
            value_key!("class.inner_classes"),
            JsonValue::Array(
                attrs
                    .inner_classes
                    .into_iter()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    put_u64(
        values,
        value_key!("class.constant_pool_count"),
        cp_count as u64,
    );
    metrics.insert(metric!("class.constant_pool_count"), cp_count as f64);
    metrics.insert(
        metric!("class.interface_count"),
        f64::from(interfaces_count),
    );
    metrics.insert(metric!("class.major_version"), f64::from(major_version));
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

fn parse_attributes(r: &mut Reader<'_>, cp: &ConstantPool) -> ClassAttributes {
    let mut out = ClassAttributes::default();
    // Inner class names already listed, borrowed from the constant pool. Up
    // to 65535 attributes may each repeat a long InnerClasses table, so the
    // dedup must not be a scan of everything listed so far.
    let mut seen_inner = std::collections::HashSet::new();
    let Some(count) = r.u16_be() else {
        return out;
    };
    for _ in 0..count {
        let Some(name_idx) = r.u16_be() else {
            return out;
        };
        let Some(length) = r.u32_be().map(|v| v as usize) else {
            return out;
        };
        let Some(body) = r.bytes(length) else {
            return out;
        };
        let attr_name = cp.utf8.get(&name_idx).map(String::as_str).unwrap_or("");
        // Every class-level attribute read here opens with a u2; a body too
        // short for it records nothing.
        let lead = body
            .split_first_chunk::<2>()
            .map(|(&lead, rest)| (u16::from_be_bytes(lead), rest));
        match (attr_name, lead) {
            ("SourceFile", Some((idx, _))) => {
                if let Some(s) = cp.utf8.get(&idx) {
                    out.source_file = Some(s.clone());
                }
            }
            ("Signature", Some((idx, _))) => {
                if let Some(s) = cp.utf8.get(&idx) {
                    out.signature = Some(s.clone());
                }
            }
            ("InnerClasses", Some((entry_count, entries))) => {
                // Each entry is four u2s, the first inner_class_info_index.
                let entries = entries.as_chunks::<8>().0;
                for &[i0, i1, ..] in entries.iter().take(usize::from(entry_count)) {
                    if let Some(name) = cp.class_name(u16::from_be_bytes([i0, i1]))
                        && seen_inner.insert(name)
                    {
                        out.inner_classes.push(name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Walk the `methods[]` array and push each declared method into the
/// typed `Functions` view. Field structure
/// per JVM Spec §4.6: `access_flags u2; name_index u2;
/// descriptor_index u2; attributes_count u2; attributes[]`.
///
/// We don't parse the per-method `Code` attribute — only the
/// declaration matters for the symbol surface. Attributes are
/// length-skipped. Methods past the name budget are walked but not emitted.
fn parse_methods(
    r: &mut Reader<'_>,
    cp: &ConstantPool,
    symbols_out: &mut crate::Symbols,
    name_budget: &mut usize,
) -> Option<()> {
    let count = r.u16_be()?;
    for _ in 0..count {
        // access_flags u2, then name_index u2, then descriptor_index u2.
        r.skip(2)?;
        let name_idx = r.u16_be()?;
        r.skip(2)?;
        skip_attributes(r)?;
        let Some(name) = cp.utf8.get(&name_idx) else {
            continue;
        };
        if !charge(name_budget, name.len()) {
            continue;
        }
        symbols_out.push(crate::Symbol::Function {
            name: name.clone(),
            // The method name is a constant-pool UTF-8 entry, so anchor the
            // function symbol at the name bytes just like methodref imports.
            offset: cp.utf8_offset.get(&name_idx).copied(),
            complexity: None,
            callees: Vec::new(),
        });
    }
    Some(())
}

/// Take `len` bytes from a symbol-name budget, or report it spent.
fn charge(budget: &mut usize, len: usize) -> bool {
    let Some(rest) = budget.checked_sub(len) else {
        return false;
    };
    *budget = rest;
    true
}

/// Push two flavours of typed `Import` entries discovered through
/// the constant pool: external-class references (the JVM's import
/// system at compile time) and methodref-resolved foreign-method
/// references. Methodref imports past the name budget are counted but
/// not emitted.
fn populate_imports(
    cp: &ConstantPool,
    this_idx: u16,
    symbols_out: &mut crate::Symbols,
    metrics: &mut Metrics,
    name_budget: &mut usize,
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
            // Anchored at the class name's string in the constant pool.
            offset: cp
                .class
                .get(&idx)
                .and_then(|n| cp.utf8_offset.get(n))
                .copied(),
            ordinal: None,
        });
        class_count = class_count.saturating_add(1);
    }
    metrics.insert(
        metric!("class.external_class_count"),
        f64::from(class_count),
    );

    // Methodref / InterfaceMethodref / Fieldref — surface only the
    // ones we can fully resolve to (class, name, descriptor). The
    // owning-class name carries the library identity; the symbol
    // name is the method name, anchored at its constant-pool string. The
    // descriptor must resolve but is not stored on the import.
    let mut method_ref_count: u32 = 0;
    for &(class_idx, nat_idx) in cp.methodref.values() {
        let Some(owner) = cp.class_name(class_idx) else {
            continue;
        };
        let Some(&(name_idx, desc_idx)) = cp.name_and_type.get(&nat_idx) else {
            continue;
        };
        let (Some(name), true) = (cp.utf8.get(&name_idx), cp.utf8.contains_key(&desc_idx)) else {
            continue;
        };
        method_ref_count = method_ref_count.saturating_add(1);
        if !charge(name_budget, name.len().saturating_add(owner.len())) {
            continue;
        }
        symbols_out.push(crate::Symbol::Import {
            name: name.clone(),
            alias: None,
            library: Some(owner.to_string()),
            offset: cp.utf8_offset.get(&name_idx).copied(),
            ordinal: None,
        });
    }
    metrics.insert(
        metric!("class.method_ref_count"),
        f64::from(method_ref_count),
    );
}

/// Step over `attributes_count u2; attributes[]`, each attribute a
/// `name_index u2; length u4; info[length]`.
fn skip_attributes(r: &mut Reader<'_>) -> Option<()> {
    let count = r.u16_be()?;
    for _ in 0..count {
        r.skip(2)?;
        let len = r.u32_be()? as usize;
        r.skip(len)?;
    }
    Some(())
}

fn parse_constant_pool(r: &mut Reader<'_>, count: usize) -> Option<ConstantPool> {
    let mut cp = ConstantPool::default();
    let mut i = 1usize;
    while i < count {
        // `count` comes from a u16, so every index below it fits one.
        let slot = u16::try_from(i).ok()?;
        let tag = r.u8()?;
        match tag {
            CP_UTF8 => {
                let len = r.u16_be()? as usize;
                let offset = r.pos();
                let s = String::from_utf8_lossy(r.bytes(len)?).into_owned();
                cp.utf8.insert(slot, s);
                cp.utf8_offset.insert(slot, offset as u64);
            }
            CP_CLASS => {
                let idx = r.u16_be()?;
                cp.class.insert(slot, idx);
            }
            CP_STRING | CP_METHOD_TYPE | CP_MODULE | CP_PACKAGE => {
                r.skip(2)?;
            }
            CP_LONG | CP_DOUBLE => {
                r.skip(8)?;
                i += 1; // longs/doubles take two CP slots
            }
            CP_FIELDREF | CP_METHODREF | CP_INTERFACE_METHODREF => {
                // (class_index, name_and_type_index) — both u16,
                // big-endian. Captured so we can resolve method
                // references to (owning_class, name, descriptor)
                // triples later.
                let class_idx = r.u16_be()?;
                let nat_idx = r.u16_be()?;
                cp.methodref.insert(slot, (class_idx, nat_idx));
            }
            CP_NAME_AND_TYPE => {
                let name_idx = r.u16_be()?;
                let desc_idx = r.u16_be()?;
                cp.name_and_type.insert(slot, (name_idx, desc_idx));
            }
            CP_INTEGER | CP_FLOAT | CP_DYNAMIC | CP_INVOKE_DYNAMIC => {
                r.skip(4)?;
            }
            CP_METHOD_HANDLE => {
                r.skip(3)?;
            }
            _ => return None,
        }
        i += 1;
    }
    Some(cp)
}

#[cfg(test)]
mod tests;
