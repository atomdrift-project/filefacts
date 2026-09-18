//! Compiled Interface Builder archive (`.nib`) extractor.
//!
//! A nib is the compiled form of a `.xib`/`.storyboard`: the object graph
//! AppKit or UIKit instantiates at run time to build a window or view. Two
//! on-disk forms exist and both carry the same graph:
//!
//! - `NIBArchive` — Xcode's compact format (deployment target 10.13 / iOS 8
//!   and later). Four tables (objects, keys, values, class names) addressed
//!   from a fixed 50-byte header, with varint-encoded entries.
//! - Keyed archive — an `NSKeyedArchiver` binary plist (`keyedobjects.nib`
//!   inside an older `.nib` bundle). `$objects` holds the graph, `$class`
//!   UIDs point at class descriptors.
//!
//! What matters for attribution is not the layout but the names the graph
//! binds to code: the custom classes it instantiates, the Swift module they
//! come from, the outlets and action selectors it wires, and the visible
//! text it shows. A dropper's "Installer" window with a `runPayload:` action
//! on a `DropperController` is fully described by these facts without
//! loading the bundle. Both forms feed the same fact set:
//!
//! - `nib.format` — `nibarchive` or `keyed_archive`.
//! - `nib.classes[]` — every class the graph instantiates, sorted.
//! - `nib.class_names[]` — classes the nib instantiates *by name*
//!   (`NSClassName`, `UIClassName`, `IBClassName`). This is where the app's
//!   own code hangs off the UI: a custom File's Owner or a swapped-in view
//!   class. The framework placeholders (`NSObject`, `NSApplication`) sit in
//!   the same list, and a Swift class appears both plain and mangled
//!   (`_TtC7Dropper17DropperController`), which is where a stripped binary
//!   still leaks its module name.
//! - `nib.modules[]` — Swift module names (`IBModuleName`) the custom classes
//!   live in; a build-time identity leak like a Go module path.
//! - `nib.outlets[]`, `nib.actions[]`, `nib.bindings[]` — connection labels:
//!   ivar names, action selectors, and Cocoa binding key paths.
//! - `nib.resources[]` — image and sound resource names referenced by name.
//!
//! Every string object in the graph (titles, labels, placeholder text,
//! identifiers) is published in the literal string view with its file offset.

use std::collections::BTreeSet;
use std::ops::Range;

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{XorScan, extract_binary_strings};
use crate::metric;
use crate::output::{ExtractedString, Metrics, Strings, Values};

const MAGIC: &[u8] = b"NIBArchive";
/// Magic, two format constants, then four (count, offset) pairs.
const HEADER_LEN: usize = MAGIC.len() + 4 * 10;

/// Names the object graph binds to code, independent of the on-disk form.
#[derive(Default)]
struct Facts {
    classes: BTreeSet<String>,
    class_names: BTreeSet<String>,
    modules: BTreeSet<String>,
    outlets: BTreeSet<String>,
    actions: BTreeSet<String>,
    bindings: BTreeSet<String>,
    resources: BTreeSet<String>,
    object_count: usize,
    connection_count: usize,
}

impl Facts {
    /// Record one object of class `class`. `field` resolves one of the
    /// object's keys to a string, in whichever encoding the form uses.
    fn note_object(&mut self, class: &str, field: impl Fn(&str) -> Option<String>) {
        self.object_count += 1;
        self.classes.insert(class.to_string());
        let connection = match class {
            "NSNibOutletConnector"
            | "UIRuntimeOutletConnection"
            | "UIRuntimeOutletCollectionConnection" => Some(&mut self.outlets),
            "NSNibControlConnector" | "UIRuntimeEventConnection" => Some(&mut self.actions),
            "NSNibBindingConnector" => Some(&mut self.bindings),
            _ => None,
        };
        if let Some(labels) = connection {
            if let Some(label) = field("NSLabel").or_else(|| field("UILabel")) {
                labels.insert(label);
            }
            self.connection_count += 1;
            return;
        }
        if class == "NSCustomResource" || class == "UIImageNibPlaceholder" {
            if let Some(name) = field("NSResourceName").or_else(|| field("UIResourceName")) {
                self.resources.insert(name);
            }
            return;
        }
        for key in ["NSClassName", "UIClassName", "IBClassName"] {
            if let Some(name) = field(key) {
                self.class_names.insert(name);
            }
        }
        if let Some(module) = field("IBModuleName").filter(|m| !m.is_empty()) {
            self.modules.insert(module);
        }
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings, XorScan::No);

    let mut facts = Facts::default();
    let literal_count_before = strings.literals.len();
    let format = if bytes.starts_with(MAGIC) {
        let archive = Archive::parse(bytes)?;
        values.insert(
            "nib.format_version",
            JsonValue::Number(archive.format_version.into()),
        );
        archive.collect(bytes, &mut facts, strings);
        "nibarchive"
    } else if bytes.starts_with(b"bplist") {
        let archiver = collect_keyed(bytes, &mut facts, strings)?;
        values.insert("nib.archiver", JsonValue::String(archiver));
        "keyed_archive"
    } else {
        return Err(Error::malformed(
            "nib",
            "neither a NIBArchive nor a keyed-archive plist",
        ));
    };
    let string_count = strings.literals.len() - literal_count_before;

    metrics.insert(metric!("nib.object_count"), facts.object_count as f64);
    metrics.insert(metric!("nib.class_count"), facts.classes.len() as f64);
    metrics.insert(
        metric!("nib.class_name_count"),
        facts.class_names.len() as f64,
    );
    metrics.insert(
        metric!("nib.connection_count"),
        facts.connection_count as f64,
    );
    metrics.insert(metric!("nib.string_count"), string_count as f64);
    tracing::debug!(
        format,
        objects = facts.object_count,
        classes = facts.classes.len(),
        class_names = facts.class_names.len(),
        connections = facts.connection_count,
        strings = string_count,
        "nib extracted"
    );

    values.insert("nib.format", JsonValue::String(format.into()));
    for (path, set) in [
        ("nib.classes", facts.classes),
        ("nib.class_names", facts.class_names),
        ("nib.modules", facts.modules),
        ("nib.outlets", facts.outlets),
        ("nib.actions", facts.actions),
        ("nib.bindings", facts.bindings),
        ("nib.resources", facts.resources),
    ] {
        let list = set.into_iter().map(JsonValue::String).collect();
        values.insert(path, JsonValue::Array(list));
    }
    Ok(())
}

fn push_literal(strings: &mut Strings, text: &str, offset: usize) {
    strings.literals.push(ExtractedString {
        text: text.to_string(),
        offset,
        method: Some("nib-string".into()),
        encoding: Some("utf8".into()),
        ..Default::default()
    });
}

// ---------------------------------------------------------------------------
// NIBArchive
// ---------------------------------------------------------------------------

/// One entry of the object table: a class and a run of values.
#[derive(Debug)]
struct Object {
    class: usize,
    first_value: usize,
    value_count: usize,
}

/// One entry of the value table. Only data and object references carry
/// names; a numeric, boolean, or nil payload is skipped over. `Data` keeps
/// its byte range in the file so a string literal can report where it lives.
#[derive(Debug)]
enum Payload {
    Scalar,
    Data(Range<usize>),
    Ref(usize),
}

/// Payload width by type code for the scalar types: int8, int16, int32,
/// int64, true, false, float, double, (data), nil.
const SCALAR_LEN: [usize; 10] = [1, 2, 4, 8, 0, 0, 4, 8, 0, 0];

#[derive(Debug)]
struct Value {
    key: usize,
    payload: Payload,
}

#[derive(Debug)]
struct Archive {
    format_version: u32,
    objects: Vec<Object>,
    keys: Vec<String>,
    values: Vec<Value>,
    classes: Vec<String>,
}

impl Archive {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < HEADER_LEN {
            return Err(Error::malformed("nib", "truncated NIBArchive header"));
        }
        // Ten little-endian words follow the magic; the length check above
        // is what makes the fixed slicing below safe.
        let word = |i: usize| {
            let at = MAGIC.len() + 4 * i;
            u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
        };
        let [
            constant,
            format_version,
            object_count,
            object_offset,
            key_count,
            key_offset,
            value_count,
            value_offset,
            class_count,
            class_offset,
        ] = std::array::from_fn(word);
        if constant != 1 {
            tracing::debug!(
                constant,
                format_version,
                "unexpected NIBArchive header constant"
            );
        }

        let objects = parse_table(data, object_count, object_offset, "object", |c| {
            Some(Object {
                class: c.varint()?,
                first_value: c.varint()?,
                value_count: c.varint()?,
            })
        })?;
        let keys = parse_table(data, key_count, key_offset, "key", |c| {
            let len = c.varint()?;
            Some(String::from_utf8_lossy(c.take(len)?).into_owned())
        })?;
        let values = parse_table(data, value_count, value_offset, "value", |c| {
            let key = c.varint()?;
            let payload = match c.u8()? {
                8 => {
                    let len = c.varint()?;
                    let start = c.pos;
                    c.take(len)?;
                    Payload::Data(start..c.pos)
                }
                10 => Payload::Ref(c.u32()? as usize),
                kind @ (0..=7 | 9) => {
                    c.take(SCALAR_LEN[usize::from(kind)])?;
                    Payload::Scalar
                }
                _ => return None,
            };
            Some(Value { key, payload })
        })?;
        let classes = parse_table(data, class_count, class_offset, "class name", |c| {
            let len = c.varint()?;
            let extras = c.varint()?;
            c.take(extras.checked_mul(4)?)?;
            let name = c.take(len)?;
            let name = name.strip_suffix(b"\0").unwrap_or(name);
            Some(String::from_utf8_lossy(name).into_owned())
        })?;
        Ok(Self {
            format_version,
            objects,
            keys,
            values,
            classes,
        })
    }

    fn values_of(&self, object: &Object) -> &[Value] {
        let start = object.first_value.min(self.values.len());
        let end = start
            .saturating_add(object.value_count)
            .min(self.values.len());
        &self.values[start..end]
    }

    /// The value stored under `key` on `object`, if any.
    fn field<'a>(&'a self, object: &Object, key: &str) -> Option<&'a Value> {
        self.values_of(object)
            .iter()
            .find(|v| self.keys.get(v.key).is_some_and(|k| k == key))
    }

    /// Resolve a value to its string and offset. Inline data is the string
    /// itself; an object reference is followed exactly one hop, into an
    /// `NSString` whose text is its `NS.bytes` data value, so a reference
    /// cycle in a crafted file cannot recurse.
    fn string<'a>(&'a self, data: &'a [u8], value: &Value) -> Option<(&'a str, usize)> {
        let range = match &value.payload {
            Payload::Data(range) => range,
            Payload::Ref(index) => {
                let target = self.objects.get(*index)?;
                match &self.field(target, "NS.bytes")?.payload {
                    Payload::Data(range) => range,
                    _ => return None,
                }
            }
            Payload::Scalar => return None,
        };
        let text = std::str::from_utf8(data.get(range.clone())?).ok()?;
        Some((text, range.start))
    }

    fn collect(&self, data: &[u8], facts: &mut Facts, strings: &mut Strings) {
        let mut seen = BTreeSet::new();
        for object in &self.objects {
            let Some(class) = self.classes.get(object.class) else {
                continue;
            };
            if class == "NSString" || class == "NSMutableString" {
                if let Some((text, offset)) = self
                    .field(object, "NS.bytes")
                    .and_then(|v| self.string(data, v))
                    && !text.is_empty()
                    && seen.insert(offset)
                {
                    push_literal(strings, text, offset);
                }
            }
            facts.note_object(class, |key| {
                self.field(object, key)
                    .and_then(|v| self.string(data, v))
                    .map(|(text, _)| text.to_string())
            });
        }
    }
}

/// Read `count` entries starting at `offset`. Every entry is at least one
/// byte, so a count beyond the file is rejected up front, and the vector
/// grows only as entries actually parse rather than reserving for the
/// header's claim.
fn parse_table<T>(
    data: &[u8],
    count: u32,
    offset: u32,
    what: &'static str,
    mut read: impl FnMut(&mut Cursor<'_>) -> Option<T>,
) -> Result<Vec<T>, Error> {
    let (count, offset) = (count as usize, offset as usize);
    if offset > data.len() || count > data.len() - offset {
        return Err(Error::malformed(
            "nib",
            format!("{what} table does not fit: {count} entries at offset {offset}"),
        ));
    }
    let mut cursor = Cursor { data, pos: offset };
    let mut out = Vec::new();
    for index in 0..count {
        let Some(entry) = read(&mut cursor) else {
            return Err(Error::malformed(
                "nib",
                format!("{what} table entry {index} is truncated or malformed"),
            ));
        };
        out.push(entry);
    }
    Ok(out)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)?.try_into().ok().map(u32::from_le_bytes)
    }

    /// NIBArchive varint: little-endian 7-bit groups, with the high bit set
    /// on the *last* byte rather than on the continuation bytes.
    fn varint(&mut self) -> Option<usize> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 != 0 {
                return usize::try_from(value).ok();
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// NSKeyedArchiver form
// ---------------------------------------------------------------------------

/// Walk a keyed-archive nib. Returns the `$archiver` name.
fn collect_keyed(bytes: &[u8], facts: &mut Facts, strings: &mut Strings) -> Result<String, Error> {
    use plist::Value as P;

    let root = plist::Value::from_reader(std::io::Cursor::new(bytes))
        .map_err(|e| Error::malformed("nib", e.to_string()))?;
    let P::Dictionary(root) = root else {
        return Err(Error::malformed(
            "nib",
            "keyed archive root is not a dictionary",
        ));
    };
    let archiver = root
        .get("$archiver")
        .and_then(P::as_string)
        .unwrap_or_default()
        .to_string();
    let Some(P::Array(objects)) = root.get("$objects") else {
        return Err(Error::malformed("nib", "keyed archive has no $objects"));
    };

    // A UID points into `$objects`; strings are usually stored there once
    // and referenced, but a short one may sit inline in its owner. Entry 0
    // is the archiver's `$null` sentinel, which an absent field points at.
    let resolve = |value: &P| -> Option<String> {
        let text = match value {
            P::String(s) => s.as_str(),
            P::Uid(uid) => objects
                .get(usize::try_from(uid.get()).ok()?)
                .and_then(P::as_string)?,
            _ => return None,
        };
        (text != "$null").then(|| text.to_string())
    };

    // Literals are deduplicated by text borrowed from the parsed archive.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for object in objects {
        match object {
            P::String(text) => note_string(&mut seen, strings, bytes, text),
            P::Dictionary(dict) => {
                // `$classname` and friends are archiver bookkeeping, not
                // strings the nib carries; the class names have their own fact.
                for (key, value) in dict {
                    if let P::String(text) = value
                        && !key.starts_with('$')
                    {
                        note_string(&mut seen, strings, bytes, text);
                    }
                }
                if let Some(class) = class_name(objects, dict) {
                    facts.note_object(class, |key| dict.get(key).and_then(resolve));
                }
            }
            _ => {}
        }
    }
    Ok(archiver)
}

/// Publish one keyed-archive string as a literal, once per distinct text.
/// Entry 0 of `$objects` is the archiver's `$null` sentinel, not a string.
fn note_string<'a>(
    seen: &mut BTreeSet<&'a str>,
    strings: &mut Strings,
    bytes: &[u8],
    text: &'a str,
) {
    if !text.is_empty() && text != "$null" && seen.insert(text) {
        push_literal(strings, text, locate(bytes, text));
    }
}

/// Follow an object's `$class` UID to its class descriptor's `$classname`.
fn class_name<'a>(objects: &'a [plist::Value], object: &plist::Dictionary) -> Option<&'a str> {
    let plist::Value::Uid(uid) = object.get("$class")? else {
        return None;
    };
    objects
        .get(usize::try_from(uid.get()).ok()?)?
        .as_dictionary()?
        .get("$classname")?
        .as_string()
}

/// File offset of `text` in a binary plist. An ASCII string is stored as
/// its bytes behind a `0x5n` marker and anything else as UTF-16BE behind
/// `0x6n`, where `n` is the length or `0xf` followed by an int object for
/// 15 and up. Searching with the marker keeps `Dropper` from matching the
/// front of `DropperController`. Zero when the string is not stored
/// verbatim.
fn locate(bytes: &[u8], text: &str) -> usize {
    let (marker, body, count): (u8, Vec<u8>, usize) = if text.is_ascii() {
        (0x50, text.as_bytes().to_vec(), text.len())
    } else {
        let body: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
        let count = body.len() / 2;
        (0x60, body, count)
    };
    let mut needle = match count {
        0..=14 => vec![marker | count as u8],
        15..=0xff => vec![marker | 0xf, 0x10, count as u8],
        0x100..=0xffff => {
            let mut v = vec![marker | 0xf, 0x11];
            v.extend((count as u16).to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![marker | 0xf, 0x12];
            v.extend((count as u32).to_be_bytes());
            v
        }
    };
    let header = needle.len();
    needle.extend(&body);
    memchr::memmem::find(bytes, &needle).map_or(0, |at| at + header)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const NIBARCHIVE: &[u8] = include_bytes!("../../tests/fixtures/dropper.nib");
    const KEYED: &[u8] = include_bytes!("../../tests/fixtures/dropper-keyed.nib");

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
        let literals: Vec<&str> = strings.literals.iter().map(|s| s.text.as_str()).collect();
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
            .find(|s| s.text == "Run Payload")
            .unwrap();
        assert_eq!(
            &NIBARCHIVE[run_payload.offset..run_payload.offset + 11],
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
        assert!(strings.literals.iter().all(|s| s.text != "NSCustomObject"));
        // Each literal's offset lands on its own bytes, so the short module
        // name is not confused with the front of the longer class name.
        for literal in &strings.literals {
            let end = literal.offset + literal.text.len();
            assert_eq!(
                &KEYED[literal.offset..end],
                literal.text.as_bytes(),
                "offset of {:?}",
                literal.text
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
        let mut cursor = Cursor {
            data: &[0x2c, 0x82, 0x81],
            pos: 0,
        };
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
}
