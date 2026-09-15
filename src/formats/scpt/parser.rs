//! Bounded structural reader for the big-endian `FasdUAS ` stream.
//!
//! Runtime wrappers are unwrapped into an owned arena. Vector items are arena
//! indices (not FAS reference IDs); a runtime tag is separate from the items.
//! Typed data stays Bytes: runtimeobjects.String is tag 0, RawData/code is
//! 0x0d, and UnicodeText is 0xb1. Function code can also be an untyped block
//! (tag None); identify it by function slot 6, not by a required data tag.
//! No text scanning or bytecode interpretation.
//! Bytes offsets address their first payload byte; all other offsets address
//! the containing FAS record header, including synthetic metadata integers.
//!
//! Format conventions and limits:
//! - Optional shebang, then outer version; >= 1.10 has a second version word.
//!   Effective versions 0.98 through 1.10 are accepted. The effective version
//!   is returned. Only one root stream is read; trailing container data is
//!   ignored, as in the reference loader.
//! - Nonnegative signed-16-bit IDs are shared, negative IDs always load a new
//!   inline record. Unresolved references must match the next record exactly.
//!   All positive IDs are registered, including scalars. Vectors are registered
//!   before their children. Consumers must handle cycles in the returned graph.
//! - Lists are untagged [first, tail] vectors (empty list: []). Bindings are
//!   untagged [key, value, next] vectors (empty binding sizes 0 or 1: []). These preserve
//!   wire structure instead of reproducing bugs in the Python linked loaders.
//! - FAS string records are Vector(Some(0xb1), [text, style]); text is
//!   Bytes(Some(0xb1)), style is Bytes(None), with neither encoding decoded.
//!   These legacy text/style records can contain single-byte text. In contrast,
//!   runtime value blocks tagged 0xb1 generally refer to untyped UTF-16BE bytes.
//! - Command vectors contain [type_info, bytecode_start, bytecode_end, ...refs].
//! - Names select the alternate spelling if present, as the reference does.
//!   UTF-8 names are decoded directly; other bytes map reversibly to U+00xx
//!   (not a claim that the legacy encoding is Latin-1).
//! - Events contain the first two FourCCs as canonical class.event names (for
//!   example syso.exec). The remaining four descriptor words are consumed but
//!   not exposed by this API. Nonprintable bytes, '.' and '\\' use \\xNN escapes.
//! - Float records retain their eight bytes with no runtime tag. Application
//!   descriptors retain their complete typed payload, including the 94-byte
//!   descriptor header. Unknown runtime data tags are retained; unknown FAS
//!   record kinds are errors because their framing cannot safely be inferred.
//! - Limits: 64 MiB input, 32 MiB owned byte/string data, 262144 arena nodes,
//!   1048576 vector edges, 256 pending vectors, and 32768 reference slots.
//!   Parsing is iterative; neither parse nor drop recursively follows edges.
//!
//! Reference: https://github.com/Jinmo/applescript-disassembler
//! `engine/fasparser.py`, `engine/fasobjects/*`, `engine/runtimeobjects.py`.
//! Adapted from the reference's MIT-licensed format handling:
//!
//! MIT License
//! Copyright (c) 2017 Jinmo
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.

#[derive(Debug)]
pub(super) struct Node {
    pub offset: usize,
    pub value: Value,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Value {
    Vector { tag: Option<u8>, items: Vec<usize> },
    Bytes { tag: Option<u8>, data: Vec<u8> },
    Int(i64),
    Bool(bool),
    Name(String),
    Event(String),
    Constant(u64),
    Unknown,
}

#[derive(Debug)]
pub(super) struct Parsed {
    pub nodes: Vec<Node>,
    pub root: usize,
    pub version: String,
}

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_DATA: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 262_144;
const MAX_EDGES: usize = 1_048_576;
const MAX_DEPTH: usize = 256;
const REF_SLOTS: usize = 32_768;

/// An unfinished vector. Reference words remain borrowed from the input, so a
/// nested stream cannot allocate a second copy of every reference array.
struct Pending {
    node: usize,
    refs: usize,
    count: usize,
    next: usize,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: Vec<Node>,
    refs: Vec<Option<usize>>,
    pending: Vec<Pending>,
    data: usize,
    edges: usize,
}

pub(super) fn parse(bytes: &[u8]) -> Result<Parsed, String> {
    let mut reader = Reader::new(bytes)?;
    let version = reader.header()?;
    let root = reader.object(0)?;
    while let Some(frame) = reader.pending.last_mut() {
        if frame.next == frame.count {
            reader.pending.pop();
            continue;
        }
        let parent = frame.node;
        let pos = frame.refs + frame.next * 2;
        frame.next += 1;
        // The entire reference slice was bounds-checked before queuing it.
        let id = i16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let child = match usize::try_from(id).ok().and_then(|id| reader.refs[id]) {
            Some(node) => node,
            None => reader.object(id)?,
        };
        if let Value::Vector { items, .. } = &mut reader.nodes[parent].value {
            // Capacity for every edge, including metadata, was reserved once.
            items.push(child);
        }
    }
    Ok(Parsed {
        nodes: reader.nodes,
        root,
        version,
    })
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() > MAX_INPUT {
            return Err("FAS at 0x0: input limit exceeded".into());
        }
        let mut refs = Vec::new();
        refs.try_reserve_exact(REF_SLOTS)
            .map_err(|_| "FAS at 0x0: reference table allocation failed".to_string())?;
        refs.resize(REF_SLOTS, None);
        Ok(Self {
            bytes,
            pos: 0,
            nodes: Vec::new(),
            refs,
            pending: Vec::new(),
            data: 0,
            edges: 0,
        })
    }

    fn error(&self, message: &str) -> String {
        format!("FAS at {:#x}: {message}", self.pos)
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(size)
            .ok_or_else(|| self.error("size overflow"))?;
        let data = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| self.error("truncated input"))?;
        self.pos = end;
        Ok(data)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn header(&mut self) -> Result<String, String> {
        if self.bytes.starts_with(b"#!") {
            self.pos = self
                .bytes
                .iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| self.error("unterminated shebang"))?
                + 1;
        }
        if self.take(8)? != b"FasdUAS " {
            return Err(self.error("expected FasdUAS magic"));
        }
        let outer = self.version_word()?;
        let effective = if outer >= *b"1.10" {
            self.version_word()?
        } else {
            outer
        };
        if effective <= *b"0.97" || effective >= *b"1.11" {
            return Err(self.error("unsupported effective version"));
        }
        Ok(effective.iter().map(|&b| char::from(b)).collect())
    }

    fn version_word(&mut self) -> Result<[u8; 4], String> {
        let b = self.take(4)?;
        if !b[0].is_ascii_digit()
            || b[1] != b'.'
            || !b[2].is_ascii_digit()
            || !b[3].is_ascii_digit()
        {
            return Err(self.error("malformed version word"));
        }
        Ok([b[0], b[1], b[2], b[3]])
    }

    fn add(&mut self, offset: usize, value: Value) -> Result<usize, String> {
        if self.nodes.len() >= MAX_NODES {
            return Err(self.error("object limit exceeded"));
        }
        self.nodes
            .try_reserve(1)
            .map_err(|_| self.error("arena allocation failed"))?;
        let id = self.nodes.len();
        self.nodes.push(Node { offset, value });
        Ok(id)
    }

    fn charge_data(&mut self, size: usize) -> Result<(), String> {
        if size > MAX_DATA - self.data {
            return Err(self.error("owned data limit exceeded"));
        }
        self.data += size;
        Ok(())
    }

    fn payload(&mut self, tag: Option<u8>, size: usize) -> Result<Node, String> {
        let offset = self.pos;
        let bytes = self.take(size)?;
        self.charge_data(size)?;
        let mut data = Vec::new();
        data.try_reserve_exact(size)
            .map_err(|_| self.error("payload allocation failed"))?;
        data.extend_from_slice(bytes);
        Ok(Node {
            offset,
            value: Value::Bytes { tag, data },
        })
    }

    fn vector(
        &mut self,
        node: usize,
        tag: Option<u8>,
        count: usize,
        metadata: &[u16],
    ) -> Result<(), String> {
        let total = count
            .checked_add(metadata.len())
            .ok_or_else(|| self.error("edge overflow"))?;
        if total > MAX_EDGES - self.edges {
            return Err(self.error("edge limit exceeded"));
        }
        if count != 0 && self.pending.len() >= MAX_DEPTH {
            return Err(self.error("nesting limit exceeded"));
        }
        let refs = self.pos;
        self.take(
            count
                .checked_mul(2)
                .ok_or_else(|| self.error("reference size overflow"))?,
        )?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(total)
            .map_err(|_| self.error("vector allocation failed"))?;
        self.edges += total;
        for &value in metadata {
            items.push(self.add(self.nodes[node].offset, Value::Int(i64::from(value)))?);
        }
        self.nodes[node].value = Value::Vector { tag, items };
        if count != 0 {
            self.pending
                .try_reserve(1)
                .map_err(|_| self.error("pending allocation failed"))?;
            self.pending.push(Pending {
                node,
                refs,
                count,
                next: 0,
            });
        }
        Ok(())
    }

    fn name(&mut self) -> Result<String, String> {
        if self.u8()? != 48 {
            return Err(self.error("user identifier tag must be 48"));
        }
        let a_len = usize::from(self.u16()?);
        if a_len >= 256 {
            return Err(self.error("user identifier length exceeds 255"));
        }
        let a = self.take(a_len)?;
        let b_len = usize::from(self.u16()?);
        if b_len >= 256 {
            return Err(self.error("user identifier length exceeds 255"));
        }
        let b = self.take(b_len)?;
        let bytes = if b.is_empty() { a } else { b };
        let utf8 = std::str::from_utf8(bytes).ok();
        let capacity = if utf8.is_some() {
            bytes.len()
        } else {
            bytes.len() * 2
        };
        self.charge_data(capacity)?;
        let mut name = String::new();
        name.try_reserve_exact(capacity)
            .map_err(|_| self.error("name allocation failed"))?;
        match utf8 {
            Some(s) => name.push_str(s),
            None => name.extend(bytes.iter().map(|&b| char::from(b))),
        }
        Ok(name)
    }

    fn code_id(&mut self, size: usize) -> Result<Value, String> {
        let tag = self.u8()?;
        match (tag, size) {
            (11, 8) => Ok(Value::Constant(self.u64()?)),
            (10 | 47, 4) => Ok(Value::Constant(u64::from(self.u32()?))),
            (46, 24) => {
                let bytes = self.take(24)?;
                const CAPACITY: usize = 8 * 4 + 1;
                self.charge_data(CAPACITY)?;
                let mut event = String::new();
                event
                    .try_reserve_exact(CAPACITY)
                    .map_err(|_| self.error("event allocation failed"))?;
                for field in [0, 1] {
                    if !event.is_empty() {
                        event.push('.');
                    }
                    for &b in &bytes[field * 4..field * 4 + 4] {
                        if (b' '..=b'~').contains(&b) && b != b'.' && b != b'\\' {
                            event.push(char::from(b));
                        } else {
                            const HEX: &[u8; 16] = b"0123456789abcdef";
                            event.push_str("\\x");
                            event.push(char::from(HEX[usize::from(b >> 4)]));
                            event.push(char::from(HEX[usize::from(b & 15)]));
                        }
                    }
                }
                Ok(Value::Event(event))
            }
            (10 | 11 | 46 | 47, _) => Err(self.error("invalid code identifier size")),
            _ => Err(self.error("unsupported code identifier tag")),
        }
    }

    fn object(&mut self, expected: i16) -> Result<usize, String> {
        let offset = self.pos;
        let kind = self.u8()?;
        let reference = self.u16()? as i16;
        let size = usize::from(self.u16()?);
        if reference != expected {
            return Err(format!(
                "FAS at {offset:#x}: reference mismatch: expected {expected}, found {reference}"
            ));
        }
        let node = self.add(offset, Value::Unknown)?;
        if reference >= 0 {
            // Pre-register even an unfinished vector so back edges resolve.
            self.refs[reference as usize] = Some(node);
        }
        let value = match kind {
            1 if size == 0 => Value::Unknown, // NIL, not an unresolved edge.
            1 => Value::Constant(self.u64()?),
            2 | 6 => {
                let count = match (kind, size) {
                    (2, 0) | (6, 0 | 1) => 0,
                    (2, 2) | (6, 3) => size,
                    _ => return Err(self.error("invalid list or binding size")),
                };
                self.vector(node, None, count, &[])?;
                return Ok(node);
            }
            // osacompile emits -123 as FAS 3 / ff85, but 32768 and 65535 as
            // FAS 7 / signed i32. The reference Python loader misses this sign.
            3 => Value::Int(i64::from(size as i16)),
            4 | 14 => {
                let tag = self.u8()?;
                self.vector(node, Some(tag), size, &[])?;
                return Ok(node);
            }
            7 if size == 4 => Value::Int(i64::from(self.u32()? as i32)),
            8 if size == 8 => {
                self.nodes[node] = self.payload(None, size)?;
                return Ok(node);
            }
            7 | 8 => return Err(self.error("invalid integer or float size")),
            9 => Value::Bool(size != 0),
            10 => self.code_id(size)?,
            11 => Value::Name(self.name()?),
            12 => {
                // There is no runtime tag byte here: the two lengths frame
                // Unicode text and its style data. Do not use inline `size`.
                self.vector(node, Some(0xb1), 0, &[0, 0])?;
                let len = usize::from(self.u16()?);
                let text = self.payload(Some(0xb1), len)?;
                let len = usize::from(self.u16()?);
                let style = self.payload(None, len)?;
                if let Value::Vector { items, .. } = &self.nodes[node].value {
                    let (a, b) = (items[0], items[1]);
                    self.nodes[a] = text;
                    self.nodes[b] = style;
                }
                return Ok(node);
            }
            13 => {
                let tag = self.u8()?;
                let metadata = [self.u16()?, self.u16()?, self.u16()?];
                self.vector(node, Some(tag), size, &metadata)?;
                return Ok(node);
            }
            16 => {
                self.vector(node, None, size, &[])?;
                return Ok(node);
            }
            15 | 17 | 18 | 19 => {
                let tag = if matches!(kind, 15 | 18) {
                    Some(self.u8()?)
                } else {
                    None
                };
                let size = if matches!(kind, 18 | 19) {
                    usize::try_from(self.u32()?).map_err(|_| self.error("data size overflow"))?
                } else {
                    size
                };
                if kind == 15 && tag == Some(8) && size < 94 {
                    return Err(self.error("application descriptor shorter than 94 bytes"));
                }
                self.nodes[node] = self.payload(tag, size)?;
                return Ok(node);
            }
            _ => return Err(format!("FAS at {offset:#x}: unknown record kind {kind}")),
        };
        self.nodes[node].value = value;
        Ok(node)
    }
}

/// Portable end-to-end input for filefacts adapter/bytecode tests. Generated
/// with `osacompile -x` from this harmless script (compiled, never executed):
///
/// ```text
/// on greet(x)
///     return {x,-123,32767,32768,65535,"Hello World"}
/// end greet
/// return greet(1)
/// ```
///
/// Contains two functions, a name, an aevt.oapp event, UTF-16BE text, negative
/// short and positive long integers, literal pools, and untyped function code.
/// Tests can call `parser::test_fixture()` without macOS or external files.
#[cfg(test)]
pub(super) fn test_fixture() -> Vec<u8> {
    let hex = concat!(
        "4661736455415320312e3130312e31300e000000040ffffffffe0001000201ffff000001fffe00000e000100000f1000",
        "020004fffd00030004000501fffd00001000030002fffcfffb0bfffc0009300005677265657400000afffb00182e6165",
        "76746f6170706e756c6c00008000000090002a2a2a2a0e0004000710fffafff9fff8fff700060007fff60bfffa000930",
        "00056772656574000001fff900000efff8000204fff5000803fff500010e0008000100fff40bfff40005300001780000",
        "02fff700001000060001fff30bfff300053000017800001000070006fff2fff1fff0ffef0009ffee03fff2ff8503fff1",
        "7fff07fff000040000800007ffef00040000ffff0e00090001b1000a11000a001600480065006c006c006f0020005700",
        "6f0072006c006403ffee000611fff6000aa0e0e1e2e3e4e5760f0f0e0005000710ffedffecffebffea000b000cffe90a",
        "ffed00182e616576746f6170706e756c6c00008000000090002a2a2a2a01ffec000001ffeb000002ffea000010000b00",
        "0010000c0001ffe80bffe800093000056772656574000011ffe900082a6b6b2b00000f0f617363720001000cfadedead",
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("static fixture hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u8, id: i16, size: u16) -> Vec<u8> {
        let mut b = vec![kind];
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&size.to_be_bytes());
        b
    }

    fn stream(body: &[u8]) -> Vec<u8> {
        let mut b = b"FasdUAS 1.101.10".to_vec();
        b.extend_from_slice(body);
        b
    }

    fn vector(kind: u8, id: i16, tag: Option<u8>, refs: &[i16]) -> Vec<u8> {
        let mut b = header(kind, id, refs.len() as u16);
        b.extend(tag);
        for r in refs {
            b.extend_from_slice(&r.to_be_bytes());
        }
        b
    }

    fn items(parsed: &Parsed, node: usize) -> &[usize] {
        match &parsed.nodes[node].value {
            Value::Vector { items, .. } => items,
            value => panic!("expected vector, found {value:?}"),
        }
    }

    fn valid_offsets(parsed: &Parsed, bytes: &[u8]) {
        assert!(parsed.root < parsed.nodes.len());
        for node in &parsed.nodes {
            assert!(node.offset <= bytes.len());
            match &node.value {
                Value::Bytes { data, .. } => {
                    assert_eq!(
                        bytes.get(node.offset..node.offset + data.len()),
                        Some(data.as_slice())
                    );
                }
                Value::Vector { items, .. } => {
                    assert!(items.iter().all(|&i| i < parsed.nodes.len()))
                }
                _ => assert!(node.offset < bytes.len()),
            }
        }
    }

    fn assert_error(bytes: &[u8], message: &str) {
        let error = parse(bytes).unwrap_err();
        assert!(
            error.contains(message),
            "expected {message:?}, got {error:?}"
        );
        assert!(error.starts_with("FAS at 0x"));
    }

    fn code_blocks(p: &Parsed) -> Vec<usize> {
        p.nodes
            .iter()
            .filter_map(|n| match &n.value {
                Value::Vector {
                    tag: Some(16),
                    items,
                } if items.len() >= 7 => {
                    matches!(&p.nodes[items[6]].value, Value::Bytes { .. }).then_some(items[6])
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn portable_compiler_fixture_preserves_signedness_and_function_layout() {
        let bytes = test_fixture();
        let p = parse(&bytes).unwrap();
        valid_offsets(&p, &bytes);
        assert_eq!(code_blocks(&p).len(), 2);
        assert!(
            p.nodes
                .iter()
                .any(|n| n.value == Value::Name("greet".into()))
        );
        assert!(
            p.nodes
                .iter()
                .any(|n| n.value == Value::Event("aevt.oapp".into()))
        );
        for (value, kind) in [(-123, 3), (32767, 3), (32768, 7), (65535, 7)] {
            let n = p
                .nodes
                .iter()
                .find(|n| n.value == Value::Int(value))
                .unwrap();
            assert_eq!(bytes[n.offset], kind);
        }
        let expected: Vec<u8> = "Hello World"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        assert!(
            p.nodes.iter().any(|n| matches!(&n.value,
            Value::Vector { tag: Some(177), items }
            if matches!(&p.nodes[items[0]].value, Value::Bytes { data, .. } if data == &expected)))
        );
        let root = items(&p, p.root);
        let functions = items(&p, *root.last().unwrap());
        let function = items(&p, functions[2]);
        assert_eq!(p.nodes[function[0]].value, Value::Name("greet".into()));
        assert!(matches!(&p.nodes[function[2]].value, Value::Vector { .. }));
        let literals = items(&p, function[5]);
        assert_eq!(p.nodes[literals[0]].value, Value::Int(-123));
        assert!(
            matches!(&p.nodes[function[6]].value, Value::Bytes { tag: None, data } if !data.is_empty())
        );
    }

    #[test]
    fn short_integer_boundaries() {
        for value in [i16::MIN, -123, -1, 0, 1, i16::MAX] {
            let p = parse(&stream(&header(3, 0, value as u16))).unwrap();
            assert_eq!(p.nodes[0].value, Value::Int(i64::from(value)));
        }
    }

    #[test]
    fn versions_shebang_and_trailer() {
        for version in ["0.98", "0.99", "1.00", "1.09", "1.10"] {
            let mut b = b"#!/usr/bin/osascript\nFasdUAS ".to_vec();
            b.extend_from_slice(version.as_bytes());
            if version == "1.10" {
                b.extend_from_slice(version.as_bytes());
            }
            let start = b.len();
            b.extend(header(1, 0, 0));
            b.extend_from_slice(b"ascr\0\x01\0\x0c\xfa\xde\xde\xad");
            let p = parse(&b).unwrap();
            assert_eq!(p.version, version);
            assert_eq!(p.nodes[p.root].offset, start);
        }
        for bad in [b"FasdUAS 0.97".as_slice(), b"FasdUAS 1.101.11"] {
            assert_error(bad, "unsupported effective version");
        }
        for bad in [b"FasdUAS x.xx".as_slice(), b"FasdUAS 1.101.x0"] {
            assert_error(bad, "malformed version");
        }
        assert_error(b"#!unterminated", "unterminated shebang");
        assert_error(b"not a script", "magic");
    }

    #[test]
    fn unknown_and_invalid_framing() {
        assert_error(&stream(&header(5, 0, 0)), "unknown record kind");
        for (kind, size) in [(2, 1), (6, 4), (6, 2), (7, 8), (8, 4)] {
            assert_error(&stream(&header(kind, 0, size)), "invalid");
        }
        let mut b = header(15, 0, 93);
        b.push(8);
        assert_error(&stream(&b), "descriptor shorter");
        for (tag, size) in [(11, 7), (10, 8), (47, 24), (46, 4), (255, 0)] {
            let mut b = header(10, 0, size);
            b.push(tag);
            assert_error(&stream(&b), "code identifier");
        }
    }

    #[test]
    fn mismatched_missing_and_extreme_references() {
        assert_error(&stream(&header(1, 1, 0)), "reference mismatch");
        for id in [-32768, -1, 1, 32767] {
            let mut b = vector(16, 0, None, &[id]);
            assert_error(&stream(&b), "truncated");
            b.extend(header(1, id, 0));
            let p = parse(&stream(&b)).unwrap();
            assert_eq!(p.nodes.len(), 2);
        }
        let mut b = vector(16, 0, None, &[7]);
        b.extend(header(1, 8, 0));
        assert_error(&stream(&b), "expected 7, found 8");
        // Reusing a negative ID still requires a new record at each use.
        let mut b = vector(16, 0, None, &[-1, -1]);
        b.extend(header(1, -1, 0));
        assert_error(&stream(&b), "truncated");
    }

    #[test]
    fn list_and_binding_chains_and_cycles() {
        for (kind, empty_size, count) in [(2, 0, 2), (6, 0, 3), (6, 1, 3)] {
            let mut refs = vec![-1; count];
            refs[count - 1] = 1;
            let mut b = vector(kind, 0, None, &refs);
            for _ in 0..count - 1 {
                b.extend(header(3, -1, 42));
            }
            b.extend(header(kind, 1, empty_size));
            let p = parse(&stream(&b)).unwrap();
            assert_eq!(items(&p, 0).len(), count);
            assert!(items(&p, *items(&p, 0).last().unwrap()).is_empty());
            let p = parse(&stream(&vector(kind, 0, None, &vec![0; count]))).unwrap();
            assert_eq!(items(&p, 0), vec![0; count]);
        }
        // A binding tail may be another object kind, not only an empty binding.
        let mut b = vector(6, 0, None, &[0, 0, -1]);
        b.extend(header(1, -1, 0));
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(items(&p, 0), [0, 0, 1]);
        assert_eq!(p.nodes[1].value, Value::Unknown);
    }

    #[test]
    fn names_choose_alternate_and_preserve_non_utf8_bytes() {
        for (a, b, expected) in [
            (b"name".as_slice(), b"".as_slice(), "name"),
            (b"name", b"Name", "Name"),
            (&[0x80, 0xff], b"", "\u{80}\u{ff}"),
        ] {
            let mut data = header(11, 0, 0);
            data.push(48);
            data.extend_from_slice(&(a.len() as u16).to_be_bytes());
            data.extend_from_slice(a);
            data.extend_from_slice(&(b.len() as u16).to_be_bytes());
            data.extend_from_slice(b);
            let data = stream(&data);
            let p = parse(&data).unwrap();
            assert_eq!(p.nodes[0].value, Value::Name(expected.into()));
            assert_eq!(p.nodes[0].offset, 16);
            for cut in 16..data.len() {
                assert_error(&data[..cut], "truncated");
            }
        }
        let mut b = header(11, 0, 0);
        b.extend_from_slice(&[48, 1, 0]);
        assert_error(&stream(&b), "length exceeds");
        let mut b = header(11, 0, 0);
        b.push(0);
        assert_error(&stream(&b), "tag must be 48");
    }

    #[test]
    fn events_constants_integers_and_floats() {
        let mut b = header(10, 0, 24);
        b.push(46);
        b.extend_from_slice(b"aaaaBBBBccccDDDDeeeeFFFF");
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(p.nodes[0].value, Value::Event("aaaa.BBBB".into()));
        b[6] = b'.';
        b[7] = 0;
        b[8] = b'\\';
        b[9] = 0xff;
        let p = parse(&stream(&b)).unwrap();
        assert_eq!(
            p.nodes[0].value,
            Value::Event("\\x2e\\x00\\x5c\\xff.BBBB".into())
        );
        for tag in [10, 11, 47] {
            let size = if tag == 11 { 8 } else { 4 };
            let mut b = header(10, 0, size);
            b.push(tag);
            b.extend(vec![0xff; usize::from(size)]);
            let p = parse(&stream(&b)).unwrap();
            assert_eq!(
                p.nodes[0].value,
                Value::Constant(if tag == 11 {
                    u64::MAX
                } else {
                    u64::from(u32::MAX)
                })
            );
        }
        let mut b = header(1, 0, 1);
        b.extend_from_slice(&123_u64.to_be_bytes());
        assert_eq!(
            parse(&stream(&b)).unwrap().nodes[0].value,
            Value::Constant(123)
        );
        let mut b = header(7, 0, 4);
        b.extend_from_slice(&i32::MIN.to_be_bytes());
        assert_eq!(
            parse(&stream(&b)).unwrap().nodes[0].value,
            Value::Int(i64::from(i32::MIN))
        );
        let mut b = header(8, 0, 8);
        b.extend_from_slice(&f64::NAN.to_be_bytes());
        let b = stream(&b);
        let p = parse(&b).unwrap();
        assert!(matches!(&p.nodes[0].value, Value::Bytes { tag: None, data } if data.len() == 8));
        valid_offsets(&p, &b);
    }

    #[test]
    fn unicode_text_and_style_and_command_metadata() {
        let mut b = header(12, 0, 0);
        b.extend_from_slice(&[0, 4, 0, b'H', 0, b'i', 0, 2, 0xaa, 0xbb]);
        let b = stream(&b);
        let p = parse(&b).unwrap();
        assert_eq!(
            p.nodes[0].value,
            Value::Vector {
                tag: Some(177),
                items: vec![1, 2]
            }
        );
        assert_eq!(p.nodes[1].offset, 23);
        assert_eq!(p.nodes[2].offset, 29);
        valid_offsets(&p, &b);
        for cut in 0..b.len() {
            assert!(parse(&b[..cut]).is_err());
        }
        let mut b = header(13, 0, 1);
        b.extend_from_slice(&[0x6c, 0, 7, 0, 10, 0, 20, 0, 0]);
        let b = stream(&b);
        let p = parse(&b).unwrap();
        assert_eq!(
            p.nodes[0].value,
            Value::Vector {
                tag: Some(0x6c),
                items: vec![1, 2, 3, 0]
            }
        );
        for (i, value) in [(1, 7), (2, 10), (3, 20)] {
            assert_eq!(p.nodes[i].value, Value::Int(value));
            assert_eq!(p.nodes[i].offset, 16);
        }
        valid_offsets(&p, &b);
    }

    #[test]
    fn nesting_is_bounded_without_recursive_stack_use() {
        let mut b = vector(16, 0, None, &[-1]);
        for _ in 1..MAX_DEPTH {
            b.extend(vector(16, -1, None, &[-1]));
        }
        let mut valid = b.clone();
        valid.extend(header(1, -1, 0));
        let p = parse(&stream(&valid)).unwrap();
        assert_eq!(p.nodes.len(), MAX_DEPTH + 1);
        b.extend(vector(16, -1, None, &[-1]));
        b.extend(header(1, -1, 0));
        assert_error(&stream(&b), "nesting limit");
    }

    #[test]
    fn oversized_and_truncated_long_data() {
        for kind in [18, 19] {
            let mut b = header(kind, 0, 0);
            if kind == 18 {
                b.push(0);
            }
            b.extend_from_slice(&u32::MAX.to_be_bytes());
            assert_error(&stream(&b), "truncated");
        }
        let mut b = stream(&header(19, 0, 0));
        b.extend_from_slice(&((MAX_DATA + 1) as u32).to_be_bytes());
        b.resize(b.len() + MAX_DATA + 1, 0);
        assert_error(&b, "owned data limit");
        b.resize(MAX_INPUT + 1, 0);
        assert_error(&b, "input limit");
    }

    #[test]
    fn aggregate_edges_are_bounded_even_when_all_shared() {
        let mut b = vector(16, 0, None, &[-1; 17]);
        for _ in 0..17 {
            b.extend(vector(16, -1, None, &vec![0; 65535]));
        }
        assert_error(&stream(&b), "edge limit");
    }

    #[test]
    fn object_count_is_bounded_even_for_tiny_inline_scalars() {
        let mut b = vector(16, 0, None, &[-1; 4]);
        for _ in 0..4 {
            b.extend(vector(16, -1, None, &vec![-1; 65535]));
            for _ in 0..65535 {
                b.extend(header(1, -1, 0));
            }
        }
        assert_error(&stream(&b), "object limit");
    }

    #[test]
    fn shared_and_negative_inline_references() {
        let mut b = vector(14, 0, Some(15), &[1, 1, -1, -1]);
        b.extend(header(3, 1, 65535));
        b.extend(header(9, -1, 1));
        b.extend(header(9, -1, 0));
        let b = stream(&b);
        let p = parse(&b).unwrap();
        assert_eq!(p.nodes.len(), 4);
        assert_eq!(items(&p, p.root), [1, 1, 2, 3]);
        assert_eq!(p.nodes[1].value, Value::Int(-1));
        assert_eq!(p.nodes[2].value, Value::Bool(true));
        assert_eq!(p.nodes[3].value, Value::Bool(false));
        valid_offsets(&p, &b);
    }

    #[test]
    fn self_and_mutual_cycles() {
        for kind in [4, 14, 16] {
            let tag = (kind != 16).then_some(15);
            let b = stream(&vector(kind, 0, tag, &[0]));
            let p = parse(&b).unwrap();
            assert_eq!(items(&p, 0), [0]);
            let mut b = vector(kind, 0, tag, &[1]);
            b.extend(vector(kind, 1, tag, &[0]));
            let p = parse(&stream(&b)).unwrap();
            assert_eq!(items(&p, 0), [1]);
            assert_eq!(items(&p, 1), [0]);
        }
    }

    #[test]
    fn bytes_keep_tags_and_payload_offsets() {
        for (kind, tag) in [
            (15, Some(0)),
            (15, Some(13)),
            (15, Some(0xfe)),
            (17, None),
            (18, Some(13)),
            (19, None),
        ] {
            let mut b = header(kind, 0, 3);
            b.extend(tag);
            if kind >= 18 {
                b.extend_from_slice(&3_u32.to_be_bytes());
            }
            let offset = 16 + b.len();
            b.extend_from_slice(&[0, 0xff, 0x42]);
            let b = stream(&b);
            let p = parse(&b).unwrap();
            assert_eq!(p.nodes[0].offset, offset);
            assert_eq!(
                p.nodes[0].value,
                Value::Bytes {
                    tag,
                    data: vec![0, 0xff, 0x42]
                }
            );
            valid_offsets(&p, &b);
            for cut in 0..b.len() {
                assert!(parse(&b[..cut]).is_err(), "kind {kind}, cut {cut}");
            }
        }
    }

    #[test]
    fn real_sample() {
        let bytes = include_bytes!("../../../tests/fixtures/stage4.scpt");
        let p = parse(bytes).unwrap();
        assert_eq!(p.version, "1.10");
        valid_offsets(&p, bytes);
        let code = code_blocks(&p).len();
        let names = p
            .nodes
            .iter()
            .filter(|n| matches!(&n.value, Value::Name(_)))
            .count();
        assert!(code > 0 && names > 0);
        assert_eq!(p.nodes.len(), 10677);
        assert_eq!(code, 48);
        assert_eq!(names, 1509);
        println!(
            "sample: {} bytes, {} nodes, {} function code blocks, {} names",
            bytes.len(),
            p.nodes.len(),
            code,
            names
        );
        // The sample ends with a 12-byte container trailer, outside the root.
        let end = p
            .nodes
            .iter()
            .filter_map(|n| match &n.value {
                Value::Bytes { data, .. } => Some(n.offset + data.len()),
                _ => None,
            })
            .max()
            .unwrap();
        assert_eq!(end, bytes.len() - 12);
        assert!(parse(&bytes[..end]).is_ok());
        for cut in (0..end).step_by(end.div_ceil(256)).chain([end - 1]) {
            assert!(
                parse(&bytes[..cut]).is_err(),
                "accepted truncated sample at {cut}"
            );
        }
    }

    #[test]
    fn real_compiled_fixtures() {
        let Some(dir) = std::env::var_os("SCPT_FIXTURES") else {
            return;
        };
        for (file, nodes, literal, event) in [
            ("simple.scpt", 143, "Hello World", "syso.dlog"),
            ("shell_script.scpt", 219, "whoami", "syso.exec"),
            ("tell_app.scpt", 174, "", "core.cnte"),
        ] {
            let bytes = std::fs::read(std::path::Path::new(&dir).join(file)).unwrap();
            let p = parse(&bytes).unwrap();
            assert_eq!(p.nodes.len(), nodes, "{file}");
            assert_eq!(code_blocks(&p).len(), 1, "{file}");
            assert!(
                p.nodes
                    .iter()
                    .any(|n| matches!(&n.value, Value::Event(e) if e.starts_with(event)))
            );
            if !literal.is_empty() {
                let expected: Vec<u8> = literal.encode_utf16().flat_map(u16::to_be_bytes).collect();
                assert!(p.nodes.iter().any(|n| matches!(&n.value,
                    Value::Vector { tag: Some(177), items }
                    if matches!(&p.nodes[items[0]].value, Value::Bytes { data, .. } if data == &expected))));
            }
            valid_offsets(&p, &bytes);
            // Validate complete stream consumption separately from its trailer.
            // Public parse already checks graph structure; code ends the root
            // in these compiler fixtures, making its last byte a useful bound.
            let code = &p.nodes[code_blocks(&p)[0]];
            let Value::Bytes { data, .. } = &code.value else {
                unreachable!()
            };
            let end = code.offset + data.len();
            assert!(parse(&bytes[..end]).is_ok());
            for cut in (0..end).step_by(end.div_ceil(128)).chain([end - 1]) {
                assert!(parse(&bytes[..cut]).is_err(), "{file}: prefix {cut}");
            }
            println!(
                "{file}: {} bytes, {nodes} nodes; sampled prefixes before {end} rejected",
                bytes.len()
            );
        }
    }

    #[test]
    fn deterministic_mutations_do_not_panic_or_make_invalid_edges() {
        let mut base = vector(14, 0, Some(177), &[1, 1, 0, -1]);
        base.extend(header(17, 1, 4));
        base.extend_from_slice(&[0, b'o', 0, b'k']);
        base.extend(header(3, -1, 42));
        let base = stream(&base);
        let mut state = 0x0ace_5eed_u32;
        for _ in 0..2048 {
            let mut b = base.clone();
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let at = state as usize % b.len();
            b[at] ^= (state >> 16) as u8;
            if let Ok(p) = parse(&b) {
                valid_offsets(&p, &b);
            }
        }
    }

    #[test]
    fn installed_compiled_corpus() {
        let Some(dir) = std::env::var_os("SCPT_CORPUS") else {
            return;
        };
        let mut dirs = vec![std::path::PathBuf::from(dir)];
        let mut files = Vec::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    dirs.push(entry.path());
                } else if kind.is_file() && entry.path().extension().is_some_and(|e| e == "scpt") {
                    files.push(entry.path());
                }
            }
        }
        assert!(!files.is_empty());
        files.sort();
        for path in &files {
            let bytes = std::fs::read(path).unwrap();
            let p = parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            valid_offsets(&p, &bytes);
            assert!(!code_blocks(&p).is_empty(), "{}", path.display());
        }
        println!("installed corpus: {} compiled scripts passed", files.len());
    }
}
