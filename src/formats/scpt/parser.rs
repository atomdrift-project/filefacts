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
//! Reference: <https://github.com/Jinmo/applescript-disassembler>
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

use std::fmt::Write as _;

use crate::bytes;

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
    /// Why the walk stopped early, if it did. The nodes already built stay
    /// usable: a truncated tree still yields the Apple Events, handlers and
    /// literals found before the stop, which is what an analyst needs from a
    /// sample that is malformed precisely so nothing can read it.
    pub truncated: Option<String>,
}

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_DATA: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 262_144;
const MAX_EDGES: usize = 1_048_576;
const MAX_DEPTH: usize = 65_536;
const REF_SLOTS: usize = 32_768;

/// An unfinished vector. Reference words remain borrowed from the input, so a
/// nested stream cannot allocate a second copy of every reference array.
struct Pending {
    node: usize,
    refs: usize,
    count: usize,
    next: usize,
}

/// Parse state over the stream. `input` is the read cursor; `bytes` is kept
/// only so the header can find the end of a shebang line.
struct Parser<'a> {
    bytes: &'a [u8],
    input: bytes::Reader<'a>,
    nodes: Vec<Node>,
    refs: Vec<Option<usize>>,
    pending: Vec<Pending>,
    data: usize,
    edges: usize,
}

/// Why a FAS stream could not be read. Renders as `FAS at <offset>: <reason>`.
#[derive(Debug)]
pub(super) enum ParseError {
    /// One of this parser's own ceilings, not a property of the file: the
    /// `input`, `object`, `owned data`, `edge` or `nesting` limit, rendered
    /// as `<limit> limit exceeded`.
    Budget { offset: usize, limit: &'static str },
    /// The stream is truncated or structurally invalid, or an allocation
    /// failed.
    Malformed { offset: usize, reason: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget { offset, limit } => {
                write!(f, "FAS at {offset:#x}: {limit} limit exceeded")
            }
            Self::Malformed { offset, reason } => write!(f, "FAS at {offset:#x}: {reason}"),
        }
    }
}

impl std::error::Error for ParseError {}

pub(super) fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    let mut parser = Parser::new(bytes)?;
    // A file that cannot produce a header or a root object is not a readable
    // FAS stream at all; there is nothing partial to hand back. Everything
    // after this point is recoverable.
    let version = parser.header()?;
    let root = parser.object(0)?;
    let mut truncated = None;
    while let Some(frame) = parser.pending.last_mut() {
        if frame.next == frame.count {
            parser.pending.pop();
            continue;
        }
        let parent = frame.node;
        let pos = frame.refs + frame.next * 2;
        frame.next += 1;
        // The entire reference slice was bounds-checked before queuing it.
        let Some(&id) = bytes.get(pos..).and_then(<[u8]>::first_chunk) else {
            return Err(parser.error("truncated reference"));
        };
        let id = i16::from_be_bytes(id);
        let child = match usize::try_from(id)
            .ok()
            .and_then(|id| parser.refs.get(id).copied().flatten())
        {
            Some(node) => node,
            None => match parser.object(id) {
                Ok(node) => node,
                // A budget we imposed is not the file's fault, and failing the
                // whole extraction over one handed an attacker a way to erase
                // every fact at once: exceed a ceiling anywhere and the
                // extractor reported nothing -- no events, no literals, no
                // handlers -- for a sample whose readable remainder is exactly
                // the evidence. Stop walking, keep what was built, and report
                // the reason through `scpt.limits`.
                //
                // Structural corruption still fails loudly. A stream that is
                // truncated or malformed is the file lying about its own
                // shape, and accepting an arbitrary prefix of one would make a
                // successful parse meaningless.
                Err(error @ ParseError::Budget { .. }) => {
                    truncated = Some(error.to_string());
                    break;
                }
                Err(error) => return Err(error),
            },
        };
        if let Some(Node {
            value: Value::Vector { items, .. },
            ..
        }) = parser.nodes.get_mut(parent)
        {
            // Capacity for every edge, including metadata, was reserved once.
            items.push(child);
        }
    }
    Ok(Parsed {
        nodes: parser.nodes,
        root,
        version,
        truncated,
    })
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() > MAX_INPUT {
            return Err(ParseError::Budget {
                offset: 0,
                limit: "input",
            });
        }
        let mut refs = Vec::new();
        refs.try_reserve_exact(REF_SLOTS)
            .map_err(|_| ParseError::Malformed {
                offset: 0,
                reason: "reference table allocation failed".into(),
            })?;
        refs.resize(REF_SLOTS, None);
        Ok(Self {
            bytes,
            input: bytes::Reader::new(bytes),
            nodes: Vec::new(),
            refs,
            pending: Vec::new(),
            data: 0,
            edges: 0,
        })
    }

    fn error(&self, reason: &str) -> ParseError {
        ParseError::Malformed {
            offset: self.input.pos(),
            reason: reason.into(),
        }
    }

    fn over_budget(&self, limit: &'static str) -> ParseError {
        ParseError::Budget {
            offset: self.input.pos(),
            limit,
        }
    }

    // A failed read leaves the cursor where it was, so every error below
    // reports the offset of the field that could not be read.
    fn take(&mut self, size: usize) -> Result<&'a [u8], ParseError> {
        if self.input.pos().checked_add(size).is_none() {
            return Err(self.error("size overflow"));
        }
        self.input
            .bytes(size)
            .ok_or_else(|| self.error("truncated input"))
    }

    // The position never passes the 64 MiB input cap, so a fixed-width read
    // cannot overflow it and running short is the only failure.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        self.input
            .array()
            .ok_or_else(|| self.error("truncated input"))
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        self.input.u8().ok_or_else(|| self.error("truncated input"))
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        self.input
            .u16_be()
            .ok_or_else(|| self.error("truncated input"))
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        self.input
            .u32_be()
            .ok_or_else(|| self.error("truncated input"))
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        self.input
            .u64_be()
            .ok_or_else(|| self.error("truncated input"))
    }

    fn header(&mut self) -> Result<String, ParseError> {
        if self.bytes.starts_with(b"#!") {
            let newline = self
                .bytes
                .iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| self.error("unterminated shebang"))?;
            self.input = bytes::Reader::at(self.bytes, newline + 1);
        }
        if self.array()? != *b"FasdUAS " {
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

    fn version_word(&mut self) -> Result<[u8; 4], ParseError> {
        match self.array()? {
            [major, b'.', minor, patch]
                if major.is_ascii_digit() && minor.is_ascii_digit() && patch.is_ascii_digit() =>
            {
                Ok([major, b'.', minor, patch])
            }
            _ => Err(self.error("malformed version word")),
        }
    }

    fn add(&mut self, offset: usize, value: Value) -> Result<usize, ParseError> {
        if self.nodes.len() >= MAX_NODES {
            return Err(self.over_budget("object"));
        }
        self.nodes
            .try_reserve(1)
            .map_err(|_| self.error("arena allocation failed"))?;
        let id = self.nodes.len();
        self.nodes.push(Node { offset, value });
        Ok(id)
    }

    fn charge_data(&mut self, size: usize) -> Result<(), ParseError> {
        if size > MAX_DATA - self.data {
            return Err(self.over_budget("owned data"));
        }
        self.data += size;
        Ok(())
    }

    fn payload(&mut self, tag: Option<u8>, size: usize) -> Result<Node, ParseError> {
        let offset = self.input.pos();
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
    ) -> Result<(), ParseError> {
        let total = count
            .checked_add(metadata.len())
            .ok_or_else(|| self.error("edge overflow"))?;
        if total > MAX_EDGES - self.edges {
            return Err(self.over_budget("edge"));
        }
        if count != 0 && self.pending.len() >= MAX_DEPTH {
            return Err(self.over_budget("nesting"));
        }
        let refs = self.input.pos();
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
        let Some(offset) = self.nodes.get(node).map(|n| n.offset) else {
            return Err(self.error("vector node out of range"));
        };
        for &value in metadata {
            items.push(self.add(offset, Value::Int(i64::from(value)))?);
        }
        if let Some(entry) = self.nodes.get_mut(node) {
            entry.value = Value::Vector { tag, items };
        }
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

    fn name(&mut self) -> Result<String, ParseError> {
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

    fn code_id(&mut self, size: usize) -> Result<Value, ParseError> {
        let tag = self.u8()?;
        match (tag, size) {
            (11, 8) => Ok(Value::Constant(self.u64()?)),
            (10 | 47, 4) => Ok(Value::Constant(u64::from(self.u32()?))),
            (46, 24) => {
                let bytes: [u8; 24] = self.array()?;
                const CAPACITY: usize = 8 * 4 + 1;
                self.charge_data(CAPACITY)?;
                let mut event = String::new();
                event
                    .try_reserve_exact(CAPACITY)
                    .map_err(|_| self.error("event allocation failed"))?;
                // The class and event FourCCs; the four remaining words are
                // not exposed.
                for fourcc in bytes.as_chunks::<4>().0.iter().take(2) {
                    if !event.is_empty() {
                        event.push('.');
                    }
                    for &b in fourcc {
                        if (b' '..=b'~').contains(&b) && b != b'.' && b != b'\\' {
                            event.push(char::from(b));
                        } else {
                            let _ = write!(event, "\\x{b:02x}");
                        }
                    }
                }
                Ok(Value::Event(event))
            }
            (10 | 11 | 46 | 47, _) => Err(self.error("invalid code identifier size")),
            _ => Err(self.error("unsupported code identifier tag")),
        }
    }

    fn object(&mut self, expected: i16) -> Result<usize, ParseError> {
        let offset = self.input.pos();
        let kind = self.u8()?;
        let reference = self.u16()? as i16;
        let size = usize::from(self.u16()?);
        if reference != expected {
            return Err(ParseError::Malformed {
                offset,
                reason: format!("reference mismatch: expected {expected}, found {reference}"),
            });
        }
        let node = self.add(offset, Value::Unknown)?;
        // Pre-register even an unfinished vector so back edges resolve. A
        // nonnegative 16-bit ID always has a slot.
        if let Ok(reference) = usize::try_from(reference)
            && let Some(slot) = self.refs.get_mut(reference)
        {
            *slot = Some(node);
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
                let payload = self.payload(None, size)?;
                if let Some(entry) = self.nodes.get_mut(node) {
                    *entry = payload;
                }
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
                if let Some(Node {
                    value: Value::Vector { items, .. },
                    ..
                }) = self.nodes.get(node)
                    && let &[a, b] = items.as_slice()
                {
                    if let Some(entry) = self.nodes.get_mut(a) {
                        *entry = text;
                    }
                    if let Some(entry) = self.nodes.get_mut(b) {
                        *entry = style;
                    }
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
                let payload = self.payload(tag, size)?;
                if let Some(entry) = self.nodes.get_mut(node) {
                    *entry = payload;
                }
                return Ok(node);
            }
            _ => {
                return Err(ParseError::Malformed {
                    offset,
                    reason: format!("unknown record kind {kind}"),
                });
            }
        };
        if let Some(entry) = self.nodes.get_mut(node) {
            entry.value = value;
        }
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
mod tests;
