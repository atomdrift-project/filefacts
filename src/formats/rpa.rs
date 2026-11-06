//! Ren'Py archives (RPA-2.0 and RPA-3.0): a bounded, inert reader for the
//! archive index, and the facts drawn from it.
//!
//! The index is zlib-compressed pickle. This module interprets only the
//! primitive container opcodes needed for the archive directory; it never
//! imports Python globals or constructs Python objects.

use std::collections::HashMap;
use std::io::Cursor;

use flate2::bufread::ZlibDecoder;
use serde_json::{Value as JsonValue, json};
use sha2::Digest;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, member_value};
use super::bounded::{MAX_ARCHIVE_MEMBERS, OnError, inflate_capped};
use super::common::hex_encode;
use super::pickle::ops::{self, Arg};
use crate::error::Error;
use crate::output::{ArchiveCompression, ArchiveMember, EntryType, Metrics, Values};
use crate::scan::entropy::shannon;
use crate::{metric, value_key};

fn sha256(bytes: &[u8]) -> String {
    hex_encode(&sha2::Sha256::digest(bytes))
}

const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const MAX_STACK: usize = 1_000_000;
/// Bytes of one member path; a longer one marks the index as forged.
const MAX_MEMBER_PATH_BYTES: usize = 4 * 1024;

/// Fixed RPA header fields, before interpreting the compressed index.
#[derive(Debug, Clone, Copy)]
struct Header {
    /// Archive format version (2 or 3).
    version: u8,
    /// Absolute byte offset of the zlib-compressed index.
    index_offset: u64,
    /// Version 3 XOR key; zero for version 2.
    key: u64,
    /// Size of the fixed header in bytes.
    header_size: usize,
}

/// One physical payload run, optionally preceded by bytes stored in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Chunk {
    /// Absolute byte offset of the physical run.
    pub offset: u64,
    /// Length of the physical run.
    pub length: u64,
    /// Bytes to prepend before the physical run.
    pub prefix: Vec<u8>,
}

/// One logical file named in the archive index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Member {
    /// Member name after UTF-8 or Latin-1 decoding. Archive-chosen: a host
    /// writing members to disk must sanitize it.
    pub path: String,
    /// Ordered physical runs making up the logical file.
    pub chunks: Vec<Chunk>,
    /// Reconstructed member size, including index-stored prefixes.
    pub size: u64,
}

/// The members a Ren'Py archive's index names, for a host that carves them
/// out: each is its index-stored prefix bytes followed by its physical runs,
/// in order. The pickled index is decoded as inert data under the same
/// bounds the extractor uses; nothing in it is executed.
///
/// # Errors
///
/// [`Error::Malformed`] when the header or index does not parse or exceeds a
/// bound.
pub fn members(bytes: &[u8]) -> Result<Vec<Member>, Error> {
    let header = parse_header(bytes)?;
    Ok(parse_index(bytes, &header)?.members)
}

/// Decoded index and forensic properties of its compressed pickle stream.
struct Index {
    /// Members in index order, after Python dictionary overwrite semantics.
    members: Vec<Member>,
    /// Declared pickle protocol, if a PROTO opcode was present.
    pickle_protocol: Option<u8>,
    /// Number of pickle opcodes interpreted.
    pickle_opcode_count: usize,
    /// Number of memo slots populated.
    pickle_memo_count: usize,
    /// Number of FRAME opcodes.
    pickle_frame_count: usize,
    /// Number of repeated key assignments in the pickle dictionary.
    duplicate_key_assignment_count: usize,
    /// Size of the zlib stream, excluding trailing bytes.
    compressed_index_size: usize,
    /// Bytes after the zlib stream, ignored by Ren'Py's decompressor.
    trailing_bytes: usize,
    /// Size of the decompressed pickle index.
    uncompressed_index_size: usize,
    /// SHA-256 of the compressed index bytes.
    compressed_index_sha256: String,
    /// SHA-256 of bytes after the zlib stream, when present.
    trailing_sha256: Option<String>,
    /// SHA-256 of the decompressed pickle bytes.
    index_sha256: String,
    /// Shannon entropy of the compressed zlib stream, in bits per byte.
    compressed_entropy: f64,
    /// Shannon entropy of the decompressed pickle stream, in bits per byte.
    index_entropy: f64,
}

fn bad(message: &'static str) -> Error {
    Error::malformed("rpa", message)
}

/// A hexadecimal header field.
fn hex_field(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(bad("invalid hexadecimal header field"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad("invalid header text"))?;
    u64::from_str_radix(text, 16).map_err(|_| bad("header number overflow"))
}

/// Parse only the fixed RPA header, rejecting unsupported, truncated or
/// invalid headers and index offsets outside the archive. The index itself
/// may still be damaged.
fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    let (version, header_size, key) = if bytes.starts_with(b"RPA-3.0 ") {
        let h = bytes.get(..34).ok_or_else(|| bad("truncated v3 header"))?;
        if h.get(24) != Some(&b' ') || h.get(33) != Some(&b'\n') {
            return Err(bad("invalid v3 header separators"));
        }
        (
            3,
            34,
            hex_field(h.get(25..33).ok_or_else(|| bad("truncated v3 key"))?)?,
        )
    } else if bytes.starts_with(b"RPA-2.0 ") {
        let h = bytes.get(..25).ok_or_else(|| bad("truncated v2 header"))?;
        if h.get(24) != Some(&b'\n') {
            return Err(bad("invalid v2 header terminator"));
        }
        (2, 25, 0)
    } else {
        return Err(bad("unsupported header"));
    };
    let index_offset = hex_field(
        bytes
            .get(8..24)
            .ok_or_else(|| bad("truncated index offset"))?,
    )?;
    if index_offset < header_size as u64 || index_offset >= bytes.len() as u64 {
        return Err(bad("index offset outside archive"));
    }
    Ok(Header {
        version,
        index_offset,
        key,
        header_size,
    })
}

enum Node {
    Mark,
    Null,
    Int(i128),
    Bytes(Vec<u8>),
    Text(Vec<u8>),
    Seq(Vec<usize>),
    Dict(Vec<(usize, usize)>),
}

struct Pickle<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: Vec<Node>,
    stack: Vec<usize>,
    marks: Vec<usize>,
    memo: HashMap<usize, usize>,
    next_memo: usize,
    protocol: Option<u8>,
    opcodes: usize,
    frames: usize,
}

impl<'a> Pickle<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            nodes: Vec::new(),
            stack: Vec::new(),
            marks: Vec::new(),
            memo: HashMap::new(),
            next_memo: 0,
            protocol: None,
            opcodes: 0,
            frames: 0,
        }
    }

    fn node(&mut self, node: Node) -> Result<usize, Error> {
        if self.nodes.len() >= MAX_NODES {
            return Err(bad("pickle node limit exceeded"));
        }
        let id = self.nodes.len();
        self.nodes.push(node);
        Ok(id)
    }

    fn push(&mut self, id: usize) -> Result<(), Error> {
        if self.stack.len() >= MAX_STACK {
            return Err(bad("pickle stack limit exceeded"));
        }
        self.stack.push(id);
        Ok(())
    }

    fn add(&mut self, node: Node) -> Result<(), Error> {
        let id = self.node(node)?;
        self.push(id)
    }

    fn node_mut(&mut self, id: usize) -> Result<&mut Node, Error> {
        self.nodes
            .get_mut(id)
            .ok_or_else(|| bad("invalid pickle node"))
    }

    fn is_mark(&self, id: usize) -> Result<bool, Error> {
        let node = self
            .nodes
            .get(id)
            .ok_or_else(|| bad("invalid pickle node"))?;
        Ok(matches!(node, Node::Mark))
    }

    fn pop(&mut self) -> Result<usize, Error> {
        let id = self
            .stack
            .pop()
            .ok_or_else(|| bad("pickle stack underflow"))?;
        if self.is_mark(id)? {
            self.marks.pop();
        }
        Ok(id)
    }

    fn top(&self) -> Result<usize, Error> {
        self.stack
            .last()
            .copied()
            .ok_or_else(|| bad("pickle stack underflow"))
    }

    fn after_mark(&mut self) -> Result<Vec<usize>, Error> {
        let mark = *self
            .marks
            .last()
            .ok_or_else(|| bad("missing pickle MARK"))?;
        if mark >= self.stack.len() {
            return Err(bad("pickle MARK outside the stack"));
        }
        let items = self.stack.split_off(mark + 1);
        self.pop()?;
        Ok(items)
    }

    fn put(&mut self, n: usize) -> Result<(), Error> {
        if n >= MAX_NODES {
            return Err(bad("pickle memo index exceeds limit"));
        }
        let id = self.top()?;
        if self.is_mark(id)? {
            return Err(bad("cannot memoize MARK"));
        }
        self.memo.insert(n, id);
        self.next_memo = self.next_memo.max(n + 1);
        Ok(())
    }

    fn get(&mut self, n: usize) -> Result<(), Error> {
        let id = *self
            .memo
            .get(&n)
            .ok_or_else(|| bad("missing pickle memo entry"))?;
        if self.is_mark(id)? {
            return Err(bad("memo refers to MARK"));
        }
        self.push(id)
    }

    fn parse(mut self) -> Result<(Self, usize), Error> {
        loop {
            let (op, next) = ops::decode(self.bytes, self.pos).map_err(|e| match e {
                ops::DecodeError::Truncated => bad("truncated pickle"),
                ops::DecodeError::Unknown(code) => Error::malformed(
                    "rpa",
                    format!("unsupported or executable pickle opcode 0x{code:02x}"),
                ),
            })?;
            self.pos = next;
            self.opcodes += 1;
            if self.opcodes > MAX_NODES {
                return Err(bad("pickle opcode limit exceeded"));
            }
            // Each operand's width is the decoder's; only the integer ones
            // need narrowing back to the opcode's own type.
            let int = || match op.arg {
                Arg::Int(n) => usize::try_from(n).map_err(|_| bad("pickle operand overflow")),
                _ => Err(bad("missing pickle operand")),
            };
            match (op.code, op.arg) {
                (0x80, Arg::Int(version)) => {
                    let version =
                        u8::try_from(version).map_err(|_| bad("unsupported pickle protocol"))?;
                    if version > 5 {
                        return Err(bad("unsupported pickle protocol"));
                    }
                    self.protocol = Some(version);
                }
                (0x95, _) => self.frames += 1,
                (b'.', _) => {
                    let root = self.pop()?;
                    if !self.stack.is_empty() {
                        return Err(bad("pickle stack has trailing values"));
                    }
                    if self.pos != self.bytes.len() {
                        return Err(bad("trailing pickle data"));
                    }
                    return Ok((self, root));
                }
                (b'(', _) => {
                    self.add(Node::Mark)?;
                    self.marks.push(self.stack.len() - 1);
                }
                (b'N', _) => self.add(Node::Null)?,
                (b'}', _) => self.add(Node::Dict(Vec::new()))?,
                (b']' | b')', _) => self.add(Node::Seq(Vec::new()))?,
                (b'K' | b'M', Arg::Int(n)) => self.add(Node::Int(i128::from(n)))?,
                (b'J', Arg::Int(n)) => {
                    let n = u32::try_from(n).map_err(|_| bad("pickle operand overflow"))?;
                    self.add(Node::Int(i128::from(n.cast_signed())))?;
                }
                (b'I' | b'L', Arg::Line(line)) => {
                    let text = std::str::from_utf8(line)
                        .map_err(|_| bad("invalid pickle integer"))?
                        .trim_end_matches('L');
                    let n = text.parse().map_err(|_| bad("invalid pickle integer"))?;
                    self.add(Node::Int(n))?;
                }
                (0x8a | 0x8b, Arg::Bytes(raw)) => {
                    if raw.len() > 16 {
                        return Err(bad("pickle integer exceeds 128 bits"));
                    }
                    let mut bytes = [0u8; 16];
                    if raw.last().is_some_and(|b| b & 0x80 != 0) {
                        bytes.fill(0xff);
                    }
                    bytes
                        .get_mut(..raw.len())
                        .ok_or_else(|| bad("pickle integer exceeds 128 bits"))?
                        .copy_from_slice(raw);
                    self.add(Node::Int(i128::from_le_bytes(bytes)))?;
                }
                (0x8c | b'X' | 0x8d, Arg::Bytes(text)) => self.add(Node::Text(text.to_vec()))?,
                (b'U' | b'C' | b'T' | b'B' | 0x8e, Arg::Bytes(bytes)) => {
                    self.add(Node::Bytes(bytes.to_vec()))?;
                }
                (b'V', Arg::Line(text)) => self.add(Node::Text(text.to_vec()))?,
                (b'S', Arg::Line(line)) => {
                    let bytes = parse_quoted(line)?;
                    self.add(Node::Bytes(bytes))?;
                }
                (b'q' | b'r', _) => self.put(int()?)?,
                (b'p', Arg::Line(line)) => self.put(parse_decimal(line)?)?,
                (b'h' | b'j', _) => self.get(int()?)?,
                (b'g', Arg::Line(line)) => self.get(parse_decimal(line)?)?,
                (0x94, _) => {
                    let n = self.next_memo;
                    self.put(n)?;
                }
                (b't' | b'l' | b'd', _) => {
                    let items = self.after_mark()?;
                    if op.code == b'd' {
                        self.add(Node::Dict(pairs(&items)?))?;
                    } else {
                        self.add(Node::Seq(items))?;
                    }
                }
                (0x85..=0x87, _) => {
                    // A MARK starts a new stack in Python, so TUPLEn may not
                    // reach below the innermost one.
                    let count = usize::from(op.code - 0x84);
                    let floor = self.marks.last().map_or(0, |&mark| mark + 1);
                    if self.stack.len() < floor + count {
                        return Err(bad("pickle stack underflow"));
                    }
                    let items = self.stack.split_off(self.stack.len() - count);
                    self.add(Node::Seq(items))?;
                }
                (b'a', _) => {
                    let item = self.pop()?;
                    let list = self.top()?;
                    match self.node_mut(list)? {
                        Node::Seq(items) => items.push(item),
                        _ => return Err(bad("APPEND target is not a list")),
                    }
                }
                (b'e', _) => {
                    let items = self.after_mark()?;
                    let list = self.top()?;
                    match self.node_mut(list)? {
                        Node::Seq(seq) => seq.extend(items),
                        _ => return Err(bad("APPENDS target is not a list")),
                    }
                }
                (b's', _) => {
                    let value = self.pop()?;
                    let key = self.pop()?;
                    let dict = self.top()?;
                    match self.node_mut(dict)? {
                        Node::Dict(items) => items.push((key, value)),
                        _ => return Err(bad("SETITEM target is not a dict")),
                    }
                }
                (b'u', _) => {
                    let items = pairs(&self.after_mark()?)?;
                    let dict = self.top()?;
                    match self.node_mut(dict)? {
                        Node::Dict(entries) => entries.extend(items),
                        _ => return Err(bad("SETITEMS target is not a dict")),
                    }
                }
                (b'2', _) => {
                    let id = self.top()?;
                    if self.is_mark(id)? {
                        return Err(bad("cannot duplicate MARK"));
                    }
                    self.push(id)?;
                }
                (b'0', _) => {
                    self.pop()?;
                }
                (b'1', _) => {
                    self.after_mark()?;
                }
                // GLOBAL, REDUCE, BUILD, persistent IDs, extension registries,
                // object constructors and floats are rejected.
                (code, _) => {
                    return Err(Error::malformed(
                        "rpa",
                        format!("unsupported or executable pickle opcode 0x{code:02x}"),
                    ));
                }
            }
        }
    }
}

fn parse_decimal(bytes: &[u8]) -> Result<usize, Error> {
    std::str::from_utf8(bytes)
        .map_err(|_| bad("invalid decimal number"))?
        .parse()
        .map_err(|_| bad("invalid decimal number"))
}

fn parse_quoted(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let Some((&quote, body)) = bytes.split_first() else {
        return Err(bad("empty quoted pickle string"));
    };
    if !matches!(quote, b'\'' | b'"') || body.last() != Some(&quote) {
        return Err(bad("invalid quoted pickle string"));
    }
    let (_, body) = body
        .split_last()
        .ok_or_else(|| bad("invalid quoted pickle string"))?;
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while let Some(&byte) = body.get(i) {
        if byte != b'\\' {
            out.push(byte);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&escaped) = body.get(i) else {
            return Err(bad("truncated pickle escape"));
        };
        match escaped {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'\\' | b'\'' | b'"' => out.push(escaped),
            b'x' => {
                let hi = *body.get(i + 1).ok_or_else(|| bad("truncated hex escape"))?;
                let lo = *body.get(i + 2).ok_or_else(|| bad("truncated hex escape"))?;
                let value = char::from(hi)
                    .to_digit(16)
                    .zip(char::from(lo).to_digit(16))
                    .map(|(hi, lo)| hi * 16 + lo)
                    .ok_or_else(|| bad("invalid hex escape"))?;
                out.push(u8::try_from(value).map_err(|_| bad("invalid hex escape"))?);
                i += 2;
            }
            _ => return Err(bad("unsupported pickle string escape")),
        }
        i += 1;
    }
    Ok(out)
}

fn pairs(items: &[usize]) -> Result<Vec<(usize, usize)>, Error> {
    let (pairs, remainder) = items.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(bad("odd number of dictionary operands"));
    }
    Ok(pairs.iter().map(|&[key, value]| (key, value)).collect())
}

fn path_node(nodes: &[Node], id: usize) -> Result<String, Error> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Text(bytes) => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| bad("invalid Unicode path")),
        // A byte-string name that is not UTF-8 is read as Latin-1.
        Node::Bytes(bytes) => Ok(std::str::from_utf8(bytes).map_or_else(
            |_| bytes.iter().copied().map(char::from).collect(),
            str::to_owned,
        )),
        _ => Err(bad("expected pickle path string")),
    }
}

/// The prefix bytes of chunk node `id`, charged to `budget`. Pickle memo
/// references let every chunk share one prefix for two bytes each, so the
/// copies are bounded by the index that holds them, not by the reference
/// count.
fn prefix_node(nodes: &[Node], id: usize, budget: &mut usize) -> Result<Vec<u8>, Error> {
    let node = nodes.get(id).ok_or_else(|| bad("invalid pickle node"))?;
    if let Node::Bytes(bytes) | Node::Text(bytes) = node {
        *budget = budget
            .checked_sub(bytes.len())
            .ok_or_else(|| bad("chunk prefixes exceed the index"))?;
    }
    match node {
        Node::Bytes(bytes) => Ok(bytes.clone()),
        Node::Text(bytes) => {
            let text =
                std::str::from_utf8(bytes).map_err(|_| bad("invalid Unicode chunk prefix"))?;
            text.chars()
                .map(|ch| {
                    u8::try_from(u32::from(ch)).map_err(|_| bad("chunk prefix is not Latin-1"))
                })
                .collect()
        }
        _ => Err(bad("expected pickle chunk prefix")),
    }
}

fn number(nodes: &[Node], id: usize) -> Result<u64, Error> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Int(n) => u64::try_from(*n).map_err(|_| bad("invalid negative or oversized extent")),
        _ => Err(bad("expected pickle integer")),
    }
}

fn sequence(nodes: &[Node], id: usize) -> Result<&[usize], Error> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Seq(items) => Ok(items),
        _ => Err(bad("expected pickle sequence")),
    }
}

/// Decode the archive directory `header` points at. Every referenced
/// physical range is checked against the payload region before the
/// compressed index. Fails on damaged compressed data, unsupported or
/// malformed pickle contents, exceeded resource limits, or invalid member
/// paths and extents.
fn parse_index(bytes: &[u8], header: &Header) -> Result<Index, Error> {
    let index_start =
        usize::try_from(header.index_offset).map_err(|_| bad("index offset overflow"))?;
    let index_tail = bytes
        .get(index_start..)
        .ok_or_else(|| bad("index offset outside archive"))?;
    if index_tail.len() > MAX_INDEX_BYTES {
        return Err(bad("compressed index exceeds limit"));
    }
    let mut decoder = ZlibDecoder::new(Cursor::new(index_tail));
    let index = inflate_capped(&mut decoder, MAX_INDEX_BYTES as u64, OnError::Discard)
        .map_err(|e| Error::malformed_with_source("rpa", "invalid zlib index", e))?;
    if index.truncated {
        return Err(bad("decompressed index exceeds limit"));
    }
    let index_bytes = index.bytes;
    let consumed = usize::try_from(decoder.into_inner().position())
        .map_err(|_| bad("index position overflow"))?;
    let (compressed, trailing) = index_tail
        .split_at_checked(consumed)
        .ok_or_else(|| bad("index position outside archive"))?;
    let (pickle, root) = Pickle::new(&index_bytes).parse()?;
    let Node::Dict(entries) = pickle
        .nodes
        .get(root)
        .ok_or_else(|| bad("invalid pickle root"))?
    else {
        return Err(bad("index root is not a dictionary"));
    };
    if entries.len() > MAX_ARCHIVE_MEMBERS {
        return Err(bad("member limit exceeded"));
    }
    let mut members: Vec<Member> = Vec::with_capacity(entries.len());
    let mut member_positions = HashMap::new();
    let mut duplicate_key_assignment_count = 0usize;
    let mut total_chunks = 0usize;
    let mut prefix_budget = index_bytes.len();
    for &(name_id, chunks_id) in entries {
        let path = path_node(&pickle.nodes, name_id)?;
        if path.is_empty() || path.len() > MAX_MEMBER_PATH_BYTES || path.contains('\0') {
            return Err(bad("invalid member path"));
        }
        let item_ids = sequence(&pickle.nodes, chunks_id)?;
        total_chunks = total_chunks
            .checked_add(item_ids.len())
            .ok_or_else(|| bad("chunk count overflow"))?;
        if total_chunks > MAX_NODES {
            return Err(bad("chunk limit exceeded"));
        }
        let mut chunks = Vec::with_capacity(item_ids.len());
        let mut size = 0u64;
        for &item_id in item_ids {
            let fields = sequence(&pickle.nodes, item_id)?;
            let (offset_id, length_id, prefix) = match *fields {
                [offset, length] => (offset, length, Vec::new()),
                [offset, length, prefix] => (
                    offset,
                    length,
                    prefix_node(&pickle.nodes, prefix, &mut prefix_budget)?,
                ),
                _ => return Err(bad("invalid chunk tuple")),
            };
            let offset = number(&pickle.nodes, offset_id)? ^ header.key;
            let length = number(&pickle.nodes, length_id)? ^ header.key;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| bad("chunk extent overflow"))?;
            if offset < header.header_size as u64 || end > header.index_offset {
                return Err(bad("chunk extent outside payload region"));
            }
            size = size
                .checked_add(length)
                .and_then(|s| s.checked_add(prefix.len() as u64))
                .ok_or_else(|| bad("member size overflow"))?;
            chunks.push(Chunk {
                offset,
                length,
                prefix,
            });
        }
        let member = Member { path, chunks, size };
        if let Some(&prior) = member_positions.get(&member.path) {
            // Python dictionaries keep the last value assigned to a key.
            // Retain that runtime view while counting overwritten assignments.
            *members
                .get_mut(prior)
                .ok_or_else(|| bad("invalid member position"))? = member;
            duplicate_key_assignment_count += 1;
        } else {
            member_positions.insert(member.path.clone(), members.len());
            members.push(member);
        }
    }
    Ok(Index {
        members,
        pickle_protocol: pickle.protocol,
        pickle_opcode_count: pickle.opcodes,
        pickle_memo_count: pickle.memo.len(),
        pickle_frame_count: pickle.frames,
        duplicate_key_assignment_count,
        compressed_index_size: compressed.len(),
        trailing_bytes: trailing.len(),
        uncompressed_index_size: index_bytes.len(),
        compressed_index_sha256: sha256(compressed),
        trailing_sha256: (!trailing.is_empty()).then(|| sha256(trailing)),
        index_sha256: sha256(&index_bytes),
        compressed_entropy: shannon(compressed),
        index_entropy: shannon(&index_bytes),
    })
}

const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::UncompressedSize(Scope::Files),
    Agg::Methods { always: true },
    Agg::EntryTypes,
    Agg::MaxFilenameLength,
    Agg::HiddenFiles,
    Agg::PathTraversal(Scope::All),
    Agg::NameTricks,
    Agg::Executables,
    Agg::Scripts,
    Agg::NestedArchives,
    Agg::MisplacedExecutables,
    Agg::NoiseFiles,
    Agg::DuplicateMembers,
];

/// Lowercase hex of the first 32 bytes.
fn hex_preview(bytes: &[u8]) -> String {
    hex_encode(bytes.get(..32).unwrap_or(bytes))
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let header = parse_header(bytes)?;
    let index = match parse_index(bytes, &header) {
        Ok(index) => index,
        Err(error) => {
            values.insert_key(
                value_key!("rpa"),
                json!({
                    "version": header.version,
                    "header_size": header.header_size,
                    "index_offset": header.index_offset,
                    "key_hex": format!("{:08x}", header.key),
                    "payload_region_bytes": header.index_offset - header.header_size as u64,
                    "complete": false,
                    "index_error": error.to_string(),
                }),
            );
            return Err(error);
        }
    };
    values.insert_key(value_key!("archive.format.kind"), json!("rpa"));

    let member_count = index.members.len();
    let mut stats = ArchiveStats::new(AGGS);
    let mut listed = Vec::with_capacity(member_count);
    let mut detailed = Vec::with_capacity(member_count);
    let mut ranges = Vec::new();
    let mut chunk_count = 0u64;
    let mut multi_chunk_count = 0u64;
    let mut prefix_member_count = 0u64;
    let mut prefix_bytes = 0u64;
    let mut referenced_bytes = 0u64;
    let mut logical_bytes = 0u64;
    let mut non_monotonic_count = 0u64;
    let mut last_offset = 0u64;
    for entry in index.members {
        if entry.chunks.len() > 1 {
            multi_chunk_count += 1;
        }
        let mut member_prefix_bytes = 0u64;
        let mut member_physical_bytes = 0u64;
        let mut chunk_values = Vec::with_capacity(entry.chunks.len());
        for chunk in &entry.chunks {
            chunk_count += 1;
            prefix_bytes += chunk.prefix.len() as u64;
            member_prefix_bytes += chunk.prefix.len() as u64;
            referenced_bytes += chunk.length;
            member_physical_bytes += chunk.length;
            if chunk.offset < last_offset {
                non_monotonic_count += 1;
            }
            last_offset = chunk.offset;
            if chunk.length > 0 {
                ranges.push((chunk.offset, chunk.offset + chunk.length));
            }
            let preview_start = usize::try_from(chunk.offset)
                .map_err(|_| Error::malformed("rpa", "chunk offset overflow"))?;
            let preview_end = usize::try_from(chunk.offset + chunk.length.min(32))
                .map_err(|_| Error::malformed("rpa", "chunk preview end overflow"))?;
            let preview = bytes
                .get(preview_start..preview_end)
                .ok_or_else(|| Error::malformed("rpa", "chunk preview outside archive"))?;
            chunk_values.push(json!({
                "offset": chunk.offset,
                "length": chunk.length,
                "payload_hex_preview": hex_preview(preview),
                "prefix_length": chunk.prefix.len(),
                "prefix_hex_preview": hex_preview(&chunk.prefix),
                "prefix_sha256": (!chunk.prefix.is_empty()).then(|| sha256(&chunk.prefix)),
            }));
        }
        if member_prefix_bytes > 0 {
            prefix_member_count += 1;
        }
        logical_bytes += entry.size;
        detailed.push(json!({
            "path": entry.path,
            "size_bytes": entry.size,
            "chunk_count": entry.chunks.len(),
            "prefix_bytes": member_prefix_bytes,
            "physical_bytes": member_physical_bytes,
            "chunks": chunk_values,
        }));
        let mut member = ArchiveMember::new(entry.path, entry.size, EntryType::Regular);
        member.compression = ArchiveCompression::new(None, Some("stored".into()));
        member.offsets.data = entry.chunks.first().map(|c| c.offset);
        stats.observe(&member, &Reading::of(&member));
        listed.push(JsonValue::Object(member_value(&member)));
        members.push(member);
    }
    ranges.sort_unstable();
    let mut covered_bytes = 0u64;
    let mut end = header.header_size as u64;
    for (start, stop) in ranges {
        if stop > end {
            covered_bytes += stop - start.max(end);
            end = stop;
        }
    }
    let payload_region_bytes = header.index_offset - header.header_size as u64;
    let index_ratio = if index.compressed_index_size == 0 {
        0.0
    } else {
        index.uncompressed_index_size as f64 / index.compressed_index_size as f64
    };
    values.insert_key(value_key!("archive.members"), JsonValue::Array(listed));
    values.insert_key(
        value_key!("rpa"),
        json!({
            "version": header.version,
            "header_size": header.header_size,
            "index_offset": header.index_offset,
            "key_hex": format!("{:08x}", header.key),
            "key_is_default": header.version == 3 && header.key == 0x42424242,
            "complete": true,
            "index": {
                "compression": "zlib",
                "compressed_size": index.compressed_index_size,
                "uncompressed_size": index.uncompressed_index_size,
                "compression_ratio": index_ratio,
                "compressed_entropy": index.compressed_entropy,
                "pickle_entropy": index.index_entropy,
                "compressed_sha256": index.compressed_index_sha256,
                "sha256": index.index_sha256,
                "trailing_bytes": index.trailing_bytes,
                "trailing_sha256": index.trailing_sha256,
                "pickle_protocol": index.pickle_protocol,
                "pickle_opcode_count": index.pickle_opcode_count,
                "pickle_memo_count": index.pickle_memo_count,
                "pickle_frame_count": index.pickle_frame_count,
            },
            "member_count": member_count,
            "duplicate_key_assignment_count": index.duplicate_key_assignment_count,
            "chunk_count": chunk_count,
            "multi_chunk_member_count": multi_chunk_count,
            "prefix_member_count": prefix_member_count,
            "prefix_bytes": prefix_bytes,
            "logical_member_bytes": logical_bytes,
            "physical_referenced_bytes": referenced_bytes,
            "physical_covered_bytes": covered_bytes,
            "overlapping_reference_bytes": referenced_bytes.saturating_sub(covered_bytes),
            "payload_region_bytes": payload_region_bytes,
            "unreferenced_payload_bytes": payload_region_bytes.saturating_sub(covered_bytes),
            "non_monotonic_chunk_count": non_monotonic_count,
            "members": detailed,
        }),
    );
    metrics.insert(metric!("rpa.chunk_count"), chunk_count as f64);
    metrics.insert(
        metric!("rpa.duplicate_key_assignment_count"),
        index.duplicate_key_assignment_count as f64,
    );
    metrics.insert(metric!("rpa.index_compression_ratio"), index_ratio);
    metrics.insert(
        metric!("rpa.index_compressed_entropy"),
        index.compressed_entropy,
    );
    metrics.insert(
        metric!("rpa.index_compressed_size"),
        index.compressed_index_size as f64,
    );
    metrics.insert(metric!("rpa.index_offset"), header.index_offset as f64);
    metrics.insert(metric!("rpa.index_pickle_entropy"), index.index_entropy);
    metrics.insert(
        metric!("rpa.index_size"),
        index.uncompressed_index_size as f64,
    );
    metrics.insert(
        metric!("rpa.index_trailing_bytes"),
        index.trailing_bytes as f64,
    );
    metrics.insert(metric!("rpa.member_count"), member_count as f64);
    metrics.insert(metric!("rpa.logical_member_bytes"), logical_bytes as f64);
    metrics.insert(
        metric!("rpa.multi_chunk_member_count"),
        multi_chunk_count as f64,
    );
    metrics.insert(
        metric!("rpa.non_monotonic_chunk_count"),
        non_monotonic_count as f64,
    );
    metrics.insert(
        metric!("rpa.overlapping_reference_bytes"),
        referenced_bytes.saturating_sub(covered_bytes) as f64,
    );
    metrics.insert(
        metric!("rpa.payload_region_bytes"),
        payload_region_bytes as f64,
    );
    metrics.insert(metric!("rpa.physical_covered_bytes"), covered_bytes as f64);
    metrics.insert(
        metric!("rpa.physical_referenced_bytes"),
        referenced_bytes as f64,
    );
    metrics.insert(metric!("rpa.prefix_bytes"), prefix_bytes as f64);
    metrics.insert(
        metric!("rpa.prefix_member_count"),
        prefix_member_count as f64,
    );
    metrics.insert(
        metric!("rpa.unreferenced_payload_bytes"),
        payload_region_bytes.saturating_sub(covered_bytes) as f64,
    );
    metrics.insert(metric!("rpa.version"), f64::from(header.version));
    stats.emit(values, metrics);
    Ok(())
}

#[cfg(test)]
mod tests;
