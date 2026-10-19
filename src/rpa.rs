//! Bounded, inert reader for Ren'Py RPA-2.0 and RPA-3.0 indexes.
//!
//! The index is zlib-compressed pickle. This module interprets only the
//! primitive container opcodes needed for the archive directory; it never
//! imports Python globals or constructs Python objects.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use flate2::bufread::ZlibDecoder;

const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEMBERS: usize = 65_536;
const MAX_NODES: usize = 1_000_000;
const MAX_STACK: usize = 1_000_000;
const MAX_PATH_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy)]
/// Fixed RPA header fields, before interpreting the compressed index.
pub struct Header {
    /// Archive format version (2 or 3).
    pub version: u8,
    /// Absolute byte offset of the zlib-compressed index.
    pub index_offset: u64,
    /// Version 3 XOR key; zero for version 2.
    pub key: u64,
    /// Size of the fixed header in bytes.
    pub header_size: usize,
}

#[derive(Debug, Clone)]
/// One physical payload run, optionally preceded by bytes stored in the index.
pub struct Chunk {
    /// Absolute byte offset of the physical run.
    pub offset: u64,
    /// Length of the physical run.
    pub length: u64,
    /// Bytes to prepend before the physical run.
    pub prefix: Vec<u8>,
}

#[derive(Debug, Clone)]
/// One logical file named in the archive index.
pub struct Member {
    /// Member name after UTF-8 or Latin-1 decoding.
    pub path: String,
    /// Ordered physical runs making up the logical file.
    pub chunks: Vec<Chunk>,
    /// Reconstructed member size, including index-stored prefixes.
    pub size: u64,
}

#[derive(Debug, Clone)]
/// Decoded index and forensic properties of its compressed pickle stream.
pub struct Index {
    /// Fixed archive header.
    pub header: Header,
    /// Members in index order, after Python dictionary overwrite semantics.
    pub members: Vec<Member>,
    /// Declared pickle protocol, if a PROTO opcode was present.
    pub pickle_protocol: Option<u8>,
    /// Number of pickle opcodes interpreted.
    pub pickle_opcode_count: usize,
    /// Number of memo slots populated.
    pub pickle_memo_count: usize,
    /// Number of FRAME opcodes.
    pub pickle_frame_count: usize,
    /// Number of repeated key assignments in the pickle dictionary.
    pub duplicate_key_assignment_count: usize,
    /// Size of the zlib stream, excluding trailing bytes.
    pub compressed_index_size: usize,
    /// Bytes after the zlib stream, ignored by Ren'Py's decompressor.
    pub trailing_bytes: usize,
    /// Size of the decompressed pickle index.
    pub uncompressed_index_size: usize,
    /// SHA-256 of the compressed index bytes.
    pub compressed_index_sha256: String,
    /// SHA-256 of bytes after the zlib stream, when present.
    pub trailing_sha256: Option<String>,
    /// SHA-256 of the decompressed pickle bytes.
    pub index_sha256: String,
    /// Shannon entropy of the compressed zlib stream, in bits per byte.
    pub compressed_entropy: f64,
    /// Shannon entropy of the decompressed pickle stream, in bits per byte.
    pub index_entropy: f64,
}

fn bad(message: &str) -> String {
    format!("RPA: {message}")
}

fn hex(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(bad("invalid hexadecimal header field"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad("invalid header text"))?;
    u64::from_str_radix(text, 16).map_err(|_| bad("header number overflow"))
}

/// Parse only the fixed RPA header. The index itself may still be damaged.
///
/// # Errors
/// Returns an error for unsupported, truncated, or invalid headers, including
/// index offsets outside the archive.
pub fn parse_header(bytes: &[u8]) -> Result<Header, String> {
    let (version, header_size, key) = if bytes.starts_with(b"RPA-3.0 ") {
        let h = bytes.get(..34).ok_or_else(|| bad("truncated v3 header"))?;
        if h.get(24) != Some(&b' ') || h.get(33) != Some(&b'\n') {
            return Err(bad("invalid v3 header separators"));
        }
        (
            3,
            34,
            hex(h.get(25..33).ok_or_else(|| bad("truncated v3 key"))?)?,
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
    let index_offset = hex(bytes
        .get(8..24)
        .ok_or_else(|| bad("truncated index offset"))?)?;
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

#[derive(Clone)]
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

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| bad("pickle offset overflow"))?;
        let part = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| bad("truncated pickle"))?;
        self.pos = end;
        Ok(part)
    }

    fn byte(&mut self) -> Result<u8, String> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| bad("truncated pickle"))
    }
    fn le32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| bad("truncated integer"))?,
        ))
    }
    fn le64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| bad("truncated integer"))?,
        ))
    }

    fn line(&mut self) -> Result<&'a [u8], String> {
        let rest = self
            .bytes
            .get(self.pos..)
            .ok_or_else(|| bad("truncated pickle"))?;
        let len = rest
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| bad("unterminated pickle line"))?;
        let line = self.take(len)?;
        self.take(1)?;
        Ok(line)
    }

    fn node(&mut self, node: Node) -> Result<usize, String> {
        if self.nodes.len() >= MAX_NODES {
            return Err(bad("pickle node limit exceeded"));
        }
        let id = self.nodes.len();
        self.nodes.push(node);
        Ok(id)
    }

    fn push(&mut self, id: usize) -> Result<(), String> {
        if self.stack.len() >= MAX_STACK {
            return Err(bad("pickle stack limit exceeded"));
        }
        self.stack.push(id);
        Ok(())
    }

    fn add(&mut self, node: Node) -> Result<(), String> {
        let id = self.node(node)?;
        self.push(id)
    }

    fn pop(&mut self) -> Result<usize, String> {
        let id = self
            .stack
            .pop()
            .ok_or_else(|| bad("pickle stack underflow"))?;
        if matches!(
            self.nodes
                .get(id)
                .ok_or_else(|| bad("invalid pickle node"))?,
            Node::Mark
        ) {
            self.marks.pop();
        }
        Ok(id)
    }
    fn top(&self) -> Result<usize, String> {
        self.stack
            .last()
            .copied()
            .ok_or_else(|| bad("pickle stack underflow"))
    }

    fn after_mark(&mut self) -> Result<Vec<usize>, String> {
        let mark = *self
            .marks
            .last()
            .ok_or_else(|| bad("missing pickle MARK"))?;
        let items = self.stack.split_off(mark + 1);
        self.pop()?;
        Ok(items)
    }

    fn put(&mut self, n: usize) -> Result<(), String> {
        if n >= MAX_NODES {
            return Err(bad("pickle memo index exceeds limit"));
        }
        let id = self.top()?;
        if matches!(
            self.nodes
                .get(id)
                .ok_or_else(|| bad("invalid pickle node"))?,
            Node::Mark
        ) {
            return Err(bad("cannot memoize MARK"));
        }
        self.memo.insert(n, id);
        self.next_memo = self.next_memo.max(n + 1);
        Ok(())
    }

    fn get(&mut self, n: usize) -> Result<(), String> {
        let id = *self
            .memo
            .get(&n)
            .ok_or_else(|| bad("missing pickle memo entry"))?;
        if matches!(
            self.nodes
                .get(id)
                .ok_or_else(|| bad("invalid pickle node"))?,
            Node::Mark
        ) {
            return Err(bad("memo refers to MARK"));
        }
        self.push(id)
    }

    fn bytes_node(&mut self, n: usize, unicode: bool) -> Result<(), String> {
        if n > MAX_INDEX_BYTES {
            return Err(bad("pickle string exceeds limit"));
        }
        let bytes = self.take(n)?.to_vec();
        self.add(if unicode {
            Node::Text(bytes)
        } else {
            Node::Bytes(bytes)
        })
    }

    fn parse(mut self) -> Result<(Self, usize), String> {
        loop {
            let op = self.byte()?;
            self.opcodes += 1;
            if self.opcodes > MAX_NODES {
                return Err(bad("pickle opcode limit exceeded"));
            }
            match op {
                0x80 => {
                    let version = self.byte()?;
                    if version > 5 {
                        return Err(bad("unsupported pickle protocol"));
                    }
                    self.protocol = Some(version);
                }
                0x95 => {
                    self.le64()?;
                    self.frames += 1;
                }
                b'.' => {
                    let root = self.pop()?;
                    if !self.stack.is_empty() {
                        return Err(bad("pickle stack has trailing values"));
                    }
                    if self.pos != self.bytes.len() {
                        return Err(bad("trailing pickle data"));
                    }
                    return Ok((self, root));
                }
                b'(' => {
                    self.add(Node::Mark)?;
                    self.marks.push(self.stack.len() - 1);
                }
                b'N' => self.add(Node::Null)?,
                b'}' => self.add(Node::Dict(Vec::new()))?,
                b']' | b')' => self.add(Node::Seq(Vec::new()))?,
                b'K' => {
                    let n = self.byte()?;
                    self.add(Node::Int(i128::from(n)))?;
                }
                b'M' => {
                    let n = u16::from_le_bytes(
                        self.take(2)?
                            .try_into()
                            .map_err(|_| bad("truncated integer"))?,
                    );
                    self.add(Node::Int(i128::from(n)))?;
                }
                b'J' => {
                    let n = i32::from_le_bytes(
                        self.take(4)?
                            .try_into()
                            .map_err(|_| bad("truncated integer"))?,
                    );
                    self.add(Node::Int(i128::from(n)))?;
                }
                b'I' | b'L' => {
                    let line = self.line()?;
                    let text = std::str::from_utf8(line)
                        .map_err(|_| bad("invalid pickle integer"))?
                        .trim_end_matches('L');
                    let n = text.parse().map_err(|_| bad("invalid pickle integer"))?;
                    self.add(Node::Int(n))?;
                }
                0x8a | 0x8b => {
                    let len = if op == 0x8a {
                        usize::from(self.byte()?)
                    } else {
                        self.le32()? as usize
                    };
                    if len > 16 {
                        return Err(bad("pickle integer exceeds 128 bits"));
                    }
                    let raw = self.take(len)?;
                    let mut bytes = [0u8; 16];
                    if raw.last().is_some_and(|b| b & 0x80 != 0) {
                        bytes.fill(0xff);
                    }
                    bytes
                        .get_mut(..len)
                        .ok_or_else(|| bad("pickle integer exceeds 128 bits"))?
                        .copy_from_slice(raw);
                    self.add(Node::Int(i128::from_le_bytes(bytes)))?;
                }
                0x8c | b'U' | b'C' => {
                    let len = usize::from(self.byte()?);
                    self.bytes_node(len, op == 0x8c)?;
                }
                b'X' | b'T' | b'B' => {
                    let len = self.le32()? as usize;
                    self.bytes_node(len, op == b'X')?;
                }
                0x8d | 0x8e => {
                    let len = usize::try_from(self.le64()?)
                        .map_err(|_| bad("pickle string length overflow"))?;
                    self.bytes_node(len, op == 0x8d)?;
                }
                b'V' => {
                    let bytes = self.line()?.to_vec();
                    self.add(Node::Text(bytes))?;
                }
                b'S' => {
                    let bytes = parse_quoted(self.line()?)?;
                    self.add(Node::Bytes(bytes))?;
                }
                b'q' => {
                    let n = usize::from(self.byte()?);
                    self.put(n)?;
                }
                b'r' => {
                    let n = self.le32()? as usize;
                    self.put(n)?;
                }
                b'p' => {
                    let n = parse_decimal(self.line()?)?;
                    self.put(n)?;
                }
                b'h' => {
                    let n = usize::from(self.byte()?);
                    self.get(n)?;
                }
                b'j' => {
                    let n = self.le32()? as usize;
                    self.get(n)?;
                }
                b'g' => {
                    let n = parse_decimal(self.line()?)?;
                    self.get(n)?;
                }
                0x94 => {
                    let n = self.next_memo;
                    self.put(n)?;
                }
                b't' | b'l' | b'd' => {
                    let items = self.after_mark()?;
                    if op == b'd' {
                        self.add(Node::Dict(pairs(&items)?))?;
                    } else {
                        self.add(Node::Seq(items))?;
                    }
                }
                0x85..=0x87 => {
                    let count = usize::from(op - 0x84);
                    if self.stack.len() < count {
                        return Err(bad("pickle stack underflow"));
                    }
                    let items = self.stack.split_off(self.stack.len() - count);
                    self.add(Node::Seq(items))?;
                }
                b'a' => {
                    let item = self.pop()?;
                    let list = self.top()?;
                    match self
                        .nodes
                        .get_mut(list)
                        .ok_or_else(|| bad("invalid pickle node"))?
                    {
                        Node::Seq(items) => items.push(item),
                        _ => return Err(bad("APPEND target is not a list")),
                    }
                }
                b'e' => {
                    let items = self.after_mark()?;
                    let list = self.top()?;
                    match self
                        .nodes
                        .get_mut(list)
                        .ok_or_else(|| bad("invalid pickle node"))?
                    {
                        Node::Seq(seq) => seq.extend(items),
                        _ => return Err(bad("APPENDS target is not a list")),
                    }
                }
                b's' => {
                    let value = self.pop()?;
                    let key = self.pop()?;
                    let dict = self.top()?;
                    match self
                        .nodes
                        .get_mut(dict)
                        .ok_or_else(|| bad("invalid pickle node"))?
                    {
                        Node::Dict(items) => items.push((key, value)),
                        _ => return Err(bad("SETITEM target is not a dict")),
                    }
                }
                b'u' => {
                    let items = pairs(&self.after_mark()?)?;
                    let dict = self.top()?;
                    match self
                        .nodes
                        .get_mut(dict)
                        .ok_or_else(|| bad("invalid pickle node"))?
                    {
                        Node::Dict(entries) => entries.extend(items),
                        _ => return Err(bad("SETITEMS target is not a dict")),
                    }
                }
                b'2' => {
                    let id = self.top()?;
                    if matches!(
                        self.nodes
                            .get(id)
                            .ok_or_else(|| bad("invalid pickle node"))?,
                        Node::Mark
                    ) {
                        return Err(bad("cannot duplicate MARK"));
                    }
                    self.push(id)?;
                }
                b'0' => {
                    self.pop()?;
                }
                b'1' => {
                    self.after_mark()?;
                }
                // GLOBAL, REDUCE, BUILD, persistent IDs, extension registries,
                // object constructors, and all unknown opcodes are rejected.
                _ => {
                    return Err(format!(
                        "RPA: unsupported or executable pickle opcode 0x{op:02x}"
                    ));
                }
            }
        }
    }
}

fn parse_decimal(bytes: &[u8]) -> Result<usize, String> {
    std::str::from_utf8(bytes)
        .map_err(|_| bad("invalid decimal number"))?
        .parse()
        .map_err(|_| bad("invalid decimal number"))
}

fn parse_quoted(bytes: &[u8]) -> Result<Vec<u8>, String> {
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

fn pairs(items: &[usize]) -> Result<Vec<(usize, usize)>, String> {
    let (pairs, remainder) = items.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(bad("odd number of dictionary operands"));
    }
    Ok(pairs.iter().map(|&[key, value]| (key, value)).collect())
}

fn path_node(nodes: &[Node], id: usize) -> Result<String, String> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Text(bytes) => {
            String::from_utf8(bytes.clone()).map_err(|_| bad("invalid Unicode path"))
        }
        Node::Bytes(bytes) => Ok(match String::from_utf8(bytes.clone()) {
            Ok(path) => path,
            Err(_) => bytes.iter().map(|b| char::from(*b)).collect(),
        }),
        _ => Err(bad("expected pickle path string")),
    }
}

fn prefix_node(nodes: &[Node], id: usize) -> Result<Vec<u8>, String> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Bytes(bytes) => Ok(bytes.clone()),
        Node::Text(bytes) => {
            let text =
                std::str::from_utf8(bytes).map_err(|_| bad("invalid Unicode chunk prefix"))?;
            text.chars()
                .map(|ch| u8::try_from(ch as u32).map_err(|_| bad("chunk prefix is not Latin-1")))
                .collect()
        }
        _ => Err(bad("expected pickle chunk prefix")),
    }
}

fn number(nodes: &[Node], id: usize) -> Result<u64, String> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Int(n) => u64::try_from(*n).map_err(|_| bad("invalid negative or oversized extent")),
        _ => Err(bad("expected pickle integer")),
    }
}

fn sequence(nodes: &[Node], id: usize) -> Result<&[usize], String> {
    match nodes.get(id).ok_or_else(|| bad("invalid pickle node"))? {
        Node::Seq(items) => Ok(items),
        _ => Err(bad("expected pickle sequence")),
    }
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        if let Some(count) = counts.get_mut(usize::from(b)) {
            *count += 1;
        }
    }
    let total = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Decode an RPA archive directory. Every referenced physical range is
/// checked against the payload region before the compressed index.
///
/// # Errors
/// Returns an error for invalid headers, compressed data, unsupported or malformed
/// pickle contents, exceeded resource limits, or invalid member paths and extents.
pub fn parse(bytes: &[u8]) -> Result<Index, String> {
    let header = parse_header(bytes)?;
    let index_start =
        usize::try_from(header.index_offset).map_err(|_| bad("index offset overflow"))?;
    let index_tail = bytes
        .get(index_start..)
        .ok_or_else(|| bad("index offset outside archive"))?;
    if index_tail.len() > MAX_INDEX_BYTES {
        return Err(bad("compressed index exceeds limit"));
    }
    let mut index_bytes = Vec::new();
    let mut decoder = ZlibDecoder::new(Cursor::new(index_tail));
    decoder
        .by_ref()
        .take((MAX_INDEX_BYTES + 1) as u64)
        .read_to_end(&mut index_bytes)
        .map_err(|_| bad("invalid zlib index"))?;
    if index_bytes.len() > MAX_INDEX_BYTES {
        return Err(bad("decompressed index exceeds limit"));
    }
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
    if entries.len() > MAX_MEMBERS {
        return Err(bad("member limit exceeded"));
    }
    let mut members: Vec<Member> = Vec::with_capacity(entries.len());
    let mut member_positions = HashMap::new();
    let mut duplicate_key_assignment_count = 0usize;
    let mut total_chunks = 0usize;
    for &(name_id, chunks_id) in entries {
        let path = path_node(&pickle.nodes, name_id)?;
        if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0') {
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
                [offset, length, prefix] => (offset, length, prefix_node(&pickle.nodes, prefix)?),
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
        header,
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
        compressed_entropy: entropy(compressed),
        index_entropy: entropy(&index_bytes),
    })
}
