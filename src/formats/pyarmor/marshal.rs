//! Bounded marshal normalization for PyArmor analysis snapshots.
//!
//! Names in `co_consts` are data, not identifiers. Keep reference slots as
//! arena indices so recursive/shared containers cannot cause deep cloning.
use super::{RecoveredPyc, ctr};
use std::ops::Range;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_DEPTH: usize = 64;

enum Value {
    Other,
    Bytes(Range<usize>),
    Text,
    Sequence(Vec<usize>),
    Code,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    minor: u8,
    values: Vec<Value>,
    refs: Vec<usize>,
    key: &'a [u8; 16],
    edits: Vec<(Range<usize>, Vec<u8>)>,
    code_objects: usize,
    edited_bytes: usize,
    decrypted_regions: usize,
    limitations: Vec<&'static str>,
    steps: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], &'static str> {
        let end = self.pos.checked_add(size).ok_or("marshal size overflow")?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or("truncated marshal value")?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, &'static str> {
        self.take(1)?.first().copied().ok_or("missing marshal byte")
    }

    fn integer(&mut self) -> Result<i32, &'static str> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes(
            b.try_into().map_err(|_| "invalid marshal integer")?,
        ))
    }

    fn length(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.integer()?).map_err(|_| "negative marshal length")
    }

    fn sequence(&mut self, count: usize, depth: usize) -> Result<Value, &'static str> {
        if count > MAX_OBJECTS || count > self.data.len().saturating_sub(self.pos) {
            return Err("marshal container budget exceeded");
        }
        let mut children = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            children.push(self.read(depth + 1)?);
        }
        Ok(Value::Sequence(children))
    }

    fn bytes(&self, node: usize) -> Result<Range<usize>, &'static str> {
        match self.values.get(node) {
            Some(Value::Bytes(range)) => Ok(range.clone()),
            _ => Err("expected marshal bytes"),
        }
    }

    fn code(&mut self, depth: usize) -> Result<Value, &'static str> {
        self.code_objects += 1;
        let header = self.pos;
        let size = if self.minor <= 10 { 24 } else { 20 };
        self.take(size)?;
        let flags_at = header + size - 4;
        let flags = crate::bytes::u32_le(self.data, flags_at).ok_or("missing code flags")?;
        let code = self.read(depth + 1)?;
        let constants = self.read(depth + 1)?;
        self.bytes(code)?;
        if !matches!(self.values.get(constants), Some(Value::Sequence(_))) {
            return Err("invalid code constants");
        }
        self.read(depth + 1)?; // names
        for _ in 0..if self.minor <= 10 { 3 } else { 2 } {
            self.read(depth + 1)?; // locals and closure metadata
        }
        self.read(depth + 1)?; // filename
        self.read(depth + 1)?; // name
        if self.minor >= 11 {
            self.read(depth + 1)?;
        } // qualname
        self.take(4)?; // first line
        self.read(depth + 1)?; // line table
        if self.minor >= 11 {
            self.read(depth + 1)?;
        } // exception table
        if flags & 0x20000000 != 0 {
            let trailer_start = self.pos;
            let length = usize::from(self.byte()?);
            let extra = self.take(length)?;
            if extra.len() < 4 {
                return Err("truncated PyArmor code metadata");
            }
            let metadata = *extra.first().ok_or("missing metadata flags")?;
            let functions = metadata & 3;
            let descriptors = (metadata >> 2) & 3;
            if metadata & 0x10 != 0 {
                self.limitations
                    .push("native/BCC code requires native analysis");
            }
            let mut position = 4usize;
            for _ in 0..functions {
                let size =
                    usize::from(*extra.get(position).ok_or("truncated function metadata")? >> 6)
                        + 2;
                position = position.checked_add(size).ok_or("metadata overflow")?;
                if position > extra.len() {
                    return Err("invalid function metadata span");
                }
            }
            let range = self.bytes(code)?;
            self.edited_bytes = self
                .edited_bytes
                .checked_add(range.len())
                .ok_or("edit size overflow")?;
            if self.edited_bytes > 16 * 1024 * 1024 {
                return Err("instruction edit budget exceeded");
            }
            let mut instructions = self
                .data
                .get(range)
                .ok_or("invalid instruction span")?
                .to_vec();
            for _ in 0..descriptors {
                let size =
                    usize::from(*extra.get(position).ok_or("truncated descriptor metadata")? >> 6)
                        + 2;
                let end = position.checked_add(size).ok_or("descriptor overflow")?;
                let item = extra
                    .get(position + 1..end)
                    .ok_or("invalid descriptor metadata span")?;
                let mut index = 0usize;
                for byte in item {
                    index = index
                        .checked_mul(256)
                        .and_then(|v| v.checked_add(usize::from(*byte)))
                        .ok_or("descriptor index overflow")?;
                }
                let Some(Value::Sequence(items)) = self.values.get(constants) else {
                    return Err("missing constants");
                };
                let node = *items
                    .get(index)
                    .ok_or("descriptor constant out of bounds")?;
                let descriptor = self
                    .data
                    .get(self.bytes(node)?)
                    .ok_or("invalid descriptor span")?;
                if self.decrypt(&mut instructions, descriptor)? {
                    self.decrypted_regions += 1;
                }
                position = end;
            }
            if descriptors != 0 {
                self.edits.push((self.bytes(code)?, instructions));
            }
            self.edits.push((
                flags_at..flags_at + 4,
                (flags & !0x20000000).to_le_bytes().to_vec(),
            ));
            self.edits.push((trailer_start..self.pos, Vec::new()));
        }
        Ok(Value::Code)
    }

    fn decrypt(&mut self, code: &mut [u8], descriptor: &[u8]) -> Result<bool, &'static str> {
        let flags = *descriptor.get(8).ok_or("short PyArmor code descriptor")?;
        let short_nonce = usize::from(*descriptor.get(9).ok_or("short code descriptor")?);
        let begin = usize::from(*descriptor.get(11).ok_or("short code descriptor")?);
        let length = crate::bytes::u32_le(descriptor, 12).ok_or("short code descriptor")? as usize;
        if descriptor.len() < 20 {
            return Err("short code descriptor");
        }
        let end = begin
            .checked_add(length)
            .ok_or("instruction range overflow")?;
        let nonce_at = if flags & 2 != 0 {
            short_nonce
        } else {
            end.checked_add(short_nonce).ok_or("nonce range overflow")?
        };
        let nonce_end = nonce_at.checked_add(12).ok_or("nonce overflow")?;
        let nonce: [u8; 12] = code
            .get(nonce_at..nonce_end)
            .ok_or("nonce outside instructions")?
            .try_into()
            .map_err(|_| "invalid nonce")?;
        if code.get(begin..end).is_none() {
            return Err("encrypted region outside instructions");
        }
        if flags & 4 != 0 {
            self.limitations
                .push("instruction nonce-XOR protection remains encrypted");
            return Ok(false);
        }
        let region = code.get_mut(begin..end).ok_or("invalid encrypted region")?;
        let decrypted = ctr(region, self.key, &nonce).ok_or("instruction cipher failed")?;
        region.copy_from_slice(&decrypted);
        if flags & 8 != 0 {
            let tail = length.checked_add(begin).ok_or("prologue overflow")?;
            if tail > code.len() {
                return Err("prologue outside instructions");
            }
            code.copy_within(length..tail, 0);
            // Preserve wordcode offsets, using each version's NOP opcode.
            let nop = match self.minor {
                13 => 30,
                14 => 27,
                _ => 9,
            };
            for pair in code
                .get_mut(length..tail)
                .ok_or("invalid prologue span")?
                .chunks_mut(2)
            {
                if let Some(opcode) = pair.first_mut() {
                    *opcode = nop;
                }
                if let Some(argument) = pair.get_mut(1) {
                    *argument = 0;
                }
            }
        }
        Ok(true)
    }

    fn read(&mut self, depth: usize) -> Result<usize, &'static str> {
        self.steps += 1;
        if depth > MAX_DEPTH || self.steps > MAX_OBJECTS {
            return Err("marshal nesting or object budget exceeded");
        }
        let tag = self.byte()?;
        let kind = tag & 0x7f;
        if kind == b'r' {
            let index = self.length()?;
            return self
                .refs
                .get(index)
                .copied()
                .ok_or("invalid marshal reference");
        }
        let node = self.values.len();
        self.values.push(Value::Other);
        if tag & 0x80 != 0 {
            self.refs.push(node);
        }
        let value = match kind {
            b'N' | b'T' | b'F' | b'S' | b'.' => Value::Other,
            b'i' => {
                self.take(4)?;
                Value::Other
            }
            b'I' | b'g' => {
                self.take(8)?;
                Value::Other
            }
            b'y' => {
                self.take(16)?;
                Value::Other
            }
            b'l' => {
                let digits = self.integer()?.unsigned_abs() as usize;
                self.take(digits.checked_mul(2).ok_or("marshal long overflow")?)?;
                Value::Other
            }
            b'f' | b'x' => {
                for _ in 0..if kind == b'x' { 2 } else { 1 } {
                    let length = usize::from(self.byte()?);
                    self.take(length)?;
                }
                Value::Other
            }
            b's' => {
                let length = self.length()?;
                let start = self.pos;
                let bytes = self.take(length)?;
                if bytes.first().is_some_and(|b| matches!(b, 0x81..=0x84)) {
                    self.limitations
                        .push("possible mixed-string protection requires further decoding");
                }
                Value::Bytes(start..self.pos)
            }
            b'u' | b'a' | b'A' | b't' | b'z' | b'Z' => {
                let length = if matches!(kind, b'z' | b'Z') {
                    usize::from(self.byte()?)
                } else {
                    self.length()?
                };
                self.take(length)?;
                Value::Text
            }
            b'(' => {
                let count = self.length()?;
                self.sequence(count, depth)?
            }
            b'[' | b'<' | b'>' => {
                let count = self.length()?;
                self.sequence(count, depth)?;
                Value::Other
            }
            b')' => {
                let count = usize::from(self.byte()?);
                self.sequence(count, depth)?
            }
            b'{' => {
                loop {
                    if self.data.get(self.pos) == Some(&b'0') {
                        self.pos += 1;
                        break;
                    }
                    self.read(depth + 1)?;
                    self.read(depth + 1)?;
                }
                Value::Other
            }
            b':' if self.minor >= 14 => {
                self.read(depth + 1)?;
                self.read(depth + 1)?;
                self.read(depth + 1)?;
                Value::Other
            }
            b'c' => self.code(depth)?,
            _ => return Err("unsupported marshal type"),
        };
        *self
            .values
            .get_mut(node)
            .ok_or("invalid marshal arena slot")? = value;
        Ok(node)
    }
}

pub(super) fn normalize(
    body: &[u8],
    minor: u8,
    key: &[u8; 16],
) -> Result<RecoveredPyc, &'static str> {
    if body.len() > MAX_BYTES {
        return Err("marshal byte budget exceeded");
    }
    if body.first().map(|b| b & 0x7f) != Some(b'c') {
        return Err("marshal root is not code");
    }
    let mut reader = Reader {
        data: body,
        pos: 0,
        minor,
        values: Vec::new(),
        refs: Vec::new(),
        steps: 0,
        key,
        edits: Vec::new(),
        code_objects: 0,
        edited_bytes: 0,
        decrypted_regions: 0,
        limitations: Vec::new(),
    };
    reader.read(0)?;
    if reader.pos != body.len() {
        return Err("trailing data after protected marshal");
    }
    reader.edits.sort_by_key(|(range, _)| range.start);
    let mut data = Vec::with_capacity(body.len());
    let mut end = 0;
    for (range, replacement) in reader.edits {
        if range.start < end {
            return Err("overlapping code-object edits");
        }
        data.extend_from_slice(body.get(end..range.start).ok_or("invalid edit gap")?);
        data.extend_from_slice(&replacement);
        end = range.end;
    }
    data.extend_from_slice(body.get(end..).ok_or("invalid edit tail")?);
    reader.limitations.sort_unstable();
    reader.limitations.dedup();
    Ok(RecoveredPyc {
        data,
        code_objects: reader.code_objects,
        decrypted_regions: reader.decrypted_regions,
        limitations: reader.limitations,
    })
}
