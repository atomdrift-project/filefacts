//! A bounded, non-executing walker over CPython's `marshal` format, for the
//! code-object streams of `.pyc` files and PyArmor containers (CPython
//! 3.8–3.14).
//!
//! Every object becomes a slot in an arena, and a back-reference is that
//! slot's index, so recursive or shared containers are never cloned. Byte
//! and text objects are kept as ranges of the input. Each code object's
//! fields are walked by the walker; a visitor sees them once they are read,
//! and may read on past them (PyArmor appends metadata there).

use std::ops::Range;

use crate::bytes::Reader;

/// Largest marshal stream walked.
pub(super) const MAX_BYTES: usize = 8 << 20;
/// Objects read from one stream, back-references included.
const MAX_OBJECTS: usize = 100_000;
/// Container nesting followed.
const MAX_DEPTH: usize = 64;

/// What the walker kept of one object.
pub(super) enum Value {
    /// Anything a visitor does not look into: numbers, singletons, sets,
    /// lists, dicts and slices.
    Other,
    /// A `bytes` object, as its range of the stream.
    Bytes(Range<usize>),
    /// A `str` object, as its range of the stream.
    Text(Range<usize>),
    /// A tuple, as the arena slots of its items.
    Sequence(Vec<usize>),
    /// A code object.
    Code,
}

/// The fields of one code object a visitor reads, as arena slots, and its
/// flags word.
pub(super) struct CodeObject {
    /// Where the `co_flags` word sits in the stream.
    pub(super) flags_at: usize,
    pub(super) flags: u32,
    /// `co_code`, a [`Value::Bytes`].
    pub(super) code: usize,
    /// `co_consts`, a [`Value::Sequence`].
    pub(super) constants: usize,
    /// `co_names`.
    pub(super) names: usize,
}

/// A marshal stream being walked: the cursor and the arena of what it read.
pub(super) struct Walker<'a> {
    reader: Reader<'a>,
    minor: u8,
    pub(super) values: Vec<Value>,
    refs: Vec<usize>,
    steps: usize,
}

/// Walk the marshal stream `data` of a CPython 3.`minor` code object,
/// calling `on_code` after the fields of each code object. Fails when the
/// stream is over [`MAX_BYTES`], its root is not a code object, it is
/// malformed or exhausts a budget, bytes follow the root, or `on_code`
/// fails.
pub(super) fn walk<'a>(
    data: &'a [u8],
    minor: u8,
    mut on_code: impl FnMut(&mut Walker<'a>, &CodeObject) -> Result<(), &'static str>,
) -> Result<Walker<'a>, &'static str> {
    if data.len() > MAX_BYTES {
        return Err("marshal byte budget exceeded");
    }
    if data.first().map(|b| b & 0x7f) != Some(b'c') {
        return Err("marshal root is not a code object");
    }
    let mut walker = Walker {
        reader: Reader::new(data),
        minor,
        values: Vec::new(),
        refs: Vec::new(),
        steps: 0,
    };
    walker.read(0, &mut on_code)?;
    if walker.reader.remaining() != 0 {
        return Err("trailing data after marshal code object");
    }
    Ok(walker)
}

impl<'a> Walker<'a> {
    /// The offset of the next byte to read.
    pub(super) fn pos(&self) -> usize {
        self.reader.pos()
    }

    /// Read the next `size` bytes.
    pub(super) fn take(&mut self, size: usize) -> Result<&'a [u8], &'static str> {
        self.reader.bytes(size).ok_or("truncated marshal value")
    }

    /// Read one byte.
    pub(super) fn byte(&mut self) -> Result<u8, &'static str> {
        self.reader.u8().ok_or("truncated marshal value")
    }

    fn integer(&mut self) -> Result<i32, &'static str> {
        self.reader
            .u32_le()
            .map(u32::cast_signed)
            .ok_or("truncated marshal value")
    }

    fn length(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.integer()?).map_err(|_| "negative marshal length")
    }

    /// The range of the `bytes` object in slot `node`.
    pub(super) fn bytes(&self, node: usize) -> Result<Range<usize>, &'static str> {
        match self.values.get(node) {
            Some(Value::Bytes(range)) => Ok(range.clone()),
            _ => Err("expected marshal bytes"),
        }
    }

    fn sequence<F>(
        &mut self,
        count: usize,
        depth: usize,
        on_code: &mut F,
    ) -> Result<Value, &'static str>
    where
        F: FnMut(&mut Self, &CodeObject) -> Result<(), &'static str>,
    {
        if count > MAX_OBJECTS || count > self.reader.remaining() {
            return Err("marshal container budget exceeded");
        }
        let mut children = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            children.push(self.read(depth + 1, on_code)?);
        }
        Ok(Value::Sequence(children))
    }

    fn code<F>(&mut self, depth: usize, on_code: &mut F) -> Result<Value, &'static str>
    where
        F: FnMut(&mut Self, &CodeObject) -> Result<(), &'static str>,
    {
        // 3.8-3.10 carry nlocals; 3.11+ moves it into localsplus.
        let fixed = if self.minor <= 10 { 24 } else { 20 };
        let header = self.take(fixed)?;
        let flags_at = self.pos() - 4;
        let flags = crate::bytes::u32_le(header, fixed - 4).ok_or("missing code flags")?;
        let code = self.read(depth + 1, on_code)?;
        let constants = self.read(depth + 1, on_code)?; // includes nested code objects
        if !matches!(self.values.get(code), Some(Value::Bytes(_)))
            || !matches!(self.values.get(constants), Some(Value::Sequence(_)))
        {
            return Err("invalid code-object bytecode or constants");
        }
        let names = self.read(depth + 1, on_code)?;
        // co_varnames, co_freevars, co_cellvars; or, from 3.11,
        // co_localsplusnames and co_localspluskinds.
        for _ in 0..if self.minor <= 10 { 3 } else { 2 } {
            self.read(depth + 1, on_code)?;
        }
        self.read(depth + 1, on_code)?; // co_filename
        self.read(depth + 1, on_code)?; // co_name
        if self.minor >= 11 {
            self.read(depth + 1, on_code)?; // co_qualname
        }
        self.take(4)?; // co_firstlineno
        self.read(depth + 1, on_code)?; // line table
        if self.minor >= 11 {
            self.read(depth + 1, on_code)?; // exception table
        }
        let object = CodeObject {
            flags_at,
            flags,
            code,
            constants,
            names,
        };
        on_code(self, &object)?;
        Ok(Value::Code)
    }

    /// Read one object into the arena, returning its slot.
    fn read<F>(&mut self, depth: usize, on_code: &mut F) -> Result<usize, &'static str>
    where
        F: FnMut(&mut Self, &CodeObject) -> Result<(), &'static str>,
    {
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
                let digits = crate::bytes::sat_usize(self.integer()?.unsigned_abs());
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
                let start = self.pos();
                self.take(length)?;
                Value::Bytes(start..self.pos())
            }
            b'u' | b'a' | b'A' | b't' | b'z' | b'Z' => {
                let length = if matches!(kind, b'z' | b'Z') {
                    usize::from(self.byte()?)
                } else {
                    self.length()?
                };
                let start = self.pos();
                self.take(length)?;
                Value::Text(start..self.pos())
            }
            b'(' => {
                let count = self.length()?;
                self.sequence(count, depth, on_code)?
            }
            b'[' | b'<' | b'>' => {
                let count = self.length()?;
                self.sequence(count, depth, on_code)?;
                Value::Other
            }
            b')' => {
                let count = usize::from(self.byte()?);
                self.sequence(count, depth, on_code)?
            }
            b'{' => {
                // A dict ends at a NULL (`0`) where a key would be.
                while self.reader.clone().u8() != Some(b'0') {
                    self.read(depth + 1, on_code)?;
                    self.read(depth + 1, on_code)?;
                }
                self.byte()?;
                Value::Other
            }
            b':' if self.minor >= 14 => {
                for _ in 0..3 {
                    self.read(depth + 1, on_code)?; // slice start, stop, step
                }
                Value::Other
            }
            b'c' => self.code(depth, on_code)?,
            _ => return Err("unsupported marshal type"),
        };
        *self.values.get_mut(node).ok_or("invalid marshal node")? = value;
        Ok(node)
    }
}
