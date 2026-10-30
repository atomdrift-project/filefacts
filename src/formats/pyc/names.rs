//! Bounded, non-executing marshal reader for code-object name tables.
//!
//! Names in `co_consts` are data, not identifiers. Keep reference slots as
//! arena indices so recursive/shared containers cannot cause deep cloning.
use crate::output::{Symbol, Symbols};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_DEPTH: usize = 64;
const MAX_NAMES: usize = 20_000;
const MAX_NAME_BYTES: usize = 1024;

enum Value<'a> {
    Other,
    Bytes,
    Text(&'a [u8], usize),
    Sequence(Vec<usize>),
    Code,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    minor: u8,
    values: Vec<Value<'a>>,
    refs: Vec<usize>,
    names: Vec<(String, usize)>,
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
        self.take(1)?
            .first()
            .copied()
            .ok_or("truncated marshal value")
    }

    fn integer(&mut self) -> Result<i32, &'static str> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| "truncated marshal value")?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn length(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.integer()?).map_err(|_| "negative marshal length")
    }

    fn sequence(&mut self, count: usize, depth: usize) -> Result<Value<'a>, &'static str> {
        if count > MAX_OBJECTS || count > self.data.len().saturating_sub(self.pos) {
            return Err("marshal container budget exceeded");
        }
        let mut children = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            children.push(self.read(depth + 1)?);
        }
        Ok(Value::Sequence(children))
    }

    fn code(&mut self, depth: usize) -> Result<Value<'a>, &'static str> {
        // 3.8-3.10 includes nlocals; 3.11+ moves that into localsplus.
        self.take(if self.minor <= 10 { 24 } else { 20 })?;
        let code = self.read(depth + 1)?;
        let constants = self.read(depth + 1)?; // includes nested code objects
        if !matches!(self.values.get(code), Some(Value::Bytes))
            || !matches!(self.values.get(constants), Some(Value::Sequence(_)))
        {
            return Err("invalid code-object bytecode or constants");
        }
        let names = self.read(depth + 1)?;
        if self.minor <= 10 {
            self.read(depth + 1)?; // co_varnames
            self.read(depth + 1)?; // co_freevars
            self.read(depth + 1)?; // co_cellvars
        } else {
            self.read(depth + 1)?; // co_localsplusnames
            self.read(depth + 1)?; // co_localspluskinds
        }
        self.read(depth + 1)?; // co_filename
        self.read(depth + 1)?; // co_name
        if self.minor >= 11 {
            self.read(depth + 1)?; // co_qualname
        }
        self.take(4)?; // co_firstlineno
        self.read(depth + 1)?; // line table
        if self.minor >= 11 {
            self.read(depth + 1)?; // exception table
        }
        let Some(Value::Sequence(ids)) = self.values.get(names) else {
            return Err("code-object names are not a tuple");
        };
        for id in ids {
            let Some(Value::Text(bytes, offset)) = self.values.get(*id) else {
                return Err("code-object name is not a string");
            };
            let name = std::str::from_utf8(bytes).map_err(|_| "invalid UTF-8 code-object name")?;
            if name.len() > MAX_NAME_BYTES {
                return Err("marshal identifier length budget exceeded");
            }
            if self.names.len() >= MAX_NAMES {
                return Err("marshal identifier budget exceeded");
            }
            if !name.is_empty() {
                self.names.push((name.to_owned(), *offset));
            }
        }
        Ok(Value::Code)
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
                self.take(length)?;
                Value::Bytes
            }
            b'u' | b'a' | b'A' | b't' | b'z' | b'Z' => {
                let length = if matches!(kind, b'z' | b'Z') {
                    usize::from(self.byte()?)
                } else {
                    self.length()?
                };
                let offset = self.pos;
                Value::Text(self.take(length)?, offset)
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
        *self.values.get_mut(node).ok_or("invalid marshal node")? = value;
        Ok(node)
    }
}

pub(super) fn extract(body: &[u8], minor: u8, symbols: &mut Symbols) -> Result<(), &'static str> {
    if body.len() > MAX_BYTES {
        return Err("marshal byte budget exceeded");
    }
    if body.first().map(|b| b & 0x7f) != Some(b'c') {
        return Err("marshal root is not a code object");
    }
    let mut reader = Reader {
        data: body,
        pos: 0,
        minor,
        values: Vec::new(),
        refs: Vec::new(),
        names: Vec::new(),
        steps: 0,
    };
    reader.read(0)?;
    if reader.pos != body.len() {
        return Err("trailing data after marshal code object");
    }
    // Commit only a completely parsed stream. A truncated stream must not
    // leave partial identifiers that could satisfy an attack composite.
    reader.names.sort_unstable();
    reader.names.dedup();
    for (name, offset) in reader.names {
        symbols.push(Symbol::Identifier {
            name,
            offset: Some((offset + 16) as u64),
        });
    }
    Ok(())
}
