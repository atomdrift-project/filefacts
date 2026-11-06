//! The pickle opcode table: each opcode's name and how its operand is laid
//! out, for every reader of a pickle stream. Decoding an opcode reads its
//! operand and nothing else; what the opcode does is the reader's business.

use crate::bytes::Reader;

/// The operand an opcode carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arg<'a> {
    /// No operand.
    None,
    /// A fixed-width little-endian unsigned integer (one, two, four or eight
    /// bytes). BININT's is signed: narrow it to `u32`, then `cast_signed`.
    Int(u64),
    /// A length-prefixed byte string, or BINFLOAT's eight bytes.
    Bytes(&'a [u8]),
    /// A newline-terminated line, without the newline.
    Line(&'a [u8]),
    /// GLOBAL's and INST's two lines: module and attribute.
    Lines(&'a [u8], &'a [u8]),
}

/// One decoded opcode.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Op<'a> {
    pub(crate) code: u8,
    pub(crate) arg: Arg<'a>,
}

/// Why no opcode could be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// A byte no pickle protocol assigns.
    Unknown(u8),
    /// The opcode or its operand runs past the input.
    Truncated,
}

/// Decode the opcode at `at` in `bytes`, returning it and the offset just
/// past its operand.
pub(crate) fn decode(bytes: &[u8], at: usize) -> Result<(Op<'_>, usize), DecodeError> {
    let mut r = Reader::at(bytes, at);
    let code = r.u8().ok_or(DecodeError::Truncated)?;
    if name(code).is_none() {
        return Err(DecodeError::Unknown(code));
    }
    let arg = operand(code, &mut r).ok_or(DecodeError::Truncated)?;
    Ok((Op { code, arg }, r.pos()))
}

/// Read the operand of `code` from `r`.
fn operand<'a>(code: u8, r: &mut Reader<'a>) -> Option<Arg<'a>> {
    let counted = |r: &mut Reader<'a>, len: u64| r.bytes(usize::try_from(len).ok()?);
    Some(match code {
        0x80 | b'K' | 0x82 | b'h' | b'q' => Arg::Int(u64::from(r.u8()?)),
        0x83 | b'M' => Arg::Int(u64::from(r.u16_le()?)),
        0x84 | b'J' | b'j' | b'r' => Arg::Int(u64::from(r.u32_le()?)),
        0x95 => Arg::Int(r.u64_le()?),
        b'G' => Arg::Bytes(r.bytes(8)?),
        b'I' | b'L' | b'F' | b'V' | b'S' | b'g' | b'p' => Arg::Line(line(r)?),
        b'c' | b'i' => Arg::Lines(line(r)?, line(r)?),
        0x8A | 0x8C | b'U' | b'C' => {
            let len = r.u8()?;
            Arg::Bytes(counted(r, u64::from(len))?)
        }
        0x8B | b'X' | b'T' | b'B' => {
            let len = r.u32_le()?;
            Arg::Bytes(counted(r, u64::from(len))?)
        }
        0x8D | 0x8E | 0x96 => {
            let len = r.u64_le()?;
            Arg::Bytes(counted(r, len)?)
        }
        _ => Arg::None,
    })
}

/// The bytes up to the next newline, stepping past it.
fn line<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let mut probe = r.clone();
    let mut len = 0;
    while probe.u8()? != b'\n' {
        len += 1;
    }
    let text = r.bytes(len)?;
    r.skip(1)?;
    Some(text)
}

/// Name of a pickle opcode, or `None` for a byte no protocol assigns.
pub(crate) const fn name(op: u8) -> Option<&'static str> {
    Some(match op {
        b'(' => "MARK",
        b'.' => "STOP",
        b'0' => "POP",
        b'1' => "POP_MARK",
        b'2' => "DUP",
        b'F' => "FLOAT",
        b'I' => "INT",
        b'J' => "BININT",
        b'K' => "BININT1",
        b'L' => "LONG",
        b'M' => "BININT2",
        b'N' => "NONE",
        b'P' => "PERSID",
        b'Q' => "BINPERSID",
        b'R' => "REDUCE",
        b'S' => "STRING",
        b'T' => "BINSTRING",
        b'B' => "BINBYTES",
        b'C' => "SHORT_BINBYTES",
        b'U' => "SHORT_BINSTRING",
        b'V' => "UNICODE",
        b'X' => "BINUNICODE",
        b'a' => "APPEND",
        b'b' => "BUILD",
        b'c' => "GLOBAL",
        b'd' => "DICT",
        b'}' => "EMPTY_DICT",
        b'e' => "APPENDS",
        b'g' => "GET",
        b'h' => "BINGET",
        b'i' => "INST",
        b'j' => "LONG_BINGET",
        b'l' => "LIST",
        b']' => "EMPTY_LIST",
        b'o' => "OBJ",
        b'p' => "PUT",
        b'q' => "BINPUT",
        b'r' => "LONG_BINPUT",
        b's' => "SETITEM",
        b't' => "TUPLE",
        b')' => "EMPTY_TUPLE",
        b'u' => "SETITEMS",
        b'G' => "BINFLOAT",
        0x80 => "PROTO",
        0x81 => "NEWOBJ",
        0x82 => "EXT1",
        0x83 => "EXT2",
        0x84 => "EXT4",
        0x85 => "TUPLE1",
        0x86 => "TUPLE2",
        0x87 => "TUPLE3",
        0x88 => "NEWTRUE",
        0x89 => "NEWFALSE",
        0x8A => "LONG1",
        0x8B => "LONG4",
        0x8C => "SHORT_BINUNICODE",
        0x8D => "BINUNICODE8",
        0x8E => "BINBYTES8",
        0x8F => "EMPTY_SET",
        0x90 => "ADDITEMS",
        0x91 => "FROZENSET",
        0x92 => "NEWOBJ_EX",
        0x93 => "STACK_GLOBAL",
        0x94 => "MEMOIZE",
        0x95 => "FRAME",
        0x96 => "BYTEARRAY8",
        0x97 => "NEXT_BUFFER",
        0x98 => "READONLY_BUFFER",
        _ => return None,
    })
}
