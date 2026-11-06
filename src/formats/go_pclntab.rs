//! Go's function table, read from the pclntab every Go binary carries.
//!
//! The runtime needs the table to unwind stacks and print tracebacks, so even
//! a stripped Go binary (`-ldflags="-s -w"`) keeps it whole: every function's
//! name and entry address. Reading it is one pass over the table, where
//! rediscovering the same functions by disassembly costs a walk of every
//! instruction. A typed function inventory is what lets a Go binary skip
//! binform's recovery.
//!
//! The layouts, as Go's `debug/gosym` reads them. Offsets count from the
//! table's start; `P` is the pointer size, and a functab field is `P` wide
//! before Go 1.18 and 4 bytes from it.
//!
//! | magic        | Go        | header words after the 8-byte prefix          |
//! |--------------|-----------|-----------------------------------------------|
//! | `0xfffffffb` | 1.2–1.15  | nfunc, then the functab itself                |
//! | `0xfffffffa` | 1.16–1.17 | nfunc, nfiles, funcname, cu, file, pc, func   |
//! | `0xfffffff0` | 1.18–1.19 | nfunc, nfiles, textStart, funcname, cu, file, pc, func |
//! | `0xfffffff1` | 1.20+     | as 1.18                                       |
//!
//! The functab is `nfunc` pairs of (entry, offset of the function's `_func`
//! record) and a closing end address. A `_func` record repeats its entry and
//! then holds a 32-bit offset of its name in the funcname table. From 1.18
//! entries are 32-bit offsets from the start of the text section rather than
//! addresses; before 1.16 every offset counts from the table's start.
//!
//! That text start is the image's own text section (`.text`,
//! `__TEXT,__text`), as `debug/gosym` takes it, not the header's textStart
//! word: the word may be unrelocated, and Go 1.27's linker writes it as zero.
//!
//! In a hostile binary the table is attacker-controlled bytes, and a table
//! that parses keeps binform from recovering the file's functions. So a table
//! is believed only whole: functab entries ascending, every `_func` record
//! agreeing with the functab on its entry, every name in bounds, and an
//! address span inside the executable code that covers most of it. A decoy
//! grafted onto a payload to dodge disassembly fails the last test.

use crate::bytes;
use crate::output::Symbol;

/// The executable code of the image a pclntab claims to describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Code {
    /// The lowest executable address.
    pub(super) start: u64,
    /// One past the highest executable address.
    pub(super) end: u64,
    /// Executable bytes, gaps between the ranges excluded.
    pub(super) bytes: u64,
}

impl Code {
    /// The code spanned by executable `(address, size)` ranges; `None` when
    /// there is none.
    pub(super) fn of(ranges: impl IntoIterator<Item = (u64, u64)>) -> Option<Self> {
        ranges.into_iter().filter(|&(_, size)| size > 0).fold(
            None,
            |code: Option<Self>, (address, size)| {
                let end = address.saturating_add(size);
                Some(match code {
                    None => Self {
                        start: address,
                        end,
                        bytes: size,
                    },
                    Some(code) => Self {
                        start: code.start.min(address),
                        end: code.end.max(end),
                        bytes: code.bytes.saturating_add(size),
                    },
                })
            },
        )
    }

    /// Whether an inventory whose functions span `covered` bytes accounts for
    /// most of this code. One that covers less leaves most of the code for
    /// disassembly to find.
    pub(super) fn mostly_covered_by(self, covered: u64) -> bool {
        covered.saturating_mul(2) >= self.bytes
    }
}

/// More functions than any real program has (Kubernetes binaries carry about
/// 100,000); a larger count is a forged header.
const MAX_FUNCTIONS: usize = 1 << 21;

/// Candidate headers [`find`] tries in one region before giving up.
const MAX_CANDIDATES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    Go12,
    Go116,
    /// Go 1.18 and later: 32-bit functab fields relative to the text start.
    Go118,
}

/// A pclntab header, its offsets checked to lie in the table.
#[derive(Debug)]
struct Header {
    version: Version,
    big_endian: bool,
    pointer: usize,
    functions: usize,
    /// Start of the funcname table.
    names: usize,
    /// Start of the functab; `_func` offsets count from here (1.16+) or from
    /// the table's start (1.2).
    functab: usize,
    records: usize,
}

/// The pclntab magics across releases and the layout each introduced, in
/// both byte orders: the table is laid out in the target's, little-endian
/// for amd64/arm64/386/arm and big-endian for s390x/mips/ppc64.
const MAGICS: [([u8; 4], Version, bool); 8] = [
    ([0xfb, 0xff, 0xff, 0xff], Version::Go12, false),
    ([0xfa, 0xff, 0xff, 0xff], Version::Go116, false),
    ([0xf0, 0xff, 0xff, 0xff], Version::Go118, false),
    ([0xf1, 0xff, 0xff, 0xff], Version::Go118, false),
    ([0xff, 0xff, 0xff, 0xfb], Version::Go12, true),
    ([0xff, 0xff, 0xff, 0xfa], Version::Go116, true),
    ([0xff, 0xff, 0xff, 0xf0], Version::Go118, true),
    ([0xff, 0xff, 0xff, 0xf1], Version::Go118, true),
];

/// The layout and byte order `table`'s magic names.
fn magic(table: &[u8]) -> Option<(Version, bool)> {
    let magic = table.first_chunk::<4>()?;
    MAGICS
        .iter()
        .find(|(known, ..)| known == magic)
        .map(|&(_, version, big_endian)| (version, big_endian))
}

/// Whether `data` begins with a Go pclntab magic: proof a `.gopclntab` /
/// `__gopclntab` section is a Go function table, not a same-named decoy
/// grafted onto a stripped payload to make it look like Go and spare it
/// binform's recovery.
pub(super) fn has_magic(data: &[u8]) -> bool {
    magic(data).is_some()
}

impl Header {
    fn read(table: &[u8]) -> Result<Self, &'static str> {
        if table.len() < 8 {
            return Err("shorter than a header");
        }
        let (version, big_endian) = magic(table).ok_or("no pclntab magic")?;
        let &[0, 0, quantum, pointer] = table.get(4..8).ok_or("shorter than a header")? else {
            return Err("nonzero header padding");
        };
        if !matches!(quantum, 1 | 2 | 4) || !matches!(pointer, 4 | 8) {
            return Err("implausible instruction quantum or pointer size");
        }
        let pointer = usize::from(pointer);
        // The byte order and pointer size, which reading the words needs.
        let order = Self {
            version,
            big_endian,
            pointer,
            functions: 0,
            names: 0,
            functab: 0,
            records: 0,
        };
        let word = |index: usize| order.uint(table, 8 + index * pointer, pointer);
        let offset = |index: usize| {
            word(index)
                .and_then(|v| usize::try_from(v).ok())
                .filter(|&v| v <= table.len())
                .ok_or("header offset outside the table")
        };
        let functions = word(0)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|&n| (1..=MAX_FUNCTIONS).contains(&n))
            .ok_or("implausible function count")?;
        let (names, functab, records) = match version {
            Version::Go12 => (0, 8 + pointer, 0),
            Version::Go116 => (offset(2)?, offset(6)?, offset(6)?),
            Version::Go118 => (offset(3)?, offset(7)?, offset(7)?),
        };
        Ok(Self {
            functions,
            names,
            functab,
            records,
            ..order
        })
    }

    /// Width of one functab field.
    fn field(&self) -> usize {
        match self.version {
            Version::Go118 => 4,
            Version::Go12 | Version::Go116 => self.pointer,
        }
    }

    /// An unsigned `width`-byte integer at `at`, in the table's byte order.
    fn uint(&self, table: &[u8], at: usize, width: usize) -> Option<u64> {
        match (width, self.big_endian) {
            (4, false) => bytes::u32_le(table, at).map(u64::from),
            (4, true) => bytes::u32_be(table, at).map(u64::from),
            (8, false) => bytes::u64_le(table, at),
            (8, true) => bytes::u64_be(table, at),
            _ => None,
        }
    }

    /// The address a functab or `_func` entry field holds.
    fn address(&self, raw: u64, text: u64) -> u64 {
        match self.version {
            Version::Go118 => text.saturating_add(raw),
            Version::Go12 | Version::Go116 => raw,
        }
    }
}

/// Every function `table` names, as typed `Function` symbols at their entry
/// addresses, when it holds together as a Go pclntab for `code`, whose Go
/// text section starts at `text`. `None` otherwise; the reason is logged.
pub(super) fn functions(table: &[u8], code: Code, text: u64) -> Option<Vec<Symbol>> {
    match read(table, code, text) {
        Ok(functions) => Some(functions),
        Err(reason) => {
            tracing::debug!(bytes = table.len(), reason, "go pclntab: not used");
            None
        }
    }
}

fn read(table: &[u8], code: Code, text: u64) -> Result<Vec<Symbol>, &'static str> {
    let header = Header::read(table)?;
    let field = header.field();
    let pairs = header
        .functions
        .checked_mul(2 * field)
        .ok_or("functab overflows")?;
    let end_field = header
        .functab
        .checked_add(pairs)
        .ok_or("functab overflows")?;
    if end_field
        .checked_add(field)
        .is_none_or(|end| end > table.len())
    {
        return Err("functab runs past the table");
    }
    let raw = |at: usize| {
        header
            .uint(table, at, field)
            .ok_or("functab runs past the table")
    };
    // The span the functab claims, first entry to closing address, is
    // checked against the code before any record is walked: a forged count
    // of up to `MAX_FUNCTIONS` records must not cost a walk to be refused.
    let first = header.address(raw(header.functab)?, text);
    let end = header.address(raw(end_field)?, text);
    if end < first {
        return Err("functab end precedes its last entry");
    }
    if first < code.start || end > code.end {
        return Err("functions lie outside the executable code");
    }
    if !code.mostly_covered_by(end - first) {
        return Err("functions cover too little of the executable code");
    }
    // Names are disjoint slices of the funcname table in an honest table; a
    // forged one can point every record at one long name, so the copies are
    // bounded by the table's size.
    let mut name_budget = table.len().saturating_mul(2);
    let mut out = Vec::with_capacity(header.functions);
    let mut previous = None;
    for index in 0..header.functions {
        let at = header.functab + index * 2 * field;
        let entry_raw = raw(at)?;
        let entry = header.address(entry_raw, text);
        if previous.is_some_and(|previous| entry < previous) {
            return Err("functab entries out of order");
        }
        previous = Some(entry);
        let record = usize::try_from(raw(at + field)?)
            .ok()
            .and_then(|offset| header.records.checked_add(offset))
            .ok_or("function record outside the table")?;
        // A `_func` record opens with its own entry, the functab's mirror.
        if header.uint(table, record, field) != Some(entry_raw) {
            return Err("function record disagrees with the functab");
        }
        // A signed 32-bit offset; a negative one points before the table.
        let name_offset = record
            .checked_add(field)
            .and_then(|at| header.uint(table, at, 4))
            .and_then(|offset| i32::try_from(offset).ok())
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| header.names.checked_add(offset))
            .ok_or("function name outside the table")?;
        let name = table
            .get(name_offset..)
            .and_then(|rest| rest.get(..memchr::memchr(0, rest)?))
            .ok_or("function name runs past the table")?;
        if name.is_empty() {
            continue;
        }
        name_budget = name_budget
            .checked_sub(name.len())
            .ok_or("function names exceed the table")?;
        out.push(Symbol::Function {
            name: String::from_utf8_lossy(name).into_owned(),
            offset: Some(entry),
            complexity: None,
            callees: Vec::new(),
        });
    }
    if previous.is_some_and(|last| end < last) {
        return Err("functab end precedes its last entry");
    }
    tracing::debug!(
        version = ?header.version,
        functions = out.len(),
        covered = end - first,
        code = code.bytes,
        "go pclntab: function inventory read"
    );
    Ok(out)
}

/// The function table in `region`, for a binary that keeps its pclntab in a
/// general data section rather than one of its own (Go's PE linker folds it
/// into `.rdata`). Each candidate header is held to everything [`functions`]
/// checks, so a stray magic in the data cannot pass.
pub(super) fn find(region: &[u8], code: Code, text: u64) -> Option<Vec<Symbol>> {
    let mut starts: Vec<usize> = MAGICS
        .iter()
        .flat_map(|(magic, ..)| {
            memchr::memmem::find_iter(region, magic)
                .filter(|&at| region.get(at + 4..at + 6) == Some(&[0, 0]))
                .take(MAX_CANDIDATES)
        })
        .collect();
    starts.sort_unstable();
    starts.truncate(MAX_CANDIDATES);
    starts
        .into_iter()
        .find_map(|at| read(region.get(at..)?, code, text).ok())
}

#[cfg(test)]
mod tests;
