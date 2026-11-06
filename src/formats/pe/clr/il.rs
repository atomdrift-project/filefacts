//! Bounded ECMA-335 metadata and IL inspection. No managed assembly is loaded.

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};

use super::operands;
use crate::bytes::{sat_usize, u16_le, u32_le, u64_le};

const MAX_ROWS: usize = 65536;
const MAX_INSTRUCTIONS: usize = 2_000_000;
const MAX_CALLS: usize = 32768;
/// Name bytes one analysis may copy, counting every copy it keeps: a few
/// hundred kilobytes of rows can name one 4 KiB heap string, or a type
/// nested sixteen deep in such names, hundreds of thousands of times, and
/// each name lands in several views.
const MAX_NAME_BYTES: usize = 64 << 20;

/// The metadata tables the walk reads, by number (ECMA-335 II.22).
const TYPE_REF: usize = 1;
const TYPE_DEF: usize = 2;
const FIELD: usize = 4;
const METHOD_PTR: usize = 5;
const METHOD_DEF: usize = 6;
const MEMBER_REF: usize = 10;
const MODULE_REF: usize = 26;
const TYPE_SPEC: usize = 27;
const IMPL_MAP: usize = 28;
const ASSEMBLY_REF: usize = 35;
const METHOD_SPEC: usize = 43;

/// Metadata tokens: the table number in the top byte, the row below it.
const METHOD_DEF_TOKEN: u32 = 0x0600_0000;
const MEMBER_REF_TOKEN: u32 = 0x0a00_0000;
const METHOD_SPEC_TOKEN: u32 = 0x2b00_0000;

/// The IL opcodes the body scan counts (ECMA-335 III).
const CALL: u16 = 0x28;
const CALLI: u16 = 0x29;
const SWITCH: u16 = 0x45;
const XOR: u16 = 0x61;
const CALLVIRT: u16 = 0x6f;
const NEWOBJ: u16 = 0x73;
const STIND_I1: u16 = 0x9c;
const LDTOKEN: u16 = 0xd0;
/// The prefix of the two-byte opcodes.
const PREFIX: u8 = 0xfe;

#[derive(Debug, Clone)]
pub(super) struct Named {
    pub(super) name: String,
    pub(super) offset: usize,
    pub(super) library: Option<String>,
    pub(super) arity: Option<usize>,
}
#[derive(Debug)]
pub(super) struct Method {
    pub(super) name: String,
    pub(super) offset: usize,
    pub(super) callees: Vec<String>,
}
#[derive(Debug, Default)]
pub(super) struct Analysis {
    pub(super) references: Vec<Named>,
    pub(super) methods: Vec<Method>,
    pub(super) calls: Vec<Named>,
    pub(super) method_count: usize,
    pub(super) instruction_count: usize,
    pub(super) calli_count: usize,
    pub(super) calli_methods: usize,
    pub(super) resolver_pointer_methods: usize,
    pub(super) resource_xor_methods: usize,
    pub(super) invalid_methods: usize,
    pub(super) truncated: bool,
}
fn index(b: &[u8], p: usize, w: usize) -> Option<u32> {
    if w == 2 {
        u16_le(b, p).map(u32::from)
    } else {
        u32_le(b, p)
    }
}
fn arity(sig: &[u8]) -> Option<usize> {
    let mut p = 1;
    if sig.first()? & 0x10 != 0 {
        p += compressed(sig, p)?.1;
    }
    let n = sat_usize(compressed(sig, p)?.0);
    (n <= 1024).then_some(n)
}
fn compressed(b: &[u8], p: usize) -> Option<(u32, usize)> {
    let a = *b.get(p)?;
    if a & 128 == 0 {
        return Some((u32::from(a), 1));
    }
    if a & 0xc0 == 0x80 {
        return Some((((u32::from(a) & 63) << 8) | u32::from(*b.get(p + 1)?), 2));
    }
    if a & 0xe0 == 0xc0 {
        return Some((
            ((u32::from(a) & 31) << 24)
                | (u32::from(*b.get(p + 1)?) << 16)
                | (u32::from(*b.get(p + 2)?) << 8)
                | u32::from(*b.get(p + 3)?),
            4,
        ));
    }
    None
}

struct Tables<'a> {
    root: &'a [u8],
    root_offset: usize,
    strings: usize,
    strings_len: usize,
    blob: usize,
    blob_len: usize,
    data: &'a [u8],
    rows: [usize; 64],
    starts: [usize; 45],
    widths: [usize; 45],
    s: usize,
    g: usize,
    b: usize,
    /// Name bytes left to copy, of [`MAX_NAME_BYTES`].
    names: Cell<usize>,
    /// Whether a copy was ever refused for want of budget.
    spent: Cell<bool>,
}
impl<'a> Tables<'a> {
    fn new(root: &'a [u8], root_offset: usize) -> Option<Self> {
        if root.get(..4)? != b"BSJB" {
            return None;
        }
        let v = sat_usize(u32_le(root, 12)?);
        let mut p = 16usize.checked_add(v.checked_add(3)? & !3)?;
        let n = usize::from(u16_le(root, p + 2)?);
        if n > 64 {
            return None;
        }
        p += 4;
        let (mut strings, mut blob, mut table) = (None, None, None);
        for _ in 0..n {
            let off = sat_usize(u32_le(root, p)?);
            let len = sat_usize(u32_le(root, p + 4)?);
            p += 8;
            let tail = root.get(p..)?;
            let end = tail.iter().take(32).position(|b| *b == 0)?;
            let name = tail.get(..end)?;
            root.get(off..off.checked_add(len)?)?;
            match name {
                b"#Strings" => strings = Some((off, len)),
                b"#Blob" => blob = Some((off, len)),
                b"#~" | b"#-" => table = Some((off, len)),
                _ => {}
            }
            p = p.checked_add((end + 1 + 3) & !3)?;
        }
        let (strings, strings_len) = strings?;
        let (blob, blob_len) = blob?;
        let (t, tl) = table?;
        let data = root.get(t..t.checked_add(tl)?)?;
        let heap = *data.get(6)?;
        let valid = u64_le(data, 8)?;
        if valid >> 45 != 0 {
            return None;
        }
        let mut rows = [0usize; 64];
        p = 24;
        for (i, row) in rows.iter_mut().enumerate() {
            if valid & (1u64 << i) != 0 {
                *row = sat_usize(u32_le(data, p)?);
                p += 4;
                if *row > MAX_ROWS {
                    return None;
                }
            }
        }
        let mut out = Self {
            root,
            root_offset,
            strings,
            strings_len,
            blob,
            blob_len,
            data,
            rows,
            starts: [0; 45],
            widths: [0; 45],
            s: if heap & 1 != 0 { 4 } else { 2 },
            g: if heap & 2 != 0 { 4 } else { 2 },
            b: if heap & 4 != 0 { 4 } else { 2 },
            names: Cell::new(MAX_NAME_BYTES),
            spent: Cell::new(false),
        };
        for (i, row_count) in rows.iter().enumerate().take(45) {
            *out.starts.get_mut(i)? = p;
            let w = out.row_width(i);
            *out.widths.get_mut(i)? = w;
            p = p.checked_add(w.checked_mul(*row_count)?)?;
            if p > data.len() {
                return None;
            }
        }
        Some(out)
    }
    fn ix(&self, t: usize) -> usize {
        if self.rows.get(t).copied().unwrap_or(0) < 65536 {
            2
        } else {
            4
        }
    }
    fn coded(&self, bits: usize, t: &[usize]) -> usize {
        if t.iter()
            .any(|i| self.rows.get(*i).copied().unwrap_or(0) >= (1usize << (16 - bits)))
        {
            4
        } else {
            2
        }
    }
    /// The width of a row of table `t`, from the column layouts of
    /// ECMA-335 II.22 in table-number order.
    fn row_width(&self, t: usize) -> usize {
        let (s, g, b) = (self.s, self.g, self.b);
        let i = |t| self.ix(t);
        let c = |bits, t: &[usize]| self.coded(bits, t);
        let tr = c(2, &[2, 1, 27]);
        match t {
            0 => 2 + s + 3 * g,
            1 => c(2, &[0, 26, 35, 1]) + 2 * s,
            2 => 4 + 2 * s + tr + i(4) + i(6),
            3 => i(4),
            4 => 2 + s + b,
            5 => i(6),
            6 => 8 + s + b + i(8),
            7 => i(8),
            8 => 4 + s,
            9 => i(2) + tr,
            10 => c(3, &[2, 1, 26, 6, 27]) + s + b,
            11 => 2 + c(2, &[4, 8, 23]) + b,
            12 => {
                c(
                    5,
                    &[
                        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42,
                        44, 43,
                    ],
                ) + c(3, &[6, 10])
                    + b
            }
            13 => c(1, &[4, 8]) + b,
            14 => 2 + c(2, &[2, 6, 32]) + b,
            15 => 6 + i(2),
            16 => 4 + i(4),
            17 => b,
            18 => i(2) + i(20),
            19 => i(20),
            20 => 2 + s + tr,
            21 => i(2) + i(23),
            22 => i(23),
            23 => 2 + s + b,
            24 => 2 + i(6) + c(1, &[20, 23]),
            25 => i(2) + 2 * c(1, &[6, 10]),
            26 => s,
            27 => b,
            28 => 2 + c(1, &[4, 6]) + s + i(26),
            29 => 4 + i(4),
            30 => 8,
            31 => 4,
            32 => 16 + b + 2 * s,
            33 => 4,
            34 => 12,
            35 => 12 + 2 * b + 2 * s,
            36 => 4 + i(35),
            37 => 12 + i(35),
            38 => 4 + s + b,
            39 => 8 + 2 * s + c(2, &[38, 35, 39]),
            40 => 8 + s + c(2, &[38, 35, 39]),
            41 => 2 * i(2),
            42 => 4 + c(1, &[2, 6]) + s,
            43 => c(1, &[6, 10]) + b,
            44 => i(42) + tr,
            _ => 0,
        }
    }
    fn row(&self, t: usize, rid: usize) -> Option<&'a [u8]> {
        if rid == 0 || rid > *self.rows.get(t)? {
            return None;
        }
        let width = *self.widths.get(t)?;
        let p = self
            .starts
            .get(t)?
            .checked_add((rid - 1).checked_mul(width)?)?;
        self.data.get(p..p.checked_add(width)?)
    }
    /// Charge `len` name bytes to the budget; `None` once it cannot pay.
    fn charge(&self, len: usize) -> Option<()> {
        let Some(left) = self.names.get().checked_sub(len) else {
            self.spent.set(true);
            return None;
        };
        self.names.set(left);
        Some(())
    }
    /// A copy of `named`, charged to the budget.
    fn copy(&self, named: &Named) -> Option<Named> {
        self.charge(
            named
                .name
                .len()
                .saturating_add(named.library.as_ref().map_or(0, String::len)),
        )?;
        Some(named.clone())
    }
    fn string(&self, n: u32) -> Option<(String, usize)> {
        let n = sat_usize(n);
        if n >= self.strings_len {
            return None;
        }
        let p = self.strings.checked_add(n)?;
        let b = self.root.get(p..self.strings + self.strings_len)?;
        let end = b.iter().take(4096).position(|x| *x == 0)?;
        self.charge(end)?;
        Some((
            std::str::from_utf8(b.get(..end)?).ok()?.to_string(),
            self.root_offset + p,
        ))
    }
    fn blob(&self, n: u32) -> Option<&'a [u8]> {
        let n = sat_usize(n);
        if n >= self.blob_len {
            return None;
        }
        let b = self.root.get(self.blob..self.blob + self.blob_len)?;
        let (len, w) = compressed(b, n)?;
        b.get(n.checked_add(w)?..n.checked_add(w)?.checked_add(sat_usize(len))?)
    }
    fn type_name(&self, t: usize, rid: usize, depth: u8) -> Option<(String, Option<String>)> {
        if depth > 16 {
            return None;
        }
        let row = self.row(t, rid)?;
        if t == TYPE_SPEC {
            let blob = self.blob(index(row, 0, self.b)?)?;
            let mut p = 0;
            if blob.first() == Some(&0x15) {
                p += 1;
            }
            if !matches!(blob.get(p), Some(0x11 | 0x12)) {
                return None;
            }
            let (v, _) = compressed(blob, p + 1)?;
            return self.type_name(
                if v & 3 == 1 {
                    TYPE_REF
                } else if v.trailing_zeros() >= 2 {
                    TYPE_DEF
                } else {
                    TYPE_SPEC
                },
                sat_usize(v >> 2),
                depth + 1,
            );
        }
        let p = if t == TYPE_REF {
            self.coded(2, &[0, MODULE_REF, ASSEMBLY_REF, TYPE_REF])
        } else {
            4
        };
        let name = self.string(index(row, p, self.s)?)?.0;
        let ns = self.string(index(row, p + self.s, self.s)?)?.0;
        let mut full = if ns.is_empty() {
            name.clone()
        } else {
            format!("{ns}.{name}")
        };
        let mut lib = None;
        if t == TYPE_REF {
            let scope = index(row, 0, p)?;
            let rid = sat_usize(scope >> 2);
            match scope & 3 {
                2 => {
                    let a = self.row(ASSEMBLY_REF, rid)?;
                    lib = Some(self.string(index(a, 12 + self.b, self.s)?)?.0);
                }
                1 => {
                    let m = self.row(MODULE_REF, rid)?;
                    lib = Some(self.string(index(m, 0, self.s)?)?.0);
                }
                3 => {
                    let parent = self.type_name(TYPE_REF, rid, depth + 1)?;
                    full = format!("{}.{}", parent.0, name);
                    lib = parent.1;
                }
                _ => {}
            }
        }
        Some((full, lib))
    }
}

#[derive(Default)]
struct Body {
    instructions: usize,
    calli: usize,
    xor: usize,
    store_byte: usize,
    calls: Vec<(u32, usize)>,
    tokens: Vec<u32>,
    valid: bool,
}
fn il_body(bytes: &[u8], offset: usize, budget: usize) -> Body {
    let mut out = Body::default();
    let Some(first) = bytes.get(offset).copied() else {
        return out;
    };
    let (code_start, len) = if first & 3 == 2 {
        (offset + 1, usize::from(first >> 2))
    } else if first & 3 == 3 {
        let Some(flags) = u16_le(bytes, offset) else {
            return out;
        };
        let hdr = usize::from(flags >> 12) * 4;
        if !(12..=60).contains(&hdr) {
            return out;
        }
        let Some(len) = u32_le(bytes, offset + 4) else {
            return out;
        };
        (offset + hdr, sat_usize(len))
    } else {
        return out;
    };
    if len > 2 << 20 {
        return out;
    }
    let Some(end) = code_start.checked_add(len) else {
        return out;
    };
    let Some(code) = bytes.get(code_start..end) else {
        return out;
    };
    let mut p = 0;
    while p < code.len() {
        if out.instructions >= budget {
            return out;
        }
        let at = p;
        let Some(&first) = code.get(p) else {
            return out;
        };
        let mut op = u16::from(first);
        p += 1;
        if first == PREFIX {
            let Some(b) = code.get(p) else {
                return out;
            };
            op = 0xfe00 | u16::from(*b);
            p += 1;
        }
        let n = if op == SWITCH {
            let Some(n) = u32_le(code, p) else {
                return out;
            };
            let Some(n) = sat_usize(n).checked_mul(4).and_then(|n| n.checked_add(4)) else {
                return out;
            };
            n
        } else {
            let Some(n) = operands::width(op) else {
                return out;
            };
            n
        };
        let Some(next) = p.checked_add(n).filter(|n| *n <= code.len()) else {
            return out;
        };
        out.instructions += 1;
        if op == CALLI {
            out.calli += 1;
        }
        if op == XOR {
            out.xor += 1;
        }
        if op == STIND_I1 {
            out.store_byte += 1;
        }
        if matches!(op, CALL | CALLVIRT | NEWOBJ) {
            if let Some(token) = u32_le(code, p) {
                if out.calls.len() < MAX_CALLS {
                    out.calls.push((token, code_start + at));
                }
            }
        }
        if op == LDTOKEN {
            if let Some(token) = u32_le(code, p) {
                out.tokens.push(token);
            }
        }
        p = next;
    }
    out.valid = true;
    out
}

pub(super) fn analyze(
    root: &[u8],
    root_offset: usize,
    bytes: &[u8],
    map: impl Fn(u32) -> Option<usize>,
) -> Option<Analysis> {
    let t = Tables::new(root, root_offset)?;
    let mut result = Analysis {
        method_count: t.rows[METHOD_DEF],
        ..Analysis::default()
    };
    let walked = walk(&t, &mut result, bytes, map);
    // A malformed table yields nothing; a spent name budget keeps what was
    // read within it.
    if t.spent.get() {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "clr-il",
            budget = MAX_NAME_BYTES,
            "CLR names past the copy budget; analysis cut short"
        );
        result.truncated = true;
    } else {
        walked?;
    }
    Some(result)
}

/// Read the names, references and method bodies of `t` into `result`.
/// `None` for a malformed table or once the name budget is spent.
fn walk(
    t: &Tables<'_>,
    result: &mut Analysis,
    bytes: &[u8],
    map: impl Fn(u32) -> Option<usize>,
) -> Option<()> {
    let mut definitions = vec![String::new(); t.rows[METHOD_DEF] + 1];
    for rid in 1..=t.rows[TYPE_DEF] {
        let row = t.row(TYPE_DEF, rid)?;
        // TypeDef's MethodList column, past Flags, Name, Namespace,
        // Extends and FieldList.
        let p = 4 + 2 * t.s + t.coded(2, &[TYPE_DEF, TYPE_REF, TYPE_SPEC]) + t.ix(FIELD);
        let start = sat_usize(index(row, p, t.ix(METHOD_DEF))?);
        let end = if rid < t.rows[TYPE_DEF] {
            sat_usize(index(t.row(TYPE_DEF, rid + 1)?, p, t.ix(METHOD_DEF))?)
        } else if t.rows[METHOD_PTR] > 0 {
            t.rows[METHOD_PTR] + 1
        } else {
            t.rows[METHOD_DEF] + 1
        };
        if start > end || end > t.rows[METHOD_DEF] + 1 {
            return None;
        }
        let owner = t.type_name(TYPE_DEF, rid, 0)?.0;
        for list in start..end {
            let m = if t.rows[METHOD_PTR] > 0 {
                sat_usize(index(t.row(METHOD_PTR, list)?, 0, t.ix(METHOD_DEF))?)
            } else {
                list
            };
            let row = t.row(METHOD_DEF, m)?;
            let name = t.string(index(row, 8, t.s)?)?.0;
            t.charge(owner.len().saturating_add(1))?;
            *definitions.get_mut(m)? = format!("{owner}.{name}");
        }
    }
    let mut references = BTreeMap::new();
    for rid in 1..=t.rows[MEMBER_REF] {
        let row = t.row(MEMBER_REF, rid)?;
        let w = t.coded(3, &[TYPE_DEF, TYPE_REF, MODULE_REF, METHOD_DEF, TYPE_SPEC]);
        let parent = index(row, 0, w)?;
        let (name, offset) = t.string(index(row, w, t.s)?)?;
        let sig = t.blob(index(row, w + t.s, t.b)?)?;
        if sig.first().is_none_or(|x| x & 15 == 6) {
            continue;
        }
        let tag = parent & 7;
        let owner = match tag {
            0 => t.type_name(TYPE_DEF, sat_usize(parent >> 3), 0),
            1 => t.type_name(TYPE_REF, sat_usize(parent >> 3), 0),
            4 => t.type_name(TYPE_SPEC, sat_usize(parent >> 3), 0),
            _ => None,
        };
        let Some((owner, lib)) = owner else {
            continue;
        };
        let r = Named {
            name: format!("{owner}.{name}"),
            offset,
            library: lib,
            arity: arity(sig),
        };
        if tag != 0 && r.library.is_some() {
            result.references.push(t.copy(&r)?);
        }
        references.insert(MEMBER_REF_TOKEN | u32::try_from(rid).ok()?, r);
    }
    for (rid, name) in definitions.iter().enumerate().skip(1) {
        t.charge(name.len())?;
        references.insert(
            METHOD_DEF_TOKEN | u32::try_from(rid).ok()?,
            Named {
                name: name.clone(),
                offset: 0,
                library: None,
                arity: t
                    .row(METHOD_DEF, rid)
                    .and_then(|r| index(r, 8 + t.s, t.b))
                    .and_then(|n| t.blob(n))
                    .and_then(arity),
            },
        );
    }
    // P/Invoke import maps bind a MethodDef to the actual native entry point.
    for rid in 1..=t.rows[IMPL_MAP] {
        let row = t.row(IMPL_MAP, rid)?;
        let w = t.coded(1, &[FIELD, METHOD_DEF]);
        let member = index(row, 2, w)?;
        if member & 1 == 0 {
            continue;
        }
        let (name, offset) = t.string(index(row, 2 + w, t.s)?)?;
        let scope = sat_usize(index(row, 2 + w + t.s, t.ix(MODULE_REF))?);
        let lib = t.string(index(t.row(MODULE_REF, scope)?, 0, t.s)?)?.0;
        let arity = references
            .get(&(METHOD_DEF_TOKEN | (member >> 1)))
            .and_then(|r| r.arity);
        let r = Named {
            name,
            offset,
            library: Some(lib),
            arity,
        };
        result.references.push(t.copy(&r)?);
        references.insert(METHOD_DEF_TOKEN | (member >> 1), r);
    }
    // Generic MethodSpec call sites preserve their underlying MethodDef/MemberRef.
    for rid in 1..=t.rows[METHOD_SPEC] {
        let row = t.row(METHOD_SPEC, rid)?;
        let m = index(row, 0, t.coded(1, &[METHOD_DEF, MEMBER_REF]))?;
        let token = if m & 1 == 0 {
            METHOD_DEF_TOKEN
        } else {
            MEMBER_REF_TOKEN
        } | (m >> 1);
        if let Some(r) = references.get(&token) {
            let r = t.copy(r)?;
            references.insert(METHOD_SPEC_TOKEN | u32::try_from(rid).ok()?, r);
        }
    }
    let mut budget = MAX_INSTRUCTIONS;
    for (rid, name) in definitions.iter().enumerate().skip(1) {
        let row = t.row(METHOD_DEF, rid)?;
        let rva = u32_le(row, 0)?;
        if rva == 0 || u16_le(row, 4)? & 3 != 0 {
            continue;
        }
        let Some(offset) = map(rva) else {
            result.invalid_methods += 1;
            continue;
        };
        if budget == 0 {
            result.truncated = true;
            break;
        }
        let b = il_body(bytes, offset, budget);
        budget = budget.saturating_sub(b.instructions);
        result.instruction_count += b.instructions;
        result.calli_count += b.calli;
        if b.calli > 0 {
            result.calli_methods += 1;
        }
        if !b.valid {
            result.invalid_methods += 1;
        }
        let mut callees = Vec::new();
        let mut seen = HashSet::new();
        for (token, offset) in b.calls {
            if let Some(r) = references.get(&token) {
                if seen.insert(r.name.as_str()) {
                    t.charge(r.name.len())?;
                    callees.push(r.name.clone());
                }
                if result.calls.len() < MAX_CALLS {
                    result.calls.push(Named {
                        offset,
                        ..t.copy(r)?
                    });
                } else {
                    result.truncated = true;
                }
            }
        }
        let has = |suffix: &str| callees.iter().any(|s| s.ends_with(suffix));
        if has(".ResolveMethod") && has(".get_MethodHandle") && has(".GetFunctionPointer") {
            result.resolver_pointer_methods += 1;
        }
        if has(".GetManifestResourceStream")
            && has(".Read")
            && has(".GetString")
            && b.xor > 0
            && b.store_byte > 0
        {
            result.resource_xor_methods += 1;
        }
        t.charge(name.len())?;
        result.methods.push(Method {
            name: name.clone(),
            offset,
            callees,
        });
    }
    Some(())
}

#[cfg(test)]
mod tests;
