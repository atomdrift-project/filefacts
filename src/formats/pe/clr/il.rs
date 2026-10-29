//! Bounded ECMA-335 metadata and IL inspection. No managed assembly is loaded.

use std::collections::{BTreeMap, HashSet};

use super::operands;
use crate::formats::common::bytes_at::{u16_le, u32_le, u64_le};

const MAX_ROWS: usize = 65536;
const MAX_INSTRUCTIONS: usize = 2_000_000;
const MAX_CALLS: usize = 32768;

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
    let n = compressed(sig, p)?.0 as usize;
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
}
impl<'a> Tables<'a> {
    fn new(root: &'a [u8], root_offset: usize) -> Option<Self> {
        if root.get(..4)? != b"BSJB" {
            return None;
        }
        let v = u32_le(root, 12)? as usize;
        let mut p = 16usize.checked_add(v.checked_add(3)? & !3)?;
        let n = usize::from(u16_le(root, p + 2)?);
        if n > 64 {
            return None;
        }
        p += 4;
        let (mut strings, mut blob, mut table) = (None, None, None);
        for _ in 0..n {
            let off = u32_le(root, p)? as usize;
            let len = u32_le(root, p + 4)? as usize;
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
                *row = u32_le(data, p)? as usize;
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
    fn string(&self, n: u32) -> Option<(String, usize)> {
        let n = n as usize;
        if n >= self.strings_len {
            return None;
        }
        let p = self.strings.checked_add(n)?;
        let b = self.root.get(p..self.strings + self.strings_len)?;
        let end = b.iter().take(4096).position(|x| *x == 0)?;
        Some((
            std::str::from_utf8(b.get(..end)?).ok()?.to_string(),
            self.root_offset + p,
        ))
    }
    fn blob(&self, n: u32) -> Option<&'a [u8]> {
        let n = n as usize;
        if n >= self.blob_len {
            return None;
        }
        let b = self.root.get(self.blob..self.blob + self.blob_len)?;
        let (len, w) = compressed(b, n)?;
        b.get(n.checked_add(w)?..n.checked_add(w)?.checked_add(len as usize)?)
    }
    fn type_name(&self, t: usize, rid: usize, depth: u8) -> Option<(String, Option<String>)> {
        if depth > 16 {
            return None;
        }
        let row = self.row(t, rid)?;
        if t == 27 {
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
                    1
                } else if v.trailing_zeros() >= 2 {
                    2
                } else {
                    27
                },
                (v >> 2) as usize,
                depth + 1,
            );
        }
        let p = if t == 1 {
            self.coded(2, &[0, 26, 35, 1])
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
        if t == 1 {
            let scope = index(row, 0, p)?;
            let rid = (scope >> 2) as usize;
            match scope & 3 {
                2 => {
                    let a = self.row(35, rid)?;
                    lib = Some(self.string(index(a, 12 + self.b, self.s)?)?.0);
                }
                1 => {
                    let m = self.row(26, rid)?;
                    lib = Some(self.string(index(m, 0, self.s)?)?.0);
                }
                3 => {
                    let parent = self.type_name(1, rid, depth + 1)?;
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
        (offset + hdr, len as usize)
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
        let mut op = u16::from(*code.get(p).unwrap_or(&0));
        p += 1;
        if op == 0xfe {
            let Some(b) = code.get(p) else {
                return out;
            };
            op = 0xfe00 | u16::from(*b);
            p += 1;
        }
        let n = if op == 0x45 {
            let Some(n) = u32_le(code, p) else {
                return out;
            };
            let Some(n) = (n as usize).checked_mul(4).and_then(|n| n.checked_add(4)) else {
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
        if op == 0x29 {
            out.calli += 1;
        }
        if op == 0x61 {
            out.xor += 1;
        }
        if op == 0x9c {
            out.store_byte += 1;
        }
        if matches!(op, 0x28 | 0x6f | 0x73) {
            if let Some(token) = u32_le(code, p) {
                if out.calls.len() < MAX_CALLS {
                    out.calls.push((token, code_start + at));
                }
            }
        }
        if op == 0xd0 {
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
        method_count: t.rows[6],
        ..Analysis::default()
    };
    let mut definitions = vec![String::new(); t.rows[6] + 1];
    for rid in 1..=t.rows[2] {
        let row = t.row(2, rid)?;
        let p = 4 + 2 * t.s + t.coded(2, &[2, 1, 27]) + t.ix(4);
        let start = index(row, p, t.ix(6))? as usize;
        let end = if rid < t.rows[2] {
            index(t.row(2, rid + 1)?, p, t.ix(6))? as usize
        } else if t.rows[5] > 0 {
            t.rows[5] + 1
        } else {
            t.rows[6] + 1
        };
        if start > end || end > t.rows[6] + 1 {
            return None;
        }
        let owner = t.type_name(2, rid, 0)?.0;
        for list in start..end {
            let m = if t.rows[5] > 0 {
                index(t.row(5, list)?, 0, t.ix(6))? as usize
            } else {
                list
            };
            let row = t.row(6, m)?;
            *definitions.get_mut(m)? = format!("{}.{}", owner, t.string(index(row, 8, t.s)?)?.0);
        }
    }
    let mut references = BTreeMap::new();
    for rid in 1..=t.rows[10] {
        let row = t.row(10, rid)?;
        let w = t.coded(3, &[2, 1, 26, 6, 27]);
        let parent = index(row, 0, w)?;
        let (name, offset) = t.string(index(row, w, t.s)?)?;
        let sig = t.blob(index(row, w + t.s, t.b)?)?;
        if sig.first().is_none_or(|x| x & 15 == 6) {
            continue;
        }
        let tag = parent & 7;
        let owner = match tag {
            0 => t.type_name(2, (parent >> 3) as usize, 0),
            1 => t.type_name(1, (parent >> 3) as usize, 0),
            4 => t.type_name(27, (parent >> 3) as usize, 0),
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
        references.insert(0x0a000000 | u32::try_from(rid).ok()?, r.clone());
        if tag != 0 && r.library.is_some() {
            result.references.push(r);
        }
    }
    for (rid, name) in definitions.iter().enumerate().skip(1) {
        references.insert(
            0x06000000 | u32::try_from(rid).ok()?,
            Named {
                name: name.clone(),
                offset: 0,
                library: None,
                arity: t
                    .row(6, rid)
                    .and_then(|r| index(r, 8 + t.s, t.b))
                    .and_then(|n| t.blob(n))
                    .and_then(arity),
            },
        );
    }
    // P/Invoke import maps bind a MethodDef to the actual native entry point.
    for rid in 1..=t.rows[28] {
        let row = t.row(28, rid)?;
        let w = t.coded(1, &[4, 6]);
        let member = index(row, 2, w)?;
        if member & 1 == 0 {
            continue;
        }
        let (name, offset) = t.string(index(row, 2 + w, t.s)?)?;
        let scope = index(row, 2 + w + t.s, t.ix(26))? as usize;
        let lib = t.string(index(t.row(26, scope)?, 0, t.s)?)?.0;
        let arity = references
            .get(&(0x06000000 | (member >> 1)))
            .and_then(|r| r.arity);
        let r = Named {
            name,
            offset,
            library: Some(lib),
            arity,
        };
        references.insert(0x06000000 | (member >> 1), r.clone());
        result.references.push(r);
    }
    // Generic MethodSpec call sites preserve their underlying MethodDef/MemberRef.
    for rid in 1..=t.rows[43] {
        let row = t.row(43, rid)?;
        let m = index(row, 0, t.coded(1, &[6, 10]))?;
        let token = if m & 1 == 0 { 0x06000000 } else { 0x0a000000 } | (m >> 1);
        if let Some(r) = references.get(&token).cloned() {
            references.insert(0x2b000000 | u32::try_from(rid).ok()?, r);
        }
    }
    let mut budget = MAX_INSTRUCTIONS;
    for (rid, name) in definitions.iter().enumerate().skip(1) {
        let row = t.row(6, rid)?;
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
                if seen.insert(r.name.clone()) {
                    callees.push(r.name.clone());
                }
                if result.calls.len() < MAX_CALLS {
                    result.calls.push(Named {
                        name: r.name.clone(),
                        offset,
                        library: r.library.clone(),
                        arity: r.arity,
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
        result.methods.push(Method {
            name: name.clone(),
            offset,
            callees,
        });
    }
    Some(result)
}

#[cfg(test)]
mod tests;
