//! Bounded DEX method and call facts, read from the bytecode without
//! loading any class.
//!
//! Every method with code becomes a `Function` symbol naming its callees,
//! every `invoke-*` a `Call` symbol with the literal arguments known at the
//! call, every method of a class the file does not define an `Import`, and
//! every string constant the bytecode loads a literal. Literal arguments are
//! propagated only within a straight-line basic block: a branch target, or
//! an instruction that writes a register in a way not modelled, forgets what
//! the registers held.
//!
//! Every table, string, method body and output view is capped, so a forged
//! header costs bounded work; a cap that ends the walk early is recorded in
//! `dex.limits`.

use std::collections::{HashMap, HashSet};

use crate::bytes::{u16_le, u32_le};
use crate::formats::common::read_uleb128;
use crate::output::{Arg, Literal, Literals, Symbol, Symbols, Values};
use crate::value_key;

/// `sizeof(header_item)`.
const HEADER_LEN: usize = 0x70;
/// `header_item.endian_tag` of a little-endian file, the only kind Android
/// writes.
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
/// `header_item` offsets: the endian tag, then each `(size, offset)` pair
/// of the id tables read here.
const ENDIAN_TAG_AT: usize = 40;
const STRING_IDS_AT: usize = 56;
const TYPE_IDS_AT: usize = 64;
const PROTO_IDS_AT: usize = 72;
const METHOD_IDS_AT: usize = 88;
const CLASS_DEFS_AT: usize = 96;

/// Entry sizes of the id tables.
const STRING_ID_LEN: usize = 4;
const TYPE_ID_LEN: usize = 4;
const PROTO_ID_LEN: usize = 12;
const METHOD_ID_LEN: usize = 8;
const CLASS_DEF_LEN: usize = 32;
/// `class_def_item.class_data_off`.
const CLASS_DATA_OFF_AT: usize = 24;
/// The `ident` code units that open the payload pseudo-instructions.
const PACKED_SWITCH_PAYLOAD: u16 = 0x0100;
const SPARSE_SWITCH_PAYLOAD: u16 = 0x0200;
const FILL_ARRAY_DATA_PAYLOAD: u16 = 0x0300;
/// `code_item.insns_size`, and where the instructions follow it.
const INSNS_SIZE_AT: usize = 12;
const INSNS_AT: usize = 16;

/// Strings read from the string table. Real apps hold well under a million
/// strings across all their DEX files.
const MAX_STRINGS: usize = 1 << 18;
/// Types, prototypes, methods and classes read: every reference to them is
/// a 16-bit index, so a larger table cannot be referenced whole.
const MAX_IDS: usize = 1 << 16;
/// Bytes scanned for string terminators, across the whole string table.
const MAX_STRING_SCAN: usize = 32 << 20;
/// The longest string decoded, and the most string bytes decoded in all.
const MAX_STRING_LEN: usize = 8192;
const MAX_STRING_BYTES: usize = 16 << 20;
/// Parameters a prototype may list: the VM's limit on argument registers.
const MAX_PARAMS: usize = 255;
/// Code units in one method body, and across every body walked.
const MAX_METHOD_CODE_UNITS: usize = 2 << 20;
const MAX_CODE_UNITS: usize = 8 << 20;
/// Switch-table targets followed in one method body.
const MAX_SWITCH_TARGETS: usize = 100_000;
/// Fields and methods one class's data may declare, and class-data entries
/// across every class.
const MAX_CLASS_MEMBERS: u32 = 1 << 16;
const MAX_CLASS_DATA_ENTRIES: usize = 2 << 20;
/// Literal bytes and literals recorded, and symbols pushed.
const MAX_LITERAL_BYTES: usize = 8 << 20;
const MAX_LITERALS: usize = 100_000;
const MAX_SYMBOLS: usize = 500_000;
/// Registers whose values are tracked at once; past this the block's
/// bindings are dropped.
const MAX_TRACKED_REGISTERS: usize = 256;
/// Bytes of `class->name` method names built for the method table. Each name
/// joins a type and a name string of up to [`MAX_STRING_LEN`] bytes, and
/// every one of 65,536 `method_id_item`s may name the same two: a gigabyte
/// of names from a file of half a megabyte. Real tables hold a few MiB.
const MAX_METHOD_NAME_BYTES: usize = 32 << 20;
/// Method-name bytes copied into symbols: import, call-target, callee and
/// function names. Every call to a method repeats its name, so a long name
/// called from a few hundred thousand sites multiplies without this. The
/// largest real files copy well under half of it.
const MAX_SYMBOL_NAME_BYTES: usize = 128 << 20;

/// What the walk of every method body may still spend.
struct Budget {
    /// Code units.
    code: usize,
    /// Literal bytes.
    literals: usize,
    /// Method-name bytes copied into symbols.
    names: usize,
}

/// Take `len` bytes from `budget`, or spend it entirely and fail.
fn charge(budget: &mut usize, len: usize) -> Option<()> {
    let Some(left) = budget.checked_sub(len) else {
        *budget = 0;
        return None;
    };
    *budget = left;
    Some(())
}

/// A DEX `uleb128`, which encodes at most 32 bits.
fn uleb(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    u32::try_from(read_uleb128(bytes, pos)?).ok()
}

/// An id table: where its entries start and how many there are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Table {
    offset: usize,
    len: usize,
}

impl Table {
    /// The table whose `(size, offset)` pair is at `header` in `bytes`, of
    /// `width`-byte entries: `None` when it holds more than `cap` entries or
    /// runs past the file.
    fn read(bytes: &[u8], header: usize, width: usize, cap: usize) -> Option<Self> {
        let len = crate::bytes::sat_usize(u32_le(bytes, header)?);
        let offset = crate::bytes::sat_usize(u32_le(bytes, header + 4)?);
        (len <= cap && offset.checked_add(len.checked_mul(width)?)? <= bytes.len())
            .then_some(Self { offset, len })
    }

    /// The file offset of entry `index`, `width` bytes each.
    fn entry(self, index: usize, width: usize) -> usize {
        self.offset + index * width
    }
}

/// Decode a Modified UTF-8 string (the DEX and JVM encoding: NUL as two
/// bytes, supplementary characters as surrogate pairs). `None` for bytes
/// that are not one.
fn mutf8(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    let mut p = 0;
    while p < bytes.len() {
        let a = *bytes.get(p)?;
        p += 1;
        if a > 0 && a < 128 {
            units.push(u16::from(a));
        } else if a & 0xe0 == 0xc0 {
            let b = *bytes.get(p)?;
            p += 1;
            if b & 0xc0 != 0x80 {
                return None;
            }
            let value = (u16::from(a & 31) << 6) | u16::from(b & 63);
            if value != 0 && value < 128 {
                return None;
            }
            units.push(value);
        } else if a & 0xf0 == 0xe0 {
            let b = *bytes.get(p)?;
            let c = *bytes.get(p + 1)?;
            p += 2;
            if b & 0xc0 != 0x80 || c & 0xc0 != 0x80 {
                return None;
            }
            let value = (u16::from(a & 15) << 12) | (u16::from(b & 63) << 6) | u16::from(c & 63);
            if value < 0x800 {
                return None;
            }
            units.push(value);
        } else {
            return None;
        }
    }
    String::from_utf16(&units).ok()
}

/// A method a `method_id_item` names.
struct Method {
    /// `Lpackage/Class;->name`.
    name: String,
    /// For each parameter, whether it is wide (`J` or `D`), taking two
    /// registers.
    params: Vec<bool>,
    /// Whether its class is defined in another file: an import.
    external: bool,
}

/// The tables of one DEX file a walk of its code needs.
struct Dex<'a> {
    bytes: &'a [u8],
    /// The string table, `None` for an entry past the caps or not Modified
    /// UTF-8.
    strings: Vec<Option<String>>,
    /// The method table, `None` for an entry whose class, name or
    /// prototype is out of range.
    methods: Vec<Option<Method>>,
    classes: Table,
}

impl<'a> Dex<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN
            || !bytes.starts_with(b"dex\n")
            || *bytes.get(7)? != 0
            || u32_le(bytes, ENDIAN_TAG_AT)? != ENDIAN_CONSTANT
        {
            return None;
        }
        let string_ids = Table::read(bytes, STRING_IDS_AT, STRING_ID_LEN, MAX_STRINGS)?;
        let mut strings = Vec::with_capacity(string_ids.len);
        let mut decoded_bytes = 0;
        let mut scan_left = MAX_STRING_SCAN;
        for i in 0..string_ids.len {
            let mut pos =
                crate::bytes::sat_usize(u32_le(bytes, string_ids.entry(i, STRING_ID_LEN))?);
            // The UTF-16 length, which the terminator makes redundant.
            uleb(bytes, &mut pos)?;
            let probe = bytes.get(pos..)?;
            let probe_len = probe.len().min(MAX_STRING_LEN + 1).min(scan_left);
            let end = probe.iter().take(probe_len).position(|&b| b == 0);
            scan_left -= end.map_or(probe_len, |n| n + 1);
            let text = end.and_then(|n| {
                if n > MAX_STRING_LEN || decoded_bytes + n > MAX_STRING_BYTES {
                    return None;
                }
                decoded_bytes += n;
                mutf8(probe.get(..n)?)
            });
            strings.push(text);
        }
        let type_ids = Table::read(bytes, TYPE_IDS_AT, TYPE_ID_LEN, MAX_IDS)?;
        let mut types = Vec::with_capacity(type_ids.len);
        for i in 0..type_ids.len {
            types.push(crate::bytes::sat_usize(u32_le(
                bytes,
                type_ids.entry(i, TYPE_ID_LEN),
            )?));
        }
        let classes = Table::read(bytes, CLASS_DEFS_AT, CLASS_DEF_LEN, MAX_IDS)?;
        let mut defined = HashSet::new();
        for i in 0..classes.len {
            defined.insert(crate::bytes::sat_usize(u32_le(
                bytes,
                classes.entry(i, CLASS_DEF_LEN),
            )?));
        }
        let type_name = |index: usize| types.get(index).and_then(|&i| strings.get(i)?.as_deref());
        let proto_ids = Table::read(bytes, PROTO_IDS_AT, PROTO_ID_LEN, MAX_IDS)?;
        let mut protos = Vec::with_capacity(proto_ids.len);
        for i in 0..proto_ids.len {
            // `proto_id_item.parameters_off`: a `type_list`, or none.
            let list =
                crate::bytes::sat_usize(u32_le(bytes, proto_ids.entry(i, PROTO_ID_LEN) + 8)?);
            let mut params = Vec::new();
            if list != 0 {
                let count = crate::bytes::sat_usize(u32_le(bytes, list)?);
                if count > MAX_PARAMS || list.checked_add(4 + count * 2)? > bytes.len() {
                    return None;
                }
                for j in 0..count {
                    let param = usize::from(u16_le(bytes, list + 4 + j * 2)?);
                    params.push(matches!(type_name(param), Some("J" | "D")));
                }
            }
            protos.push(params);
        }
        let method_ids = Table::read(bytes, METHOD_IDS_AT, METHOD_ID_LEN, MAX_IDS)?;
        let mut methods = Vec::with_capacity(method_ids.len);
        let mut name_budget = MAX_METHOD_NAME_BYTES;
        for i in 0..method_ids.len {
            let at = method_ids.entry(i, METHOD_ID_LEN);
            let class = usize::from(u16_le(bytes, at)?);
            let proto = usize::from(u16_le(bytes, at + 2)?);
            let name = crate::bytes::sat_usize(u32_le(bytes, at + 4)?);
            // A name past the budget leaves its method unresolved, as an
            // out-of-range index does.
            let method = type_name(class)
                .zip(strings.get(name).and_then(Option::as_ref))
                .zip(protos.get(proto))
                .filter(|((class_name, name), _)| {
                    charge(&mut name_budget, class_name.len() + 2 + name.len()).is_some()
                })
                .map(|((class_name, name), params)| Method {
                    name: format!("{class_name}->{name}"),
                    params: params.clone(),
                    external: !defined.contains(&class),
                });
            methods.push(method);
        }
        Some(Self {
            bytes,
            strings,
            methods,
            classes,
        })
    }
}

/// The width in code units of the instruction at `pc`, the payload
/// pseudo-instructions (`packed-switch`, `sparse-switch`,
/// `fill-array-data`) included; `None` for an opcode the format does not
/// define or an instruction running past `code`.
fn width(code: &[u16], pc: usize) -> Option<usize> {
    let v = *code.get(pc)?;
    let [op, _] = v.to_le_bytes();
    let n = match op {
        0 if v == PACKED_SWITCH_PAYLOAD => 4 + 2 * usize::from(*code.get(pc + 1)?),
        0 if v == SPARSE_SWITCH_PAYLOAD => 2 + 4 * usize::from(*code.get(pc + 1)?),
        0 if v == FILL_ARRAY_DATA_PAYLOAD => {
            let size = u32::from(*code.get(pc + 2)?) | (u32::from(*code.get(pc + 3)?) << 16);
            4usize.checked_add(
                usize::from(*code.get(pc + 1)?)
                    .checked_mul(crate::bytes::sat_usize(size))?
                    .div_ceil(2),
            )?
        }
        0x00
        | 0x01
        | 0x04
        | 0x07
        | 0x0a..=0x12
        | 0x1d
        | 0x1e
        | 0x21
        | 0x27
        | 0x28
        | 0x7b..=0x8f
        | 0xb0..=0xcf => 1,
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15
        | 0x16
        | 0x19
        | 0x1a
        | 0x1c
        | 0x1f
        | 0x20
        | 0x22
        | 0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe
        | 0xff => 2,
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24..=0x26
        | 0x2a..=0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc
        | 0xfd => 3,
        0x18 => 5,
        0xfa | 0xfb => 4,
        _ => return None,
    };
    (pc.checked_add(n)? <= code.len()).then_some(n)
}
/// The offset `off` code units from `pc`, when it lies inside `len` units of
/// code.
fn relative(pc: usize, off: i32, len: usize) -> Option<usize> {
    let target = pc.checked_add_signed(isize::try_from(off).ok()?)?;
    (target < len).then_some(target)
}
/// The signed 32-bit value two code units at `pc` hold, low unit first.
fn pair(code: &[u16], pc: usize) -> Option<i32> {
    Some((u32::from(*code.get(pc)?) | (u32::from(*code.get(pc + 1)?) << 16)).cast_signed())
}
/// Every branch and switch target in `code`: the instructions where a basic
/// block starts. `None` when the switch tables name more targets than
/// [`MAX_SWITCH_TARGETS`] or than `code` has units.
///
/// Each payload is read once, however many switches name it, and an honest
/// payload spends at least two code units per target, so the walk costs no
/// more than the body's length: without both bounds, a few thousand switches
/// naming one large payload cost each of thousands of bodies the whole cap.
fn targets(code: &[u16]) -> Option<HashSet<usize>> {
    let mut label_budget = MAX_SWITCH_TARGETS.min(code.len());
    let mut labels = HashSet::new();
    let mut payloads = HashSet::new();
    let mut pc = 0;
    while let Some(n) = width(code, pc) {
        let v = *code.get(pc)?;
        let [op, _] = v.to_le_bytes();
        let jump = match op {
            0x28 => Some(i32::from(v.cast_signed() >> 8)),
            0x29 | 0x32..=0x3d => Some(i32::from(code.get(pc + 1)?.cast_signed())),
            0x2a => pair(code, pc + 1),
            _ => None,
        };
        if let Some(t) = jump.and_then(|off| relative(pc, off, code.len())) {
            labels.insert(t);
        }
        if matches!(op, 0x2b | 0x2c)
            && let Some(p) = pair(code, pc + 1).and_then(|off| relative(pc, off, code.len()))
            && let Some(size) = code.get(p + 1).copied()
            && payloads.insert(p)
        {
            let start = if op == 0x2b {
                p + 4
            } else {
                p + 2 + 2 * usize::from(size)
            };
            for j in 0..usize::from(size) {
                if label_budget == 0 {
                    return None;
                }
                label_budget -= 1;
                if let Some(t) =
                    pair(code, start + j * 2).and_then(|off| relative(pc, off, code.len()))
                {
                    labels.insert(t);
                }
            }
        }
        pc += n;
    }
    Some(labels)
}
/// Walk the body of method `idx`, whose `code_item` is at `off`: push its
/// calls and a `Function` symbol naming its callees to `symbols`, and the
/// string constants it loads to `literals`, spending `budget`. `None` for a
/// body that is malformed or past the budget; a symbol whose name the name
/// budget cannot cover ends the walk, its body's symbols kept.
fn inspect(
    dex: &Dex<'_>,
    idx: usize,
    off: usize,
    symbols: &mut Symbols,
    literals: &mut Literals,
    budget: &mut Budget,
) -> Option<()> {
    let method = dex.methods.get(idx)?.as_ref()?;
    let count = crate::bytes::sat_usize(u32_le(dex.bytes, off + INSNS_SIZE_AT)?);
    if count > MAX_METHOD_CODE_UNITS || off.checked_add(INSNS_AT + count * 2)? > dex.bytes.len() {
        return None;
    }
    // Charge the full bytecode walk, including malformed/undecodable code,
    // before allocation and the branch-target prepass.
    charge(&mut budget.code, count)?;
    let code: Vec<u16> = dex
        .bytes
        .get(off + INSNS_AT..off + INSNS_AT + count * 2)?
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect();
    // Without the block starts, no value is carried past an instruction.
    let labels = targets(&code);
    let mut regs: HashMap<u16, Arg> = HashMap::new();
    let mut pc = 0;
    let mut callees = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    while let Some(n) = width(&code, pc) {
        if labels.as_ref().is_none_or(|labels| labels.contains(&pc)) {
            regs.clear();
        }
        let v = *code.get(pc)?;
        let [op, _] = v.to_le_bytes();
        let a = v >> 8;
        match op {
            // const/4, const/16, const.
            0x12..=0x14 => {
                let (dest, val) = match op {
                    0x12 => ((v >> 8) & 15, i64::from(v.cast_signed() >> 12)),
                    0x13 => (a, i64::from(code.get(pc + 1)?.cast_signed())),
                    _ => (a, i64::from(pair(&code, pc + 1)?)),
                };
                regs.insert(
                    dest,
                    Arg::Number {
                        text: val.to_string(),
                        value: val,
                        radix: 10,
                    },
                );
            }
            0x1a | 0x1b => {
                let si = if op == 0x1a {
                    usize::from(*code.get(pc + 1)?)
                } else {
                    usize::try_from(pair(&code, pc + 1)?.cast_unsigned()).ok()?
                };
                regs.remove(&a);
                if let Some(Some(s)) = dex.strings.get(si) {
                    // Record bytecode-referenced constants, never unused string
                    // pool entries. The source location is the const-string site.
                    if s.len() <= budget.literals && literals.len() < MAX_LITERALS {
                        budget.literals -= s.len();
                        literals.push(Literal::new(s.clone(), (off + INSNS_AT + pc * 2) as u64));
                    }
                    regs.insert(a, Arg::String { value: s.clone() });
                }
            }
            0x01 | 0x07 | 0x02 | 0x08 | 0x03 | 0x09 => {
                let (dest, src) = match op {
                    0x01 | 0x07 => ((v >> 8) & 15, (v >> 12) & 15),
                    0x02 | 0x08 => (a, *code.get(pc + 1)?),
                    _ => (*code.get(pc + 1)?, *code.get(pc + 2)?),
                };
                if let Some(value) = regs.get(&src).cloned() {
                    regs.insert(dest, value);
                } else {
                    regs.remove(&dest);
                }
            }
            0x0a..=0x0d => {
                regs.remove(&a);
                if op == 0x0b {
                    regs.remove(&a.wrapping_add(1));
                }
            }
            // Invalidate only the destination of ordinary loads. Field and
            // array reads must not erase a literal held in another register.
            0x1c | 0x22 | 0x2d..=0x31 | 0x44..=0x4a | 0x60..=0x66 | 0xfe | 0xff => {
                regs.remove(&a);
                if matches!(op, 0x45 | 0x61) {
                    regs.remove(&a.wrapping_add(1));
                }
            }
            0x20 | 0x21 | 0x23 | 0x52..=0x58 => {
                let dest = a & 15;
                regs.remove(&dest);
                if op == 0x53 {
                    regs.remove(&dest.wrapping_add(1));
                }
            }
            0x16..=0x19 => {
                regs.remove(&a);
                regs.remove(&a.wrapping_add(1));
            }
            0x6e..=0x72 | 0x74..=0x78 => {
                if let Some(Some(callee)) = dex.methods.get(usize::from(*code.get(pc + 1)?)) {
                    if seen.insert(&callee.name) {
                        charge(&mut budget.names, callee.name.len())?;
                        callees.push(callee.name.clone());
                    }
                    let rs = *code.get(pc + 2)?;
                    let registers: Vec<u16> = if op >= 0x74 {
                        (0..a).map(|i| rs.wrapping_add(i)).collect()
                    } else {
                        let all = [
                            rs & 15,
                            (rs >> 4) & 15,
                            (rs >> 8) & 15,
                            (rs >> 12) & 15,
                            (v >> 8) & 15,
                        ];
                        all.into_iter().take(usize::from(v >> 12).min(5)).collect()
                    };
                    let mut position = usize::from(!matches!(op, 0x71 | 0x77));
                    let mut args = Vec::new();
                    for wide in &callee.params {
                        args.push(
                            registers
                                .get(position)
                                .and_then(|r| regs.get(r))
                                .cloned()
                                .unwrap_or(Arg::Expression),
                        );
                        position += if *wide { 2 } else { 1 };
                    }
                    if symbols.len() < MAX_SYMBOLS {
                        charge(&mut budget.names, callee.name.len())?;
                        symbols.push(Symbol::Call {
                            target: Some(callee.name.clone()),
                            args,
                            offset: Some((off + INSNS_AT + pc * 2) as u64),
                        });
                    }
                }
            }
            0x0e..=0x11 | 0x27..=0x2c => regs.clear(),
            0x00
            | 0x1d
            | 0x1e
            | 0x24..=0x26
            | 0x32..=0x3d
            | 0x4b..=0x51
            | 0x59..=0x5f
            | 0x67..=0x6d => {}
            _ => regs.clear(),
        }
        if regs.len() > MAX_TRACKED_REGISTERS {
            regs.clear();
        }
        pc += n;
    }
    charge(&mut budget.names, method.name.len())?;
    symbols.push(Symbol::Function {
        name: method.name.clone(),
        offset: Some((off + INSNS_AT) as u64),
        complexity: None,
        callees,
    });
    Some(())
}
/// Read the methods, calls, imports and string literals of the DEX file in
/// `bytes` into `symbols` and `literals`. A file that is not DEX, or whose
/// tables are malformed, yields nothing; a cap that ends the walk is
/// recorded in `dex.limits`.
pub(super) fn extract(
    bytes: &[u8],
    symbols: &mut Symbols,
    literals: &mut Literals,
    values: &mut Values,
) {
    let Some(dex) = Dex::parse(bytes) else {
        return;
    };
    let mut budget = Budget {
        code: MAX_CODE_UNITS,
        literals: MAX_LITERAL_BYTES,
        names: MAX_SYMBOL_NAME_BYTES,
    };
    let method_ids = crate::bytes::sat_usize(u32_le(bytes, METHOD_IDS_AT + 4).unwrap_or(0));
    for (idx, method) in dex.methods.iter().enumerate() {
        if let Some(m) = method.as_ref().filter(|m| m.external) {
            if charge(&mut budget.names, m.name.len()).is_none() {
                break;
            }
            symbols.push(Symbol::Import {
                name: m.name.clone(),
                alias: None,
                library: None,
                // The method's `method_id_item`.
                offset: Some((method_ids + idx * METHOD_ID_LEN) as u64),
                ordinal: None,
            });
        }
    }
    // The budget that ran out, recorded as the walk's limit.
    let spent = |budget: &Budget| {
        if budget.code == 0 {
            Some(serde_json::json!({"code_unit_budget":true}))
        } else if budget.names == 0 {
            Some(serde_json::json!({"name_budget":true}))
        } else {
            None
        }
    };
    if let Some(limit) = spent(&budget) {
        values.insert_key(value_key!("dex.limits"), limit);
        return;
    }
    let mut class_data_entries = MAX_CLASS_DATA_ENTRIES;
    for i in 0..dex.classes.len {
        let Some(mut pos) = u32_le(
            bytes,
            dex.classes.entry(i, CLASS_DEF_LEN) + CLASS_DATA_OFF_AT,
        )
        .map(crate::bytes::sat_usize)
        .filter(|&pos| pos != 0) else {
            continue;
        };
        // `class_data_item`: static and instance field counts, then direct
        // and virtual method counts.
        let Some((static_fields, instance_fields, direct_methods, virtual_methods)) = (|| {
            Some((
                uleb(bytes, &mut pos)?,
                uleb(bytes, &mut pos)?,
                uleb(bytes, &mut pos)?,
                uleb(bytes, &mut pos)?,
            ))
        })() else {
            continue;
        };
        let fields = static_fields.saturating_add(instance_fields);
        let methods = direct_methods.saturating_add(virtual_methods);
        if fields > MAX_CLASS_MEMBERS || methods > MAX_CLASS_MEMBERS {
            continue;
        }
        let entries = crate::bytes::sat_usize(fields + methods);
        if entries > class_data_entries {
            values.insert_key(
                value_key!("dex.limits"),
                serde_json::json!({"class_data_budget":true}),
            );
            return;
        }
        class_data_entries -= entries;
        // Each `encoded_field`: an index delta and access flags.
        let fields_ok =
            (0..fields).all(|_| uleb(bytes, &mut pos).is_some() && uleb(bytes, &mut pos).is_some());
        if !fields_ok {
            continue;
        }
        for count in [direct_methods, virtual_methods] {
            // Each `encoded_method`: an index delta from the previous method
            // of its list, access flags, and its `code_item` offset.
            let mut idx = 0usize;
            for _ in 0..count {
                let Some(delta) = uleb(bytes, &mut pos) else {
                    break;
                };
                let Some(_access) = uleb(bytes, &mut pos) else {
                    break;
                };
                let Some(code) = uleb(bytes, &mut pos) else {
                    break;
                };
                let Some(next) = idx.checked_add(crate::bytes::sat_usize(delta)) else {
                    break;
                };
                idx = next;
                if code != 0 {
                    // A malformed body costs that method alone.
                    let _ = inspect(
                        &dex,
                        idx,
                        crate::bytes::sat_usize(code),
                        symbols,
                        literals,
                        &mut budget,
                    );
                }
                if let Some(limit) = spent(&budget) {
                    values.insert_key(value_key!("dex.limits"), limit);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
