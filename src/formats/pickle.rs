//! Python pickle extractor.
//!
//! Pickle is the canonical Python supply-chain RCE vector — the
//! opcode stream itself is the signal (REDUCE / BUILD / INST /
//! GLOBAL / STACK_GLOBAL all expose attacker-controlled code paths).
//! This extractor walks the opcode stream without executing it,
//! recording:
//!
//! - `pickle.protocol` — PROTO byte (0..5).
//! - `pickle.modules[]` — distinct `(module)` names from GLOBAL and
//!   statically resolved STACK_GLOBAL operands.
//! - `pickle.opcodes[]` — sorted set of opcode names seen.
//! - `pickle.dangerous_opcodes[]` — Pike-style flag array of
//!   the canonical-RCE opcode family (`reduce`, `build`, `inst`,
//!   `obj`, `newobj`, `newobj_ex`, `stack_global`, `global`,
//!   `persid`, `binpersid`, `ext1`, `ext2`, `ext4`).

use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::formats::common::bytes_at::{u32_le, u64_le};
use crate::formats::common::{XorScan, extract_binary_strings, put_str};
use crate::output::{Metrics, Strings, Values};

/// Cap on opcode-stream bytes scanned. Real malicious payloads are
/// tiny; the cap guards against pathological model files
/// (multi-GB joblib/pytorch).
const MAX_BYTES_SCANNED: usize = 8 * 1024 * 1024;

/// A text operand on the pickle stack: the scan offset of the opcode that
/// pushed it, and its text, borrowed from the scan so DUP and memo GET of a
/// multi-megabyte string copy a pointer, not the string. The offset names the
/// operand however many times it is copied.
#[derive(Clone, Copy)]
struct Operand<'a> {
    at: usize,
    text: &'a str,
}

/// A pickle stack entry.
#[derive(Clone, Copy)]
enum StackValue<'a> {
    Text(Operand<'a>),
    /// The callable a GLOBAL or STACK_GLOBAL resolved.
    Global {
        module: &'a str,
        attr: &'a str,
    },
    Other,
    Mark,
}

/// Minimal inert pickle VM used only to resolve STACK_GLOBAL operands.
///
/// A rolling string window is incorrect here: STACK_GLOBAL consumes the two
/// values on the pickle stack, and either value may have arrived through a
/// memo GET long after it was declared.  We model stack depth, marks and memo
/// traffic without importing a global or constructing an object.
#[derive(Default)]
struct PickleStack<'a> {
    values: Vec<StackValue<'a>>,
    memo: HashMap<usize, StackValue<'a>>,
    /// STACK_GLOBAL operand pairs already admitted, by operand offset.
    resolved: HashSet<(usize, usize)>,
    /// Bytes of STACK_GLOBAL operands admitted so far.
    resolved_bytes: usize,
}

impl<'a> PickleStack<'a> {
    fn push(&mut self, value: StackValue<'a>) {
        self.values.push(value);
    }

    fn pop(&mut self) -> StackValue<'a> {
        self.values.pop().unwrap_or(StackValue::Other)
    }

    fn pop_n(&mut self, count: usize) {
        for _ in 0..count {
            self.pop();
        }
    }

    fn pop_through_mark(&mut self) {
        while let Some(value) = self.values.pop() {
            if matches!(value, StackValue::Mark) {
                return;
            }
        }
    }

    fn memo_put(&mut self, index: usize) {
        if let Some(value) = self.values.last() {
            self.memo.insert(index, *value);
        }
    }

    fn memo_get(&mut self, index: usize) {
        self.values
            .push(self.memo.get(&index).copied().unwrap_or(StackValue::Other));
    }

    /// Whether STACK_GLOBAL operands `module` and `attr` should be recorded.
    /// Memo GETs let a few bytes of input name the same multi-megabyte
    /// strings again, or pair many of them up. Recording a pair once, and
    /// no more operand bytes than an honest pickle of the scanned size could
    /// hold, keeps the scan linear and its output bounded.
    fn admit_global(&mut self, module: Operand<'_>, attr: Operand<'_>) -> bool {
        if !self.resolved.insert((module.at, attr.at)) {
            return false;
        }
        self.resolved_bytes = self
            .resolved_bytes
            .saturating_add(module.text.len() + attr.text.len());
        self.resolved_bytes <= MAX_BYTES_SCANNED
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    extract_binary_strings(bytes, strings, XorScan::No);
    if bytes.is_empty() {
        return;
    }
    let scan = bytes.get(..MAX_BYTES_SCANNED).unwrap_or(bytes);

    let mut protocol: i32 = -1;
    let mut modules: BTreeSet<String> = BTreeSet::new();
    // Fully-qualified `module.attr` callable references resolved from GLOBAL
    // and STACK_GLOBAL — the actual RCE targets, gated to Python-identifier
    // shape so trait rules can match on e.g. `os.system` / `builtins.exec`.
    let mut globals: BTreeSet<String> = BTreeSet::new();
    let mut opcodes: BTreeSet<&'static str> = BTreeSet::new();
    let mut stack = PickleStack::default();

    // The legacy torch container begins with a fixed magic integer and
    // serialization version, then carries three more pickles before raw
    // storage bytes. Ordinary pickle readers stop at the first STOP.
    let torch_legacy = crate::fileid::torch_protocol2_legacy_header(scan);
    let mut streams_left = if torch_legacy { 5 } else { 1 };
    let mut i = 0_usize;
    while let Some(&op) = scan.get(i) {
        let Some(name) = opcode_name(op) else { break };
        // Unsupported/truncated PROTO operands are not protocol declarations.
        if op == 0x80 && scan.get(i + 1).is_none_or(|p| *p > 5) {
            break;
        }
        let Some(frame) = payload_size(op, i, scan) else {
            break;
        };
        if i.checked_add(frame).is_none_or(|end| end > scan.len()) {
            break;
        }
        opcodes.insert(name);
        apply_side_effects(
            op,
            i,
            scan,
            &mut protocol,
            &mut modules,
            &mut globals,
            &mut stack,
        );
        i += frame;
        if op == b'.' {
            streams_left -= 1;
            if streams_left == 0 {
                break;
            }
            stack = PickleStack::default();
            // This bounded legacy variant uses protocol-2 headers for every
            // pickle; a corrupt next frame is not a raw-storage opcode scan.
            if scan.get(i..i + 2) != Some(&[0x80, 2]) {
                break;
            }
        }
    }

    if streams_left > 0 && i < scan.len() {
        tracing::debug!(
            target: "filefacts::pickle",
            stage = "opcodes",
            offset = i,
            len = scan.len(),
            "opcode scan stopped at an unknown opcode or a truncated operand"
        );
    }
    if opcodes.is_empty() && modules.is_empty() && protocol < 0 {
        return;
    }

    if protocol >= 0 {
        metrics.insert(metric!("pickle.protocol"), f64::from(protocol));
        put_str(values, value_key!("pickle.protocol"), protocol.to_string());
    }
    if !modules.is_empty() {
        values.insert_key(
            value_key!("pickle.modules"),
            JsonValue::Array(modules.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !globals.is_empty() {
        values.insert_key(
            value_key!("pickle.globals"),
            JsonValue::Array(globals.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !opcodes.is_empty() {
        let dangerous: Vec<JsonValue> = opcodes
            .iter()
            .filter(|name| is_dangerous(name))
            .map(|name| JsonValue::String(name.to_ascii_lowercase()))
            .collect();
        if !dangerous.is_empty() {
            values.insert_key(
                value_key!("pickle.dangerous_opcodes"),
                JsonValue::Array(dangerous),
            );
        }
        values.insert_key(
            value_key!("pickle.opcodes"),
            JsonValue::Array(
                opcodes
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
}

/// Opcode names that grant attacker-controlled code execution
/// (`REDUCE` invokes a callable; `BUILD` calls `__setstate__`;
/// `INST` / `OBJ` / `NEWOBJ` / `NEWOBJ_EX` construct objects;
/// `GLOBAL` / `STACK_GLOBAL` resolve callables; `PERSID` /
/// `BINPERSID` and `EXT*` jump through registries).
fn is_dangerous(name: &str) -> bool {
    matches!(
        name,
        "REDUCE"
            | "BUILD"
            | "INST"
            | "OBJ"
            | "NEWOBJ"
            | "NEWOBJ_EX"
            | "GLOBAL"
            | "STACK_GLOBAL"
            | "PERSID"
            | "BINPERSID"
            | "EXT1"
            | "EXT2"
            | "EXT4"
    )
}

/// Bytes occupied by `op` plus its payload. Returns `None` when
/// the payload runs past `scan.len()` or the length prefix can't
/// be read — caller treats that as end-of-stream.
fn payload_size(op: u8, i: usize, scan: &[u8]) -> Option<usize> {
    let read_until_newline = || -> Option<usize> {
        let nl = scan.get(i + 1..)?.iter().position(|&b| b == b'\n')?;
        Some(2 + nl)
    };
    let read_len_prefixed = |len_bytes: usize, len_value: usize| -> Option<usize> {
        // `len_value` comes from the file; unchecked, a u64 length wraps the
        // frame to 0 and the caller's scan never advances.
        let frame = len_value.checked_add(1 + len_bytes)?;
        (i.checked_add(frame)? <= scan.len()).then_some(frame)
    };
    match op {
        0x80 | b'K' | 0x82 | b'h' | b'q' => Some(2),
        0x83 | b'M' => Some(3),
        0x84 | b'J' | b'j' | b'r' => Some(5),
        b'G' | 0x95 => Some(9),
        b'I' | b'L' | b'F' | b'V' | b'S' | b'g' | b'p' => read_until_newline(),
        b'c' | b'i' => {
            let m_nl = scan.get(i + 1..)?.iter().position(|&b| b == b'\n')?;
            let attr_start = i + 2 + m_nl;
            let a_nl = scan.get(attr_start..)?.iter().position(|&b| b == b'\n')?;
            Some((attr_start + a_nl + 1) - i)
        }
        0x8A | 0x8C | b'U' | b'C' => {
            let len = *scan.get(i + 1)? as usize;
            read_len_prefixed(1, len)
        }
        0x8B | b'X' | b'T' | b'B' => {
            let len = u32_le(scan, i + 1)? as usize;
            read_len_prefixed(4, len)
        }
        0x8D | 0x8E | 0x96 => {
            let len = usize::try_from(u64_le(scan, i + 1)?).ok()?;
            read_len_prefixed(8, len)
        }
        _ => Some(1),
    }
}

/// Python-identifier shape (allowing dotted submodules), matching the gate
/// used when forming `module.attr` callable references.
fn is_pickle_ident(s: &str) -> bool {
    !s.is_empty()
        && s.is_ascii()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && s.starts_with(|c: char| c.is_alphabetic() || c == '_')
}

fn line_usize(scan: &[u8], start: usize) -> Option<usize> {
    let end = scan.get(start..)?.iter().position(|&byte| byte == b'\n')? + start;
    std::str::from_utf8(scan.get(start..end)?)
        .ok()?
        .parse()
        .ok()
}

fn inline_global(scan: &[u8], i: usize) -> Option<(&str, &str)> {
    let module_end = scan.get(i + 1..)?.iter().position(|&byte| byte == b'\n')? + i + 1;
    let attr_start = module_end + 1;
    let attr_end = scan
        .get(attr_start..)?
        .iter()
        .position(|&byte| byte == b'\n')?
        + attr_start;
    Some((
        std::str::from_utf8(scan.get(i + 1..module_end)?).ok()?,
        std::str::from_utf8(scan.get(attr_start..attr_end)?).ok()?,
    ))
}

fn unicode_operand(op: u8, scan: &[u8], i: usize) -> Option<&str> {
    let slice = match op {
        0x8C => {
            let len = usize::from(*scan.get(i + 1)?);
            scan.get(i + 2..i + 2 + len)?
        }
        b'X' => {
            let len = usize::try_from(u32_le(scan, i + 1)?).ok()?;
            scan.get(i + 5..i + 5 + len)?
        }
        0x8D => {
            let len = usize::try_from(u64_le(scan, i + 1)?).ok()?;
            scan.get(i + 9..i + 9 + len)?
        }
        b'V' => {
            let end = scan.get(i + 1..)?.iter().position(|&byte| byte == b'\n')? + i + 1;
            scan.get(i + 1..end)?
        }
        _ => return None,
    };
    std::str::from_utf8(slice).ok()
}

/// Recover source stored by Ren'Py's `renpy.ast.PyCode.__getstate__` without
/// constructing the pickled object. The supported shape is a GLOBAL PyCode,
/// NEWOBJ, then a state tuple beginning `(1, source, ...)`, applied by BUILD.
/// Ordinary dialogue strings elsewhere in the pickle are never promoted to
/// executable Python source. Unsupported object layouts simply yield nothing.
pub(crate) fn renpy_pycode_sources(bytes: &[u8]) -> Vec<String> {
    const MAX_SOURCE_BYTES: usize = 1024 * 1024;
    const MAX_SOURCE_COUNT: usize = 100;
    const MAX_WALK_OPCODES: usize = 128;
    let scan = bytes.get(..MAX_BYTES_SCANNED).unwrap_or(bytes);
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut stage = 0u8;
    let mut age = 0usize;
    let mut candidate: Option<&str> = None;
    let mut stack = PickleStack::default();
    let mut protocol = -1;
    let mut modules = BTreeSet::new();
    let mut globals = BTreeSet::new();
    while let Some(&op) = scan.get(pos) {
        if opcode_name(op).is_none() {
            break;
        }
        let Some(width) = payload_size(op, pos, scan) else {
            break;
        };
        if pos.checked_add(width).is_none_or(|end| end > scan.len()) {
            break;
        }
        if stage != 0 {
            age += 1;
            if age > MAX_WALK_OPCODES {
                stage = 0;
                candidate = None;
            }
        }
        apply_side_effects(
            op,
            pos,
            scan,
            &mut protocol,
            &mut modules,
            &mut globals,
            &mut stack,
        );
        // GLOBAL, STACK_GLOBAL and the memo GETs each push one value, so
        // the top is what this opcode resolved.
        let pycode_global = matches!(op, b'c' | 0x93 | b'g' | b'h' | b'j')
            && matches!(
                stack.values.last(),
                Some(StackValue::Global {
                    module: "renpy.ast",
                    attr: "PyCode"
                })
            );
        match stage {
            0 if pycode_global => {
                stage = 1;
                age = 0;
            }
            1 if matches!(op, 0x81 | 0x92) => stage = 2, // NEWOBJ / NEWOBJ_EX
            1 if !matches!(op, b'q' | b'r' | 0x94 | b')') => stage = 0,
            2 if op == b'(' => stage = 3, // state tuple MARK
            2 if !matches!(op, b'q' | b'r' | 0x94) => stage = 0,
            3 if op == b'K' && scan.get(pos + 1) == Some(&1) => stage = 4,
            3 if op == b'J' && scan.get(pos + 1..pos + 5) == Some(&[1, 0, 0, 0]) => stage = 4,
            4 => {
                candidate = unicode_operand(op, scan, pos)
                    .filter(|source| !source.is_empty() && source.len() <= MAX_SOURCE_BYTES);
                stage = if candidate.is_some() { 5 } else { 0 };
            }
            5 if op == b'b' => {
                if let Some(source) = candidate.take()
                    && !out.iter().any(|existing| existing == source)
                {
                    out.push(source.to_owned());
                    if out.len() >= MAX_SOURCE_COUNT {
                        break;
                    }
                }
                stage = 0;
            }
            _ => {}
        }
        pos += width;
        if op == b'.' {
            break;
        }
    }
    out
}

fn record_global(
    module: &str,
    attr: &str,
    modules: &mut BTreeSet<String>,
    globals: &mut BTreeSet<String>,
) {
    if !module.is_empty() {
        modules.insert(module.to_owned());
    }
    if is_pickle_ident(module) && is_pickle_ident(attr) {
        globals.insert(format!("{module}.{attr}"));
    }
}

fn apply_side_effects<'a>(
    op: u8,
    i: usize,
    scan: &'a [u8],
    protocol: &mut i32,
    modules: &mut BTreeSet<String>,
    globals: &mut BTreeSet<String>,
    stack: &mut PickleStack<'a>,
) {
    match op {
        0x80 => {
            if let Some(&p) = scan.get(i + 1) {
                *protocol = i32::from(p);
            }
        }
        b'c' => {
            let global = inline_global(scan, i);
            if let Some((module, attr)) = global {
                record_global(module, attr, modules, globals);
            }
            stack.push(
                global.map_or(StackValue::Other, |(module, attr)| StackValue::Global {
                    module,
                    attr,
                }),
            );
        }
        0x8C | b'X' | 0x8D | b'V' => {
            stack.push(
                unicode_operand(op, scan, i).map_or(StackValue::Other, |text| {
                    StackValue::Text(Operand { at: i, text })
                }),
            );
        }
        b'(' => stack.push(StackValue::Mark),
        b'0' => {
            stack.pop();
        }
        b'1' => stack.pop_through_mark(),
        b'2' => {
            if let Some(&value) = stack.values.last() {
                stack.push(value);
            }
        }
        b'q' => {
            if let Some(&index) = scan.get(i + 1) {
                stack.memo_put(usize::from(index));
            }
        }
        b'r' => {
            if let Some(index) = u32_le(scan, i + 1).and_then(|value| usize::try_from(value).ok()) {
                stack.memo_put(index);
            }
        }
        b'p' => {
            if let Some(index) = line_usize(scan, i + 1) {
                stack.memo_put(index);
            }
        }
        0x94 => stack.memo_put(stack.memo.len()),
        b'h' => {
            if let Some(&index) = scan.get(i + 1) {
                stack.memo_get(usize::from(index));
            } else {
                stack.push(StackValue::Other);
            }
        }
        b'j' => {
            if let Some(index) = u32_le(scan, i + 1).and_then(|value| usize::try_from(value).ok()) {
                stack.memo_get(index);
            } else {
                stack.push(StackValue::Other);
            }
        }
        b'g' => {
            if let Some(index) = line_usize(scan, i + 1) {
                stack.memo_get(index);
            } else {
                stack.push(StackValue::Other);
            }
        }
        0x93 => {
            let attr = stack.pop();
            let module = stack.pop();
            let resolved = match (module, attr) {
                (StackValue::Text(module), StackValue::Text(attr)) => {
                    if stack.admit_global(module, attr) {
                        record_global(module.text, attr.text, modules, globals);
                    }
                    StackValue::Global {
                        module: module.text,
                        attr: attr.text,
                    }
                }
                _ => StackValue::Other,
            };
            stack.push(resolved);
        }
        // Scalars, bytes, extension-registry results and out-of-band buffers.
        b'F' | b'I' | b'J' | b'K' | b'L' | b'M' | b'N' | b'S' | b'T' | b'U' | b'G' | b'B'
        | b'C' | 0x82 | 0x83 | 0x84 | 0x88 | 0x89 | 0x8A | 0x8B | 0x8E | 0x96 | 0x97 | b'P' => {
            stack.push(StackValue::Other)
        }
        // Empty containers.
        b')' | b']' | b'}' | 0x8F => stack.push(StackValue::Other),
        // MARK-delimited container constructors.
        b'd' | b'l' | b't' | 0x91 => {
            stack.pop_through_mark();
            stack.push(StackValue::Other);
        }
        // Batch mutations consume through MARK but retain their container.
        b'e' | b'u' | 0x90 => stack.pop_through_mark(),
        // Single mutations consume their arguments and retain the container.
        b'a' => stack.pop_n(1),
        b's' => stack.pop_n(2),
        // Fixed-arity tuples.
        0x85 => {
            stack.pop_n(1);
            stack.push(StackValue::Other);
        }
        0x86 => {
            stack.pop_n(2);
            stack.push(StackValue::Other);
        }
        0x87 => {
            stack.pop_n(3);
            stack.push(StackValue::Other);
        }
        // Construction never executes here; only stack effects are modeled.
        b'R' | 0x81 => {
            stack.pop_n(2);
            stack.push(StackValue::Other);
        }
        0x92 => {
            stack.pop_n(3);
            stack.push(StackValue::Other);
        }
        b'b' => stack.pop_n(1),
        b'i' => {
            if let Some((module, attr)) = inline_global(scan, i) {
                record_global(module, attr, modules, globals);
            }
            stack.pop_through_mark();
            stack.push(StackValue::Other);
        }
        b'o' => {
            stack.pop_through_mark();
            stack.push(StackValue::Other);
        }
        b'Q' => {
            stack.pop_n(1);
            stack.push(StackValue::Other);
        }
        // PROTO, FRAME, STOP and READONLY_BUFFER have no modeled stack effect.
        _ => {}
    }
}

/// Name of a pickle opcode, or `None` for a byte no protocol assigns.
const fn opcode_name(op: u8) -> Option<&'static str> {
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

#[cfg(test)]
mod tests;
