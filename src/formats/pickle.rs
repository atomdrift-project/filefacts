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
//!   statically resolved STACK_GLOBAL operands, as Python imports them
//!   (a protocol 0–2 `__builtin__` is `builtins`).
//! - `pickle.opcodes[]` — sorted set of opcode names seen.
//! - `pickle.dangerous_opcodes[]` — Pike-style flag array of
//!   the canonical-RCE opcode family (`reduce`, `build`, `inst`,
//!   `obj`, `newobj`, `newobj_ex`, `stack_global`, `global`,
//!   `persid`, `binpersid`, `ext1`, `ext2`, `ext4`).

use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::formats::common::{XorScan, extract_binary_strings, put_str};
use crate::output::{Metrics, Strings, Values};

mod compat;
pub(super) mod ops;

use ops::{Arg, Op};

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

    let mut protocol: Option<u8> = None;
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
    while let Ok((op, next)) = ops::decode(scan, i) {
        // Unsupported PROTO operands are not protocol declarations.
        if matches!(op.arg, Arg::Int(p) if op.code == 0x80 && p > 5) {
            break;
        }
        if let Some(name) = ops::name(op.code) {
            opcodes.insert(name);
        }
        apply_side_effects(
            &op,
            i,
            &mut protocol,
            &mut modules,
            &mut globals,
            &mut stack,
        );
        i = next;
        if op.code == b'.' {
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
    if opcodes.is_empty() && modules.is_empty() && protocol.is_none() {
        return;
    }

    if let Some(protocol) = protocol {
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

/// Python-identifier shape (allowing dotted submodules), matching the gate
/// used when forming `module.attr` callable references.
fn is_pickle_ident(s: &str) -> bool {
    !s.is_empty()
        && s.is_ascii()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && s.starts_with(|c: char| c.is_alphabetic() || c == '_')
}

/// The text a Unicode-string opcode pushes.
fn unicode_operand<'a>(op: &Op<'a>) -> Option<&'a str> {
    match (op.code, op.arg) {
        (0x8C | b'X' | 0x8D, Arg::Bytes(bytes)) | (b'V', Arg::Line(bytes)) => {
            std::str::from_utf8(bytes).ok()
        }
        _ => None,
    }
}

/// GLOBAL's and INST's module and attribute.
fn inline_global<'a>(op: &Op<'a>) -> Option<(&'a str, &'a str)> {
    let Arg::Lines(module, attr) = op.arg else {
        return None;
    };
    Some((
        std::str::from_utf8(module).ok()?,
        std::str::from_utf8(attr).ok()?,
    ))
}

/// How far [`renpy_pycode_sources`] is into one `PyCode` construction.
#[derive(Clone, Copy)]
enum PyCodeWalk<'a> {
    Idle,
    /// GLOBAL (or a memo GET of) `renpy.ast.PyCode`.
    Global,
    /// NEWOBJ or NEWOBJ_EX built the object.
    Constructed,
    /// The state tuple's MARK.
    StateTuple,
    /// The state version, 1.
    Version,
    /// The source string, waiting for BUILD.
    Source(&'a str),
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
    let mut walk = PyCodeWalk::Idle;
    let mut age = 0usize;
    let mut stack = PickleStack::default();
    let mut protocol = None;
    let mut modules = BTreeSet::new();
    let mut globals = BTreeSet::new();
    while let Ok((decoded, next)) = ops::decode(scan, pos) {
        let op = decoded.code;
        if !matches!(walk, PyCodeWalk::Idle) {
            age += 1;
            if age > MAX_WALK_OPCODES {
                walk = PyCodeWalk::Idle;
            }
        }
        apply_side_effects(
            &decoded,
            pos,
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
        walk = match walk {
            PyCodeWalk::Idle if pycode_global => {
                age = 0;
                PyCodeWalk::Global
            }
            PyCodeWalk::Global if matches!(op, 0x81 | 0x92) => PyCodeWalk::Constructed,
            PyCodeWalk::Global if !matches!(op, b'q' | b'r' | 0x94 | b')') => PyCodeWalk::Idle,
            PyCodeWalk::Constructed if op == b'(' => PyCodeWalk::StateTuple,
            PyCodeWalk::Constructed if !matches!(op, b'q' | b'r' | 0x94) => PyCodeWalk::Idle,
            PyCodeWalk::StateTuple if matches!(op, b'K' | b'J') && decoded.arg == Arg::Int(1) => {
                PyCodeWalk::Version
            }
            PyCodeWalk::Version => unicode_operand(&decoded)
                .filter(|source| !source.is_empty() && source.len() <= MAX_SOURCE_BYTES)
                .map_or(PyCodeWalk::Idle, PyCodeWalk::Source),
            PyCodeWalk::Source(source) if op == b'b' => {
                if !out.iter().any(|existing| existing == source) {
                    out.push(source.to_owned());
                    if out.len() >= MAX_SOURCE_COUNT {
                        break;
                    }
                }
                PyCodeWalk::Idle
            }
            unchanged => unchanged,
        };
        pos = next;
        if op == b'.' {
            break;
        }
    }
    out
}

/// Record the global a pickle at `protocol` names as `module.attr`, as the
/// name Python imports for it (see [`compat::find_class`]).
fn record_global(
    module: &str,
    attr: &str,
    protocol: Option<u8>,
    modules: &mut BTreeSet<String>,
    globals: &mut BTreeSet<String>,
) {
    let (module, attr) = compat::find_class(protocol, module, attr);
    if !module.is_empty() {
        modules.insert(module.to_owned());
    }
    if is_pickle_ident(module) && is_pickle_ident(attr) {
        globals.insert(format!("{module}.{attr}"));
    }
}

/// Model one opcode's effect on the stack, recording the globals it names.
/// `i` is the opcode's offset, which names the operands it pushes.
fn apply_side_effects<'a>(
    op: &Op<'a>,
    i: usize,
    protocol: &mut Option<u8>,
    modules: &mut BTreeSet<String>,
    globals: &mut BTreeSet<String>,
    stack: &mut PickleStack<'a>,
) {
    let index = match op.arg {
        Arg::Int(n) => usize::try_from(n).ok(),
        // A decimal memo index on a text line.
        Arg::Line(line) => std::str::from_utf8(line).ok().and_then(|s| s.parse().ok()),
        _ => None,
    };
    match op.code {
        0x80 => {
            // PROTO's operand is one byte, so it always narrows.
            if let Arg::Int(p) = op.arg {
                *protocol = u8::try_from(p).ok();
            }
        }
        b'c' => {
            let global = inline_global(op);
            if let Some((module, attr)) = global {
                record_global(module, attr, *protocol, modules, globals);
            }
            stack
                .values
                .push(
                    global.map_or(StackValue::Other, |(module, attr)| StackValue::Global {
                        module,
                        attr,
                    }),
                );
        }
        0x8C | b'X' | 0x8D | b'V' => {
            stack
                .values
                .push(unicode_operand(op).map_or(StackValue::Other, |text| {
                    StackValue::Text(Operand { at: i, text })
                }));
        }
        b'(' => stack.values.push(StackValue::Mark),
        b'0' => {
            stack.pop();
        }
        b'1' => stack.pop_through_mark(),
        b'2' => {
            if let Some(&value) = stack.values.last() {
                stack.values.push(value);
            }
        }
        b'q' | b'r' | b'p' => {
            if let Some(index) = index {
                stack.memo_put(index);
            }
        }
        0x94 => stack.memo_put(stack.memo.len()),
        b'h' | b'j' | b'g' => {
            let value = index.and_then(|index| stack.memo.get(&index).copied());
            stack.values.push(value.unwrap_or(StackValue::Other));
        }
        0x93 => {
            let attr = stack.pop();
            let module = stack.pop();
            let resolved = match (module, attr) {
                (StackValue::Text(module), StackValue::Text(attr)) => {
                    if stack.admit_global(module, attr) {
                        record_global(module.text, attr.text, *protocol, modules, globals);
                    }
                    StackValue::Global {
                        module: module.text,
                        attr: attr.text,
                    }
                }
                _ => StackValue::Other,
            };
            stack.values.push(resolved);
        }
        // Scalars, bytes, extension-registry results and out-of-band buffers.
        b'F' | b'I' | b'J' | b'K' | b'L' | b'M' | b'N' | b'S' | b'T' | b'U' | b'G' | b'B'
        | b'C' | 0x82 | 0x83 | 0x84 | 0x88 | 0x89 | 0x8A | 0x8B | 0x8E | 0x96 | 0x97 | b'P' => {
            stack.values.push(StackValue::Other)
        }
        // Empty containers.
        b')' | b']' | b'}' | 0x8F => stack.values.push(StackValue::Other),
        // MARK-delimited container constructors.
        b'd' | b'l' | b't' | 0x91 => {
            stack.pop_through_mark();
            stack.values.push(StackValue::Other);
        }
        // Batch mutations consume through MARK but retain their container.
        b'e' | b'u' | 0x90 => stack.pop_through_mark(),
        // Single mutations consume their arguments and retain the container.
        b'a' => stack.pop_n(1),
        b's' => stack.pop_n(2),
        // Fixed-arity tuples.
        0x85 => {
            stack.pop_n(1);
            stack.values.push(StackValue::Other);
        }
        0x86 => {
            stack.pop_n(2);
            stack.values.push(StackValue::Other);
        }
        0x87 => {
            stack.pop_n(3);
            stack.values.push(StackValue::Other);
        }
        // Construction never executes here; only stack effects are modeled.
        b'R' | 0x81 => {
            stack.pop_n(2);
            stack.values.push(StackValue::Other);
        }
        0x92 => {
            stack.pop_n(3);
            stack.values.push(StackValue::Other);
        }
        b'b' => stack.pop_n(1),
        b'i' => {
            if let Some((module, attr)) = inline_global(op) {
                record_global(module, attr, *protocol, modules, globals);
            }
            stack.pop_through_mark();
            stack.values.push(StackValue::Other);
        }
        b'o' => {
            stack.pop_through_mark();
            stack.values.push(StackValue::Other);
        }
        b'Q' => {
            stack.pop_n(1);
            stack.values.push(StackValue::Other);
        }
        // PROTO, FRAME, STOP and READONLY_BUFFER have no modeled stack effect.
        _ => {}
    }
}

#[cfg(test)]
mod tests;
