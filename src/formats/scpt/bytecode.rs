//! Bounded, static AppleScript bytecode analysis. No Apple events are executed.
//!
//! Parser contract: vector `items` EXCLUDE the runtime tag. A Bytes node's
//! `offset` MUST address data[0], not its serialized object header. Function
//! offsets address the function node; call/recovery offsets address opcodes.
//!
//! Opcode names, widths and function layout are based on disassembler.py and
//! engine/util.py in Jinmo's applescript-disassembler. RepeatInCollection has
//! a two-byte variable operand (the reference printer does not consume it).
//! LinkRepeat's displacement, like Jump's, is relative to its first operand
//! byte; the reference printer adds two extra bytes for LinkRepeat.
//! Unknown or unverified instruction widths terminate that handler.
//!
//! MIT License — Copyright (c) 2017 Jinmo
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.

use super::parser::{Parsed, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
pub(super) struct Analysis {
    pub functions: Vec<Function>,
}

#[derive(Debug)]
pub(super) struct Function {
    pub name: String,
    pub offset: usize,
    pub calls: Vec<Call>,
    pub decoded: Vec<Recovered>,
    pub limitations: Vec<String>,
}

#[derive(Debug)]
pub(super) struct Call {
    pub target: String,
    pub offset: usize,
    /// Positional arguments, or the direct argument followed by named argument
    /// values in bytecode order. Unknown values never contain guessed fragments.
    pub args: Vec<Argument>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Argument {
    String(String),
    Number(i64),
    Bool(bool),
    Unknown,
}

#[derive(Debug)]
pub(super) struct Recovered {
    pub text: String,
    /// Source offset of the decoder invocation, constant Concatenate opcode, or
    /// call consuming constructed constant text. Never the integer-array offset.
    /// This is an exact value/subexpression, not necessarily a complete command.
    pub offset: usize,
}

const MAX_FUNCTIONS: usize = 1024;
const MAX_NODES: usize = 262_144;
const MAX_INSTRUCTIONS: usize = 262_144;
const MAX_ARRAY: usize = 4096;
const MAX_TEXT: usize = 16_384;
const MAX_STACK: usize = 4096;
const MAX_LOCALS: usize = 1024;
const MAX_WORK: usize = 8_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Known {
    // The flag marks constructed text, so callsite recovery need not re-emit
    // every raw string literal already reported by the structural reader.
    String(String, bool),
    Number(i64),
    Bool(bool),
    Constant(u64),
    Array(Vec<i64>),
    Receiver,
    Unknown,
}

impl Known {
    fn argument(&self) -> Argument {
        match self {
            Self::String(s, _) => Argument::String(s.clone()),
            Self::Number(n) => Argument::Number(*n),
            Self::Bool(b) => Argument::Bool(*b),
            _ => Argument::Unknown,
        }
    }

    fn cost(&self) -> usize {
        match self {
            Self::String(s, _) => 1 + s.len(),
            Self::Array(a) => 1 + a.len() * 8,
            _ => 1,
        }
    }
}

fn vector(parsed: &Parsed, id: usize) -> Option<&[usize]> {
    match &parsed.nodes.get(id)?.value {
        Value::Vector { items, .. } => Some(items),
        _ => None,
    }
}

fn target(parsed: &Parsed, id: usize) -> Option<String> {
    match &parsed.nodes.get(id)?.value {
        Value::Name(s) | Value::Event(s) if s.len() <= MAX_TEXT => Some(s.clone()),
        _ => None,
    }
}

fn unicode(data: &[u8]) -> Known {
    if data.len() <= MAX_TEXT && data.len().is_multiple_of(2) {
        let units: Vec<_> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&units) {
            if s.len() <= MAX_TEXT {
                return Known::String(s, false);
            }
        }
    }
    Known::Unknown
}

fn literal(parsed: &Parsed, id: usize) -> Known {
    let Some(node) = parsed.nodes.get(id) else {
        return Known::Unknown;
    };
    match &node.value {
        Value::Int(n) => Known::Number(*n),
        Value::Bool(b) => Known::Bool(*b),
        Value::Constant(n) => Known::Constant(*n),
        Value::Bytes { tag: Some(0), data } if data.len() <= MAX_TEXT && data.is_ascii() => {
            // ASCII is valid UTF-8; borrow it rather than risk a panicking
            // conversion whose precondition lives in the match guard.
            match std::str::from_utf8(data) {
                Ok(text) => Known::String(text.to_owned(), false),
                Err(_) => Known::Unknown,
            }
        }
        // Native Unicode vectors refer to untyped UTF-16BE bytes. A child
        // tagged 177 marks legacy FAS-12 text; its encoding is not established.
        // Arbitrary byte blobs, names, and event identifiers are not strings.
        Value::Vector {
            tag: Some(177),
            items,
        } if matches!(items.len(), 1 | 2) => {
            if let Some(Value::Bytes { tag: None, data }) =
                parsed.nodes.get(items[0]).map(|n| &n.value)
            {
                return unicode(data);
            }
            Known::Unknown
        }
        _ => Known::Unknown,
    }
}

struct Handler<'a> {
    name: String,
    offset: usize,
    code_offset: usize,
    code: &'a [u8],
    literals: &'a [usize],
    arity: Option<i64>,
}

fn handlers(parsed: &Parsed) -> (Vec<Handler<'_>>, bool) {
    let mut seen = BTreeSet::new();
    let mut pending = vec![parsed.root];
    let mut found = Vec::new();
    let mut limited = false;
    while let Some(id) = pending.pop() {
        if seen.contains(&id) {
            continue;
        }
        if seen.len() >= MAX_NODES {
            limited = true;
            break;
        }
        seen.insert(id);
        let Some(node) = parsed.nodes.get(id) else {
            continue;
        };
        let Value::Vector { tag, items } = &node.value else {
            continue;
        };
        if pending.len().saturating_add(items.len()) > MAX_NODES {
            limited = true;
            break;
        }
        pending.extend(items.iter().rev().copied());
        // Runtime tag 16 denotes a handler. Offsets in the Python reference
        // include the tag at index zero; this parser stores it separately.
        if *tag != Some(16) || items.len() != 7 {
            continue;
        }
        let (Some(name), Some(literals), Some(code_node)) = (
            target(parsed, items[0]),
            vector(parsed, items[5]),
            parsed.nodes.get(items[6]),
        ) else {
            continue;
        };
        let Value::Bytes { data: code, .. } = &code_node.value else {
            continue;
        };
        let arity = vector(parsed, items[2])
            .and_then(|v| v.first())
            .and_then(|id| match parsed.nodes.get(*id)?.value {
                Value::Int(n) => Some(n),
                _ => None,
            });
        if found.len() >= MAX_FUNCTIONS {
            limited = true;
            break;
        }
        found.push(Handler {
            name,
            offset: node.offset,
            code_offset: code_node.offset,
            code,
            literals,
            arity,
        });
    }
    found.sort_by_key(|h| h.offset);
    (found, limited)
}

#[derive(Clone, Copy, Debug)]
struct Instruction {
    pc: usize,
    op: u8,
    operand: u16,
}

/// Only widths supported by the reference or verified by operand structure.
/// In particular do not use a fallback one-byte width for Undefined opcodes.
fn width(op: u8) -> Option<usize> {
    match op {
        9 | 10 | 12 | 18 | 20 | 23 | 27 | 28 | 29 | 43 | 75 | 87 | 89 | 93..=97 => Some(3),
        88 | 98 | 99 => Some(5),
        0..=8
        | 11
        | 13..=15
        | 22
        | 25
        | 30..=42
        | 44..=71
        | 79..=86
        | 90..=92
        | 101..=109
        | 118
        | 160..=239 => Some(1),
        _ => None,
    }
}

fn branch_target(i: Instruction) -> Option<usize> {
    if !matches!(i.op, 9 | 10 | 20 | 23 | 29 | 87 | 89) {
        return None;
    }
    // All modeled displacements are relative to the first operand byte.
    // In particular LinkRepeat must land on the instruction after the backedge,
    // not two bytes into that instruction as in the reference printer.
    let base = i.pc.checked_add(1)?;
    base.checked_add_signed(i.operand as i16 as isize)
}

fn limit(out: &mut Function, text: &str) {
    if out.limitations.len() < 32 && !out.limitations.iter().any(|s| s == text) {
        out.limitations.push(text.to_string());
    }
}

fn decode(
    code: &[u8],
    base: usize,
    remaining: &mut usize,
    out: &mut Function,
) -> (Vec<Instruction>, BTreeSet<usize>) {
    let mut decoded = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        if *remaining == 0 {
            limit(
                out,
                "instruction budget exhausted; handler decoding stopped",
            );
            break;
        }
        let op = code[pc];
        let Some(size) = width(op) else {
            limit(
                out,
                &format!(
                    "unknown/unverified opcode 0x{op:02x} at byte {}; handler decoding stopped",
                    base.saturating_add(pc)
                ),
            );
            break;
        };
        if size > code.len() - pc {
            limit(
                out,
                &format!(
                    "truncated opcode 0x{op:02x} at byte {}; handler decoding stopped",
                    base.saturating_add(pc)
                ),
            );
            break;
        }
        let operand = if size >= 3 {
            u16::from_be_bytes([code[pc + 1], code[pc + 2]])
        } else {
            0
        };
        decoded.push(Instruction { pc, op, operand });
        pc += size;
        *remaining -= 1;
    }
    let boundaries: BTreeSet<_> = decoded
        .iter()
        .map(|i| i.pc)
        .chain(std::iter::once(pc))
        .collect();
    let mut joins = BTreeSet::new();
    let mut stop = decoded.len();
    for (n, &i) in decoded.iter().enumerate() {
        if matches!(i.op, 9 | 10 | 20 | 23 | 29 | 87 | 89) {
            match branch_target(i) {
                Some(t) if t <= code.len() && boundaries.contains(&t) => {
                    joins.insert(t);
                }
                // A valid forward target can lie beyond an unsupported opcode.
                // No values beyond that stop will be analyzed in either case.
                Some(t) if pc < code.len() && t > pc && t <= code.len() => {}
                _ => {
                    limit(
                        out,
                        &format!(
                            "invalid branch target at byte {}; handler analysis stopped",
                            base.saturating_add(i.pc)
                        ),
                    );
                    stop = n;
                    break;
                }
            }
        }
    }
    decoded.truncate(stop);
    (decoded, joins)
}

#[derive(Clone, Copy, Debug)]
enum Decoder {
    SubtractArrays,
    AddArrays,
    SubtractArraysAndScalar,
    SubtractScalar,
}

// Complete bodies, including all loop edges and returns, not signatures of
// arbitrary handler names. Literal semantics and formal arity are also checked.
// Restricting recognition to these exact instruction sequences intentionally
// sacrifices coverage for an auditable proof of what gets evaluated.
const DECODER_BODIES: [(&str, Decoder, i64, &[u64]); 5] = [
    (
        "e045b24f6a45b34f1700366ba06a0c00016b681c0004a3a0e2a42f1ee32345b34fa22ae4a0e2a42fa1e2a42f1fe5302545b24fa36d20e32345b35b4f59ffd64fa20f0f",
        Decoder::SubtractArrays,
        2,
        &[0x636f626a, 9999, 0x63686120, 0x6b66726d49442020],
    ),
    (
        "e045b24f6b45b34f1700346ba06a0c00016b681c0004a3a1e2a42f1ee32345b34fa22ae4a0e2a42fa1e2a42f1ee5302545b24fa36b1e45b35b4f59ffd84fa20f0f",
        Decoder::AddArrays,
        2,
        &[0x636f626a, 9999, 0x63686120, 0x6b66726d49442020],
    ),
    (
        "e045b34f6a45b44f1700356ba06a0c00016b681c0005a0e2a52fa21f45b64fa6a1e2a52f1f45b64fa32ae3a6e4302545b34fa4a61ee52345b45b4f59ffd74fa30f0f",
        Decoder::SubtractArraysAndScalar,
        3,
        &[0x636f626a, 0x63686120, 0x6b66726d49442020, 9999],
    ),
    (
        "e045b24f1700206ba06a0c00016b681c0003a22ae2a0e3a32fa11fe4302545b25b4f59ffec4fa20f0f",
        Decoder::SubtractScalar,
        2,
        &[0x63686120, 0x636f626a, 0x6b66726d49442020],
    ),
    (
        "e045b24f1700276ba06a0c00016b681c0003a0e2a32fa1e2a32f1e45b44fa22ae3a4e4302545b25b4f59ffe54fa20f0f",
        Decoder::AddArrays,
        2,
        &[0x636f626a, 0x63686120, 0x6b66726d49442020],
    ),
];

fn matches_hex(code: &[u8], hex: &str) -> bool {
    code.len() * 2 == hex.len()
        && code
            .iter()
            .zip(hex.as_bytes().as_chunks::<2>().0.iter())
            .all(|(b, h)| {
                let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
                *b == digit(h[0]) * 16 + digit(h[1])
            })
}

fn recognize(parsed: &Parsed, h: &Handler<'_>) -> Option<Decoder> {
    for &(body, decoder, arity, constants) in &DECODER_BODIES {
        if h.arity != Some(arity)
            || !matches_hex(h.code, body)
            || h.literals.len() != constants.len() + 2
        {
            continue;
        }
        if literal(parsed, h.literals[0]) != Known::String(String::new(), false)
            || !matches!(parsed.nodes.get(h.literals[1]).map(|n| &n.value),
                Some(Value::Event(s)) if s == "core.cnte")
        {
            continue;
        }
        if constants.iter().enumerate().all(|(i, c)| {
            literal(parsed, h.literals[i + 2])
                == if *c == 9999 {
                    Known::Number(9999)
                } else {
                    Known::Constant(*c)
                }
        }) {
            return Some(decoder);
        }
    }
    None
}

fn recover(decoder: Decoder, args: &[Known]) -> Option<String> {
    let Known::Array(a) = args.first()? else {
        return None;
    };
    if a.len() > MAX_ARRAY {
        return None;
    }
    let (b, scalar) = match decoder {
        Decoder::SubtractScalar => {
            let [_, Known::Number(n)] = args else {
                return None;
            };
            (None, *n)
        }
        Decoder::SubtractArraysAndScalar => {
            let [_, Known::Array(b), Known::Number(n)] = args else {
                return None;
            };
            (Some(b), *n)
        }
        _ => {
            let [_, Known::Array(b)] = args else {
                return None;
            };
            (Some(b), 0)
        }
    };
    if scalar.unsigned_abs() > 1_000_000 || b.is_some_and(|b| b.len() != a.len()) {
        return None;
    }
    let mut text = String::with_capacity(a.len());
    for (i, &x) in a.iter().enumerate() {
        let y = b.map_or(0, |b| b[i]);
        // Bounds also prove that the unused checksum arithmetic in the fully
        // matched bodies cannot overflow or prevent the function from returning.
        if x.unsigned_abs() > 1_000_000 || y.unsigned_abs() > 1_000_000 {
            return None;
        }
        let n = match decoder {
            Decoder::AddArrays => x.checked_add(y)?,
            Decoder::SubtractArrays => x.checked_sub(y)?,
            Decoder::SubtractArraysAndScalar => x.checked_sub(scalar)?.checked_sub(y)?,
            Decoder::SubtractScalar => x.checked_sub(scalar)?,
        };
        // ASCII is unambiguous across AppleScript character-ID encodings.
        // Wider Unicode/legacy encodings are deliberately not guessed.
        if !(0..=127).contains(&n) {
            return None;
        }
        text.push(n as u8 as char);
    }
    Some(text)
}

#[derive(Default)]
struct State {
    stack: Vec<Known>,
    locals: BTreeMap<usize, Known>,
}

impl State {
    fn clear(&mut self) {
        self.stack.clear();
        self.locals.clear();
    }
    fn pop(&mut self) -> Known {
        self.stack.pop().unwrap_or(Known::Unknown)
    }
    fn count(&mut self, maximum: usize) -> Option<usize> {
        match self.pop() {
            Known::Number(n) if n >= 0 && (n as u64) <= maximum as u64 => Some(n as usize),
            _ => None,
        }
    }
    fn take(&mut self, count: usize) -> Option<Vec<Known>> {
        if count > self.stack.len() {
            return None;
        }
        Some(self.stack.split_off(self.stack.len() - count))
    }
    fn push(&mut self, value: Known, work: &mut usize) -> bool {
        let cost = value.cost();
        if self.stack.len() >= MAX_STACK || cost > *work {
            return false;
        }
        *work -= cost;
        self.stack.push(value);
        true
    }
}

fn calculate(op: u8, left: Known, right: Known) -> Known {
    match (op, left, right) {
        (37, Known::String(mut a, _), Known::String(b, _)) if a.len() + b.len() <= MAX_TEXT => {
            a.push_str(&b);
            Known::String(a, true)
        }
        (30..=35, Known::Number(a), Known::Number(b)) => {
            let n = match op {
                30 => a.checked_add(b),
                31 => a.checked_sub(b),
                32 => a.checked_mul(b),
                // Divide produces a real in AppleScript; no integer approximation.
                34 => a.checked_div(b),
                35 => a.checked_rem(b),
                _ => None,
            };
            n.map(Known::Number).unwrap_or(Known::Unknown)
        }
        _ => Known::Unknown,
    }
}

pub(super) fn analyze(parsed: &Parsed) -> Analysis {
    let (handlers, graph_limited) = handlers(parsed);
    // Disable name-based resolution if scopes contain duplicate handler names.
    let mut names = BTreeMap::<&str, usize>::new();
    for h in &handlers {
        *names.entry(&h.name).or_default() += 1;
    }
    let mut decoders = BTreeMap::new();
    if !graph_limited {
        for h in &handlers {
            if names.get(h.name.as_str()) == Some(&1) {
                if let Some(d) = recognize(parsed, h) {
                    decoders.insert(h.name.as_str(), d);
                }
            }
        }
    }
    let mut analysis = Analysis::default();
    let mut remaining = MAX_INSTRUCTIONS;
    let mut work = MAX_WORK;
    for h in &handlers {
        let mut out = Function {
            name: h.name.clone(),
            offset: h.offset,
            calls: Vec::new(),
            decoded: Vec::new(),
            limitations: Vec::new(),
        };
        if graph_limited {
            limit(
                &mut out,
                "handler graph limit reached; decoder resolution disabled",
            );
        }
        let Some(_) = h.code_offset.checked_add(h.code.len()) else {
            limit(&mut out, "bytecode source offset overflow");
            analysis.functions.push(out);
            continue;
        };
        let (instructions, joins) = decode(h.code, h.code_offset, &mut remaining, &mut out);
        let mut state = State::default();
        let mut tell_depth = 0usize;
        for i in instructions {
            if work == 0 {
                limit(&mut out, "constant recovery work budget exhausted");
                break;
            }
            work -= 1;
            if joins.contains(&i.pc) {
                state.clear();
            }
            let offset = h.code_offset + i.pc;
            let mut pushed = None;
            match i.op {
                224..=239 | 97 => {
                    let idx = if i.op == 97 {
                        i.operand as usize
                    } else {
                        (i.op & 15) as usize
                    };
                    pushed = Some(
                        h.literals
                            .get(idx)
                            .map_or(Known::Unknown, |id| literal(parsed, *id)),
                    );
                }
                160..=175 | 93 => {
                    let idx = if i.op == 93 {
                        i.operand as usize
                    } else {
                        (i.op & 15) as usize
                    };
                    pushed = Some(state.locals.get(&idx).cloned().unwrap_or(Known::Unknown));
                }
                176..=191 | 94 => {
                    let idx = if i.op == 94 {
                        i.operand as usize
                    } else {
                        (i.op & 15) as usize
                    };
                    let value = state.pop();
                    if idx < MAX_LOCALS {
                        state.locals.insert(idx, value);
                    } else {
                        limit(&mut out, "local-variable index exceeds recovery limit");
                    }
                }
                192..=207 | 95 | 98 => {
                    pushed = Some(Known::Unknown);
                }
                208..=223 | 96 | 99 => {
                    state.clear();
                    limit(
                        &mut out,
                        "global/parent assignment clears propagated constants",
                    );
                }
                101 => pushed = Some(Known::Bool(true)),
                102 => pushed = Some(Known::Bool(false)),
                103 => pushed = Some(Known::Unknown),
                104 => pushed = Some(Known::Unknown),
                105..=109 => pushed = Some(Known::Number(i.op as i64 - 106)),
                41 => pushed = Some(Known::Receiver),
                42 => {
                    pushed = Some(if tell_depth == 0 {
                        Known::Receiver
                    } else {
                        Known::Unknown
                    })
                }
                40 | 69 => {} // Dereference only already-known immutable values.
                90 => {
                    state.pop();
                }
                91 => pushed = Some(state.stack.last().cloned().unwrap_or(Known::Unknown)),
                79 => {
                    // StoreResult consumes the expression left by the statement;
                    // after PopVariable the stack may already be empty. Result is
                    // intentionally unknown, to avoid ambiguous statement semantics.
                    state.pop();
                }
                80 => pushed = Some(Known::Unknown),
                118 => {
                    let array =
                        state
                            .count(MAX_ARRAY)
                            .and_then(|n| state.take(n))
                            .and_then(|values| {
                                values
                                    .into_iter()
                                    .map(|v| match v {
                                        Known::Number(n) => Some(n),
                                        _ => None,
                                    })
                                    .collect::<Option<Vec<_>>>()
                            });
                    if let Some(a) = array {
                        pushed = Some(Known::Array(a));
                    } else {
                        state.clear();
                        pushed = Some(Known::Unknown);
                    }
                }
                0..=8 | 30..=38 => {
                    let right = state.pop();
                    let left = state.pop();
                    let value = calculate(i.op, left, right);
                    // This is the exact constant subexpression at Concatenate,
                    // even when a subsequent operation appends an unknown path.
                    // Its source offset must not be confused with a shell call.
                    if i.op == 37 {
                        if let Known::String(text, true) = &value {
                            if text.len() > work {
                                limit(&mut out, "constant recovery work budget exhausted");
                                break;
                            }
                            work -= text.len();
                            out.decoded.push(Recovered {
                                text: text.clone(),
                                offset,
                            });
                        }
                    }
                    pushed = Some(value);
                }
                11 | 39 => {
                    let v = state.pop();
                    pushed = Some(match (i.op, v) {
                        (11, Known::Bool(b)) => Known::Bool(!b),
                        (39, Known::Number(n)) => {
                            n.checked_neg().map_or(Known::Unknown, Known::Number)
                        }
                        _ => Known::Unknown,
                    });
                }
                12 | 43 => {
                    let name = h
                        .literals
                        .get(i.operand as usize)
                        .and_then(|id| target(parsed, *id));
                    let mut arguments = None;
                    let mut receiver = Known::Unknown;
                    if i.op == 43 {
                        if let Some(n) = state.count(64) {
                            arguments = state.take(n);
                            receiver = state.pop();
                        }
                    } else if let Some(n) = state.count(128) {
                        // MessageSend: direct parameter, (keyword, value)*, word count.
                        if n % 2 == 0 {
                            if let Some(named) = state.take(n) {
                                let direct = state.pop();
                                if named
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .all(|pair| matches!(pair[0], Known::Constant(_)))
                                {
                                    let mut args = vec![direct];
                                    args.extend(
                                        named
                                            .into_iter()
                                            .enumerate()
                                            .filter_map(|(j, v)| (j % 2 == 1).then_some(v)),
                                    );
                                    arguments = Some(args);
                                }
                            }
                        }
                    }
                    if let Some(args) = &arguments {
                        for value in args {
                            if let Known::String(text, true) = value {
                                if text.len() <= work {
                                    work -= text.len();
                                    out.decoded.push(Recovered {
                                        text: text.clone(),
                                        offset,
                                    });
                                } else {
                                    limit(&mut out, "constant recovery work budget exhausted");
                                }
                            }
                        }
                    }
                    out.calls.push(Call {
                        target: name
                            .clone()
                            .unwrap_or_else(|| format!("<literal:{}>", i.operand)),
                        offset,
                        args: arguments
                            .as_ref()
                            .map(|a| a.iter().map(Known::argument).collect())
                            .unwrap_or_else(|| vec![Argument::Unknown]),
                    });
                    if name.is_none() {
                        limit(&mut out, "call literal is missing or is not a name/event");
                    }
                    let decoder = if i.op == 43 && receiver == Known::Receiver {
                        name.as_deref().and_then(|n| decoders.get(n)).copied()
                    } else {
                        None
                    };
                    let recovered =
                        decoder.and_then(|d| arguments.as_deref().and_then(|a| recover(d, a)));
                    if let Some(text) = recovered {
                        if text.len() > work {
                            limit(&mut out, "constant recovery work budget exhausted");
                            break;
                        }
                        work -= text.len();
                        out.decoded.push(Recovered {
                            text: text.clone(),
                            offset,
                        });
                        pushed = Some(Known::String(text, true));
                    } else {
                        if decoder.is_some() {
                            limit(
                                &mut out,
                                "verified decoder arguments unknown, out of bounds, or non-ASCII",
                            );
                        }
                        state.clear();
                        pushed = Some(Known::Unknown);
                        limit(
                            &mut out,
                            "unmodeled calls clear propagated constants; return values unknown",
                        );
                    }
                }
                18 => {
                    tell_depth = tell_depth.saturating_add(1);
                    state.clear();
                    limit(&mut out, "tell context clears propagated constants");
                }
                85 => {
                    tell_depth = tell_depth.saturating_sub(1);
                    state.clear();
                }
                9 | 10 | 15 | 20 | 22 | 23 | 25 | 27 | 28 | 29 | 87 | 88 | 89 => {
                    state.clear();
                    limit(
                        &mut out,
                        "control-flow boundaries clear propagated constants; paths are not executed",
                    );
                }
                _ => {
                    // Known boundary, unmodeled stack/side effects. Do not let
                    // stale locals or fragments masquerade as later call args.
                    state.clear();
                    limit(
                        &mut out,
                        "unmodeled instruction semantics clear propagated constants",
                    );
                }
            }
            if let Some(v) = pushed {
                if !state.push(v, &mut work) {
                    limit(&mut out, "stack or constant recovery work budget exhausted");
                    break;
                }
            }
        }
        analysis.functions.push(out);
    }
    analysis
}

#[cfg(test)]
mod tests {
    use super::super::parser::Node;
    use super::*;

    #[test]
    fn legacy_text_is_unknown_but_native_unicode_is_known() {
        let legacy =
            super::super::parser::parse(b"FasdUAS 1.101.10\x0c\0\0\0\0\0\x04ABCD\0\0").unwrap();
        assert_eq!(literal(&legacy, legacy.root), Known::Unknown);
        let child = vector(&legacy, legacy.root).unwrap()[0];
        assert_eq!(literal(&legacy, child), Known::Unknown);
        let mut native = arena();
        let id = text(&mut native, "Hello \u{1f30d}");
        assert_eq!(
            literal(&native, id),
            Known::String("Hello \u{1f30d}".into(), false)
        );
    }

    fn arena() -> Parsed {
        Parsed {
            nodes: vec![Node {
                offset: 0,
                value: Value::Vector {
                    tag: None,
                    items: Vec::new(),
                },
            }],
            root: 0,
            version: "1.10".into(),
            truncated: None,
        }
    }

    fn node(p: &mut Parsed, value: Value, offset: usize) -> usize {
        let id = p.nodes.len();
        p.nodes.push(Node { offset, value });
        id
    }

    fn text(p: &mut Parsed, s: &str) -> usize {
        let bytes = s.encode_utf16().flat_map(u16::to_be_bytes).collect();
        let data = node(
            p,
            Value::Bytes {
                tag: None,
                data: bytes,
            },
            0,
        );
        node(
            p,
            Value::Vector {
                tag: Some(177),
                items: vec![data],
            },
            0,
        )
    }

    fn handler(
        p: &mut Parsed,
        name: &str,
        code: Vec<u8>,
        literals: Vec<usize>,
        arity: i64,
        base: usize,
    ) -> usize {
        let name = node(p, Value::Name(name.into()), base - 100);
        let n = node(p, Value::Int(arity), 0);
        let args = node(
            p,
            Value::Vector {
                tag: Some(4),
                items: vec![n],
            },
            0,
        );
        let locals = node(p, Value::Unknown, 0);
        let lits = node(
            p,
            Value::Vector {
                tag: None,
                items: literals,
            },
            0,
        );
        let code = node(
            p,
            Value::Bytes {
                tag: Some(13),
                data: code,
            },
            base,
        );
        let id = node(
            p,
            Value::Vector {
                tag: Some(16),
                items: vec![name, locals, args, locals, locals, lits, code],
            },
            base - 110,
        );
        if let Value::Vector { items, .. } = &mut p.nodes[0].value {
            items.push(id);
        }
        id
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).expect("ASCII hex"), 16).unwrap())
            .collect()
    }

    fn add_decoder(p: &mut Parsed, index: usize, name: &str) -> usize {
        let (body, _, arity, constants) = DECODER_BODIES[index];
        let empty = text(p, "");
        let event = node(p, Value::Event("core.cnte".into()), 0);
        let mut lits = vec![empty, event];
        for c in constants {
            lits.push(node(
                p,
                if *c == 9999 {
                    Value::Int(9999)
                } else {
                    Value::Constant(*c)
                },
                0,
            ));
        }
        handler(p, name, hex(body), lits, arity, 0x1000 + index * 0x100)
    }

    fn push_literal(code: &mut Vec<u8>, index: usize) {
        code.push(97);
        code.extend_from_slice(&(index as u16).to_be_bytes());
    }

    fn push_number(p: &mut Parsed, code: &mut Vec<u8>, lits: &mut Vec<usize>, n: i64) {
        let id = node(p, Value::Int(n), 0);
        push_literal(code, lits.len());
        lits.push(id);
    }

    fn push_array(p: &mut Parsed, code: &mut Vec<u8>, lits: &mut Vec<usize>, array: &[i64]) {
        for n in array {
            push_number(p, code, lits, *n);
        }
        push_number(p, code, lits, array.len() as i64);
        code.push(118);
    }

    fn fixture(index: usize, s: &str) -> (Parsed, usize, usize) {
        let mut p = arena();
        // Deliberately unrelated names: names are lookup keys, never signatures.
        add_decoder(&mut p, index, "arbitrary_handler");
        let mut code = vec![42];
        let mut lits = Vec::new();
        let (_, decoder, arity, _) = DECODER_BODIES[index];
        let a: Vec<i64> = s
            .bytes()
            .map(|c| match decoder {
                Decoder::AddArrays => 42,
                Decoder::SubtractArrays => i64::from(c) + 42,
                Decoder::SubtractArraysAndScalar => i64::from(c) + 55,
                Decoder::SubtractScalar => i64::from(c) + 13,
            })
            .collect();
        push_array(&mut p, &mut code, &mut lits, &a);
        match decoder {
            Decoder::SubtractScalar => push_number(&mut p, &mut code, &mut lits, 13),
            _ => {
                let b: Vec<i64> = s
                    .bytes()
                    .map(|c| {
                        if matches!(decoder, Decoder::AddArrays) {
                            i64::from(c) - 42
                        } else {
                            42
                        }
                    })
                    .collect();
                push_array(&mut p, &mut code, &mut lits, &b);
                if arity == 3 {
                    push_number(&mut p, &mut code, &mut lits, 13);
                }
            }
        }
        push_number(&mut p, &mut code, &mut lits, arity);
        let call_pc = code.len();
        code.push(43);
        code.extend_from_slice(&(lits.len() as u16).to_be_bytes());
        lits.push(node(&mut p, Value::Name("arbitrary_handler".into()), 0));
        code.push(106);
        let exec_pc = code.len();
        code.push(12);
        code.extend_from_slice(&(lits.len() as u16).to_be_bytes());
        lits.push(node(&mut p, Value::Event("syso.exec".into()), 0));
        code.push(15);
        handler(&mut p, "caller", code, lits, 0, 0x4000);
        (p, 0x4000 + call_pc, 0x4000 + exec_pc)
    }

    #[test]
    fn all_verified_bodies_recover_with_unrelated_names_and_exact_offsets() {
        for index in 0..5 {
            let expected = "security find-generic-password -w -s 'Chrome Safe Storage'";
            let (p, call, exec) = fixture(index, expected);
            let a = analyze(&p);
            let f = a.functions.iter().find(|f| f.name == "caller").unwrap();
            assert_eq!(f.calls.len(), 2);
            assert_eq!(f.calls[0].offset, call);
            assert_eq!(f.calls[1].offset, exec);
            assert_eq!(f.calls[1].target, "syso.exec");
            assert_eq!(f.calls[1].args, [Argument::String(expected.into())]);
            assert_eq!(f.decoded.len(), 2);
            assert_eq!(
                (f.decoded[0].text.as_str(), f.decoded[0].offset),
                (expected, call)
            );
            assert_eq!(
                (f.decoded[1].text.as_str(), f.decoded[1].offset),
                (expected, exec)
            );
        }
    }

    #[test]
    fn body_literal_arity_and_name_collisions_are_checked() {
        for mutation in 0..4 {
            let (mut p, _, _) = fixture(0, "hello");
            let h = handlers(&p).0[0].offset;
            let index = p.nodes.iter().position(|n| n.offset == h).unwrap();
            let items = vector(&p, index).unwrap().to_vec();
            match mutation {
                0 => {
                    if let Value::Bytes { data, .. } = &mut p.nodes[items[6]].value {
                        data[0] = 107;
                    }
                }
                1 => {
                    let lit = vector(&p, items[5]).unwrap()[2];
                    p.nodes[lit].value = Value::Constant(0x63686120);
                }
                2 => {
                    let n = vector(&p, items[2]).unwrap()[0];
                    p.nodes[n].value = Value::Int(3);
                }
                _ => {
                    add_decoder(&mut p, 1, "arbitrary_handler");
                }
            }
            let a = analyze(&p);
            let f = a.functions.iter().find(|f| f.name == "caller").unwrap();
            assert!(f.decoded.is_empty(), "mutation {mutation}");
            assert_eq!(f.calls[1].args, [Argument::Unknown]);
        }
    }

    fn shell(code: Vec<u8>) -> Analysis {
        let mut p = arena();
        let a = text(&mut p, "security ");
        let b = text(&mut p, "find-generic-password");
        let event = node(&mut p, Value::Event("syso.exec".into()), 0);
        handler(&mut p, "caller", code, vec![a, b, event], 0, 0x1000);
        analyze(&p)
    }

    #[test]
    fn constant_concatenation_is_recovered_at_callsite() {
        let a = shell(vec![224, 225, 37, 106, 12, 0, 2]);
        let f = &a.functions[0];
        assert_eq!(
            f.calls[0].args,
            [Argument::String("security find-generic-password".into())]
        );
        assert_eq!(f.decoded[0].offset, 0x1002);
        assert_eq!(f.decoded[0].text, "security find-generic-password");
        assert_eq!(f.decoded[1].offset, 0x1004);
        let raw = shell(vec![224, 106, 12, 0, 2]);
        assert!(raw.functions[0].decoded.is_empty());
    }

    #[test]
    fn dynamic_concatenation_does_not_claim_a_command() {
        let a = shell(vec![224, 160, 37, 106, 12, 0, 2]);
        assert_eq!(a.functions[0].calls[0].args, [Argument::Unknown]);
        assert!(a.functions[0].decoded.is_empty());
        let b = shell(vec![224, 225, 37, 160, 37, 106, 12, 0, 2]);
        assert_eq!(b.functions[0].calls[0].args, [Argument::Unknown]);
        assert_eq!(b.functions[0].decoded.len(), 1);
        assert_eq!(
            b.functions[0].decoded[0].text,
            "security find-generic-password"
        );
        assert_eq!(b.functions[0].decoded[0].offset, 0x1002);
    }

    #[test]
    fn unknown_and_truncated_opcodes_stop_before_embedded_calls() {
        for prefix in [vec![114], vec![97, 12], vec![98, 12, 0, 2]] {
            let a = shell(prefix);
            assert!(a.functions[0].calls.is_empty());
            assert!(
                a.functions[0]
                    .limitations
                    .iter()
                    .any(|s| s.contains("stopped"))
            );
        }
        let a = shell(vec![114, 224, 106, 12, 0, 2]);
        assert!(a.functions[0].calls.is_empty());
    }

    #[test]
    fn operand_bytes_are_not_opcodes() {
        // RepeatInCollection's 0x000c variable operand is not MessageSend.
        let a = shell(vec![27, 0, 12, 224, 106, 12, 0, 2]);
        assert_eq!(a.functions[0].calls.len(), 1);
        assert_eq!(a.functions[0].calls[0].offset, 0x1005);
        // Parent-variable operands occupy four bytes, including these 0x0c bytes.
        let b = shell(vec![98, 12, 0, 12, 0, 224, 106, 12, 0, 2]);
        assert_eq!(b.functions[0].calls.len(), 1);
        assert_eq!(b.functions[0].calls[0].offset, 0x1007);
    }

    #[test]
    fn branch_displacements_land_on_real_boundaries() {
        let a = shell(vec![23, 0, 5, 89, 0xff, 0xff, 224, 106, 12, 0, 2]);
        assert_eq!(a.functions[0].calls.len(), 1);
        assert!(
            !a.functions[0]
                .limitations
                .iter()
                .any(|s| s.contains("invalid branch"))
        );
        let invalid = shell(vec![89, 0, 1, 224, 106, 12, 0, 2]);
        assert!(invalid.functions[0].calls.is_empty());
        assert!(
            invalid.functions[0]
                .limitations
                .iter()
                .any(|s| s.contains("invalid branch"))
        );
    }

    #[test]
    fn control_joins_clear_values_from_the_linear_predecessor() {
        // Jump reaches pc=6. The linear scan sees the other predecessor's local
        // assignment at pc=4; that value must be discarded at the join.
        let a = shell(vec![89, 0, 5, 224, 176, 79, 160, 106, 12, 0, 2]);
        assert_eq!(a.functions[0].calls[0].args, [Argument::Unknown]);
        // A backedge also makes pc=3 a join, despite the prior local assignment.
        let b = shell(vec![224, 176, 79, 160, 106, 12, 0, 2, 89, 0xff, 0xfa]);
        assert_eq!(b.functions[0].calls[0].args, [Argument::Unknown]);
    }

    #[test]
    fn calls_and_unmodeled_effects_invalidate_locals() {
        for effect in [vec![92], vec![70], vec![208], vec![104, 106, 12, 0, 2]] {
            let mut code = vec![224, 176, 79];
            code.extend(effect);
            code.extend([160, 106, 12, 0, 2]);
            let a = shell(code);
            assert_eq!(
                a.functions[0].calls.last().unwrap().args,
                [Argument::Unknown]
            );
        }
    }

    #[test]
    fn numeric_recovery_rejects_bounds_mismatch_and_overflow() {
        assert_eq!(
            recover(
                Decoder::AddArrays,
                &[Known::Array(vec![232]), Known::Array(vec![-123])]
            ),
            Some("m".into())
        );
        assert!(
            recover(
                Decoder::SubtractArrays,
                &[Known::Array(vec![100]), Known::Array(vec![])]
            )
            .is_none()
        );
        assert!(
            recover(
                Decoder::SubtractScalar,
                &[Known::Array(vec![i64::MAX]), Known::Number(-1)]
            )
            .is_none()
        );
        assert!(
            recover(
                Decoder::SubtractScalar,
                &[Known::Array(vec![128]), Known::Number(0)]
            )
            .is_none()
        );
        assert!(
            recover(
                Decoder::SubtractScalar,
                &[Known::Array(vec![65; MAX_ARRAY + 1]), Known::Number(0)]
            )
            .is_none()
        );
        assert_eq!(
            calculate(30, Known::Number(i64::MAX), Known::Number(1)),
            Known::Unknown
        );
        assert_eq!(
            calculate(35, Known::Number(1), Known::Number(0)),
            Known::Unknown
        );
    }

    #[test]
    fn data_is_only_text_in_a_verified_text_container() {
        let mut p = arena();
        let raw = node(
            &mut p,
            Value::Bytes {
                tag: None,
                data: b"AB".to_vec(),
            },
            0,
        );
        assert_eq!(literal(&p, raw), Known::Unknown);
        let bad = node(
            &mut p,
            Value::Bytes {
                tag: Some(177),
                data: vec![0xd8, 0],
            },
            0,
        );
        assert_eq!(literal(&p, bad), Known::Unknown);
        let good = text(&mut p, "A\u{1f600}");
        assert_eq!(literal(&p, good), Known::String("A\u{1f600}".into(), false));
    }

    #[test]
    fn cyclic_graphs_and_budget_limits_terminate() {
        let mut p = arena();
        if let Value::Vector { items, .. } = &mut p.nodes[0].value {
            items.push(0);
        }
        assert!(analyze(&p).functions.is_empty());
        let mut out = Function {
            name: "budget".into(),
            offset: 0,
            calls: vec![],
            decoded: vec![],
            limitations: vec![],
        };
        let (instructions, _) = decode(&[106, 106, 12, 0, 0], 100, &mut 2, &mut out);
        assert_eq!(instructions.len(), 2);
        assert!(out.limitations.iter().any(|s| s.contains("budget")));
        let mut state = State::default();
        assert!(!state.push(Known::String("too large".into(), false), &mut 1));
    }
}
