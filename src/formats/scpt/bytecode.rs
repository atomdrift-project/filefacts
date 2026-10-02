//! Bounded, static AppleScript bytecode analysis. No Apple events are executed.
//!
//! Parser contract: vector `items` EXCLUDE the runtime tag. A Bytes node's
//! `offset` MUST address `data[0]`, not its serialized object header. Function
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
            if let Some(Value::Bytes { tag: None, data }) = items
                .first()
                .and_then(|&item| parsed.nodes.get(item))
                .map(|n| &n.value)
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
        let (Some(16), &[name, _, arity, _, _, literals, code]) = (*tag, items.as_slice()) else {
            continue;
        };
        let (Some(name), Some(literals), Some(code_node)) = (
            target(parsed, name),
            vector(parsed, literals),
            parsed.nodes.get(code),
        ) else {
            continue;
        };
        let Value::Bytes { data: code, .. } = &code_node.value else {
            continue;
        };
        let arity = vector(parsed, arity)
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
    while let Some(&op) = code.get(pc) {
        if *remaining == 0 {
            limit(
                out,
                "instruction budget exhausted; handler decoding stopped",
            );
            break;
        }
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
        let operand = match code.get(pc + 1..pc + 3) {
            Some(&[high, low]) if size >= 3 => u16::from_be_bytes([high, low]),
            _ => 0,
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
        let [empty, event, constant_literals @ ..] = h.literals else {
            continue;
        };
        if literal(parsed, *empty) != Known::String(String::new(), false)
            || !matches!(parsed.nodes.get(*event).map(|n| &n.value),
                Some(Value::Event(s)) if s == "core.cnte")
        {
            continue;
        }
        if constants.iter().zip(constant_literals).all(|(c, &id)| {
            literal(parsed, id)
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
        let y = b.and_then(|b| b.get(i)).copied().unwrap_or(0);
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
mod tests;
