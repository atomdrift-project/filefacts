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
use std::collections::{BTreeSet, HashMap};

use crate::formats::common::bytes_at::{u32_le, u64_le};
use crate::formats::common::{XorScan, extract_binary_strings, put_str};
use crate::output::{Metrics, Strings, Values};

/// Cap on opcode-stream bytes scanned. Real malicious payloads are
/// tiny; the cap guards against pathological model files
/// (multi-GB joblib/pytorch).
const MAX_BYTES_SCANNED: usize = 8 * 1024 * 1024;

#[derive(Clone)]
enum StackValue {
    Text(String),
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
struct PickleStack {
    values: Vec<StackValue>,
    memo: HashMap<usize, StackValue>,
}

impl PickleStack {
    fn push(&mut self, value: StackValue) {
        self.values.push(value);
    }

    fn pop(&mut self) -> StackValue {
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
            self.memo.insert(index, value.clone());
        }
    }

    fn memo_get(&mut self, index: usize) {
        self.values
            .push(self.memo.get(&index).cloned().unwrap_or(StackValue::Other));
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

fn unicode_operand(op: u8, scan: &[u8], i: usize) -> Option<String> {
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
    std::str::from_utf8(slice).ok().map(str::to_owned)
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

fn apply_side_effects(
    op: u8,
    i: usize,
    scan: &[u8],
    protocol: &mut i32,
    modules: &mut BTreeSet<String>,
    globals: &mut BTreeSet<String>,
    stack: &mut PickleStack,
) {
    match op {
        0x80 => {
            if let Some(&p) = scan.get(i + 1) {
                *protocol = i32::from(p);
            }
        }
        b'c' => {
            if let Some((module, attr)) = inline_global(scan, i) {
                record_global(module, attr, modules, globals);
            }
            stack.push(StackValue::Other);
        }
        0x8C | b'X' | 0x8D | b'V' => {
            stack.push(
                unicode_operand(op, scan, i)
                    .map(StackValue::Text)
                    .unwrap_or(StackValue::Other),
            );
        }
        b'(' => stack.push(StackValue::Mark),
        b'0' => {
            stack.pop();
        }
        b'1' => stack.pop_through_mark(),
        b'2' => {
            if let Some(value) = stack.values.last().cloned() {
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
            if let (StackValue::Text(module), StackValue::Text(attr)) = (module, attr) {
                record_global(&module, &attr, modules, globals);
            }
            stack.push(StackValue::Other);
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
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m);
        (v, m)
    }

    #[test]
    fn oversized_binbytes8_length_ends_the_scan() {
        // PROTO 4, then BINBYTES8 whose length makes `1 + 8 + len` wrap to 0.
        let data = [
            0x80, 4, 0x8D, 0xF7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let (_, m) = run(&data);
        assert_eq!(m.get("pickle.protocol"), Some(4.0));
    }

    #[test]
    fn surfaces_protocol_and_global() {
        let mut data = vec![0x80, 4, b'c'];
        data.extend_from_slice(b"os\nsystem\n");
        data.extend_from_slice(&[b'R', b'.']);
        let (v, m) = run(&data);
        assert_eq!(m.get("pickle.protocol"), Some(4.0));
        let mods = v.get("pickle.modules").and_then(|x| x.as_array()).unwrap();
        assert_eq!(mods[0].as_str(), Some("os"));
        let globals = v.get("pickle.globals").and_then(|x| x.as_array()).unwrap();
        assert!(
            globals.iter().any(|g| g.as_str() == Some("os.system")),
            "GLOBAL should resolve the module.attr callable: {globals:?}"
        );
        let danger = v
            .get("pickle.dangerous_opcodes")
            .and_then(|x| x.as_array())
            .unwrap();
        let names: Vec<&str> = danger.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"reduce"));
        assert!(names.contains(&"global"));
    }

    #[test]
    fn surfaces_stack_global() {
        let mut data = vec![0x80, 5, 0x95, 0, 0, 0, 0, 0, 0, 0, 0];
        data.push(0x8C);
        data.push(10);
        data.extend_from_slice(b"subprocess");
        data.push(0x94);
        data.push(0x8C);
        data.push(5);
        data.extend_from_slice(b"Popen");
        data.push(0x94);
        data.push(0x93);
        data.push(b'.');
        let (v, _) = run(&data);
        let mods = v.get("pickle.modules").and_then(|x| x.as_array()).unwrap();
        assert!(mods.iter().any(|v| v.as_str() == Some("subprocess")));
        let globals = v.get("pickle.globals").and_then(|x| x.as_array()).unwrap();
        assert!(
            globals
                .iter()
                .any(|g| g.as_str() == Some("subprocess.Popen")),
            "STACK_GLOBAL should resolve module.attr: {globals:?}"
        );
    }

    #[test]
    fn stack_global_uses_pickle_stack_and_memo_not_recent_strings() {
        let mut data = vec![0x80, 4];
        let short_unicode = |data: &mut Vec<u8>, value: &[u8]| {
            data.extend_from_slice(&[0x8C, value.len() as u8]);
            data.extend_from_slice(value);
        };

        // Memo 0 holds the module. Resolve one class, then discard it.
        short_unicode(&mut data, b"docutils.nodes");
        data.push(0x94);
        short_unicode(&mut data, b"section");
        data.extend_from_slice(&[0x94, 0x93, b'0']);

        // These identifier-shaped document strings used to pollute the
        // rolling string window and produce `section.title`.
        short_unicode(&mut data, b"arbitrary.document.text");
        data.push(b'0');

        // Reload the real module through a LONG_BINGET and resolve the second
        // class. The opcode walker must consume all four index bytes.
        data.extend_from_slice(&[b'j', 0, 0, 0, 0]);
        short_unicode(&mut data, b"title");
        data.extend_from_slice(&[0x93, b'.']);

        let (values, metrics) = run(&data);
        assert_eq!(metrics.get("pickle.protocol"), Some(4.0));
        assert_eq!(
            values.get("pickle.modules"),
            Some(&serde_json::json!(["docutils.nodes"]))
        );
        assert_eq!(
            values.get("pickle.globals"),
            Some(&serde_json::json!([
                "docutils.nodes.section",
                "docutils.nodes.title"
            ]))
        );
    }

    #[test]
    fn torch_legacy_storage_is_not_an_opcode_stream() {
        let bytes = include_bytes!("../testdata/pickle/torch-protocol2-float-tensor.pt");
        let (values, metrics) = run(bytes);
        assert_eq!(metrics.get("pickle.protocol"), Some(2.0));
        assert_eq!(
            values.get("pickle.globals"),
            Some(&serde_json::json!([
                "collections.OrderedDict",
                "torch.FloatStorage",
                "torch._utils._rebuild_tensor_v2"
            ]))
        );
        let ops = values.get("pickle.opcodes").unwrap().as_array().unwrap();
        assert!(!ops.contains(&serde_json::json!("POP")));
        let mut extended = bytes.to_vec();
        extended.extend_from_slice(b"\x80\x29cos\nsystem\nR.");
        assert_eq!(
            serde_json::to_value(run(&extended).0).unwrap(),
            serde_json::to_value(values).unwrap()
        );
    }

    #[test]
    fn raw_bytes_operands_and_trailing_bytes_do_not_declare_globals() {
        let payload = b"\x80\x29cos\nsystem\nR";
        for op in [b'B', b'C', 0x8e] {
            let mut bytes = vec![0x80, 4, op];
            match op {
                b'B' => bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes()),
                b'C' => bytes.push(payload.len() as u8),
                _ => bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes()),
            }
            bytes.extend_from_slice(payload);
            bytes.push(b'.');
            bytes.extend_from_slice(b"cos\nsystem\nR");
            let (values, metrics) = run(&bytes);
            assert_eq!(metrics.get("pickle.protocol"), Some(4.0));
            assert!(values.get("pickle.globals").is_none());
            assert!(values.get("pickle.dangerous_opcodes").is_none());
        }
    }

    #[test]
    fn invalid_proto_and_corrupt_legacy_headers_do_not_scan_storage() {
        let (values, metrics) = run(b"\x80\x29cos\nsystem\nR.");
        assert!(values.get("pickle.globals").is_none());
        assert!(metrics.get("pickle.protocol").is_none());
        let mut bytes =
            include_bytes!("../testdata/pickle/torch-protocol2-float-tensor.pt").to_vec();
        bytes[4] ^= 1;
        assert!(run(&bytes).0.get("pickle.globals").is_none());
        let mut short = vec![0x80, 4, b'B'];
        short.extend_from_slice(&u32::MAX.to_le_bytes());
        short.extend_from_slice(b"cos\nsystem\nR.");
        assert!(run(&short).0.get("pickle.globals").is_none());
    }

    #[test]
    fn empty_is_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("pickle.protocol").is_none());
    }

    #[test]
    fn truncated_length_prefix_doesnt_crash() {
        // SHORT_BINUNICODE with length=10 but only 3 bytes follow.
        let data = vec![0x80, 5, 0x8C, 10, b'a', b'b', b'c'];
        let (_, _) = run(&data);
        // Just confirm no panic.
    }

    #[test]
    fn dangerous_opcodes_recognized() {
        // Protocol 0 GLOBAL+REDUCE — classic RCE pattern.
        let mut data = vec![b'c'];
        data.extend_from_slice(b"subprocess\nPopen\n");
        data.push(b'R');
        data.push(b'.');
        let (v, _) = run(&data);
        let danger = v
            .get("pickle.dangerous_opcodes")
            .and_then(|x| x.as_array())
            .unwrap();
        let names: Vec<&str> = danger.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"global"));
        assert!(names.contains(&"reduce"));
    }

    #[test]
    fn non_pickle_input_is_silent() {
        // Random binary that doesn't match any opcode pattern.
        let (v, _) = run(b"this is some random text that won't match much");
        // It might match a few stray opcodes (chars like '.', 'c'),
        // but should not report a protocol or modules.
        assert!(v.get("pickle.modules").is_none() || v.get("pickle.protocol").is_none());
    }

    #[test]
    fn protocol_5_recognized() {
        // PROTO 5 + STOP.
        let data = vec![0x80, 5, b'.'];
        let (_, m) = run(&data);
        assert_eq!(m.get("pickle.protocol"), Some(5.0));
    }
}
