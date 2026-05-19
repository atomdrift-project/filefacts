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
//!   from the recent-strings ring buffer for STACK_GLOBAL.
//! - `pickle.opcodes[]` — sorted set of opcode names seen.
//! - `pickle.dangerous_opcodes[]` — Pike-style flag array of
//!   the canonical-RCE opcode family (`reduce`, `build`, `inst`,
//!   `obj`, `newobj`, `newobj_ex`, `stack_global`, `global`,
//!   `persid`, `binpersid`, `ext1`, `ext2`, `ext4`).

use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeSet, VecDeque};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str};
use crate::output::{Metrics, Strings, Values};

/// Cap on opcode-stream bytes scanned. Real malicious payloads are
/// tiny; the cap guards against pathological model files
/// (multi-GB joblib/pytorch).
const MAX_BYTES_SCANNED: usize = 8 * 1024 * 1024;
const RECENT_STRING_CAP: usize = 16;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);
    if bytes.is_empty() {
        return Ok(());
    }
    let scan = &bytes[..bytes.len().min(MAX_BYTES_SCANNED)];

    let mut protocol: i32 = -1;
    let mut modules: BTreeSet<String> = BTreeSet::new();
    let mut opcodes: BTreeSet<&'static str> = BTreeSet::new();
    let mut recent: VecDeque<&str> = VecDeque::with_capacity(RECENT_STRING_CAP);

    let mut i = 0_usize;
    while i < scan.len() {
        let op = scan[i];
        if let Some(name) = OPCODE_NAMES[op as usize] {
            opcodes.insert(name);
        }
        apply_side_effects(op, i, scan, &mut protocol, &mut modules, &mut recent);
        let Some(frame) = payload_size(op, i, scan) else {
            break;
        };
        i += frame;
    }

    if opcodes.is_empty() && modules.is_empty() && protocol < 0 {
        return Ok(());
    }

    if protocol >= 0 {
        metrics.insert("pickle.protocol", f64::from(protocol));
        put_str(values, "pickle.protocol", protocol.to_string());
    }
    if !modules.is_empty() {
        values.insert(
            "pickle.modules",
            JsonValue::Array(modules.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !opcodes.is_empty() {
        let dangerous: Vec<JsonValue> = opcodes
            .iter()
            .filter(|name| is_dangerous(name))
            .map(|name| JsonValue::String(name.to_ascii_lowercase()))
            .collect();
        if !dangerous.is_empty() {
            values.insert("pickle.dangerous_opcodes", JsonValue::Array(dangerous));
        }
        values.insert(
            "pickle.opcodes",
            JsonValue::Array(opcodes.into_iter().map(|s| JsonValue::String(s.into())).collect()),
        );
    }

    Ok(())
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
        let frame = 1 + len_bytes + len_value;
        if i + frame > scan.len() {
            None
        } else {
            Some(frame)
        }
    };
    match op {
        0x80 | b'K' | 0x82 | b'h' | b'q' => Some(2),
        0x83 | b'M' => Some(3),
        0x84 | b'J' | b'r' => Some(5),
        b'G' | 0x95 => Some(9),
        b'I' | b'L' | b'F' | b'V' | b'S' | b'g' | b'p' => read_until_newline(),
        b'c' | b'i' => {
            let m_nl = scan.get(i + 1..)?.iter().position(|&b| b == b'\n')?;
            let attr_start = i + 2 + m_nl;
            let a_nl = scan.get(attr_start..)?.iter().position(|&b| b == b'\n')?;
            Some((attr_start + a_nl + 1) - i)
        }
        0x8A | 0x8C | b'U' => {
            let len = *scan.get(i + 1)? as usize;
            read_len_prefixed(1, len)
        }
        0x8B | b'X' | b'T' => {
            let bytes = scan.get(i + 1..i + 5)?.try_into().ok()?;
            let len = u32::from_le_bytes(bytes) as usize;
            read_len_prefixed(4, len)
        }
        0x8D | 0x96 => {
            let bytes = scan.get(i + 1..i + 9)?.try_into().ok()?;
            let len = u64::from_le_bytes(bytes) as usize;
            read_len_prefixed(8, len)
        }
        _ => Some(1),
    }
}

fn apply_side_effects<'a>(
    op: u8,
    i: usize,
    scan: &'a [u8],
    protocol: &mut i32,
    modules: &mut BTreeSet<String>,
    recent: &mut VecDeque<&'a str>,
) {
    let push_recent = |rs: &mut VecDeque<&'a str>, s: &'a str| {
        if rs.len() == RECENT_STRING_CAP {
            rs.pop_front();
        }
        rs.push_back(s);
    };
    match op {
        0x80 => {
            if let Some(&p) = scan.get(i + 1) {
                *protocol = i32::from(p);
            }
        }
        b'c' => {
            if let Some(nl) = scan.get(i + 1..).and_then(|s| s.iter().position(|&b| b == b'\n')) {
                if let Ok(module) = std::str::from_utf8(&scan[i + 1..i + 1 + nl]) {
                    if !module.is_empty() {
                        modules.insert(module.to_string());
                    }
                }
            }
        }
        0x8C => {
            if let Some(&len) = scan.get(i + 1) {
                let start = i + 2;
                let end = start + len as usize;
                if let Some(slice) = scan.get(start..end) {
                    if let Ok(s) = std::str::from_utf8(slice) {
                        push_recent(recent, s);
                    }
                }
            }
        }
        b'X' => {
            if let Some(bytes) = scan.get(i + 1..i + 5) {
                if let Ok(arr) = bytes.try_into() {
                    let len = u32::from_le_bytes(arr) as usize;
                    let start = i + 5;
                    let end = start + len;
                    if let Some(slice) = scan.get(start..end) {
                        if let Ok(s) = std::str::from_utf8(slice) {
                            push_recent(recent, s);
                        }
                    }
                }
            }
        }
        0x93 => {
            // STACK_GLOBAL: the most recent two recorded strings
            // are typically (module, attr) for protocol 4+.
            let n = recent.len();
            if let Some(&module) = n.checked_sub(2).and_then(|j| recent.get(j)) {
                if !module.is_empty() {
                    modules.insert(module.to_string());
                }
            }
        }
        _ => {}
    }
}

const OPCODE_NAMES: [Option<&'static str>; 256] = {
    let mut t: [Option<&'static str>; 256] = [None; 256];
    t[b'(' as usize] = Some("MARK");
    t[b'.' as usize] = Some("STOP");
    t[b'0' as usize] = Some("POP");
    t[b'1' as usize] = Some("POP_MARK");
    t[b'2' as usize] = Some("DUP");
    t[b'F' as usize] = Some("FLOAT");
    t[b'I' as usize] = Some("INT");
    t[b'J' as usize] = Some("BININT");
    t[b'K' as usize] = Some("BININT1");
    t[b'L' as usize] = Some("LONG");
    t[b'M' as usize] = Some("BININT2");
    t[b'N' as usize] = Some("NONE");
    t[b'P' as usize] = Some("PERSID");
    t[b'Q' as usize] = Some("BINPERSID");
    t[b'R' as usize] = Some("REDUCE");
    t[b'S' as usize] = Some("STRING");
    t[b'T' as usize] = Some("BINSTRING");
    t[b'U' as usize] = Some("SHORT_BINSTRING");
    t[b'V' as usize] = Some("UNICODE");
    t[b'X' as usize] = Some("BINUNICODE");
    t[b'a' as usize] = Some("APPEND");
    t[b'b' as usize] = Some("BUILD");
    t[b'c' as usize] = Some("GLOBAL");
    t[b'd' as usize] = Some("DICT");
    t[b'}' as usize] = Some("EMPTY_DICT");
    t[b'e' as usize] = Some("APPENDS");
    t[b'g' as usize] = Some("GET");
    t[b'h' as usize] = Some("BINGET");
    t[b'i' as usize] = Some("INST");
    t[b'j' as usize] = Some("LONG_BINGET");
    t[b'l' as usize] = Some("LIST");
    t[b']' as usize] = Some("EMPTY_LIST");
    t[b'o' as usize] = Some("OBJ");
    t[b'p' as usize] = Some("PUT");
    t[b'q' as usize] = Some("BINPUT");
    t[b'r' as usize] = Some("LONG_BINPUT");
    t[b's' as usize] = Some("SETITEM");
    t[b't' as usize] = Some("TUPLE");
    t[b')' as usize] = Some("EMPTY_TUPLE");
    t[b'u' as usize] = Some("SETITEMS");
    t[b'G' as usize] = Some("BINFLOAT");
    t[0x80] = Some("PROTO");
    t[0x81] = Some("NEWOBJ");
    t[0x82] = Some("EXT1");
    t[0x83] = Some("EXT2");
    t[0x84] = Some("EXT4");
    t[0x85] = Some("TUPLE1");
    t[0x86] = Some("TUPLE2");
    t[0x87] = Some("TUPLE3");
    t[0x88] = Some("NEWTRUE");
    t[0x89] = Some("NEWFALSE");
    t[0x8A] = Some("LONG1");
    t[0x8B] = Some("LONG4");
    t[0x8C] = Some("SHORT_BINUNICODE");
    t[0x8D] = Some("BINUNICODE8");
    t[0x8E] = Some("BINBYTES8");
    t[0x8F] = Some("EMPTY_SET");
    t[0x90] = Some("ADDITEMS");
    t[0x91] = Some("FROZENSET");
    t[0x92] = Some("NEWOBJ_EX");
    t[0x93] = Some("STACK_GLOBAL");
    t[0x94] = Some("MEMOIZE");
    t[0x95] = Some("FRAME");
    t[0x96] = Some("BYTEARRAY8");
    t[0x97] = Some("NEXT_BUFFER");
    t[0x98] = Some("READONLY_BUFFER");
    t
};

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
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
    }

    #[test]
    fn empty_is_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("pickle.protocol").is_none());
    }
}
