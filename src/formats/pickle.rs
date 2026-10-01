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

use crate::metric;
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, VecDeque};

use crate::error::Error;
use crate::formats::common::bytes_at::{u32_le, u64_le};
use crate::formats::common::{XorScan, extract_binary_strings, put_str};
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
    extract_binary_strings(bytes, strings, XorScan::No);
    if bytes.is_empty() {
        return Ok(());
    }
    let scan = bytes.get(..MAX_BYTES_SCANNED).unwrap_or(bytes);

    let mut protocol: i32 = -1;
    let mut modules: BTreeSet<String> = BTreeSet::new();
    // Fully-qualified `module.attr` callable references resolved from GLOBAL
    // and STACK_GLOBAL — the actual RCE targets, gated to Python-identifier
    // shape so trait rules can match on e.g. `os.system` / `builtins.exec`.
    let mut globals: BTreeSet<String> = BTreeSet::new();
    let mut opcodes: BTreeSet<&'static str> = BTreeSet::new();
    let mut recent: VecDeque<&str> = VecDeque::with_capacity(RECENT_STRING_CAP);

    let mut i = 0_usize;
    while let Some(&op) = scan.get(i) {
        if let Some(name) = opcode_name(op) {
            opcodes.insert(name);
        }
        apply_side_effects(
            op,
            i,
            scan,
            &mut protocol,
            &mut modules,
            &mut globals,
            &mut recent,
        );
        let Some(frame) = payload_size(op, i, scan) else {
            break;
        };
        i += frame;
    }

    if opcodes.is_empty() && modules.is_empty() && protocol < 0 {
        return Ok(());
    }

    if protocol >= 0 {
        metrics.insert(metric!("pickle.protocol"), f64::from(protocol));
        put_str(values, "pickle.protocol", protocol.to_string());
    }
    if !modules.is_empty() {
        values.insert(
            "pickle.modules",
            JsonValue::Array(modules.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !globals.is_empty() {
        values.insert(
            "pickle.globals",
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
            values.insert("pickle.dangerous_opcodes", JsonValue::Array(dangerous));
        }
        values.insert(
            "pickle.opcodes",
            JsonValue::Array(
                opcodes
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
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
        // `len_value` comes from the file; unchecked, a u64 length wraps the
        // frame to 0 and the caller's scan never advances.
        let frame = len_value.checked_add(1 + len_bytes)?;
        (i.checked_add(frame)? <= scan.len()).then_some(frame)
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
            let len = u32_le(scan, i + 1)? as usize;
            read_len_prefixed(4, len)
        }
        0x8D | 0x96 => {
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

fn apply_side_effects<'a>(
    op: u8,
    i: usize,
    scan: &'a [u8],
    protocol: &mut i32,
    modules: &mut BTreeSet<String>,
    globals: &mut BTreeSet<String>,
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
            // GLOBAL: "module\nattr\n". Record the module and, when both the
            // module and the following attr are identifier-shaped, the
            // fully-qualified `module.attr` callable reference.
            if let Some(m_nl) = scan
                .get(i + 1..)
                .and_then(|s| s.iter().position(|&b| b == b'\n'))
            {
                let module_end = i + 1 + m_nl;
                if let Some(Ok(module)) = scan.get(i + 1..module_end).map(std::str::from_utf8) {
                    if !module.is_empty() {
                        modules.insert(module.to_string());
                    }
                    if let Some(a_nl) = scan
                        .get(module_end + 1..)
                        .and_then(|s| s.iter().position(|&b| b == b'\n'))
                    {
                        let attr_end = module_end + 1 + a_nl;
                        if let Some(Ok(attr)) =
                            scan.get(module_end + 1..attr_end).map(std::str::from_utf8)
                            && is_pickle_ident(module)
                            && is_pickle_ident(attr)
                        {
                            globals.insert(format!("{module}.{attr}"));
                        }
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
            if let Some(len) = u32_le(scan, i + 1) {
                let start = i + 5;
                // `len` is file-controlled; a string past the address space
                // is past the end of the scan, like any truncated one.
                if let Some(slice) = start
                    .checked_add(len as usize)
                    .and_then(|end| scan.get(start..end))
                {
                    if let Ok(s) = std::str::from_utf8(slice) {
                        push_recent(recent, s);
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
                if let Some(&attr) = n.checked_sub(1).and_then(|j| recent.get(j))
                    && is_pickle_ident(module)
                    && is_pickle_ident(attr)
                {
                    globals.insert(format!("{module}.{attr}"));
                }
            }
        }
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
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
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
