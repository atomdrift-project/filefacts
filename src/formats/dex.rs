//! Bounded DEX method/call facts. Reads bytecode without loading any class.
//! Literal arguments are propagated only within a straight-line basic block;
//! branch targets and unknown writes invalidate their bindings.
use crate::output::{Arg, Literal, Literals, Symbol, Symbols, Values};
use crate::value_key;
use std::collections::{HashMap, HashSet};

fn u16at(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(p..p.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32at(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(p..p.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn uleb(b: &[u8], p: &mut usize) -> Option<u32> {
    let mut v = 0u32;
    for shift in (0..35).step_by(7) {
        let x = *b.get(*p)?;
        *p += 1;
        if shift == 28 && x > 15 {
            return None;
        }
        v |= u32::from(x & 127) << shift;
        if x & 128 == 0 {
            return Some(v);
        }
    }
    None
}
fn table(b: &[u8], header: usize, width: usize, cap: usize) -> Option<(usize, usize)> {
    let n = u32at(b, header)? as usize;
    let p = u32at(b, header + 4)? as usize;
    (n <= cap && p.checked_add(n.checked_mul(width)?)? <= b.len()).then_some((p, n))
}
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
#[derive(Clone)]
struct Method {
    name: String,
    params: Vec<bool>,
    external: bool,
}
struct Dex<'a> {
    bytes: &'a [u8],
    strings: Vec<Option<String>>,
    methods: Vec<Option<Method>>,
    classes: (usize, usize),
}
impl<'a> Dex<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < 112
            || !b.starts_with(b"dex\n")
            || *b.get(7)? != 0
            || u32at(b, 40)? != 0x12345678
        {
            return None;
        }
        let (sp, sn) = table(b, 56, 4, 262144)?;
        let mut strings = Vec::with_capacity(sn);
        let mut string_bytes = 0;
        let mut string_work = 32 * 1024 * 1024usize;
        for i in 0..sn {
            let mut p = u32at(b, sp + i * 4)? as usize;
            let _ = uleb(b, &mut p)?;
            let probe = b.get(p..)?;
            let probe_len = probe.len().min(8193).min(string_work);
            let end = probe.iter().take(probe_len).position(|v| *v == 0);
            string_work -= end.map_or(probe_len, |n| n + 1);
            let text = end.and_then(|n| {
                if n > 8192 || string_bytes + n > 16 * 1024 * 1024 {
                    return None;
                }
                string_bytes += n;
                mutf8(probe.get(..n)?)
            });
            strings.push(text);
        }
        let (tp, tn) = table(b, 64, 4, 65536)?;
        let mut types = Vec::with_capacity(tn);
        for i in 0..tn {
            types.push(u32at(b, tp + i * 4)? as usize);
        }
        let classes = table(b, 96, 32, 65536)?;
        let mut defined = HashSet::new();
        for i in 0..classes.1 {
            defined.insert(u32at(b, classes.0 + i * 32)? as usize);
        }
        let (pp, pn) = table(b, 72, 12, 65536)?;
        let mut protos = Vec::with_capacity(pn);
        for i in 0..pn {
            let off = u32at(b, pp + i * 12 + 8)? as usize;
            let mut params = Vec::new();
            if off != 0 {
                let n = u32at(b, off)? as usize;
                if n > 255 || off.checked_add(4 + n * 2)? > b.len() {
                    return None;
                }
                for j in 0..n {
                    let ti = u16at(b, off + 4 + j * 2)? as usize;
                    let text = types
                        .get(ti)
                        .and_then(|x| strings.get(*x))
                        .and_then(Option::as_deref);
                    params.push(matches!(text, Some("J" | "D")));
                }
            }
            protos.push(params);
        }
        let (mp, mn) = table(b, 88, 8, 65536)?;
        let mut methods = Vec::with_capacity(mn);
        for i in 0..mn {
            let owner = u16at(b, mp + i * 8)? as usize;
            let proto = u16at(b, mp + i * 8 + 2)? as usize;
            let ni = u32at(b, mp + i * 8 + 4)? as usize;
            let method = types
                .get(owner)
                .and_then(|i| strings.get(*i))
                .and_then(Option::as_ref)
                .zip(strings.get(ni).and_then(Option::as_ref))
                .zip(protos.get(proto))
                .map(|((c, n), p)| Method {
                    name: format!("{c}->{n}"),
                    params: p.clone(),
                    external: !defined.contains(&owner),
                });
            methods.push(method);
        }
        Some(Self {
            bytes: b,
            strings,
            methods,
            classes,
        })
    }
}
fn width(code: &[u16], pc: usize) -> Option<usize> {
    let v = *code.get(pc)?;
    let [op, _] = v.to_le_bytes();
    let n = match op {
        0 if v == 0x0100 => 4 + 2 * usize::from(*code.get(pc + 1)?),
        0 if v == 0x0200 => 2 + 4 * usize::from(*code.get(pc + 1)?),
        0 if v == 0x0300 => {
            let size = u32::from(*code.get(pc + 2)?) | (u32::from(*code.get(pc + 3)?) << 16);
            4usize.checked_add(
                usize::from(*code.get(pc + 1)?)
                    .checked_mul(size as usize)?
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
fn relative(pc: usize, off: i32, len: usize) -> Option<usize> {
    let target = pc.checked_add_signed(isize::try_from(off).ok()?)?;
    (target < len).then_some(target)
}
fn pair(code: &[u16], pc: usize) -> Option<i32> {
    Some((u32::from(*code.get(pc)?) | (u32::from(*code.get(pc + 1)?) << 16)).cast_signed())
}
fn targets(code: &[u16]) -> Option<HashSet<usize>> {
    let mut label_budget = 100000usize;
    let mut labels = HashSet::new();
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
        if matches!(op, 0x2b | 0x2c) {
            if let Some(p) = pair(code, pc + 1).and_then(|off| relative(pc, off, code.len())) {
                if let Some(size) = code.get(p + 1).copied() {
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
            }
        }
        pc += n;
    }
    Some(labels)
}
fn inspect(
    d: &Dex<'_>,
    idx: usize,
    off: usize,
    symbols: &mut Symbols,
    literals: &mut Literals,
    literal_budget: &mut usize,
    budget: &mut usize,
) -> Option<()> {
    let method = d.methods.get(idx)?.as_ref()?;
    let count = u32at(d.bytes, off + 12)? as usize;
    if count > 2 * 1024 * 1024 || off.checked_add(16 + count * 2)? > d.bytes.len() {
        return None;
    }
    // Charge the full bytecode walk, including malformed/undecodable code,
    // before allocation and the branch-target prepass.
    if count > *budget {
        *budget = 0;
        return None;
    }
    *budget -= count;
    let code: Vec<u16> = d
        .bytes
        .get(off + 16..off + 16 + count * 2)?
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect();
    let maybe_labels = targets(&code);
    let propagate = maybe_labels.is_some();
    let labels = maybe_labels.unwrap_or_default();
    let mut regs: HashMap<u16, Arg> = HashMap::new();
    let mut pc = 0;
    let mut callees = Vec::new();
    let mut seen = HashSet::new();
    while let Some(n) = width(&code, pc) {
        if !propagate || labels.contains(&pc) {
            regs.clear();
        }
        let v = *code.get(pc)?;
        let [op, _] = v.to_le_bytes();
        let a = v >> 8;
        match op {
            0x12 => {
                let val = i64::from(v.cast_signed() >> 12);
                regs.insert(
                    (v >> 8) & 15,
                    Arg::Number {
                        text: val.to_string(),
                        value: val,
                        radix: 10,
                    },
                );
            }
            0x13 => {
                let val = i64::from(code.get(pc + 1)?.cast_signed());
                regs.insert(
                    a,
                    Arg::Number {
                        text: val.to_string(),
                        value: val,
                        radix: 10,
                    },
                );
            }
            0x14 => {
                let val = i64::from(pair(&code, pc + 1)?);
                regs.insert(
                    a,
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
                if let Some(Some(s)) = d.strings.get(si) {
                    // Record bytecode-referenced constants, never unused string
                    // pool entries. The source location is the const-string site.
                    if s.len() <= *literal_budget && literals.len() < 100000 {
                        *literal_budget -= s.len();
                        literals.push(Literal::new(s.clone(), (off + 16 + pc * 2) as u64));
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
                if let Some(Some(callee)) = d.methods.get(usize::from(*code.get(pc + 1)?)) {
                    if seen.insert(callee.name.clone()) {
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
                    if symbols.len() < 500000 {
                        symbols.push(Symbol::Call {
                            target: Some(callee.name.clone()),
                            args,
                            offset: Some((off + 16 + pc * 2) as u64),
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
        if regs.len() > 256 {
            regs.clear();
        }
        pc += n;
    }
    symbols.push(Symbol::Function {
        name: method.name.clone(),
        offset: Some((off + 16) as u64),
        complexity: None,
        callees,
    });
    Some(())
}
pub(super) fn extract(
    bytes: &[u8],
    symbols: &mut Symbols,
    literals: &mut Literals,
    values: &mut Values,
) {
    let Some(d) = Dex::parse(bytes) else {
        return;
    };
    for (idx, method) in d.methods.iter().enumerate() {
        if let Some(m) = method.as_ref().filter(|m| m.external) {
            symbols.push(Symbol::Import {
                name: m.name.clone(),
                alias: None,
                library: None,
                offset: Some((u32at(bytes, 92).unwrap_or(0) as usize + idx * 8) as u64),
                ordinal: None,
            });
        }
    }
    let mut budget = 8 * 1024 * 1024usize;
    let mut literal_budget = 8 * 1024 * 1024usize;
    let mut class_data_entries = 2 * 1024 * 1024usize;
    for i in 0..d.classes.1 {
        let Some(mut p) = u32at(bytes, d.classes.0 + i * 32 + 24)
            .map(|v| v as usize)
            .filter(|p| *p != 0)
        else {
            continue;
        };
        let Some((sf, inf, dm, vm)) = (|| {
            Some((
                uleb(bytes, &mut p)?,
                uleb(bytes, &mut p)?,
                uleb(bytes, &mut p)?,
                uleb(bytes, &mut p)?,
            ))
        })() else {
            continue;
        };
        if sf.saturating_add(inf) > 65536 || dm.saturating_add(vm) > 65536 {
            continue;
        }
        let entries = (sf + inf + dm + vm) as usize;
        if entries > class_data_entries {
            values.insert_key(
                value_key!("dex.limits"),
                serde_json::json!({"class_data_budget":true}),
            );
            return;
        }
        class_data_entries -= entries;
        let fields_ok =
            (0..sf + inf).all(|_| uleb(bytes, &mut p).is_some() && uleb(bytes, &mut p).is_some());
        if !fields_ok {
            continue;
        }
        for n in [dm, vm] {
            let mut idx = 0usize;
            for _ in 0..n {
                let Some(delta) = uleb(bytes, &mut p) else {
                    break;
                };
                let Some(_access) = uleb(bytes, &mut p) else {
                    break;
                };
                let Some(off) = uleb(bytes, &mut p) else {
                    break;
                };
                let Some(next) = idx.checked_add(delta as usize) else {
                    break;
                };
                idx = next;
                if off != 0 {
                    let _ = inspect(
                        &d,
                        idx,
                        off as usize,
                        symbols,
                        literals,
                        &mut literal_budget,
                        &mut budget,
                    );
                }
                if budget == 0 {
                    values.insert_key(
                        value_key!("dex.limits"),
                        serde_json::json!({"code_unit_budget":true}),
                    );
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observed(code: &[u16], literal_budget: usize) -> (Vec<Symbol>, Literals) {
        let mut bytes = vec![0; 16];
        bytes[12..16].copy_from_slice(&(code.len() as u32).to_le_bytes());
        for unit in code {
            bytes.extend(unit.to_le_bytes());
        }
        let d = Dex {
            bytes: &bytes,
            strings: vec![Some("/data/".to_owned())],
            classes: (0, 0),
            methods: vec![
                Some(Method {
                    name: "LExample;->run".to_owned(),
                    params: vec![],
                    external: false,
                }),
                Some(Method {
                    name: "Landroid/net/wifi/WifiManager;->setWifiEnabled".to_owned(),
                    params: vec![false],
                    external: true,
                }),
                Some(Method {
                    name: "LExample;->remove".to_owned(),
                    params: vec![false],
                    external: false,
                }),
            ],
        };
        let mut result = Symbols::new();
        let mut budget = 1000;
        let mut literals = Literals::new();
        let mut literal_budget = literal_budget;
        inspect(
            &d,
            0,
            0,
            &mut result,
            &mut literals,
            &mut literal_budget,
            &mut budget,
        )
        .unwrap();
        let calls = result
            .iter()
            .filter(|s| matches!(s, Symbol::Call { .. }))
            .cloned()
            .collect();
        (calls, literals)
    }
    fn calls(code: &[u16]) -> Vec<Symbol> {
        observed(code, 8192).0
    }
    #[test]
    fn only_referenced_constants_become_literals() {
        assert!(observed(&[0x000e], 8192).1.is_empty());
        let (_, literals) = observed(&[0x001a, 0, 0x000e], 8192);
        assert_eq!(literals.len(), 1);
        assert_eq!(literals.as_slice()[0].value, "/data/");
        assert_eq!(literals.as_slice()[0].offset, 16);
        assert!(observed(&[0x001a, 0, 0x000e], 2).1.is_empty());
    }
    #[test]
    fn jumbo_string_reference_becomes_literal() {
        let (_, literals) = observed(&[0x001b, 0, 0, 0x000e], 8192);
        assert_eq!(literals.as_slice()[0].value, "/data/");
    }
    #[test]
    fn distinguishes_true_and_false() {
        for value in [0, 1] {
            let out = calls(&[(value << 12) | 0x0112, 0x206e, 1, 0x0010, 0x000e]);
            assert!(
                matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Number{value:v,..} if *v==i64::from(value)))
            );
        }
    }
    #[test]
    fn signed_constants_retain_their_values() {
        for (mut code, expected) in [
            (vec![0x8112], -8),
            (vec![0x7112], 7),
            (vec![0x0113, 0x8000], i64::from(i16::MIN)),
            (vec![0x0113, 0x7fff], i64::from(i16::MAX)),
            (vec![0x0114, 0, 0x8000], i64::from(i32::MIN)),
            (vec![0x0114, 0xffff, 0x7fff], i64::from(i32::MAX)),
        ] {
            code.extend([0x1071, 2, 1, 0x000e]);
            let out = calls(&code);
            assert!(matches!(&out[0], Symbol::Call { args, .. }
                    if matches!(&args[0], Arg::Number { value, .. } if *value == expected)));
        }
    }
    #[test]
    fn branch_offsets_retain_their_sign() {
        for code in [
            vec![0x0128, 0xff28],
            vec![0x0000, 0x0029, 0xffff],
            vec![0x0000, 0x002a, 0xffff, 0xffff],
        ] {
            assert!(targets(&code).unwrap().contains(&0));
        }
        assert_eq!(relative(0, -1, 10), None);
        assert_eq!(relative(5, 5, 10), None);
        assert_eq!(relative(5, -5, 10), Some(0));
        assert_eq!(relative(usize::MAX, 1, usize::MAX), None);
        assert_eq!(
            relative(usize::MAX - 1, -1, usize::MAX),
            Some(usize::MAX - 2)
        );
    }
    #[test]
    fn string_argument_and_moved_register() {
        let out = calls(&[0x001a, 0, 0x0107, 0x1071, 2, 0x0001, 0x000e]);
        assert!(
            matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::String{value} if value=="/data/"))
        );
    }
    #[test]
    fn range_invoke_argument() {
        let out = calls(&[0x011a, 0, 0x0177, 2, 1, 0x000e]);
        assert!(
            matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::String{value} if value=="/data/"))
        );
    }
    #[test]
    fn branch_target_drops_stale_constant() {
        let out = calls(&[0x0112, 0x0038, 2, 0x206e, 1, 0x0010, 0x000e]);
        assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
    }
    #[test]
    fn unknown_write_drops_literal() {
        let out = calls(&[0x011a, 0, 0x0122, 0, 0x0177, 2, 1, 0x000e]);
        assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
    }
    #[test]
    fn unrelated_field_read_preserves_literal() {
        let out = calls(&[0x011a, 0, 0x2054, 0, 0x0177, 2, 1, 0x000e]);
        assert!(
            matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::String{value} if value=="/data/"))
        );
    }
    #[test]
    fn field_destination_discards_literal() {
        let out = calls(&[0x011a, 0, 0x2154, 0, 0x0177, 2, 1, 0x000e]);
        assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
    }
    #[test]
    fn wide_write_discards_second_register() {
        let out = calls(&[0x011a, 0, 0x0016, 0, 0x0177, 2, 1, 0x000e]);
        assert!(matches!(&out[0],Symbol::Call{args,..} if matches!(&args[0],Arg::Expression)));
    }
    #[test]
    fn truncated_instructions_and_headers_do_not_panic() {
        for code in [
            vec![0x1a],
            vec![0x0100],
            vec![0x0300, 0xffff, 0xffff, 0xffff],
            vec![0xff],
        ] {
            assert!(calls(&code).is_empty());
        }
        for n in 0..112 {
            assert!(Dex::parse(&vec![0; n]).is_none());
        }
    }
    #[test]
    fn modified_utf8_retains_nul_and_surrogate_pair() {
        assert_eq!(
            mutf8(b"A\xc0\x80\xed\xa0\xbd\xed\xb8\x80"),
            Some("A\0😀".to_owned())
        );
        assert!(mutf8(b"\xed\xa0\xbd").is_none());
        assert!(mutf8(b"\xc1\x81").is_none());
    }
}
