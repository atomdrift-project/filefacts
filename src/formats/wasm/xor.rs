//! Statically recover bounded, constant-index XOR loops over active WASM data.
//! This reads instructions and data only; it never instantiates the module.

#[derive(Debug)]
pub(super) struct Decoded {
    pub(super) offset: usize,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn byte(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn unsigned(&mut self) -> Option<u32> {
        let mut n = 0u32;
        for shift in (0..35).step_by(7) {
            let b = self.byte()?;
            if shift == 28 && b & 0xf0 != 0 {
                return None;
            }
            n |= u32::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(n);
            }
        }
        None
    }
    fn signed(&mut self) -> Option<i32> {
        let mut n = 0u32;
        for shift in (0..35).step_by(7) {
            let b = self.byte()?;
            if shift == 28 && !matches!(b & 0x78, 0 | 0x78) {
                return None;
            }
            n |= u32::from(b & 0x7f).wrapping_shl(shift);
            if b & 0x80 == 0 {
                let bits = shift + 7;
                if bits < 32 && b & 0x40 != 0 {
                    n |= u32::MAX << bits;
                }
                return Some(n.cast_signed());
            }
        }
        None
    }
    fn expect(&mut self, want: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(want.len())?;
        if self.bytes.get(self.pos..end)? != want {
            return None;
        }
        self.pos = end;
        Some(())
    }
    fn local(&mut self, op: u8) -> Option<u32> {
        self.expect(&[op])?;
        self.unsigned()
    }
    fn constant(&mut self) -> Option<i32> {
        self.expect(&[0x41])?;
        self.signed()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }
}

struct Segment {
    address: u32,
    offset: usize,
    len: usize,
}
struct Loop {
    address: u32,
    len: usize,
    key: [u8; 4],
}

// loop: for (i=0; i<N; i++) mem[A+i] ^= key >> ((i&3)<<3)
// Require the same counter and identical source/destination addresses.
fn decoder(bytes: &[u8]) -> Option<Loop> {
    let mut r = Reader::new(bytes);
    if r.constant()? != 0 {
        return None;
    }
    let index = r.local(0x21)?;
    r.expect(&[0x03, 0x40])?;
    if r.local(0x20)? != index {
        return None;
    }
    let len = usize::try_from(r.constant()?).ok()?;
    if !(4..=65536).contains(&len) {
        return None;
    }
    r.expect(&[0x49, 0x04, 0x40])?;
    if r.local(0x20)? != index || r.local(0x20)? != index {
        return None;
    }
    let address = u32::try_from(r.constant()?).ok()?;
    r.expect(&[0x6a, 0x2d])?;
    if r.unsigned()? != 0 || r.unsigned()? != 0 {
        return None;
    }
    let key = r.constant()?.to_le_bytes();
    if key == [0; 4] {
        return None;
    }
    if r.local(0x20)? != index || r.constant()? != 3 {
        return None;
    }
    r.expect(&[0x71])?;
    if r.constant()? != 3 {
        return None;
    }
    r.expect(&[0x74, 0x76, 0x73, 0x3a])?;
    if r.unsigned()? != 0 || r.unsigned()? != address {
        return None;
    }
    if r.local(0x20)? != index || r.constant()? != 1 {
        return None;
    }
    r.expect(&[0x6a])?;
    if r.local(0x21)? != index {
        return None;
    }
    r.expect(&[0x0c, 0x01, 0x0b, 0x0b])?;
    Some(Loop { address, len, key })
}

pub(super) fn recover(bytes: &[u8]) -> Vec<Decoded> {
    const LIMIT: usize = 8192;
    const BYTE_LIMIT: usize = 4 << 20;
    if !bytes.starts_with(b"\0asm\x01\0\0\0") {
        return Vec::new();
    }
    let mut r = Reader::new(bytes);
    r.pos = 8;
    let mut code = None;
    let mut segments = Vec::new();
    while let Some(id) = r.byte() {
        let Some(n) = r.unsigned() else {
            break;
        };
        let offset = r.pos;
        let Some(body) = r.take(n as usize) else {
            break;
        };
        if id == 10 && code.is_none() {
            code = Some(body);
        }
        if id != 11 || !segments.is_empty() {
            continue;
        }
        let mut d = Reader::new(body);
        let Some(count) = d
            .unsigned()
            .filter(|n| usize::try_from(*n).is_ok_and(|n| n <= LIMIT))
        else {
            continue;
        };
        for _ in 0..count {
            let Some(flag) = d.unsigned() else {
                break;
            };
            let active = match flag {
                0 => true,
                1 => false,
                2 => {
                    if d.unsigned() == Some(0) {
                        true
                    } else {
                        break;
                    }
                }
                _ => break,
            };
            let address = if active {
                let Some(a) = d.constant().and_then(|a| u32::try_from(a).ok()) else {
                    break;
                };
                if d.expect(&[0x0b]).is_none() {
                    break;
                }
                a
            } else {
                0
            };
            let Some(len) = d.unsigned() else {
                break;
            };
            let data_offset = offset + d.pos;
            if d.take(len as usize).is_none() {
                break;
            }
            if active {
                segments.push(Segment {
                    address,
                    offset: data_offset,
                    len: len as usize,
                });
            }
        }
    }
    let Some(code) = code else {
        return Vec::new();
    };
    let mut c = Reader::new(code);
    let Some(count) = c
        .unsigned()
        .filter(|n| usize::try_from(*n).is_ok_and(|n| n <= LIMIT))
    else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut budget = BYTE_LIMIT;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..count {
        let Some(len) = c.unsigned() else {
            break;
        };
        let Some(body) = c.take(len as usize) else {
            break;
        };
        // Search executable function bodies, never custom/data sections.
        // The complete loop fingerprint binds every operand and iteration.
        // Every decoder loop opens with `i32.const 0`, at least 40 bytes
        // before the body's end.
        let searched = body
            .get(..body.len().saturating_sub(39))
            .unwrap_or_default();
        for p in memchr::memmem::find_iter(searched, &[0x41, 0]) {
            let Some(loop_) = decoder(body.get(p..).unwrap_or_default()) else {
                continue;
            };
            if loop_.len > budget || result.len() >= LIMIT {
                return result;
            }
            let Some((segment, delta)) = segments.iter().find_map(|s| {
                let delta = loop_.address.checked_sub(s.address)? as usize;
                (delta.checked_add(loop_.len)? <= s.len).then_some((s, delta))
            }) else {
                continue;
            };
            let offset = segment.offset + delta;
            if !seen.insert((offset, loop_.len)) {
                continue;
            }
            let Some(data) = bytes.get(offset..offset + loop_.len) else {
                continue;
            };
            let decoded = data
                .iter()
                .zip(loop_.key.iter().cycle())
                .map(|(b, key)| b ^ key)
                .collect();
            budget -= loop_.len;
            result.push(Decoded {
                offset,
                bytes: decoded,
            });
        }
    }
    result
}

#[cfg(test)]
mod tests;
