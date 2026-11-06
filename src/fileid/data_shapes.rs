//! Known non-text data shapes: headerless binaries that have no file type of
//! their own and no magic to claim them.
//!
//! Each shape is recognised for one reason. Identification reports a body
//! that nothing claims as [`FileType::Unknown`](super::FileType::Unknown),
//! which no analyzer reads, so an unnamed copy of one of these would never be
//! looked at. Recognised, it is [`FileType::Data`](super::FileType::Data) and
//! reaches generic binary analysis. Nothing here asserts behaviour, malicious
//! or otherwise. Every check is structural and bounded; a lone magic word is
//! never enough.

use crate::bytes;

/// Whether `data` has a shape.
type Shape = fn(&[u8]) -> bool;

/// The shapes, each named for the decision log. The first that matches wins;
/// they are disjoint in practice, as each demands its own leading bytes.
const DATA_SHAPES: &[(&str, Shape)] = &[
    // A Commodore 64 PRG has only its load address for a header. Without
    // this, a BASIC `SYS` loader is Unknown.
    ("c64_basic_sys_loader", has_basic_sys_loader),
    // Apple II ProDOS system programs load at $2000 with no header. Without
    // this, a SYS program is Unknown.
    ("prodos_system_code", has_prodos_system_code),
    // A universal ProDOS/SOS boot image. Without this, a boot image is
    // Unknown.
    ("prodos_boot_code", has_prodos_boot_code),
    // Sign of Misery's serialized script header. Without this, a script
    // under any name but its own is Unknown.
    ("sign_of_misery_script", looks_like_sign_of_misery_script),
    // A 16-bit impure Unix a.out image. Its 0407 magic does not name a CPU,
    // so it is generic data. Without this, it is Unknown.
    ("unix_aout16_image", looks_like_aout16_image),
];

/// The name of the first shape `data` has.
pub(super) fn shape_of(data: &[u8]) -> Option<&'static str> {
    DATA_SHAPES
        .iter()
        .find(|(_, matches)| matches(data))
        .map(|&(name, _)| name)
}

/// A Commodore 64 BASIC `SYS` loader: a self-consistent first BASIC line, a
/// literal SYS destination inside the file, and a bounded address range. This
/// is a format hint, not a complete C64 program detector.
fn has_basic_sys_loader(data: &[u8]) -> bool {
    const LOAD: usize = 0x0801;
    if data.len() < 20 || data.len() > 65537 - LOAD || data.get(..2) != Some(&[0x01, 0x08]) {
        return false;
    }
    let (Some(next_line), Some(line_number)) = (bytes::u16_le(data, 2), bytes::u16_le(data, 4))
    else {
        return false;
    };
    let next_line = usize::from(next_line);
    if line_number > 63999 || data.get(6) != Some(&0x9e) {
        return false;
    }
    let mut p = 7;
    while data.get(p) == Some(&b' ') {
        p += 1;
    }
    let start = p;
    let mut entry = 0usize;
    while let Some(b @ b'0'..=b'9') = data.get(p).copied() {
        let Some(v) = entry
            .checked_mul(10)
            .and_then(|v| v.checked_add(usize::from(b - b'0')))
        else {
            return false;
        };
        if v > usize::from(u16::MAX) {
            return false;
        }
        entry = v;
        p += 1;
    }
    if p == start || p - start > 5 {
        return false;
    }
    while data.get(p) == Some(&b' ') {
        p += 1;
    }
    if data.get(p) != Some(&0) {
        return false;
    }
    let Some(expected_next) = LOAD.checked_add(p + 1 - 2) else {
        return false;
    };
    if next_line != expected_next || entry < next_line || entry > next_line + 32 {
        return false;
    }
    let Some(offset) = entry.checked_sub(LOAD).and_then(|n| n.checked_add(2)) else {
        return false;
    };
    data.len().saturating_sub(offset) >= 8
}

/// Headerless Apple II ProDOS system code. A SYS program conventionally loads
/// at $2000; a bounded initial absolute jump into its own bytes and complete
/// ProDOS MLI call records for open, read or write, and close are required.
fn has_prodos_system_code(data: &[u8]) -> bool {
    const LOAD: usize = 0x2000;
    if data.len() < 512 || data.len() > 0x10000 - LOAD || data.first() != Some(&0x4c) {
        return false;
    }
    let Some(target) = bytes::u16_le(data, 1).map(usize::from) else {
        return false;
    };
    if target < LOAD || target >= LOAD + data.len() {
        return false;
    }
    // JSR $BF00 is followed by one command byte and a two-byte pointer.
    let mut open = false;
    let mut close = false;
    let mut io = false;
    for window in data.windows(6) {
        let &[0x20, 0x00, 0xbf, command, lo, hi] = window else {
            continue;
        };
        let pointer = u16::from_le_bytes([lo, hi]);
        if !(0x0200..=0xbfff).contains(&pointer) {
            continue;
        }
        match command {
            0xc8 => open = true,
            0xca | 0xcb => io = true,
            0xcc => close = true,
            _ => {}
        }
    }
    open && io && close
}

/// A two-block universal ProDOS/SOS boot image with its device-loader code
/// and both operating-system names, clean or modified.
fn has_prodos_boot_code(data: &[u8]) -> bool {
    if data.len() != 1024 || data.get(..5) != Some(&[0x01, 0x38, 0xb0, 0x03, 0x4c]) {
        return false;
    }
    let Some(destination) = bytes::u16_le(data, 5) else {
        return false;
    };
    (0x0800..0x0c00).contains(&destination)
        && data.windows(6).any(|w| w == b"PRODOS")
        && data.windows(10).any(|w| w == b"SOS.KERNEL")
        && data
            .windows(6)
            .any(|w| w == [0xa5, 0x60, 0x85, 0x44, 0xa5, 0x61])
}

/// A serialized Sign of Misery script: its magic, the fixed field labels, and
/// a command record in the bounded prefix.
fn looks_like_sign_of_misery_script(data: &[u8]) -> bool {
    const HEADER: &[u8] = b"Program: \0Protection: \0Cracker: \0Group: \0Released: \0";
    const MAGIC: &[u8] = b"\x0a\x01\0\0";
    const RECORD: &[u8] = b"\xff\x93\x01\0\0\0\x7e\0\0\0\0";
    if !data.starts_with(MAGIC) || data.get(8..8 + HEADER.len()) != Some(HEADER) {
        return false;
    }
    // Producers leave the stored length inconsistent, so it is not used as an
    // offset; the command-record prefix is required instead.
    let tail = data
        .get(8 + HEADER.len()..data.len().min(512))
        .unwrap_or_default();
    tail.windows(RECORD.len()).any(|window| window == RECORD)
}

/// A 16-bit impure Unix a.out image (magic 0407) whose text, data and symbol
/// sizes, entry point and flags are consistent with the bytes at hand.
fn looks_like_aout16_image(data: &[u8]) -> bool {
    let word = |at| bytes::u16_le(data, at).map(usize::from);
    let (Some(magic), Some(text), Some(initialized), Some(symbols), Some(entry), Some(flags)) =
        (word(0), word(2), word(4), word(8), word(10), word(14))
    else {
        return false;
    };
    if magic != 0o407
        || flags != 1
        || text < 2
        || !text.is_multiple_of(2)
        || !entry.is_multiple_of(2)
        || entry >= text
    {
        return false;
    }
    let image_size = text + initialized;
    image_size <= 65_536 && 16 + image_size + symbols <= data.len()
}

#[cfg(test)]
mod tests;
