//! DOS-era x86 without a header: COM programs and FAT boot sectors. The
//! GetPC idioms of position-independent code are in `shellcode`.

use super::{sniff::Sniff, text::contains_ci};
use crate::bytes;

/// Largest image a DOS COM program can occupy: one 64 KiB segment less the PSP.
pub(super) const DOS_COM_MAX_SIZE: usize = 0xFF00;

/// Recognize a standalone FAT12/16/32 volume boot sector. Require the BIOS
/// jump, 0x55AA boot signature, and mutually plausible BPB fields; the final
/// two bytes alone are common in unrelated 512-byte data and are not enough.
pub(super) fn looks_like_fat_boot_sector(data: &[u8]) -> bool {
    let Some(sector) = data.first_chunk::<512>() else {
        return false;
    };
    if !sector.ends_with(&[0x55, 0xAA])
        || !matches!(sector[0], 0xE9 | 0xEB)
        || (sector[0] == 0xEB && sector[2] != 0x90)
    {
        return false;
    }

    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    let sectors_per_cluster = sector[13];
    let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
    let fat_count = sector[16];
    let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
    let media = sector[21];
    let fat_size_16 = u16::from_le_bytes([sector[22], sector[23]]);
    let sectors_per_track = u16::from_le_bytes([sector[24], sector[25]]);
    let heads = u16::from_le_bytes([sector[26], sector[27]]);
    let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
    let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);

    let valid_sector_size = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096);
    let valid_cluster_size = sectors_per_cluster.is_power_of_two() && sectors_per_cluster <= 128;
    let valid_media = media == 0xF0 || media >= 0xF8;
    let has_fat_size = fat_size_16 != 0 || fat_size_32 != 0;
    let has_volume_size = total_sectors_16 != 0 || total_sectors_32 != 0;

    valid_sector_size
        && valid_cluster_size
        && reserved_sectors != 0
        && (1..=4).contains(&fat_count)
        && valid_media
        && has_fat_size
        && has_volume_size
        && (1..=63).contains(&sectors_per_track)
        && heads != 0
}

/// A DOS COM program: no header of its own, so the code has to show it.
/// A body that is not text and calls a DOS service -- `INT 21h` behind an
/// `AH` selector, adjacent or established by bounded decoding from the entry
/// point -- a BIOS disk service followed by bootstrap, or one with the
/// complete shape of a small overwriter. A bare
/// `CD 21` is not enough: two bytes recur in arbitrary binary data.
///
/// The size gate comes first: every unclaimed body of any size is asked, and
/// only one that fits a COM image is worth reading.
pub(super) fn looks_like_dos_com(sniff: &Sniff<'_>) -> bool {
    let data = sniff.data;
    if data.len() > DOS_COM_MAX_SIZE {
        return false;
    }
    let not_text = || sniff.binary_not_source() || std::str::from_utf8(data).is_err();
    // `mov ah, n` or `mov ax, n` immediately before `int 21h`.
    let adjacent_service_call = || {
        data.windows(4).any(|w| matches!(w, [0xB4, _, 0xCD, 0x21]))
            || data
                .windows(5)
                .any(|w| matches!(w, [0xB8, _, _, 0xCD, 0x21]))
    };
    (not_text() && (adjacent_service_call() || has_entry_dos_service_call(data)))
        || looks_like_dos_com_overwriter(data)
}

/// A short DOS overwriter may be mostly zero-padded, so the general binary
/// classifier can treat its bytes as text-like. Require its complete small
/// execution shape before overriding that result: repeated DOS interrupts,
/// DOS termination, and a COM wildcard in the code/data prefix.
fn looks_like_dos_com_overwriter(data: &[u8]) -> bool {
    if !(64..=DOS_COM_MAX_SIZE).contains(&data.len()) {
        return false;
    }
    let prefix = data.get(..256).unwrap_or(data);
    let dos_calls = prefix.windows(2).filter(|w| *w == [0xCD, 0x21]).count();
    dos_calls >= 2
        && prefix.windows(2).any(|w| w == [0xCD, 0x20])
        && contains_ci(prefix, b"*.com\0")
}

/// Follow a bounded 16-bit entry path rather than searching for unrelated
/// selector/interrupt bytes. Track AH across argument setup and segment prefixes;
/// invalidate it on writes, other interrupts and the continuation of a call.
fn has_entry_dos_service_call(data: &[u8]) -> bool {
    use iced_x86::{
        Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
        Register,
    };
    use std::collections::{HashSet, VecDeque};

    let prefix = data.get(..512).unwrap_or(data);
    let mut pending = VecDeque::from([(0usize, None::<u8>, 0u8)]);
    let mut seen = HashSet::new();
    let mut info = InstructionInfoFactory::new();
    for _ in 0..256 {
        let Some((pc, mut ah, age)) = pending.pop_front() else {
            break;
        };
        if pc >= prefix.len() || !seen.insert((pc, ah, age.min(16))) {
            continue;
        }
        if age >= 16 {
            ah = None;
        }
        let Some(code) = prefix.get(pc..) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(16, code, pc as u64 + 0x100, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let next = pc + instruction.len();
        if instruction.mnemonic() == Mnemonic::Int {
            if instruction.immediate8() == 0x21 && ah.is_some_and(|n| (1..=0x6c).contains(&n)) {
                return true;
            }
            // COM utilities can call BIOS services without making a DOS
            // syscall. Keep this tied to the decoded entry path and a known
            // read/write selector, then require the BIOS bootstrap instruction.
            // Recognize reads as well as writes: format identification must
            // not depend on whether the disk operation is destructive.
            if instruction.immediate8() == 0x13
                && matches!(ah, Some(0x02 | 0x03))
                && prefix.get(next..next.saturating_add(2)) == Some(&[0xCD, 0x19])
            {
                return true;
            }
            pending.push_back((next, None, 0));
            continue;
        }
        let mut selected = None;
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
            let immediate = instruction.try_immediate(1).ok();
            selected = match instruction.op0_register() {
                Register::AH => immediate.map(|n| n.to_le_bytes()[0]),
                Register::AX => immediate.map(|n| n.to_le_bytes()[1]),
                _ => None,
            };
        }
        for used in info.info(&instruction).used_registers() {
            if matches!(
                used.register(),
                Register::AH | Register::AX | Register::EAX | Register::RAX
            ) && matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                ah = None;
            }
        }
        let next_age = if let Some(value) = selected {
            ah = Some(value);
            0
        } else {
            age.saturating_add(1)
        };
        let target = || {
            usize::try_from(instruction.near_branch_target())
                .ok()
                .and_then(|n| n.checked_sub(0x100))
                .filter(|n| *n < prefix.len())
        };
        match instruction.flow_control() {
            FlowControl::Next => pending.push_back((next, ah, next_age)),
            FlowControl::ConditionalBranch => {
                pending.push_back((next, ah, next_age));
                if let Some(to) = target() {
                    pending.push_back((to, ah, next_age));
                }
            }
            FlowControl::UnconditionalBranch => {
                if let Some(to) = target() {
                    pending.push_back((to, ah, next_age));
                }
            }
            FlowControl::Call => {
                if let Some(to) = target() {
                    pending.push_back((to, ah, next_age));
                }
                pending.push_back((next, None, 0));
            }
            _ => {}
        }
    }
    false
}

/// Recognize a structurally coherent MZ-format 16-bit DOS executable. MZ is
/// not enough by itself: page geometry, relocation table and CS:IP must all
/// fit. PE/NE and other stronger formats are classified before this fallback.
pub(super) fn looks_like_dos_mz(data: &[u8]) -> bool {
    if data.len() < 32 || !data.starts_with(b"MZ") {
        return false;
    }
    let word = |at| bytes::u16_le(data, at).map(usize::from);
    let (
        Some(tail),
        Some(pages),
        Some(relocations),
        Some(paragraphs),
        Some(ip),
        Some(cs),
        Some(table),
    ) = (
        word(2),
        word(4),
        word(6),
        word(8),
        word(20),
        word(22),
        word(24),
    )
    else {
        return false;
    };
    if pages == 0 || tail > 511 || paragraphs < 2 {
        return false;
    }
    let Some(size) = (pages - 1)
        .checked_mul(512)
        .and_then(|n| n.checked_add(if tail == 0 { 512 } else { tail }))
    else {
        return false;
    };
    let Some(header) = paragraphs.checked_mul(16) else {
        return false;
    };
    let Some(entry) = cs
        .checked_mul(16)
        .and_then(|n| n.checked_add(ip))
        .and_then(|n| n.checked_add(header))
    else {
        return false;
    };
    if size > data.len() || header >= size || entry >= size {
        return false;
    }
    if relocations > 0 {
        let Some(end) = relocations
            .checked_mul(4)
            .and_then(|n| table.checked_add(n))
        else {
            return false;
        };
        if table < 28 || end > header {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests;
