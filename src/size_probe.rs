//! Cheap questions about a file a scheduler asks before reading it whole:
//! how far a container inflates, and whether a file is a flat image whose
//! memory footprint tracks its own size. Each reads a header or a tail
//! through a seekable reader, never the body.
//!
//! - gzip: the trailer's `ISIZE` (modulo 2^32).
//! - zip: the uncompressed sizes in the central directory.
//! - cab: the sizes in the CFFILE table.
//! - dmg: the sector count in the UDIF `koly` trailer ([`udif_volume_size`]).

use std::io::{Read, Seek, SeekFrom};

/// Most directory entries walked for a hint.
const MAX_ENTRIES: usize = 20_000;

/// What the gzip, zip or cab container in `reader` (`len` bytes long)
/// inflates to. `None` for any other format, an unreadable or truncated
/// one, a zip64 directory, or more entries than are worth walking.
pub fn inflated_size<R: Read + Seek>(reader: &mut R, len: u64) -> Option<u64> {
    if len < 22 {
        return None;
    }
    let mut magic = [0u8; 4];
    reader.seek(SeekFrom::Start(0)).ok()?;
    reader.read_exact(&mut magic).ok()?;
    match magic {
        [0x1f, 0x8b, _, _] => {
            reader.seek(SeekFrom::End(-4)).ok()?;
            let mut trailer = [0u8; 4];
            reader.read_exact(&mut trailer).ok()?;
            Some(u64::from(u32::from_le_bytes(trailer)))
        }
        [b'P', b'K', 3, 4] => zip_inflated_size(reader, len),
        [b'M', b'S', b'C', b'F'] => cab_inflated_size(reader, len),
        _ => None,
    }
}

/// The mounted volume size an Apple disk image (UDIF `.dmg`) declares in its
/// 512-byte `koly` trailer: `sector_count` (big-endian `u64` at trailer
/// offset 492) times 512. `None` when the trailer is absent or truncated.
/// A DMG has no magic at its start, so this reads only the tail of `data`.
#[must_use]
pub fn udif_volume_size(data: &[u8]) -> Option<u64> {
    let trailer = data.get(data.len().checked_sub(512)?..)?;
    if !trailer.starts_with(b"koly") {
        return None;
    }
    let sectors = u64::from_be_bytes(trailer.get(492..500)?.try_into().ok()?);
    sectors.checked_mul(512)
}

/// Whether `magic` (a file's first bytes) opens an executable (PE, ELF,
/// Mach-O, fat Mach-O) or an OLE compound file: an image whose footprint
/// follows its own size rather than an unknown container expansion.
#[must_use]
pub fn is_flat_image(magic: &[u8]) -> bool {
    matches!(
        magic,
        [b'M', b'Z', ..]
            | [0x7f, b'E', b'L', b'F', ..]
            | [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..]
            | [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..]
            | [0xca, 0xfe, 0xba, 0xbe, ..]
            | [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ..]
    )
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        buf.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The sum of a zip central directory's uncompressed sizes.
fn zip_inflated_size<R: Read + Seek>(reader: &mut R, len: u64) -> Option<u64> {
    const EOCD_MIN: u64 = 22;
    let tail_len = len.min(EOCD_MIN + 0xFFFF);
    reader
        .seek(SeekFrom::End(-i64::try_from(tail_len).ok()?))
        .ok()?;
    let mut tail = vec![0u8; usize::try_from(tail_len).ok()?];
    reader.read_exact(&mut tail).ok()?;
    let eocd = tail
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .filter(|&at| at + 22 <= tail.len())?;
    let entries = usize::from(u16_at(&tail, eocd + 10)?);
    let dir_len = u64::from(u32_at(&tail, eocd + 12)?);
    let dir_offset = u64::from(u32_at(&tail, eocd + 16)?);
    if entries == 0 || entries > MAX_ENTRIES || entries == 0xFFFF || dir_offset == 0xFFFF_FFFF {
        return None;
    }
    if dir_offset.checked_add(dir_len)? > len {
        return None;
    }
    reader.seek(SeekFrom::Start(dir_offset)).ok()?;
    let mut dir = vec![0u8; usize::try_from(dir_len).ok()?];
    reader.read_exact(&mut dir).ok()?;
    let mut at = 0usize;
    let mut total = 0u64;
    for _ in 0..entries {
        if dir.get(at..at.checked_add(4)?)? != b"PK\x01\x02" {
            return None;
        }
        let uncompressed = u32_at(&dir, at + 24)?;
        if uncompressed == 0xFFFF_FFFF {
            return None; // zip64
        }
        total = total.saturating_add(u64::from(uncompressed));
        let variable = usize::from(u16_at(&dir, at + 28)?)
            + usize::from(u16_at(&dir, at + 30)?)
            + usize::from(u16_at(&dir, at + 32)?);
        at = at.checked_add(46 + variable)?;
    }
    Some(total)
}

/// The sum of a cabinet's CFFILE sizes. Each CFFILE is `cbFile` (u32),
/// folder offset, folder index, date, time, attributes, then a
/// NUL-terminated name of at most 256 bytes.
fn cab_inflated_size<R: Read + Seek>(reader: &mut R, len: u64) -> Option<u64> {
    const HEADER_LEN: usize = 36;
    const MAX_ENTRY_LEN: usize = 16 + 257;
    reader.seek(SeekFrom::Start(0)).ok()?;
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).ok()?;
    let files_offset = u64::from(u32_at(&header, 16)?);
    let entries = usize::from(u16_at(&header, 28)?);
    if entries == 0 || entries > MAX_ENTRIES || files_offset >= len {
        return None;
    }
    let table_len = (entries * MAX_ENTRY_LEN).min(usize::try_from(len - files_offset).ok()?);
    reader.seek(SeekFrom::Start(files_offset)).ok()?;
    let mut table = vec![0u8; table_len];
    reader.read_exact(&mut table).ok()?;
    let mut at = 0usize;
    let mut total = 0u64;
    for _ in 0..entries {
        total = total.saturating_add(u64::from(u32_at(&table, at)?));
        let name_start = at.checked_add(16)?;
        let name_len = memchr::memchr(0, table.get(name_start..)?)?;
        at = name_start + name_len + 1;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::{Cursor, Write};

    fn probe(bytes: &[u8]) -> Option<u64> {
        inflated_size(&mut Cursor::new(bytes), bytes.len() as u64)
    }

    #[test]
    fn zip_sums_its_central_directory() {
        let mut buf = Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for name in ["a.js", "b.js"] {
            zip.start_file(name, opts).unwrap();
            zip.write_all(&vec![b'x'; 1 << 20]).unwrap();
        }
        zip.finish().unwrap();
        let bytes = buf.into_inner();
        assert!(bytes.len() < 1 << 16);
        assert_eq!(probe(&bytes), Some(2 << 20));
    }

    #[test]
    fn cab_sums_its_file_table() {
        let files_offset: u32 = 36 + 8;
        let mut cab = b"MSCF".to_vec();
        cab.extend_from_slice(&[0; 12]); // reserved1, cbCabinet, reserved2
        cab.extend_from_slice(&files_offset.to_le_bytes());
        cab.extend_from_slice(&[0; 4]); // reserved3
        cab.extend_from_slice(&[3, 1]); // version
        cab.extend_from_slice(&1u16.to_le_bytes()); // cFolders
        cab.extend_from_slice(&2u16.to_le_bytes()); // cFiles
        cab.extend_from_slice(&[0; 6]); // flags, setID, iCabinet
        cab.extend_from_slice(&[0; 8]); // CFFOLDER
        for (size, name) in [(826_355u32, &b"segment.js"[..]), (1_000, &b"b.txt"[..])] {
            cab.extend_from_slice(&size.to_le_bytes());
            cab.extend_from_slice(&[0; 12]);
            cab.extend_from_slice(name);
            cab.push(0);
        }
        cab.extend_from_slice(&[0; 64]);
        assert_eq!(probe(&cab), Some(827_355));
    }

    #[test]
    fn gzip_reads_its_trailer_and_others_are_none() {
        let mut gz = vec![0x1f, 0x8b, 8, 0];
        gz.extend_from_slice(&[0; 20]);
        gz.extend_from_slice(&123_456u32.to_le_bytes());
        assert_eq!(probe(&gz), Some(123_456));
        assert_eq!(probe(&[7u8; 4096]), None);
        assert_eq!(probe(b"PK\x03\x04"), None, "too short to probe");
    }

    #[test]
    fn udif_trailer_declares_the_volume_size() {
        let mut dmg = vec![0u8; 1024];
        let at = dmg.len() - 512;
        dmg[at..at + 4].copy_from_slice(b"koly");
        dmg[at + 492..at + 500].copy_from_slice(&2048u64.to_be_bytes());
        assert_eq!(udif_volume_size(&dmg), Some(2048 * 512));
        assert_eq!(
            udif_volume_size(&dmg[..600]),
            None,
            "trailer not at the end"
        );
        assert_eq!(udif_volume_size(b"koly"), None, "too short for a trailer");
        assert_eq!(udif_volume_size(&[0u8; 1024]), None, "no koly magic");
    }

    #[test]
    fn flat_images() {
        assert!(is_flat_image(b"MZ\x90\0\x03\0\0\0"));
        assert!(is_flat_image(b"\x7fELF\x02\x01\x01\0"));
        assert!(is_flat_image(&[
            0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
        ]));
        assert!(!is_flat_image(b"PK\x03\x04\0\0\0\0"));
    }
}
