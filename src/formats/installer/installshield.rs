//! InstallShield `ISSetupStream` setup launchers.
//!
//! An InstallShield (2010-2015 era) `Setup.exe` carries everything it
//! installs -- the product `.msi`, transforms, prerequisites, `ISSetup.dll` --
//! in a stream appended to the launcher that starts with `ISSetupStream\0`:
//!
//! ```text
//! header  "ISSetupStream\0"  u16 count  u32 type  26 reserved bytes   (46 bytes)
//! entry   u32 name_len  u32 flags  2 bytes  u32 data_len  8 bytes  u16 unicode
//!         name (name_len bytes, UTF-16LE when `unicode` is set)
//!         data (data_len bytes)
//! ```
//!
//! Entry data with flag `0x2` (as one run) or `0x4` (in 1024-byte blocks) is
//! obfuscated: each byte is nibble-swapped, XORed with a key derived from the
//! entry name (its bytes XORed with `13 35 86 07`), then inverted, the key
//! position restarting with every block. What comes out is usually a zlib
//! stream holding the file itself.
//!
//! The table is read as inert data: every length is checked against the bytes
//! present, the entry count and name length are bounded, and decoding writes
//! at most the caller's limit.

use std::io::{Read, Write};

use crate::bytes::{Endian, Reader, utf16_lossy};
use crate::error::Error;

/// The bytes an `ISSetupStream` starts with.
pub const MAGIC: &[u8] = b"ISSetupStream\0";
/// Most entries read from one stream. Real launchers carry a few dozen.
pub const MAX_ENTRIES: usize = 4096;

/// Bytes before the first entry.
const HEADER_LEN: usize = 46;
/// Longest entry name, in bytes.
const MAX_NAME_LEN: usize = 4096;
/// The key every entry name is XORed with to obfuscate its data.
const NAME_KEY: [u8; 4] = [0x13, 0x35, 0x86, 0x07];
/// Entry flag: the data is obfuscated as one run.
const FLAG_OBFUSCATED: u32 = 0x2;
/// Entry flag: the data is obfuscated in blocks of [`BLOCK_LEN`] bytes.
const FLAG_OBFUSCATED_BLOCKS: u32 = 0x4;
/// Bytes after which the key restarts under [`FLAG_OBFUSCATED_BLOCKS`].
const BLOCK_LEN: usize = 1024;
/// Format label for errors.
const FORMAT: &str = "installshield";

/// One entry of an `ISSetupStream`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// The entry's file name. Archive-chosen: a host writing it to disk must
    /// sanitize it.
    pub name: String,
    /// The entry's flags (`0x2`/`0x4`: obfuscated).
    pub flags: u32,
    /// Where the entry's stored data starts, from the start of the stream.
    pub offset: usize,
    /// Bytes of stored (obfuscated, usually compressed) data.
    pub stored_size: usize,
}

/// The entries an `ISSetupStream` lists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Listing {
    /// Entries in table order, up to the first malformed one.
    pub entries: Vec<Entry>,
    /// The count the header declares.
    pub declared: usize,
    /// Whether every declared entry was read; `false` when the table is
    /// truncated or malformed part-way.
    pub complete: bool,
}

/// Whether `stream` begins with the `ISSetupStream` magic.
pub fn is_stream(stream: &[u8]) -> bool {
    stream.starts_with(MAGIC)
}

/// The entries of the `ISSetupStream` that `stream` starts with. Entries
/// before a malformed one are kept and the listing marked incomplete.
///
/// # Errors
///
/// [`Error::Malformed`] when `stream` lacks the magic, its header is
/// truncated, or it declares more than [`MAX_ENTRIES`] entries.
pub fn entries(stream: &[u8]) -> Result<Listing, Error> {
    if !is_stream(stream) {
        return Err(Error::malformed(FORMAT, "missing ISSetupStream magic"));
    }
    let mut header = Reader::at(stream, MAGIC.len());
    let declared = header
        .u16_le()
        .map(usize::from)
        .ok_or_else(|| Error::malformed(FORMAT, "truncated header"))?;
    if stream.len() < HEADER_LEN {
        return Err(Error::malformed(FORMAT, "truncated header"));
    }
    if declared > MAX_ENTRIES {
        return Err(Error::malformed(
            FORMAT,
            format!("{declared} entries declared, more than {MAX_ENTRIES}"),
        ));
    }
    let mut reader = Reader::at(stream, HEADER_LEN);
    let mut entries = Vec::with_capacity(declared.min(256));
    for index in 0..declared {
        match next_entry(&mut reader) {
            Some(entry) => entries.push(entry),
            None => {
                tracing::debug!(target: "filefacts::installshield", index, declared, "entry table malformed; stopping");
                break;
            }
        }
    }
    let complete = entries.len() == declared;
    Ok(Listing {
        entries,
        declared,
        complete,
    })
}

/// The next entry's header, name and data span, or `None` when the table
/// runs out or an entry is malformed.
fn next_entry(reader: &mut Reader<'_>) -> Option<Entry> {
    let name_len = crate::bytes::sat_usize(reader.u32_le()?);
    let flags = reader.u32_le()?;
    reader.skip(2)?;
    let stored_size = crate::bytes::sat_usize(reader.u32_le()?);
    reader.skip(8)?;
    let unicode = reader.u16_le()? != 0;
    if name_len > MAX_NAME_LEN {
        return None;
    }
    let raw_name = reader.bytes(name_len)?;
    let name = if unicode {
        utf16_lossy(raw_name, Endian::Little)
    } else {
        raw_name.iter().map(|&b| char::from(b)).collect()
    };
    let offset = reader.pos();
    reader.bytes(stored_size)?;
    Some(Entry {
        name,
        flags,
        offset,
        stored_size,
    })
}

/// The data key for an entry named `name`: its characters as bytes (`?` for
/// any outside Latin-1, as the launcher narrows them), each XORed with
/// [`NAME_KEY`].
fn entry_key(name: &str) -> Vec<u8> {
    name.chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .zip(NAME_KEY.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

/// Reads an entry's data with the obfuscation undone.
struct Deobfuscate<'a> {
    data: &'a [u8],
    pos: usize,
    key: Vec<u8>,
    /// Bytes after which the key position restarts.
    block: usize,
}

impl Read for Deobfuscate<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        for (i, (out, &b)) in buf.iter_mut().zip(rest).enumerate() {
            let k = self
                .pos
                .checked_add(i)
                .and_then(|at| at.checked_rem(self.block))
                .and_then(|in_block| in_block.checked_rem(self.key.len()))
                .and_then(|at| self.key.get(at))
                .copied()
                .unwrap_or(0);
            *out = !(k ^ b.rotate_left(4));
        }
        self.pos = self.pos.saturating_add(n);
        Ok(n)
    }
}

/// Whether `head` begins a zlib stream (RFC 1950): deflate, a window of at
/// most 32 KiB, and a header checksum that holds.
fn is_zlib(head: &[u8]) -> bool {
    match head {
        [cmf, flg, ..] => {
            cmf & 0x0F == 8 && cmf >> 4 <= 7 && u16::from_be_bytes([*cmf, *flg]) % 31 == 0
        }
        _ => false,
    }
}

/// Write `entry`'s file -- its data with the obfuscation undone and, when
/// that is a zlib stream, inflated -- to `out`, at most `limit` bytes.
/// Returns the bytes written. `stream` is the slice [`entries`] read `entry`
/// from.
///
/// # Errors
///
/// [`Error::Malformed`] when the entry lies outside `stream`, is obfuscated
/// but unnamed (so has no key), does not inflate, or would expand past
/// `limit`; [`Error::Io`] when `out` fails. `out` may then hold a partial
/// file, which the caller should discard.
pub fn decode_entry(
    stream: &[u8],
    entry: &Entry,
    out: &mut impl Write,
    limit: u64,
) -> Result<u64, Error> {
    let data = entry
        .offset
        .checked_add(entry.stored_size)
        .and_then(|end| stream.get(entry.offset..end))
        .ok_or_else(|| Error::malformed(FORMAT, "entry outside the stream"))?;
    let block = if entry.flags & FLAG_OBFUSCATED_BLOCKS != 0 {
        BLOCK_LEN
    } else if entry.flags & FLAG_OBFUSCATED != 0 {
        usize::MAX
    } else {
        0
    };
    let mut plain: Box<dyn Read + '_> = if block == 0 {
        Box::new(data)
    } else {
        let key = entry_key(&entry.name);
        if key.is_empty() {
            return Err(Error::malformed(FORMAT, "obfuscated entry has no name"));
        }
        Box::new(Deobfuscate {
            data,
            pos: 0,
            key,
            block,
        })
    };
    let mut head = [0u8; 2];
    let head_len = read_up_to(&mut plain, &mut head);
    let head = head.get(..head_len).unwrap_or_default();
    let zlib = is_zlib(head);
    let mut body: Box<dyn Read + '_> = Box::new(head.chain(plain));
    if zlib {
        body = Box::new(flate2::read::ZlibDecoder::new(body));
    }
    let written = std::io::copy(&mut body.take(limit.saturating_add(1)), out).map_err(|e| {
        if zlib {
            Error::malformed_with_source(FORMAT, "entry does not inflate", e)
        } else {
            Error::Io {
                path: None,
                source: e,
            }
        }
    })?;
    if written > limit {
        return Err(Error::malformed(
            FORMAT,
            format!("entry expands past its {limit}-byte limit"),
        ));
    }
    Ok(written)
}

/// Fill as much of `buf` as `reader` yields, returning the bytes read.
/// Reading undone data cannot fail.
fn read_up_to(reader: &mut dyn Read, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match reader.read(rest) {
            Ok(0) | Err(_) => break,
            Ok(n) => filled = filled.saturating_add(n),
        }
    }
    filled
}

/// The offset of the first `ISSetupStream` in `data` whose header and
/// entries parse. The launcher's own code names the magic too, so a bare
/// match is not enough. A stream whose whole table reads wins over one that breaks off.
pub(crate) fn find(data: &[u8]) -> Option<usize> {
    let mut partial = None;
    for at in memchr::memmem::find_iter(data, MAGIC) {
        let Some(listing) = data.get(at..).and_then(|stream| entries(stream).ok()) else {
            continue;
        };
        if listing.entries.is_empty() {
            continue;
        }
        if listing.complete {
            return Some(at);
        }
        partial.get_or_insert(at);
    }
    partial
}

#[cfg(test)]
mod tests;
