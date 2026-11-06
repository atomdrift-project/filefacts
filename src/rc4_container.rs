//! Bounded RC4 recovery qualified by complete DEX or ZIP integrity checks.
//! Keys are supplied by the caller; no code, script or recovered payload runs.
use sha1::{Digest, Sha1};
use std::io::{self, Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::bytes::{sat_usize, u16_le, u32_le};
use crate::formats::bounded::{OnError, inflate_capped};

/// Maximum ciphertext retained for one code-container candidate.
pub const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_EXPANDED: u64 = 16 * 1024 * 1024;
const MAX_MEMBERS: usize = 128;
/// A ZIP end-of-central-directory record, without its trailing comment.
const EOCD_LEN: usize = 22;
/// Bytes a ZIP's end-of-central-directory record may sit before the end:
/// the record plus the largest comment.
const EOCD_SEARCH: usize = EOCD_LEN + 65_535;
/// A classic DEX header, whose `header_size` field must say so.
const DEX_HEADER_LEN: u32 = 112;
/// A little-endian DEX's `endian_tag`.
const DEX_ENDIAN_CONSTANT: u32 = 0x1234_5678;
/// Bytes hashed or decoded between cancellation checks.
const CANCEL_CHECK_BLOCK: usize = 64 * 1024;

/// Validated recovered code-container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A classic DEX file with complete checksum validation.
    Dex,
    /// A CRC-checked ZIP containing at least one validated DEX.
    Zip,
}

/// Decoded bytes after complete format integrity checks.
#[derive(Debug)]
pub struct Recovery {
    /// Complete decoded code-container bytes.
    pub data: Vec<u8>,
    /// Format established by integrity validation.
    pub kind: Kind,
}

struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

#[expect(
    clippy::indexing_slicing,
    reason = "every index is a `u8` widened to `usize`, so it is always inside the 256-entry state"
)]
impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut state: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or_default());
        let mut j = 0u8;
        for (i, &k) in (0..=255u8).zip(key.iter().cycle()) {
            j = j.wrapping_add(state[usize::from(i)]).wrapping_add(k);
            state.swap(usize::from(i), usize::from(j));
        }
        Self { state, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let k = self.state[usize::from(self.i)].wrapping_add(self.state[usize::from(self.j)]);
            *byte ^= self.state[usize::from(k)];
        }
    }
}

fn dex_magic(data: &[u8]) -> bool {
    matches!(
        data.first_chunk::<8>(),
        Some(
            [b'd', b'e', b'x', b'\n', b'0', b'3', b'5'..=b'9', 0]
                | [b'd', b'e', b'x', b'\n', b'0', b'4', b'0', 0]
        )
    )
}

/// A reader that fails once `cancelled` says so, so a long bounded read
/// stops between blocks.
struct Cancellable<R, F> {
    inner: R,
    cancelled: F,
}

impl<R: Read, F: Fn() -> bool> Read for Cancellable<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if (self.cancelled)() {
            return Err(io::Error::other("cancelled"));
        }
        self.inner.read(buf)
    }
}

fn valid_dex(data: &[u8], cancelled: &impl Fn() -> bool) -> bool {
    let (Some(digest), Some(hashed), Some(summed)) =
        (data.get(12..32), data.get(32..), data.get(12..))
    else {
        return false;
    };
    if data.len() < DEX_HEADER_LEN as usize
        || !dex_magic(data)
        || u32_le(data, 32) != u32::try_from(data.len()).ok()
        || u32_le(data, 36) != Some(DEX_HEADER_LEN)
        || u32_le(data, 40) != Some(DEX_ENDIAN_CONSTANT)
    {
        return false;
    }
    let mut hash = Sha1::new();
    for chunk in hashed.chunks(CANCEL_CHECK_BLOCK) {
        if cancelled() {
            return false;
        }
        hash.update(chunk);
    }
    if hash.finalize().as_slice() != digest {
        return false;
    }
    let (mut a, mut b) = (1u32, 0u32);
    // zlib's 5552-byte bound prevents either sum overflowing u32.
    for chunk in summed.chunks(5552) {
        if cancelled() {
            return false;
        }
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    u32_le(data, 8) == Some((b << 16) | a)
}

fn valid_zip(data: &[u8], cancelled: &impl Fn() -> bool) -> bool {
    // Bound the directory count before allowing the ZIP parser to allocate.
    // ZIP64 and multidisk layouts are outside this recovery heuristic.
    let start = data.len().saturating_sub(EOCD_SEARCH);
    let Some(eocd) = data
        .get(start..)
        .and_then(|tail| tail.windows(4).rposition(|v| v == b"PK\x05\x06"))
        .map(|offset| start + offset)
    else {
        return false;
    };
    let Some(tail) = data.get(eocd..eocd + EOCD_LEN) else {
        return false;
    };
    let word = |offset| u16_le(tail, offset).map_or(usize::MAX, usize::from);
    let count = word(10);
    if word(4) != 0
        || word(6) != 0
        || word(8) != count
        || count == 0
        || count > MAX_MEMBERS
        || eocd + EOCD_LEN + word(20) != data.len()
    {
        return false;
    }
    let Some(directory_end) = u32_le(tail, 16)
        .zip(u32_le(tail, 12))
        .and_then(|(offset, size)| sat_usize(offset).checked_add(sat_usize(size)))
    else {
        return false;
    };
    if directory_end > eocd {
        return false;
    }
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    if archive.len() != count {
        return false;
    }
    let mut remaining = MAX_EXPANDED;
    let mut has_dex = false;
    for i in 0..archive.len() {
        if cancelled() {
            return false;
        }
        let Ok(entry) = archive.by_index(i) else {
            return false;
        };
        if entry.encrypted()
            || entry.size() > remaining
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return false;
        }
        let declared = entry.size();
        // Reading through EOF makes the ZIP reader check the member CRC.
        let reader = Cancellable {
            inner: entry,
            cancelled,
        };
        let Ok(member) = inflate_capped(reader, remaining, OnError::Discard) else {
            return false;
        };
        if member.truncated || member.bytes.len() as u64 != declared {
            return false;
        }
        remaining -= declared;
        if dex_magic(&member.bytes) {
            if !valid_dex(&member.bytes, cancelled) {
                return false;
            }
            has_dex = true;
        }
    }
    has_dex
}

/// Try one supplied RC4 key. A cheap header probe precedes full decoding.
/// Accept only classic DEX 035–040 with SHA-1/Adler-32 checks, or a bounded
/// ZIP whose every member passes size/CRC checks and contains such a DEX.
/// A successful decode proves recoverable contents, not malicious intent or
/// that the application's runtime uses this particular key/payload pairing.
///
/// `cancellation`, as with [`crate::OpenOptions::cancellation`], stops the
/// attempt early with `None` once it is set.
pub fn recover(data: &[u8], key: &[u8], cancellation: Option<&AtomicBool>) -> Option<Recovery> {
    recover_until(data, key, || {
        cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
    })
}

/// [`recover`], polling `cancelled` between its stages.
fn recover_until(data: &[u8], key: &[u8], cancelled: impl Fn() -> bool) -> Option<Recovery> {
    if data.len() > MAX_INPUT || !(1..=64).contains(&key.len()) || cancelled() {
        return None;
    }
    let mut prefix = *data.first_chunk::<32>()?;
    Rc4::new(key).apply(&mut prefix);
    let kind = if dex_magic(&prefix) {
        Kind::Dex
    } else if prefix.starts_with(b"PK\x03\x04") {
        Kind::Zip
    } else {
        return None;
    };
    let mut decoded = data.to_vec();
    let mut cipher = Rc4::new(key);
    for chunk in decoded.chunks_mut(CANCEL_CHECK_BLOCK) {
        if cancelled() {
            return None;
        }
        cipher.apply(chunk);
    }
    let valid = match kind {
        Kind::Dex => valid_dex(&decoded, &cancelled),
        Kind::Zip => valid_zip(&decoded, &cancelled),
    };
    valid.then_some(Recovery {
        data: decoded,
        kind,
    })
}

#[cfg(test)]
mod tests;
