//! Bounded RC4 recovery qualified by complete DEX or ZIP integrity checks.
//! Keys are supplied by the caller; no code, script or recovered payload runs.
// Indices below are bounded by fixed RC4 state sizes or validated input lengths.
#![allow(clippy::indexing_slicing)]
use sha1::{Digest, Sha1};
use std::io::{Cursor, Read};

/// Maximum ciphertext retained for one code-container candidate.
pub const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_EXPANDED: u64 = 16 * 1024 * 1024;
const MAX_MEMBERS: usize = 128;

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
    i: usize,
    j: usize,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut state = std::array::from_fn(|i| u8::try_from(i).unwrap_or_default());
        let mut j = 0;
        for i in 0..256 {
            j = (j + state[i] as usize + key[i % key.len()] as usize) & 255;
            state.swap(i, j);
        }
        Self { state, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = (self.i + 1) & 255;
            self.j = (self.j + self.state[self.i] as usize) & 255;
            self.state.swap(self.i, self.j);
            *byte ^= self.state[(self.state[self.i] as usize + self.state[self.j] as usize) & 255];
        }
    }
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn dex_magic(data: &[u8]) -> bool {
    data.len() >= 8
        && &data[..4] == b"dex\n"
        && data[7] == 0
        && matches!(
            &data[4..7],
            b"035" | b"036" | b"037" | b"038" | b"039" | b"040"
        )
}

fn valid_dex(data: &[u8], cancelled: &impl Fn() -> bool) -> bool {
    if data.len() < 112
        || !dex_magic(data)
        || u32_at(data, 32) != u32::try_from(data.len()).ok()
        || u32_at(data, 36) != Some(112)
        || u32_at(data, 40) != Some(0x12345678)
    {
        return false;
    }
    let mut hash = Sha1::new();
    for chunk in data[32..].chunks(65536) {
        if cancelled() {
            return false;
        }
        hash.update(chunk);
    }
    if hash.finalize().as_slice() != &data[12..32] {
        return false;
    }
    let (mut a, mut b) = (1u32, 0u32);
    // zlib's 5552-byte bound prevents either sum overflowing u32.
    for chunk in data[12..].chunks(5552) {
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
    u32_at(data, 8) == Some((b << 16) | a)
}

fn valid_zip(data: &[u8], cancelled: &impl Fn() -> bool) -> bool {
    // Bound the directory count before allowing the ZIP parser to allocate.
    // ZIP64 and multidisk layouts are outside this recovery heuristic.
    let start = data.len().saturating_sub(65557);
    let Some(eocd) = data[start..]
        .windows(4)
        .rposition(|v| v == b"PK\x05\x06")
        .map(|offset| start + offset)
    else {
        return false;
    };
    let Some(tail) = data.get(eocd..eocd + 22) else {
        return false;
    };
    let word = |offset| u16::from_le_bytes([tail[offset], tail[offset + 1]]);
    let count = word(10) as usize;
    if word(4) != 0
        || word(6) != 0
        || word(8) as usize != count
        || count == 0
        || count > MAX_MEMBERS
        || eocd + 22 + word(20) as usize != data.len()
    {
        return false;
    }
    let Some(directory_end) = u32_at(tail, 16)
        .zip(u32_at(tail, 12))
        .and_then(|(offset, size)| (offset as usize).checked_add(size as usize))
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
        let Ok(mut entry) = archive.by_index(i) else {
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
        let mut bytes = Vec::with_capacity(declared.min(1024 * 1024) as usize);
        // Reading through EOF makes the ZIP reader check the member CRC.
        // Check cancellation between bounded reads rather than one read_to_end.
        let mut block = vec![0u8; 65536];
        loop {
            if cancelled() {
                return false;
            }
            let Ok(n) = entry.read(&mut block) else {
                return false;
            };
            if n == 0 {
                break;
            }
            if bytes.len() as u64 + n as u64 > remaining {
                return false;
            }
            bytes.extend_from_slice(&block[..n]);
        }
        if bytes.len() as u64 != declared {
            return false;
        }
        remaining -= bytes.len() as u64;
        if dex_magic(&bytes) {
            if !valid_dex(&bytes, cancelled) {
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
pub fn recover(data: &[u8], key: &[u8], cancelled: impl Fn() -> bool) -> Option<Recovery> {
    if !(32..=MAX_INPUT).contains(&data.len()) || !(1..=64).contains(&key.len()) || cancelled() {
        return None;
    }
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&data[..32]);
    Rc4::new(key).apply(&mut prefix);
    let kind = if dex_magic(&prefix) {
        Kind::Dex
    } else if &prefix[..4] == b"PK\x03\x04" {
        Kind::Zip
    } else {
        return None;
    };
    let mut decoded = data.to_vec();
    let mut cipher = Rc4::new(key);
    for chunk in decoded.chunks_mut(65536) {
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dex() -> Vec<u8> {
        let mut bytes = vec![0u8; 112];
        bytes[..8].copy_from_slice(b"dex\n035\0");
        bytes[32..36].copy_from_slice(&112u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        let hash = Sha1::digest(&bytes[32..]);
        bytes[12..32].copy_from_slice(&hash);
        let (mut a, mut b) = (1u32, 0u32);
        for byte in &bytes[12..] {
            a = (a + u32::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        bytes[8..12].copy_from_slice(&((b << 16) | a).to_le_bytes());
        bytes
    }

    fn apply(data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut bytes = data.to_vec();
        Rc4::new(key).apply(&mut bytes);
        bytes
    }

    fn archive(dex: Option<&[u8]>) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("notes.txt", options).unwrap();
        writer.write_all(b"benign control").unwrap();
        if let Some(dex) = dex {
            writer.start_file("renamed-component.bin", options).unwrap();
            writer.write_all(dex).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn standard_rc4_vector() {
        assert_eq!(
            apply(b"Plaintext", b"Key"),
            [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
        );
    }

    #[test]
    fn recovers_dex_with_varied_keys_and_checks_both_digests() {
        for key in [b"x".as_slice(), b"changed-key", "密钥".as_bytes(), b"a\0b"] {
            let data = dex();
            let recovered = recover(&apply(&data, key), key, || false).unwrap();
            assert_eq!(recovered.kind, Kind::Dex);
            assert_eq!(recovered.data, data);
        }
        for at in [8, 12, 44] {
            let mut bad = dex();
            bad[at] ^= 1;
            assert!(recover(&apply(&bad, b"k"), b"k", || false).is_none());
        }
    }

    #[test]
    fn recovers_zip_with_renamed_dex_and_requires_dex_contents() {
        let zip = archive(Some(&dex()));
        let result = recover(&apply(&zip, b"new-key"), b"new-key", || false).unwrap();
        assert_eq!(result.kind, Kind::Zip);
        assert_eq!(result.data, zip);
        assert!(recover(&apply(&archive(None), b"k"), b"k", || false).is_none());
    }

    #[test]
    fn rejects_wrong_key_truncation_and_invalid_zip_crc() {
        let zip = archive(Some(&dex()));
        let encrypted = apply(&zip, b"new-key");
        assert!(recover(&encrypted, b"wrong-key", || false).is_none());
        assert!(recover(&encrypted[..encrypted.len() - 1], b"new-key", || false).is_none());
        let mut bad = zip;
        let cd = bad.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
        bad[cd + 16] ^= 1;
        assert!(recover(&apply(&bad, b"k"), b"k", || false).is_none());
    }

    #[test]
    fn rejects_invalid_inner_dex_and_declared_expansion_budget() {
        let mut bad_dex = dex();
        bad_dex[12] ^= 1;
        assert!(recover(&apply(&archive(Some(&bad_dex)), b"k"), b"k", || false).is_none());
        let mut zip = archive(Some(&dex()));
        let cd = zip.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
        zip[cd + 24..cd + 28].copy_from_slice(&(MAX_EXPANDED as u32 + 1).to_le_bytes());
        assert!(recover(&apply(&zip, b"k"), b"k", || false).is_none());
    }

    #[test]
    fn rejects_encrypted_members_and_excessive_directory_count() {
        let mut zip = archive(Some(&dex()));
        let cd = zip.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
        zip[cd + 8] |= 1;
        assert!(recover(&apply(&zip, b"k"), b"k", || false).is_none());
        let mut zip = archive(Some(&dex()));
        let eocd = zip.windows(4).rposition(|v| v == b"PK\x05\x06").unwrap();
        for at in [eocd + 8, eocd + 10] {
            zip[at..at + 2].copy_from_slice(&129u16.to_le_bytes());
        }
        assert!(recover(&apply(&zip, b"k"), b"k", || false).is_none());
    }

    #[test]
    fn enforces_input_key_and_cancellation_limits() {
        let data = apply(&dex(), b"k");
        assert!(recover(&data, b"", || false).is_none());
        assert!(recover(&data, &[1; 65], || false).is_none());
        assert!(recover(&data[..31], b"k", || false).is_none());
        assert!(recover(&vec![0; MAX_INPUT + 1], b"k", || false).is_none());
        assert!(recover(&data, b"k", || true).is_none());
        let calls = std::cell::Cell::new(0);
        assert!(
            recover(&data, b"k", || {
                calls.set(calls.get() + 1);
                calls.get() > 2
            })
            .is_none()
        );
    }
}
