//! The structure of a native phar: the stub boundary, the manifest and the
//! shape of the signature trailer.
//!
//! The layout follows `ext/phar/phar.c`: the stub ends at the first
//! `__HALT_COMPILER();`, every integer is little-endian, and the manifest is
//! at most 100 MB. Identification needs only to know the manifest parses;
//! the extractor (`formats::phar`) publishes it and checks the signature's
//! digest, which costs a pass over the whole file.

use crate::bytes;
use crate::error::Error;

/// What ends the stub. PHP's phar reader looks for exactly this spelling.
const HALT_TOKEN: &[u8] = b"__HALT_COMPILER();";

/// The largest manifest PHP will read.
const MAX_MANIFEST_SIZE: u32 = 100 << 20;

/// The trailer magic every signed phar ends with.
pub(crate) const SIGNATURE_MAGIC: &[u8; 4] = b"GBMB";

/// Global flag: the archive carries a signature trailer.
pub(crate) const FLAG_SIGNATURE: u32 = 0x0001_0000;

/// Bytes of stub [`is_phar`] searches for `__HALT_COMPILER();`. Identification
/// asks this of every PHP file, so the search must not cost a pass over a
/// large one; real stubs run from a few hundred bytes to a few KiB.
pub(crate) const MAX_DETECT_STUB: usize = 1 << 20;

/// Manifest entries a parse keeps; the rest are counted in
/// [`Phar::unlisted`]. Identification keeps none.
const DETECT_ENTRY_CAP: usize = 0;

/// A parsed native phar: everything but the members' contents.
pub(crate) struct Phar<'a> {
    /// Where the stub ends and the manifest's length field starts.
    pub(crate) stub_size: usize,
    /// The manifest's declared length, not counting its length field.
    pub(crate) manifest_size: u32,
    /// `major.minor.release`.
    pub(crate) api_version: String,
    pub(crate) alias: &'a [u8],
    /// The global metadata, PHP-serialized.
    pub(crate) metadata: &'a [u8],
    pub(crate) entries: Vec<Entry<'a>>,
    /// Entries past the parse's cap, counted but not parsed into the list.
    pub(crate) unlisted: u64,
    pub(crate) signature: Option<Trailer>,
}

/// One manifest entry.
pub(crate) struct Entry<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) size: u32,
    pub(crate) mtime: u32,
    pub(crate) compressed_size: u32,
    pub(crate) crc32: u32,
    pub(crate) flags: u32,
    pub(crate) metadata: &'a [u8],
    /// Where the content starts, from the start of the file.
    pub(crate) offset: u64,
}

/// The signature trailer: `<signature><flags u32>GBMB`, with an OpenSSL
/// signature's length between the two. The signed bytes are everything before
/// the signature.
pub(crate) struct Trailer {
    pub(crate) algorithm: Algorithm,
    /// Where the signature starts; the signed bytes are those before it.
    pub(crate) start: usize,
    /// Where the signature ends.
    pub(crate) end: usize,
}

/// Whether `data` is a native phar, by a parse of its manifest. Cheap for
/// most input: it needs a trailing `GBMB` (every signed phar), or a PHP or
/// shebang opening (the usual stub of an unsigned one), and the stub's end
/// within [`MAX_DETECT_STUB`] bytes, before it parses. The parse reads the
/// manifest and the trailer's shape, not the digest.
pub(crate) fn is_phar(data: &[u8]) -> bool {
    let signed = data.ends_with(SIGNATURE_MAGIC);
    let head = data.trim_ascii_start();
    let php_stub = head.starts_with(b"<?") || head.starts_with(b"#!");
    let window = data
        .get(..MAX_DETECT_STUB + HALT_TOKEN.len())
        .unwrap_or(data);
    (signed || php_stub)
        && memchr::memmem::find(window, HALT_TOKEN).is_some()
        && parse(data, DETECT_ENTRY_CAP).is_ok()
}

/// Parse the stub boundary, manifest and signature trailer of a native phar,
/// keeping at most `entry_cap` manifest entries.
pub(crate) fn parse(data: &[u8], entry_cap: usize) -> Result<Phar<'_>, Error> {
    let halt = memchr::memmem::find(data, HALT_TOKEN)
        .ok_or_else(|| Error::malformed("phar", "no __HALT_COMPILER(); stub end"))?;
    let stub_size = stub_end(data, halt + HALT_TOKEN.len());

    let manifest_size = bytes::u32_le(data, stub_size)
        .ok_or_else(|| Error::malformed("phar", "truncated manifest length"))?;
    if manifest_size > MAX_MANIFEST_SIZE {
        return Err(Error::malformed("phar", "manifest larger than 100 MB"));
    }
    let manifest_start = stub_size + 4;
    let data_offset = manifest_start + manifest_size as usize;
    let manifest = data
        .get(manifest_start..data_offset)
        .ok_or_else(|| Error::malformed("phar", "manifest extends past end of file"))?;

    let mut r = bytes::Reader::new(manifest);
    let count = r.u32_le().ok_or_else(|| truncated("member count"))?;
    let [hi, lo] = r.array::<2>().ok_or_else(|| truncated("API version"))?;
    if hi >> 4 != 1 {
        return Err(Error::malformed("phar", "unsupported manifest API version"));
    }
    let api_version = format!("{}.{}.{}", hi >> 4, hi & 0xf, lo >> 4);
    let flags = r.u32_le().ok_or_else(|| truncated("global flags"))?;
    let alias = length_prefixed(&mut r).ok_or_else(|| truncated("alias"))?;
    let metadata = length_prefixed(&mut r).ok_or_else(|| truncated("metadata"))?;

    let mut entries = Vec::new();
    let mut offset = data_offset as u64;
    for _ in 0..count {
        let name = length_prefixed(&mut r).ok_or_else(|| truncated("member name"))?;
        if name.is_empty() {
            return Err(Error::malformed("phar", "member with an empty name"));
        }
        let (Some(size), Some(mtime), Some(compressed_size), Some(crc32), Some(entry_flags)) =
            (r.u32_le(), r.u32_le(), r.u32_le(), r.u32_le(), r.u32_le())
        else {
            return Err(truncated("member entry"));
        };
        let entry_metadata = length_prefixed(&mut r).ok_or_else(|| truncated("member metadata"))?;
        if entries.len() < entry_cap {
            entries.push(Entry {
                name,
                size,
                mtime,
                compressed_size,
                crc32,
                flags: entry_flags,
                metadata: entry_metadata,
                offset,
            });
        }
        offset = offset.saturating_add(u64::from(compressed_size));
    }

    let signature = if flags & FLAG_SIGNATURE != 0 {
        Some(trailer(data)?)
    } else {
        None
    };

    Ok(Phar {
        stub_size,
        manifest_size,
        api_version,
        alias,
        metadata,
        unlisted: u64::from(count).saturating_sub(entries.len() as u64),
        entries,
        signature,
    })
}

/// A `u32` length and that many bytes.
fn length_prefixed<'a>(r: &mut bytes::Reader<'a>) -> Option<&'a [u8]> {
    let len = r.u32_le()?;
    r.bytes(bytes::sat_usize(len))
}

fn truncated(what: &str) -> Error {
    Error::malformed("phar", format!("manifest truncated in the {what}"))
}

/// Where the stub ends, `after_token` being the byte after
/// `__HALT_COMPILER();`. As `phar.c` reads it: a following ` ?>` (or `\n?>`)
/// belongs to the stub, and so does one newline after that.
fn stub_end(data: &[u8], after_token: usize) -> usize {
    let rest = data.get(after_token..).unwrap_or_default();
    let mut end = after_token;
    if let [b' ' | b'\n', b'?', b'>', tail @ ..] = rest {
        end += 3;
        end += match tail {
            [b'\r', b'\n', ..] => 2,
            [b'\n', ..] => 1,
            _ => 0,
        };
    }
    end
}

/// A phar signature's algorithm, from the trailer's flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    /// An OpenSSL signature, checkable only with the archive's public key.
    OpenSsl,
    OpenSslSha256,
    OpenSslSha512,
}

impl Algorithm {
    fn from_flags(flags: u32) -> Option<Self> {
        Some(match flags {
            0x01 => Self::Md5,
            0x02 => Self::Sha1,
            0x03 => Self::Sha256,
            0x04 => Self::Sha512,
            0x10 => Self::OpenSsl,
            0x11 => Self::OpenSslSha256,
            0x12 => Self::OpenSslSha512,
            _ => return None,
        })
    }

    /// The digest's length for a hash signature; `None` for OpenSSL, whose
    /// trailer records its signature's length.
    fn digest_len(self) -> Option<usize> {
        match self {
            Self::Md5 => Some(16),
            Self::Sha1 => Some(20),
            Self::Sha256 => Some(32),
            Self::Sha512 => Some(64),
            Self::OpenSsl | Self::OpenSslSha256 | Self::OpenSslSha512 => None,
        }
    }

    /// The name `phar.signature.algorithm` reports.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::OpenSsl => "openssl",
            Self::OpenSslSha256 => "openssl_sha256",
            Self::OpenSslSha512 => "openssl_sha512",
        }
    }
}

/// Locate the signature trailer and name its algorithm.
fn trailer(data: &[u8]) -> Result<Trailer, Error> {
    let bad = |detail: &str| Error::malformed("phar", format!("signature trailer {detail}"));
    if !data.ends_with(SIGNATURE_MAGIC) {
        return Err(bad("missing its GBMB magic"));
    }
    let flags_at = data.len().checked_sub(8).ok_or_else(|| bad("truncated"))?;
    let flags = bytes::u32_le(data, flags_at).ok_or_else(|| bad("truncated"))?;
    let algorithm =
        Algorithm::from_flags(flags).ok_or_else(|| bad("names an unknown algorithm"))?;
    let (start, end) = match algorithm.digest_len() {
        Some(len) => (
            flags_at.checked_sub(len).ok_or_else(|| bad("truncated"))?,
            flags_at,
        ),
        None => {
            let len_at = flags_at.checked_sub(4).ok_or_else(|| bad("truncated"))?;
            let len = bytes::u32_le(data, len_at).ok_or_else(|| bad("truncated"))?;
            let len = bytes::sat_usize(len);
            (
                len_at.checked_sub(len).ok_or_else(|| bad("truncated"))?,
                len_at,
            )
        }
    };
    if data.get(start..end).is_none() {
        return Err(bad("truncated"));
    }
    Ok(Trailer {
        algorithm,
        start,
        end,
    })
}

#[cfg(test)]
mod tests;
