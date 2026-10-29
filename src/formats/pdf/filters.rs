//! Stream filters: reading a dictionary's `/Filter` chain, and decoding a
//! stream body through it.

use std::borrow::Cow;
use std::fmt;

use super::MAX_INFLATED;
use super::lex::{decode_hex, is_white, key_ends, name_list};
use super::objects::DictRegion;

/// The `/Filter` chain of a dictionary, outermost first, from its first
/// `/Filter` entry: a single name or an array of them, without slashes.
pub(super) fn find_filters(dict: &[u8]) -> Option<Vec<String>> {
    name_list(dict, key_ends(dict, b"Filter").next()?)
}

/// Deduplicated comma-joined filter chain strings across every
/// `/Filter` declaration inside an object dictionary. A single-name
/// declaration like `/Filter /FlateDecode` becomes `"FlateDecode"`;
/// an array like `/Filter [/ASCIIHexDecode /FlateDecode]` becomes
/// `"ASCIIHexDecode,FlateDecode"`. Order preserves first appearance.
pub(super) fn scan_filter_chains(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for region in dict_regions {
        let dict = region.dict(bytes);
        for at in key_ends(dict, b"Filter") {
            if let Some(chain) = name_list(dict, at).map(|names| names.join(","))
                && seen.insert(chain.clone())
            {
                out.push(chain);
            }
        }
    }
    out
}

/// Why a stream body could not be decoded.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DecodeError {
    /// A filter this extractor does not implement (LZW, RunLength, the
    /// image codecs, `Crypt`).
    Unsupported(String),
    /// A Flate stage that produced nothing.
    Corrupt,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => write!(f, "filter {name} is not decoded"),
            Self::Corrupt => f.write_str("flate data did not inflate"),
        }
    }
}

/// Decode a stream body through `filters` (outermost first), keeping at
/// most `cap` bytes. Flate, ASCIIHex and ASCII85 are decoded, under their
/// full or abbreviated names; a body with no filter is its own prefix.
///
/// Each stage before the last is held to [`MAX_INFLATED`] (or `cap`, if
/// larger), so a chain cannot hold more than one inflate's worth at a time.
pub(super) fn decode_stream(
    raw: &[u8],
    filters: &[String],
    cap: usize,
) -> Result<Vec<u8>, DecodeError> {
    let mut data = Cow::Borrowed(raw);
    for (i, filter) in filters.iter().enumerate() {
        let stage_cap = if i + 1 == filters.len() {
            cap
        } else {
            cap.max(MAX_INFLATED)
        };
        let next = match filter.as_str() {
            "FlateDecode" | "Fl" => inflate_capped(&data, stage_cap).ok_or(DecodeError::Corrupt)?,
            "ASCIIHexDecode" | "AHx" => decode_hex(data.iter().copied(), stage_cap).0,
            "ASCII85Decode" | "A85" => ascii85_decode(&data, stage_cap),
            other => return Err(DecodeError::Unsupported(other.to_string())),
        };
        data = Cow::Owned(next);
    }
    Ok(match data {
        Cow::Borrowed(raw) => raw.get(..cap).unwrap_or(raw).to_vec(),
        Cow::Owned(decoded) => decoded,
    })
}

/// Decode a FlateDecode stream into a buffer of at most `max` bytes, so an
/// adversarial deflate bomb can't blow memory.
///
/// A truncated stream or one with a bad checksum still yields what decoded
/// before the damage: viewers render that prefix, and malicious PDFs ship
/// such streams on purpose to trip strict parsers. `None` only when nothing
/// decoded at all.
pub(super) fn inflate_capped(input: &[u8], max: usize) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(input).take(max as u64);
    let mut out = Vec::new();
    // `read_to_end` keeps what it read before an error.
    let complete = decoder.read_to_end(&mut out).is_ok();
    (complete || !out.is_empty()).then_some(out)
}

/// Decode ASCII85 (ISO 32000-1 §7.4.3) up to its `~>` end marker, keeping
/// at most `cap` bytes. Whitespace is skipped, `z` stands for four zero
/// bytes, and a final partial group of n characters yields n − 1 bytes.
/// Decoding stops at the first byte outside the alphabet or the first
/// group too large for 32 bits, keeping what came before it.
fn ascii85_decode(input: &[u8], cap: usize) -> Vec<u8> {
    /// A group of base-85 digits, padded with the largest digit.
    fn word(digits: &[u8]) -> Option<[u8; 4]> {
        let value = (0..5).fold(0u64, |acc, i| {
            acc * 85 + u64::from(digits.get(i).copied().unwrap_or(84))
        });
        u32::try_from(value).ok().map(u32::to_be_bytes)
    }
    // Some writers keep the `<~` opener of the stand-alone format.
    let start = input.iter().position(|&b| !is_white(b)).unwrap_or(0);
    let input = match input.get(start..) {
        Some([b'<', b'~', rest @ ..]) => rest,
        _ => input,
    };
    let mut out = Vec::new();
    let mut group = Vec::with_capacity(5);
    for &b in input {
        if out.len() >= cap {
            break;
        }
        match b {
            b'z' if group.is_empty() => out.extend_from_slice(&[0; 4]),
            b'!'..=b'u' => {
                group.push(b - b'!');
                if group.len() == 5 {
                    let Some(bytes) = word(&group) else {
                        return out;
                    };
                    out.extend_from_slice(&bytes);
                    group.clear();
                }
            }
            _ if is_white(b) => {}
            _ => break,
        }
    }
    if group.len() > 1
        && let Some(bytes) = word(&group)
    {
        out.extend(bytes.iter().take(group.len() - 1));
    }
    out.truncate(cap);
    out
}
