//! PE "Rich" header extractor.
//!
//! Microsoft's link.exe (and `cl.exe` invoked through it) embeds a
//! compact, lightly-obfuscated table between the DOS stub and the PE
//! header that lists every build tool that touched the binary and how
//! many compilation units came from each. It is colloquially called
//! the *Rich header* after the trailing `Rich` magic.
//!
//! The header is never read by the Windows loader — it exists purely
//! as a build-tool stamp — and Microsoft does not document it. The
//! decoding algorithm below is the widely-reverse-engineered consensus:
//!
//! 1. Find the literal `Rich` marker (4 bytes) somewhere before the
//!    PE signature.
//! 2. The 4 bytes following `Rich` are the XOR mask (the "Rich key").
//! 3. Walk *backwards* from the `Rich` marker, XOR-decoding 4-byte
//!    words with the mask, until reading the `DanS` marker (`0x536e_6144`)
//!    — that's the start of the table.
//! 4. The table is `(DanS, 0, 0, 0)` followed by `(comp_id, count)`
//!    pairs. Each `comp_id` packs `(build_id << 16) | product_id`.
//!
//! For each `(product_id, build_id, count)` triple we emit a small
//! object. The full Rich header itself fingerprints the build
//! environment far better than any single field — its hash is the
//! "rich pv" or "rich hash" malware-clustering signal.

use md5::{Digest, Md5};
use serde_json::{Value as JsonValue, json};

use crate::bytes::u32_le;
use crate::formats::common::{hex_encode, put_str, put_u64};
use crate::output::Values;
use crate::value_key;

const RICH_MAGIC: &[u8; 4] = b"Rich";
// "DanS" little-endian read as u32: 'D'=0x44, 'a'=0x61, 'n'=0x6e, 'S'=0x53.
const DANS_MARKER: u32 = 0x536e_6144;
/// Most `pe.rich.entries` reported. Each eight-byte entry becomes a JSON
/// object some thirty times its size, and a forged stub runs as far as
/// `e_lfanew` says; a real table lists tens of tools.
const MAX_RICH_ENTRIES: usize = 1024;

/// Where a Rich header sits in a PE's DOS stub.
struct RichLocation {
    /// Offset of the last `Rich` marker before `e_lfanew`.
    rich_pos: usize,
    /// The XOR key following the marker.
    key: u32,
    /// Offset of the XOR-encoded `DanS` marker that opens the table, or
    /// `None` when the `Rich` magic has no decodable table behind it.
    dans_pos: Option<usize>,
}

/// Locate the Rich header: the `Rich` marker in the DOS stub, its key, and
/// the `DanS` marker found by walking back from it in 4-byte words. `None`
/// when there is no marker (Go, Rust, MinGW, packed/stripped binaries, …)
/// or no room for its key.
fn locate(bytes: &[u8]) -> Option<RichLocation> {
    // The Rich header lives entirely inside the DOS stub region; PE
    // signature offset is at 0x3c (e_lfanew). Anything past that is
    // PE proper.
    if bytes.len() < 0x40 {
        return None;
    }
    let scan_end = crate::bytes::sat_usize(u32_le(bytes, 0x3c)?).min(bytes.len());
    if scan_end < 8 {
        return None;
    }
    // The last marker in the stub: a false positive deep in arbitrary data
    // cannot misfire.
    let rich_pos = bytes
        .get(..scan_end)?
        .windows(4)
        .rposition(|w| w == RICH_MAGIC)?;
    // Need at least 4 bytes after the marker for the XOR key.
    let key = u32_le(bytes, rich_pos + 4)?;
    let dans_pos = (1..=rich_pos / 4)
        .map(|words_back| rich_pos - 4 * words_back)
        .find(|&pos| u32_le(bytes, pos).is_some_and(|raw| raw ^ key == DANS_MARKER));
    Some(RichLocation {
        rich_pos,
        key,
        dans_pos,
    })
}

/// Find and decode the Rich header in `bytes`, populating
/// `pe.rich.*` keys. No-op when the binary has no Rich header, or the
/// `Rich` magic is present without a decodable table.
pub(super) fn extract(bytes: &[u8], values: &mut Values) {
    let Some(RichLocation {
        rich_pos,
        key,
        dans_pos: Some(dans_pos),
    }) = locate(bytes)
    else {
        return;
    };
    let (Some(raw_table), Some(encoded)) = (
        bytes.get(dans_pos..rich_pos),
        bytes.get(dans_pos + 4..rich_pos),
    ) else {
        return;
    };
    // The decoded words after DanS, in file order.
    let words: Vec<u32> = encoded
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word) ^ key)
        .collect();
    emit(&words, key, raw_table, values);
}

fn emit(words: &[u32], key: u32, raw_table: &[u8], values: &mut Values) {
    // After DanS the table has three padding zeros, then (comp_id,
    // count) pairs. We popped DanS off when we found it, so `words`
    // starts with the three pad words followed by the entries.
    let Some(entries_words) = words.get(3..) else {
        return;
    };
    if !entries_words.len().is_multiple_of(2) {
        return;
    }

    let pairs = entries_words.as_chunks::<2>().0;
    if pairs.len() > MAX_RICH_ENTRIES {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "rich-header",
            entries = pairs.len(),
            reported = MAX_RICH_ENTRIES,
            "Rich table past the entry cap"
        );
    }
    let mut entries: Vec<JsonValue> = Vec::new();
    for &[comp_id, count] in pairs.iter().take(MAX_RICH_ENTRIES) {
        let build_id = (comp_id >> 16) & 0xffff;
        let product_id = comp_id & 0xffff;
        entries.push(json!({
            "product_id": product_id,
            "build_id": build_id,
            "use_count": count,
        }));
    }

    put_u64(values, value_key!("pe.rich.key"), u64::from(key));
    values.insert_key(value_key!("pe.rich.entries"), JsonValue::Array(entries));

    // The "rich hash" is MD5 over the *decrypted* table bytes (DanS
    // through last entry, post-XOR). Distinct from "rich pv hash"
    // which uses the encrypted form. We emit the decrypted version
    // because it's the one VT and YARA conventions converged on.
    let key_bytes = key.to_le_bytes();
    let decrypted: Vec<u8> = raw_table
        .iter()
        .zip(key_bytes.iter().cycle())
        .map(|(&b, &k)| b ^ k)
        .collect();
    put_str(
        values,
        value_key!("pe.rich.hash"),
        hex_encode(&Md5::digest(&decrypted)),
    );
}

#[cfg(test)]
mod tests;
