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
use serde_json::{json, Value as JsonValue};

use crate::formats::common::{hex_encode, put_str, put_u64};
use crate::output::Values;

const RICH_MAGIC: &[u8; 4] = b"Rich";
// "DanS" little-endian read as u32: 'D'=0x44, 'a'=0x61, 'n'=0x6e, 'S'=0x53.
const DANS_MARKER: u32 = 0x536e_6144;

/// Find and decode the Rich header in `bytes`, populating
/// `pe.rich.*` keys. No-op when the binary has no Rich header (Go,
/// Rust, MinGW, packed/stripped binaries, …).
pub(super) fn extract(bytes: &[u8], values: &mut Values) {
    // The Rich header lives entirely inside the DOS stub region; PE
    // signature offset is at 0x3c (e_lfanew). Anything past that is
    // PE proper.
    if bytes.len() < 0x40 {
        return;
    }
    let e_lfanew =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let scan_end = e_lfanew.min(bytes.len());
    if scan_end < 8 {
        return;
    }

    let Some(rich_pos) = find_rich_marker(&bytes[..scan_end]) else {
        return;
    };
    // Need at least 4 bytes after the marker for the XOR key.
    if rich_pos + 8 > bytes.len() {
        return;
    }
    let key = u32::from_le_bytes([
        bytes[rich_pos + 4],
        bytes[rich_pos + 5],
        bytes[rich_pos + 6],
        bytes[rich_pos + 7],
    ]);

    // Walk backwards in 4-byte words until we find the XOR-encoded
    // DanS marker.
    let mut words = Vec::new();
    let mut pos = rich_pos;
    while pos >= 4 {
        pos -= 4;
        let raw = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        let decoded = raw ^ key;
        if decoded == DANS_MARKER {
            words.reverse();
            return emit(&words, key, &bytes[pos..rich_pos], values);
        }
        words.push(decoded);
    }
    // No DanS marker found — silently skip; this isn't a valid Rich
    // header even though the `Rich` magic was present.
}

fn emit(words: &[u32], key: u32, raw_table: &[u8], values: &mut Values) {
    // After DanS the table has three padding zeros, then (comp_id,
    // count) pairs. We popped DanS off when we found it, so `words`
    // starts with the three pad words followed by the entries.
    if words.len() < 3 {
        return;
    }
    let entries_words = &words[3..];
    if entries_words.len() % 2 != 0 {
        return;
    }

    let mut entries: Vec<JsonValue> = Vec::new();
    for pair in entries_words.chunks_exact(2) {
        let comp_id = pair[0];
        let count = pair[1];
        let build_id = (comp_id >> 16) & 0xffff;
        let product_id = comp_id & 0xffff;
        entries.push(json!({
            "product_id": product_id,
            "build_id": build_id,
            "use_count": count,
        }));
    }

    put_u64(values, "pe.rich.key", u64::from(key));
    values.insert("pe.rich.entries", JsonValue::Array(entries));

    // The "rich hash" is MD5 over the *decrypted* table bytes (DanS
    // through last entry, post-XOR). Distinct from "rich pv hash"
    // which uses the encrypted form. We emit the decrypted version
    // because it's the one VT and YARA conventions converged on.
    put_str(values, "pe.rich.hash", rich_md5(raw_table, key));
}

fn rich_md5(encrypted: &[u8], key: u32) -> String {
    let key_bytes = key.to_le_bytes();
    let mut decrypted = Vec::with_capacity(encrypted.len());
    for (i, &b) in encrypted.iter().enumerate() {
        decrypted.push(b ^ key_bytes[i % 4]);
    }
    hex_encode(&Md5::digest(&decrypted))
}

fn find_rich_marker(bytes: &[u8]) -> Option<usize> {
    // The Rich marker sits in the DOS stub region; we scan only that
    // small window so a false positive deep in arbitrary data can't
    // misfire.
    bytes.windows(4).rposition(|w| w == RICH_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rich_header_is_silent() {
        // A minimal "PE-ish" buffer with no Rich marker.
        let mut buf = vec![0u8; 0x80];
        // PE signature offset.
        buf[0x3c] = 0x40;
        let mut v = Values::new();
        extract(&buf, &mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn rich_md5_is_deterministic() {
        let bytes = b"hello world here is some data";
        let h1 = rich_md5(bytes, 0xdead_beef);
        let h2 = rich_md5(bytes, 0xdead_beef);
        assert_eq!(h1, h2);
        // Different key changes the digest.
        let h3 = rich_md5(bytes, 0xcafe_babe);
        assert_ne!(h1, h3);
    }

    #[test]
    fn find_rich_marker_locates_last_occurrence() {
        let mut buf = vec![0u8; 64];
        buf[20..24].copy_from_slice(b"Rich");
        buf[40..44].copy_from_slice(b"Rich");
        assert_eq!(find_rich_marker(&buf), Some(40));
    }

    /// End-to-end Rich header decode for the canonical `test.exe`
    /// fixture. Pinning the key, the canonical MD5, and the first
    /// entry's `(product_id, build_id, use_count)` guards against
    /// silent drift in the XOR-key recovery, tuple walker, or hash
    /// computation. Regenerate values by running
    /// `cargo run --bin expose -- ../cleave/tests/fixtures/test.exe`.
    #[test]
    fn rich_header_decodes_test_exe_to_known_values() {
        let bytes = std::fs::read("../cleave/tests/fixtures/test.exe")
            .expect("test.exe fixture is required");
        let mut v = Values::new();
        extract(&bytes, &mut v);

        assert_eq!(
            v.get("pe.rich.key").and_then(|x| x.as_u64()),
            Some(110_128_735),
        );
        assert_eq!(
            v.get("pe.rich.hash").and_then(|x| x.as_str()),
            Some("d7fdfa1db9e0bba7aef35f999a032c9a"),
        );
        let entries = v
            .get("pe.rich.entries")
            .and_then(|x| x.as_array())
            .expect("entries populated for a Rich-header PE");
        assert_eq!(entries.len(), 10);
        let first = &entries[0];
        assert_eq!(
            first.get("product_id").and_then(|x| x.as_u64()),
            Some(30729),
        );
        assert_eq!(first.get("build_id").and_then(|x| x.as_u64()), Some(147));
        assert_eq!(first.get("use_count").and_then(|x| x.as_u64()), Some(10));
    }
}
