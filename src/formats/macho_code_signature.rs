//! Mach-O embedded code-signature parser.
//!
//! Mach-O binaries reference a code-signature blob from the
//! `LC_CODE_SIGNATURE` load command. The blob is a **SuperBlob** —
//! a magic-prefixed container of typed sub-blobs identified by their
//! own magic numbers. The forensically valuable contents:
//!
//! - **CodeDirectory** (`CSMAGIC_CODEDIRECTORY` = `0xfade0c02`):
//!   identifier, team_id, hash algorithm, hash slots, flags. The
//!   SHA-256 of the entire CodeDirectory blob is itself a unique
//!   per-binary fingerprint (the "cdhash" macOS uses for `codesign
//!   --verify` lookups).
//! - **Embedded Entitlements** (`CSMAGIC_EMBEDDED_ENTITLEMENTS` =
//!   `0xfade7171`): the application's plist entitlements — what
//!   capabilities the app claims.
//! - **CMS Signature wrapper** (`CSMAGIC_BLOBWRAPPER` = `0xfade0b01`):
//!   PKCS#7 SignedData with the Apple Developer cert chain. We hand
//!   this to the same parser the Authenticode code path uses.
//!
//! All multi-byte fields inside the code signature are stored
//! **big-endian** — uniquely among Mach-O structures, which are
//! otherwise host-endian.

use serde_json::{Map, Value as JsonValue};
use sha2::{Digest, Sha256};

use crate::formats::common::{hex_encode, put_str, put_u64};
use crate::output::Values;

/// Outer wrapper magic. Every embedded code signature starts here.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
/// `Detached` signature, sometimes seen in `__cs_blob` sections.
const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
/// Per-blob magics we care about.
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_DER_ENTITLEMENTS: u32 = 0xfade_7172;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;

/// Parse the code-signature blob at offset `sig_off..sig_off+sig_size`
/// in `bytes` and populate the `macho.code_signature.*` subtree.
pub(super) fn parse(bytes: &[u8], sig_off: usize, sig_size: usize, values: &mut Values) {
    let end = sig_off.saturating_add(sig_size);
    if end > bytes.len() || sig_size < 12 {
        return;
    }
    let sig = &bytes[sig_off..end];

    let magic = read_u32_be(sig, 0);
    let total_len = read_u32_be(sig, 4) as usize;
    if total_len < 12 || total_len > sig.len() {
        return;
    }
    if magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_DETACHED_SIGNATURE {
        return;
    }

    let count = read_u32_be(sig, 8) as usize;
    // Each BlobIndex: u32 type, u32 offset (12 bytes header + 8 * count
    // for the index table).
    let index_end = 12 + count.checked_mul(8).unwrap_or(0);
    if index_end > total_len {
        return;
    }

    for i in 0..count {
        let entry_off = 12 + i * 8;
        let _slot_type = read_u32_be(sig, entry_off);
        let blob_off = read_u32_be(sig, entry_off + 4) as usize;
        if blob_off + 8 > total_len {
            continue;
        }
        let blob_magic = read_u32_be(sig, blob_off);
        let blob_len = read_u32_be(sig, blob_off + 4) as usize;
        if blob_len < 8 || blob_off + blob_len > total_len {
            continue;
        }
        let blob = &sig[blob_off..blob_off + blob_len];

        match blob_magic {
            CSMAGIC_CODEDIRECTORY => parse_code_directory(blob, values),
            CSMAGIC_REQUIREMENTS => {
                // Presence-as-marker: a `requirements` field on the
                // code-signature object exists iff a Requirements blob
                // was found. We don't yet parse the requirement
                // expression itself; the marker carries the byte size
                // so consumers can spot unusually large or empty blobs.
                put_u64(
                    values,
                    "macho.code_signature.requirements_size",
                    (blob.len() - 8) as u64,
                );
            }
            CSMAGIC_EMBEDDED_ENTITLEMENTS => parse_entitlements(blob, values),
            CSMAGIC_DER_ENTITLEMENTS => {
                // Same pattern: presence of `der_entitlements_size`
                // signals a DER-encoded entitlements blob was found.
                put_u64(
                    values,
                    "macho.code_signature.der_entitlements_size",
                    (blob.len() - 8) as u64,
                );
            }
            CSMAGIC_BLOBWRAPPER => parse_cms(blob, values),
            _ => {}
        }
    }
}

/// CodeDirectory layout (excerpt — fields up to v20100 are stable).
fn parse_code_directory(blob: &[u8], values: &mut Values) {
    // Header layout (big-endian):
    //   u32 magic     (already validated)
    //   u32 length
    //   u32 version
    //   u32 flags
    //   u32 hashOffset
    //   u32 identOffset
    //   u32 nSpecialSlots
    //   u32 nCodeSlots
    //   u32 codeLimit
    //   u8  hashSize
    //   u8  hashType
    //   u8  platform
    //   u8  pageSize         (log2)
    //   u32 spare2
    //   // v20100+:
    //   u32 teamOffset       (at offset 0x30)
    if blob.len() < 0x30 {
        return;
    }
    let version = read_u32_be(blob, 8);
    let flags = read_u32_be(blob, 12);
    let ident_offset = read_u32_be(blob, 20) as usize;
    let hash_size = blob[36];
    let hash_type = blob[37];
    let platform = blob[38];

    if let Some(ident) = read_cstr(blob, ident_offset) {
        put_str(values, "macho.code_signature.identifier", ident);
    }

    // The team_offset field landed in version 0x20100.
    if version >= 0x0002_0100 && blob.len() >= 0x34 {
        let team_offset = read_u32_be(blob, 48) as usize;
        if team_offset != 0 {
            if let Some(team) = read_cstr(blob, team_offset) {
                if !team.is_empty() {
                    put_str(values, "macho.code_signature.team_id", team);
                }
            }
        }
    }

    put_str(values, "macho.code_signature.hash", hash_label(hash_type));
    put_u64(values, "macho.code_signature.platform", u64::from(platform));
    put_u64(values, "macho.code_signature.version", u64::from(version));
    // hash_size duplicates `hash` (every algorithm has a fixed digest
    // length); the underlying byte stays available via the parsed
    // structure if anyone needs it.
    let _ = hash_size;

    // Decompose the flag bitfield into named strings. The `adhoc` flag
    // sits in this array — trait authors check it via `exact: adhoc`
    // on `macho.code_signature.flags`, so a separate `is_ad_hoc`
    // boolean would only restate the array's contents.
    let flag_names = code_signature_flags(flags);
    values.insert(
        "macho.code_signature.flags",
        JsonValue::Array(flag_names.into_iter().map(JsonValue::String).collect()),
    );

    // cdhash: SHA-256 of the entire CodeDirectory blob. This is the
    // value macOS reports in `codesign -dv --verbose=4` and the one
    // used for notarisation lookups.
    let digest = Sha256::digest(blob);
    put_str(values, "macho.code_signature.cdhash", hex_encode(&digest));
}

fn parse_entitlements(blob: &[u8], values: &mut Values) {
    // 8-byte header (magic + length); the rest is XML plist.
    if blob.len() <= 8 {
        return;
    }
    let xml_bytes = &blob[8..];
    let Ok(parsed) = plist::from_bytes::<plist::Value>(xml_bytes) else {
        // Surface raw text as a fallback so the consumer at least sees
        // what was claimed.
        if let Ok(s) = std::str::from_utf8(xml_bytes) {
            put_str(values, "macho.code_signature.entitlements_xml", s);
        }
        return;
    };
    let json = plist_to_json(parsed);
    values.insert("macho.code_signature.entitlements", json);
}

fn parse_cms(blob: &[u8], values: &mut Values) {
    if blob.len() <= 8 {
        return;
    }
    // Record the CMS blob's byte size. The CMS sub-object below
    // signals presence on its own when the strict-DER parse succeeds;
    // the explicit size field carries forensic value (unusually small
    // or large CMS payloads are a malware-signing red flag) and
    // doubles as a presence marker for the BER-encoded majority where
    // the deep parse can't decode the SignedData.
    put_u64(
        values,
        "macho.code_signature.cms_size",
        (blob.len() - 8) as u64,
    );
    // Apple emits the inner SignedData with BER indefinite-length
    // encoding; the strict-DER cms/x509-cert crates we use for
    // Authenticode reject it on the first length byte. We try the
    // strict parse anyway — it succeeds for the small fraction of
    // Apple-signed binaries that happen to use definite-length form,
    // and for the rest we keep the presence flag above.
    let der = &blob[8..];
    if let Some(sig) = super::pe_authenticode::parse_cms_blob(der) {
        values.insert("macho.code_signature.cms", sig);
    }
}

fn read_u32_be(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_cstr(b: &[u8], off: usize) -> Option<String> {
    if off >= b.len() {
        return None;
    }
    let slice = &b[off..];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).ok().map(str::to_string)
}

fn hash_label(t: u8) -> &'static str {
    // Constants from `CS_HASHTYPE_*` in xnu's `cs_blobs.h`.
    match t {
        1 => "sha1",
        2 => "sha256",
        3 => "sha256_truncated",
        4 => "sha384",
        5 => "sha512",
        _ => "unknown",
    }
}

fn code_signature_flags(flags: u32) -> Vec<String> {
    // From xnu `CS_*` flags. Forensically relevant subset.
    let mut out = Vec::new();
    if flags & 0x0000_0001 != 0 {
        out.push("valid".to_string());
    }
    if flags & 0x0000_0002 != 0 {
        out.push("ad_hoc".to_string());
    }
    if flags & 0x0000_0004 != 0 {
        out.push("get_task_allow".to_string());
    }
    if flags & 0x0000_0008 != 0 {
        out.push("installer".to_string());
    }
    if flags & 0x0000_0100 != 0 {
        out.push("hard".to_string());
    }
    if flags & 0x0000_0200 != 0 {
        out.push("kill".to_string());
    }
    if flags & 0x0000_0400 != 0 {
        out.push("check_expiration".to_string());
    }
    if flags & 0x0000_0800 != 0 {
        out.push("restrict".to_string());
    }
    if flags & 0x0000_1000 != 0 {
        out.push("enforcement".to_string());
    }
    if flags & 0x0000_2000 != 0 {
        out.push("library_validation".to_string());
    }
    if flags & 0x0001_0000 != 0 {
        out.push("runtime".to_string());
    }
    if flags & 0x0002_0000 != 0 {
        out.push("linker_signed".to_string());
    }
    out
}

fn plist_to_json(value: plist::Value) -> JsonValue {
    use plist::Value as P;
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => {
            serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
        }
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(format!("{d:?}")),
        P::Array(arr) => JsonValue::Array(arr.into_iter().map(plist_to_json).collect()),
        P::Dictionary(dict) => {
            let mut obj = Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v));
            }
            JsonValue::Object(obj)
        }
        _ => JsonValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_labels_known() {
        assert_eq!(hash_label(1), "sha1");
        assert_eq!(hash_label(2), "sha256");
        assert_eq!(hash_label(0), "unknown");
    }

    #[test]
    fn flags_decompose() {
        let f = code_signature_flags(0x2 | 0x2000 | 0x1_0000);
        assert!(f.contains(&"ad_hoc".to_string()));
        assert!(f.contains(&"library_validation".to_string()));
        assert!(f.contains(&"runtime".to_string()));
    }

    #[test]
    fn cstr_terminates_at_null() {
        let buf = b"hello\0world";
        assert_eq!(read_cstr(buf, 0).unwrap(), "hello");
        assert_eq!(read_cstr(buf, 6).unwrap(), "world");
    }

    #[test]
    fn flags_use_ad_hoc_separator() {
        // The CS_ADHOC flag — ad-hoc signing — is two-words in
        // English; the emitted name uses an underscore to match the
        // rest of the Pike-style flag taxonomy.
        let f = code_signature_flags(0x2);
        assert!(f.contains(&"ad_hoc".to_string()));
        assert!(!f.contains(&"adhoc".to_string()));
    }

    #[test]
    fn flags_empty_when_zero() {
        assert!(code_signature_flags(0).is_empty());
    }

    #[test]
    fn flags_decompose_full_set() {
        // Sum of every documented CS_* flag the parser handles.
        let all = 0x0000_0001
            | 0x0000_0002
            | 0x0000_0004
            | 0x0000_0008
            | 0x0000_0100
            | 0x0000_0200
            | 0x0000_0400
            | 0x0000_0800
            | 0x0000_1000
            | 0x0000_2000
            | 0x0001_0000
            | 0x0002_0000;
        let f = code_signature_flags(all);
        assert_eq!(f.len(), 12);
        // Spot-check ordering matches the bit ordering in code_signature_flags.
        assert_eq!(f[0], "valid");
        assert_eq!(f[1], "ad_hoc");
        assert_eq!(f.last().map(String::as_str), Some("linker_signed"));
    }

    #[test]
    fn hash_label_covers_canonical_digest_set() {
        assert_eq!(hash_label(3), "sha256_truncated");
        assert_eq!(hash_label(4), "sha384");
        assert_eq!(hash_label(5), "sha512");
        assert_eq!(hash_label(99), "unknown");
    }

    #[test]
    fn cstr_handles_offset_beyond_terminator() {
        // After the second NUL the read should still terminate at the
        // next NUL we encounter, returning whatever's between.
        let buf = b"a\0b\0c";
        assert_eq!(read_cstr(buf, 2).unwrap(), "b");
        assert_eq!(read_cstr(buf, 4).unwrap(), "c");
    }

    #[test]
    fn cstr_empty_when_first_byte_is_null() {
        let buf = b"\0afterward";
        let s = read_cstr(buf, 0).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn read_u32_be_reads_in_network_order() {
        // Code-signature blobs are all big-endian.
        let buf = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_be(&buf, 0), 0x0102_0304);
    }

}
