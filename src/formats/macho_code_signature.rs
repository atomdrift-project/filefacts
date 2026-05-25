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

/// Maximum recursion depth honoured when decoding Apple Requirement
/// expressions. Real-world expressions are shallow (a handful of
/// AND/OR/NOT operators); the cap bounds stack usage on adversarial
/// blobs that chain operators arbitrarily deep.
const MAX_REQUIREMENT_DEPTH: u8 = 32;

/// Maximum recursion depth honoured when projecting a parsed plist
/// into JSON. Bounds stack usage on plists whose value graph nests
/// arrays and dictionaries beyond what real macOS artifacts emit.
const MAX_PLIST_DEPTH: u8 = 64;

/// Upper bound on the XML plist payload we hand to `plist::from_bytes`
/// in `parse_entitlements`. Real entitlements blobs are at most a few
/// KiB; capping prevents an oversized payload from forcing the plist
/// parser through megabytes of attacker XML.
const MAX_ENTITLEMENT_XML_BYTES: usize = 1 << 20;

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
    let Some(index_end) = count.checked_mul(8).and_then(|n| n.checked_add(12)) else {
        return;
    };
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
                put_u64(
                    values,
                    "macho.code_signature.requirements_size",
                    (blob.len() - 8) as u64,
                );
                parse_requirements_set(blob, values);
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

/// CodeDirectory layout (excerpt — fields through v20400 are stable).
fn parse_code_directory(blob: &[u8], values: &mut Values) {
    // Header layout (big-endian):
    //   u32 magic            (already validated)
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
    //   u8  pageSize         (log2 — actual page size is 1 << pageSize)
    //   u32 spare2
    //   // v20100+:
    //   u32 scatterOffset
    //   // v20200+:
    //   u32 teamOffset       (at offset 0x30)
    //   // v20300+:
    //   u32 spare3
    //   u64 codeLimit64
    //   // v20400+:
    //   u64 execSegBase
    //   u64 execSegLimit
    //   u64 execSegFlags
    if blob.len() < 0x2c {
        return;
    }
    let version = read_u32_be(blob, 8);
    let flags = read_u32_be(blob, 12);
    let ident_offset = read_u32_be(blob, 20) as usize;
    let n_special_slots = read_u32_be(blob, 24);
    let n_code_slots = read_u32_be(blob, 28);
    let code_limit = read_u32_be(blob, 32);
    let hash_size = blob[36];
    let hash_type = blob[37];
    let platform = blob[38];
    let page_size_log2 = blob[39];

    if let Some(ident) = read_cstr(blob, ident_offset) {
        put_str(values, "macho.code_signature.identifier", ident);
    }

    // The team_offset field landed in version 0x20200.
    if version >= 0x0002_0200 && blob.len() >= 0x34 {
        let team_offset = read_u32_be(blob, 48) as usize;
        if team_offset != 0 {
            if let Some(team) = read_cstr(blob, team_offset) {
                if !team.is_empty() {
                    put_str(values, "macho.code_signature.team_id", team);
                }
            }
        }
    }

    // Executable-segment descriptor — present from version 0x20400
    // onward. The three u64 fields sit at 0x40, 0x48, 0x50 inside the
    // CodeDirectory blob. Forensically meaningful as a per-binary
    // bound on which bytes the kernel will enforce as executable.
    if version >= 0x0002_0400 && blob.len() >= 0x58 {
        let exec_base =
            u64::from(read_u32_be(blob, 0x40)) << 32 | u64::from(read_u32_be(blob, 0x44));
        let exec_limit =
            u64::from(read_u32_be(blob, 0x48)) << 32 | u64::from(read_u32_be(blob, 0x4c));
        let exec_flags =
            u64::from(read_u32_be(blob, 0x50)) << 32 | u64::from(read_u32_be(blob, 0x54));
        put_u64(values, "macho.code_signature.exec_segment_base", exec_base);
        put_u64(
            values,
            "macho.code_signature.exec_segment_limit",
            exec_limit,
        );
        // CS_EXECSEG_* flags: 0x1 main binary, 0x10 allow unsigned,
        // 0x20 debugger, 0x40 jit, 0x80 skip library validation,
        // 0x100 can load CDHash, 0x200 can exec CDHash, 0x10000
        // allow_root.
        put_u64(
            values,
            "macho.code_signature.exec_segment_flags",
            exec_flags,
        );
    }

    put_str(values, "macho.code_signature.hash", hash_label(hash_type));
    put_u64(
        values,
        "macho.code_signature.hash_size",
        u64::from(hash_size),
    );
    put_u64(values, "macho.code_signature.platform", u64::from(platform));
    put_u64(values, "macho.code_signature.version", u64::from(version));
    put_u64(
        values,
        "macho.code_signature.special_slots",
        u64::from(n_special_slots),
    );
    put_u64(
        values,
        "macho.code_signature.code_slots",
        u64::from(n_code_slots),
    );
    put_u64(
        values,
        "macho.code_signature.code_limit",
        u64::from(code_limit),
    );
    if page_size_log2 > 0 && page_size_log2 < 32 {
        put_u64(
            values,
            "macho.code_signature.page_size",
            1u64 << page_size_log2,
        );
    }

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

/// Walk a Requirements SuperBlob and decode each requirement's
/// expression tree to its canonical textual form (e.g.
/// `identifier "com.apple.ls" and anchor apple`). Each requirement is
/// keyed by its slot type — the *designated* requirement is the one
/// `codesign -d -r-` prints and the one Gatekeeper actually checks.
///
/// Apple's requirement expressions are documented in
/// `<Security/SecCode.h>` and Apple's Technical Note TN2206. The
/// expression opcodes are a stack machine encoded big-endian with
/// length-prefixed strings padded to 4-byte alignment.
fn parse_requirements_set(blob: &[u8], values: &mut Values) {
    // SuperBlob header is already validated by the caller.
    if blob.len() < 12 {
        return;
    }
    let count = read_u32_be(blob, 8) as usize;
    let index_end = 12_usize.saturating_add(count.saturating_mul(8));
    if index_end > blob.len() {
        return;
    }
    let mut requirements = serde_json::Map::new();
    for i in 0..count {
        let entry_off = 12 + i * 8;
        let slot_type = read_u32_be(blob, entry_off);
        let req_off = read_u32_be(blob, entry_off + 4) as usize;
        if req_off + 12 > blob.len() {
            continue;
        }
        let req_magic = read_u32_be(blob, req_off);
        let req_len = read_u32_be(blob, req_off + 4) as usize;
        // CSMAGIC_REQUIREMENT = 0xfade_0c00.
        if req_magic != 0xfade_0c00 || req_len < 12 || req_off + req_len > blob.len() {
            continue;
        }
        // Expression tree starts after the 12-byte requirement
        // header (magic + length + kind). The trailing kind isn't
        // forensically interesting (always 1 = expression in
        // practice); we ignore it and parse the expression tree.
        let expr_start = req_off + 12;
        let expr_end = req_off + req_len;
        let mut cursor = expr_start;
        let text = decode_expression(blob, &mut cursor, expr_end, 0).unwrap_or_else(|| "?".into());
        let key = requirement_slot_name(slot_type);
        requirements.insert(key.to_string(), JsonValue::String(text));
    }
    if !requirements.is_empty() {
        values.insert(
            "macho.code_signature.requirements",
            JsonValue::Object(requirements),
        );
    }
}

/// Map a Requirements-SuperBlob slot type to the canonical short
/// name `codesign -d -r-` uses (`designated`, `host`, `guest`,
/// `library`, `plugin`).
fn requirement_slot_name(slot: u32) -> &'static str {
    match slot {
        1 => "host",
        2 => "guest",
        3 => "designated",
        4 => "library",
        5 => "plugin",
        _ => "unknown",
    }
}

/// Recursive descent through the Apple Requirement expression tree.
/// Opcodes are u32 big-endian; strings, data blobs, and integers
/// follow inline with 4-byte alignment between fields. The textual
/// output matches what Apple's `csreq` / `codesign -d -r-` emit so
/// values can be diffed directly against those tools' output.
///
/// `depth` is the recursion level (start at 0). Adversarial blobs can
/// chain AND/OR/NOT operators to arbitrary depth — cap at
/// [`MAX_REQUIREMENT_DEPTH`] to keep stack usage bounded.
fn decode_expression(blob: &[u8], cursor: &mut usize, end: usize, depth: u8) -> Option<String> {
    if depth > MAX_REQUIREMENT_DEPTH {
        return None;
    }
    if *cursor + 4 > end {
        return None;
    }
    let op = read_u32_be(blob, *cursor);
    *cursor += 4;
    // Match-flags live in the top byte of the opcode on certain
    // string-match instructions; the low 24 bits hold the actual
    // opcode. The match-flag handling matters only for `info`/
    // `entitlement` ops which we render without flag annotations.
    let op_low = op & 0x00ff_ffff;
    Some(match op_low {
        0 => "never".into(),
        1 => "always".into(),
        2 => format!("identifier \"{}\"", read_expr_string(blob, cursor, end)?),
        3 => "anchor apple".into(),
        4 => {
            let slot = read_u32_be_advance(blob, cursor, end)?;
            let hash = read_expr_data(blob, cursor, end)?;
            format!("certificate {slot} = H\"{}\"", hex_encode(&hash))
        }
        5 => {
            let key = read_expr_string(blob, cursor, end)?;
            let val = read_expr_string(blob, cursor, end)?;
            format!("info[{key}] = \"{val}\"")
        }
        6 => {
            let left = decode_expression(blob, cursor, end, depth + 1)?;
            let right = decode_expression(blob, cursor, end, depth + 1)?;
            format!("({left} and {right})")
        }
        7 => {
            let left = decode_expression(blob, cursor, end, depth + 1)?;
            let right = decode_expression(blob, cursor, end, depth + 1)?;
            format!("({left} or {right})")
        }
        8 => format!(
            "cdhash H\"{}\"",
            hex_encode(&read_expr_data(blob, cursor, end)?)
        ),
        9 => {
            let inner = decode_expression(blob, cursor, end, depth + 1)?;
            format!("!({inner})")
        }
        10 => {
            let key = read_expr_string(blob, cursor, end)?;
            let m = read_match(blob, cursor, end)?;
            format!("info[{key}] {m}")
        }
        11 => {
            let slot = read_u32_be_advance(blob, cursor, end)?;
            let field = read_expr_string(blob, cursor, end)?;
            let m = read_match(blob, cursor, end)?;
            format!("certificate {slot}[{field}] {m}")
        }
        12 => format!(
            "certificate {} trusted",
            read_u32_be_advance(blob, cursor, end)?
        ),
        13 => "anchor trusted".into(),
        14 => {
            let slot = read_u32_be_advance(blob, cursor, end)?;
            let oid = read_expr_data(blob, cursor, end)?;
            let m = read_match(blob, cursor, end)?;
            format!("certificate {slot}[field.{}] {m}", hex_encode(&oid))
        }
        15 => "anchor apple generic".into(),
        16 => {
            let key = read_expr_string(blob, cursor, end)?;
            let m = read_match(blob, cursor, end)?;
            format!("entitlement[{key}] {m}")
        }
        17 => {
            let slot = read_u32_be_advance(blob, cursor, end)?;
            let oid = read_expr_data(blob, cursor, end)?;
            let m = read_match(blob, cursor, end)?;
            format!("certificate {slot}[policy.{}] {m}", hex_encode(&oid))
        }
        18 => format!("anchor apple {}", read_expr_string(blob, cursor, end)?),
        19 => format!("anchor named \"{}\"", read_expr_string(blob, cursor, end)?),
        20 => format!("platform = {}", read_u32_be_advance(blob, cursor, end)?),
        21 => "notarized".into(),
        22 => {
            let slot = read_u32_be_advance(blob, cursor, end)?;
            let field = read_expr_string(blob, cursor, end)?;
            let m = read_match(blob, cursor, end)?;
            format!("certificate {slot}[{field}.date] {m}")
        }
        23 => "legacy".into(),
        _ => format!("op({op_low:#x})"),
    })
}

/// Match-suffix operator. The opcode tag advances the cursor; for
/// every flavour except `exists` a string operand follows.
fn read_match(blob: &[u8], cursor: &mut usize, end: usize) -> Option<String> {
    let op = read_u32_be_advance(blob, cursor, end)?;
    Some(match op {
        0 => "exists".into(),
        1 => format!("= \"{}\"", read_expr_string(blob, cursor, end)?),
        2 => format!("~ \"*{}*\"", read_expr_string(blob, cursor, end)?),
        3 => format!("~ \"{}*\"", read_expr_string(blob, cursor, end)?),
        4 => format!("~ \"*{}\"", read_expr_string(blob, cursor, end)?),
        5 => format!("< \"{}\"", read_expr_string(blob, cursor, end)?),
        6 => format!("> \"{}\"", read_expr_string(blob, cursor, end)?),
        7 => format!("<= \"{}\"", read_expr_string(blob, cursor, end)?),
        8 => format!(">= \"{}\"", read_expr_string(blob, cursor, end)?),
        _ => format!("match({op:#x})"),
    })
}

fn read_u32_be_advance(blob: &[u8], cursor: &mut usize, end: usize) -> Option<u32> {
    if *cursor + 4 > end {
        return None;
    }
    let v = read_u32_be(blob, *cursor);
    *cursor += 4;
    Some(v)
}

/// Length-prefixed UTF-8 string. Strings are padded with NULs to the
/// next 4-byte boundary.
fn read_expr_string(blob: &[u8], cursor: &mut usize, end: usize) -> Option<String> {
    let len = read_u32_be_advance(blob, cursor, end)? as usize;
    if *cursor + len > end {
        return None;
    }
    let s = std::str::from_utf8(&blob[*cursor..*cursor + len])
        .ok()?
        .to_owned();
    *cursor += len;
    // 4-byte alignment padding.
    let pad = (4 - (len & 3)) & 3;
    *cursor += pad;
    Some(s)
}

/// Length-prefixed binary blob (certificate hashes, OIDs). Padded to
/// the next 4-byte boundary just like strings.
fn read_expr_data(blob: &[u8], cursor: &mut usize, end: usize) -> Option<Vec<u8>> {
    let len = read_u32_be_advance(blob, cursor, end)? as usize;
    if *cursor + len > end {
        return None;
    }
    let v = blob[*cursor..*cursor + len].to_vec();
    *cursor += len;
    let pad = (4 - (len & 3)) & 3;
    *cursor += pad;
    Some(v)
}

fn parse_entitlements(blob: &[u8], values: &mut Values) {
    // 8-byte header (magic + length); the rest is XML plist.
    if blob.len() <= 8 {
        return;
    }
    let xml_bytes = &blob[8..];
    if xml_bytes.len() > MAX_ENTITLEMENT_XML_BYTES {
        return;
    }
    let Ok(parsed) = plist::from_bytes::<plist::Value>(xml_bytes) else {
        // Surface raw text as a fallback so the consumer at least sees
        // what was claimed.
        if let Ok(s) = std::str::from_utf8(xml_bytes) {
            put_str(values, "macho.code_signature.entitlements_xml", s);
        }
        return;
    };
    let json = plist_to_json(parsed, 0);
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
    crate::formats::common::bytes_at::u32_be(b, off).unwrap_or(0)
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

fn plist_to_json(value: plist::Value, depth: u8) -> JsonValue {
    use plist::Value as P;
    if depth > MAX_PLIST_DEPTH {
        return JsonValue::Null;
    }
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(format!("{d:?}")),
        P::Array(arr) => JsonValue::Array(
            arr.into_iter()
                .map(|v| plist_to_json(v, depth + 1))
                .collect(),
        ),
        P::Dictionary(dict) => {
            let mut obj = Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v, depth + 1));
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
