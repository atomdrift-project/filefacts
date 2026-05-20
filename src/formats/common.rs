//! Helpers shared across format extractors.

use serde_json::Value as JsonValue;

use crate::output::{Strings, Values};
use crate::scan::ascii;
use crate::scan::utf16;

/// Push every ASCII run in `bytes` into `strings.ascii`, applying the
/// scanner's default minimum length.
pub(super) fn extract_ascii_strings(bytes: &[u8], strings: &mut Strings) {
    strings
        .ascii
        .extend(ascii::extract_runs(bytes, ascii::DEFAULT_MIN_LEN));
}

/// Push every UTF-16LE run in `bytes` into `strings.utf16le`.
pub(super) fn extract_utf16_strings(bytes: &[u8], strings: &mut Strings) {
    strings
        .utf16le
        .extend(utf16::extract_runs(bytes, utf16::DEFAULT_MIN_LEN));
}

/// Language-aware binary string extraction via the `stng` crate.
/// Used by PE/ELF/Mach-O extractors in place of the raw
/// `extract_ascii_strings` byte-scan: stng's pointer+length-aware
/// extraction dedupes Go/Rust packed strings, recovers XOR-deobfuscated
/// runs, and decodes base64/hex/url payloads. UTF-16-recovered runs
/// land in `strings.utf16le`; everything else in `strings.ascii`.
///
/// `method` is set only for *transformation* methods (the string went
/// through a decoder: `base64`, `xor`, `unicode-escape`, …) — the
/// pure recovery methods (raw scan, instruction-pattern, structure)
/// add noise and aren't worth tagging. Convention: kebab-case for
/// multi-word encoding names (`base64-obf`, `unicode-escape`), `+` to
/// separate chained encodings (`base64+zlib`).
pub(super) fn extract_binary_strings(bytes: &[u8], strings: &mut Strings) {
    use crate::output::{ExtractedString, StringCategory};
    let opts = stng::ExtractOptions {
        min_length: ascii::DEFAULT_MIN_LEN,
        ..Default::default()
    };
    let extracted = stng::extract_strings_with_options(bytes, &opts);
    for s in extracted {
        let is_utf16 = matches!(
            s.method,
            stng::StringMethod::WideString
                | stng::StringMethod::Utf16LeDecode
                | stng::StringMethod::Utf16BeDecode
        );
        let category = if is_utf16 {
            StringCategory::Utf16Le
        } else {
            StringCategory::Ascii
        };
        let entry = ExtractedString {
            category,
            text: s.value,
            offset: s.data_offset as usize,
            method: stng_method_label(s.method).map(str::to_string),
            kind: s.kind.map(stng_kind_label).map(str::to_string),
            section: s.section,
        };
        if is_utf16 {
            strings.utf16le.push(entry);
        } else {
            strings.ascii.push(entry);
        }
    }
}

/// Map stng's `StringMethod` to a canonical kebab-case encoding name.
/// Only decoder/transformation methods are surfaced; pure recovery
/// methods (raw scan, structure, instruction-pattern) return `None`
/// because trait engines don't gain anything from "this string was
/// found by looking at bytes". Convention matches cleave's existing
/// `encoding_chain` values so `type: kv path: strings.ascii[*].method`
/// rules port across without renaming.
fn stng_method_label(m: stng::StringMethod) -> Option<&'static str> {
    use stng::StringMethod as M;
    Some(match m {
        // Transformation methods — the string went through a decoder.
        M::Base64Decode => "base64",
        M::Base64ObfuscatedDecode => "base64-obf",
        M::HexDecode => "hex",
        M::UrlDecode => "url",
        M::Base32Decode => "base32",
        M::Base85Decode => "base85",
        M::UnicodeEscapeDecode => "unicode-escape",
        M::XorDecode => "xor",
        M::XorStackPair => "xor-stack-pair",
        M::StackString => "stack",
        M::WideString => "wide",
        M::Utf16LeDecode => "utf16-le",
        M::Utf16BeDecode => "utf16-be",
        M::SpacedAscii => "spaced-ascii",
        M::ScriptDecode => "script",
        M::CodeSignature => "code-signature",
        M::PclntabSymbol => "pclntab",
        // Pure recovery — not interesting to annotate.
        M::Structure
        | M::InstructionPattern
        | M::RawScan
        | M::Heuristic
        | M::R2String
        | M::R2Symbol => return None,
        _ => return None,
    })
}

/// Map stng's classifier `StringKind` to a kebab-case label. Mirrors
/// the method-label convention. Coverage focuses on malware-detection
/// useful kinds; unrecognised variants pass through as `other` so
/// trait engines can fire on the negative (`kind: other` =
/// classifier ran but didn't match anything specific).
fn stng_kind_label(k: stng::StringKind) -> &'static str {
    use stng::StringKind as K;
    match k {
        K::FuncName => "func-name",
        K::FilePath => "file-path",
        K::MapKey => "map-key",
        K::Error => "error",
        K::EnvVar => "env-var",
        K::Url => "url",
        K::Path => "path",
        K::Arg => "arg",
        K::Ident => "ident",
        K::Garbage => "garbage",
        K::Section => "section",
        K::Import => "import",
        K::Export => "export",
        K::IP => "ip",
        K::IPPort => "ip-port",
        K::Hostname => "hostname",
        K::ShellCmd => "shell-cmd",
        K::AppleScript => "applescript",
        K::PythonCode => "python-code",
        K::JavaScriptCode => "javascript-code",
        K::PhpCode => "php-code",
        K::PowerShellCode => "powershell-code",
        K::SuspiciousPath => "suspicious-path",
        K::Registry => "registry",
        K::Base58 => "base58",
        K::Base85 => "base85",
        K::Overlay => "overlay",
        K::CryptoWallet => "crypto-wallet",
        K::MiningPool => "mining-pool",
        K::Email => "email",
        K::TorAddress => "tor-address",
        K::CTFFlag => "ctf-flag",
        K::SQLInjection => "sql-injection",
        K::XSSPayload => "xss-payload",
        K::CommandInjection => "command-injection",
        K::JWT => "jwt",
        K::APIKey => "api-key",
        K::Mutex => "mutex",
        K::GUID => "guid",
        K::Hash => "hash",
        K::RansomNote => "ransom-note",
        K::LDAPPath => "ldap-path",
        K::OverlayWide => "overlay-wide",
        K::StackString => "stack-string",
        K::Entitlement => "entitlement",
        K::AppId => "app-id",
        K::EntitlementsXml => "entitlements-xml",
        K::XorKey => "xor-key",
        _ => "other",
    }
}

/// Convenience wrapper for emitting a string-typed value into `values`.
pub(super) fn put_str(values: &mut Values, path: &str, s: impl Into<String>) {
    values.insert(path, JsonValue::String(s.into()));
}

/// Convenience wrapper for emitting an integer-typed value.
pub(super) fn put_u64(values: &mut Values, path: &str, n: u64) {
    values.insert(path, JsonValue::Number(n.into()));
}

/// Convenience wrapper for emitting a signed-integer value (for fields
/// that are conventionally signed, e.g. Unix timestamps).
pub(super) fn put_i64(values: &mut Values, path: &str, n: i64) {
    values.insert(path, JsonValue::Number(n.into()));
}

// Bool emissions intentionally absent: a "true/false" kv pair where
// `false` simply means "no data" duplicates what trait authors can
// express with `exists:`. Emit a presence marker (or a richer
// numeric/string value) instead — never a bare boolean that mirrors
// presence/absence.

/// Lowercase hex encoding of arbitrary bytes. Used wherever a hash
/// digest or serial number needs a stable, comparable representation.
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hex_encode;

    #[test]
    fn hex_encode_known_vectors() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }
}
