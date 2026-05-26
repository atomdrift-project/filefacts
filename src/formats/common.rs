//! Helpers shared across format extractors.

use serde_json::Value as JsonValue;

use crate::output::{Strings, Values};
use crate::scan::ascii;
use crate::scan::utf16;

/// Push every ASCII run in `bytes` into the byte-scan Text view,
/// applying the scanner's default minimum length.
pub(super) fn extract_ascii_strings(bytes: &[u8], strings: &mut Strings) {
    strings
        .text
        .ascii
        .extend(ascii::extract_runs(bytes, ascii::DEFAULT_MIN_LEN));
}

/// Push every UTF-16LE run in `bytes` into the byte-scan Text view.
pub(super) fn extract_utf16_strings(bytes: &[u8], strings: &mut Strings) {
    strings
        .text
        .utf16le
        .extend(utf16::extract_runs(bytes, utf16::DEFAULT_MIN_LEN));
}

/// Language-aware binary string extraction via the `stng` crate.
/// Used by PE/ELF/Mach-O extractors in place of the raw
/// `extract_ascii_strings` byte-scan: stng's pointer+length-aware
/// extraction dedupes Go/Rust packed strings, recovers XOR-deobfuscated
/// runs, and decodes base64/hex/url payloads. UTF-16-recovered runs
/// land in the Text.utf16le partition; everything else in Text.ascii.
///
/// `method` is set only for *transformation* methods (the string went
/// through a decoder: `base64`, `xor`, `unicode-escape`, …) — the
/// pure recovery methods (raw scan, instruction-pattern, structure)
/// add noise and aren't worth tagging.
pub(super) fn extract_binary_strings(bytes: &[u8], strings: &mut Strings) {
    use crate::output::ExtractedString;
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
        let entry = ExtractedString {
            text: s.value,
            offset: s.data_offset as usize,
            method: stng_method_label(s.method).map(str::to_string),
            kind: s.kind.map(stng_kind_label).map(str::to_string),
            section: s.section,
            ..ExtractedString::default()
        };
        if is_utf16 {
            strings.text.utf16le.push(entry);
        } else {
            strings.text.ascii.push(entry);
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

/// Return the last path segment of `path`, treating both `/` and `\`
/// as separators. `"C:\\foo\\bar.exe"` and `"/tmp/bar.exe"` both yield
/// `"bar.exe"`. Returns the input unchanged if no separator is found.
#[must_use]
pub(crate) fn basename(path: &str) -> &str {
    match path.rfind(['/', '\\']) {
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

/// Return `name` with its trailing `.<ext>` removed, where `<ext>`
/// contains no further `.`. Matches Python's `pathlib.Path.stem`:
/// a leading dot is *not* an extension separator (so `.gitignore`
/// has stem `.gitignore`), and only the last extension is stripped
/// (so `foo.tar.gz` has stem `foo.tar`).
///
/// Pure function on basenames; callers should pass the output of
/// [`basename`] when starting from a path.
#[must_use]
pub(crate) fn stem(name: &str) -> String {
    // Leading-dot files have no extension to strip.
    let body_start = name.bytes().take_while(|b| *b == b'.').count();
    let body = &name[body_start..];
    let stem_end = body.rfind('.').unwrap_or(body.len());
    format!("{}{}", &name[..body_start], &body[..stem_end])
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

/// Run rizin recovery when the static parse produced an empty symbol
/// table — the canonical "stripped binary" signal goblin can't recover
/// from. Shared by PE / ELF / Mach-O extractors. No-op when rizin
/// isn't on PATH or when goblin already populated any symbol kind.
pub(super) fn rizin_fallback(
    bytes: &[u8],
    symbols: &mut crate::Symbols,
    metrics: &mut crate::output::Metrics,
) {
    if !symbols.is_empty() {
        return;
    }
    if let Some(recovery) = crate::rizin::recover(bytes) {
        recovery.apply(symbols, metrics);
    }
}

/// Extended rizin fallback for PE: tries to recover sections as well
/// as symbols, and emits `*.recovered_*` metrics under the supplied
/// prefix so callers can attribute the recovered counts in trait
/// rules.
///
/// The caller passes the metric prefix (`"pe"`, `"elf"`, `"macho"`)
/// so the emitted keys are `{prefix}.recovered_sections` etc. The
/// path stays tool-agnostic — if the disassembler ever swaps from
/// rizin to radare2 / Ghidra the schema doesn't ripple.
pub(super) fn rizin_fallback_with_sections(
    bytes: &[u8],
    symbols: &mut crate::Symbols,
    sections: &mut Vec<crate::output::Section>,
    metrics: &mut crate::output::Metrics,
    metric_prefix: &str,
) {
    // Skip the spawn entirely when goblin already gave us *anything* —
    // any symbol or any section. Matches cleave's historical "all
    // empty → run rizin" gate.
    if !symbols.is_empty() || !sections.is_empty() {
        return;
    }
    let Some(recovery) = crate::rizin::recover(bytes) else {
        return;
    };
    let counts = recovery.apply_with_sections(symbols, sections, metrics);
    if counts.imports > 0 {
        metrics.insert(
            format!("{metric_prefix}.recovered_imports"),
            f64::from(counts.imports),
        );
    }
    if counts.exports > 0 {
        metrics.insert(
            format!("{metric_prefix}.recovered_exports"),
            f64::from(counts.exports),
        );
    }
    if counts.functions > 0 {
        metrics.insert(
            format!("{metric_prefix}.recovered_functions"),
            f64::from(counts.functions),
        );
    }
    if counts.sections > 0 {
        metrics.insert(
            format!("{metric_prefix}.recovered_sections"),
            f64::from(counts.sections),
        );
    }
}

/// Panic-safe fixed-width integer reads. Each helper bounds-checks
/// via `slice::get`, so an out-of-range offset returns `None` instead
/// of panicking — the right idiom for parsing untrusted input where
/// callers may have a bug in their length-check.
///
/// Per-format extractors that need a non-`Option` return type can
/// wrap the call in `.unwrap_or(0)` to keep their existing signature;
/// the panic surface is gone either way.
pub(super) mod bytes_at {
    /// Read a little-endian `u16` at `off`.
    #[inline]
    pub(crate) fn u16_le(b: &[u8], off: usize) -> Option<u16> {
        b.get(off..off.checked_add(2)?)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes)
    }

    /// Read a little-endian `u32` at `off`.
    #[inline]
    pub(crate) fn u32_le(b: &[u8], off: usize) -> Option<u32> {
        b.get(off..off.checked_add(4)?)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
    }

    /// Read a big-endian `u32` at `off`.
    #[inline]
    pub(crate) fn u32_be(b: &[u8], off: usize) -> Option<u32> {
        b.get(off..off.checked_add(4)?)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes)
    }

    /// Read a little-endian `u64` at `off`.
    #[inline]
    pub(crate) fn u64_le(b: &[u8], off: usize) -> Option<u64> {
        b.get(off..off.checked_add(8)?)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
    }
}

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
    use super::{basename, hex_encode, stem};

    #[test]
    fn hex_encode_known_vectors() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn basename_unix_path() {
        assert_eq!(basename("/tmp/foo/bar.exe"), "bar.exe");
    }

    #[test]
    fn basename_windows_path() {
        assert_eq!(basename("C:\\Users\\bob\\stealer.exe"), "stealer.exe");
    }

    #[test]
    fn basename_mixed_separators() {
        // Windows forward-slash convention.
        assert_eq!(basename("C:/Users\\bob/run.exe"), "run.exe");
    }

    #[test]
    fn basename_no_separator() {
        assert_eq!(basename("foo.exe"), "foo.exe");
    }

    #[test]
    fn basename_trailing_separator_returns_empty() {
        // Pure mechanical behavior: the segment after the last separator is "".
        // Callers should normalize trailing separators before calling.
        assert_eq!(basename("foo/"), "");
    }

    #[test]
    fn stem_simple() {
        assert_eq!(stem("update.exe"), "update");
    }

    #[test]
    fn stem_strips_only_last_extension() {
        // Python pathlib semantics: stem of "foo.tar.gz" is "foo.tar".
        assert_eq!(stem("foo.tar.gz"), "foo.tar");
    }

    #[test]
    fn stem_no_extension() {
        assert_eq!(stem("Makefile"), "Makefile");
    }

    #[test]
    fn stem_leading_dot_is_not_extension() {
        // .gitignore is a hidden file, not "extension only".
        assert_eq!(stem(".gitignore"), ".gitignore");
        // ..foo has stem ..foo for the same reason.
        assert_eq!(stem("..foo"), "..foo");
    }

    #[test]
    fn stem_dotfile_with_extension() {
        // .config.json: leading-dot prefix preserved, .json stripped.
        assert_eq!(stem(".config.json"), ".config");
    }

    #[test]
    fn stem_empty_string() {
        assert_eq!(stem(""), "");
    }
}
