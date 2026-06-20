//! Helpers shared across format extractors.

use serde_json::Value as JsonValue;

use crate::output::{Strings, Values};
use crate::scan::ascii;

/// stng extraction options. filefacts is the
/// single string-extraction authority for cleave, so these mirror the rich opts
/// cleave used to pass to stng directly:
/// - `garbage_filter` drops high-noise runs,
/// - `xor` recovers XOR-deobfuscated strings (key auto-detected),
/// - `caller_provides_symbols` skips stng's symbol pass — filefacts walks the
///   symbol tables itself (`extract_symbols`), the single symbol codepath.
fn string_opts() -> stng::ExtractOptions {
    stng::ExtractOptions::new(ascii::DEFAULT_MIN_LEN)
        .with_garbage_filter(true)
        .with_xor(None)
        .with_caller_provides_symbols(true)
}

/// Partition stng's extracted strings into the UTF-16 / ASCII buckets,
/// retaining the raw typed `stng::ExtractedString` rows (the consumer reads
/// stng's `StringKind`/`StringMethod` directly).
fn push_stng_strings(extracted: Vec<stng::ExtractedString>, strings: &mut Strings) {
    for s in extracted {
        let is_utf16 = matches!(
            s.method,
            stng::StringMethod::WideString
                | stng::StringMethod::Utf16LeDecode
                | stng::StringMethod::Utf16BeDecode
        );
        if is_utf16 {
            strings.text.utf16le.push(s);
        } else {
            strings.text.ascii.push(s);
        }
    }
}

/// Extract strings from a binary stng parses itself. Used as the fallback when
/// the format handler's own goblin parse failed (malformed input) — see
/// [`extract_binary_strings_from_object`] for the fast path that reuses an
/// already-parsed object.
pub(super) fn extract_binary_strings(bytes: &[u8], strings: &mut Strings) {
    push_stng_strings(
        stng::extract_strings_with_options(bytes, &string_opts()),
        strings,
    );
}

/// Extract strings from a goblin object the caller already parsed, so the
/// binary isn't parsed a second time inside stng. stng re-parses only for
/// `Object::Unknown`; filefacts only ever passes a recognised Mach-O / ELF / PE
/// object here, so the parse is genuinely skipped.
pub(super) fn extract_binary_strings_from_object(
    object: &goblin::Object<'_>,
    bytes: &[u8],
    strings: &mut Strings,
) {
    push_stng_strings(
        stng::extract_strings_from_object(object, bytes, &string_opts()),
        strings,
    );
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
    analysis: crate::rizin::Analysis,
) {
    if !symbols.is_empty() {
        return;
    }
    match crate::rizin::recover(bytes, analysis) {
        Some(recovery) => {
            recovery.apply(symbols, metrics);
        }
        None => note_incomplete_recovery(metrics),
    }
}

/// Record that rizin *should* have recovered symbols here but its run
/// didn't complete. Fires only when rizin is on PATH — i.e. the cache
/// key (via [`crate::rizin::cache_fingerprint`]) claims rizin-grade
/// recovery, yet this run produced nothing because rizin timed out, was
/// killed on the output cap, was muted, or was skipped by the size gate.
/// The empty table is an artefact of this run, not of the bytes, so the
/// `binary.rizin_incomplete` marker lets a cache consumer treat the
/// payload as [`crate::cache::Computed::Transient`] and refuse to persist
/// a poisoned entry (see [`crate::ParsedFile::rizin_recovery_incomplete`]).
/// When rizin is absent the no-rizin result is correct for the
/// environment — and keyed as such — so nothing is recorded.
fn note_incomplete_recovery(metrics: &mut crate::output::Metrics) {
    if crate::rizin::available() {
        metrics.insert("binary.rizin_incomplete", 1.0);
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
    // PE recovery has no cheap complete-function-table signal (no Go pclntab),
    // so it always needs the deep discovery pass.
    let recovery = match crate::rizin::recover(bytes, crate::rizin::Analysis::Deep) {
        Some(recovery) => recovery,
        None => {
            note_incomplete_recovery(metrics);
            return;
        }
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

/// Decode a single ASCII hex digit to its 0–15 value, or `None` if the
/// byte is not `[0-9a-fA-F]`.
pub(super) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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
