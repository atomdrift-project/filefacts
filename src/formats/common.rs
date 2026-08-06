//! Helpers shared across format extractors.

use serde_json::Value as JsonValue;

use crate::output::{Strings, Text, Values};
use crate::scan::ascii;

/// Whether stng's XOR seed search runs for a member.
///
/// XOR string obfuscation is a *payload* technique. It appears in executable
/// code — ELF, PE, Mach-O — and in shell/JS/Python source that necessarily
/// ships its own decoder, and effectively never in container, document, image
/// or bytecode formats. On those the scan is pure cost, and on high-entropy
/// content (a compressed disk image, a media blob) its short anchors match by
/// chance, so each hit also triggers 4 KB of speculative decoding and the
/// false positives that come with it.
///
/// Every extraction site states its answer explicitly so a newly added format
/// has to make the choice rather than inherit one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum XorScan {
    /// Executable code or a script carrying XOR intent.
    Yes,
    /// Everything else.
    No,
}

/// Ceiling on XOR scanning. Beyond this the scan's cost outgrows any plausible
/// yield — hand-rolled XOR string obfuscation is a small-payload technique, and
/// a single member this large is a bundled runtime or media blob.
const XOR_MAX_BYTES: usize = 300 << 20;

impl XorScan {
    fn runs_on(self, bytes: &[u8]) -> bool {
        self == Self::Yes && bytes.len() < XOR_MAX_BYTES
    }
}

/// stng extraction options. filefacts is the
/// single string-extraction authority for cleave, so these mirror the rich opts
/// cleave used to pass to stng directly:
/// - `garbage_filter` drops high-noise runs,
/// - `xor` recovers XOR-deobfuscated strings (key auto-detected),
/// - `caller_provides_symbols` skips stng's symbol pass — filefacts walks the
///   symbol tables itself (`extract_symbols`), the single symbol codepath.
fn string_opts_for(xor: XorScan, bytes: &[u8]) -> stng::ExtractOptions {
    let opts = stng::ExtractOptions::new(ascii::DEFAULT_MIN_LEN)
        .with_garbage_filter(true)
        .with_caller_provides_symbols(true);
    if xor.runs_on(bytes) {
        opts.with_xor(None)
    } else {
        opts
    }
}

/// Adopt stng's shared string rows as the `text` tier. stng owns the
/// allocation (via its string cache); filefacts holds the `Arc` so the rows are
/// never copied here, and downstream consumers borrow the same allocation. The
/// ASCII / UTF-16 split is a view over these rows, derived from each row's
/// `StringMethod`, rather than two separate buffers.
fn push_stng_strings(
    extracted: std::sync::Arc<[stng::ExtractedString]>,
    text_key: Option<String>,
    strings: &mut Strings,
) {
    strings.text = Text::from_rows(extracted);
    strings.text_key = text_key;
}

/// Extract strings from a binary stng parses itself. Used as the fallback when
/// the format handler's own goblin parse failed (malformed input) — see
/// [`extract_binary_strings_from_object`] for the fast path that reuses an
/// already-parsed object.
pub(super) fn extract_binary_strings(bytes: &[u8], strings: &mut Strings, xor: XorScan) {
    let opts = string_opts_for(xor, bytes);
    push_stng_strings(
        stng::cached_strings_with_options(bytes, &opts),
        stng::cache_key_for(bytes, &opts),
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
    xor: XorScan,
) {
    let opts = string_opts_for(xor, bytes);
    push_stng_strings(
        stng::cached_strings_from_object(object, bytes, &opts),
        stng::cache_key_for(bytes, &opts),
        strings,
    );
}

/// Cheap pre-scan for XOR intent in source/script bytes. A self-contained
/// script that ships an XOR-encoded payload must also carry the code that
/// *decodes* it in the same file, so the absence of any XOR operator or keyword
/// means stng's XOR auto-detect scan would only burn cycles finding nothing.
/// Indicators (either is enough):
/// - the `^` byte — the bitwise-XOR operator in C/JS/Python/Java/Go/Rust/…,
/// - the substring `xor` (case-insensitive) — `xor`, VBScript `Xor`,
///   PowerShell `-bxor`, `.xor(`, etc.
///
/// Binaries are never gated this way — their decode logic is machine code, not
/// greppable text — so this is only consulted for [`FileType::is_source_code`].
pub(super) fn has_xor_intent(bytes: &[u8]) -> bool {
    if memchr::memchr(b'^', bytes).is_some() {
        return true;
    }
    static XOR_WORD: std::sync::OnceLock<Option<aho_corasick::AhoCorasick>> =
        std::sync::OnceLock::new();
    XOR_WORD
        .get_or_init(|| {
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(["xor"])
                .ok()
        })
        .as_ref()
        .is_some_and(|ac| ac.find(bytes).is_some())
}

/// `strings(1)`-tier byte view for a text/source member. Mirrors
/// [`extract_binary_strings`] but for text/source bytes; callers gate source
/// files on [`has_xor_intent`].
pub(super) fn extract_text_strings(bytes: &[u8], strings: &mut Strings, xor: XorScan) {
    let opts = string_opts_for(xor, bytes);
    push_stng_strings(
        stng::cached_strings_with_options(bytes, &opts),
        stng::cache_key_for(bytes, &opts),
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
    use super::{basename, has_xor_intent, hex_encode, stem};

    #[test]
    fn xor_intent_detects_operator_and_keyword() {
        // bitwise-XOR operator (C/JS/Python/…)
        assert!(has_xor_intent(b"for (i=0;i<n;i++) out[i] = buf[i] ^ key;"));
        // `xor` keyword, any case (xor / VBScript Xor / PowerShell -bxor)
        assert!(has_xor_intent(b"result = a xor b"));
        assert!(has_xor_intent(b"$d = $b -bxor 0x42"));
        assert!(has_xor_intent(b"value = data.XOR(key)"));
    }

    #[test]
    fn xor_intent_absent_in_benign_source() {
        // A plain comment / coordinate string of the kind that previously
        // mis-decoded into speculative "XOR payload" false positives.
        assert!(!has_xor_intent(
            b"// Build data=\"Name:v1,v2;...\" from series"
        ));
        assert!(!has_xor_intent(
            b"10504 1900 10802 2169 L 11697 1363 C 11971"
        ));
        assert!(!has_xor_intent(b"const greeting = `hello ${name}`;"));
        assert!(!has_xor_intent(b""));
    }

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
