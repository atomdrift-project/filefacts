//! Helpers shared across format extractors.

use std::sync::LazyLock;

use serde_json::Value as JsonValue;

use crate::output::{Strings, Text, ValueKey, Values};
use crate::scan::entropy;

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

/// Byte-scan rows one file keeps, earliest first. Each row costs a record
/// and its JSON, and NUL-separated four-byte runs make one row per five
/// input bytes: twenty million rows, and gigabytes, from a 100 MB file. The
/// largest real binaries (browser engines, compiler toolchains) carry about
/// half a million.
pub(super) const MAX_TEXT_ROWS: usize = 2_000_000;

/// stng extraction options. filefacts is the one string-extraction authority
/// for its callers, so it asks stng for the full treatment:
/// - `garbage_filter` drops high-noise runs,
/// - `xor` recovers XOR-deobfuscated strings (key auto-detected),
/// - `caller_provides_symbols` skips stng's symbol pass — filefacts walks the
///   symbol tables itself (`extract_symbols`), the single symbol codepath.
pub(super) fn string_opts_for(xor: XorScan, bytes: &[u8]) -> stng::ExtractOptions {
    // Four bytes is the minimum run `strings(1)` reports.
    let opts = stng::ExtractOptions::new(4)
        .with_garbage_filter(true)
        .with_caller_provides_symbols(true);
    if xor == XorScan::Yes && bytes.len() < XOR_MAX_BYTES {
        opts.with_xor(stng::XorMode::Auto)
    } else {
        opts
    }
}

/// Adopt stng's rows as the `text` tier. The ASCII / UTF-16 split is a view
/// over these rows, derived from each row's `StringMethod`, rather than two
/// separate buffers.
fn push_stng_strings(extracted: Vec<stng::ExtractedString>, strings: &mut Strings) {
    strings.text = Text::capped(extracted, MAX_TEXT_ROWS);
}

/// Return the payload of a malformed UTF-16 wrapper.
///
/// A few script builders prepend a UTF-16 BOM to ordinary UTF-8 source to
/// defeat consumers that choose the decoder from those two bytes alone. Do not
/// reinterpret real UTF-16: ASCII UTF-16 has NUL padding, while this malformed
/// form is valid UTF-8 with no embedded NULs after its BOM. A trailing NUL is
/// tolerated as a text terminator.
fn malformed_utf16_bom_payload(bytes: &[u8]) -> Option<&[u8]> {
    let payload = bytes
        .strip_prefix(&[0xff, 0xfe])
        .or_else(|| bytes.strip_prefix(&[0xfe, 0xff]))?;
    let text_end = payload
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |i| i + 1);
    let text = payload.get(..text_end).unwrap_or_default();
    (!text.contains(&0) && std::str::from_utf8(text).is_ok()).then_some(payload)
}

/// Extract strings from a binary stng parses itself. Used as the fallback when
/// the format handler's own goblin parse failed (malformed input) — see
/// [`extract_binary_strings_from_object`] for the fast path that reuses an
/// already-parsed object.
pub(super) fn extract_binary_strings(bytes: &[u8], strings: &mut Strings, xor: XorScan) {
    let opts = string_opts_for(xor, bytes);
    push_stng_strings(stng::extract_strings_with_options(bytes, &opts), strings);
}

/// Add the strings of a buffer the file does not literally contain.
///
/// [`extract_binary_strings`] *replaces* `strings.text`, because for every
/// ordinary format there is one buffer and one extraction. A carrier that
/// hides text behind an encoding has two: its own bytes, and what decodes out
/// of them. This appends the second set rather than substituting it.
pub(super) fn append_decoded_strings(bytes: &[u8], strings: &mut Strings, xor: XorScan) {
    let opts = string_opts_for(xor, bytes);
    let extracted = stng::extract_strings_with_options(bytes, &opts);
    strings.text.append_rows(&extracted, MAX_TEXT_ROWS);
}

/// Extract strings from a goblin object the caller already parsed, so the
/// binary isn't parsed a second time inside stng. stng re-parses only for
/// `Object::Unknown`; filefacts only ever passes a recognised Mach-O / ELF / PE
/// object here, so the parse is genuinely skipped.
///
/// `layouts` are the binform layouts already read from `bytes`, each with the
/// file offset of the bytes it was read from (a universal Mach-O's slices), so
/// stng need not read any of them again.
pub(super) fn extract_binary_strings_from_object<'d>(
    object: &goblin::Object<'_>,
    layouts: &[stng::Layout<'_, 'd>],
    bytes: &'d [u8],
    strings: &mut Strings,
    xor: XorScan,
) {
    let opts = string_opts_for(xor, bytes);
    push_stng_strings(
        stng::extract_strings_from_parsed(object, layouts, bytes, &opts),
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
/// greppable text — so this is only consulted for [`crate::FileType::is_source_code`].
/// stng scans only input it judges binary, so the gate matters for a script
/// with binary content appended, not for plain source.
pub(super) fn has_xor_intent(bytes: &[u8]) -> bool {
    static XOR_WORD: LazyLock<Option<aho_corasick::AhoCorasick>> = LazyLock::new(|| {
        aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(["xor"])
            .ok()
    });
    memchr::memchr(b'^', bytes).is_some()
        || XOR_WORD.as_ref().is_some_and(|ac| ac.find(bytes).is_some())
}

/// `strings(1)`-tier byte view for a text/source member. Mirrors
/// [`extract_binary_strings`] but for text/source bytes; callers gate source
/// files on [`has_xor_intent`].
pub(super) fn extract_text_strings(bytes: &[u8], strings: &mut Strings, xor: XorScan) {
    if let Some(payload) = malformed_utf16_bom_payload(bytes) {
        let opts = string_opts_for(xor, payload);
        let mut rows = stng::extract_strings_with_options(payload, &opts);
        // Offsets are into the file, past the two-byte BOM.
        for row in &mut rows {
            row.data_offset = row.data_offset.saturating_add(2);
        }
        push_stng_strings(rows, strings);
        return;
    }
    let opts = string_opts_for(xor, bytes);
    push_stng_strings(stng::extract_strings_with_options(bytes, &opts), strings);
}

/// Convenience wrapper for emitting a string-typed value into `values` at a
/// checked key from `value_key!`.
pub(super) fn put_str(values: &mut Values, key: ValueKey, s: impl Into<String>) {
    values.insert_key(key, JsonValue::String(s.into()));
}

/// The path of a compound-file entry, always `/`-separated.
///
/// `cfb` hands back a `PathBuf`, so rendering it joins the components with
/// the *host* separator: a stream inside a storage reads `/VBA/dir` on Unix
/// but `/VBA\dir` on Windows. Every caller here matches these paths against
/// literals from the OLE specs — `VBA/dir`, `/ObjectPool/` — and several
/// publish them as facts, so the host's separator has no business reaching
/// either. Normalising once at the boundary keeps matching and output
/// identical on every platform.
pub(super) fn cfb_entry_path(entry: &cfb::Entry) -> String {
    entry.path().to_string_lossy().replace('\\', "/")
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

/// Whether `name` starts with `prefix`, ignoring ASCII case.
#[must_use]
pub(crate) fn starts_with_ci(name: &str, prefix: &str) -> bool {
    name.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
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
pub(crate) fn stem(name: &str) -> &str {
    // Leading-dot files have no extension to strip.
    let body_start = name.bytes().take_while(|b| *b == b'.').count();
    let body = &name[body_start..];
    let stem_end = body.rfind('.').unwrap_or(body.len());
    &name[..body_start + stem_end]
}

/// Convenience wrapper for emitting an integer-typed value at a checked key.
pub(super) fn put_u64(values: &mut Values, key: ValueKey, n: u64) {
    values.insert_key(key, JsonValue::Number(n.into()));
}

/// Convenience wrapper for emitting a signed-integer value at a checked key
/// (for fields that are conventionally signed, e.g. Unix timestamps).
pub(super) fn put_i64(values: &mut Values, key: ValueKey, n: i64) {
    values.insert_key(key, JsonValue::Number(n.into()));
}

// Bool emissions intentionally absent: a "true/false" kv pair where
// `false` simply means "no data" duplicates what trait authors can
// express with `exists:`. Emit a presence marker (or a richer
// numeric/string value) instead — never a bare boolean that mirrors
// presence/absence.

/// Recover with binform, from the `layout` it read, the functions and calls
/// of a binary whose function view is empty. Returns how many functions it
/// added; `None` when the binary already has functions or binform cannot read
/// it.
pub(super) fn recover_natively(
    layout: Option<&binform::Binary<'_>>,
    symbols: &mut crate::Symbols,
    metrics: &mut crate::output::Metrics,
) -> Option<u32> {
    Some(native(layout, symbols)?.functions.apply(symbols, metrics))
}

/// binform's answer for the binary `layout` describes, or `None` when
/// `symbols` already holds a function inventory (a symbol table, Go's
/// pclntab) or binform cannot read the binary.
pub(super) fn native(
    layout: Option<&binform::Binary<'_>>,
    symbols: &crate::Symbols,
) -> Option<crate::functions::Native> {
    if has_functions(symbols) {
        return None;
    }
    crate::functions::recover(layout)
}

/// Whether `symbols` already holds a function inventory: a symbol table's,
/// Go's pclntab's, or binform's.
pub(crate) fn has_functions(symbols: &crate::Symbols) -> bool {
    symbols
        .iter_kind(crate::SymbolKind::Function)
        .next()
        .is_some()
}

/// The name an import or export by ordinal alone goes by in the typed
/// views, the spelling binform gives PE exports: `Ordinal_<n>`.
pub(super) fn unnamed_ordinal(ordinal: impl std::fmt::Display) -> String {
    format!("Ordinal_{ordinal}")
}

/// The layout binform reads from `bytes`: the section, import and export
/// tables every binary extractor takes, the functions binform recovers and
/// the tables stng reads. Read once per binary (per slice of a universal
/// one) and shared by all of them.
///
/// When binform cannot read it, the reason is returned rather than recorded:
/// a caller records it only when goblin read the file, since goblin's own
/// error otherwise says the same. A panic in binform is caught and returned
/// the same way, so goblin's facts survive it.
pub(super) fn read_layout(bytes: &[u8]) -> Result<binform::Binary<'_>, String> {
    crate::panic_guard::catch_infallible(|| binform::parse(bytes))
        .map_err(|panic| format!("layout: binform panicked: {panic}"))?
        .map_err(|error| format!("layout: {error}"))
}

/// Lowercase hex encoding of arbitrary bytes. Used wherever a hash
/// digest or serial number needs a stable, comparable representation.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    // Nibbles are always below the radix, so no digit is dropped.
    out.extend(
        bytes
            .iter()
            .flat_map(|&b| [b >> 4, b & 0x0f])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16)),
    );
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

/// Shannon entropy of the file bytes a section header places at
/// `offset..offset + size`, clamped to the end of the file. 0.0 for an empty
/// section or one that starts past EOF.
pub(super) fn section_entropy(bytes: &[u8], offset: u64, size: u64) -> f64 {
    let Ok(start) = usize::try_from(offset) else {
        return 0.0;
    };
    let len = usize::try_from(size).unwrap_or(usize::MAX);
    let end = start.saturating_add(len).min(bytes.len());
    bytes.get(start..end).map_or(0.0, entropy::shannon)
}

/// Format a 16-byte Microsoft GUID as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
/// The first three fields are stored little-endian and the last two
/// byte-for-byte, so the result matches `dumpbin`, symchk and `ikdasm`.
pub(super) fn format_guid(b: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let data2 = u16::from_le_bytes([b[4], b[5]]);
    let data3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{}-{}",
        hex_encode(&b[8..10]),
        hex_encode(&b[10..16])
    )
}

/// Read an unsigned LEB128 (Go's "uvarint") at `*offset`, advancing past it.
/// Mirrors `scroll::Uleb128::read`: `None` when the encoding is truncated or
/// runs past ten bytes.
pub(super) fn read_uleb128(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*offset)?;
        *offset += 1;
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

/// Nesting honoured by [`plist_to_json`]. Bounds stack use on plists whose
/// value graph nests arrays and dictionaries beyond what real Apple artifacts
/// emit.
const MAX_PLIST_DEPTH: u8 = 64;

/// Project a parsed plist (an embedded `Info.plist`, code-signing
/// entitlements) into JSON. Nodes deeper than [`MAX_PLIST_DEPTH`] and types
/// with no JSON analogue (`Data`, `Uid`) become `null`.
pub(super) fn plist_to_json(value: plist::Value, depth: u8) -> JsonValue {
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
        P::Dictionary(dict) => JsonValue::Object(
            dict.into_iter()
                .map(|(k, v)| (k, plist_to_json(v, depth + 1)))
                .collect(),
        ),
        _ => JsonValue::Null,
    }
}

#[cfg(test)]
mod tests;
