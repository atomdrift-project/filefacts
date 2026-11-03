//! Helpers shared across format extractors.

use crate::functions::RecoveryCounts;
use crate::metric;
use serde_json::Value as JsonValue;

use crate::output::{Section, Strings, Text, ValueKey, Values};
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

impl XorScan {
    fn runs_on(self, bytes: &[u8]) -> bool {
        self == Self::Yes && bytes.len() < XOR_MAX_BYTES
    }
}

/// stng extraction options. filefacts is the one string-extraction authority
/// for its callers, so it asks stng for the full treatment:
/// - `garbage_filter` drops high-noise runs,
/// - `xor` recovers XOR-deobfuscated strings (key auto-detected),
/// - `caller_provides_symbols` skips stng's symbol pass — filefacts walks the
///   symbol tables itself (`extract_symbols`), the single symbol codepath.
fn string_opts_for(xor: XorScan, bytes: &[u8]) -> stng::ExtractOptions {
    // Four bytes is the minimum run `strings(1)` reports.
    let opts = stng::ExtractOptions::new(4)
        .with_garbage_filter(true)
        .with_caller_provides_symbols(true);
    if xor.runs_on(bytes) {
        opts.with_xor(stng::XorMode::Auto)
    } else {
        opts
    }
}

/// Adopt stng's rows as the `text` tier. The ASCII / UTF-16 split is a view
/// over these rows, derived from each row's `StringMethod`, rather than two
/// separate buffers.
fn push_stng_strings(extracted: Vec<stng::ExtractedString>, strings: &mut Strings) {
    strings.text = Text::from_rows(extracted.into());
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

fn extract_malformed_utf16_bom_text_strings(
    bytes: &[u8],
    strings: &mut Strings,
    xor: XorScan,
) -> bool {
    let Some(payload) = malformed_utf16_bom_payload(bytes) else {
        return false;
    };
    let opts = string_opts_for(xor, payload);
    let mut rows = stng::extract_strings_with_options(payload, &opts);
    for row in &mut rows {
        row.data_offset = row.data_offset.saturating_add(2);
    }
    push_stng_strings(rows, strings);
    true
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
    if !extracted.is_empty() {
        strings.text.append_rows(&extracted);
    }
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
        stng::extract_strings_from_object(object, bytes, &opts),
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
    if extract_malformed_utf16_bom_text_strings(bytes, strings, xor) {
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

/// Whether `name` ends with `suffix`, ignoring ASCII case. Member names from
/// a hostile archive arrive in any case, and the readers that matter match
/// them case-insensitively: Windows (`.PYD`), OPC part names (`.XML`,
/// `.RELS`), and the JDK's `META-INF/*.SF` lookup.
#[must_use]
pub(crate) fn ends_with_ci(name: &str, suffix: &str) -> bool {
    name.len()
        .checked_sub(suffix.len())
        .and_then(|start| name.as_bytes().get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix.as_bytes()))
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
pub(crate) fn stem(name: &str) -> String {
    // Leading-dot files have no extension to strip.
    let body_start = name.bytes().take_while(|b| *b == b'.').count();
    let body = &name[body_start..];
    let stem_end = body.rfind('.').unwrap_or(body.len());
    format!("{}{}", &name[..body_start], &body[..stem_end])
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

/// Recover with binform what the format parser did not supply: the
/// functions and calls of a binary whose function view is empty, and the
/// import, export and section views goblin left empty (`sections` is given
/// only by PE, the one format where goblin can fail to read the table and
/// still extract). Returns what it added; `None` when the binary already
/// has functions or binform cannot read it.
pub(super) fn recover_natively(
    bytes: &[u8],
    symbols: &mut crate::Symbols,
    sections: Option<&mut Vec<Section>>,
    metrics: &mut crate::output::Metrics,
) -> Option<RecoveryCounts> {
    Some(apply_native(
        native(bytes, symbols)?,
        symbols,
        sections,
        metrics,
    ))
}

/// binform's answer for `bytes`, or `None` when `symbols` already holds a
/// function inventory (a symbol table, Go's pclntab) or binform cannot read
/// the binary.
pub(super) fn native(bytes: &[u8], symbols: &crate::Symbols) -> Option<crate::functions::Native> {
    if symbols
        .iter()
        .any(|symbol| symbol.kind() == crate::SymbolKind::Function)
    {
        return None;
    }
    crate::functions::recover(bytes)
}

/// Fill the typed views the format parser left empty from binform's
/// answer: imports when it found none, exports likewise, the functions and
/// their calls, and the section table when `sections_out` is given and
/// empty (a PE whose section table the native parser could not read).
pub(super) fn apply_native(
    native: crate::functions::Native,
    symbols: &mut crate::Symbols,
    sections_out: Option<&mut Vec<Section>>,
    metrics: &mut crate::output::Metrics,
) -> RecoveryCounts {
    use crate::output::{SectionFlag, Symbol, SymbolKind};
    let mut counts = RecoveryCounts::default();
    let had_imports = symbols.iter().any(|s| s.kind() == SymbolKind::Import);
    let had_exports = symbols.iter().any(|s| s.kind() == SymbolKind::Export);
    if !had_imports {
        for import in native.imports {
            // An import by ordinal from a DLL whose ordinals are stable goes
            // by the name the DLL exports there.
            let name = import
                .ordinal
                .zip(import.library.as_deref())
                .and_then(|(ordinal, dll)| {
                    super::pe::imports::known_ordinal(&dll.to_ascii_lowercase(), ordinal)
                })
                .map_or(import.name, str::to_owned);
            symbols.push(Symbol::Import {
                name,
                alias: None,
                library: import.library,
                offset: import.slot,
                ordinal: import.ordinal.map(u32::from),
            });
            counts.imports = counts.imports.saturating_add(1);
        }
    }
    if !had_exports {
        for export in native.exports {
            symbols.push(Symbol::Export {
                name: export.name,
                offset: Some(export.addr),
                ordinal: None,
                forward_to: export.forward,
            });
            counts.exports = counts.exports.saturating_add(1);
        }
    }
    counts.functions = native.functions.apply(symbols, metrics);
    if let Some(sections_out) = sections_out
        && sections_out.is_empty()
    {
        for section in native.sections {
            let flags = [
                (section.readable, SectionFlag::Readable),
                (section.writable, SectionFlag::Writable),
                (section.executable, SectionFlag::Executable),
            ]
            .into_iter()
            .filter_map(|(set, flag)| set.then_some(flag))
            .collect();
            sections_out.push(Section {
                name: section.name,
                vaddr: section.addr,
                vsize: section.size,
                file_offset: section.offset,
                file_size: section.file_size,
                flags,
                flags_raw: None,
                entropy: None,
            });
            counts.sections = counts.sections.saturating_add(1);
        }
    }
    counts
}

/// Emit the `pe.recovered_*_count` metrics: how many entries of each view
/// came from binform rather than goblin.
pub(super) fn recovered_counts(counts: RecoveryCounts, metrics: &mut crate::output::Metrics) {
    for (key, count) in [
        (metric!("pe.recovered_import_count"), counts.imports),
        (metric!("pe.recovered_export_count"), counts.exports),
        (metric!("pe.recovered_function_count"), counts.functions),
        (metric!("pe.recovered_section_count"), counts.sections),
    ] {
        if count > 0 {
            metrics.insert(key, f64::from(count));
        }
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
pub(super) use crate::bytes as bytes_at;

/// Lowercase hex encoding of arbitrary bytes. Used wherever a hash
/// digest or serial number needs a stable, comparable representation.
pub(super) fn hex_encode(bytes: &[u8]) -> String {
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

/// Sort `(file_offset, size, tag)` ranges and clip each against the ones
/// before it, so no file byte is visited twice however the headers overlap
/// their sections. A range running past `file_len` keeps its in-file head (a
/// truncated binary still holds the start of its code); empty, overflowing,
/// and fully covered ranges are dropped. The tag rides along with the part of
/// its range that survives.
pub(super) fn disjoint_file_ranges<T>(
    mut ranges: Vec<(usize, usize, T)>,
    file_len: usize,
) -> Vec<(std::ops::Range<usize>, T)> {
    ranges.sort_unstable_by_key(|&(start, size, _)| (start, size));
    let mut covered = 0;
    ranges
        .into_iter()
        .filter_map(|(start, size, tag)| {
            let end = start.checked_add(size)?.min(file_len);
            if end <= start || end <= covered {
                return None;
            }
            let start = start.max(covered);
            covered = end;
            Some((start..end, tag))
        })
        .collect()
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
        P::Dictionary(dict) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v, depth + 1));
            }
            JsonValue::Object(obj)
        }
        _ => JsonValue::Null,
    }
}

#[cfg(test)]
mod tests;
