//! Helpers shared across format extractors.

use crate::metric;
use serde_json::Value as JsonValue;

use crate::output::{Section, Strings, Text, ValueKey, Values};
use crate::scan::{ascii, entropy};

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

/// Native executable formats sharing the Rizin admission policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeFormat {
    Elf,
    MachO,
    Pe,
}

/// Inputs to the deliberately small Rizin admission policy. Keeping this a
/// plain fact bundle makes the decision table testable without spawning a
/// disassembler or manufacturing three kinds of executable fixture.
#[derive(Clone, Copy, Debug)]
struct RizinProfile {
    format: NativeFormat,
    size: usize,
    function_count: usize,
    section_count: usize,
    stripped: Option<bool>,
    go_function_metadata: bool,
    string_count: usize,
    string_bytes: usize,
    code_entropy: Option<f64>,
    overall_entropy: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RizinDecision {
    Skip(&'static str),
    Analyze(&'static str),
}

impl RizinDecision {
    pub(super) fn runs(self) -> bool {
        matches!(self, Self::Analyze(_))
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Skip(reason) | Self::Analyze(reason) => reason,
        }
    }
}

/// Above this size, stripping alone is not enough reason to spend minutes in
/// `aaa`: large release binaries are commonly stripped but otherwise fully
/// transparent. String poverty or high code entropy still admits a binary of
/// any size, so this is not a blanket size cap.
const LARGE_RIZIN_INPUT: usize = 32 << 20;
const FEW_STRINGS: usize = 64;
const HIGH_CODE_ENTROPY: f64 = 7.2;

/// One explicit, cross-platform decision table. There is intentionally no
/// weighted score to tune: each branch states the fact that justifies paying
/// for deep recovery.
fn decide_rizin(profile: RizinProfile) -> RizinDecision {
    if profile.go_function_metadata && profile.function_count > 0 {
        return RizinDecision::Skip("typed Go function inventory available");
    }

    // Go build metadata / pclntab identifies a binary whose function names
    // are recoverable, but the string extractor's PclntabSymbol rows are a
    // mixed name pool (packages, types, fields, paths, and functions), not a
    // typed function inventory. If no typed functions made it into `symbols`,
    // let Rizin provide the actual function table.
    if profile.go_function_metadata {
        return RizinDecision::Analyze("Go function inventory needs recovery");
    }

    // A PE whose native parser could not recover even its section table needs
    // Rizin for structural recovery, not merely function metrics. ELF/Mach-O
    // parse failures return before this policy and retain their typed errors.
    if profile.format == NativeFormat::Pe && profile.section_count == 0 {
        return RizinDecision::Analyze("PE section table needs recovery");
    }

    // Imports and exports do not constitute a function inventory. A stripped
    // ELF with libc imports still benefits from CFG recovery. Conversely, once
    // native parsing supplied functions, `RizinRecovery::apply` deliberately
    // preserves them instead of replacing them, so a deep run cannot add the
    // function-level metrics this policy exists to obtain.
    if profile.function_count > 0 {
        return RizinDecision::Skip("static function inventory available");
    }

    // Importless PEs are a useful platform-specific exception: a compact PE
    // with no symbol projection is often a resolver/hash stub, and the PE
    // analyzer correlates Rizin's call graph with its native API-hash facts.
    if profile.format == NativeFormat::Pe && profile.size <= 5 * 1024 * 1024 {
        return RizinDecision::Analyze("small importless PE");
    }

    // "No obvious strings" means either genuinely few runs, or printable
    // content occupying less than roughly 0.1% of the file. The density test
    // catches a huge packed payload with a small loader banner.
    let strings_are_sparse = profile.string_count < FEW_STRINGS
        || profile.string_bytes.saturating_mul(1024) < profile.size;
    if strings_are_sparse {
        return RizinDecision::Analyze("printable strings are sparse");
    }

    // Prefer the size-weighted executable-section entropy. Whole-file entropy
    // is only a fallback for formats/fixtures without executable sections, so
    // a compressed resource or installer overlay does not admit an otherwise
    // transparent program.
    let entropy = profile.code_entropy.unwrap_or(profile.overall_entropy);
    if entropy >= HIGH_CODE_ENTROPY {
        return RizinDecision::Analyze("executable code has high entropy");
    }

    if profile.stripped == Some(true) && profile.size <= LARGE_RIZIN_INPUT {
        return RizinDecision::Analyze("stripped binary within deep-analysis budget");
    }

    RizinDecision::Skip("static facts show a transparent binary")
}

fn weighted_code_entropy(sections: &[Section]) -> Option<f64> {
    let (weighted, bytes) = sections
        .iter()
        .filter(|section| section.is_code())
        .filter_map(|section| {
            section
                .entropy
                .map(|entropy| (entropy * section.file_size as f64, section.file_size))
        })
        .fold((0.0, 0_u64), |(sum, size), (part, part_size)| {
            (sum + part, size.saturating_add(part_size))
        });
    (bytes > 0).then_some(weighted / bytes as f64)
}

/// What a rizin recovery would look at: the bytes, the static facts that
/// decide whether it is worth running, and this open's settings.
#[derive(Clone, Copy)]
pub(super) struct RizinTarget<'a> {
    pub(super) format: NativeFormat,
    pub(super) bytes: &'a [u8],
    pub(super) strings: &'a Strings,
    /// Go function metadata (a pclntab) is present, so a native parse that
    /// found no typed functions still has an inventory worth recovering.
    pub(super) go_function_metadata: bool,
    pub(super) settings: &'a crate::rizin::Settings,
}

pub(super) fn rizin_decision(
    target: &RizinTarget<'_>,
    sections: &[Section],
    symbols: &crate::Symbols,
    metrics: &crate::output::Metrics,
) -> RizinDecision {
    let RizinTarget {
        format,
        bytes,
        strings,
        go_function_metadata,
        ..
    } = *target;
    let string_bytes = strings.text.iter().fold(0_usize, |total, string| {
        total.saturating_add(string.value.len())
    });
    decide_rizin(RizinProfile {
        format,
        size: bytes.len(),
        function_count: symbols
            .iter()
            .filter(|symbol| symbol.kind() == crate::SymbolKind::Function)
            .count(),
        section_count: sections.len(),
        stripped: metrics
            .get_key(&metric!("binary.is_stripped"))
            .map(|value| value != 0.0),
        go_function_metadata,
        string_count: strings.text.len(),
        string_bytes,
        code_entropy: weighted_code_entropy(sections),
        overall_entropy: metrics.get_key(&metric!("file.entropy")).unwrap_or(0.0),
    })
}

/// Run full Rizin recovery only when the static facts say it is likely to add
/// useful function metrics and the target's settings admit its bytes. Shared
/// by ELF and Mach-O; PE uses the extended helper below so malformed images
/// can recover sections too.
pub(super) fn rizin_fallback(
    target: RizinTarget<'_>,
    sections: &[Section],
    symbols: &mut crate::Symbols,
    metrics: &mut crate::output::Metrics,
) {
    let decision = rizin_decision(&target, sections, symbols, metrics);
    let RizinTarget {
        format,
        bytes,
        go_function_metadata,
        settings,
        ..
    } = target;
    tracing::debug!(
        ?format,
        bytes = bytes.len(),
        run = decision.runs(),
        reason = decision.reason(),
        "rizin admission decision"
    );
    if !decision.runs() || !settings.admits(bytes) {
        return;
    }
    match crate::rizin::recover_with_symbols(bytes, symbols.len(), go_function_metadata, settings) {
        Some(recovery) => {
            recovery.apply(symbols, metrics);
        }
        None => note_incomplete_recovery(metrics),
    }
}

/// Record that rizin *should* have recovered symbols here but its run
/// didn't complete. Fires only when rizin is on PATH and the settings
/// admitted the input — i.e. the cache key (via
/// [`crate::rizin::cache_fingerprint`]) claims rizin-grade recovery, yet
/// this run produced nothing because rizin timed out, was killed on the
/// output cap, or had latched itself off. The empty table is an artefact
/// of this run, not of the bytes, so the `binary.rizin_incomplete` marker
/// lets a cache consumer treat the
/// payload as [`crate::cache::Computed::Transient`] and refuse to persist
/// a poisoned entry (see [`crate::ParsedFile::rizin_recovery_incomplete`]).
/// When rizin is absent, turned off, or skipped by the size cap, the
/// no-rizin result is correct for the environment and settings — and keyed
/// as such — so nothing is recorded.
fn note_incomplete_recovery(metrics: &mut crate::output::Metrics) {
    if crate::rizin::available() {
        metrics.insert(metric!("binary.rizin_incomplete"), 1.0);
    }
}

/// Extended rizin fallback for PE: tries to recover sections as well
/// as symbols, and emits `*.recovered_*_count` metrics under the supplied
/// prefix so callers can attribute the recovered counts in trait
/// rules.
///
/// The caller passes the metric prefix (`"pe"`, `"elf"`, `"macho"`)
/// so the emitted keys are `{prefix}.recovered_section_count` etc. The
/// path stays tool-agnostic — if the disassembler ever swaps from
/// rizin to radare2 / Ghidra the schema doesn't ripple.
pub(super) fn rizin_fallback_with_sections(
    target: RizinTarget<'_>,
    declares_exports: bool,
    symbols: &mut crate::Symbols,
    sections: &mut Vec<crate::output::Section>,
    metrics: &mut crate::output::Metrics,
) {
    let RizinTarget {
        bytes,
        go_function_metadata,
        settings,
        ..
    } = target;
    // Normally goblin's native symbols or sections are enough to avoid an
    // expensive disassembly. Go is the exception: its native parser can
    // expose sections and imports while still having no typed functions;
    // allow Rizin to fill that missing function inventory.
    let has_functions = symbols
        .iter()
        .any(|symbol| symbol.kind() == crate::SymbolKind::Function);
    let has_native_inventory = !symbols.is_empty() || !sections.is_empty();
    let needs_go_function_recovery = go_function_metadata && !has_functions;
    if has_native_inventory && !needs_go_function_recovery {
        return;
    }
    let decision = rizin_decision(&target, sections, symbols, metrics);
    tracing::debug!(
        format = ?target.format,
        bytes = bytes.len(),
        run = decision.runs(),
        reason = decision.reason(),
        "rizin admission decision"
    );
    if !decision.runs() || !settings.admits(bytes) {
        return;
    }
    let recovery = match crate::rizin::recover_with_symbols(
        bytes,
        symbols.len(),
        go_function_metadata,
        settings,
    ) {
        Some(recovery) => recovery,
        None => {
            note_incomplete_recovery(metrics);
            return;
        }
    };
    let recovery = if declares_exports {
        recovery
    } else {
        recovery.without_exports()
    };
    let counts = recovery.apply_with_sections(symbols, sections, metrics);
    if counts.imports > 0 {
        metrics.insert(
            metric!("pe.recovered_import_count"),
            f64::from(counts.imports),
        );
    }
    if counts.exports > 0 {
        metrics.insert(
            metric!("pe.recovered_export_count"),
            f64::from(counts.exports),
        );
    }
    if counts.functions > 0 {
        metrics.insert(
            metric!("pe.recovered_function_count"),
            f64::from(counts.functions),
        );
    }
    if counts.sections > 0 {
        metrics.insert(
            metric!("pe.recovered_section_count"),
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
