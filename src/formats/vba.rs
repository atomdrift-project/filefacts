//! VBA macro source-text extraction from OLE2 / CFBF compound files.
//!
//! Microsoft Office stores VBA modules under a `/VBA/` (or
//! `/Macros/VBA/`, `/_VBA_PROJECT_CUR/VBA/`) storage. The module
//! source code is RLE-compressed per MS-OVBA §2.4.1 with the
//! per-module byte offset recorded in the `dir` stream. This module
//! walks that structure and surfaces the decompressed source text so
//! trait rules can `regex:` directly against macro contents
//! (`Auto_Open`, `Shell`, `GetObject`, `URLDownloadToFile`, …).
//!
//! Schema emitted under `office.vba.*`:
//!
//! - `office.vba.modules[]` — array of `{name, stream_name, kind,
//!   source}` per module. `kind` is `"standard"`, `"class"`, or
//!   `"document"` from the dir-stream MODULETYPE record.
//! - `office.vba.module_count` (metric) — convenience count.
//!
//! Layered on top of the existing `ole2::extract` walk (which has
//! already emitted `office.kind`, `office.streams[]`, the `macros`
//! feature flag, etc.). A document without a VBA project is not a
//! failure and records nothing. A project that is there but cannot be
//! read — a compound file that does not open, a corrupt or truncated
//! `dir` stream, a module stream that is missing or does not decompress —
//! is recorded in `errors`, and the modules that could be read are still
//! surfaced: partial output is more useful than none. A cap that stops the
//! walk is a coverage limit rather than a failure, so it goes to
//! `office.limits` instead.

use crate::metric;
use crate::value_key;
use std::io::{Cursor, Read, Seek};

use serde_json::Value as JsonValue;

use crate::formats::common::bytes_at;
use crate::output::{Errors, Metrics, Stage, Values};

/// Cap on the decompressed size of a single module — 10 MiB matches
/// cleave's bound.
const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;
/// Cap on the raw CFB stream length we'll read into memory.
const MAX_STREAM_SIZE: u64 = 20 * 1024 * 1024;
/// Cap on the number of modules we'll surface. Real projects max out
/// around 50; the cap keeps a hostile doc with thousands of empty
/// module records from blowing past the allocator.
const MAX_MODULES: usize = 256;
/// Cap on the decompressed source kept across every module of a project.
/// A few kilobytes of copy tokens decompress to [`MAX_DECOMPRESSED_SIZE`],
/// and the dir stream may point all [`MAX_MODULES`] modules at that one
/// stream: 2.5 GiB of source from one small document.
const MAX_PROJECT_SOURCE: usize = 32 * 1024 * 1024;

/// Walk the CFB and surface VBA modules under `office.vba.*`. The
/// dispatcher is expected to have already opened the file via
/// [`super::ole2::extract`]; this re-opens it because the cfb crate keeps
/// the archive handle mutable internally and we'd otherwise have to
/// thread it through the dispatch contract.
///
/// Module source bytes are also fed to [`super::vba_symbols::extract`],
/// which pushes `vba-declare`, `vba-createobject`, `vba-getobject`,
/// and `vba-decl` entries into the unified `symbols_out` view plus
/// document-level aggregate metrics under `office.vba.*_count`.
///
/// A project that cannot be read is recorded in `errors` under
/// [`Stage::Ole2Parse`].
pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
    errors: &mut Errors,
) {
    let mut report = Report::new(errors, Stage::Ole2Parse, None);
    extract_project(bytes, values, metrics, symbols_out, &mut report);
    report.finish(values);
}

/// Where a VBA walk sends what stopped it. A genuine failure goes to
/// `errors`, which traits read as "the parser failed"; a cap is not that,
/// so it goes to `office.limits` like the zip/rar/cab walkers' caps.
struct Report<'a> {
    errors: &'a mut Errors,
    stage: Stage,
    /// The package part the project was read from, prefixed to messages.
    origin: Option<&'a str>,
    limits: Vec<JsonValue>,
}

impl<'a> Report<'a> {
    fn new(errors: &'a mut Errors, stage: Stage, origin: Option<&'a str>) -> Self {
        Self {
            errors,
            stage,
            origin,
            limits: Vec::new(),
        }
    }

    fn located(&self, message: String) -> String {
        match self.origin {
            Some(origin) => format!("{origin}: {message}"),
            None => message,
        }
    }

    fn failure(&mut self, message: String) {
        let message = self.located(message);
        self.errors.record_malformed(self.stage, message);
    }

    fn limit(&mut self, stage: &str, reason: String) {
        let reason = self.located(reason);
        self.limits
            .push(serde_json::json!({ "stage": stage, "reason": reason }));
    }

    /// Append the caps hit to `office.limits`, after any the OOXML layer
    /// already put there.
    fn finish(self, values: &mut Values) {
        if self.limits.is_empty() {
            return;
        }
        let mut limits = values
            .get_key(value_key!("office.limits"))
            .and_then(JsonValue::as_array)
            .cloned()
            .unwrap_or_default();
        limits.extend(self.limits);
        values.insert_key(value_key!("office.limits"), JsonValue::Array(limits));
    }
}

fn extract_project(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
    report: &mut Report<'_>,
) {
    let cursor = Cursor::new(bytes);
    let mut comp = match cfb::CompoundFile::open(cursor) {
        Ok(comp) => comp,
        Err(e) => {
            report.failure(format!("VBA project does not open as a compound file: {e}"));
            return;
        }
    };
    // No VBA storage is a macro-free document, not a failure.
    let Some(prefix) = find_vba_prefix(&mut comp) else {
        return;
    };

    // Read & decompress the dir stream.
    let dir_path = format!("{prefix}/dir");
    let dir_bytes = match read_stream(&mut comp, &dir_path) {
        Ok(bytes) => bytes,
        Err(StreamError::TooLarge(len)) => {
            report.limit(
                "vba-stream-cap",
                format!(
                    "{dir_path}: {len} bytes, over the {MAX_STREAM_SIZE}-byte cap; \
                     VBA project not read"
                ),
            );
            return;
        }
        Err(StreamError::Unreadable(e)) => {
            report.failure(format!("VBA dir stream {dir_path:?} unreadable: {e}"));
            return;
        }
    };
    let dir_decompressed = match decompress_vba(&dir_bytes) {
        Ok(data) => data,
        Err(DecompressError::BadSignature) => {
            report.failure(format!(
                "VBA dir stream {dir_path:?} is corrupt: invalid compression signature"
            ));
            return;
        }
        Err(DecompressError::TooLarge) => {
            report.limit(
                "vba-decompress-cap",
                format!(
                    "{dir_path}: decompresses past the {MAX_DECOMPRESSED_SIZE}-byte cap; \
                     VBA project not read"
                ),
            );
            return;
        }
    };
    if dir_decompressed.is_empty() {
        report.failure(format!("VBA dir stream {dir_path:?} is empty"));
        return;
    }

    // Parse module metadata from the decompressed dir stream.
    let dir = parse_dir_stream(&dir_decompressed);
    if dir.truncated {
        report.failure(format!(
            "VBA dir stream {dir_path:?} is corrupt: a record runs past the end of its {} bytes",
            dir_decompressed.len()
        ));
    }
    if dir.modules.len() > MAX_MODULES {
        report.limit(
            "vba-module-cap",
            format!(
                "read {MAX_MODULES} of {} VBA module records",
                dir.modules.len()
            ),
        );
    }
    let mut modules: Vec<JsonValue> = Vec::new();
    // Document-level aggregate counters folded across modules. The
    // per-module stats from `vba_symbols::extract` accumulate here
    // so a doc with three modules and one Declare each surfaces a
    // single `office.vba.declare_count = 3`.
    let mut agg = super::vba_symbols::VbaSymbolStats::default();
    // Mark where this document's VBA symbols start so the identifier-shape
    // metrics below are computed over exactly the symbols emitted here.
    let sym_start = symbols_out.len();
    let mut source_left = MAX_PROJECT_SOURCE;
    for info in dir.modules.iter().take(MAX_MODULES) {
        if info.stream_name.is_empty() {
            // Only a corrupt dir stream leaves a module without a stream
            // name; a truncated one is already reported above.
            if !dir.truncated {
                report.failure(format!(
                    "VBA dir stream {dir_path:?} is corrupt: module {:?} names no stream",
                    info.name
                ));
            }
            continue;
        }
        let stream_path = format!("{}/{}", prefix, info.stream_name);
        let stream_bytes = match read_stream(&mut comp, &stream_path) {
            Ok(bytes) => bytes,
            Err(StreamError::TooLarge(len)) => {
                report.limit(
                    "vba-stream-cap",
                    format!(
                        "{stream_path}: {len} bytes, over the {MAX_STREAM_SIZE}-byte cap; \
                         module {:?} not read",
                        info.name
                    ),
                );
                continue;
            }
            Err(StreamError::Unreadable(e)) => {
                report.failure(format!(
                    "VBA module {:?}: stream {stream_path:?} unreadable: {e}",
                    info.name
                ));
                continue;
            }
        };
        let offset = info.offset as usize;
        let Some(container) = stream_bytes.get(offset..).filter(|c| !c.is_empty()) else {
            report.failure(format!(
                "VBA module {:?}: source offset {offset} is past the end of its {}-byte stream",
                info.name,
                stream_bytes.len()
            ));
            continue;
        };
        let cap = source_left.min(MAX_DECOMPRESSED_SIZE);
        let source_bytes = match decompress_vba_within(container, cap) {
            Ok(source) => source,
            Err(DecompressError::BadSignature) => {
                report.failure(format!(
                    "VBA module {:?}: source in {stream_path:?} has an invalid compression signature",
                    info.name
                ));
                continue;
            }
            Err(DecompressError::TooLarge) => {
                report.limit(
                    "vba-decompress-cap",
                    format!(
                        "{stream_path}: source decompresses past the {cap} bytes left of the \
                         {MAX_DECOMPRESSED_SIZE}-byte module and {MAX_PROJECT_SOURCE}-byte \
                         project caps; module {:?} not read",
                        info.name
                    ),
                );
                continue;
            }
        };
        source_left -= source_bytes.len();
        // VBA source is documented as Windows-1252 on disk but most
        // real-world macros are ASCII; `from_utf8_lossy` handles
        // non-ASCII gracefully by substituting U+FFFD without
        // dropping the surrounding lines a trait might match against.
        let source = String::from_utf8_lossy(&source_bytes).into_owned();

        // Run the symbol extractor before moving `source` into the
        // module record.
        let stats = super::vba_symbols::extract(&source, symbols_out);
        agg.declare_count = agg.declare_count.saturating_add(stats.declare_count);
        agg.declare_non_literal_count = agg
            .declare_non_literal_count
            .saturating_add(stats.declare_non_literal_count);
        agg.createobject_count = agg
            .createobject_count
            .saturating_add(stats.createobject_count);
        agg.createobject_non_literal_count = agg
            .createobject_non_literal_count
            .saturating_add(stats.createobject_non_literal_count);
        agg.getobject_count = agg.getobject_count.saturating_add(stats.getobject_count);
        agg.getobject_non_literal_count = agg
            .getobject_non_literal_count
            .saturating_add(stats.getobject_non_literal_count);
        agg.trigger_handler_count = agg
            .trigger_handler_count
            .saturating_add(stats.trigger_handler_count);

        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), JsonValue::String(info.name.clone()));
        obj.insert(
            "stream_name".into(),
            JsonValue::String(info.stream_name.clone()),
        );
        obj.insert(
            "kind".into(),
            JsonValue::String(
                match info.module_type {
                    VbaModuleType::Standard => "standard",
                    VbaModuleType::Class => "class",
                }
                .into(),
            ),
        );
        obj.insert("source".into(), JsonValue::String(source));
        modules.push(JsonValue::Object(obj));
    }

    if !modules.is_empty() {
        let count = modules.len() as f64;
        values.insert_key(value_key!("office.vba.modules"), JsonValue::Array(modules));
        metrics.insert(metric!("office.vba.module_count"), count);
        // Aggregate symbol-extraction counters surface as metrics so
        // composite rules can count obfuscation signals without
        // walking the imports view.
        metrics.insert(
            metric!("office.vba.declare_count"),
            f64::from(agg.declare_count),
        );
        metrics.insert(
            metric!("office.vba.declare_non_literal_count"),
            f64::from(agg.declare_non_literal_count),
        );
        metrics.insert(
            metric!("office.vba.createobject_count"),
            f64::from(agg.createobject_count),
        );
        metrics.insert(
            metric!("office.vba.createobject_non_literal_count"),
            f64::from(agg.createobject_non_literal_count),
        );
        metrics.insert(
            metric!("office.vba.getobject_count"),
            f64::from(agg.getobject_count),
        );
        metrics.insert(
            metric!("office.vba.getobject_non_literal_count"),
            f64::from(agg.getobject_non_literal_count),
        );
        metrics.insert(
            metric!("office.vba.trigger_handler_count"),
            f64::from(agg.trigger_handler_count),
        );

        // Identifier-shape signals over this document's VBA symbol names
        // (imports + functions): mean length, Shannon entropy of the
        // byte-frequency distribution, and the count of *distinct* trigger
        // handlers. Random/obfuscated macros skew length+entropy; the
        // distinct-trigger count separates one auto-exec stub from a doc
        // that hooks many lifecycle events.
        let mut byte_counts = [0u32; 256];
        let mut total_chars = 0u64;
        let mut total_idents = 0u32;
        let mut distinct_triggers = std::collections::BTreeSet::new();
        for sym in symbols_out.iter().skip(sym_start) {
            let Some(name) = sym.name().filter(|n| !n.is_empty()) else {
                continue;
            };
            total_idents += 1;
            for b in name.bytes() {
                if let Some(count) = byte_counts.get_mut(usize::from(b)) {
                    *count = count.saturating_add(1);
                }
                total_chars += 1;
            }
            if matches!(sym, crate::Symbol::Function { .. })
                && super::vba_symbols::is_trigger_name(name)
            {
                distinct_triggers.insert(name.to_string());
            }
        }
        if total_idents > 0 {
            metrics.insert(
                metric!("office.vba.avg_identifier_length"),
                total_chars as f64 / f64::from(total_idents),
            );
        }
        if total_chars > 0 {
            let total = total_chars as f64;
            let entropy: f64 = byte_counts
                .iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = f64::from(c) / total;
                    -p * p.log2()
                })
                .sum();
            metrics.insert(metric!("office.vba.identifier_entropy"), entropy);
        }
        metrics.insert(
            metric!("office.vba.distinct_trigger_count"),
            distinct_triggers.len() as f64,
        );
    }
}

/// Decompress VBA macros carried in an OOXML `vbaProject.bin` member.
///
/// `vbaProject.bin` is itself a standalone CFBF compound file, so once
/// its bytes are read out of the zip they flow through the same CFB walk
/// as the legacy [`extract`] path and populate `office.vba.*`
/// identically. This mirrors the `FileType::OleDoc` dispatch so macros in
/// `.docm`/`.xlsm`/`.pptm` are decompressed, not merely flagged by stream
/// path. A document carries a single VBA project; the first part the
/// package declares as one wins, falling back to the conventional
/// `vbaProject.bin` name when nothing is declared.
///
/// A project part that cannot be read is recorded in `errors` under
/// [`Stage::OoxmlParse`], its message prefixed with the part name.
pub(super) fn extract_from_zip<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
    errors: &mut Errors,
) {
    // Find the part by what the package says it is, not by what it is called.
    //
    // `office.macros` comes from `[Content_Types].xml`, which is where the
    // package declares which part is the VBA project. Matching on the name
    // `vbaProject.bin` instead meant a package that renamed it extracted no
    // macros at all -- and renaming it is free: one sample here declares
    // `Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"`
    // and ships the project as `A@@@@.../Vasp7676CDT11.bin`, 273 KB of it.
    let declared = values
        .get_key(value_key!("office.macros"))
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .find(|n| zip.index_for_name(n).is_some())
        .map(str::to_string);
    let Some(name) = declared.or_else(|| {
        zip.file_names()
            .find(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin"))
            .map(str::to_string)
    }) else {
        return;
    };
    let mut report = Report::new(errors, Stage::OoxmlParse, Some(&name));
    if let Some(bytes) = read_project_part(zip, &name, &mut report) {
        extract_project(&bytes, values, metrics, symbols_out, &mut report);
    }
    report.finish(values);
}

/// The bytes of the `vbaProject.bin` part, or `None` once the failure or
/// the cap that stopped the read is reported.
fn read_project_part<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
    report: &mut Report<'_>,
) -> Option<Vec<u8>> {
    // The header's claim refuses an honestly huge part before inflating
    // any of it; `read_member` caps what the inflater actually produces.
    let declared = match zip.by_name(name) {
        Ok(entry) => entry.size(),
        Err(e) => {
            report.failure(format!("VBA project part unreadable: {e}"));
            return None;
        }
    };
    if declared > MAX_STREAM_SIZE {
        report.limit(
            "vba-project-cap",
            format!("{declared} bytes, over the {MAX_STREAM_SIZE}-byte cap; VBA project not read"),
        );
        return None;
    }
    match super::zip::read_member(zip, name, MAX_STREAM_SIZE) {
        Ok(bytes) => bytes,
        Err(super::zip::MemberError::TooLarge { .. }) => {
            report.limit(
                "vba-project-cap",
                format!(
                    "inflates past the {MAX_STREAM_SIZE}-byte cap (header claims {declared}); \
                     VBA project not read"
                ),
            );
            None
        }
        Err(e) => {
            report.failure(format!("VBA project part unreadable: {e}"));
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum VbaModuleType {
    Standard,
    Class,
}

struct ModuleInfo {
    name: String,
    stream_name: String,
    offset: u32,
    module_type: VbaModuleType,
}

/// Module records parsed out of a decompressed `dir` stream.
struct DirStream {
    modules: Vec<ModuleInfo>,
    /// A record's declared size ran past the end of the stream: the stream
    /// is truncated or corrupt, and the last module may be incomplete.
    truncated: bool,
}

/// Walk the CFB entries looking for a `/dir` stream under any of the
/// documented VBA storage paths. Returns the prefix (e.g. `/VBA`,
/// `/Macros/VBA`) — without the trailing `/dir`.
fn find_vba_prefix<R: Read + std::io::Seek>(comp: &mut cfb::CompoundFile<R>) -> Option<String> {
    let entries: Vec<String> = comp
        .walk()
        .map(|e| super::common::cfb_entry_path(&e))
        .collect();
    const CANDIDATES: &[&str] = &[
        "VBA",
        "Macros/VBA",
        "_VBA_PROJECT_CUR/VBA",
        "Word/VBA",
        "Excel/VBA",
    ];
    for cand in CANDIDATES {
        for entry in &entries {
            let normalized = entry.trim_start_matches('/');
            if normalized.eq_ignore_ascii_case(&format!("{cand}/dir")) {
                return Some(format!("/{cand}"));
            }
        }
    }
    // Fallback: any path ending in `/VBA/dir` (case-insensitive).
    for entry in &entries {
        let lower = entry.to_lowercase();
        if lower.ends_with("/vba/dir") {
            // The last four characters lowercase to `/dir`, and nothing
            // outside ASCII lowercases to those, so this cut is always on a
            // character boundary.
            if let Some(prefix) = entry.get(..entry.len().saturating_sub(4)) {
                return Some(prefix.to_string());
            }
        }
    }
    None
}

/// Why a VBA stream was not read.
enum StreamError {
    /// Over [`MAX_STREAM_SIZE`]: a coverage limit.
    TooLarge(u64),
    /// Missing, not a stream, or a broken sector chain: a failure.
    Unreadable(std::io::Error),
}

fn read_stream<R: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<R>,
    path: &str,
) -> Result<Vec<u8>, StreamError> {
    let mut stream = comp.open_stream(path).map_err(StreamError::Unreadable)?;
    let size = stream.len();
    if size > MAX_STREAM_SIZE {
        return Err(StreamError::TooLarge(size));
    }
    let mut buf = Vec::with_capacity(crate::bytes::sat_usize(size));
    stream
        .read_to_end(&mut buf)
        .map_err(StreamError::Unreadable)?;
    Ok(buf)
}

/// Why [`decompress_vba`] gave up.
#[derive(Debug, PartialEq, Eq)]
enum DecompressError {
    /// The container does not start with the `0x01` signature byte.
    BadSignature,
    /// The output would pass the cap.
    TooLarge,
}

/// [`decompress_vba_within`] the per-module cap, [`MAX_DECOMPRESSED_SIZE`].
fn decompress_vba(data: &[u8]) -> Result<Vec<u8>, DecompressError> {
    decompress_vba_within(data, MAX_DECOMPRESSED_SIZE)
}

/// Decompress an MS-OVBA RLE stream into at most `cap` bytes. The format
/// starts with a `0x01` signature byte; each subsequent chunk has a 12-bit
/// length plus an "is compressed" bit. Compressed chunks alternate 1-byte
/// flag fields with eight tokens (literal byte or LZ-style back-reference).
fn decompress_vba_within(data: &[u8], cap: usize) -> Result<Vec<u8>, DecompressError> {
    let Some(&signature) = data.first() else {
        return Ok(Vec::new());
    };
    if signature != 0x01 {
        return Err(DecompressError::BadSignature);
    }
    let mut output: Vec<u8> = Vec::with_capacity(data.len().saturating_mul(2).min(cap));
    let mut pos = 1usize;
    while pos < data.len() {
        let Some(header) = bytes_at::u16_le(data, pos) else {
            break;
        };
        pos += 2;
        let chunk_size = (header & 0x0FFF) as usize + 3;
        let is_compressed = (header & 0x8000) != 0;
        if !is_compressed {
            let end = (pos + 4096).min(data.len());
            let chunk = data.get(pos..end).unwrap_or_default();
            if output.len() + chunk.len() > cap {
                return Err(DecompressError::TooLarge);
            }
            output.extend_from_slice(chunk);
            pos = end;
            continue;
        }
        let chunk_end = pos
            .saturating_add(chunk_size)
            .saturating_sub(2)
            .min(data.len());
        let decompressed_start = output.len();
        while pos < chunk_end {
            let Some(&flag) = data.get(pos) else {
                break;
            };
            pos += 1;
            for bit in 0..8u8 {
                if pos >= chunk_end {
                    break;
                }
                if (flag >> bit) & 1 == 0 {
                    if let Some(&literal) = data.get(pos) {
                        if output.len() >= cap {
                            return Err(DecompressError::TooLarge);
                        }
                        output.push(literal);
                        pos += 1;
                    }
                } else {
                    let Some(token) = bytes_at::u16_le(data, pos) else {
                        pos = data.len();
                        break;
                    };
                    pos += 2;
                    let decompressed_pos = output.len().saturating_sub(decompressed_start);
                    let bits = max_bit_count(decompressed_pos);
                    let len_mask = 0xFFFFu16 >> bits;
                    let off_mask = !len_mask;
                    let length = ((token & len_mask) + 3) as usize;
                    let offset = ((token & off_mask) >> (16 - bits)) as usize + 1;
                    if output.len().saturating_add(length) > cap {
                        return Err(DecompressError::TooLarge);
                    }
                    for _ in 0..length {
                        let src = output.len().wrapping_sub(offset);
                        let byte = output.get(src).copied().unwrap_or(0);
                        output.push(byte);
                    }
                }
            }
        }
    }
    Ok(output)
}

/// Number of bits a copy token spends on its offset, for a token at the
/// given position within the current chunk (MS-OVBA §2.4.1.3.19.1).
///
/// The spec is `max(4, ceil(log2(DecompressedCurrent - DecompressedChunkStart)))`,
/// capped at 12: early in a chunk there is little to point back at, so the
/// offset is cheap and the length gets the remaining bits; as the chunk fills,
/// the offset claims more.
///
/// This ran the other way round -- 12 bits at the start of a chunk, shrinking
/// toward 4 -- so every copy token decoded with the wrong split and produced
/// plausible-looking but wrong bytes. The dir stream of a real `vbaProject.bin`
/// came out with `04` bytes turned into `00`, which is enough to make its
/// record sizes nonsense and yield zero modules: every OOXML document's macro
/// source was silently unavailable, and so was the OLE2 path's.
fn max_bit_count(decompressed_pos: usize) -> u16 {
    let mut bits = 4u16;
    while bits < 12 && (1usize << bits) < decompressed_pos {
        bits += 1;
    }
    bits
}

/// Offset of the first MODULE record, found via the PROJECTMODULES header.
///
/// Returns the position just past PROJECTMODULES and its PROJECTCOOKIE
/// (`Id=0x0013, Size=0x0002`), which is where the MODULENAME chain begins.
fn find_project_modules(data: &[u8]) -> Option<usize> {
    const PROJECT_MODULES: [u8; 6] = [0x0F, 0x00, 0x02, 0x00, 0x00, 0x00];
    let at = data
        .windows(PROJECT_MODULES.len())
        .position(|w| w == PROJECT_MODULES)?;
    // PROJECTMODULES: id(2) size(4) count(2)
    let mut pos = at + 8;
    // PROJECTCOOKIE: id(2) size(4) cookie(2)
    if data.get(pos..pos + 2) == Some(&[0x13, 0x00]) {
        pos += 8;
    }
    (pos < data.len()).then_some(pos)
}

/// The `Id` and `Size` of the dir-stream record at `pos`, when its 6-byte
/// header is wholly inside `data`.
fn record_header(data: &[u8], pos: usize) -> Option<(u16, usize)> {
    let id = bytes_at::u16_le(data, pos)?;
    let size = bytes_at::u32_le(data, pos.checked_add(2)?)?;
    // A size past the stream's end reads nothing either way; clamping it keeps
    // the walk's `pos += 6 + size` steps from wrapping on 32-bit targets.
    Some((id, crate::bytes::sat_usize(size).min(data.len())))
}

/// Parse the decompressed dir stream into per-module metadata
/// records (name, on-disk stream name, source-offset within that
/// stream, module kind). Per MS-OVBA §2.3.4.2.
fn parse_dir_stream(data: &[u8]) -> DirStream {
    let mut out = Vec::new();
    // Start at PROJECTMODULES rather than at byte zero.
    //
    // The records before it cannot be walked by `id`/`size` alone, and trying
    // reached no module at all on real files. PROJECTVERSION (0x0009) declares
    // Size 4 but carries 6 bytes, because the field is Reserved rather than a
    // length; and the PROJECTREFERENCES that follow have per-kind layouts with
    // their own embedded sizes. A project without references is rare enough --
    // `stdole` is in nearly all of them -- that the walk fell over on
    // essentially every document, which is why office.vba.modules[] was empty
    // everywhere and no rule ever saw a line of macro source.
    //
    // PROJECTMODULES is `Id=0x000F, Size=0x00000002`, and the MODULE records
    // after it are a clean id/size chain, which is the part this needs.
    let mut pos = find_project_modules(data).unwrap_or(0);
    while let Some((record_id, record_size)) = record_header(data, pos) {
        match record_id {
            0x000F => break, // MODULETERMINATOR — end of project
            0x0019 => {
                // MODULENAME (record_size bytes of MBCS text)
                pos += 6;
                let name = read_ascii_string(data, pos, record_size);
                pos += record_size;
                let mut info = ModuleInfo {
                    name: name.clone(),
                    stream_name: name,
                    offset: 0,
                    module_type: VbaModuleType::Standard,
                };
                // Parse the remaining per-module sub-records until we
                // hit a MODULETERMINATOR (0x002B).
                while let Some((sub_id, sub_size)) = record_header(data, pos) {
                    match sub_id {
                        0x001A => {
                            // MODULESTREAMNAME, MBCS, followed by the same
                            // name in UTF-16LE (0x0032).
                            //
                            // Prefer the Unicode one. The MBCS form is
                            // code-page bytes, and reading it as UTF-8 turns
                            // any non-ASCII letter into a replacement
                            // character -- so a project with a module called
                            // `Módulo1` looked for a stream named `M?dulo1`,
                            // found nothing, and yielded no source at all.
                            // Every non-English VBA project extracted empty.
                            pos += 6;
                            info.stream_name = read_ascii_string(data, pos, sub_size);
                            pos += sub_size;
                            if let Some((0x0032, next_size)) = record_header(data, pos) {
                                if let Some(wide) = read_utf16_string(data, pos + 6, next_size) {
                                    info.stream_name = wide;
                                }
                                pos += 6 + next_size;
                            }
                        }
                        0x0031 => {
                            // MODULEOFFSET (u32 source-text byte
                            // offset inside the module stream).
                            pos += 6;
                            if sub_size >= 4 {
                                if let Some(offset) = bytes_at::u32_le(data, pos) {
                                    info.offset = offset;
                                }
                            }
                            pos += sub_size;
                        }
                        0x0021 => {
                            info.module_type = VbaModuleType::Standard;
                            pos += 6 + sub_size;
                        }
                        0x0022 => {
                            info.module_type = VbaModuleType::Class;
                            pos += 6 + sub_size;
                        }
                        0x001C => {
                            // MODULEDOCSTRING — skip (then skip
                            // trailing unicode variant 0x0048 if
                            // present).
                            pos += 6 + sub_size;
                            if let Some((0x0048, next_size)) = record_header(data, pos) {
                                pos += 6 + next_size;
                            }
                        }
                        0x002B => {
                            pos += 6; // MODULETERMINATOR
                            break;
                        }
                        _ => {
                            pos += 6 + sub_size;
                        }
                    }
                }
                out.push(info);
            }
            _ => {
                pos += 6 + record_size;
            }
        }
    }
    // Every step either stays inside the stream or moves past a record whose
    // declared size crossed its end, after which nothing more is read.
    DirStream {
        modules: out,
        truncated: pos > data.len(),
    }
}

/// Decode a UTF-16LE run of `len` bytes starting at `pos`.
///
/// Returns `None` when the run is truncated, has an odd length, is not
/// well-formed UTF-16, or holds nothing but NUL padding — in each case the
/// caller keeps the MBCS name it already read.
fn read_utf16_string(data: &[u8], pos: usize, len: usize) -> Option<String> {
    let bytes = slice_at(data, pos, len)?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut s = bytes_at::utf16_strict(bytes, bytes_at::Endian::Little)?;
    s.truncate(s.trim_end_matches('\0').len());
    (!s.is_empty()).then_some(s)
}

/// Decode a `len`-byte MBCS run as UTF-8, lossily. Bytes outside ASCII are
/// code-page dependent and become replacement characters; prefer the
/// UTF-16LE variant that MS-OVBA pairs with most of these fields.
fn read_ascii_string(data: &[u8], pos: usize, len: usize) -> String {
    let Some(bytes) = slice_at(data, pos, len) else {
        return String::new();
    };
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
}

/// `data[pos..pos + len]`, or `None` if that range is not wholly within
/// `data`. Avoids the overflow that a bare `pos + len` risks on lengths read
/// from the file.
fn slice_at(data: &[u8], pos: usize, len: usize) -> Option<&[u8]> {
    data.get(pos..)?.get(..len)
}

#[cfg(test)]
mod tests;
