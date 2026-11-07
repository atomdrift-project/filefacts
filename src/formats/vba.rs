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
//!   source}` per module. `kind` is `"standard"` (procedural) or `"class"`
//!   (document, class or designer) from the dir-stream MODULETYPE record.
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
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek};

use serde_json::Value as JsonValue;

use crate::formats::bounded::Limits;
use crate::output::{Errors, Metrics, Stage, Values};

/// Cap on the decompressed size of a single module. Real modules are tens
/// of kilobytes; 10 MiB leaves room for generated or padded macros.
const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;
/// Cap on the raw CFB stream length we'll read into memory.
const MAX_STREAM_SIZE: u64 = 20 * 1024 * 1024;
/// Cap on the number of modules we'll surface. Real projects max out
/// around 50; the cap keeps a hostile doc with thousands of empty
/// module records from blowing past the allocator.
const MAX_MODULES: usize = 256;
/// Cap on the source decompressed across every module of a project, kept
/// or refused. A few kilobytes of copy tokens decompress to
/// [`MAX_DECOMPRESSED_SIZE`], and the dir stream may point all
/// [`MAX_MODULES`] modules at that one stream: 2.5 GiB of source from one
/// small document, whether each module is kept or refused at the cap.
const MAX_PROJECT_SOURCE: usize = 32 * 1024 * 1024;

/// Walk an open compound file and surface VBA modules under
/// `office.vba.*`. The dispatcher opens the file once for this and
/// [`super::ole2::extract`].
///
/// Module source bytes are also fed to [`super::vba_symbols::extract`],
/// which pushes `vba-declare`, `vba-createobject`, `vba-getobject`,
/// and `vba-decl` entries into the unified `symbols_out` view plus
/// document-level aggregate metrics under `office.vba.*_count`.
///
/// A project that cannot be read is recorded in `errors` under
/// [`Stage::Ole2Parse`].
pub(super) fn extract<R: Read + Seek>(
    comp: &mut cfb::CompoundFile<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
    errors: &mut Errors,
) {
    let mut report = Report::new(errors, Stage::Ole2Parse, None);
    extract_project(comp, values, metrics, symbols_out, &mut report);
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
    limits: Limits,
}

impl<'a> Report<'a> {
    fn new(errors: &'a mut Errors, stage: Stage, origin: Option<&'a str>) -> Self {
        Self {
            errors,
            stage,
            origin,
            limits: Limits::default(),
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

    fn limit(&mut self, stage: &'static str, reason: String) {
        let reason = self.located(reason);
        self.limits.push(stage, reason);
    }

    /// Append the caps hit to `office.limits`, after any the OOXML layer
    /// already put there.
    fn finish(self, values: &mut Values) {
        self.limits.emit(values, value_key!("office.limits"));
    }
}

/// The decompressed `dir` stream at `dir_path`, or `None` once the failure
/// or cap that stopped it is reported.
fn read_dir_stream<R: Read + Seek>(
    comp: &mut cfb::CompoundFile<R>,
    dir_path: &str,
    report: &mut Report<'_>,
) -> Option<Vec<u8>> {
    let dir_bytes = match read_stream(comp, dir_path) {
        Ok(bytes) => bytes,
        Err(StreamError::TooLarge(len)) => {
            report.limit(
                "vba-stream-cap",
                format!("{dir_path}: {len} bytes, over the {MAX_STREAM_SIZE}-byte cap; not read"),
            );
            return None;
        }
        Err(StreamError::Unreadable(e)) => {
            report.failure(format!("VBA dir stream {dir_path:?} unreadable: {e}"));
            return None;
        }
    };
    match decompress_vba(&dir_bytes, MAX_DECOMPRESSED_SIZE) {
        Ok(data) if data.is_empty() => {
            report.failure(format!("VBA dir stream {dir_path:?} is empty"));
            None
        }
        Ok(data) => Some(data),
        Err(DecompressError::BadSignature) => {
            report.failure(format!(
                "VBA dir stream {dir_path:?} is corrupt: invalid compression signature"
            ));
            None
        }
        Err(DecompressError::TooLarge) => {
            report.limit(
                "vba-decompress-cap",
                format!(
                    "{dir_path}: decompresses past the {MAX_DECOMPRESSED_SIZE}-byte cap; not read"
                ),
            );
            None
        }
    }
}

fn extract_project<R: Read + Seek>(
    comp: &mut cfb::CompoundFile<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
    report: &mut Report<'_>,
) {
    // No VBA storage is a macro-free document, not a failure.
    let Some(prefix) = find_vba_prefix(comp) else {
        return;
    };

    // Module metadata from the decompressed dir stream.
    let dir_path = format!("{prefix}/dir");
    let dir_read = read_dir_stream(comp, &dir_path, report);
    let mut dir = dir_read
        .as_deref()
        .map(parse_dir_stream)
        .unwrap_or_default();
    if let Some(data) = &dir_read
        && dir.truncated
    {
        report.failure(format!(
            "VBA dir stream {dir_path:?} is corrupt: a record runs past the end of its {} bytes",
            data.len()
        ));
    }
    // A dir stream that names no module (unreadable, corrupt, or forged
    // empty) leaves the module streams themselves: read each one whose
    // source can be found by its opening. An unreadable dir stream is
    // already recorded; one that reads but names nothing is recorded here.
    if dir.modules.is_empty() {
        dir.modules = storage_modules(comp, &prefix);
        if dir_read.is_some() && !dir.truncated && !dir.modules.is_empty() {
            report.failure(format!(
                "VBA dir stream {dir_path:?} names no module; reading the {} streams of its storage",
                dir.modules.len()
            ));
        }
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
    // Document-level aggregate counters, accumulated across modules by
    // `vba_symbols::extract` so a doc with three modules and one Declare
    // each surfaces a single `office.vba.declare_count = 3`.
    let mut agg = super::vba_symbols::VbaSymbolStats::default();
    let mut logical_lines = 0_usize;
    let mut generated_names = 0_usize;
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
        if source_left == 0 {
            report.limit(
                "vba-decompress-cap",
                format!(
                    "{stream_path}: the {MAX_PROJECT_SOURCE}-byte project decompression budget \
                     is spent; module {:?} not read",
                    info.name
                ),
            );
            continue;
        }
        let stream_bytes = match read_stream(comp, &stream_path) {
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
        let Some(offset) = info.offset.map_or_else(
            || source_start(&stream_bytes),
            |o| Some(crate::bytes::sat_usize(o)),
        ) else {
            // Only a guessed module stream has no offset; one holding no
            // source is not a module, not a failure.
            tracing::debug!(target: "filefacts::vba", stream = %stream_path, "storage stream holds no module source");
            continue;
        };
        let Some(container) = stream_bytes.get(offset..).filter(|c| !c.is_empty()) else {
            report.failure(format!(
                "VBA module {:?}: source offset {offset} is past the end of its {}-byte stream",
                info.name,
                stream_bytes.len()
            ));
            continue;
        };
        let cap = source_left.min(MAX_DECOMPRESSED_SIZE);
        let source_bytes = match decompress_vba(container, cap) {
            Ok(source) => source,
            Err(DecompressError::BadSignature) => {
                report.failure(format!(
                    "VBA module {:?}: source in {stream_path:?} has an invalid compression signature",
                    info.name
                ));
                continue;
            }
            Err(DecompressError::TooLarge) => {
                // The work up to the cap was done, so it is spent.
                source_left -= cap;
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
        super::vba_symbols::extract(&source, symbols_out, &mut agg);
        logical_lines += logical_line_count(&source);
        if looks_generated_name(&info.name) {
            generated_names += 1;
        }

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
        metrics.insert(
            metric!("office.vba.total_logical_lines"),
            logical_lines as f64,
        );
        if generated_names > 0 {
            metrics.insert(
                metric!("office.vba.random_named_module_count"),
                generated_names as f64,
            );
        }

        // Identifier-shape signals over this document's VBA symbol names
        // (imports + functions): mean length, Shannon entropy of the
        // byte-frequency distribution, and the count of *distinct* trigger
        // handlers. Random/obfuscated macros skew length+entropy; the
        // distinct-trigger count separates one auto-exec stub from a doc
        // that hooks many lifecycle events.
        let mut byte_counts = [0u64; 256];
        let mut total_chars = 0usize;
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
            metrics.insert(
                metric!("office.vba.identifier_entropy"),
                crate::scan::entropy::shannon_from_histogram(&byte_counts, total_chars),
            );
        }
        metrics.insert(
            metric!("office.vba.distinct_trigger_count"),
            distinct_triggers.len() as f64,
        );
    }
}

/// Non-blank lines of VBA source: the size of the code a person (or a
/// generator) wrote, independent of padding blank lines.
fn logical_line_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

/// Whether a module name looks generated rather than chosen: eight or more
/// characters mixing upper case, lower case and digits (`xKpL7m8sWq`).
/// Office's own names (`Module1`, `ThisDocument`, `Sheet1`) and a person's
/// (`clsLogger`) do not.
fn looks_generated_name(name: &str) -> bool {
    name.len() >= 8
        && name.bytes().any(|b| b.is_ascii_uppercase())
        && name.bytes().any(|b| b.is_ascii_lowercase())
        && name.bytes().any(|b| b.is_ascii_digit())
}

/// Decompress VBA macros carried in an OOXML `vbaProject.bin` member.
///
/// `vbaProject.bin` is itself a standalone CFBF compound file, so once
/// its bytes are read out of the zip they flow through the same CFB walk
/// as the binary-document [`extract`] path and populate `office.vba.*`
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
    // package declares which part is the VBA project. The part name is free
    // to choose: a `Default Extension="bin"
    // ContentType="application/vnd.ms-office.vbaProject"` declaration makes
    // any `.bin` part the project, so a name match alone would miss renamed
    // projects.
    //
    // OPC part names compare without regard to ASCII case (ECMA-376 Part 2
    // §9.1.1.1), so a declared name that matches no part exactly still
    // finds its part whatever the case of either.
    let declared: Vec<&str> = values
        .lookup(value_key!("office.macros"))
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .collect();
    let exact = declared
        .iter()
        .find(|n| zip.index_for_name(n).is_some())
        .map(|n| (*n).to_string());
    let declared = exact.or_else(|| {
        if declared.is_empty() {
            return None;
        }
        let folded: HashMap<String, String> = zip
            .file_names()
            .filter_map(Result::ok)
            .map(|n| (n.to_ascii_lowercase(), n.into_owned()))
            .collect();
        declared
            .iter()
            .find_map(|n| folded.get(&n.to_ascii_lowercase()).cloned())
    });
    let Some(name) = declared.or_else(|| {
        zip.file_names()
            .filter_map(Result::ok)
            .find(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin"))
            .map(std::borrow::Cow::into_owned)
    }) else {
        return;
    };
    let mut report = Report::new(errors, Stage::OoxmlParse, Some(&name));
    if let Some(bytes) = read_project_part(zip, &name, &mut report) {
        match cfb::CompoundFile::open(Cursor::new(bytes)) {
            Ok(mut comp) => extract_project(&mut comp, values, metrics, symbols_out, &mut report),
            Err(e) => {
                report.failure(format!("VBA project does not open as a compound file: {e}"));
            }
        }
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
    /// Where the compressed source starts in the module stream, from
    /// MODULEOFFSET; `None` for a stream found without a dir record, whose
    /// source is located by [`source_start`].
    offset: Option<u32>,
    module_type: VbaModuleType,
}

/// Module records parsed out of a decompressed `dir` stream.
#[derive(Default)]
struct DirStream {
    modules: Vec<ModuleInfo>,
    /// A record's declared size ran past the end of the stream: the stream
    /// is truncated or corrupt, and the last module may be incomplete.
    truncated: bool,
}

/// Walk the CFB entries looking for a `/dir` stream under any of the
/// documented VBA storage paths. Returns the prefix (e.g. `/VBA`,
/// `/Macros/VBA`) — without the trailing `/dir`.
fn find_vba_prefix<R: Read + std::io::Seek>(comp: &cfb::CompoundFile<R>) -> Option<String> {
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
        let found = entries.iter().any(|entry| {
            let path = entry.trim_start_matches('/');
            path.get(..cand.len())
                .is_some_and(|storage| storage.eq_ignore_ascii_case(cand))
                && path
                    .get(cand.len()..)
                    .is_some_and(|rest| rest.eq_ignore_ascii_case("/dir"))
        });
        if found {
            return Some(format!("/{cand}"));
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

/// Decompress an MS-OVBA RLE stream into at most `cap` bytes. The format
/// starts with a `0x01` signature byte; each subsequent chunk has a 12-bit
/// length plus an "is compressed" bit. Compressed chunks alternate 1-byte
/// flag fields with eight tokens (literal byte or LZ-style back-reference).
fn decompress_vba(data: &[u8], cap: usize) -> Result<Vec<u8>, DecompressError> {
    let Some(&signature) = data.first() else {
        return Ok(Vec::new());
    };
    if signature != 0x01 {
        return Err(DecompressError::BadSignature);
    }
    let mut output: Vec<u8> = Vec::with_capacity(data.len().saturating_mul(2).min(cap));
    let mut pos = 1usize;
    while pos < data.len() {
        let Some(header) = crate::bytes::u16_le(data, pos) else {
            break;
        };
        pos += 2;
        let chunk_size = usize::from(header & 0x0FFF) + 3;
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
                    let Some(token) = crate::bytes::u16_le(data, pos) else {
                        pos = data.len();
                        break;
                    };
                    pos += 2;
                    let decompressed_pos = output.len().saturating_sub(decompressed_start);
                    let bits = max_bit_count(decompressed_pos);
                    let len_mask = 0xFFFFu16 >> bits;
                    let off_mask = !len_mask;
                    let length = usize::from(token & len_mask) + 3;
                    let offset = usize::from((token & off_mask) >> (16 - bits)) + 1;
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
/// the offset claims more. Getting the split backwards still yields
/// plausible-looking bytes, so a wrong decoder fails silently on dir-stream
/// record sizes rather than loudly.
fn max_bit_count(decompressed_pos: usize) -> u16 {
    let mut bits = 4u16;
    while bits < 12 && (1usize << bits) < decompressed_pos {
        bits += 1;
    }
    bits
}

/// The `Id` and `Size` of the dir-stream record at `pos`, when its 6-byte
/// header is wholly inside `data`.
fn record_header(data: &[u8], pos: usize) -> Option<(u16, usize)> {
    let id = crate::bytes::u16_le(data, pos)?;
    let size = crate::bytes::u32_le(data, pos.checked_add(2)?)?;
    // A size past the stream's end reads nothing either way; clamping it keeps
    // the walk's `pos += 6 + size` steps from wrapping on 32-bit targets.
    Some((id, crate::bytes::sat_usize(size).min(data.len())))
}

/// PROJECTVERSION: its `Size` field is a constant 4 (MS-OVBA calls it
/// Reserved), but six bytes of version follow it.
const PROJECTVERSION: u16 = 0x0009;
/// The record that ends the dir stream (MS-OVBA §2.3.4.2, `Terminator`).
const DIR_TERMINATOR: u16 = 0x0010;
/// MODULENAME, the first record of each module.
const MODULENAME: u16 = 0x0019;

/// Parse the decompressed dir stream into per-module metadata
/// records (name, on-disk stream name, source-offset within that
/// stream, module kind). Per MS-OVBA §2.3.4.2.
///
/// The stream is walked record by record from its start: every record of
/// PROJECTINFORMATION, PROJECTREFERENCES and PROJECTMODULES is an `Id`, a
/// `Size` and `Size` bytes, PROJECTVERSION excepted. Records are never found
/// by searching for their bytes, which text inside a project constant or a
/// reference's LibId could imitate. The walk ends at the dir terminator.
fn parse_dir_stream(data: &[u8]) -> DirStream {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some((record_id, record_size)) = record_header(data, pos) {
        match record_id {
            DIR_TERMINATOR => break,
            PROJECTVERSION => pos += 6 + 6,
            MODULENAME => {
                // MODULENAME (record_size bytes of MBCS text)
                pos += 6;
                let name = read_ascii_string(data, pos, record_size);
                pos += record_size;
                let mut info = ModuleInfo {
                    name: name.clone(),
                    stream_name: name,
                    offset: Some(0),
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
                            // character, so a module called `Módulo1` would
                            // name a stream `M?dulo1` that does not exist.
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
                            if sub_size >= 4
                                && let Some(offset) = crate::bytes::u32_le(data, pos)
                            {
                                info.offset = Some(offset);
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
                        0x002B => {
                            pos += 6; // MODULETERMINATOR
                            break;
                        }
                        // A module without its terminator ends where the
                        // next module or the stream does.
                        MODULENAME | DIR_TERMINATOR => break,
                        // Everything else, MODULEDOCSTRING and its Unicode
                        // twin included, is a plain id/size record.
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

/// Where the compressed source of a module stream starts, found by its
/// opening rather than a dir record. Every module's source begins
/// `Attribute VB_Name`; compressed, that is the container signature `0x01`,
/// a two-byte chunk header, then two all-literal flag groups:
/// `00 "Attribut" 00 "e "`.
fn source_start(stream: &[u8]) -> Option<usize> {
    const OPENING: &[u8] = b"\x00Attribut\x00e ";
    let at = stream
        .windows(OPENING.len())
        .position(|w| w == OPENING)?
        .checked_sub(3)?;
    (stream.get(at) == Some(&0x01)).then_some(at)
}

/// The module streams of the VBA storage at `prefix`, for a project whose
/// dir stream names none: every stream except the project's own (`dir`,
/// `_VBA_PROJECT`, `__SRP_*`), at most [`MAX_MODULES`] of them, each to be
/// read from where [`source_start`] finds its source.
fn storage_modules<R: Read + Seek>(comp: &cfb::CompoundFile<R>, prefix: &str) -> Vec<ModuleInfo> {
    let Ok(entries) = comp.read_storage(prefix) else {
        return Vec::new();
    };
    entries
        .filter(cfb::Entry::is_stream)
        .map(|entry| entry.name().to_string())
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower != "dir" && lower != "_vba_project" && !lower.starts_with("__srp_")
        })
        .take(MAX_MODULES)
        .map(|name| ModuleInfo {
            stream_name: name.clone(),
            name,
            offset: None,
            module_type: VbaModuleType::Standard,
        })
        .collect()
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
    let mut s = crate::bytes::utf16_strict(bytes, crate::bytes::Endian::Little)?;
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
