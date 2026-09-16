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
//! feature flag, etc.). Failure to find the VBA project or decompress
//! a single module is silent — partial output is more useful than
//! none.

use crate::metric;
use std::io::{Cursor, Read, Seek};

use serde_json::Value as JsonValue;

use crate::output::{Metrics, Values};

/// Cap on the decompressed size of a single module — 10 MiB matches
/// cleave's bound.
const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;
/// Cap on the raw CFB stream length we'll read into memory.
const MAX_STREAM_SIZE: u64 = 20 * 1024 * 1024;
/// Cap on the number of modules we'll surface. Real projects max out
/// around 50; the cap keeps a hostile doc with thousands of empty
/// module records from blowing past the allocator.
const MAX_MODULES: usize = 256;

/// Walk the CFB and surface VBA modules under `office.vba.*`. The
/// dispatcher is expected to have already opened the file via
/// [`ole2::extract`]; this re-opens it because the cfb crate keeps
/// the archive handle mutable internally and we'd otherwise have to
/// thread it through the dispatch contract.
///
/// Module source bytes are also fed to [`super::vba_symbols::extract`],
/// which pushes `vba-declare`, `vba-createobject`, `vba-getobject`,
/// and `vba-decl` entries into the unified `symbols_out` view plus
/// document-level aggregate metrics under `office.vba.*_count`.
pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
) {
    let cursor = Cursor::new(bytes);
    let Ok(mut comp) = cfb::CompoundFile::open(cursor) else {
        return;
    };
    let Some(prefix) = find_vba_prefix(&mut comp) else {
        return;
    };

    // Read & decompress the dir stream.
    let dir_path = format!("{prefix}/dir");
    let Ok(dir_bytes) = read_stream(&mut comp, &dir_path) else {
        return;
    };
    let Ok(dir_decompressed) = decompress_vba(&dir_bytes) else {
        return;
    };

    // Parse module metadata from the decompressed dir stream.
    let module_infos = parse_dir_stream(&dir_decompressed);
    let mut modules: Vec<JsonValue> = Vec::new();
    // Document-level aggregate counters folded across modules. The
    // per-module stats from `vba_symbols::extract` accumulate here
    // so a doc with three modules and one Declare each surfaces a
    // single `office.vba.declare_count = 3`.
    let mut agg = super::vba_symbols::VbaSymbolStats::default();
    // Mark where this document's VBA symbols start so the identifier-shape
    // metrics below are computed over exactly the symbols emitted here.
    let sym_start = symbols_out.len();
    for info in module_infos.iter().take(MAX_MODULES) {
        let stream_path = format!("{}/{}", prefix, info.stream_name);
        let Ok(stream_bytes) = read_stream(&mut comp, &stream_path) else {
            continue;
        };
        let offset = info.offset as usize;
        if offset >= stream_bytes.len() {
            continue;
        }
        let Ok(source_bytes) = decompress_vba(&stream_bytes[offset..]) else {
            continue;
        };
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
        values.insert("office.vba.modules", JsonValue::Array(modules));
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
                byte_counts[b as usize] = byte_counts[b as usize].saturating_add(1);
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
                metric!("office.vba.mean_identifier_length"),
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
pub(super) fn extract_from_zip<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
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
        .get("office.macros")
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
    let Ok(mut entry) = zip.by_name(&name) else {
        return;
    };
    if entry.size() > MAX_STREAM_SIZE {
        return;
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    if entry.read_to_end(&mut bytes).is_err() {
        return;
    }
    extract(&bytes, values, metrics, symbols_out);
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
            return Some(entry[..entry.len() - 4].to_string());
        }
    }
    None
}

fn read_stream<R: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<R>,
    path: &str,
) -> Result<Vec<u8>, std::io::Error> {
    let mut stream = comp.open_stream(path)?;
    let size = stream.len();
    if size > MAX_STREAM_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream too large",
        ));
    }
    let mut buf = Vec::with_capacity(size as usize);
    stream.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Decompress an MS-OVBA RLE stream. The format starts with a `0x01`
/// signature byte; each subsequent chunk has a 12-bit length plus an
/// "is compressed" bit. Compressed chunks alternate 1-byte flag fields
/// with eight tokens (literal byte or LZ-style back-reference).
fn decompress_vba(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] != 0x01 {
        return Err("invalid VBA compression signature");
    }
    let mut output: Vec<u8> =
        Vec::with_capacity(data.len().saturating_mul(2).min(MAX_DECOMPRESSED_SIZE));
    let mut pos = 1usize;
    while pos < data.len() {
        if pos + 1 >= data.len() {
            break;
        }
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let chunk_size = (header & 0x0FFF) as usize + 3;
        let is_compressed = (header & 0x8000) != 0;
        if !is_compressed {
            let end = (pos + 4096).min(data.len());
            let copy_len = end - pos;
            if output.len() + copy_len > MAX_DECOMPRESSED_SIZE {
                return Err("decompressed size exceeds cap");
            }
            output.extend_from_slice(&data[pos..end]);
            pos = end;
            continue;
        }
        let chunk_end = pos
            .saturating_add(chunk_size)
            .saturating_sub(2)
            .min(data.len());
        let decompressed_start = output.len();
        while pos < chunk_end {
            if pos >= data.len() {
                break;
            }
            let flag = data[pos];
            pos += 1;
            for bit in 0..8u8 {
                if pos >= chunk_end {
                    break;
                }
                if (flag >> bit) & 1 == 0 {
                    if pos < data.len() {
                        if output.len() >= MAX_DECOMPRESSED_SIZE {
                            return Err("decompressed size exceeds cap");
                        }
                        output.push(data[pos]);
                        pos += 1;
                    }
                } else {
                    if pos + 1 >= data.len() {
                        pos = data.len();
                        break;
                    }
                    let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    let decompressed_pos = output.len().saturating_sub(decompressed_start);
                    let bits = max_bit_count(decompressed_pos);
                    let len_mask = 0xFFFFu16 >> bits;
                    let off_mask = !len_mask;
                    let length = ((token & len_mask) + 3) as usize;
                    let offset = ((token & off_mask) >> (16 - bits)) as usize + 1;
                    if output.len().saturating_add(length) > MAX_DECOMPRESSED_SIZE {
                        return Err("decompressed size exceeds cap");
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

/// Parse the decompressed dir stream into per-module metadata
/// records (name, on-disk stream name, source-offset within that
/// stream, module kind). Per MS-OVBA §2.3.4.2.
fn parse_dir_stream(data: &[u8]) -> Vec<ModuleInfo> {
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
    while pos + 6 <= data.len() {
        let record_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let record_size =
            u32::from_le_bytes([data[pos + 2], data[pos + 3], data[pos + 4], data[pos + 5]])
                as usize;
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
                while pos + 6 <= data.len() {
                    let sub_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    let sub_size = u32::from_le_bytes([
                        data[pos + 2],
                        data[pos + 3],
                        data[pos + 4],
                        data[pos + 5],
                    ]) as usize;
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
                            if pos + 6 <= data.len()
                                && u16::from_le_bytes([data[pos], data[pos + 1]]) == 0x0032
                            {
                                let next_size = u32::from_le_bytes([
                                    data[pos + 2],
                                    data[pos + 3],
                                    data[pos + 4],
                                    data[pos + 5],
                                ]) as usize;
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
                            if sub_size >= 4 && pos + 4 <= data.len() {
                                info.offset = u32::from_le_bytes([
                                    data[pos],
                                    data[pos + 1],
                                    data[pos + 2],
                                    data[pos + 3],
                                ]);
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
                            if pos + 6 <= data.len()
                                && u16::from_le_bytes([data[pos], data[pos + 1]]) == 0x0048
                            {
                                let next_size = u32::from_le_bytes([
                                    data[pos + 2],
                                    data[pos + 3],
                                    data[pos + 4],
                                    data[pos + 5],
                                ]) as usize;
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
    out
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
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes);
    let mut s: String = char::decode_utf16(units).collect::<Result<_, _>>().ok()?;
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
mod tests {
    use super::*;

    #[test]
    fn a_unicode_stream_name_survives_where_the_mbcs_one_is_mangled() {
        // `Módulo1` in UTF-16LE. The MBCS twin of this field is code-page
        // bytes, so the lossy UTF-8 read of it cannot round-trip the accent.
        let wide: Vec<u8> = "M\u{f3}dulo1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            read_utf16_string(&wide, 0, wide.len()).as_deref(),
            Some("M\u{f3}dulo1")
        );
    }

    #[test]
    fn a_malformed_unicode_stream_name_is_rejected_rather_than_guessed() {
        let wide: Vec<u8> = "Mod1".encode_utf16().flat_map(u16::to_le_bytes).collect();
        // Truncated: the declared length runs past the end of the stream.
        assert_eq!(read_utf16_string(&wide, 0, wide.len() + 2), None);
        // A length that cannot be whole UTF-16 code units.
        assert_eq!(read_utf16_string(&wide, 0, 3), None);
        // An unpaired surrogate.
        assert_eq!(read_utf16_string(&[0x00, 0xD8], 0, 2), None);
        // NUL padding alone carries no name.
        assert_eq!(read_utf16_string(&[0, 0, 0, 0], 0, 4), None);
        // An offset past the end does not panic.
        assert_eq!(read_utf16_string(&wide, wide.len() + 9, 2), None);
    }

    #[test]
    fn decompress_empty_input_yields_empty_output() {
        assert!(decompress_vba(&[]).unwrap().is_empty());
    }

    #[test]
    fn decompress_rejects_wrong_signature() {
        // First byte must be 0x01.
        let err = decompress_vba(&[0xFF, 0x00, 0x00]).unwrap_err();
        assert!(err.contains("signature"));
    }

    #[test]
    fn decompress_uncompressed_chunk_roundtrip() {
        // Signature, header with high bit clear (uncompressed),
        // followed by 5 literal bytes. The decompressor reads up to
        // 4096 bytes after the header for uncompressed chunks.
        let mut input = vec![0x01u8];
        input.extend_from_slice(&0x0002_u16.to_le_bytes()); // chunk_size 2+3=5, uncompressed
        input.extend_from_slice(b"hello");
        let out = decompress_vba(&input).unwrap();
        assert!(out.starts_with(b"hello"));
    }

    #[test]
    fn max_bit_count_matches_spec_steps() {
        // MAX(4, CeilingLog2(DecompressedCurrent - DecompressedChunkStart)),
        // capped at 12 (MS-OVBA 2.4.1.3.19.1). It grows with the position;
        // it used to shrink, which decoded every copy token wrongly.
        assert_eq!(max_bit_count(0), 4);
        assert_eq!(max_bit_count(4), 4);
        assert_eq!(max_bit_count(16), 4);
        assert_eq!(max_bit_count(17), 5);
        assert_eq!(max_bit_count(32), 5);
        assert_eq!(max_bit_count(33), 6);
        assert_eq!(max_bit_count(0x800), 11);
        assert_eq!(max_bit_count(0x1000), 12);
        // Capped, and never spins on a huge input.
        assert_eq!(max_bit_count(usize::MAX), 12);
    }

    /// A dir stream shaped like a real one: the PROJECTVERSION quirk, one
    /// reference, then the modules.
    fn realistic_dir_stream() -> Vec<u8> {
        let mut d = Vec::new();
        let rec = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
            d.extend_from_slice(&id.to_le_bytes());
            d.extend_from_slice(&(body.len() as u32).to_le_bytes());
            d.extend_from_slice(body);
        };
        rec(&mut d, 0x0001, &1u32.to_le_bytes()); // SysKind
        rec(&mut d, 0x0002, &0x0409u32.to_le_bytes()); // Lcid
        rec(&mut d, 0x0003, &0x04e4u16.to_le_bytes()); // CodePage
        rec(&mut d, 0x0004, b"Project"); // Name
        // PROJECTVERSION: Size is Reserved and reads 4, the payload is 6.
        d.extend_from_slice(&0x0009u16.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // A registered reference, whose layout the generic walk cannot follow.
        rec(&mut d, 0x0016, b"stdole");
        rec(
            &mut d,
            0x000D,
            b"*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#stdole2.tlb#OLE",
        );
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // PROJECTMODULES + PROJECTCOOKIE, then one module.
        d.extend_from_slice(&0x000Fu16.to_le_bytes());
        d.extend_from_slice(&2u32.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&0x0013u16.to_le_bytes());
        d.extend_from_slice(&2u32.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        rec(&mut d, 0x0019, b"ThisDocument"); // MODULENAME
        rec(&mut d, 0x001A, b"ThisDocument"); // MODULESTREAMNAME
        rec(&mut d, 0x0031, &0x2Au32.to_le_bytes()); // MODULEOFFSET
        rec(&mut d, 0x0022, &[]); // MODULETYPE: class
        rec(&mut d, 0x002B, &[]); // MODULETERMINATOR
        d
    }

    #[test]
    fn modules_are_found_past_the_version_quirk_and_the_references() {
        // Walking from byte zero by id/size reaches no module on a real file:
        // PROJECTVERSION lies about its length and the references have their
        // own layouts. Anchoring on PROJECTMODULES steps over both.
        let infos = parse_dir_stream(&realistic_dir_stream());
        assert_eq!(infos.len(), 1, "expected one module");
        assert_eq!(infos[0].name, "ThisDocument");
        assert_eq!(infos[0].stream_name, "ThisDocument");
        assert_eq!(infos[0].offset, 0x2A);
    }

    #[test]
    fn a_non_ascii_module_name_comes_from_the_unicode_record() {
        // `Módulo1` in code-page bytes is not UTF-8, so reading the MBCS
        // record gives `M<replacement>dulo1` and the stream lookup misses.
        // MS-OVBA writes the same name in UTF-16 right after it.
        let mut d = Vec::new();
        d.extend_from_slice(&0x000Fu16.to_le_bytes());
        d.extend_from_slice(&2u32.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        let rec = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
            d.extend_from_slice(&id.to_le_bytes());
            d.extend_from_slice(&(body.len() as u32).to_le_bytes());
            d.extend_from_slice(body);
        };
        rec(&mut d, 0x0019, b"M\xf3dulo1"); // MODULENAME, cp1252
        rec(&mut d, 0x001A, b"M\xf3dulo1"); // MODULESTREAMNAME, cp1252
        let wide: Vec<u8> = "Módulo1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        rec(&mut d, 0x0032, &wide); // the Unicode variant
        rec(&mut d, 0x0031, &4u32.to_le_bytes());
        rec(&mut d, 0x002B, &[]);

        let infos = parse_dir_stream(&d);
        assert_eq!(infos.len(), 1);
        assert_eq!(
            infos[0].stream_name, "Módulo1",
            "stream name must come from the UTF-16 record"
        );
    }

    #[test]
    fn dir_stream_parser_handles_empty_input() {
        let infos = parse_dir_stream(&[]);
        assert!(infos.is_empty());
    }

    #[test]
    fn decompress_compressed_chunk_pure_literals() {
        // Compressed chunk with only literal tokens. MS-OVBA encodes
        // chunk_size as `stored + 3` where the stored value is the
        // 12 low bits of the chunk header. chunk_size *includes* the
        // 2-byte chunk header, so a body of (flag + 8 literals) = 9
        // bytes needs chunk_size = 11, encoded as stored=8.
        let mut input = vec![0x01u8];
        let header = 0x8000u16 | 0x0008u16;
        input.extend_from_slice(&header.to_le_bytes());
        input.push(0x00); // flag byte — all literals
        input.extend_from_slice(b"abcdefgh");
        let out = decompress_vba(&input).unwrap();
        assert_eq!(&out, b"abcdefgh");
    }

    #[test]
    fn decompress_compressed_chunk_with_back_reference() {
        // Literal "ABCD" (4 bytes) followed by a copy-token that
        // copies 3 bytes from offset 4 — yielding "ABCDABC".
        // Body: flag(1) + 4 literals + token(2) = 7 bytes.
        // chunk_size = 7 + 2 (header) = 9 → stored = 6.
        let mut input = vec![0x01u8];
        let header = 0x8000u16 | 0x0006u16;
        input.extend_from_slice(&header.to_le_bytes());
        // Flag byte: bits 0..3 are the four literals (=0), bit 4 is
        // the token (=1). High bits unused.
        input.push(0b0001_0000);
        input.extend_from_slice(b"ABCD");
        // Token at decompressed_pos=4, where BitCount is 4: the offset
        // occupies the top 4 bits and the length the low 12. Want length=3,
        // offset=4 -> length_field=0, offset_field=3 -> (3 << 12) | 0.
        let token = 0x3000u16;
        input.extend_from_slice(&token.to_le_bytes());
        let out = decompress_vba(&input).unwrap();
        assert_eq!(&out, b"ABCDABC");
    }

    #[test]
    fn decompress_handles_truncated_chunk_header() {
        // Signature plus a single byte — chunk header needs 2 bytes,
        // so the loop should exit cleanly.
        let input = vec![0x01u8, 0xAB];
        let out = decompress_vba(&input).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn dir_stream_parser_handles_multiple_modules() {
        let mut d = Vec::new();
        // Helper to push a record.
        let push_record = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
            d.extend_from_slice(&id.to_le_bytes());
            d.extend_from_slice(&(body.len() as u32).to_le_bytes());
            d.extend_from_slice(body);
        };
        push_record(&mut d, 0x0019, b"Module1");
        push_record(&mut d, 0x001A, b"Stream1");
        push_record(&mut d, 0x0031, &10u32.to_le_bytes());
        push_record(&mut d, 0x0021, &[]); // procedural
        push_record(&mut d, 0x002B, &[]); // terminator
        push_record(&mut d, 0x0019, b"ClassMod");
        push_record(&mut d, 0x001A, b"ClassStream");
        push_record(&mut d, 0x0031, &20u32.to_le_bytes());
        push_record(&mut d, 0x0022, &[]); // class
        push_record(&mut d, 0x002B, &[]);
        let infos = parse_dir_stream(&d);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].name, "Module1");
        assert_eq!(infos[0].stream_name, "Stream1");
        assert_eq!(infos[0].offset, 10);
        assert!(matches!(infos[0].module_type, VbaModuleType::Standard));
        assert_eq!(infos[1].name, "ClassMod");
        assert_eq!(infos[1].offset, 20);
        assert!(matches!(infos[1].module_type, VbaModuleType::Class));
    }

    #[test]
    fn dir_stream_parser_stops_at_terminator() {
        let mut d = Vec::new();
        // First module then a MODULETERMINATOR_PROJECT (0x000F) —
        // parser should stop, not pick up further records.
        d.extend_from_slice(&0x0019_u16.to_le_bytes());
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(b"Foo");
        d.extend_from_slice(&0x002B_u16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0x000F_u16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        // Ghost module past the terminator — shouldn't be parsed.
        d.extend_from_slice(&0x0019_u16.to_le_bytes());
        d.extend_from_slice(&5u32.to_le_bytes());
        d.extend_from_slice(b"Ghost");
        let infos = parse_dir_stream(&d);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "Foo");
    }

    #[test]
    fn dir_stream_parser_handles_truncated_record_size() {
        // Record claims a size that runs past the stream end —
        // parser must not panic.
        let mut d = Vec::new();
        d.extend_from_slice(&0x0019_u16.to_le_bytes());
        d.extend_from_slice(&1000u32.to_le_bytes()); // claims 1000 bytes of name
        d.extend_from_slice(b"shortbody"); // but only 9 are actually present
        let _ = parse_dir_stream(&d); // must not panic
    }

    #[test]
    fn ascii_string_handles_null_terminator() {
        // Trailing NULs (common in fixed-width stream slots) are
        // trimmed.
        let data = b"hello\0\0\0";
        assert_eq!(read_ascii_string(data, 0, 8), "hello");
    }

    #[test]
    fn ascii_string_bounds_checked() {
        // Out-of-bounds request returns an empty string instead of
        // panicking.
        assert_eq!(read_ascii_string(b"abc", 5, 2), "");
        assert_eq!(read_ascii_string(b"abc", 0, 100), "");
    }

    #[test]
    fn dir_stream_parser_extracts_single_module() {
        // Minimal dir stream with one MODULENAME + MODULESTREAMNAME +
        // MODULEOFFSET + MODULETERMINATOR record sequence.
        let mut d = Vec::new();
        // MODULENAME(0x0019) size=3 "Foo"
        d.extend_from_slice(&0x0019_u16.to_le_bytes());
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(b"Foo");
        // MODULESTREAMNAME(0x001A) size=3 "Bar"
        d.extend_from_slice(&0x001A_u16.to_le_bytes());
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(b"Bar");
        // MODULEOFFSET(0x0031) size=4 offset=42
        d.extend_from_slice(&0x0031_u16.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&42u32.to_le_bytes());
        // MODULETERMINATOR(0x002B) size=0
        d.extend_from_slice(&0x002B_u16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());

        let infos = parse_dir_stream(&d);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "Foo");
        assert_eq!(infos[0].stream_name, "Bar");
        assert_eq!(infos[0].offset, 42);
    }

    /// Wrap raw bytes as a single uncompressed MS-OVBA chunk so the
    /// decompressor round-trips them verbatim (`raw` must be ≤ 4096).
    fn ovba_store(raw: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8];
        out.extend_from_slice(&0u16.to_le_bytes()); // header, high bit clear → uncompressed
        out.extend_from_slice(raw);
        out
    }

    #[test]
    fn ooxml_vbaproject_member_is_decompressed() {
        use std::io::{Cursor, Write};

        // dir stream describing one standard module "Module1" whose
        // source lives in the "Module1" stream at offset 0.
        let mut dir = Vec::new();
        let push = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
            d.extend_from_slice(&id.to_le_bytes());
            d.extend_from_slice(&(body.len() as u32).to_le_bytes());
            d.extend_from_slice(body);
        };
        push(&mut dir, 0x0019, b"Module1"); // MODULENAME
        push(&mut dir, 0x001A, b"Module1"); // MODULESTREAMNAME
        push(&mut dir, 0x0031, &0u32.to_le_bytes()); // MODULEOFFSET = 0
        push(&mut dir, 0x0021, &[]); // procedural
        push(&mut dir, 0x002B, &[]); // terminator

        let source =
            b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  Shell \"calc.exe\"\r\nEnd Sub\r\n";

        // vbaProject.bin is a standalone CFBF with a /VBA storage.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
            comp.create_storage("/VBA").unwrap();
            {
                let mut s = comp.create_stream("/VBA/dir").unwrap();
                s.write_all(&ovba_store(&dir)).unwrap();
            }
            {
                let mut s = comp.create_stream("/VBA/Module1").unwrap();
                s.write_all(&ovba_store(source)).unwrap();
            }
        }
        let vba_bin = buf.into_inner();

        // Wrap it in an OOXML-style zip under word/vbaProject.bin.
        let mut zw = zip::ZipWriter::new(Cursor::new(Vec::<u8>::new()));
        zw.start_file(
            "word/vbaProject.bin",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zw.write_all(&vba_bin).unwrap();
        let zip_bytes = zw.finish().unwrap().into_inner();

        let mut zip = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        let mut symbols = crate::output::Symbols::new();
        extract_from_zip(&mut zip, &mut values, &mut metrics, &mut symbols);

        let modules = values
            .get("office.vba.modules")
            .and_then(|v| v.as_array())
            .expect("office.vba.modules populated from OOXML vbaProject.bin");
        assert_eq!(modules.len(), 1);
        let src = modules[0]
            .get("source")
            .and_then(|v| v.as_str())
            .expect("module source present");
        assert!(src.contains("AutoOpen"), "decompressed source: {src}");
        assert!(src.contains("Shell"));
        assert_eq!(metrics.get("office.vba.module_count"), Some(1.0));
    }
}
