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
        metrics.insert("office.vba.module_count", count);
        // Aggregate symbol-extraction counters surface as metrics so
        // composite rules can count obfuscation signals without
        // walking the imports view.
        metrics.insert("office.vba.declare_count", f64::from(agg.declare_count));
        metrics.insert(
            "office.vba.declare_non_literal_count",
            f64::from(agg.declare_non_literal_count),
        );
        metrics.insert(
            "office.vba.createobject_count",
            f64::from(agg.createobject_count),
        );
        metrics.insert(
            "office.vba.createobject_non_literal_count",
            f64::from(agg.createobject_non_literal_count),
        );
        metrics.insert("office.vba.getobject_count", f64::from(agg.getobject_count));
        metrics.insert(
            "office.vba.getobject_non_literal_count",
            f64::from(agg.getobject_non_literal_count),
        );
        metrics.insert(
            "office.vba.trigger_handler_count",
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
                "office.vba.mean_identifier_length",
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
            metrics.insert("office.vba.identifier_entropy", entropy);
        }
        metrics.insert(
            "office.vba.distinct_trigger_count",
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
/// path. A document carries a single `vbaProject.bin`; the first match
/// wins, matching the legacy extractor's selection.
pub(super) fn extract_from_zip<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::output::Symbols,
) {
    let Some(name) = zip
        .file_names()
        .find(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin"))
        .map(str::to_string)
    else {
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
        .map(|e| e.path().to_string_lossy().into_owned())
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

/// Compute the offset-bit count for a copy token at the given
/// decompressed-position (MS-OVBA §2.4.1.3.19.1). Smaller positions
/// reserve more bits for the length field; the longer the chunk
/// runs, the more bits the offset claims.
fn max_bit_count(decompressed_pos: usize) -> u16 {
    if decompressed_pos <= 0x80 {
        return 12;
    }
    let mut bits = 12u16;
    let mut threshold = 0x80usize;
    // `checked_mul(2)` returns `None` when the next doubling would
    // wrap — that's the exit condition for `usize::MAX`-style inputs
    // that would otherwise spin the loop forever (the verbatim port
    // of cleave's code had this bug; this is the fix).
    while threshold < decompressed_pos {
        let Some(next) = threshold.checked_mul(2) else {
            break;
        };
        threshold = next;
        if bits > 4 {
            bits -= 1;
        }
    }
    bits
}

/// Parse the decompressed dir stream into per-module metadata
/// records (name, on-disk stream name, source-offset within that
/// stream, module kind). Per MS-OVBA §2.3.4.2.
fn parse_dir_stream(data: &[u8]) -> Vec<ModuleInfo> {
    let mut out = Vec::new();
    let mut pos = 0usize;
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
                            // MODULESTREAMNAME (MBCS)
                            pos += 6;
                            info.stream_name = read_ascii_string(data, pos, sub_size);
                            pos += sub_size;
                            // Skip the trailing UTF-16LE variant
                            // (0x0032) if present.
                            if pos + 6 <= data.len()
                                && u16::from_le_bytes([data[pos], data[pos + 1]]) == 0x0032
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

fn read_ascii_string(data: &[u8], pos: usize, len: usize) -> String {
    if pos + len > data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&data[pos..pos + len])
        .trim_end_matches('\0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // ≤0x80 → 12 bits for the offset.
        assert_eq!(max_bit_count(0), 12);
        assert_eq!(max_bit_count(0x80), 12);
        // Each doubling past 0x80 shaves one bit, floor 4.
        assert_eq!(max_bit_count(0x81), 11);
        assert_eq!(max_bit_count(0x101), 10);
        assert_eq!(max_bit_count(0x201), 9);
        // Tail saturates at 4.
        assert!(max_bit_count(usize::MAX) >= 4);
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
        // Token at decompressed_pos=4 where max_bit_count=12. Per
        // MS-OVBA §2.4.1.3.19.3 the offset_field occupies the high
        // `bit_count` bits and length_field the low `16 - bit_count`
        // bits — so for bit_count=12, offset has 12 bits in the
        // upper half and length has 4 bits in the lower nibble.
        // Want length=3, offset=4 → length_field=0, offset_field=3
        // → token = (3 << 4) | 0 = 0x0030.
        let token = 0x0030u16;
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
        zw.start_file("word/vbaProject.bin", zip::write::SimpleFileOptions::default())
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
