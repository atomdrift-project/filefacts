//! Compiled HTML Help (`.chm`) extractor.
//!
//! Parses the ITSF header + ITSP directory + every PMGL chunk.
//! Surfaces `chm.itsf.*` (file-wide attribution), `chm.system.*`
//! (`#SYSTEM` records — title, compiler version, source filename,
//! default topic), the entry roster, and presence-flag indicators
//! (`chm.features[]`).
//!
//! LZX-compressed help topics aren't decompressed: every fact
//! traits consume lives in the Uncompressed section (ITSF header,
//! directory, `#SYSTEM`, `::DataSpace/NameList`). Keeping the
//! extractor pure-Rust per the project's "no external commands"
//! rule means skipping LZX entirely.
//!
//! Schema:
//!
//! - `chm.itsf.{version, timestamp_counter, lcid}` — ITSF header
//!   (the LCID here is the locale of the *compiling* machine, more
//!   honest than `chm.system.locale_id`).
//! - `chm.system.{title, default_topic, default_window,
//!   default_font, compiler_version, chm_filename, locale_id,
//!   timestamp}` — `#SYSTEM` records.
//! - `chm.content_sections[]` — names from `::DataSpace/NameList`.
//! - `chm.features[]` — Pike-style flag array: `html`, `toc`,
//!   `index`, `objinst`, `keyword_links`, `associative_links`,
//!   `fifti`.
//! - `chm.entries[]` — distinct user-visible internal file names
//!   (capped at 256 entries — `metrics.chm.user_entry_count` carries
//!   the raw count).

use crate::metric;
use crate::value_key;
use serde_json::{Value as JsonValue, json};

use crate::bytes::{self, Reader};
use crate::error::Error;
use crate::formats::common::{XorScan, extract_binary_strings};
use crate::output::{Metrics, Strings, Values};

const MAX_ENTRIES_SURFACED: usize = 256;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    image_end: &mut Option<u64>,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings, XorScan::No);

    let Some(header) = bytes
        .first_chunk::<0x60>()
        .filter(|h| h.starts_with(b"ITSF"))
    else {
        return Ok(());
    };
    // Every field is read out of the 0x60-byte version-3 `header`, so none
    // of the reads can come up short and the `unwrap_or(0)` defaults never
    // apply.
    let version = bytes::u32_le(header, 0x04).unwrap_or(0);
    if version != 3 {
        return Ok(());
    }
    let timestamp_counter = bytes::u32_le(header, 0x10).unwrap_or(0);
    let lcid = bytes::u32_le(header, 0x14).unwrap_or(0);

    let section1_offset = bytes::u64_le(header, 0x48).unwrap_or(0) as usize;
    let section1_length = bytes::u64_le(header, 0x50).unwrap_or(0) as usize;
    let data_offset = bytes::u64_le(header, 0x58).unwrap_or(0) as usize;

    let mut itsf = serde_json::Map::new();
    itsf.insert("version".into(), json!(version));
    itsf.insert("timestamp_counter".into(), json!(timestamp_counter));
    itsf.insert("lcid".into(), json!(lcid));
    values.insert_key(value_key!("chm.itsf"), JsonValue::Object(itsf));
    // The LCID is reachable via `chm.itsf.lcid` (nested value).
    // Don't dual-emit as a flat `chm.itsf_lcid` metric.

    let Some(dir) = bytes.get(section1_offset..section1_offset.saturating_add(section1_length))
    else {
        return Ok(());
    };
    let entries = parse_directory(dir);
    if entries.is_empty() {
        return Ok(());
    }

    // The archive consists of the ITSF directory and the physical data
    // extents for section-0 entries. Section-1 offsets are logical offsets
    // into the LZX stream and cannot be used as file offsets. This handles
    // both common layouts: data before the directory, and a directory at
    // the end of the file. Ignore invalid entry extents rather than letting
    // malformed offsets hide an appended payload.
    let Some(directory_end) = section1_offset.checked_add(section1_length) else {
        return Ok(());
    };
    let mut logical_end = directory_end as u64;
    for entry in entries.iter().filter(|entry| entry.section == 0) {
        let (Ok(offset), Ok(length)) =
            (usize::try_from(entry.offset), usize::try_from(entry.length))
        else {
            continue;
        };
        let Some(end) = data_offset
            .checked_add(offset)
            .and_then(|start| start.checked_add(length))
        else {
            continue;
        };
        if end <= bytes.len() {
            logical_end = logical_end.max(end as u64);
        }
    }
    *image_end = Some(image_end.unwrap_or(0).max(logical_end));

    // Presence-flag accumulator + user-visible entry list + roll-ups.
    let mut features: Vec<&'static str> = Vec::new();
    let mut user_entries: Vec<String> = Vec::new();
    let mut user_names_lower: Vec<String> = Vec::new();
    let mut html_count = 0_u32;
    let mut script_count = 0_u32;
    let mut image_count = 0_u32;
    let mut control_count = 0_u32;
    let mut user_count = 0_u32;
    let mut user_total: u64 = 0;
    let mut user_max: u64 = 0;

    for e in &entries {
        let stripped = e.name.strip_prefix('/').unwrap_or(&e.name);
        if is_control_name(stripped) {
            control_count += 1;
            match stripped {
                "$OBJINST" => push_unique(&mut features, "objinst"),
                "$WWKeywordLinks/Property" => push_unique(&mut features, "keyword_links"),
                "$WWAssociativeLinks/Property" => push_unique(&mut features, "associative_links"),
                "$FIftiMain" => push_unique(&mut features, "fifti"),
                _ => {}
            }
            continue;
        }
        if e.name == "/" || e.name.ends_with('/') || e.length == 0 {
            continue;
        }
        user_count += 1;
        user_total = user_total.saturating_add(e.length);
        if e.length > user_max {
            user_max = e.length;
        }
        let lower = e.name.to_ascii_lowercase();
        if lower.ends_with(".html") || lower.ends_with(".htm") {
            html_count += 1;
        }
        if lower.ends_with(".js") || lower.ends_with(".vbs") || lower.ends_with(".wsf") {
            script_count += 1;
        }
        if lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".gif")
            || lower.ends_with(".bmp")
        {
            image_count += 1;
        }
        if lower.ends_with(".hhc") {
            push_unique(&mut features, "toc");
        }
        if lower.ends_with(".hhk") {
            push_unique(&mut features, "index");
        }
        user_names_lower.push(stripped.to_ascii_lowercase());
        if user_entries.len() < MAX_ENTRIES_SURFACED {
            user_entries.push(e.name.clone());
        }
    }
    if html_count > 0 {
        push_unique(&mut features, "html");
    }
    if !features.is_empty() {
        values.insert_key(
            value_key!("chm.features"),
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
    if !user_entries.is_empty() {
        values.insert_key(
            value_key!("chm.entries"),
            JsonValue::Array(user_entries.into_iter().map(JsonValue::String).collect()),
        );
    }

    // Per-entry metrics roll-up (formerly cleave's `ChmMetrics`).
    metrics.insert(metric!("chm.user_entry_count"), f64::from(user_count));
    metrics.insert(metric!("chm.control_entry_count"), f64::from(control_count));
    metrics.insert(metric!("chm.html_entry_count"), f64::from(html_count));
    metrics.insert(metric!("chm.script_entry_count"), f64::from(script_count));
    metrics.insert(metric!("chm.image_entry_count"), f64::from(image_count));
    metrics.insert(metric!("chm.max_user_entry_size"), user_max as f64);
    metrics.insert(metric!("chm.total_user_entry_size"), user_total as f64);
    let file_size = bytes.len() as u64;
    if file_size > 0 {
        metrics.insert(
            metric!("chm.user_byte_ratio"),
            user_total as f64 / file_size as f64,
        );
    }

    // Content-section names from `::DataSpace/NameList` (Uncompressed
    // section 0 — no LZX needed).
    if let Some(name_list_entry) = entries.iter().find(|e| e.name == "::DataSpace/NameList") {
        if let Some(body) = read_uncompressed(bytes, data_offset, name_list_entry) {
            let sections = parse_namelist(body);
            if !sections.is_empty() {
                values.insert_key(
                    value_key!("chm.content_sections"),
                    JsonValue::Array(sections.into_iter().map(JsonValue::String).collect()),
                );
            }
        }
    }

    // `#SYSTEM` lives in the Uncompressed section. Some CHMs prefix
    // with `/`, some don't. We emit the kv subtree AND fold a few
    // consistency metrics (default_topic_missing, title_topic_mismatch,
    // no_compiler_version, infotype_count) so trait rules don't have
    // to recompute them from the kv tree.
    let sys_entry = entries
        .iter()
        .find(|e| e.name == "/#SYSTEM" || e.name == "#SYSTEM");
    let sys_summary = sys_entry
        .and_then(|e| read_uncompressed(bytes, data_offset, e))
        .map(|body| emit_system(body, values));
    let summary = sys_summary.unwrap_or_default();
    metrics.insert(
        metric!("chm.no_compiler_version"),
        f64::from(u8::from(!summary.has_compiler_version)),
    );
    metrics.insert(
        metric!("chm.infotype_count"),
        f64::from(summary.infotype_count),
    );
    if let Some(topic) = summary.default_topic.as_deref() {
        let topic_lower = topic.to_ascii_lowercase();
        let missing = !user_names_lower.iter().any(|n| n == &topic_lower);
        metrics.insert(
            metric!("chm.default_topic_missing"),
            f64::from(u8::from(missing)),
        );
    }
    if let (Some(title), Some(topic)) = (summary.title.as_deref(), summary.default_topic.as_deref())
    {
        let mismatch = !title.is_empty() && !topic.is_empty() && !title.eq_ignore_ascii_case(topic);
        metrics.insert(
            metric!("chm.title_topic_mismatch"),
            f64::from(u8::from(mismatch)),
        );
    }

    // LZX framing parameters for `MSCompressed/Content` — directly
    // parsed from `ControlData` + `ResetTable`, both of which live
    // in the Uncompressed section. No LZX decoder needed for the
    // framing kv; the actual help-topic decompression would.
    emit_lzx_framing(bytes, data_offset, &entries, values, metrics);

    Ok(())
}

/// Surface `chm.lzx.{window_bytes, reset_interval_bytes, block_len,
/// uncompressed_size, compressed_size}` when the CHM has an
/// `MSCompressed/Content` section. The framing tuple is a strong
/// "same toolchain" fingerprint — reproducible across rebuilds of
/// the same source even when the rebuild counter changes.
fn emit_lzx_framing(
    bytes: &[u8],
    data_offset: usize,
    entries: &[DirEntry],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Some(content) = entries
        .iter()
        .find(|e| e.name == "::DataSpace/Storage/MSCompressed/Content")
    else {
        return;
    };
    let Some(control) = entries
        .iter()
        .find(|e| e.name == "::DataSpace/Storage/MSCompressed/ControlData")
    else {
        return;
    };
    let Some(reset) = entries.iter().find(|e| {
        e.name
            .starts_with("::DataSpace/Storage/MSCompressed/Transform/")
            && e.name.ends_with("/InstanceData/ResetTable")
    }) else {
        return;
    };

    let Some(cd_bytes) = read_uncompressed(bytes, data_offset, control) else {
        return;
    };
    let Some(rt_bytes) = read_uncompressed(bytes, data_offset, reset) else {
        return;
    };
    let Some(cd) = parse_control_data(cd_bytes) else {
        return;
    };
    let Some(rt) = parse_reset_table(rt_bytes) else {
        return;
    };

    let mut lzx = serde_json::Map::new();
    lzx.insert("window_bytes".into(), json!(cd.window_bytes));
    lzx.insert(
        "reset_interval_bytes".into(),
        json!(u64::from(cd.reset_interval_chunks) * 0x8000),
    );
    lzx.insert("block_len".into(), json!(rt.block_len));
    lzx.insert("uncompressed_size".into(), json!(rt.uncompressed_size));
    lzx.insert("compressed_size".into(), json!(content.length));
    values.insert_key(value_key!("chm.lzx"), JsonValue::Object(lzx));

    metrics.insert(metric!("chm.lzx_reset_count"), rt.reset_count as f64);
    // Compression ratio is a classic forensic signal — values
    // significantly off from typical (~3-5×) suggest a hand-rolled
    // or tampered build.
    if content.length > 0 && rt.uncompressed_size > 0 {
        let ratio = rt.uncompressed_size as f64 / content.length as f64;
        metrics.insert(metric!("chm.lzx_compression_ratio"), ratio);
    }
}

struct ControlData {
    /// Reset interval in 0x8000-byte chunks. The decoder resets its
    /// state every `reset_interval_chunks × 32 KB` of *uncompressed*
    /// output.
    reset_interval_chunks: u32,
    /// LZX window size in bytes (`window_chunks × 32 KB`).
    window_bytes: u64,
}

fn parse_control_data(data: &[u8]) -> Option<ControlData> {
    if data.len() < 0x1c || data.get(4..8) != Some(b"LZXC") {
        return None;
    }
    let reset_interval_chunks = bytes::u32_le(data, 0x0c)?;
    let window_chunks = bytes::u32_le(data, 0x10)?;
    Some(ControlData {
        reset_interval_chunks,
        window_bytes: u64::from(window_chunks) * 0x8000,
    })
}

struct ResetTable {
    uncompressed_size: u64,
    block_len: u64,
    reset_count: u32,
}

fn parse_reset_table(data: &[u8]) -> Option<ResetTable> {
    if data.len() < 0x28 {
        return None;
    }
    let num_entries = bytes::u32_le(data, 0x04)?;
    let entry_size = bytes::u32_le(data, 0x08)?;
    let uncompressed_size = bytes::u64_le(data, 0x10)?;
    let block_len = bytes::u64_le(data, 0x20)?;
    if entry_size != 8 || block_len == 0 {
        return None;
    }
    Some(ResetTable {
        uncompressed_size,
        block_len,
        reset_count: num_entries,
    })
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    section: u64,
    offset: u64,
    length: u64,
}

fn read_uncompressed<'a>(bytes: &'a [u8], data_offset: usize, e: &DirEntry) -> Option<&'a [u8]> {
    if e.section != 0 {
        return None;
    }
    let start = data_offset.checked_add(usize::try_from(e.offset).ok()?)?;
    let end = start.checked_add(usize::try_from(e.length).ok()?)?;
    bytes.get(start..end)
}

fn parse_directory(section: &[u8]) -> Vec<DirEntry> {
    let mut out = Vec::new();
    if section.len() < 0x54 || !section.starts_with(b"ITSP") {
        return out;
    }
    // The length check above covers all three fields.
    let header_len = bytes::u32_le(section, 0x08).unwrap_or(0) as usize;
    let chunk_size = bytes::u32_le(section, 0x10).unwrap_or(0) as usize;
    let chunk_count = bytes::u32_le(section, 0x2c).unwrap_or(0) as usize;
    if chunk_size < 0x14 {
        return out;
    }
    for i in 0..chunk_count {
        let Some(off) = i
            .checked_mul(chunk_size)
            .and_then(|n| header_len.checked_add(n))
        else {
            break;
        };
        let Some(end) = off.checked_add(chunk_size) else {
            break;
        };
        let Some(chunk) = section.get(off..end) else {
            break;
        };
        if !chunk.starts_with(b"PMGL") {
            continue;
        }
        let Some(quickref) = bytes::u32_le(chunk, 0x04).map(|n| n as usize) else {
            continue;
        };
        if quickref >= chunk_size {
            continue;
        }
        let entries_end = chunk_size - quickref;
        let mut pos = 0x14_usize;
        while pos < entries_end {
            let Some((entry, consumed)) = chunk.get(pos..entries_end).and_then(parse_entry) else {
                break;
            };
            pos += consumed;
            out.push(entry);
        }
    }
    out
}

/// One PMGL directory entry: an ENCINT-prefixed name, then the section,
/// offset and length ENCINTs. Returns the entry and the bytes it took.
fn parse_entry(buf: &[u8]) -> Option<(DirEntry, usize)> {
    let (name_len, mut pos) = read_encint(buf)?;
    // The length is attacker-controlled and an ENCINT reaches `u64::MAX`, so
    // the end of the name is computed checked: `pos + name_len` used to
    // overflow (a panic in debug builds, and a reversed slice range in
    // release) before the bounds check could reject it.
    let name_end = pos.checked_add(usize::try_from(name_len).ok()?)?;
    let name = String::from_utf8_lossy(buf.get(pos..name_end)?).into_owned();
    pos = name_end;
    let (section, n) = read_encint(buf.get(pos..)?)?;
    pos += n;
    let (offset, n) = read_encint(buf.get(pos..)?)?;
    pos += n;
    let (length, n) = read_encint(buf.get(pos..)?)?;
    pos += n;
    Some((
        DirEntry {
            name,
            section,
            offset,
            length,
        },
        pos,
    ))
}

/// CHM ENCINT — variable-length, big-endian, high bit set on
/// every continuation byte.
fn read_encint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &b) in buf.iter().take(10).enumerate() {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// `::DataSpace/NameList` carries the content-section names (typically
/// `Uncompressed` and `MSCompressed`). Layout: u16 length-in-words +
/// u16 count + count × (u16 name_words + UTF-16LE name + u16 NUL).
fn parse_namelist(data: &[u8]) -> Vec<String> {
    let Some(count) = bytes::u16_le(data, 2).map(usize::from) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(count);
    let mut names = Reader::at(data, 4);
    for _ in 0..count {
        // A name counts only with its NUL terminator in the stream.
        let Some(name_words) = names.u16_le() else {
            break;
        };
        let Some(raw) = names.bytes(usize::from(name_words) * 2) else {
            break;
        };
        if names.skip(2).is_none() {
            break;
        }
        out.push(utf16le_to_string(raw));
    }
    out
}

/// Fields lifted out of `#SYSTEM` that downstream consistency
/// metrics consume. The kv subtree (`chm.system.*`) is a strict
/// superset of what lands here; the summary is just the subset
/// that `extract()` needs to compute derived flags.
#[derive(Default)]
struct SystemSummary {
    title: Option<String>,
    default_topic: Option<String>,
    has_compiler_version: bool,
    infotype_count: u32,
}

/// `#SYSTEM` is a sequence of `(u16 code, u16 length, u8[length] data)`
/// records prefixed by a u32 version word. Codes carrying
/// attribution-grade strings get surfaced as `chm.system.<field>`;
/// the function also returns a small summary used by the
/// consistency-check metrics in the caller.
fn emit_system(data: &[u8], values: &mut Values) -> SystemSummary {
    let mut summary = SystemSummary::default();
    let mut sys = serde_json::Map::new();
    let mut records = Reader::at(data, 4);
    while let Some(code) = records.u16_le()
        && let Some(len) = records.u16_le()
        && let Some(payload) = records.bytes(usize::from(len))
    {
        match code {
            0 => {
                if let Some(v) = insert_cstr(&mut sys, "default_topic", payload) {
                    summary.default_topic = Some(v);
                }
            }
            1 => {
                insert_cstr(&mut sys, "default_window", payload);
            }
            2 => {
                if let Some(v) = insert_cstr(&mut sys, "title", payload) {
                    summary.title = Some(v);
                }
            }
            3 => {
                if let Some(lcid) = bytes::u32_le(payload, 0) {
                    sys.insert("locale_id".into(), json!(lcid));
                }
            }
            4 => {
                if let Some(ts) = bytes::u32_le(payload, 4) {
                    sys.insert("timestamp".into(), json!(ts));
                }
            }
            5 => summary.infotype_count = summary.infotype_count.saturating_add(1),
            6 => {
                insert_cstr(&mut sys, "chm_filename", payload);
            }
            9 => {
                if insert_cstr(&mut sys, "compiler_version", payload).is_some() {
                    summary.has_compiler_version = true;
                }
            }
            16 => {
                insert_cstr(&mut sys, "default_font", payload);
            }
            _ => {}
        }
    }
    if !sys.is_empty() {
        values.insert_key(value_key!("chm.system"), JsonValue::Object(sys));
    }
    summary
}

fn insert_cstr(
    obj: &mut serde_json::Map<String, JsonValue>,
    key: &str,
    payload: &[u8],
) -> Option<String> {
    let text = payload.split(|&c| c == 0).next().unwrap_or_default();
    let s = std::str::from_utf8(text).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let owned = trimmed.to_string();
    obj.insert(key.to_string(), JsonValue::String(owned.clone()));
    Some(owned)
}

/// CHM-internal entries (`#SYSTEM`, `$OBJINST`, `::DataSpace/...`)
/// share the `'#'` / `'::'` / `'$'` prefix convention.
fn is_control_name(stripped: &str) -> bool {
    stripped.starts_with('#') || stripped.starts_with("::") || stripped.starts_with('$')
}

fn push_unique(features: &mut Vec<&'static str>, name: &'static str) {
    if !features.iter().any(|f| *f == name) {
        features.push(name);
    }
}

fn utf16le_to_string(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut image_end = None;
        extract(bytes, &mut v, &mut s, &mut m, &mut image_end).unwrap();
        (v, m)
    }

    #[test]
    fn rejects_non_chm() {
        let (v, _) = run(b"not a chm");
        assert!(v.get("chm.itsf").is_none());
    }

    #[test]
    fn surfaces_itsf_header() {
        // Minimal ITSF v3 header with no directory content; we just want
        // to confirm itsf.* surfaces and the parser doesn't crash on a
        // missing/empty directory section.
        let mut buf = vec![0u8; 0x60];
        buf[..4].copy_from_slice(b"ITSF");
        buf[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        buf[0x10..0x14].copy_from_slice(&42u32.to_le_bytes()); // timestamp_counter
        buf[0x14..0x18].copy_from_slice(&0x0409u32.to_le_bytes()); // lcid = en-US
        // section1 offset/length point past end → empty directory
        buf[0x48..0x50].copy_from_slice(&0u64.to_le_bytes());
        buf[0x50..0x58].copy_from_slice(&0u64.to_le_bytes());
        buf[0x58..0x60].copy_from_slice(&0u64.to_le_bytes());
        let (v, _m) = run(&buf);
        let itsf = v.get("chm.itsf").and_then(|x| x.as_object()).unwrap();
        assert_eq!(itsf.get("version").and_then(|x| x.as_u64()), Some(3));
        assert_eq!(itsf.get("lcid").and_then(|x| x.as_u64()), Some(0x0409));
        assert_eq!(
            itsf.get("timestamp_counter").and_then(|x| x.as_u64()),
            Some(42)
        );
        // LCID is reachable via the nested `chm.itsf.lcid` value
        // surfaced above; no flat `chm.itsf_lcid` metric is emitted.
    }

    #[test]
    fn encint_decodes_single_and_multi_byte() {
        // Single-byte ENCINT (high bit clear).
        assert_eq!(read_encint(&[0x42]), Some((0x42, 1)));
        // Two-byte ENCINT: 0x81 = 1<<7|1, encoded high bits first
        // with the continuation marker on the leading byte.
        assert_eq!(read_encint(&[0x81, 0x01]), Some((0x81, 2)));
        // Empty or all-continuation inputs return None.
        assert_eq!(read_encint(&[]), None);
    }

    #[test]
    fn control_name_classifier() {
        assert!(is_control_name("$OBJINST"));
        assert!(is_control_name("#SYSTEM"));
        assert!(is_control_name("::DataSpace/NameList"));
        assert!(!is_control_name("help/topic.html"));
        assert!(!is_control_name("toc.hhc"));
    }

    #[test]
    fn rejects_wrong_version() {
        // Version 2 (only 3 is supported).
        let mut buf = vec![0u8; 0x60];
        buf[..4].copy_from_slice(b"ITSF");
        buf[0x04..0x08].copy_from_slice(&2u32.to_le_bytes());
        let (v, _) = run(&buf);
        assert!(v.get("chm.itsf").is_none());
    }

    #[test]
    fn truncated_header_doesnt_crash() {
        let (v, _) = run(b"ITSF\x03\0\0\0short");
        assert!(v.get("chm.itsf").is_none());
    }

    #[test]
    fn empty_input_is_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("chm.itsf").is_none());
    }

    #[test]
    fn parse_namelist_handles_known_sections() {
        // u16 reserved + u16 count + 2 entries.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&2u16.to_le_bytes()); // count
        for name in &["Uncompressed", "MSCompressed"] {
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            for c in name.encode_utf16() {
                buf.extend_from_slice(&c.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes()); // trailing NUL
        }
        let names = parse_namelist(&buf);
        assert_eq!(names, vec!["Uncompressed", "MSCompressed"]);
    }

    #[test]
    fn control_data_parser_recognizes_lzxc() {
        let mut buf = vec![0u8; 0x1c];
        buf[4..8].copy_from_slice(b"LZXC");
        buf[0x0c..0x10].copy_from_slice(&2u32.to_le_bytes()); // reset_interval_chunks
        buf[0x10..0x14].copy_from_slice(&32u32.to_le_bytes()); // window_chunks (1 MiB)
        let cd = parse_control_data(&buf).unwrap();
        assert_eq!(cd.reset_interval_chunks, 2);
        assert_eq!(cd.window_bytes, 32 * 0x8000);
    }

    #[test]
    fn control_data_rejects_wrong_signature() {
        let mut buf = vec![0u8; 0x1c];
        buf[4..8].copy_from_slice(b"XXXX");
        assert!(parse_control_data(&buf).is_none());
    }

    #[test]
    fn reset_table_rejects_wrong_entry_size() {
        let mut buf = vec![0u8; 0x28];
        // entry_size = 4 instead of expected 8
        buf[0x08..0x0c].copy_from_slice(&4u32.to_le_bytes());
        buf[0x20..0x28].copy_from_slice(&100u64.to_le_bytes()); // block_len
        assert!(parse_reset_table(&buf).is_none());
    }

    /// An ENCINT that decodes to `u64::MAX`: nine continuation bytes and a
    /// final `0x7F`.
    const HUGE_ENCINT: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];

    /// A directory entry whose name length is `u64::MAX` overflowed
    /// `pos + name_len` and panicked (a reversed slice range in release
    /// builds). It is a malformed entry: parsing stops there, and the
    /// entries before it are kept.
    #[test]
    fn a_huge_entry_name_length_does_not_panic() {
        assert_eq!(read_encint(&HUGE_ENCINT), Some((u64::MAX, 10)));
        let mut entry = HUGE_ENCINT.to_vec();
        entry.extend_from_slice(b"rest of the chunk");
        assert!(parse_entry(&entry).is_none());

        // The same entry reached through a whole file.
        const CHUNK: usize = 0x200;
        const ITSP_LEN: usize = 0x54;
        let mut chunk = vec![0u8; CHUNK];
        chunk[..4].copy_from_slice(b"PMGL");
        let mut entries = vec![7u8];
        entries.extend_from_slice(b"/a.html");
        entries.extend_from_slice(&[0, 0, 1]); // section 0, offset 0, length 1
        entries.extend_from_slice(&HUGE_ENCINT);
        chunk[0x14..0x14 + entries.len()].copy_from_slice(&entries);
        let mut itsp = vec![0u8; ITSP_LEN];
        itsp[..4].copy_from_slice(b"ITSP");
        itsp[0x08..0x0C].copy_from_slice(&(ITSP_LEN as u32).to_le_bytes());
        itsp[0x10..0x14].copy_from_slice(&(CHUNK as u32).to_le_bytes());
        itsp[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        let mut buf = vec![0u8; 0x60];
        buf[..4].copy_from_slice(b"ITSF");
        buf[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        buf[0x48..0x50].copy_from_slice(&0x60u64.to_le_bytes());
        buf[0x50..0x58].copy_from_slice(&((ITSP_LEN + CHUNK) as u64).to_le_bytes());
        buf[0x58..0x60].copy_from_slice(&((0x60 + ITSP_LEN + CHUNK) as u64).to_le_bytes());
        buf.extend_from_slice(&itsp);
        buf.extend_from_slice(&chunk);
        buf.push(b'x');
        let (v, m) = run(&buf);
        assert_eq!(v.get("chm.entries"), Some(&serde_json::json!(["/a.html"])));
        assert_eq!(m.get("chm.user_entry_count"), Some(1.0));
    }
}
