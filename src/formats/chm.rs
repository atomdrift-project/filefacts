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
use crate::formats::common::{XorScan, ends_with_ci, extract_binary_strings};
use crate::output::{Metrics, Strings, Values};

const MAX_ENTRIES_SURFACED: usize = 256;
/// Directory entries parsed. An entry takes as little as four bytes of
/// directory and becomes an owned name, a lowercased copy and a `DirEntry`,
/// so an uncapped directory multiplies its size several times over. The
/// largest real help files carry tens of thousands of entries.
const MAX_DIR_ENTRIES: usize = 1 << 18;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    image_end: &mut Option<u64>,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    let Some(header) = bytes
        .first_chunk::<0x60>()
        .filter(|h| h.starts_with(b"ITSF"))
    else {
        return;
    };
    // Every field is read out of the 0x60-byte version-3 `header`, so none
    // of the reads can come up short and the `unwrap_or(0)` defaults never
    // apply.
    let version = bytes::u32_le(header, 0x04).unwrap_or(0);
    if version != 3 {
        return;
    }
    let timestamp_counter = bytes::u32_le(header, 0x10).unwrap_or(0);
    let lcid = bytes::u32_le(header, 0x14).unwrap_or(0);

    let section1_offset = bytes::sat_usize(bytes::u64_le(header, 0x48).unwrap_or(0));
    let section1_length = bytes::sat_usize(bytes::u64_le(header, 0x50).unwrap_or(0));
    let data_offset = bytes::sat_usize(bytes::u64_le(header, 0x58).unwrap_or(0));

    let mut itsf = serde_json::Map::new();
    itsf.insert("version".into(), json!(version));
    itsf.insert("timestamp_counter".into(), json!(timestamp_counter));
    itsf.insert("lcid".into(), json!(lcid));
    values.insert_key(value_key!("chm.itsf"), JsonValue::Object(itsf));
    // The LCID is reachable via `chm.itsf.lcid` (nested value).
    // Don't dual-emit as a flat `chm.itsf_lcid` metric.

    let Some(dir) = bytes.get(section1_offset..section1_offset.saturating_add(section1_length))
    else {
        return;
    };
    let (entries, truncated) = parse_directory(dir);
    if truncated {
        let mut limits = super::bounded::Limits::default();
        limits.push(
            "directory-entries",
            format!("stopped at {MAX_DIR_ENTRIES} directory entries"),
        );
        limits.emit(values, value_key!("chm.limits"));
    }
    if entries.is_empty() {
        return;
    }

    // The archive consists of the ITSF directory and the physical data
    // extents for section-0 entries. Section-1 offsets are logical offsets
    // into the LZX stream and cannot be used as file offsets. This handles
    // both common layouts: data before the directory, and a directory at
    // the end of the file. Ignore invalid entry extents rather than letting
    // malformed offsets hide an appended payload.
    let Some(directory_end) = section1_offset.checked_add(section1_length) else {
        return;
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
        let has_ext = |exts: &[&str]| exts.iter().any(|ext| ends_with_ci(&e.name, ext));
        if has_ext(&[".html", ".htm"]) {
            html_count += 1;
        }
        if has_ext(&[".js", ".vbs", ".wsf"]) {
            script_count += 1;
        }
        if has_ext(&[".png", ".jpg", ".jpeg", ".gif", ".bmp"]) {
            image_count += 1;
        }
        if has_ext(&[".hhc"]) {
            push_unique(&mut features, "toc");
        }
        if has_ext(&[".hhk"]) {
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

    // Per-entry metrics roll-up.
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

    metrics.insert(metric!("chm.lzx_reset_count"), f64::from(rt.reset_count));
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

/// The PMGL entries of an `ITSP` directory, and whether the walk stopped at
/// [`MAX_DIR_ENTRIES`] with more to read.
fn parse_directory(section: &[u8]) -> (Vec<DirEntry>, bool) {
    let mut out = Vec::new();
    if section.len() < 0x54 || !section.starts_with(b"ITSP") {
        return (out, false);
    }
    // The length check above covers all three fields.
    let header_len = bytes::u32_le(section, 0x08).unwrap_or(0) as usize;
    let chunk_size = bytes::u32_le(section, 0x10).unwrap_or(0) as usize;
    let chunk_count = bytes::u32_le(section, 0x2c).unwrap_or(0) as usize;
    if chunk_size < 0x14 {
        return (out, false);
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
            if out.len() == MAX_DIR_ENTRIES {
                return (out, true);
            }
            out.push(entry);
        }
    }
    (out, false)
}

/// One PMGL directory entry: an ENCINT-prefixed name, then the section,
/// offset and length ENCINTs. Returns the entry and the bytes it took.
fn parse_entry(buf: &[u8]) -> Option<(DirEntry, usize)> {
    let (name_len, mut pos) = read_encint(buf)?;
    // The length is attacker-controlled and an ENCINT reaches `u64::MAX`, so
    // the end of the name is computed checked: an unchecked `pos + name_len`
    // overflows (a panic in debug builds, a reversed slice range in release)
    // before the bounds check can reject it.
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
        out.push(bytes::utf16_lossy(raw, bytes::Endian::Little));
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

#[cfg(test)]
mod tests;
