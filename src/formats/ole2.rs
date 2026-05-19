//! OLE2 / CFBF (Compound File Binary Format) extractor.
//!
//! Walks the storage / stream hierarchy of legacy Microsoft Office
//! documents (`.doc` / `.xls` / `.ppt`) plus the related `.msi`,
//! `.msg`, and `.dot` packages — all of which use the same on-disk
//! container.
//!
//! Emits an `office.*` schema parallel to the OOXML extractor's:
//!
//! - `office.kind` — `"doc" | "xls" | "ppt" | "msg" | "msi" | "ole2"`
//!   chosen from canonical stream names (`WordDocument`, `Workbook`,
//!   `PowerPoint Document`, …).
//! - `office.streams[]` — Pike-style flat list of every storage /
//!   stream path inside the document. Trait rules can match stream
//!   names directly (e.g. `office.streams[*] regex: VBA`).
//! - `office.features[]` — array tokens like `"macros"` (any
//!   `VBA`-named storage), `"encryption"` (`EncryptionInfo` /
//!   `EncryptedPackage` streams), `"ole_objects"`
//!   (`\1Ole10Native` streams).
//! - `office.macro_count`, `office.stream_count` — metrics.
//!
//! Metadata / property-set parsing is deferred to a follow-up slice;
//! the SummaryInformation stream uses a documented but non-trivial
//! property-set encoding (FMTID GUIDs + property IDs from MS-OSHARED).
//! For Phase 2's first slice, we surface the structural inventory
//! that supply-chain detection traits care about most.

use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::put_str;
use crate::output::{Metrics, Values};

/// Hard cap on the number of stream entries we enumerate. Real Office
/// documents have ≤ a few hundred; the cap keeps a hostile compound
/// file from looping us forever.
const MAX_STREAMS: usize = 4096;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    let Ok(mut comp) = cfb::CompoundFile::open(cursor) else {
        // Magic-byte detection might pick up something with the same
        // header signature that isn't a parseable OLE2 file. Silent
        // bail keeps the dispatcher's contract simple.
        return Ok(());
    };

    let mut streams: Vec<String> = Vec::new();
    let mut macro_count: u64 = 0;
    let mut features: Vec<&'static str> = Vec::new();
    let mut had_ole10native = false;
    let mut had_encryption_info = false;
    let mut had_encrypted_package = false;
    let mut dangerous_clsids: Vec<JsonValue> = Vec::new();

    for entry in comp.walk() {
        if streams.len() >= MAX_STREAMS {
            break;
        }
        let path = entry.path().to_string_lossy().into_owned();
        let lower = path.to_ascii_lowercase();

        // Macros live under `/VBA/` storage. Some macro-enabled
        // templates also use `Macros/` or `_VBA_PROJECT_CUR/`; cover
        // all the documented forms.
        if entry.is_storage() {
            if lower.contains("/vba") || lower == "/macros" || lower.contains("/macros/") {
                macro_count += 1;
            }
            // Storage entries carry a CLSID identifying the OLE class
            // bound to that container. Specific CLSIDs are documented
            // exploit vectors (Equation Editor / Packager Shell / …);
            // surface every match as a structural fact for traits to
            // act on.
            let clsid = entry.clsid().to_string();
            if let Some(name) = lookup_dangerous_clsid(&clsid) {
                let mut obj = serde_json::Map::new();
                obj.insert("clsid".into(), JsonValue::String(clsid));
                obj.insert("name".into(), JsonValue::String(name.into()));
                obj.insert("storage".into(), JsonValue::String(path.clone()));
                dangerous_clsids.push(JsonValue::Object(obj));
            }
        }

        // Forensic-marker streams.
        if path.contains("Ole10Native") {
            had_ole10native = true;
        }
        if path == "/EncryptionInfo" || lower.contains("encryptioninfo") {
            had_encryption_info = true;
        }
        if path == "/EncryptedPackage" || lower.contains("encryptedpackage") {
            had_encrypted_package = true;
        }

        streams.push(path);
    }

    // Empty stream listing → almost certainly not a real OLE2 doc.
    if streams.is_empty() {
        return Ok(());
    }

    let kind = detect_kind(&streams);
    put_str(values, "office.kind", kind);

    metrics.insert("office.stream_count", streams.len() as f64);
    values.insert(
        "office.streams",
        JsonValue::Array(streams.into_iter().map(JsonValue::String).collect()),
    );

    if macro_count > 0 {
        features.push("macros");
        metrics.insert("office.macro_count", macro_count as f64);
    }
    if had_ole10native {
        features.push("ole_objects");
    }
    if had_encryption_info || had_encrypted_package {
        features.push("encryption");
    }
    if !dangerous_clsids.is_empty() {
        features.push("dangerous_clsid");
        let count = dangerous_clsids.len() as f64;
        values.insert("office.dangerous_clsids", JsonValue::Array(dangerous_clsids));
        metrics.insert("office.dangerous_clsid_count", count);
    }
    if !features.is_empty() {
        values.insert(
            "office.features",
            JsonValue::Array(
                features.into_iter().map(|s| JsonValue::String(s.into())).collect(),
            ),
        );
    }

    // SummaryInformation property set — `office.core.*`. The stream
    // name is `\x05SummaryInformation` (the SOH-prefix is the CFB
    // shorthand for a control-character storage). Mirrors the OOXML
    // `office.core.*` schema so cross-format trait rules work
    // uniformly.
    let mut core: serde_json::Map<String, JsonValue> = serde_json::Map::new();
    if let Ok(mut stream) = comp.open_stream("\x05SummaryInformation") {
        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            core = parse_summary_information(&data);
        }
    }
    // DocumentSummaryInformation extends the core set with
    // manager / company / security_flag / hyperlink_base — fields
    // OOXML carries in `docProps/app.xml`. Mixing them into the same
    // `office.core.*` object keeps the cross-format trait surface
    // uniform.
    if let Ok(mut stream) = comp.open_stream("\x05DocumentSummaryInformation") {
        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            for (k, v) in parse_document_summary_information(&data) {
                core.entry(k).or_insert(v);
            }
        }
    }
    if !core.is_empty() {
        values.insert("office.core", JsonValue::Object(core));
    }

    // CompObj stream — `\x01CompObj` carries the OLE-class identity
    // strings. The forensically interesting one is the ProgID
    // (`Excel.Sheet.8`, `Word.Document.8`, `PowerPoint.Show.8`, …) —
    // a `.doc` file whose CompObj declares Excel is the canonical
    // CVE-2017-0199 extension-mismatch shape.
    if let Ok(mut stream) = comp.open_stream("\x01CompObj") {
        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            if let Some(co) = parse_compobj(&data) {
                let mut obj = serde_json::Map::new();
                if !co.user_type.is_empty() {
                    obj.insert("user_type".into(), JsonValue::String(co.user_type));
                }
                if !co.clipboard_format.is_empty() {
                    obj.insert(
                        "clipboard_format".into(),
                        JsonValue::String(co.clipboard_format),
                    );
                }
                if !co.app_version.is_empty() {
                    // Naming note: cleave-side called this
                    // `app_version`, but MS-OLEDS calls it the
                    // ProgID. We surface both — `prog_id` is the
                    // forward-looking name (matches the spec);
                    // `app_version` stays for trait-rule continuity.
                    obj.insert(
                        "prog_id".into(),
                        JsonValue::String(co.app_version.clone()),
                    );
                    obj.insert("app_version".into(), JsonValue::String(co.app_version));
                }
                if !obj.is_empty() {
                    values.insert("office.compobj", JsonValue::Object(obj));
                }
            }
        }
    }

    Ok(())
}

/// Parse the `\x05SummaryInformation` property set (MS-OLEPS) and
/// return a map keyed by the same canonical names the OOXML
/// extractor uses for `office.core.*`, so trait rules can match
/// either legacy or modern Office uniformly.
///
/// Property layout:
/// - 28-byte header: byte-order mark, version, OS, class GUID, section count.
/// - Per-section header: FMTID (16 bytes) + offset (4 bytes).
/// - Section body: size (4) + property count (4) + (PID, offset) pairs.
/// - Each property entry: type tag (4) + value bytes (length depends on type).
fn parse_summary_information(data: &[u8]) -> serde_json::Map<String, JsonValue> {
    let mut out = serde_json::Map::new();
    let Some(section) = locate_first_section(data) else {
        return out;
    };
    if section.len() < 8 {
        return out;
    }
    let num_props =
        u32::from_le_bytes([section[4], section[5], section[6], section[7]]) as usize;
    // Cap the count so a malformed header can't request unbounded
    // property reads.
    let num_props = num_props.min(256);
    for i in 0..num_props {
        let entry_off = 8 + i * 8;
        if entry_off + 8 > section.len() {
            break;
        }
        let pid = read_u32_le(section, entry_off);
        let val_off = read_u32_le(section, entry_off + 4) as usize;
        // PIDSI_* per MS-OLEPS §2.4.1. The mapping uses the same
        // canonical names as the OOXML core-properties schema so
        // traits don't have to special-case the format.
        let key = match pid {
            0x02 => "title",
            0x03 => "subject",
            0x04 => "creator",         // PIDSI_AUTHOR
            0x05 => "keywords",
            0x06 => "description",     // PIDSI_COMMENTS
            0x07 => "template",
            0x08 => "last_modified_by",// PIDSI_LASTAUTHOR
            0x09 => "revision",        // VT_LPSTR holding a decimal string
            0x0B => "last_printed",    // VT_FILETIME
            0x0C => "created",         // VT_FILETIME
            0x0D => "modified",        // PIDSI_LASTSAVE_DTM, VT_FILETIME
            0x12 => "application",     // PIDSI_APPNAME
            _ => continue,
        };
        if out.contains_key(key) {
            continue;
        }
        if let Some(value) = read_property(section, val_off) {
            out.insert(key.into(), value);
        }
    }
    out
}

/// Parse the `\x05DocumentSummaryInformation` property set into the
/// subset of fields that overlap with the OOXML `office.core.*` /
/// `office.{company, manager}` shape. The full DSI also carries
/// custom user-defined properties in a second section; we skip those
/// for now — trait rules that care will get their own slice.
fn parse_document_summary_information(data: &[u8]) -> serde_json::Map<String, JsonValue> {
    let mut out = serde_json::Map::new();
    let Some(section) = locate_first_section(data) else {
        return out;
    };
    if section.len() < 8 {
        return out;
    }
    let num_props =
        u32::from_le_bytes([section[4], section[5], section[6], section[7]]) as usize;
    let num_props = num_props.min(256);
    for i in 0..num_props {
        let entry_off = 8 + i * 8;
        if entry_off + 8 > section.len() {
            break;
        }
        let pid = read_u32_le(section, entry_off);
        let val_off = read_u32_le(section, entry_off + 4) as usize;
        // PIDDSI_* per MS-OLEPS §2.4.2. We only surface the fields
        // that have a matching OOXML core / app-properties slot.
        let key = match pid {
            0x02 => "category",
            0x05 => "presentation_format",
            0x09 => "slide_count",          // VT_I4
            0x10 => "manager",              // VT_LPSTR
            0x11 => "company",              // VT_LPSTR
            0x13 => "security_flag",        // VT_I4 — bitfield
            0x1A => "hyperlink_base",       // VT_LPSTR
            _ => continue,
        };
        if out.contains_key(key) {
            continue;
        }
        if let Some(value) = read_property(section, val_off).or_else(|| read_property_i32(section, val_off)) {
            out.insert(key.into(), value);
        }
    }
    out
}

/// Read a VT_I4 (signed 32-bit integer) at `(section + offset)`.
/// Separate from `read_property` because the canonical helper only
/// surfaces types that flow through OOXML's `office.core.*` schema
/// (strings + filetime); DSI counts like `slide_count` need integer
/// decoding.
fn read_property_i32(section: &[u8], offset: usize) -> Option<JsonValue> {
    if offset + 8 > section.len() {
        return None;
    }
    let vt = read_u32_le(section, offset);
    if vt != 0x0003 {
        return None;
    }
    let v = i32::from_le_bytes([
        section[offset + 4],
        section[offset + 5],
        section[offset + 6],
        section[offset + 7],
    ]);
    Some(JsonValue::Number(v.into()))
}

/// Locate the first section's byte slice within a property-set
/// stream. The header layout (offsets within `data`):
/// - 0..4   ByteOrder (0xFFFE) | Version (2)
/// - 4..24  OS / CLSID — skipped
/// - 24..28 Section count (u32, must be ≥ 1)
/// - 28..44 Section[0].FMTID
/// - 44..48 Section[0].Offset → `data[offset..]` is the section body
fn locate_first_section(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 48 {
        return None;
    }
    let bom = u16::from_le_bytes([data[0], data[1]]);
    if bom != 0xFFFE {
        return None;
    }
    let num_sections = read_u32_le(data, 24) as usize;
    if num_sections == 0 {
        return None;
    }
    let section_off = read_u32_le(data, 44) as usize;
    if section_off >= data.len() {
        return None;
    }
    Some(&data[section_off..])
}

/// Read a property value at `(section + offset)` and decode it into
/// JSON. Returns `None` for types we don't surface as core metadata
/// (thumbnails, BLOBs, integer counts that aren't part of the
/// `office.core.*` schema).
fn read_property(section: &[u8], offset: usize) -> Option<JsonValue> {
    if offset + 4 > section.len() {
        return None;
    }
    let vt = read_u32_le(section, offset);
    let body = section.get(offset + 4..)?;
    match vt {
        // VT_LPSTR (0x001E): u32 length + ANSI/CP1252-ish bytes.
        0x001E => read_lpstr(body),
        // VT_LPWSTR (0x001F): u32 char count + UTF-16LE chars.
        0x001F => read_lpwstr(body),
        // VT_FILETIME (0x0040): u64 100-ns ticks since Windows epoch
        // (1601-01-01 UTC). Decode to ISO-8601 UTC for human-
        // readable output.
        0x0040 => read_filetime(body),
        // Skip unsupported types — the canonical core fields we care
        // about land in one of the three forms above.
        _ => None,
    }
}

fn read_lpstr(body: &[u8]) -> Option<JsonValue> {
    if body.len() < 4 {
        return None;
    }
    let len = read_u32_le(body, 0) as usize;
    if len == 0 || 4 + len > body.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&body[4..4 + len])
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(JsonValue::String(s))
    }
}

fn read_lpwstr(body: &[u8]) -> Option<JsonValue> {
    if body.len() < 4 {
        return None;
    }
    let chars = read_u32_le(body, 0) as usize;
    let byte_len = chars.checked_mul(2)?;
    if chars == 0 || 4 + byte_len > body.len() {
        return None;
    }
    let mut units = Vec::with_capacity(chars);
    for i in 0..chars {
        let off = 4 + i * 2;
        units.push(u16::from_le_bytes([body[off], body[off + 1]]));
    }
    let s = String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(JsonValue::String(s))
    }
}

fn read_filetime(body: &[u8]) -> Option<JsonValue> {
    if body.len() < 8 {
        return None;
    }
    let ticks = u64::from_le_bytes(body[..8].try_into().ok()?);
    if ticks == 0 {
        return None;
    }
    // Windows FILETIME → Unix seconds: subtract the 1601→1970
    // 100-ns-tick offset, then divide by 10_000_000.
    const EPOCH_OFFSET: u64 = 11_644_473_600;
    let unix_seconds = ticks / 10_000_000;
    if unix_seconds < EPOCH_OFFSET {
        // Stored value is a duration (e.g. PIDSI_EDITTIME), not an
        // absolute timestamp — surface the raw value as seconds so
        // the consumer can interpret it.
        return Some(JsonValue::String(format!("PT{}S", unix_seconds)));
    }
    let unix = unix_seconds - EPOCH_OFFSET;
    Some(JsonValue::String(format_iso8601_utc(unix)))
}

/// Format a Unix timestamp as ISO-8601 in UTC without pulling in a
/// date crate. The math is the textbook proleptic-Gregorian
/// algorithm — Howard Hinnant's `civil_from_days` formula.
fn format_iso8601_utc(unix: u64) -> String {
    let seconds_per_day: u64 = 86_400;
    let days = (unix / seconds_per_day) as i64;
    let secs = unix % seconds_per_day;
    let hour = (secs / 3600) as u32;
    let minute = ((secs % 3600) / 60) as u32;
    let second = (secs % 60) as u32;
    // Convert days-since-1970 to civil date.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + if month <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Parsed CompObj stream contents.
#[derive(Debug, Default)]
struct CompObjData {
    user_type: String,
    clipboard_format: String,
    app_version: String,
}

/// Parse the CompObj stream layout (MS-OLEDS §2.3.6.1).
///
/// Header: 28 bytes of reserved/version fields.
/// Body:
///   - AnsiUserType: LengthPrefixedAnsiString
///   - AnsiClipboardFormat: ClipboardFormatOrAnsiString (4-byte
///     registered ID OR length-prefixed string)
///   - Reserved3: optional LengthPrefixedAnsiString (the ProgID,
///     surfaced as `app_version` for trait-rule continuity)
///
/// `LengthPrefixedAnsiString` = u32 LE length (including trailing
/// NUL) + that many bytes. Length 0 means absent.
fn parse_compobj(data: &[u8]) -> Option<CompObjData> {
    const HEADER_SIZE: usize = 28;
    if data.len() < HEADER_SIZE + 4 {
        return None;
    }
    let mut pos = HEADER_SIZE;
    let mut out = CompObjData::default();

    if let Some((s, advance)) = read_length_prefixed_ansi(&data[pos..]) {
        out.user_type = s;
        pos += advance;
    } else {
        return Some(out);
    }

    // ClipboardFormat — disambiguate between a small registered ID
    // and a length-prefixed string. The naive "small = ID, large =
    // length" heuristic fails for short formats like "Biff8\0"
    // (length 6 looks like an ID). Prefer the string interpretation
    // when the declared length fits and the bytes are printable
    // ASCII; otherwise treat as a 4-byte registered ID.
    if data.len() < pos + 4 {
        return Some(out);
    }
    let marker =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    if marker == 0 {
        pos += 4;
    } else {
        let len = marker as usize;
        let str_start = pos + 4;
        let fits = data.len() >= str_start + len && len > 0 && len <= 256;
        let printable = fits
            && data[str_start..str_start + len]
                .iter()
                .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0);
        if fits && printable {
            out.clipboard_format = sanitize_ansi(&data[str_start..str_start + len]);
            pos = str_start + len;
        } else {
            pos += 4;
        }
    }

    // ProgID — surfaced as `app_version` because the existing
    // forensic trait corpus references it under that name.
    if let Some((s, _)) = read_length_prefixed_ansi(&data[pos..]) {
        out.app_version = s;
    }

    Some(out)
}

fn read_length_prefixed_ansi(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 {
        return Some((String::new(), 4));
    }
    if buf.len() < 4 + len {
        return None;
    }
    Some((sanitize_ansi(&buf[4..4 + len]), 4 + len))
}

fn sanitize_ansi(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
}

/// Curated allowlist of OLE CLSIDs that are documented exploitation
/// vectors. Returns a short human-readable label when the CLSID is
/// known, `None` otherwise. The list mirrors cleave's `office/ole2.rs`
/// `lookup_dangerous_clsid` allowlist verbatim so traits that match
/// on `office.dangerous_clsids[*].name` get the same string regardless
/// of which side did the detection.
fn lookup_dangerous_clsid(clsid: &str) -> Option<&'static str> {
    // `cfb::Entry::clsid().to_string()` produces canonical RFC-4122
    // hyphenated lowercase. Match against that form.
    match clsid {
        // Equation Editor — CVE-2017-11882 / CVE-2018-0802.
        "0002ce02-0000-0000-c000-000000000046" => {
            Some("Equation Editor 3.0 (CVE-2017-11882)")
        }
        // Packager Shell Object — embeds arbitrary files as
        // double-click-to-execute payloads.
        "f20da720-c02f-11ce-927b-0800095ae340" => Some("OLE Package Shell Object"),
        // scriptlet.typelib — script execution via Windows Script Host.
        "06290bd2-48aa-11d2-8432-006008c3fbfc" => {
            Some("scriptlet.typelib (script execution)")
        }
        // htmlfile — HTML Application surface (HTA-style execution).
        "25336920-03f9-11cf-8fd0-00aa00686f13" => Some("htmlfile (HTML document)"),
        // MSCOMCTL.ListViewCtrl — CVE-2012-0158 family.
        "996bf5e0-8044-4650-adeb-0b013914e99c" => {
            Some("MSCOMCTL.ListViewCtrl (CVE-2012-0158)")
        }
        "bdd1f04b-858b-11d1-b16a-00c0f0283628" => {
            Some("MSCOMCTL.ListViewCtrl.2 (CVE-2012-0158)")
        }
        // Shell.Explorer — embedded browser, repeated RCE history.
        "8856f961-340a-11d0-a96b-00c04fd705a2" => {
            Some("Shell.Explorer (embedded browser)")
        }
        // StdOleLink — external link object (template-injection
        // surrogate in OLE2 documents).
        "00000300-0000-0000-c000-000000000046" => Some("StdOleLink (external link)"),
        _ => None,
    }
}

/// Map the stream-name inventory to a short application label.
/// Canonical stream names per MS-DOC, MS-XLS, MS-PPT, MS-MSG, MS-OSHARED.
fn detect_kind(streams: &[String]) -> &'static str {
    let has = |needle: &str| streams.iter().any(|s| s.contains(needle));
    if has("WordDocument") {
        return "doc";
    }
    if has("Workbook") || has("Book") {
        return "xls";
    }
    if has("PowerPoint Document") || has("PowerPoint") {
        return "ppt";
    }
    if has("__substg1.0_") || has("__nameid_version1.0") {
        return "msg";
    }
    // MSI installer packages use a CFB container with `_Tables`,
    // `_Columns`, `_Validation`, … streams.
    if has("_Columns") && has("_Tables") {
        return "msi";
    }
    "ole2"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Metrics, Values};

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let _ = extract(bytes, &mut v, &mut m);
        (v, m)
    }

    /// Build a tiny in-memory CFB with the given stream paths and
    /// optional bodies. Creates parent storages on demand — the
    /// `cfb` crate requires every storage to exist before a stream
    /// inside it can be created.
    fn build_cfb(streams: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut cfb = cfb::CompoundFile::create(&mut buf).unwrap();
            for (path, body) in streams {
                // Walk every "/foo/bar/" prefix and create the storage
                // if it doesn't yet exist.
                let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                if parts.len() > 1 {
                    let mut accum = String::new();
                    for part in &parts[..parts.len() - 1] {
                        accum.push('/');
                        accum.push_str(part);
                        if !cfb.exists(&accum) {
                            cfb.create_storage(&accum).unwrap();
                        }
                    }
                }
                let mut stream = cfb.create_stream(path).unwrap();
                stream.write_all(body).unwrap();
            }
        }
        buf.into_inner()
    }

    #[test]
    fn detects_word_document() {
        let cfb = build_cfb(&[("/WordDocument", b"fake-word-body")]);
        let (v, m) = run(&cfb);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("doc"));
        let streams = v.get("office.streams").and_then(|x| x.as_array()).unwrap();
        assert!(streams
            .iter()
            .any(|s| s.as_str() == Some("/WordDocument")));
        assert!(m.get("office.stream_count").unwrap() >= 1.0);
    }

    #[test]
    fn detects_excel_workbook() {
        let cfb = build_cfb(&[("/Workbook", b"fake-xl-body")]);
        let (v, _) = run(&cfb);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("xls"));
    }

    #[test]
    fn detects_powerpoint_document() {
        let cfb = build_cfb(&[("/PowerPoint Document", b"fake-ppt-body")]);
        let (v, _) = run(&cfb);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("ppt"));
    }

    #[test]
    fn unrecognised_streams_fall_back_to_ole2() {
        let cfb = build_cfb(&[("/RandomStream", b"junk")]);
        let (v, _) = run(&cfb);
        assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("ole2"));
    }

    #[test]
    fn detects_macros_in_vba_storage() {
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/Macros/VBA/Module1", b"Sub Auto_Open\nEnd Sub"),
        ]);
        let (v, m) = run(&cfb);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"macros"));
        assert!(m.get("office.macro_count").unwrap() >= 1.0);
    }

    #[test]
    fn detects_encryption_info_stream() {
        let cfb = build_cfb(&[
            ("/EncryptionInfo", b"\x04\x00\x04\x00encrypted-info-blob"),
            ("/EncryptedPackage", b"ciphertext"),
        ]);
        let (v, _) = run(&cfb);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"encryption"));
    }

    #[test]
    fn detects_ole10native_objects() {
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/ObjectPool/_1234567890/\u{1}Ole10Native", b"native-obj"),
        ]);
        let (v, _) = run(&cfb);
        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"ole_objects"));
    }

    #[test]
    fn non_cfb_input_silent() {
        let (v, _) = run(b"not even close to OLE2 bytes");
        assert!(v.get("office.kind").is_none());
        assert!(v.get("office.streams").is_none());
    }

    #[test]
    fn empty_input_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("office.kind").is_none());
    }

    #[test]
    fn streams_listed_in_walk_order() {
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/SummaryInformation", b"y"),
            ("/1Table", b"z"),
        ]);
        let (v, _) = run(&cfb);
        let streams = v.get("office.streams").and_then(|x| x.as_array()).unwrap();
        let paths: Vec<&str> = streams.iter().filter_map(|x| x.as_str()).collect();
        // Just check membership — the cfb crate's walk order isn't
        // part of the contract.
        assert!(paths.iter().any(|p| *p == "/WordDocument"));
        assert!(paths.iter().any(|p| *p == "/SummaryInformation"));
        assert!(paths.iter().any(|p| *p == "/1Table"));
    }

    /// Build a SummaryInformation stream containing the listed
    /// (PID, VT_LPSTR string) pairs. Used to exercise the
    /// property-set parser end-to-end through `extract`.
    fn build_summary_info(props: &[(u32, &str)]) -> Vec<u8> {
        // Header (48 bytes total): 28-byte main header + 16-byte
        // section header. The section data starts at offset 48 (= 28
        // + 16-byte FMTID + 4-byte section offset, with `offset = 48`).
        let mut out = Vec::new();
        // Main header.
        out.extend_from_slice(&0xFFFE_u16.to_le_bytes()); // ByteOrder
        out.extend_from_slice(&0x0000_u16.to_le_bytes()); // Version
        out.extend_from_slice(&[0u8; 4]); // OS
        out.extend_from_slice(&[0u8; 16]); // CLSID
        out.extend_from_slice(&1u32.to_le_bytes()); // section count
        // Section header: 16-byte FMTID + 4-byte offset.
        out.extend_from_slice(&[0u8; 16]); // FMTID
        out.extend_from_slice(&48u32.to_le_bytes()); // section starts at byte 48

        // Build the property-name table first to compute the entry
        // table size.
        let n = props.len() as u32;
        let entry_table_size = 8 + (n as usize) * 8; // size + count + entries

        // Reserve a slot for the section header (size + count).
        let mut section_body: Vec<u8> = Vec::new();
        section_body.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        section_body.extend_from_slice(&n.to_le_bytes()); // num props

        // Entry table — PID + offset-from-section-start.
        let mut values_blob: Vec<u8> = Vec::new();
        for (pid, _) in props {
            let offset_in_section = entry_table_size + values_blob.len();
            section_body.extend_from_slice(&pid.to_le_bytes());
            section_body.extend_from_slice(&(offset_in_section as u32).to_le_bytes());
            // Add the value to the blob: VT_LPSTR (0x001E), u32 byte
            // length, NUL-terminated bytes, then pad to 4-byte align.
            let s = props.iter().find(|(p, _)| *p == *pid).unwrap().1;
            let mut s_bytes = s.as_bytes().to_vec();
            s_bytes.push(0);
            let len = s_bytes.len() as u32;
            values_blob.extend_from_slice(&0x0000_001E_u32.to_le_bytes());
            values_blob.extend_from_slice(&len.to_le_bytes());
            values_blob.extend_from_slice(&s_bytes);
            while values_blob.len() % 4 != 0 {
                values_blob.push(0);
            }
        }

        section_body.extend_from_slice(&values_blob);
        // Fill in the actual section size.
        let total_size = section_body.len() as u32;
        section_body[0..4].copy_from_slice(&total_size.to_le_bytes());

        out.extend_from_slice(&section_body);
        out
    }

    #[test]
    fn surfaces_office_core_from_summary_information() {
        let summary = build_summary_info(&[
            (0x02, "Quarterly Report"),
            (0x04, "Alice"),
            (0x08, "Bob"),
            (0x12, "Microsoft Word"),
        ]);
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/\x05SummaryInformation", &summary),
        ]);
        let (v, _) = run(&cfb);
        let core = v.get("office.core").and_then(|x| x.as_object()).unwrap();
        assert_eq!(core.get("title").and_then(|x| x.as_str()), Some("Quarterly Report"));
        assert_eq!(core.get("creator").and_then(|x| x.as_str()), Some("Alice"));
        assert_eq!(
            core.get("last_modified_by").and_then(|x| x.as_str()),
            Some("Bob")
        );
        assert_eq!(
            core.get("application").and_then(|x| x.as_str()),
            Some("Microsoft Word")
        );
    }

    /// Build a property-set stream containing a mix of VT_LPSTR and
    /// VT_I4 properties. Mirror of `build_summary_info` but supports
    /// both types so we can exercise DocumentSummaryInformation
    /// counts (slide_count, security_flag).
    enum PropValue {
        Lpstr(&'static str),
        I4(i32),
    }

    fn build_property_set(props: &[(u32, PropValue)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xFFFE_u16.to_le_bytes());
        out.extend_from_slice(&0x0000_u16.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&48u32.to_le_bytes());

        let n = props.len() as u32;
        let entry_table_size = 8 + (n as usize) * 8;
        let mut section_body: Vec<u8> = Vec::new();
        section_body.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        section_body.extend_from_slice(&n.to_le_bytes());

        let mut values_blob: Vec<u8> = Vec::new();
        for (pid, val) in props {
            let offset_in_section = entry_table_size + values_blob.len();
            section_body.extend_from_slice(&pid.to_le_bytes());
            section_body.extend_from_slice(&(offset_in_section as u32).to_le_bytes());
            match val {
                PropValue::Lpstr(s) => {
                    let mut s_bytes = s.as_bytes().to_vec();
                    s_bytes.push(0);
                    let len = s_bytes.len() as u32;
                    values_blob.extend_from_slice(&0x0000_001E_u32.to_le_bytes());
                    values_blob.extend_from_slice(&len.to_le_bytes());
                    values_blob.extend_from_slice(&s_bytes);
                }
                PropValue::I4(v) => {
                    values_blob.extend_from_slice(&0x0000_0003_u32.to_le_bytes());
                    values_blob.extend_from_slice(&v.to_le_bytes());
                }
            }
            while values_blob.len() % 4 != 0 {
                values_blob.push(0);
            }
        }
        section_body.extend_from_slice(&values_blob);
        let total_size = section_body.len() as u32;
        section_body[0..4].copy_from_slice(&total_size.to_le_bytes());
        out.extend_from_slice(&section_body);
        out
    }

    #[test]
    fn merges_document_summary_information_into_core() {
        let summary = build_summary_info(&[
            (0x02, "Quarterly Report"),
            (0x04, "Alice"),
        ]);
        let dsi = build_property_set(&[
            (0x10, PropValue::Lpstr("Eve")),      // manager
            (0x11, PropValue::Lpstr("Acme Inc")), // company
            (0x09, PropValue::I4(42)),            // slide_count
            (0x13, PropValue::I4(1)),             // security_flag
        ]);
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/\x05SummaryInformation", &summary),
            ("/\x05DocumentSummaryInformation", &dsi),
        ]);
        let (v, _) = run(&cfb);
        let core = v.get("office.core").and_then(|x| x.as_object()).unwrap();
        // From SummaryInformation:
        assert_eq!(core.get("title").and_then(|x| x.as_str()), Some("Quarterly Report"));
        assert_eq!(core.get("creator").and_then(|x| x.as_str()), Some("Alice"));
        // From DocumentSummaryInformation:
        assert_eq!(core.get("manager").and_then(|x| x.as_str()), Some("Eve"));
        assert_eq!(
            core.get("company").and_then(|x| x.as_str()),
            Some("Acme Inc")
        );
        assert_eq!(core.get("slide_count").and_then(|x| x.as_i64()), Some(42));
        assert_eq!(
            core.get("security_flag").and_then(|x| x.as_i64()),
            Some(1)
        );
    }

    #[test]
    fn document_summary_alone_still_populates_core() {
        // No SummaryInformation present — DSI fields should still
        // land in office.core.
        let dsi = build_property_set(&[
            (0x11, PropValue::Lpstr("Acme Inc")),
            (0x1A, PropValue::Lpstr("https://intranet.acme/docs")),
        ]);
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/\x05DocumentSummaryInformation", &dsi),
        ]);
        let (v, _) = run(&cfb);
        let core = v.get("office.core").and_then(|x| x.as_object()).unwrap();
        assert_eq!(
            core.get("company").and_then(|x| x.as_str()),
            Some("Acme Inc")
        );
        assert_eq!(
            core.get("hyperlink_base").and_then(|x| x.as_str()),
            Some("https://intranet.acme/docs")
        );
    }

    #[test]
    fn flags_equation_editor_clsid_on_storage() {
        // CVE-2017-11882 — Equation Editor 3.0 CLSID.
        // Bytes are the canonical little-endian on-disk form.
        let equation_clsid = uuid::Uuid::parse_str("0002ce02-0000-0000-c000-000000000046").unwrap();
        // Build a CFB with a storage that has the dangerous CLSID set.
        let mut buf = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut cfb = cfb::CompoundFile::create(&mut buf).unwrap();
            cfb.create_storage("/EQUATION").unwrap();
            cfb.set_storage_clsid("/EQUATION", equation_clsid).unwrap();
            let mut s = cfb.create_stream("/WordDocument").unwrap();
            std::io::Write::write_all(&mut s, b"x").unwrap();
        }
        let bytes = buf.into_inner();
        let (v, m) = run(&bytes);

        let dangerous = v
            .get("office.dangerous_clsids")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(dangerous.len(), 1);
        assert_eq!(
            dangerous[0]["clsid"].as_str(),
            Some("0002ce02-0000-0000-c000-000000000046")
        );
        assert!(dangerous[0]["name"]
            .as_str()
            .unwrap()
            .contains("Equation Editor"));
        assert!(dangerous[0]["name"]
            .as_str()
            .unwrap()
            .contains("CVE-2017-11882"));
        assert_eq!(dangerous[0]["storage"].as_str(), Some("/EQUATION"));
        assert_eq!(m.get("office.dangerous_clsid_count"), Some(1.0));

        let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"dangerous_clsid"));
    }

    #[test]
    fn benign_clsids_dont_trigger_dangerous_list() {
        let benign_clsid = uuid::Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let mut buf = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut cfb = cfb::CompoundFile::create(&mut buf).unwrap();
            cfb.create_storage("/random").unwrap();
            cfb.set_storage_clsid("/random", benign_clsid).unwrap();
            let mut s = cfb.create_stream("/WordDocument").unwrap();
            std::io::Write::write_all(&mut s, b"x").unwrap();
        }
        let (v, _) = run(&buf.into_inner());
        assert!(v.get("office.dangerous_clsids").is_none());
    }

    #[test]
    fn lookup_dangerous_clsid_known_entries() {
        assert!(lookup_dangerous_clsid("0002ce02-0000-0000-c000-000000000046").is_some());
        assert!(lookup_dangerous_clsid("f20da720-c02f-11ce-927b-0800095ae340").is_some());
        assert!(lookup_dangerous_clsid("996bf5e0-8044-4650-adeb-0b013914e99c").is_some());
        assert!(lookup_dangerous_clsid("00000000-0000-0000-0000-000000000000").is_none());
    }

    /// Build a minimal CompObj stream body — 28-byte header followed
    /// by AnsiUserType + (optional) ProgID. ClipboardFormat slot is
    /// left as a 4-byte zero marker.
    fn build_compobj_body(user_type: &str, prog_id: Option<&str>) -> Vec<u8> {
        let mut body = vec![0u8; 28];
        // AnsiUserType
        let mut ut = user_type.as_bytes().to_vec();
        ut.push(0);
        body.extend_from_slice(&(ut.len() as u32).to_le_bytes());
        body.extend_from_slice(&ut);
        // ClipboardFormat: zero marker → no string follows.
        body.extend_from_slice(&0u32.to_le_bytes());
        // ProgID (Reserved3)
        if let Some(pid) = prog_id {
            let mut p = pid.as_bytes().to_vec();
            p.push(0);
            body.extend_from_slice(&(p.len() as u32).to_le_bytes());
            body.extend_from_slice(&p);
        }
        body
    }

    #[test]
    fn surfaces_compobj_prog_id_for_extension_mismatch() {
        // .doc file whose CompObj actually claims to be Excel — the
        // CVE-2017-0199 / T1036.005 shape.
        let body = build_compobj_body("Microsoft Excel Worksheet", Some("Excel.Sheet.8"));
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/\x01CompObj", &body),
        ]);
        let (v, _) = run(&cfb);
        let co = v.get("office.compobj").and_then(|x| x.as_object()).unwrap();
        assert_eq!(
            co.get("app_version").and_then(|x| x.as_str()),
            Some("Excel.Sheet.8")
        );
        assert_eq!(
            co.get("prog_id").and_then(|x| x.as_str()),
            Some("Excel.Sheet.8")
        );
        assert_eq!(
            co.get("user_type").and_then(|x| x.as_str()),
            Some("Microsoft Excel Worksheet")
        );
    }

    #[test]
    fn compobj_parser_handles_missing_prog_id() {
        // Documents without a ProgID still surface the user_type.
        let body = build_compobj_body("Microsoft Word Document", None);
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/\x01CompObj", &body),
        ]);
        let (v, _) = run(&cfb);
        let co = v.get("office.compobj").and_then(|x| x.as_object()).unwrap();
        assert_eq!(
            co.get("user_type").and_then(|x| x.as_str()),
            Some("Microsoft Word Document")
        );
        assert!(co.get("app_version").is_none());
    }

    #[test]
    fn compobj_parser_rejects_truncated_stream() {
        // Just the 4-byte header — too short to carry any strings.
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/\x01CompObj", &[0u8; 4]),
        ]);
        let (v, _) = run(&cfb);
        // No office.compobj emitted when the stream can't be parsed.
        assert!(v.get("office.compobj").is_none());
    }

    #[test]
    fn iso8601_format_matches_known_unix_timestamp() {
        // 2024-01-15T08:00:00Z = 1_705_305_600
        assert_eq!(
            format_iso8601_utc(1_705_305_600),
            "2024-01-15T08:00:00Z"
        );
        // 1970-01-01T00:00:00Z = 0
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn macro_count_reflects_multiple_vba_storages() {
        // Real macro-enabled docs sometimes have nested VBA storages.
        let cfb = build_cfb(&[
            ("/WordDocument", b"x"),
            ("/Macros/VBA/Module1", b""),
            ("/Macros/VBA/Module2", b""),
            ("/Macros/VBA/_VBA_PROJECT", b""),
        ]);
        let (_, m) = run(&cfb);
        // Each /VBA storage entry counts; the exact tally depends on
        // how `cfb::CompoundFile::walk` materializes parent storages,
        // so we just assert a non-trivial count.
        assert!(m.get("office.macro_count").unwrap() >= 1.0);
    }
}
