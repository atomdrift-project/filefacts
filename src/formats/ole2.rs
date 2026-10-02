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
//! - `office.sheet_count`, `office.xlm_sheet_count`,
//!   `office.hidden_sheet_count` — BIFF worksheet inventory.
//!
//! Metadata / property-set parsing is deferred to a follow-up slice;
//! the SummaryInformation stream uses a documented but non-trivial
//! property-set encoding (FMTID GUIDs + property IDs from MS-OSHARED).
//! For Phase 2's first slice, we surface the structural inventory
//! that supply-chain detection traits care about most.

use crate::metric;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;

use crate::bytes::{self, Reader};
use crate::error::Error;
use crate::formats::common::put_str;
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

/// Hard cap on the number of stream entries we enumerate. Real Office
/// documents have ≤ a few hundred; the cap keeps a hostile compound
/// file from looping us forever.
const MAX_STREAMS: usize = 4096;

/// Hard cap on the property-entry count read from a single OLEPS
/// section header. The header's `cProperties` field is attacker-
/// controlled; a malformed file could otherwise request unbounded
/// reads.
const MAX_PROPERTIES_PER_SECTION: usize = 256;
const MAX_NAMES: usize = 256;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    // A file carrying the OLE2 signature that `cfb` cannot open loses the
    // whole `office.*` view, and a malformed compound file is itself an
    // evasion shape, so the failure is reported rather than passed as an
    // empty document.
    let mut comp =
        cfb::CompoundFile::open(cursor).map_err(|e| Error::malformed_caused_by("ole2", e))?;

    let mut streams: Vec<String> = Vec::new();
    let mut macro_count: u64 = 0;
    let mut features: Vec<&'static str> = Vec::new();
    let mut had_ole10native = false;
    let mut had_encryption_info = false;
    let mut had_encrypted_package = false;
    let mut had_encrypted_summary = false;
    let mut had_object_pool = false;
    let mut dangerous_clsids: Vec<JsonValue> = Vec::new();

    for entry in comp.walk() {
        if streams.len() >= MAX_STREAMS {
            break;
        }
        let path = super::common::cfb_entry_path(&entry);
        let lower = path.to_ascii_lowercase();

        // Macros live under `/VBA/` storage. Some macro-enabled
        // templates also use `Macros/` or `_VBA_PROJECT_CUR/`; cover
        // all the documented forms. Excel writes the project directly as
        // `/_VBA_PROJECT`, which the `/vba` form misses -- the underscore
        // sits between the separator and the name.
        if entry.is_storage() {
            if lower.contains("/vba")
                || lower.contains("/_vba_project")
                || lower == "/macros"
                || lower.contains("/macros/")
            {
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
        if lower == "/objectpool" || lower.contains("/objectpool/") {
            had_object_pool = true;
        }
        if path == "/EncryptionInfo" || lower.contains("encryptioninfo") {
            had_encryption_info = true;
        }
        if path == "/EncryptedPackage" || lower.contains("encryptedpackage") {
            had_encrypted_package = true;
        }
        if lower.contains("encryptedsummary") {
            had_encrypted_summary = true;
        }

        streams.push(path);
    }

    // Empty stream listing → almost certainly not a real OLE2 doc.
    if streams.is_empty() {
        return Ok(());
    }

    let kind = detect_kind(&streams);
    put_str(values, value_key!("office.kind"), kind);

    metrics.insert(metric!("office.stream_count"), streams.len() as f64);
    values.insert_key(
        value_key!("office.streams"),
        JsonValue::Array(streams.iter().cloned().map(JsonValue::String).collect()),
    );

    if kind == "msg" {
        let attachments = msg_attachments(&mut comp, &streams);
        metrics.insert(
            metric!("office.msg.attachment_count"),
            attachments.len() as f64,
        );
        if !attachments.is_empty() {
            values.insert_key(
                value_key!("office.msg.attachments"),
                JsonValue::Array(attachments),
            );
        }
    }

    let summary_data = read_stream_data(&mut comp, "\x05SummaryInformation", errors);
    let summary_security_encrypted = summary_data
        .as_deref()
        .is_some_and(summary_document_security_encrypted);
    let word_document_encrypted = word_document_encrypted(&mut comp, errors);

    if macro_count > 0 {
        features.push("macros");
        metrics.insert(metric!("office.macro_count"), macro_count as f64);
    }

    // Excel 4.0 macro sheets. Deprecated since the 1990s and disabled by
    // default from 2021 precisely because of the maldoc wave that used them,
    // so a workbook still declaring one is worth reporting on its own.
    let workbook = ["Workbook", "Book"]
        .iter()
        .find_map(|name| read_stream_data(&mut comp, name, errors))
        .unwrap_or_default();
    let workbook = if biff_encrypted(&workbook) {
        Vec::new()
    } else {
        workbook
    };
    let sheets = boundsheets(&workbook);
    let names = defined_names(&workbook);
    for auto in ["auto_open", "auto_close"] {
        if names.iter().any(|n| n == auto) {
            features.push(if auto == "auto_open" {
                "auto_open"
            } else {
                "auto_close"
            });
        }
    }
    if !names.is_empty() {
        metrics.insert(metric!("office.name_count"), names.len() as f64);
        // XLM payloads live in defined names -- each one labels a cell the
        // macro sheet calls -- so the names themselves are worth reading.
        values.insert_key(
            value_key!("office.names"),
            JsonValue::Array(
                names
                    .iter()
                    .take(MAX_NAMES)
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    if !sheets.is_empty() {
        let xlm = sheets.iter().filter(|s| s.kind == SHEET_XLM).count();
        let hidden = sheets.iter().filter(|s| s.visibility != 0).count();
        metrics.insert(metric!("office.sheet_count"), sheets.len() as f64);
        values.insert_key(
            value_key!("office.sheet_names"),
            JsonValue::Array(
                sheets
                    .iter()
                    .filter(|s| !s.name.is_empty())
                    .map(|s| JsonValue::String(s.name.clone()))
                    .collect(),
            ),
        );
        if xlm > 0 {
            features.push("xlm_macros");
            metrics.insert(metric!("office.xlm_sheet_count"), xlm as f64);
        }
        if hidden > 0 {
            metrics.insert(metric!("office.hidden_sheet_count"), hidden as f64);
        }
        // Visibility 2 is "very hidden": the sheet cannot be unhidden from
        // Excel's own UI, only from VBA. Nothing a person maintaining a
        // workbook has a reason to set.
        if sheets.iter().any(|s| s.visibility == SHEET_VERY_HIDDEN) {
            features.push("veryhidden_sheets");
        }
    }
    if had_ole10native || had_object_pool {
        features.push("ole_objects");
    }
    if had_object_pool {
        features.push("object_pool");
    }
    if had_encryption_info
        || had_encrypted_package
        || had_encrypted_summary
        || summary_security_encrypted
        || word_document_encrypted
    {
        features.push("encryption");
    }
    if !dangerous_clsids.is_empty() {
        features.push("dangerous_clsid");
        let count = dangerous_clsids.len() as f64;
        values.insert_key(
            value_key!("office.dangerous_clsids"),
            JsonValue::Array(dangerous_clsids),
        );
        metrics.insert(metric!("office.dangerous_clsid_count"), count);
    }
    if !features.is_empty() {
        values.insert_key(
            value_key!("office.features"),
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    // SummaryInformation property set. The stream name is
    // `\x05SummaryInformation` (the SOH-prefix is the CFB shorthand
    // for a control-character storage). Emit the same `office.*`
    // paths as OOXML so rules do not care which container supplied
    // the property.
    let mut props: BTreeMap<ValueKey, JsonValue> = summary_data
        .as_deref()
        .map(parse_summary_information)
        .unwrap_or_default();
    // DocumentSummaryInformation extends the summary set with
    // manager / company / security_flag / hyperlink_base — fields
    // OOXML carries in `docProps/app.xml`.
    if let Some(data) = read_stream_data(&mut comp, "\x05DocumentSummaryInformation", errors) {
        for (k, v) in parse_document_summary_information(&data) {
            props.entry(k).or_insert(v);
        }
    }
    for (key, value) in props {
        values.insert_key(key, value);
    }

    // CompObj stream — `\x01CompObj` carries the OLE-class identity
    // strings. The forensically interesting one is the ProgID
    // (`Excel.Sheet.8`, `Word.Document.8`, `PowerPoint.Show.8`, …) —
    // a `.doc` file whose CompObj declares Excel is the canonical
    // CVE-2017-0199 extension-mismatch shape.
    if let Some(co) =
        read_stream_data(&mut comp, "\x01CompObj", errors).and_then(|data| parse_compobj(&data))
    {
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
        if !co.prog_id.is_empty() {
            // Naming note: cleave-side called this
            // `app_version`, but MS-OLEDS calls it the
            // ProgID. We surface both — `prog_id` is the
            // forward-looking name (matches the spec);
            // `app_version` stays for trait-rule continuity.
            obj.insert("prog_id".into(), JsonValue::String(co.prog_id.clone()));
            obj.insert("app_version".into(), JsonValue::String(co.prog_id));
        }
        if !obj.is_empty() {
            values.insert_key(value_key!("office.compobj"), JsonValue::Object(obj));
        }
    }

    Ok(())
}

/// Parse the `\x05SummaryInformation` property set (MS-OLEPS) and
/// return a map keyed by the same canonical names the OOXML
/// extractor uses for `office.*`, so trait rules can match
/// either legacy or modern Office uniformly.
///
/// Property layout:
/// - 28-byte header: byte-order mark, version, OS, class GUID, section count.
/// - Per-section header: FMTID (16 bytes) + offset (4 bytes).
/// - Section body: size (4) + property count (4) + (PID, offset) pairs.
/// - Each property entry: type tag (4) + value bytes (length depends on type).
fn parse_summary_information(data: &[u8]) -> BTreeMap<ValueKey, JsonValue> {
    let mut out = BTreeMap::new();
    let Some(section) = locate_first_section(data) else {
        return out;
    };
    for (pid, val_off) in property_entries(section) {
        // PIDSI_* per MS-OLEPS §2.4.1. The mapping uses the same
        // canonical names as the OOXML core-properties schema so
        // traits don't have to special-case the format.
        let key = match pid {
            0x02 => value_key!("office.title"),
            0x03 => value_key!("office.subject"),
            0x04 => value_key!("office.creator"), // PIDSI_AUTHOR
            0x05 => value_key!("office.keywords"),
            0x06 => value_key!("office.description"), // PIDSI_COMMENTS
            0x07 => value_key!("office.template"),
            0x08 => value_key!("office.last_modified_by"), // PIDSI_LASTAUTHOR
            0x09 => value_key!("office.revision"),         // VT_LPSTR holding a decimal string
            0x0B => value_key!("office.last_printed"),     // VT_FILETIME
            0x0C => value_key!("office.created"),          // VT_FILETIME
            0x0D => value_key!("office.modified"),         // PIDSI_LASTSAVE_DTM, VT_FILETIME
            0x12 => value_key!("office.application"),      // PIDSI_APPNAME
            0x13 => value_key!("office.document_security"), // PIDSI_DOC_SECURITY, VT_I4 bitfield
            _ => continue,
        };
        if out.contains_key(&key) {
            continue;
        }
        if let Some(value) =
            read_property(section, val_off).or_else(|| read_property_i32(section, val_off))
        {
            out.insert(key, value);
        }
    }
    out
}

/// Parse the `\x05DocumentSummaryInformation` property set into the
/// subset of fields that overlap with the OOXML `office.*` shape.
/// The full DSI also carries
/// custom user-defined properties in a second section; we skip those
/// for now — trait rules that care will get their own slice.
fn parse_document_summary_information(data: &[u8]) -> BTreeMap<ValueKey, JsonValue> {
    let mut out = BTreeMap::new();
    let Some(section) = locate_first_section(data) else {
        return out;
    };
    for (pid, val_off) in property_entries(section) {
        // PIDDSI_* per MS-OLEPS §2.4.2. We only surface the fields
        // that have a matching OOXML core / app-properties slot.
        let key = match pid {
            0x02 => value_key!("office.category"),
            0x05 => value_key!("office.presentation_format"),
            0x09 => value_key!("office.slide_count"), // VT_I4
            0x10 => value_key!("office.manager"),     // VT_LPSTR
            0x11 => value_key!("office.company"),     // VT_LPSTR
            0x13 => value_key!("office.security_flag"), // VT_I4 — bitfield
            0x1A => value_key!("office.hyperlink_base"), // VT_LPSTR
            _ => continue,
        };
        if out.contains_key(&key) {
            continue;
        }
        if let Some(value) =
            read_property(section, val_off).or_else(|| read_property_i32(section, val_off))
        {
            out.insert(key, value);
        }
    }
    out
}

/// A worksheet declared by a BIFF `BOUNDSHEET` record.
#[derive(Debug, PartialEq, Eq)]
struct BoundSheet {
    /// 0 = worksheet, 1 = Excel 4.0 macro sheet, 2 = chart, 6 = VB module.
    kind: u8,
    /// 0 = visible, 1 = hidden, 2 = very hidden.
    visibility: u8,
    name: String,
}

/// Excel 4.0 macro sheet.
const SHEET_XLM: u8 = 1;
const SHEET_VERY_HIDDEN: u8 = 2;

/// Built-in defined names, stored as an index rather than as text.
/// `auto_open` and `auto_close` are the two that make a workbook run
/// something without the reader touching anything.
const BUILTIN_NAMES: [&str; 14] = [
    "consolidate_area",
    "auto_open",
    "auto_close",
    "extract",
    "database",
    "criteria",
    "print_area",
    "print_titles",
    "recorder",
    "data_form",
    "auto_activate",
    "auto_deactivate",
    "sheet_title",
    "filter_database",
];

/// Read the `BOUNDSHEET` records from a BIFF workbook stream.
///
/// Excel 4.0 macro sheets are the payload surface of the XLM maldoc wave:
/// they hold formulas, not VBA, so a workbook carrying one has no
/// `_VBA_PROJECT` stream and looks macro-free to anything that only counts
/// those. The sheet type lives here and nowhere else.
///
/// Walks the record stream properly rather than scanning for the record id —
/// a `0x0085` byte pair occurs constantly inside cell data, and scanning
/// finds sheets in files that have none.
fn defined_names(data: &[u8]) -> Vec<String> {
    const DEFINEDNAME: u16 = 0x0018;
    const BUILTIN: u16 = 0x0020;
    // grbit(2) chKey(1) cch(1) cce(2) reserved(2) itab(2) then four length
    // bytes. BIFF8 then spends one byte on the string encoding before the
    // name itself; BIFF5 stores the bytes directly.
    const FIXED: usize = 14;
    let biff8 = biff_version(data) >= 0x0600;
    let start = if biff8 { FIXED + 1 } else { FIXED };
    let mut out = Vec::new();
    for (id, body) in biff_records(data) {
        let cch = match body.get(3) {
            Some(&c) if body.len() > start && id == DEFINEDNAME => c as usize,
            _ => continue,
        };
        // `body.len() > start` above, so the header and the first name byte
        // are present.
        let grbit = bytes::u16_le(body, 0).unwrap_or(0);
        // A built-in name is stored as its index rather than its text, and is
        // always one character long.
        if grbit & BUILTIN != 0 && cch == 1 {
            let Some(&idx) = body.get(start) else {
                continue;
            };
            out.push(match BUILTIN_NAMES.get(idx as usize) {
                Some(name) => (*name).to_string(),
                None => format!("builtin_{idx}"),
            });
            continue;
        }
        // Otherwise it is text: BIFF8 marks a wide string in the byte before
        // it, and the names that matter here are all ASCII either way.
        let wide = biff8 && body.get(FIXED).is_some_and(|b| b & 1 != 0);
        let step = if wide { 2 } else { 1 };
        let name: String = (0..cch)
            .filter_map(|i| body.get(start + i * step).map(|&b| b as char))
            .collect();
        if name.chars().count() == cch {
            out.push(name.to_ascii_lowercase());
        }
    }
    out
}

/// A sheet name: a length, then in BIFF8 an encoding byte and possibly
/// two-byte characters. Builders name sheets with random tokens, so the name
/// is worth reading even though nothing else here needs it.
fn sheet_name(rest: &[u8], biff8: bool) -> String {
    let Some(&cch) = rest.first() else {
        return String::new();
    };
    let cch = cch as usize;
    let (start, step) = match biff8 {
        true if rest.get(1).is_some_and(|f| f & 1 != 0) => (2, 2),
        true => (2, 1),
        false => (1, 1),
    };
    (0..cch)
        .filter_map(|i| rest.get(start + i * step).map(|&b| b as char))
        .collect()
}

/// Whether the workbook's record payloads are encrypted.
///
/// BIFF encryption leaves the record headers in the clear and enciphers the
/// bodies, so the walk still succeeds but every field it reads is ciphertext
/// -- sheet names come out as mojibake, and a random byte in the right place
/// would announce a macro sheet that is not there. `FILEPASS` appears in the
/// globals substream ahead of anything worth reading.
fn biff_encrypted(data: &[u8]) -> bool {
    const FILEPASS: u16 = 0x002F;
    const BOUNDSHEET: u16 = 0x0085;
    biff_records(data)
        .take_while(|(id, _)| *id != BOUNDSHEET)
        .any(|(id, _)| id == FILEPASS)
}

/// The BIFF version from the leading `BOF` record: `0x0500` for BIFF5,
/// `0x0600` for BIFF8. Record layouts differ between them.
fn biff_version(data: &[u8]) -> u16 {
    bytes::u16_le(data, 4).unwrap_or(0)
}

/// Walk a BIFF stream, yielding each record's id and payload.
///
/// A workbook stream opens with `BOF`; anything else is not BIFF, and walking
/// it would produce records out of arbitrary bytes.
fn biff_records(data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    const BOF: u16 = 0x0809;
    let biff = data.len() >= 4 && bytes::u16_le(data, 0) == Some(BOF);
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        if !biff {
            return None;
        }
        let id = bytes::u16_le(data, pos)?;
        let len = bytes::u16_le(data, pos + 2)? as usize;
        let body = data.get(pos + 4..pos + 4 + len)?;
        pos += 4 + len;
        Some((id, body))
    })
}

fn boundsheets(data: &[u8]) -> Vec<BoundSheet> {
    const BOUNDSHEET: u16 = 0x0085;
    let biff8 = biff_version(data) >= 0x0600;
    let mut out = Vec::new();
    for (id, body) in biff_records(data) {
        // lbPlyPos(4) + grbit(2) + cch(1) is the shortest useful BOUNDSHEET.
        if id != BOUNDSHEET || body.len() < 7 {
            continue;
        }
        let (Some(grbit), Some(rest)) = (bytes::u16_le(body, 4), body.get(6..)) else {
            continue;
        };
        out.push(BoundSheet {
            kind: (grbit >> 8) as u8,
            visibility: (grbit & 0xFF) as u8,
            name: sheet_name(rest, biff8),
        });
    }
    out
}

/// Storage-name prefix of an Outlook attachment object (MS-OXMSG §2.2.2).
const MSG_ATTACH_STORAGE_PREFIX: &str = "__attach_version1.0_#";

/// Attachments described per message. Outlook caps a message well below
/// this; the bound only stops a hostile file from inflating the values tree.
const MAX_MSG_ATTACHMENTS: usize = 64;

/// Longest string property read for an attachment (filename, MIME type,
/// content id). Real values are a few hundred bytes at most.
const MAX_MSG_STRING_BYTES: u64 = 4096;

/// `PidTagAttachMethod` value for an attached message (MS-OXCMSG §2.2.2.9).
const ATTACH_EMBEDDED_MSG: u32 = 5;

/// Describe the attachments of an Outlook `.msg` (MS-OXMSG): one object per
/// top-level `__attach_version1.0_#XXXXXXXX` storage, carrying the
/// properties a rule wants to key on without reading the payload.
///
/// - `filename` — `PidTagAttachLongFilename`, falling back to
///   `PidTagAttachFilename` (8.3) and `PidTagDisplayName`, as written.
/// - `extension` — lowercased suffix of `filename`, when it has one.
/// - `mime` — `PidTagAttachMimeTag`; `content_id` — `PidTagAttachContentId`.
/// - `size` — byte length of the `PidTagAttachDataBinary` stream.
/// - `method` — `PidTagAttachMethod` (`by_value`, `embedded_message`, `ole`,
///   ...); an embedded message or OLE object has no binary stream, its
///   payload is the `__substg1.0_3701000D` storage.
/// - `hidden` — `PidTagAttachmentHidden`, emitted only when set.
///
/// Attachments of an attached message live under that message's storage and
/// are not listed here.
fn msg_attachments<T: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<T>,
    streams: &[String],
) -> Vec<JsonValue> {
    let storages: Vec<&String> = streams
        .iter()
        .filter(|p| {
            p.strip_prefix('/').is_some_and(|name| {
                name.starts_with(MSG_ATTACH_STORAGE_PREFIX) && !name.contains('/')
            })
        })
        .take(MAX_MSG_ATTACHMENTS)
        .collect();

    let mut out = Vec::with_capacity(storages.len());
    for storage in storages {
        let mut obj = serde_json::Map::new();
        let filename = ["3707", "3704", "3001"]
            .iter()
            .find_map(|id| read_msg_string(comp, storage, id));
        if let Some(name) = filename {
            if let Some(ext) = attachment_extension(&name) {
                obj.insert("extension".into(), JsonValue::String(ext));
            }
            obj.insert("filename".into(), JsonValue::String(name));
        }
        if let Some(mime) = read_msg_string(comp, storage, "370E") {
            obj.insert("mime".into(), JsonValue::String(mime));
        }
        if let Some(cid) = read_msg_string(comp, storage, "3712") {
            obj.insert("content_id".into(), JsonValue::String(cid));
        }
        if let Ok(entry) = comp.entry(format!("{storage}/__substg1.0_37010102")) {
            if entry.is_stream() {
                obj.insert("size".into(), JsonValue::from(entry.len()));
            }
        }
        let props = msg_attachment_properties(comp, storage);
        let method = props.method.or_else(|| {
            // Writers that omit the property still store an attached
            // message / OLE object as a sub-storage.
            comp.is_storage(format!("{storage}/__substg1.0_3701000D"))
                .then_some(ATTACH_EMBEDDED_MSG)
        });
        if let Some(method) = method.and_then(attach_method_name) {
            obj.insert("method".into(), JsonValue::String(method.into()));
        }
        if props.hidden {
            obj.insert("hidden".into(), JsonValue::Bool(true));
        }
        out.push(JsonValue::Object(obj));
    }
    out
}

fn attach_method_name(method: u32) -> Option<&'static str> {
    Some(match method {
        0 => "none",
        1 => "by_value",
        2 => "by_reference",
        4 => "by_reference_only",
        5 => "embedded_message",
        6 => "ole",
        _ => return None,
    })
}

/// Fixed-size properties read from an attachment's property stream.
#[derive(Default)]
struct MsgAttachmentProperties {
    method: Option<u32>,
    hidden: bool,
}

/// Parse `__properties_version1.0` of an attachment storage: an 8-byte
/// reserved header, then 16-byte entries of `tag (u32) | flags (u32) |
/// value (8 bytes)` (MS-OXMSG §2.4.2). Only fixed-width values are inline,
/// which is all this reads.
fn msg_attachment_properties<T: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<T>,
    storage: &str,
) -> MsgAttachmentProperties {
    const PID_TAG_ATTACH_METHOD: u32 = 0x3705_0003;
    const PID_TAG_ATTACHMENT_HIDDEN: u32 = 0x7FFE_000B;
    const HEADER: usize = 8;
    const ENTRY: usize = 16;
    // An attachment carries a few dozen properties; bound the read anyway.
    const MAX_BYTES: u64 = 64 * 1024;

    let mut props = MsgAttachmentProperties::default();
    let Ok(stream) = comp.open_stream(format!("{storage}/__properties_version1.0")) else {
        return props;
    };
    let mut data = Vec::new();
    if stream.take(MAX_BYTES).read_to_end(&mut data).is_err() {
        return props;
    }
    for entry in data
        .get(HEADER..)
        .unwrap_or_default()
        .as_chunks::<ENTRY>()
        .0
    {
        let (Some(tag), Some(value)) = (bytes::u32_le(entry, 0), bytes::u32_le(entry, 8)) else {
            continue;
        };
        match tag {
            PID_TAG_ATTACH_METHOD => props.method = Some(value),
            PID_TAG_ATTACHMENT_HIDDEN => props.hidden = value & 0xFF != 0,
            _ => {}
        }
    }
    props
}

/// Read a string property stream `__substg1.0_<id><type>` of `storage`,
/// preferring the Unicode (`001F`, UTF-16LE) spelling over the 8-bit
/// (`001E`) one. NULs are stripped and surrounding whitespace trimmed;
/// empty values read as absent.
fn read_msg_string<T: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<T>,
    storage: &str,
    prop_id: &str,
) -> Option<String> {
    for (prop_type, wide) in [("001F", true), ("001E", false)] {
        let Ok(stream) = comp.open_stream(format!("{storage}/__substg1.0_{prop_id}{prop_type}"))
        else {
            continue;
        };
        let mut data = Vec::new();
        if stream
            .take(MAX_MSG_STRING_BYTES)
            .read_to_end(&mut data)
            .is_err()
        {
            continue;
        }
        let text = if wide {
            bytes::utf16_lossy(&data, bytes::Endian::Little)
        } else {
            String::from_utf8_lossy(&data).into_owned()
        };
        let text: String = text.chars().filter(|c| *c != '\0').collect();
        let text = text.trim();
        if !text.is_empty() {
            return Some(text.to_string());
        }
    }
    None
}

/// Lowercased extension of an attachment filename: the text after the last
/// `.` of its final path segment, when that is non-empty, at most 16
/// characters, and free of whitespace.
fn attachment_extension(filename: &str) -> Option<String> {
    let base = super::common::basename(filename);
    let (stem, ext) = base.rsplit_once('.')?;
    let usable = !stem.is_empty()
        && !ext.is_empty()
        && ext.chars().count() <= 16
        && !ext.chars().any(char::is_whitespace);
    usable.then(|| ext.to_lowercase())
}

/// Read a whole stream. An absent stream is `None` and normal; one that is
/// listed but cannot be read (a broken sector chain) is also recorded, since
/// whatever is built from it would otherwise just be missing.
fn read_stream_data<T: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<T>,
    path: &str,
    errors: &mut Errors,
) -> Option<Vec<u8>> {
    let mut stream = comp.open_stream(path).ok()?;
    let mut data = Vec::new();
    if let Err(e) = stream.read_to_end(&mut data) {
        record_unreadable_stream(errors, path, &e);
        return None;
    }
    Some(data)
}

fn record_unreadable_stream(errors: &mut Errors, path: &str, e: &std::io::Error) {
    errors.record_malformed(
        Stage::Ole2Parse,
        format!(
            "stream {:?} unreadable: {e}",
            path.trim_start_matches(['\x01', '\x05'])
        ),
    );
}

fn summary_document_security_encrypted(data: &[u8]) -> bool {
    let Some(section) = locate_first_section(data) else {
        return false;
    };
    let Some(value) = property_i32_by_pid(section, 0x13) else {
        return false;
    };
    value & 1 == 1
}

fn property_i32_by_pid(section: &[u8], wanted_pid: u32) -> Option<i32> {
    let (_, val_off) = property_entries(section).find(|&(pid, _)| pid == wanted_pid)?;
    let Some(JsonValue::Number(value)) = read_property_i32(section, val_off) else {
        return None;
    };
    value.as_i64().and_then(|v| i32::try_from(v).ok())
}

/// The `(PID, value offset)` pairs of a property-set section, which follow
/// its size and property-count words. At most [`MAX_PROPERTIES_PER_SECTION`]
/// are read, and the walk stops at the first pair that runs past the section.
fn property_entries(section: &[u8]) -> impl Iterator<Item = (u32, usize)> {
    let count =
        bytes::u32_le(section, 4).map_or(0, |n| (n as usize).min(MAX_PROPERTIES_PER_SECTION));
    let mut entries = Reader::at(section, 8);
    (0..count).map_while(move |_| Some((entries.u32_le()?, entries.u32_le()? as usize)))
}

fn word_document_encrypted<T: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<T>,
    errors: &mut Errors,
) -> bool {
    const PATH: &str = "WordDocument";
    let Ok(mut stream) = comp.open_stream(PATH) else {
        return false;
    };
    // Only the FIB flag word at offset 10 is needed. The rest of the stream
    // is still read through, into a sink rather than a buffer, so a sector
    // chain that ends early is recorded like any other unreadable stream.
    let mut fib = Vec::with_capacity(12);
    let read = (&mut stream)
        .take(12)
        .read_to_end(&mut fib)
        .and_then(|_| std::io::copy(&mut stream, &mut std::io::sink()));
    if let Err(e) = read {
        record_unreadable_stream(errors, PATH, &e);
        return false;
    }
    bytes::u16_le(&fib, 10).is_some_and(|flags| flags & 0x0100 != 0)
}

/// Read a VT_I4 (signed 32-bit integer) at `(section + offset)`.
/// Separate from `read_property` because the canonical helper only
/// surfaces types that flow through OOXML's `office.*` schema
/// (strings + filetime); DSI counts like `slide_count` need integer
/// decoding.
fn read_property_i32(section: &[u8], offset: usize) -> Option<JsonValue> {
    let mut property = Reader::at(section, offset);
    let vt = property.u32_le()?;
    let v = property.u32_le()?.cast_signed();
    (vt == 0x0003).then(|| JsonValue::Number(v.into()))
}

/// Locate the first section's byte slice within a property-set
/// stream. The header layout (offsets within `data`):
/// - 0..4   ByteOrder (0xFFFE) | Version (2)
/// - 4..24  OS / CLSID — skipped
/// - 24..28 Section count (u32, must be ≥ 1)
/// - 28..44 `Section[0].FMTID`
/// - 44..48 `Section[0].Offset` → `data[offset..]` is the section body
fn locate_first_section(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 48 {
        return None;
    }
    if bytes::u16_le(data, 0) != Some(0xFFFE) {
        return None;
    }
    if bytes::u32_le(data, 24)? == 0 {
        return None;
    }
    let section_off = bytes::u32_le(data, 44)? as usize;
    if section_off >= data.len() {
        return None;
    }
    data.get(section_off..)
}

/// Read a property value at `(section + offset)` and decode it into
/// JSON. Returns `None` for types we don't surface as core metadata
/// (thumbnails, BLOBs, integer counts that aren't part of the
/// `office.*` schema).
fn read_property(section: &[u8], offset: usize) -> Option<JsonValue> {
    let vt = bytes::u32_le(section, offset)?;
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
    let len = bytes::u32_le(body, 0)? as usize;
    if len == 0 {
        return None;
    }
    let s = String::from_utf8_lossy(body.get(4..4 + len)?)
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(JsonValue::String(s))
    }
}

fn read_lpwstr(body: &[u8]) -> Option<JsonValue> {
    let chars = bytes::u32_le(body, 0)? as usize;
    let byte_len = chars.checked_mul(2)?;
    if chars == 0 {
        return None;
    }
    let units = body.get(4..byte_len.checked_add(4)?)?;
    let s = bytes::utf16_lossy(units, bytes::Endian::Little)
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(JsonValue::String(s))
    }
}

fn read_filetime(body: &[u8]) -> Option<JsonValue> {
    let ticks = bytes::u64_le(body, 0)?;
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
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "civil_from_days: every intermediate is bounded by the day count of a u64 second value"
)]
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

/// Parsed CompObj stream contents.
#[derive(Debug, Default)]
struct CompObjData {
    user_type: String,
    clipboard_format: String,
    /// Emitted as both `prog_id` and the legacy `app_version` key.
    prog_id: String,
}

/// Parse the CompObj stream layout (MS-OLEDS §2.3.6.1).
///
/// Header: 28 bytes of reserved/version fields.
/// Body:
///   - AnsiUserType: LengthPrefixedAnsiString
///   - AnsiClipboardFormat: ClipboardFormatOrAnsiString (4-byte
///     registered ID OR length-prefixed string)
///   - Reserved3: optional LengthPrefixedAnsiString (the ProgID)
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

    if let Some((s, advance)) = data.get(pos..).and_then(read_length_prefixed_ansi) {
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
    let Some(marker) = bytes::u32_le(data, pos) else {
        return Some(out);
    };
    if marker == 0 {
        pos += 4;
    } else {
        let len = marker as usize;
        let str_start = pos + 4;
        let text = data
            .get(str_start..str_start + len)
            .filter(|_| len > 0 && len <= 256)
            .filter(|t| {
                t.iter()
                    .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0)
            });
        if let Some(text) = text {
            out.clipboard_format = sanitize_ansi(text);
            pos = str_start + len;
        } else {
            pos += 4;
        }
    }

    if let Some((s, _)) = data.get(pos..).and_then(read_length_prefixed_ansi) {
        out.prog_id = s;
    }

    Some(out)
}

fn read_length_prefixed_ansi(buf: &[u8]) -> Option<(String, usize)> {
    let len = bytes::u32_le(buf, 0)? as usize;
    if len == 0 {
        return Some((String::new(), 4));
    }
    Some((sanitize_ansi(buf.get(4..4 + len)?), 4 + len))
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
    match clsid {
        "00021700-0000-0000-c000-000000000046"
        | "0002ce02-0000-0000-c000-000000000046"
        | "0003000b-0000-0000-c000-000000000046"
        | "0004a6b0-0000-0000-c000-000000000046" => Some("Equation Editor"),
        "00020c01-0000-0000-c000-000000000046"
        | "00022601-0000-0000-c000-000000000046"
        | "00022602-0000-0000-c000-000000000046"
        | "00022603-0000-0000-c000-000000000046"
        | "0003000c-0000-0000-c000-000000000046"
        | "0003000d-0000-0000-c000-000000000046"
        | "0003000e-0000-0000-c000-000000000046"
        | "f20da720-c02f-11ce-927b-0800095ae340" => Some("OLE Package"),
        "d27cdb6e-ae6d-11cf-96b8-444553540000" | "d27cdb70-ae6d-11cf-96b8-444553540000" => {
            Some("Shockwave Flash")
        }
        "06290bd2-48aa-11d2-8432-006008c3fbfc" => Some("scriptlet.typelib"),
        "25336920-03f9-11cf-8fd0-00aa00686f13" => Some("htmlfile"),
        "996bf5e0-8044-4650-adeb-0b013914e99c" => Some("MSCOMCTL.ListViewCtrl"),
        "bdd1f04b-858b-11d1-b16a-00c0f0283628" => Some("MSCOMCTL.ListViewCtrl.2"),
        "8856f961-340a-11d0-a96b-00c04fd705a2" => Some("Shell.Explorer"),
        "00000300-0000-0000-c000-000000000046" => Some("StdOleLink"),
        "79eac9d0-baf9-11ce-8c82-00aa004ba90b" | "79eac9d1-baf9-11ce-8c82-00aa004ba90b" => {
            Some("StdHlink")
        }
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
mod tests;
