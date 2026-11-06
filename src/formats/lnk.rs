//! Windows Shell Link (`.lnk`) extractor.
//!
//! Parses the 76-byte SHLLINK header, the optional IDList /
//! LinkInfo / StringData sections, and walks every ExtraData
//! block (Tracker / EnvironmentVariable / Darwin / Shim /
//! KnownFolder / SpecialFolder / IconEnvironment / PropertyStore).
//!
//! Trait-valuable forensic facts surface under `lnk.*`:
//!
//! - `lnk.header.{file_size, icon_index, show_command, hotkey,
//!   creation_time, access_time, write_time, flags[],
//!   file_attributes[]}` — the times as signed Unix seconds (UTC), a zero
//!   FILETIME omitted; the flags and attributes as arrays of set-bit
//!   names.
//! - `lnk.description`, `lnk.relative_path`, `lnk.working_directory`,
//!   `lnk.arguments`, `lnk.icon_location` — StringData entries
//!   resolved through their length-prefixed UTF-16LE / ANSI
//!   variant per `IsUnicode`.
//! - `lnk.tracker.{machine_id, mac_address, volume_droid,
//!   file_droid}` — TrackerDataBlock; the MAC is derived from the
//!   trailing bytes of the file Droid GUID.
//! - `lnk.environment_target`, `lnk.icon_environment_target`,
//!   `lnk.darwin_data`, `lnk.shim_layer_name`,
//!   `lnk.known_folder_id`, `lnk.special_folder_id` — single-field
//!   ExtraData blocks.
//! - `lnk.blocks[]` — the ExtraData block names
//!   present in the file.

use crate::metric;
use serde_json::{Value as JsonValue, json};

use crate::formats::common::{XorScan, extract_binary_strings, format_guid, put_str, put_u64};
use crate::output::{Metrics, Strings, ValueKey, Values};
use crate::value_key;

/// `{0001-4C00-0000-0000-AA00-3826B3713F}` — the canonical CLSID
/// in the SHLLINK header. The leading u32 doubles as the header
/// size field (76), so a quick "starts with 4C 00 00 00" magic
/// check is sufficient.
const LNK_MAGIC: &[u8; 4] = b"\x4C\x00\x00\x00";

const FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const FLAG_HAS_LINK_INFO: u32 = 0x0000_0002;
const FLAG_HAS_NAME: u32 = 0x0000_0004;
const FLAG_HAS_RELATIVE_PATH: u32 = 0x0000_0008;
const FLAG_HAS_WORKING_DIR: u32 = 0x0000_0010;
const FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;
const FLAG_HAS_ICON_LOCATION: u32 = 0x0000_0040;
const FLAG_IS_UNICODE: u32 = 0x0000_0080;

// ExtraData block signatures.
const EXTRA_ENVIRONMENT_VARIABLE_DATA: u32 = 0xA000_0001;
const EXTRA_CONSOLE_DATA: u32 = 0xA000_0002;
const EXTRA_TRACKER_DATA: u32 = 0xA000_0003;
const EXTRA_CONSOLE_FE_DATA: u32 = 0xA000_0004;
const EXTRA_SPECIAL_FOLDER_DATA: u32 = 0xA000_0005;
const EXTRA_DARWIN_DATA: u32 = 0xA000_0006;
const EXTRA_ICON_ENVIRONMENT_DATA: u32 = 0xA000_0007;
const EXTRA_SHIM_DATA: u32 = 0xA000_0008;
const EXTRA_PROPERTY_STORE_DATA: u32 = 0xA000_0009;
/// Byte offset of the ShowCommand u32 inside the fixed 76-byte header.
const SHOW_COMMAND_OFFSET: usize = 60;

const EXTRA_KNOWN_FOLDER_DATA: u32 = 0xA000_000B;
const EXTRA_VISTA_AND_ABOVE_IDLIST_DATA: u32 = 0xA000_000C;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    // Header is exactly 76 bytes; first 4 bytes are its self-described
    // length.
    if bytes.len() < 76 || !bytes.starts_with(LNK_MAGIC) {
        tracing::debug!(
            target: "filefacts::lnk",
            stage = "header",
            len = bytes.len(),
            "no 76-byte SHLLINK header; not parsed"
        );
        return;
    }

    let link_flags = crate::bytes::u32_le(bytes, 20).unwrap_or(0);
    let file_attributes = crate::bytes::u32_le(bytes, 24).unwrap_or(0);
    let creation_time = crate::bytes::u64_le(bytes, 28).unwrap_or(0);
    let access_time = crate::bytes::u64_le(bytes, 36).unwrap_or(0);
    let write_time = crate::bytes::u64_le(bytes, 44).unwrap_or(0);
    let file_size = crate::bytes::u32_le(bytes, 52).unwrap_or(0);
    let icon_index = crate::bytes::u32_le(bytes, 56).map_or(0, u32::cast_signed);
    let show_command = crate::bytes::u32_le(bytes, SHOW_COMMAND_OFFSET).unwrap_or(0);
    let hotkey = crate::bytes::u16_le(bytes, 64).unwrap_or(0);

    // Header object.
    let mut header = serde_json::Map::new();
    header.insert("file_size".into(), json!(file_size));
    header.insert("icon_index".into(), json!(icon_index));
    header.insert(
        "show_command".into(),
        JsonValue::String(show_command_name(show_command).to_string()),
    );
    // The name is decoded, but it came from the u32 at header offset 60.
    header.insert("show_command_offset".into(), json!(SHOW_COMMAND_OFFSET));
    if hotkey != 0 {
        header.insert("hotkey".into(), JsonValue::String(format_hotkey(hotkey)));
    }
    for (key, filetime) in [
        ("creation_time", creation_time),
        ("access_time", access_time),
        ("write_time", write_time),
    ] {
        if filetime != 0 {
            header.insert(key.into(), json!(crate::time::filetime_to_unix(filetime)));
        }
    }
    for (key, names) in [
        ("flags", bit_names(link_flags, LINK_FLAG_NAMES)),
        (
            "file_attributes",
            bit_names(file_attributes, FILE_ATTRIBUTE_NAMES),
        ),
    ] {
        if !names.is_empty() {
            header.insert(key.into(), JsonValue::from(names));
        }
    }
    values.insert_key(value_key!("lnk.header"), JsonValue::Object(header));

    // StringData sections.
    let is_unicode = link_flags & FLAG_IS_UNICODE != 0;
    let mut offset = 76usize;
    // Both sources carry the file offset of the bytes the path was read
    // from, so `lnk.target_path` anchors like every other fact.
    let mut id_list_path: Option<(String, usize)> = None;
    if link_flags & FLAG_HAS_LINK_TARGET_ID_LIST != 0
        && let Some(id_list_size) = crate::bytes::u16_le(bytes, offset)
    {
        let id_list_end = offset.saturating_add(2 + usize::from(id_list_size));
        let body = offset + 2;
        match bytes.get(body..id_list_end) {
            Some(list) => id_list_path = walk_id_list(list).map(|(p, at)| (p, body + at)),
            None => tracing::debug!(
                target: "filefacts::lnk",
                stage = "id-list",
                offset,
                len = id_list_size,
                "IDList runs past the end of the file"
            ),
        }
        offset = id_list_end;
    }
    let mut link_info_path: Option<(String, usize)> = None;
    if link_flags & FLAG_HAS_LINK_INFO != 0
        && let Some(link_info_size) = crate::bytes::u32_le(bytes, offset)
    {
        let link_info_size = crate::bytes::sat_usize(link_info_size);
        let link_info_end = offset.saturating_add(link_info_size);
        if link_info_size >= 0x1C
            && let Some(block) = bytes.get(offset..link_info_end)
        {
            link_info_path = parse_link_info(block, offset, values);
        }
        offset = link_info_end;
    }
    // Resolved target_path: the IDList walk is the canonical source;
    // LinkInfo's LocalBasePath + CommonPathSuffix is the documented
    // fallback when there's no IDList (per MS-SHLLINK §2.5).
    if let Some((p, at)) = id_list_path.or(link_info_path)
        && !p.is_empty()
    {
        put_str(values, value_key!("lnk.target_path"), p);
        put_u64(values, value_key!("lnk.target_path_offset"), at as u64);
    }
    // Each StringData field with the key of its `_offset` companion.
    let string_keys: &[(u32, ValueKey, ValueKey)] = &[
        (
            FLAG_HAS_NAME,
            value_key!("lnk.description"),
            value_key!("lnk.description_offset"),
        ),
        (
            FLAG_HAS_RELATIVE_PATH,
            value_key!("lnk.relative_path"),
            value_key!("lnk.relative_path_offset"),
        ),
        (
            FLAG_HAS_WORKING_DIR,
            value_key!("lnk.working_directory"),
            value_key!("lnk.working_directory_offset"),
        ),
        (
            FLAG_HAS_ARGUMENTS,
            value_key!("lnk.arguments"),
            value_key!("lnk.arguments_offset"),
        ),
        (
            FLAG_HAS_ICON_LOCATION,
            value_key!("lnk.icon_location"),
            value_key!("lnk.icon_location_offset"),
        ),
    ];
    for &(flag, key, offset_key) in string_keys {
        if link_flags & flag == 0 {
            continue;
        }
        match read_stringdata(bytes, offset, is_unicode) {
            Some((value, next)) => {
                if !value.is_empty() {
                    // Surface whitespace-obfuscation metrics on the
                    // arguments string. CVE-2025-9491 (ZDI-CAN-25373)
                    // padded argument fields to push the real command
                    // past the visible end of the properties dialog —
                    // detection traits consume these metric fields.
                    if flag == FLAG_HAS_ARGUMENTS {
                        emit_argument_whitespace_metrics(metrics, &value);
                    }
                    put_str(values, key, value);
                    // Anchor the fact to its StringData body (2 bytes of
                    // length prefix precede it). Consumers read the
                    // `<path>_offset` companion to turn a `value:` match
                    // into a byte-addressed span.
                    put_u64(values, offset_key, (offset + 2) as u64);
                }
                offset = next;
            }
            None => {
                tracing::debug!(
                    target: "filefacts::lnk",
                    stage = "string-data",
                    field = key.as_str(),
                    offset,
                    "StringData runs past the end of the file; later fields not read"
                );
                break;
            }
        }
    }

    // ExtraData blocks.
    let mut blocks: Vec<&'static str> = Vec::new();
    while offset + 8 <= bytes.len() {
        let Some(block_size) = crate::bytes::u32_le(bytes, offset).map(crate::bytes::sat_usize)
        else {
            break;
        };
        // A size under 4 is the TerminalBlock that ends the list.
        if block_size < 8 {
            if block_size >= 4 {
                tracing::debug!(
                    target: "filefacts::lnk",
                    stage = "extra-data",
                    offset,
                    len = block_size,
                    "ExtraData block too short for its signature; walk stopped"
                );
            }
            break;
        }
        let Some(block) = offset
            .checked_add(block_size)
            .and_then(|end| bytes.get(offset..end))
        else {
            tracing::debug!(
                target: "filefacts::lnk",
                stage = "extra-data",
                offset,
                len = block_size,
                "ExtraData block runs past the end of the file; walk stopped"
            );
            break;
        };
        let Some(signature) = crate::bytes::u32_le(block, 4) else {
            break;
        };
        // The shell finds a block by its signature and reads the first
        // (`SHFindDataBlock`), so a later block of the same signature is
        // never read: it must not replace the first one's facts, and it
        // lists nothing new.
        let Some(name) = block_name(signature).filter(|name| !blocks.contains(name)) else {
            offset += block_size;
            continue;
        };
        blocks.push(name);
        match signature {
            EXTRA_ENVIRONMENT_VARIABLE_DATA => {
                put_target_string(
                    block,
                    offset,
                    values,
                    value_key!("lnk.environment_target"),
                    value_key!("lnk.environment_target_offset"),
                );
            }
            EXTRA_TRACKER_DATA => {
                let mut tr = serde_json::Map::new();
                if let Some(s) = read_fixed_ansi(block, 16, 16) {
                    tr.insert("machine_id".into(), JsonValue::String(s));
                }
                if let Some(g) = read_guid(block, 0x20) {
                    tr.insert("volume_droid".into(), JsonValue::String(g));
                }
                if let Some(g) = read_guid(block, 0x30) {
                    // Last 6 bytes of the file Droid GUID are the
                    // node ID — the MAC address of the machine
                    // that created the link.
                    if let Some(mac) = derive_mac(&g) {
                        tr.insert("mac_address".into(), JsonValue::String(mac));
                    }
                    tr.insert("file_droid".into(), JsonValue::String(g));
                }
                if !tr.is_empty() {
                    values.insert_key(value_key!("lnk.tracker"), JsonValue::Object(tr));
                }
            }
            EXTRA_SPECIAL_FOLDER_DATA => {
                if let Some(id) = crate::bytes::u32_le(block, 8) {
                    put_u64(values, value_key!("lnk.special_folder_id"), u64::from(id));
                }
            }
            EXTRA_DARWIN_DATA => {
                put_target_string(
                    block,
                    offset,
                    values,
                    value_key!("lnk.darwin_data"),
                    value_key!("lnk.darwin_data_offset"),
                );
            }
            EXTRA_ICON_ENVIRONMENT_DATA => {
                put_target_string(
                    block,
                    offset,
                    values,
                    value_key!("lnk.icon_environment_target"),
                    value_key!("lnk.icon_environment_target_offset"),
                );
            }
            EXTRA_SHIM_DATA => {
                if let Some(s) = read_utf16le_string(block, 8, block_size.saturating_sub(8)) {
                    put_str(values, value_key!("lnk.shim_layer_name"), s);
                    put_u64(
                        values,
                        value_key!("lnk.shim_layer_name_offset"),
                        (offset + 8) as u64,
                    );
                }
            }
            EXTRA_KNOWN_FOLDER_DATA => {
                if let Some(g) = read_guid(block, 8) {
                    put_str(values, value_key!("lnk.known_folder_id"), g);
                }
            }
            _ => {}
        }
        offset += block_size;
    }
    if !blocks.is_empty() {
        values.insert_key(value_key!("lnk.blocks"), JsonValue::from(blocks));
    }
    metrics.insert(metric!("lnk.file_size"), f64::from(file_size));
}

/// The name `lnk.blocks` lists an ExtraData block under, by its signature;
/// `None` for one MS-SHLLINK does not define.
fn block_name(signature: u32) -> Option<&'static str> {
    Some(match signature {
        EXTRA_ENVIRONMENT_VARIABLE_DATA => "environment_variable",
        EXTRA_CONSOLE_DATA => "console",
        EXTRA_CONSOLE_FE_DATA => "console_fe",
        EXTRA_TRACKER_DATA => "tracker",
        EXTRA_SPECIAL_FOLDER_DATA => "special_folder",
        EXTRA_DARWIN_DATA => "darwin",
        EXTRA_ICON_ENVIRONMENT_DATA => "icon_environment",
        EXTRA_SHIM_DATA => "shim",
        EXTRA_PROPERTY_STORE_DATA => "property_store",
        EXTRA_KNOWN_FOLDER_DATA => "known_folder",
        EXTRA_VISTA_AND_ABOVE_IDLIST_DATA => "vista_idlist",
        _ => return None,
    })
}

/// Compute whitespace-obfuscation counts over an LNK argument
/// string and emit them under `lnk.arguments_*`. Trait rules read these
/// raw counts and pick their own thresholds (e.g. the CVE-2025-9491
/// "interpreter padding" composite uses
/// `arguments_max_whitespace_run >= 50` plus
/// `arguments_whitespace_count >= 100`). No derived decisions live here.
fn emit_argument_whitespace_metrics(metrics: &mut Metrics, args: &str) {
    let mut leading_spaces = 0usize;
    let mut leading_tabs = 0usize;
    let mut total_whitespace = 0usize;
    let mut current_run = 0usize;
    let mut max_run = 0usize;
    let mut in_leading = true;
    for c in args.chars() {
        if c.is_whitespace() {
            total_whitespace += 1;
            current_run += 1;
            if in_leading {
                match c {
                    ' ' => leading_spaces += 1,
                    '\t' => leading_tabs += 1,
                    _ => {}
                }
            }
        } else {
            in_leading = false;
            max_run = max_run.max(current_run);
            current_run = 0;
        }
    }
    max_run = max_run.max(current_run);
    metrics.insert(
        metric!("lnk.arguments_leading_spaces"),
        leading_spaces as f64,
    );
    metrics.insert(metric!("lnk.arguments_leading_tabs"), leading_tabs as f64);
    metrics.insert(
        metric!("lnk.arguments_whitespace_count"),
        total_whitespace as f64,
    );
    metrics.insert(metric!("lnk.arguments_max_whitespace_run"), max_run as f64);
}

/// Map the SHLLINK `ShowCommand` value to its Windows `SW_*`
/// friendly name. Trait rules consume the string form so the
/// underlying numeric encoding stays an implementation detail.
fn show_command_name(v: u32) -> &'static str {
    match v {
        0 => "hidden",
        1 => "normal",
        2 => "minimized",
        3 => "maximized",
        4 => "show_no_activate",
        5 => "show",
        6 => "minimize",
        7 => "minimized_no_active",
        8 => "show_na",
        9 => "restore",
        10 => "show_default",
        11 => "force_minimize",
        _ => "unknown",
    }
}

/// Format a hotkey word as `Modifier+Key` (e.g. `"ctrl+alt+F1"`).
fn format_hotkey(v: u16) -> String {
    let [key, mods] = v.to_le_bytes();
    let mut parts: Vec<&str> = Vec::new();
    if mods & 0x01 != 0 {
        parts.push("shift");
    }
    if mods & 0x02 != 0 {
        parts.push("ctrl");
    }
    if mods & 0x04 != 0 {
        parts.push("alt");
    }
    let key_name = match key {
        // VK codes for digits and letters are their ASCII characters.
        b'0'..=b'9' | b'A'..=b'Z' => char::from(key).to_string(),
        0x70..=0x87 => format!("F{}", key - 0x6F),
        _ => format!("0x{key:02x}"),
    };
    parts.push(&key_name);
    parts.join("+")
}

/// `LinkFlags` bits and their names.
const LINK_FLAG_NAMES: &[(u32, &str)] = &[
    (FLAG_HAS_LINK_TARGET_ID_LIST, "has_link_target_id_list"),
    (FLAG_HAS_LINK_INFO, "has_link_info"),
    (FLAG_HAS_NAME, "has_name"),
    (FLAG_HAS_RELATIVE_PATH, "has_relative_path"),
    (FLAG_HAS_WORKING_DIR, "has_working_dir"),
    (FLAG_HAS_ARGUMENTS, "has_arguments"),
    (FLAG_HAS_ICON_LOCATION, "has_icon_location"),
    (FLAG_IS_UNICODE, "is_unicode"),
    (0x0000_0100, "force_no_link_info"),
    (0x0000_0200, "has_exp_string"),
    (0x0000_0400, "run_in_separate_process"),
    (0x0000_1000, "has_darwin_id"),
    (0x0000_2000, "run_as_user"),
    (0x0000_4000, "has_exp_icon"),
    (0x0000_8000, "no_pidl_alias"),
    (0x0002_0000, "run_with_shim_layer"),
    (0x0004_0000, "force_no_link_track"),
    (0x0008_0000, "enable_target_metadata"),
    (0x0010_0000, "disable_link_path_tracking"),
    (0x0020_0000, "disable_known_folder_tracking"),
    (0x0040_0000, "disable_known_folder_alias"),
    (0x0080_0000, "allow_link_to_link"),
    (0x0100_0000, "unalias_on_save"),
    (0x0200_0000, "prefer_environment_path"),
    (0x0400_0000, "keep_local_id_list_for_unc_target"),
];

/// `FileAttributes` bits and their names.
const FILE_ATTRIBUTE_NAMES: &[(u32, &str)] = &[
    (0x0001, "readonly"),
    (0x0002, "hidden"),
    (0x0004, "system"),
    (0x0010, "directory"),
    (0x0020, "archive"),
    (0x0080, "normal"),
    (0x0100, "temporary"),
    (0x0200, "sparse"),
    (0x0400, "reparse_point"),
    (0x0800, "compressed"),
    (0x1000, "offline"),
    (0x2000, "not_content_indexed"),
    (0x4000, "encrypted"),
];

/// The names of the bits of `v` set in `names`, in table order.
fn bit_names(v: u32, names: &[(u32, &'static str)]) -> Vec<&'static str> {
    names
        .iter()
        .filter(|&&(bit, _)| v & bit != 0)
        .map(|&(_, name)| name)
        .collect()
}

/// Read a SHLLINK StringData (`u16 length` + N×byte content).
/// Returns `(decoded, next_offset)`. The length is in characters,
/// not bytes — multiply by 2 for the unicode case.
fn read_stringdata(bytes: &[u8], offset: usize, is_unicode: bool) -> Option<(String, usize)> {
    let len_chars = usize::from(crate::bytes::u16_le(bytes, offset)?);
    let body_start = offset + 2;
    let byte_len = if is_unicode { len_chars * 2 } else { len_chars };
    let body_end = body_start.checked_add(byte_len)?;
    let body = bytes.get(body_start..body_end)?;
    // StringData is returned verbatim — trimming would hide
    // CVE-2025-9491-style argument-padding obfuscation, which the
    // whitespace metrics are specifically designed to catch.
    let decoded = if is_unicode {
        crate::bytes::utf16_lossy(body, crate::bytes::Endian::Little)
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    Some((decoded, body_end))
}

/// Read a fixed-length UTF-16LE NUL-terminated string starting
/// at `offset`. Stops at the first 0-word.
fn read_utf16le_string(bytes: &[u8], offset: usize, len: usize) -> Option<String> {
    let slice = bytes.get(offset..offset.checked_add(len)?)?;
    let s = crate::bytes::utf16_lossy(
        crate::bytes::utf16_until_nul(slice),
        crate::bytes::Endian::Little,
    )
    .trim()
    .to_string();
    (!s.is_empty()).then_some(s)
}

/// Read a fixed-length ANSI NUL-terminated string.
fn read_fixed_ansi(bytes: &[u8], offset: usize, len: usize) -> Option<String> {
    let slice = bytes.get(offset..offset.checked_add(len)?)?;
    let text = slice.split(|b| *b == 0).next().unwrap_or_default();
    let s = String::from_utf8_lossy(text).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Publish the target an EnvironmentVariable, Darwin or IconEnvironment
/// block at file offset `block_offset` carries: a 260-byte ANSI field at +8
/// and its 520-byte Unicode counterpart at +268, the Unicode one preferred
/// when present. Its file offset goes to `offset_key`.
fn put_target_string(
    block: &[u8],
    block_offset: usize,
    values: &mut Values,
    key: ValueKey,
    offset_key: ValueKey,
) {
    const ANSI: (usize, usize) = (8, 260);
    const UNICODE: (usize, usize) = (268, 520);
    let Some((s, at)) = read_utf16le_string(block, UNICODE.0, UNICODE.1)
        .map(|s| (s, UNICODE.0))
        .or_else(|| read_fixed_ansi(block, ANSI.0, ANSI.1).map(|s| (s, ANSI.0)))
    else {
        return;
    };
    put_str(values, key, s);
    put_u64(values, offset_key, (block_offset + at) as u64);
}

/// Decode a GUID stored as little-endian Data1/Data2/Data3 + raw
/// Data4 (canonical Microsoft layout).
fn read_guid(bytes: &[u8], offset: usize) -> Option<String> {
    let b = bytes.get(offset..)?.first_chunk::<16>()?;
    Some(format_guid(b))
}

/// Extract the MAC address from the trailing 12 hex chars of a
/// SHLLINK file Droid GUID (the "node" portion of an RFC 4122
/// type-1 UUID, which is the originating machine's MAC).
fn derive_mac(guid: &str) -> Option<String> {
    let tail = guid.rsplit('-').next()?;
    if tail.len() != 12 {
        return None;
    }
    let bytes: Vec<String> = tail
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    Some(bytes.join(":"))
}

/// Parse the LinkInfo block (MS-SHLLINK §2.3). Emits
/// `lnk.volume.{drive_type, serial, name}` and
/// `lnk.network.{share, device, provider}` and returns the
/// composed local target path (`LocalBasePath` + `CommonPathSuffix`)
/// with the file offset of the base path, when present.
///
/// `block_base` is the offset of `block` within the file, so every
/// emitted fact carries a file-relative `_offset` companion.
fn parse_link_info(
    block: &[u8],
    block_base: usize,
    values: &mut Values,
) -> Option<(String, usize)> {
    if block.len() < 0x1C {
        return None;
    }
    let field = |at: usize| crate::bytes::u32_le(block, at).map(crate::bytes::sat_usize);
    let header_size = field(4)?;
    let link_info_flags = crate::bytes::u32_le(block, 8)?;
    let volume_id_off = field(12)?;
    let local_base_off = field(16)?;
    let net_link_off = field(20)?;
    let common_suffix_off = field(24)?;
    let (local_base_off_u, common_suffix_off_u) = if header_size >= 0x24 {
        (field(28).unwrap_or(0), field(32).unwrap_or(0))
    } else {
        (0, 0)
    };

    // VolumeIDAndLocalBasePath flag (bit 0).
    let vol = block.get(volume_id_off..).unwrap_or_default();
    if (link_info_flags & 0x1) != 0 && volume_id_off > 0 && vol.len() >= 16 {
        let drive_type = crate::bytes::u32_le(vol, 4).unwrap_or(0);
        let serial = crate::bytes::u32_le(vol, 8).unwrap_or(0);
        let label_off = crate::bytes::sat_usize(crate::bytes::u32_le(vol, 12).unwrap_or(0));
        let mut volume = serde_json::Map::new();
        volume.insert(
            "drive_type".into(),
            JsonValue::String(drive_type_name(drive_type).to_string()),
        );
        volume.insert("serial".into(), json!(serial));
        // When label_off == 0x14, a Unicode label offset follows
        // at +0x10 and the ASCII label is empty.
        let name = if label_off == 0x14 && vol.len() >= 20 {
            let unicode_off = crate::bytes::sat_usize(crate::bytes::u32_le(vol, 16).unwrap_or(0));
            read_utf16le_cstring(vol, unicode_off).map(|s| (s, unicode_off))
        } else {
            read_ansi_cstring(vol, label_off).map(|s| (s, label_off))
        };
        if let Some((name, at)) = name.filter(|(s, _)| !s.is_empty()) {
            volume.insert("name".into(), JsonValue::String(name));
            volume.insert("name_offset".into(), json!(block_base + volume_id_off + at));
        }
        values.insert_key(value_key!("lnk.volume"), JsonValue::Object(volume));
    }

    // CommonNetworkRelativeLinkAndPathSuffix flag (bit 1).
    let net = block.get(net_link_off..).unwrap_or_default();
    if (link_info_flags & 0x2) != 0 && net_link_off > 0 && net.len() >= 20 {
        let net_flags = crate::bytes::u32_le(net, 4).unwrap_or(0);
        let net_name_off = crate::bytes::sat_usize(crate::bytes::u32_le(net, 8).unwrap_or(0));
        let device_name_off = crate::bytes::sat_usize(crate::bytes::u32_le(net, 12).unwrap_or(0));
        let provider = crate::bytes::u32_le(net, 16).unwrap_or(0);
        let mut network = serde_json::Map::new();
        if let Some(name) = read_ansi_cstring(net, net_name_off)
            && !name.is_empty()
        {
            network.insert("share".into(), JsonValue::String(name));
            network.insert(
                "share_offset".into(),
                json!(block_base + net_link_off + net_name_off),
            );
        }
        // ValidDevice bit (0x1) → DeviceNameOffset is meaningful.
        if (net_flags & 0x1) != 0
            && let Some(name) = read_ansi_cstring(net, device_name_off)
            && !name.is_empty()
        {
            network.insert("device".into(), JsonValue::String(name));
            network.insert(
                "device_offset".into(),
                json!(block_base + net_link_off + device_name_off),
            );
        }
        if provider != 0 {
            network.insert("provider".into(), json!(provider));
        }
        if !network.is_empty() {
            values.insert_key(value_key!("lnk.network"), JsonValue::Object(network));
        }
    }

    // Compose local target path. Prefer Unicode offsets when present.
    let base = if local_base_off_u != 0 {
        read_utf16le_cstring(block, local_base_off_u).map(|s| (s, local_base_off_u))
    } else if local_base_off != 0 {
        read_ansi_cstring(block, local_base_off).map(|s| (s, local_base_off))
    } else {
        None
    };
    let suffix = if common_suffix_off_u != 0 {
        read_utf16le_cstring(block, common_suffix_off_u)
    } else if common_suffix_off != 0 {
        read_ansi_cstring(block, common_suffix_off)
    } else {
        None
    };
    match (base, suffix) {
        (Some((b, at)), Some(s)) if !s.is_empty() => Some((format!("{b}{s}"), block_base + at)),
        (Some((b, at)), _) => Some((b, block_base + at)),
        _ => None,
    }
}

fn drive_type_name(t: u32) -> &'static str {
    match t {
        0 => "unknown",
        1 => "no_root_dir",
        2 => "removable",
        3 => "fixed",
        4 => "remote",
        5 => "cdrom",
        6 => "ramdisk",
        _ => "unknown",
    }
}

fn read_ansi_cstring(buf: &[u8], offset: usize) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let rest = buf.get(offset..).filter(|r| !r.is_empty())?;
    let text = rest.split(|&b| b == 0).next().unwrap_or_default();
    Some(String::from_utf8_lossy(text).into_owned())
}

fn read_utf16le_cstring(buf: &[u8], offset: usize) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let rest = buf.get(offset..).filter(|r| r.len() >= 2)?;
    crate::bytes::utf16_strict(
        crate::bytes::utf16_until_nul(rest),
        crate::bytes::Endian::Little,
    )
}

/// Minimal IDList walker (MS-SHLLINK §2.2 + MS-SHLLINK Item ID Lists).
/// We walk the ItemID chain and pick up readable path components from
/// FileSystem-class items (class byte 0x30..=0x3F). The resolved path
/// is `\\?\<root>\<components…>` style — close enough to the
/// canonical `link_target()` for trait matching without bringing in
/// the full shell-folder parser.
///
/// Returns the path together with an anchor offset into `buf`. The
/// path is composed from several ItemIDs, so it exists nowhere in the
/// file as one contiguous run; the anchor points at the leaf
/// component's name — the part path traits actually match — falling
/// back to the drive root when that is all there is.
fn walk_id_list(buf: &[u8]) -> Option<(String, usize)> {
    let mut i = 0usize;
    let mut components: Vec<String> = Vec::new();
    let mut drive: Option<(String, usize)> = None;
    let mut anchor: Option<usize> = None;
    while let Some(size) = crate::bytes::u16_le(buf, i) {
        let size = usize::from(size);
        if size == 0 {
            break;
        }
        if size < 2 {
            return None;
        }
        let item = buf.get(i + 2..i + size)?;
        if let Some((c, at)) = parse_id_item(item, i + 2, &mut drive)
            && !c.is_empty()
        {
            components.push(c);
            anchor = Some(at);
        }
        i += size;
    }
    let anchor = anchor.or_else(|| drive.as_ref().map(|(_, at)| *at))?;
    let mut out = drive.map(|(d, _)| d).unwrap_or_default();
    for c in components {
        if !out.is_empty() && !out.ends_with('\\') {
            out.push('\\');
        }
        out.push_str(&c);
    }
    Some((out, anchor))
}

/// Parse one ItemID body. `item_base` is the body's offset within the
/// IDList, so returned (and recorded) anchors are IDList-relative.
fn parse_id_item(
    item: &[u8],
    item_base: usize,
    drive: &mut Option<(String, usize)>,
) -> Option<(String, usize)> {
    let &class = item.first()?;
    match class {
        // MyComputer / RootRegItem container — class 0x1F has an
        // embedded GUID at +2..+18; not interesting for path
        // resolution.
        0x1F => None,
        // Drive item: class 0x2E/0x2F; data is an ASCII drive root
        // like "C:\\\0".
        0x23..=0x25 | 0x2E..=0x2F => {
            if item.len() >= 4 {
                let root = item.get(1..).unwrap_or_default();
                let root = root.split(|&b| b == 0).next().unwrap_or_default();
                let s = String::from_utf8_lossy(root).into_owned();
                if !s.is_empty() {
                    let s = s.trim_end_matches('\\').to_string();
                    *drive = Some((s, item_base + 1));
                }
            }
            None
        }
        // FileSystem items: class 0x30..=0x3F. Layout:
        //   u8 class
        //   u8 reserved
        //   u32 file_size
        //   u32 last_modified
        //   u16 file_attrs
        //   ANSI ShortName (null-terminated, word-aligned)
        //   …extension block with Unicode LongName
        0x30..=0x3F => parse_filesystem_item(item).map(|(n, at)| (n, item_base + at)),
        _ => None,
    }
}

/// Returns the best available name with its offset within `item`.
fn parse_filesystem_item(item: &[u8]) -> Option<(String, usize)> {
    if item.len() < 14 {
        return None;
    }
    // ANSI ShortName begins at offset 12 of the item body (which is
    // offset 14 from the start of the ItemID record — we strip the
    // 2-byte size header before passing the body in).
    let name_start = 12;
    let names = item.get(name_start..).filter(|n| !n.is_empty())?;
    let ansi_len = names.iter().position(|&b| b == 0)?;
    let ansi_end = name_start + ansi_len;
    let short = String::from_utf8_lossy(names.get(..ansi_len)?).into_owned();

    // Walk past padding to a possible extension block containing the
    // Unicode LongName. The extension chain starts at the first
    // word-aligned offset after the ANSI name terminator.
    let mut probe = (ansi_end + 1).next_multiple_of(2);
    while probe + 6 <= item.len() {
        let (Some(ext_size), Some(ext_sig)) = (
            crate::bytes::u16_le(item, probe),
            crate::bytes::u16_le(item, probe + 4),
        ) else {
            break;
        };
        let ext_size = usize::from(ext_size);
        if ext_size < 6 {
            break;
        }
        let Some(ext) = item.get(probe..probe + ext_size) else {
            break;
        };
        // BEEF0004 extension blocks (long-name + timestamps) sit at
        // signature 0xBEEF; only the low word survives this read,
        // so we accept 0xBEEF as the marker.
        if ext_sig == 0xBEEF && ext_size >= 0x10 {
            // LongName UTF-16LE sits at a known sub-offset inside
            // BEEF0004; layout varies by version. Try +0x12 first
            // (XP+) and +0x1E (Vista+) and pick whichever decodes.
            for sub in [0x12usize, 0x1E] {
                if probe + sub + 2 > probe + ext_size {
                    continue;
                }
                if let Some(name) = read_utf16le_cstring(ext, sub)
                    && !name.is_empty()
                {
                    return Some((name, probe + sub));
                }
            }
        }
        probe += ext_size;
    }
    (!short.is_empty()).then_some((short, name_start))
}

#[cfg(test)]
mod tests;
