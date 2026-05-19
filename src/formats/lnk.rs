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
//!   file_attributes[]}` — Pike-style flag arrays replace the
//!   per-flag-bool sprawl.
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
//! - `lnk.blocks[]` — Pike-style array of ExtraData block names
//!   present in the file.

use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str, put_u64};
use crate::output::{Metrics, Strings, Values};

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
const EXTRA_KNOWN_FOLDER_DATA: u32 = 0xA000_000B;
const EXTRA_VISTA_AND_ABOVE_IDLIST_DATA: u32 = 0xA000_000C;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    // Header is exactly 76 bytes; first 4 bytes are its self-described
    // length.
    if bytes.len() < 76 || &bytes[..4] != LNK_MAGIC {
        return Ok(());
    }

    let link_flags = read_u32(bytes, 20).unwrap_or(0);
    let file_attributes = read_u32(bytes, 24).unwrap_or(0);
    let creation_time = read_u64(bytes, 28).unwrap_or(0);
    let access_time = read_u64(bytes, 36).unwrap_or(0);
    let write_time = read_u64(bytes, 44).unwrap_or(0);
    let file_size = read_u32(bytes, 52).unwrap_or(0);
    let icon_index = read_i32(bytes, 56).unwrap_or(0);
    let show_command = read_u32(bytes, 60).unwrap_or(0);
    let hotkey = read_u16(bytes, 64).unwrap_or(0);

    // Header object.
    let mut header = serde_json::Map::new();
    header.insert("file_size".into(), json!(file_size));
    header.insert("icon_index".into(), json!(icon_index));
    header.insert(
        "show_command".into(),
        JsonValue::String(show_command_name(show_command).to_string()),
    );
    if hotkey != 0 {
        header.insert("hotkey".into(), JsonValue::String(format_hotkey(hotkey)));
    }
    if creation_time != 0 {
        header.insert("creation_time".into(), json!(creation_time));
    }
    if access_time != 0 {
        header.insert("access_time".into(), json!(access_time));
    }
    if write_time != 0 {
        header.insert("write_time".into(), json!(write_time));
    }
    let flags = decode_link_flags(link_flags);
    if !flags.is_empty() {
        header.insert(
            "flags".into(),
            JsonValue::Array(flags.into_iter().map(|s| JsonValue::String(s.into())).collect()),
        );
    }
    let attrs = decode_file_attributes(file_attributes);
    if !attrs.is_empty() {
        header.insert(
            "file_attributes".into(),
            JsonValue::Array(attrs.into_iter().map(|s| JsonValue::String(s.into())).collect()),
        );
    }
    values.insert("lnk.header", JsonValue::Object(header));

    // StringData sections.
    let is_unicode = link_flags & FLAG_IS_UNICODE != 0;
    let mut offset = 76usize;
    let mut id_list_path: Option<String> = None;
    if link_flags & FLAG_HAS_LINK_TARGET_ID_LIST != 0 {
        if let Some(id_list_size) = read_u16(bytes, offset) {
            let id_list_end = offset.saturating_add(2 + id_list_size as usize);
            if id_list_end <= bytes.len() {
                id_list_path = walk_id_list(&bytes[offset + 2..id_list_end]);
            }
            offset = id_list_end;
        }
    }
    let mut link_info_path: Option<String> = None;
    if link_flags & FLAG_HAS_LINK_INFO != 0 {
        if let Some(link_info_size) = read_u32(bytes, offset) {
            let link_info_size = link_info_size as usize;
            let link_info_end = offset.saturating_add(link_info_size);
            if link_info_size >= 0x1C && link_info_end <= bytes.len() {
                link_info_path = parse_link_info(&bytes[offset..link_info_end], values);
            }
            offset = link_info_end;
        }
    }
    // Resolved target_path: the IDList walk is the canonical source;
    // LinkInfo's LocalBasePath + CommonPathSuffix is the documented
    // fallback when there's no IDList (per MS-SHLLINK §2.5).
    if let Some(p) = id_list_path.or(link_info_path) {
        if !p.is_empty() {
            put_str(values, "lnk.target_path", p);
        }
    }
    let string_keys: &[(u32, &str)] = &[
        (FLAG_HAS_NAME, "lnk.description"),
        (FLAG_HAS_RELATIVE_PATH, "lnk.relative_path"),
        (FLAG_HAS_WORKING_DIR, "lnk.working_directory"),
        (FLAG_HAS_ARGUMENTS, "lnk.arguments"),
        (FLAG_HAS_ICON_LOCATION, "lnk.icon_location"),
    ];
    for (flag, key) in string_keys {
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
                    if *key == "lnk.arguments" {
                        emit_argument_whitespace_metrics(metrics, &value);
                    }
                    put_str(values, key, value);
                }
                offset = next;
            }
            None => break,
        }
    }

    // ExtraData blocks.
    let mut blocks: Vec<&'static str> = Vec::new();
    while offset + 8 <= bytes.len() {
        let Some(block_size) = read_u32(bytes, offset).map(|n| n as usize) else {
            break;
        };
        if block_size < 8 || offset + block_size > bytes.len() {
            break;
        }
        let block = &bytes[offset..offset + block_size];
        let Some(signature) = read_u32(block, 4) else {
            break;
        };
        match signature {
            EXTRA_ENVIRONMENT_VARIABLE_DATA => {
                blocks.push("environment_variable");
                if let Some(s) = read_ansi_or_unicode_pair(block, 8, 268, 260, 520) {
                    put_str(values, "lnk.environment_target", s);
                }
            }
            EXTRA_CONSOLE_DATA => blocks.push("console"),
            EXTRA_CONSOLE_FE_DATA => blocks.push("console_fe"),
            EXTRA_TRACKER_DATA => {
                blocks.push("tracker");
                let mut tr = serde_json::Map::new();
                if let Some(s) = read_fixed_ansi(block, 16, 16) {
                    tr.insert("machine_id".into(), JsonValue::String(s));
                }
                let volume_droid = read_guid(block, 0x20);
                let file_droid = read_guid(block, 0x30);
                if let Some(g) = volume_droid.as_ref() {
                    tr.insert("volume_droid".into(), JsonValue::String(g.clone()));
                }
                if let Some(g) = file_droid.as_ref() {
                    tr.insert("file_droid".into(), JsonValue::String(g.clone()));
                    // Last 6 bytes of the file Droid GUID are the
                    // node ID — the MAC address of the machine
                    // that created the link.
                    if let Some(mac) = derive_mac(g) {
                        tr.insert("mac_address".into(), JsonValue::String(mac));
                    }
                }
                if !tr.is_empty() {
                    values.insert("lnk.tracker", JsonValue::Object(tr));
                }
            }
            EXTRA_SPECIAL_FOLDER_DATA => {
                blocks.push("special_folder");
                if let Some(id) = read_u32(block, 8) {
                    put_u64(values, "lnk.special_folder_id", u64::from(id));
                }
            }
            EXTRA_DARWIN_DATA => {
                blocks.push("darwin");
                if let Some(s) = read_ansi_or_unicode_pair(block, 8, 268, 260, 520) {
                    put_str(values, "lnk.darwin_data", s);
                }
            }
            EXTRA_ICON_ENVIRONMENT_DATA => {
                blocks.push("icon_environment");
                if let Some(s) = read_ansi_or_unicode_pair(block, 8, 268, 260, 520) {
                    put_str(values, "lnk.icon_environment_target", s);
                }
            }
            EXTRA_SHIM_DATA => {
                blocks.push("shim");
                if let Some(s) = read_utf16le_string(block, 8, block_size.saturating_sub(8)) {
                    put_str(values, "lnk.shim_layer_name", s);
                }
            }
            EXTRA_PROPERTY_STORE_DATA => blocks.push("property_store"),
            EXTRA_KNOWN_FOLDER_DATA => {
                blocks.push("known_folder");
                if let Some(g) = read_guid(block, 8) {
                    put_str(values, "lnk.known_folder_id", g);
                }
            }
            EXTRA_VISTA_AND_ABOVE_IDLIST_DATA => blocks.push("vista_idlist"),
            _ => {}
        }
        offset += block_size;
    }
    if !blocks.is_empty() {
        values.insert(
            "lnk.blocks",
            JsonValue::Array(blocks.into_iter().map(|s| JsonValue::String(s.into())).collect()),
        );
    }
    metrics.insert("lnk.file_size", f64::from(file_size));

    Ok(())
}

/// Compute whitespace-obfuscation counts over an LNK argument
/// string and emit them under `lnk.args_*`. Trait rules read these
/// raw counts and pick their own thresholds (e.g. the CVE-2025-9491
/// "interpreter padding" composite uses `args_max_whitespace_run
/// >= 50` plus `args_whitespace_total >= 100`). No derived
/// decisions live here.
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
            if current_run > max_run {
                max_run = current_run;
            }
            current_run = 0;
        }
    }
    if current_run > max_run {
        max_run = current_run;
    }
    metrics.insert("lnk.args_leading_spaces", leading_spaces as f64);
    metrics.insert("lnk.args_leading_tabs", leading_tabs as f64);
    metrics.insert("lnk.args_whitespace_total", total_whitespace as f64);
    metrics.insert("lnk.args_max_whitespace_run", max_run as f64);
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
    let key = (v & 0xFF) as u8;
    let mods = (v >> 8) as u8;
    let mut parts: Vec<&str> = Vec::new();
    if mods & 0x01 != 0 { parts.push("shift"); }
    if mods & 0x02 != 0 { parts.push("ctrl"); }
    if mods & 0x04 != 0 { parts.push("alt"); }
    let key_name = match key {
        0x30..=0x39 => format!("{}", (key - 0x30) as char),
        0x41..=0x5A => format!("{}", key as char),
        0x70..=0x87 => format!("F{}", key - 0x6F),
        _ => format!("0x{key:02x}"),
    };
    parts.push(""); // separator placeholder
    let mut out = parts[..parts.len() - 1].join("+");
    if !out.is_empty() {
        out.push('+');
    }
    out.push_str(&key_name);
    out
}

fn decode_link_flags(v: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if v & FLAG_HAS_LINK_TARGET_ID_LIST != 0 { out.push("has_link_target_id_list"); }
    if v & FLAG_HAS_LINK_INFO != 0 { out.push("has_link_info"); }
    if v & FLAG_HAS_NAME != 0 { out.push("has_name"); }
    if v & FLAG_HAS_RELATIVE_PATH != 0 { out.push("has_relative_path"); }
    if v & FLAG_HAS_WORKING_DIR != 0 { out.push("has_working_dir"); }
    if v & FLAG_HAS_ARGUMENTS != 0 { out.push("has_arguments"); }
    if v & FLAG_HAS_ICON_LOCATION != 0 { out.push("has_icon_location"); }
    if v & FLAG_IS_UNICODE != 0 { out.push("is_unicode"); }
    if v & 0x0000_0100 != 0 { out.push("force_no_link_info"); }
    if v & 0x0000_0200 != 0 { out.push("has_exp_string"); }
    if v & 0x0000_0400 != 0 { out.push("run_in_separate_process"); }
    if v & 0x0000_1000 != 0 { out.push("has_darwin_id"); }
    if v & 0x0000_2000 != 0 { out.push("run_as_user"); }
    if v & 0x0000_4000 != 0 { out.push("has_exp_icon"); }
    if v & 0x0000_8000 != 0 { out.push("no_pidl_alias"); }
    if v & 0x0002_0000 != 0 { out.push("run_with_shim_layer"); }
    if v & 0x0004_0000 != 0 { out.push("force_no_link_track"); }
    if v & 0x0008_0000 != 0 { out.push("enable_target_metadata"); }
    if v & 0x0010_0000 != 0 { out.push("disable_link_path_tracking"); }
    if v & 0x0020_0000 != 0 { out.push("disable_known_folder_tracking"); }
    if v & 0x0040_0000 != 0 { out.push("disable_known_folder_alias"); }
    if v & 0x0080_0000 != 0 { out.push("allow_link_to_link"); }
    if v & 0x0100_0000 != 0 { out.push("unalias_on_save"); }
    if v & 0x0200_0000 != 0 { out.push("prefer_environment_path"); }
    if v & 0x0400_0000 != 0 { out.push("keep_local_id_list_for_unc_target"); }
    out
}

fn decode_file_attributes(v: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if v & 0x0001 != 0 { out.push("readonly"); }
    if v & 0x0002 != 0 { out.push("hidden"); }
    if v & 0x0004 != 0 { out.push("system"); }
    if v & 0x0010 != 0 { out.push("directory"); }
    if v & 0x0020 != 0 { out.push("archive"); }
    if v & 0x0080 != 0 { out.push("normal"); }
    if v & 0x0100 != 0 { out.push("temporary"); }
    if v & 0x0200 != 0 { out.push("sparse"); }
    if v & 0x0400 != 0 { out.push("reparse_point"); }
    if v & 0x0800 != 0 { out.push("compressed"); }
    if v & 0x1000 != 0 { out.push("offline"); }
    if v & 0x2000 != 0 { out.push("not_content_indexed"); }
    if v & 0x4000 != 0 { out.push("encrypted"); }
    out
}

/// Read a SHLLINK StringData (`u16 length` + N×byte content).
/// Returns `(decoded, next_offset)`. The length is in characters,
/// not bytes — multiply by 2 for the unicode case.
fn read_stringdata(bytes: &[u8], offset: usize, is_unicode: bool) -> Option<(String, usize)> {
    let len_chars = read_u16(bytes, offset)? as usize;
    let body_start = offset + 2;
    let byte_len = if is_unicode { len_chars * 2 } else { len_chars };
    let body_end = body_start.checked_add(byte_len)?;
    if body_end > bytes.len() {
        return None;
    }
    let body = &bytes[body_start..body_end];
    // StringData is returned verbatim — trimming would hide
    // CVE-2025-9491-style argument-padding obfuscation, which the
    // whitespace metrics are specifically designed to catch.
    let decoded = if is_unicode {
        let words: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&words)
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    Some((decoded, body_end))
}

/// Read a fixed-length UTF-16LE NUL-terminated string starting
/// at `offset`. Stops at the first 0-word.
fn read_utf16le_string(bytes: &[u8], offset: usize, len: usize) -> Option<String> {
    let slice = bytes.get(offset..offset + len)?;
    let mut words = Vec::new();
    for c in slice.chunks_exact(2) {
        let w = u16::from_le_bytes([c[0], c[1]]);
        if w == 0 {
            break;
        }
        words.push(w);
    }
    let s = String::from_utf16_lossy(&words).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Read a fixed-length ANSI NUL-terminated string.
fn read_fixed_ansi(bytes: &[u8], offset: usize, len: usize) -> Option<String> {
    let slice = bytes.get(offset..offset + len)?;
    let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    let s = String::from_utf8_lossy(&slice[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Read either an ANSI field or its Unicode counterpart that
/// occupies higher offsets in the same block. Prefer the Unicode
/// version when present.
fn read_ansi_or_unicode_pair(
    block: &[u8],
    ansi_off: usize,
    uni_off: usize,
    ansi_len: usize,
    uni_len: usize,
) -> Option<String> {
    read_utf16le_string(block, uni_off, uni_len).or_else(|| read_fixed_ansi(block, ansi_off, ansi_len))
}

/// Decode a GUID stored as little-endian Data1/Data2/Data3 + raw
/// Data4 (canonical Microsoft layout).
fn read_guid(bytes: &[u8], offset: usize) -> Option<String> {
    let b = bytes.get(offset..offset + 16)?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    ))
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
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect();
    Some(bytes.join(":"))
}

/// Parse the LinkInfo block (MS-SHLLINK §2.3). Emits
/// `lnk.volume.{drive_type, serial, name}` and
/// `lnk.network.{share, device, provider}` and returns the
/// composed local target path (`LocalBasePath` + `CommonPathSuffix`)
/// when present.
fn parse_link_info(block: &[u8], values: &mut Values) -> Option<String> {
    if block.len() < 0x1C {
        return None;
    }
    let header_size = read_u32(block, 4)? as usize;
    let link_info_flags = read_u32(block, 8)?;
    let volume_id_off = read_u32(block, 12)? as usize;
    let local_base_off = read_u32(block, 16)? as usize;
    let net_link_off = read_u32(block, 20)? as usize;
    let common_suffix_off = read_u32(block, 24)? as usize;
    let (local_base_off_u, common_suffix_off_u) = if header_size >= 0x24 {
        (
            read_u32(block, 28).map(|n| n as usize).unwrap_or(0),
            read_u32(block, 32).map(|n| n as usize).unwrap_or(0),
        )
    } else {
        (0, 0)
    };

    // VolumeIDAndLocalBasePath flag (bit 0).
    if (link_info_flags & 0x1) != 0 && volume_id_off > 0 && volume_id_off < block.len() {
        let vol = &block[volume_id_off..];
        if vol.len() >= 16 {
            let drive_type = read_u32(vol, 4).unwrap_or(0);
            let serial = read_u32(vol, 8).unwrap_or(0);
            let label_off = read_u32(vol, 12).unwrap_or(0) as usize;
            let mut volume = serde_json::Map::new();
            volume.insert(
                "drive_type".into(),
                JsonValue::String(drive_type_name(drive_type).to_string()),
            );
            volume.insert("serial".into(), json!(serial));
            // When label_off == 0x14, a Unicode label offset follows
            // at +0x10 and the ASCII label is empty.
            let name = if label_off == 0x14 && vol.len() >= 20 {
                let unicode_off = read_u32(vol, 16).unwrap_or(0) as usize;
                read_utf16le_cstring(vol, unicode_off)
            } else {
                read_ansi_cstring(vol, label_off)
            };
            if let Some(name) = name.filter(|s| !s.is_empty()) {
                volume.insert("name".into(), JsonValue::String(name));
            }
            values.insert("lnk.volume", JsonValue::Object(volume));
        }
    }

    // CommonNetworkRelativeLinkAndPathSuffix flag (bit 1).
    if (link_info_flags & 0x2) != 0 && net_link_off > 0 && net_link_off < block.len() {
        let net = &block[net_link_off..];
        if net.len() >= 20 {
            let net_flags = read_u32(net, 4).unwrap_or(0);
            let net_name_off = read_u32(net, 8).unwrap_or(0) as usize;
            let device_name_off = read_u32(net, 12).unwrap_or(0) as usize;
            let provider = read_u32(net, 16).unwrap_or(0);
            let mut network = serde_json::Map::new();
            if let Some(name) = read_ansi_cstring(net, net_name_off) {
                if !name.is_empty() {
                    network.insert("share".into(), JsonValue::String(name));
                }
            }
            // ValidDevice bit (0x1) → DeviceNameOffset is meaningful.
            if (net_flags & 0x1) != 0 {
                if let Some(name) = read_ansi_cstring(net, device_name_off) {
                    if !name.is_empty() {
                        network.insert("device".into(), JsonValue::String(name));
                    }
                }
            }
            if provider != 0 {
                network.insert("provider".into(), json!(provider));
            }
            if !network.is_empty() {
                values.insert("lnk.network", JsonValue::Object(network));
            }
        }
    }

    // Compose local target path. Prefer Unicode offsets when present.
    let base = if local_base_off_u != 0 {
        read_utf16le_cstring(block, local_base_off_u)
    } else if local_base_off != 0 {
        read_ansi_cstring(block, local_base_off)
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
        (Some(b), Some(s)) if !s.is_empty() => Some(format!("{b}{s}")),
        (Some(b), _) => Some(b),
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
    if offset == 0 || offset >= buf.len() {
        return None;
    }
    let end = buf[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(buf.len(), |p| offset + p);
    Some(String::from_utf8_lossy(&buf[offset..end]).into_owned())
}

fn read_utf16le_cstring(buf: &[u8], offset: usize) -> Option<String> {
    if offset == 0 || offset + 2 > buf.len() {
        return None;
    }
    let mut units = Vec::new();
    let mut i = offset;
    while i + 2 <= buf.len() {
        let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16(&units).ok()
}

/// Minimal IDList walker (MS-SHLLINK §2.2 + MS-SHLLINK Item ID Lists).
/// We walk the ItemID chain and pick up readable path components from
/// FileSystem-class items (class byte 0x30..=0x3F). The resolved path
/// is `\\?\<root>\<components…>` style — close enough to the
/// canonical `link_target()` for trait matching without bringing in
/// the full shell-folder parser.
fn walk_id_list(buf: &[u8]) -> Option<String> {
    let mut i = 0usize;
    let mut components: Vec<String> = Vec::new();
    let mut drive: Option<String> = None;
    while i + 2 <= buf.len() {
        let size = u16::from_le_bytes([buf[i], buf[i + 1]]) as usize;
        if size == 0 {
            break;
        }
        if size < 2 || i + size > buf.len() {
            return None;
        }
        let item = &buf[i + 2..i + size];
        if let Some(c) = parse_id_item(item, &mut drive) {
            if !c.is_empty() {
                components.push(c);
            }
        }
        i += size;
    }
    if drive.is_none() && components.is_empty() {
        return None;
    }
    let mut out = drive.unwrap_or_default();
    for c in components {
        if !out.is_empty() && !out.ends_with('\\') {
            out.push('\\');
        }
        out.push_str(&c);
    }
    Some(out)
}

fn parse_id_item(item: &[u8], drive: &mut Option<String>) -> Option<String> {
    if item.is_empty() {
        return None;
    }
    let class = item[0];
    match class {
        // MyComputer / RootRegItem container — class 0x1F has an
        // embedded GUID at +2..+18; not interesting for path
        // resolution.
        0x1F => None,
        // Drive item: class 0x2E/0x2F; data is an ASCII drive root
        // like "C:\\\0".
        0x23..=0x25 | 0x2E..=0x2F => {
            if item.len() >= 4 {
                let end = item[1..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(item.len(), |p| 1 + p);
                let s = String::from_utf8_lossy(&item[1..end]).into_owned();
                if !s.is_empty() {
                    let s = s.trim_end_matches('\\').to_string();
                    *drive = Some(s);
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
        0x30..=0x3F => parse_filesystem_item(item),
        _ => None,
    }
}

fn parse_filesystem_item(item: &[u8]) -> Option<String> {
    if item.len() < 14 {
        return None;
    }
    // ANSI ShortName begins at offset 12 of the item body (which is
    // offset 14 from the start of the ItemID record — we strip the
    // 2-byte size header before passing the body in).
    let name_start = 12;
    if name_start >= item.len() {
        return None;
    }
    let ansi_end = item[name_start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| name_start + p)?;
    let short = String::from_utf8_lossy(&item[name_start..ansi_end]).into_owned();

    // Walk past padding to a possible extension block containing the
    // Unicode LongName. The extension chain starts at the first
    // word-aligned offset after the ANSI name terminator.
    let mut probe = ansi_end + 1;
    if probe % 2 != 0 {
        probe += 1;
    }
    while probe + 6 <= item.len() {
        let ext_size = u16::from_le_bytes([item[probe], item[probe + 1]]) as usize;
        if ext_size < 6 || probe + ext_size > item.len() {
            break;
        }
        let ext_sig = u16::from_le_bytes([item[probe + 4], item[probe + 5]]);
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
                if let Some(name) = read_utf16le_cstring(&item[probe..probe + ext_size], sub) {
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
        }
        probe += ext_size;
    }
    if short.is_empty() {
        None
    } else {
        Some(short)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    bytes
        .get(offset..offset + 4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(link_flags: u32, file_attrs: u32, show_command: u32) -> Vec<u8> {
        let mut h = vec![0u8; 76];
        h[..4].copy_from_slice(&0x0000_004Cu32.to_le_bytes());
        // CLSID (16 bytes from offset 4) — exact value doesn't matter for our parse
        h[4] = 0x01; h[5] = 0x14; h[6] = 0x02; h[7] = 0x00;
        h[20..24].copy_from_slice(&link_flags.to_le_bytes());
        h[24..28].copy_from_slice(&file_attrs.to_le_bytes());
        h[52..56].copy_from_slice(&0x1234u32.to_le_bytes());
        h[60..64].copy_from_slice(&show_command.to_le_bytes());
        h
    }

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
    }

    #[test]
    fn rejects_non_lnk() {
        let (v, _) = run(b"not an lnk");
        assert!(v.get("lnk.header").is_none());
    }

    #[test]
    fn surfaces_header_flags() {
        let lnk = header_bytes(FLAG_HAS_LINK_TARGET_ID_LIST | FLAG_IS_UNICODE, 0x0020, 3);
        let (v, _) = run(&lnk);
        let header = v.get("lnk.header").and_then(|x| x.as_object()).unwrap();
        assert_eq!(header.get("show_command").and_then(|x| x.as_str()), Some("maximized"));
        let flags = header.get("flags").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = flags.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"has_link_target_id_list"));
        assert!(names.contains(&"is_unicode"));
        let attrs = header.get("file_attributes").and_then(|x| x.as_array()).unwrap();
        let attr_names: Vec<&str> = attrs.iter().filter_map(|x| x.as_str()).collect();
        assert!(attr_names.contains(&"archive"));
    }

    #[test]
    fn extracts_relative_path_unicode() {
        // Header sets HAS_RELATIVE_PATH + IS_UNICODE; no IDList/LinkInfo so the
        // string sits at offset 76 directly.
        let path = "..\\target.exe";
        let mut lnk = header_bytes(FLAG_HAS_RELATIVE_PATH | FLAG_IS_UNICODE, 0, 1);
        let chars: Vec<u16> = path.encode_utf16().collect();
        lnk.extend_from_slice(&(chars.len() as u16).to_le_bytes());
        for w in &chars {
            lnk.extend_from_slice(&w.to_le_bytes());
        }
        let (v, _) = run(&lnk);
        assert_eq!(
            v.get("lnk.relative_path").and_then(|x| x.as_str()),
            Some(path)
        );
    }

    #[test]
    fn extracts_tracker_block() {
        // Build a minimal header + TrackerData ExtraData block.
        let mut lnk = header_bytes(0, 0, 1);
        // TrackerDataBlock: u32 block_size, u32 signature, u32 length,
        // u32 version, ansi machine_id[16], guid volume[16], guid file[16]
        let mut block = Vec::new();
        block.extend_from_slice(&(96u32).to_le_bytes()); // block_size (rounded for our layout)
        block.extend_from_slice(&EXTRA_TRACKER_DATA.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes()); // length
        block.extend_from_slice(&0u32.to_le_bytes()); // version
        let mut machine = b"build-host-01\0\0\0".to_vec();
        machine.resize(16, 0);
        block.extend_from_slice(&machine);
        // Volume Droid GUID
        block.extend_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC, 0xDD,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        // File Droid GUID (last 6 bytes encode the MAC)
        block.extend_from_slice(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ]);
        // Block was declared as 96 bytes total; pad if needed.
        while block.len() < 96 {
            block.push(0);
        }
        // Final zero u32 terminates ExtraData.
        lnk.extend_from_slice(&block);
        lnk.extend_from_slice(&0u32.to_le_bytes());

        let (v, _) = run(&lnk);
        let tracker = v.get("lnk.tracker").and_then(|x| x.as_object()).unwrap();
        assert_eq!(tracker.get("machine_id").and_then(|x| x.as_str()), Some("build-host-01"));
        let mac = tracker.get("mac_address").and_then(|x| x.as_str()).unwrap();
        assert_eq!(mac, "22:33:44:55:66:77");
        let blocks = v.get("lnk.blocks").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = blocks.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"tracker"));
    }

    #[test]
    fn empty_input_is_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("lnk.header").is_none());
    }

    #[test]
    fn truncated_header_doesnt_crash() {
        // Right header size field but file is shorter than the declared
        // header — should silently bail rather than panic.
        let mut h = vec![0u8; 40];
        h[..4].copy_from_slice(&0x0000_004Cu32.to_le_bytes());
        let (v, _) = run(&h);
        assert!(v.get("lnk.header").is_none());
    }

    #[test]
    fn wrong_header_size_rejected() {
        // Header size != 0x4C → not a valid SHLLINK header.
        let mut h = vec![0u8; 76];
        h[..4].copy_from_slice(&0x0000_0040u32.to_le_bytes());
        let (v, _) = run(&h);
        assert!(v.get("lnk.header").is_none());
    }

    #[test]
    fn file_size_metric_surfaces() {
        let lnk = header_bytes(0, 0, 1);
        let (_, m) = run(&lnk);
        // file_size at offset 52 == 0x1234.
        assert_eq!(m.get("lnk.file_size"), Some(f64::from(0x1234)));
    }

    #[test]
    fn show_command_defaults_for_unknown_value() {
        // Show command of 999 is not 1/3/7 → should fall back without panic.
        let lnk = header_bytes(0, 0, 999);
        let (v, _) = run(&lnk);
        let header = v.get("lnk.header").and_then(|x| x.as_object()).unwrap();
        // show_command may be absent or have a sane fallback; just assert no panic.
        let _ = header.get("show_command");
    }

    #[test]
    fn derive_mac_handles_short_guid() {
        assert!(derive_mac("not-a-guid").is_none());
        assert!(derive_mac("aaaaaaaa-bbbb-cccc-dddd-zz").is_none());
    }

    #[test]
    fn derive_mac_extracts_six_bytes() {
        let mac = derive_mac("00000000-0000-0000-0000-aabbccddeeff").unwrap();
        assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
    }

    /// Build a minimal LinkInfo block (no Unicode optional fields,
    /// VolumeIDAndLocalBasePath set) of the form:
    ///
    /// [header 0x1C bytes][VolumeID][LocalBasePath ASCIIZ][CommonPathSuffix ASCIIZ]
    fn build_link_info_with_local_path(
        drive_type: u32,
        serial: u32,
        label: &str,
        local: &str,
        suffix: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        // Header: 7 u32 fields, 0x1C bytes total. We fill offsets in
        // after constructing payload positions.
        out.extend_from_slice(&[0u8; 0x1C]);

        // VolumeID block at offset 0x1C.
        let volume_offset = out.len() as u32;
        let mut vol = Vec::new();
        vol.extend_from_slice(&[0u8; 4]); // size placeholder
        vol.extend_from_slice(&drive_type.to_le_bytes());
        vol.extend_from_slice(&serial.to_le_bytes());
        vol.extend_from_slice(&(0x10u32).to_le_bytes()); // VolumeLabelOffset
        vol.extend_from_slice(label.as_bytes());
        vol.push(0);
        let vol_size = vol.len() as u32;
        vol[0..4].copy_from_slice(&vol_size.to_le_bytes());
        out.extend_from_slice(&vol);

        // LocalBasePath.
        let local_offset = out.len() as u32;
        out.extend_from_slice(local.as_bytes());
        out.push(0);

        // CommonPathSuffix.
        let suffix_offset = out.len() as u32;
        out.extend_from_slice(suffix.as_bytes());
        out.push(0);

        let total_size = out.len() as u32;
        out[0..4].copy_from_slice(&total_size.to_le_bytes());
        out[4..8].copy_from_slice(&0x1Cu32.to_le_bytes()); // HeaderSize
        out[8..12].copy_from_slice(&0x1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
        out[12..16].copy_from_slice(&volume_offset.to_le_bytes());
        out[16..20].copy_from_slice(&local_offset.to_le_bytes());
        out[20..24].copy_from_slice(&0u32.to_le_bytes()); // no network link
        out[24..28].copy_from_slice(&suffix_offset.to_le_bytes());
        out
    }

    #[test]
    fn link_info_yields_volume_and_target_path() {
        let mut lnk = header_bytes(FLAG_HAS_LINK_INFO, 0x20, 1);
        let info = build_link_info_with_local_path(
            3, // fixed drive
            0xDEAD_BEEF,
            "System",
            "C:\\Windows\\System32\\notepad.exe",
            "",
        );
        lnk.extend_from_slice(&info);
        let (v, _) = run(&lnk);
        let vol = v.get("lnk.volume").and_then(|x| x.as_object()).unwrap();
        assert_eq!(vol.get("drive_type").and_then(|x| x.as_str()), Some("fixed"));
        assert_eq!(vol.get("serial").and_then(|x| x.as_u64()), Some(0xDEAD_BEEF));
        assert_eq!(vol.get("name").and_then(|x| x.as_str()), Some("System"));
        assert_eq!(
            v.get("lnk.target_path").and_then(|x| x.as_str()),
            Some("C:\\Windows\\System32\\notepad.exe")
        );
    }

    #[test]
    fn link_info_with_path_suffix_concatenates() {
        let mut lnk = header_bytes(FLAG_HAS_LINK_INFO, 0x20, 1);
        let info = build_link_info_with_local_path(
            3,
            0,
            "",
            "C:\\Users\\victim",
            "\\Desktop\\target.exe",
        );
        lnk.extend_from_slice(&info);
        let (v, _) = run(&lnk);
        assert_eq!(
            v.get("lnk.target_path").and_then(|x| x.as_str()),
            Some("C:\\Users\\victim\\Desktop\\target.exe")
        );
    }

    #[test]
    fn id_list_walk_recovers_drive_root_when_no_link_info() {
        // Header has IDList flag set but no LinkInfo. Build a single
        // drive-root ItemID (class 0x2F, content "C:\\\0").
        let mut lnk = header_bytes(FLAG_HAS_LINK_TARGET_ID_LIST, 0, 1);

        // First, the IDList size (u16). We'll fill it in after.
        let id_list_start = lnk.len();
        lnk.extend_from_slice(&[0u8; 2]);

        // ItemID #1: drive root C:\
        let item1: Vec<u8> = {
            let mut b = vec![0x2Fu8]; // class
            b.extend_from_slice(b"C:\\\0");
            b
        };
        let item1_size = (2 + item1.len()) as u16;
        lnk.extend_from_slice(&item1_size.to_le_bytes());
        lnk.extend_from_slice(&item1);

        // Terminator (u16 0).
        lnk.extend_from_slice(&[0u8, 0u8]);
        let id_list_size = (lnk.len() - id_list_start - 2) as u16;
        lnk[id_list_start..id_list_start + 2].copy_from_slice(&id_list_size.to_le_bytes());

        let (v, _) = run(&lnk);
        let target = v.get("lnk.target_path").and_then(|x| x.as_str()).unwrap();
        assert!(target.starts_with("C:"), "got: {target}");
    }

    #[test]
    fn link_info_too_short_is_silent() {
        // FLAG_HAS_LINK_INFO set but the LinkInfo size field
        // declares less than the 0x1C header.
        let mut lnk = header_bytes(FLAG_HAS_LINK_INFO, 0, 1);
        lnk.extend_from_slice(&8u32.to_le_bytes()); // size = 8 (truncated)
        lnk.extend_from_slice(&[0u8; 4]);
        let (v, _) = run(&lnk);
        assert!(v.get("lnk.volume").is_none());
        assert!(v.get("lnk.target_path").is_none());
    }

    #[test]
    fn drive_type_name_maps_known_values() {
        assert_eq!(drive_type_name(3), "fixed");
        assert_eq!(drive_type_name(4), "remote");
        assert_eq!(drive_type_name(5), "cdrom");
        assert_eq!(drive_type_name(99), "unknown");
    }

    /// Build an LNK with a `HasArguments` StringData payload whose
    /// UTF-16LE content is the requested string.
    fn lnk_with_arguments(args: &str) -> Vec<u8> {
        let mut lnk = header_bytes(FLAG_HAS_ARGUMENTS | FLAG_IS_UNICODE, 0, 1);
        let chars: Vec<u16> = args.encode_utf16().collect();
        lnk.extend_from_slice(&(chars.len() as u16).to_le_bytes());
        for w in &chars {
            lnk.extend_from_slice(&w.to_le_bytes());
        }
        lnk
    }

    #[test]
    fn argument_whitespace_metrics_fire_on_padded_args() {
        // 60 leading spaces + "powershell.exe -enc AAAA".
        let mut args = " ".repeat(60);
        args.push_str("powershell.exe -enc AAAA");
        let (_, m) = run(&lnk_with_arguments(&args));
        assert_eq!(m.get("lnk.args_leading_spaces"), Some(60.0));
        assert_eq!(m.get("lnk.args_max_whitespace_run"), Some(60.0));
        assert!(m.get("lnk.args_whitespace_total").unwrap() >= 60.0);
    }

    #[test]
    fn argument_whitespace_metrics_quiet_on_normal_args() {
        let (_, m) = run(&lnk_with_arguments("/c notepad.exe"));
        assert!(m.get("lnk.args_max_whitespace_run").unwrap() < 50.0);
        assert_eq!(m.get("lnk.args_leading_tabs"), Some(0.0));
    }

    #[test]
    fn argument_whitespace_metrics_count_leading_tabs() {
        let args = format!("{}cmd.exe", "\t".repeat(55));
        let (_, m) = run(&lnk_with_arguments(&args));
        assert_eq!(m.get("lnk.args_leading_tabs"), Some(55.0));
        assert_eq!(m.get("lnk.args_max_whitespace_run"), Some(55.0));
    }
}
