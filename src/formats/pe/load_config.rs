//! Load-time configuration: the load-config directory's mitigation fields
//! and the TLS callbacks that run before the entry point.

use goblin::pe::PE;
use goblin::pe::optional_header::MAGIC_64;
use serde_json::Value as JsonValue;

use super::layout::rva_to_file_offset;
use crate::bytes::{u32_le, u64_le};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Most TLS callbacks [`tls_callbacks`] records. goblin reads the callback
/// array to its first null entry, so a forged array runs to the end of the
/// file: a quarter of its size in callbacks, each a JSON object some fifty
/// times larger than the four bytes it came from. Real images register one or
/// two. `pe.tls_callback_count` stays exact.
const MAX_TLS_CALLBACK_RECORDS: usize = 1024;

/// The TLS directory's `AddressOfCallBacks` table as callback VAs. TLS
/// callbacks are the Windows analogue of ELF `.init_array`: they run before
/// the entry point, which makes them a classic anti-analysis hook (malware
/// uses them to defeat breakpoint-on-entry debuggers). A callback at an
/// export of binform's `layout` carries the export's name.
pub(super) fn tls_callbacks(
    pe: &PE<'_>,
    layout: Option<&binform::Binary<'_>>,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Some(tls) = pe.tls_data.as_ref() else {
        return;
    };
    if tls.callbacks.is_empty() {
        return;
    }
    metrics.insert(metric!("pe.tls_callback_count"), tls.callbacks.len() as f64);

    // binform's export addresses are VAs in the preferred image, as the
    // callback table's are.
    let export_by_va: std::collections::HashMap<u64, &str> = layout
        .iter()
        .flat_map(|layout| layout.exports())
        .filter(|export| export.forward.is_none())
        .filter_map(|export| Some((export.addr?, export.name.as_str())))
        .collect();

    let entries: Vec<JsonValue> = tls
        .callbacks
        .iter()
        .take(MAX_TLS_CALLBACK_RECORDS)
        .map(|addr| {
            let mut node = serde_json::Map::new();
            node.insert("addr".into(), JsonValue::String(format!("0x{addr:x}")));
            if let Some(name) = export_by_va.get(addr) {
                node.insert("symbol".into(), JsonValue::String((*name).to_string()));
            }
            JsonValue::Object(node)
        })
        .collect();
    values.insert_key(value_key!("pe.tls_callbacks"), JsonValue::Array(entries));
}

/// `SEHandlerTable` and `SEHandlerCount`, as `(PE32, PE32+)` offsets into
/// `IMAGE_LOAD_CONFIG_DIRECTORY{32,64}` (winnt.h).
const SE_HANDLER_TABLE: (usize, usize) = (0x40, 0x60);
const SE_HANDLER_COUNT: (usize, usize) = (0x44, 0x68);

/// The pointer-sized load-config fields `pe.load_config` reports, with their
/// `(PE32, PE32+)` offsets. The fields before the cookie (TimeDateStamp,
/// GlobalFlags, the thresholds) are rarely forensically interesting and are
/// skipped.
const POINTER_FIELDS: [(&str, (usize, usize)); 11] = [
    ("security_cookie", (0x3C, 0x58)),
    ("se_handler_table", SE_HANDLER_TABLE),
    ("se_handler_count", SE_HANDLER_COUNT),
    ("guard_cf_check_function_pointer", (0x48, 0x70)),
    ("guard_cf_dispatch_function_pointer", (0x4C, 0x78)),
    ("guard_cf_function_table", (0x50, 0x80)),
    ("guard_cf_function_count", (0x54, 0x88)),
    ("guard_address_taken_iat_entry_table", (0x68, 0xA0)),
    ("guard_address_taken_iat_entry_count", (0x6C, 0xA8)),
    ("guard_long_jump_target_table", (0x70, 0xB0)),
    ("guard_long_jump_target_count", (0x74, 0xB8)),
];

/// Parse the IMAGE_LOAD_CONFIG_DIRECTORY structure using the `Size`
/// field embedded at offset 0 — Microsoft's spec says this is the
/// authoritative size, not the data-directory entry's `Size` field.
/// goblin's parser slices to `dd.size` and silently drops every field
/// past it, which on modern binaries truncates the parse before
/// `GuardFlags` (the CFG / mitigation status indicator).
///
/// Surfaces the security-cookie, the SafeSEH table, the full CFG /
/// Return Flow Guard / XFG pointer set, and a decoded
/// `IMAGE_GUARD_*` flag-name array. Field absence (`None`) is
/// preserved by omitting the key, so trait authors can distinguish
/// "field present and zero" (a cleared-cookie tampering tell) from
/// "field not in this binary's load_config".
pub(super) fn load_config(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_load_config_table() else {
        return;
    };
    if dd.virtual_address == 0 {
        return;
    }
    let Some(start) = rva_to_file_offset(pe, dd.virtual_address) else {
        return;
    };
    let Some(embedded_size) = u32_le(bytes, start).map(crate::bytes::sat_usize) else {
        return;
    };
    if embedded_size < 4 {
        return;
    }
    let end = start.saturating_add(embedded_size).min(bytes.len());
    let Some(slice) = bytes.get(start..end) else {
        return;
    };
    let is_64 = opt.standard_fields.magic == MAGIC_64;
    let mut obj = serde_json::Map::new();
    obj.insert("size".into(), JsonValue::Number(embedded_size.into()));

    let read_ptr = |(off32, off64): (usize, usize)| -> Option<u64> {
        if is_64 {
            u64_le(slice, off64)
        } else {
            u32_le(slice, off32).map(u64::from)
        }
    };
    for (key, offsets) in POINTER_FIELDS {
        // A zero cookie is a cleared-cookie tampering tell; any other zero
        // pointer or count is an unused feature.
        if let Some(v) = read_ptr(offsets)
            && (v != 0 || key == "security_cookie")
        {
            obj.insert(key.into(), JsonValue::Number(v.into()));
        }
    }

    // `GuardFlags` is a u32 in both layouts.
    let guard_flags_off = if is_64 { 0x90 } else { 0x58 };
    if let Some(flags) = u32_le(slice, guard_flags_off) {
        // Both forms — raw u32 for round-trip and a string-flag array
        // for human-readable trait matches against `cf_instrumented`
        // / `cfw_instrumented`. Zero is still emitted; "no flags set"
        // is itself a meaningful signal ("CFG was not wired up").
        obj.insert("guard_flags_raw".into(), JsonValue::Number(flags.into()));
        let names = guard_flag_names(flags);
        if !names.is_empty() {
            obj.insert(
                "guard_flags".into(),
                JsonValue::Array(
                    names
                        .into_iter()
                        .map(|s| JsonValue::String(s.to_string()))
                        .collect(),
                ),
            );
        }
        // Cross-format mitigation summary metrics — boolean-valued for
        // easy trait composition.
        let cf_on = flags & GUARD_CF_INSTRUMENTED != 0;
        metrics.insert(metric!("pe.has_cfg"), f64::from(u8::from(cf_on)));
    }
    if read_ptr(SE_HANDLER_TABLE).unwrap_or(0) != 0 && read_ptr(SE_HANDLER_COUNT).unwrap_or(0) != 0
    {
        metrics.insert(metric!("pe.has_safe_seh"), 1.0);
    }

    values.insert_key(value_key!("pe.load_config"), JsonValue::Object(obj));
}

/// `IMAGE_GUARD_CF_INSTRUMENTED`: the image was built with Control Flow
/// Guard.
const GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;

/// `IMAGE_GUARD_*` constants from `winnt.h`. Names follow the
/// Microsoft-published abbreviations (sans `IMAGE_GUARD_` prefix,
/// lowercased) so analysts can `exact:` against the flag directly.
fn guard_flag_names(flags: u32) -> Vec<&'static str> {
    [
        (GUARD_CF_INSTRUMENTED, "cf_instrumented"),
        (0x0000_0200, "cfw_instrumented"),
        (0x0000_0400, "function_table_present"),
        (0x0000_0800, "security_cookie_unused"),
        (0x0000_1000, "protect_delayload_iat"),
        (0x0000_2000, "delayload_iat_in_its_own_section"),
        (0x0000_4000, "export_suppression_info_present"),
        (0x0000_8000, "enable_export_suppression"),
        (0x0001_0000, "longjump_table_present"),
        (0x0002_0000, "rf_instrumented"),
        (0x0004_0000, "rf_enable"),
        (0x0008_0000, "rf_strict"),
        (0x0010_0000, "retpoline_present"),
        (0x0040_0000, "eh_continuation_table_present"),
        (0x0080_0000, "xfg_enabled"),
        (0x0100_0000, "castguard_present"),
        (0x0200_0000, "memcpy_present"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (flags & bit != 0).then_some(name))
    .collect()
}

#[cfg(test)]
mod tests;
