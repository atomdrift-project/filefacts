//! Load-time configuration: the load-config directory's mitigation fields
//! and the TLS callbacks that run before the entry point.

use goblin::pe::PE;
use goblin::pe::optional_header::MAGIC_64;
use serde_json::Value as JsonValue;

use super::layout::rva_to_file_offset;
use crate::formats::common::bytes_at::{u32_le, u64_le};
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
/// export carries the export's name.
pub(super) fn tls_callbacks(pe: &PE<'_>, values: &mut Values, metrics: &mut Metrics) {
    let Some(tls) = pe.tls_data.as_ref() else {
        return;
    };
    if tls.callbacks.is_empty() {
        return;
    }
    metrics.insert(metric!("pe.tls_callback_count"), tls.callbacks.len() as f64);

    let export_by_va: std::collections::HashMap<u64, &str> = pe
        .exports
        .iter()
        .filter_map(|e| {
            // `e.rva` is the export RVA; turn it into a VA by adding
            // the image base for symbol-attribution lookup against the
            // TLS callback table (which is stored as VAs).
            let va = pe
                .header
                .optional_header
                .as_ref()
                .map(|h| h.windows_fields.image_base.saturating_add(e.rva as u64))?;
            e.name.map(|n| (va, n))
        })
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
    let Some(embedded_size) = u32_le(bytes, start).map(|v| v as usize) else {
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

    let read_ptr = |off: usize| -> Option<u64> {
        if is_64 {
            u64_le(slice, off)
        } else {
            u32_le(slice, off).map(u64::from)
        }
    };

    // Field offsets per IMAGE_LOAD_CONFIG_DIRECTORY{32,64} from winnt.h.
    // Pre-cookie fields (TimeDateStamp, GlobalFlags, *Threshold, etc.)
    // are rarely forensically interesting and bloat the surface — we
    // skip straight to the security/mitigation-relevant block.
    let (
        sec_cookie,
        seh_table,
        seh_count,
        cf_check,
        cf_dispatch,
        cf_table,
        cf_count,
        guard_flags_off,
        taken_iat_table,
        taken_iat_count,
        longjmp_table,
        longjmp_count,
    ) = if is_64 {
        (
            0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0xA0, 0xA8, 0xB0, 0xB8,
        )
    } else {
        (
            0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x68, 0x6C, 0x70, 0x74,
        )
    };

    let put_ptr =
        |obj: &mut serde_json::Map<String, JsonValue>, key: &str, off: usize, allow_zero: bool| {
            if let Some(v) = read_ptr(off) {
                if v != 0 || allow_zero {
                    obj.insert(key.into(), JsonValue::Number(v.into()));
                }
            }
        };
    put_ptr(&mut obj, "security_cookie", sec_cookie, true);
    put_ptr(&mut obj, "se_handler_table", seh_table, false);
    put_ptr(&mut obj, "se_handler_count", seh_count, false);
    put_ptr(&mut obj, "guard_cf_check_function_pointer", cf_check, false);
    put_ptr(
        &mut obj,
        "guard_cf_dispatch_function_pointer",
        cf_dispatch,
        false,
    );
    put_ptr(&mut obj, "guard_cf_function_table", cf_table, false);
    put_ptr(&mut obj, "guard_cf_function_count", cf_count, false);
    put_ptr(
        &mut obj,
        "guard_address_taken_iat_entry_table",
        taken_iat_table,
        false,
    );
    put_ptr(
        &mut obj,
        "guard_address_taken_iat_entry_count",
        taken_iat_count,
        false,
    );
    put_ptr(
        &mut obj,
        "guard_long_jump_target_table",
        longjmp_table,
        false,
    );
    put_ptr(
        &mut obj,
        "guard_long_jump_target_count",
        longjmp_count,
        false,
    );

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
        let cf_on = flags & 0x0000_0100 != 0;
        metrics.insert(metric!("pe.has_cfg"), f64::from(u8::from(cf_on)));
    }
    if read_ptr(seh_table).unwrap_or(0) != 0 && read_ptr(seh_count).unwrap_or(0) != 0 {
        metrics.insert(metric!("pe.has_safe_seh"), 1.0);
    }

    values.insert_key(value_key!("pe.load_config"), JsonValue::Object(obj));
}

/// `IMAGE_GUARD_*` constants from `winnt.h`. Names follow the
/// Microsoft-published abbreviations (sans `IMAGE_GUARD_` prefix,
/// lowercased) so analysts can `exact:` against the flag directly.
fn guard_flag_names(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0000_0100 != 0 {
        out.push("cf_instrumented");
    }
    if flags & 0x0000_0200 != 0 {
        out.push("cfw_instrumented");
    }
    if flags & 0x0000_0400 != 0 {
        out.push("function_table_present");
    }
    if flags & 0x0000_0800 != 0 {
        out.push("security_cookie_unused");
    }
    if flags & 0x0000_1000 != 0 {
        out.push("protect_delayload_iat");
    }
    if flags & 0x0000_2000 != 0 {
        out.push("delayload_iat_in_its_own_section");
    }
    if flags & 0x0000_4000 != 0 {
        out.push("export_suppression_info_present");
    }
    if flags & 0x0000_8000 != 0 {
        out.push("enable_export_suppression");
    }
    if flags & 0x0001_0000 != 0 {
        out.push("longjump_table_present");
    }
    if flags & 0x0002_0000 != 0 {
        out.push("rf_instrumented");
    }
    if flags & 0x0004_0000 != 0 {
        out.push("rf_enable");
    }
    if flags & 0x0008_0000 != 0 {
        out.push("rf_strict");
    }
    if flags & 0x0010_0000 != 0 {
        out.push("retpoline_present");
    }
    if flags & 0x0040_0000 != 0 {
        out.push("eh_continuation_table_present");
    }
    if flags & 0x0080_0000 != 0 {
        out.push("xfg_enabled");
    }
    if flags & 0x0100_0000 != 0 {
        out.push("castguard_present");
    }
    if flags & 0x0200_0000 != 0 {
        out.push("memcpy_present");
    }
    out
}

#[cfg(test)]
mod tests;
