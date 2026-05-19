//! PE debug-directory and CodeView (PDB) extractor.
//!
//! The debug directory carries entries identifying how the binary was
//! built. The CodeView entry (PDB 7.0 / RSDS form, the modern shape)
//! is the forensic prize: it carries the **filesystem path to the
//! `.pdb` file** the linker emitted, plus the GUID + age that pair
//! the binary with that PDB. The PDB path routinely leaks the
//! developer's username, project layout, or build-agent hostname —
//! one of the highest-signal attribution fields a PE carries.

use goblin::pe::debug::{
    CodeviewPDB70DebugInfo, DebugData, ImageDebugDirectory, IMAGE_DEBUG_TYPE_CODEVIEW,
};
use serde_json::Value as JsonValue;

use crate::formats::common::{hex_encode, put_i64, put_str, put_u64};
use crate::output::Values;

pub(super) fn extract(debug: &DebugData<'_>, values: &mut Values) {
    // Enumerate every directory entry so a consumer can see the full
    // set of debug-information shapes the binary carries.
    let entries: Vec<JsonValue> = debug
        .entries()
        .filter_map(Result::ok)
        .map(|e| {
            serde_json::json!({
                "type": debug_type_label(e.data_type),
                "timestamp_unix": e.time_date_stamp,
                "size_bytes": e.size_of_data,
            })
        })
        .collect();
    if !entries.is_empty() {
        values.insert("pe.debug.entries", JsonValue::Array(entries));
    }

    if let Some(ref cv) = debug.codeview_pdb70_debug_info {
        codeview_pdb70(cv, debug, values);
    }
    // PDB 2.0 (NB10) is the older format — rare today; report when seen
    // without the GUID since it uses a 32-bit signature instead.
    if let Some(ref cv) = debug.codeview_pdb20_debug_info {
        if let Ok(path) = std::str::from_utf8(cv.filename) {
            let path = path.trim_end_matches('\0');
            if !path.is_empty() {
                put_str(values, "pe.debug.pdb.path", path);
            }
        }
        put_u64(values, "pe.debug.pdb.age", u64::from(cv.age));
    }
}

fn codeview_pdb70(
    cv: &CodeviewPDB70DebugInfo<'_>,
    debug: &DebugData<'_>,
    values: &mut Values,
) {
    if let Ok(path) = std::str::from_utf8(cv.filename) {
        // The PDB filename is null-terminated inside the codeview blob;
        // trim the trailing NULs before exposing.
        let path = path.trim_end_matches('\0');
        if !path.is_empty() {
            put_str(values, "pe.debug.pdb.path", path);
        }
    }
    put_str(values, "pe.debug.pdb.guid", format_guid(&cv.signature));
    put_u64(values, "pe.debug.pdb.age", u64::from(cv.age));

    // Pair the GUID with the originating debug-entry timestamp so
    // consumers can build the same `<GUID><age>` PE-debug fingerprint
    // tools like symchk/symbol-server use to look the PDB up.
    if let Some(idd) = find_codeview_entry(debug) {
        put_i64(values, "pe.debug.pdb.timestamp", i64::from(idd.time_date_stamp));
    }
}

fn find_codeview_entry(debug: &DebugData<'_>) -> Option<ImageDebugDirectory> {
    debug
        .entries()
        .filter_map(Result::ok)
        .find(|e| e.data_type == IMAGE_DEBUG_TYPE_CODEVIEW)
}

/// Format the 16-byte CodeView signature as a Microsoft-style GUID:
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. The first three groups are
/// stored little-endian inside the file; we re-byteswap them so the
/// emitted string matches `dumpbin /headers`, symchk, and every other
/// Windows tool.
fn format_guid(b: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let data2 = u16::from_le_bytes([b[4], b[5]]);
    let data3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        data1,
        data2,
        data3,
        hex_encode(&b[8..10]),
        hex_encode(&b[10..16])
    )
}

fn debug_type_label(t: u32) -> &'static str {
    // IMAGE_DEBUG_TYPE_* — values 0..15 covered; rarer types fall
    // back to "other".
    match t {
        0 => "unknown",
        1 => "coff",
        2 => "codeview",
        3 => "fpo",
        4 => "misc",
        5 => "exception",
        6 => "fixup",
        7 => "omap_to_src",
        8 => "omap_from_src",
        9 => "borland",
        10 => "reserved10",
        11 => "clsid",
        12 => "vc_feature",
        13 => "pogo",
        14 => "iltcg",
        15 => "mpx",
        16 => "repro",
        20 => "ex_dllcharacteristics",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::format_guid;

    #[test]
    fn guid_byteswaps_first_three_groups() {
        // Microsoft GUIDs use little-endian for the first three groups
        // when stored on disk. Bytes `01 02 03 04 05 06 07 08 09 0a …`
        // should display as `04030201-0605-0807-090a-0b0c0d0e0f10`.
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        assert_eq!(
            format_guid(&bytes),
            "04030201-0605-0807-090a-0b0c0d0e0f10"
        );
    }
}
