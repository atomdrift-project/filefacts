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
            // Emit both a stable string label (forensic consumers) and
            // the raw IMAGE_DEBUG_TYPE_* numeric id so downstream
            // aggregators can reconstruct deduplicated/sorted type
            // vectors without a reverse lookup table.
            serde_json::json!({
                "type": debug_type_label(e.data_type),
                "type_id": e.data_type,
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

fn codeview_pdb70(cv: &CodeviewPDB70DebugInfo<'_>, debug: &DebugData<'_>, values: &mut Values) {
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
        put_i64(
            values,
            "pe.debug.pdb.timestamp",
            i64::from(idd.time_date_stamp),
        );
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
    use super::{debug_type_label, format_guid};

    #[test]
    fn guid_byteswaps_first_three_groups() {
        // Microsoft GUIDs use little-endian for the first three groups
        // when stored on disk. Bytes `01 02 03 04 05 06 07 08 09 0a …`
        // should display as `04030201-0605-0807-090a-0b0c0d0e0f10`.
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        assert_eq!(format_guid(&bytes), "04030201-0605-0807-090a-0b0c0d0e0f10");
    }

    #[test]
    fn guid_zero_bytes() {
        let bytes = [0u8; 16];
        assert_eq!(format_guid(&bytes), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn guid_canonical_microsoft_form() {
        // Real-world example: a Visual Studio toolchain GUID.
        // Source bytes in file order, output should match
        // `dumpbin /headers`'s representation.
        let bytes = [
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67,
            0x89, 0xab,
        ];
        assert_eq!(
            format_guid(&bytes),
            "12efcdab-5634-9a78-bcde-f1234567 89ab".replace(' ', "")
        );
    }

    #[test]
    fn debug_type_labels_cover_known_types() {
        assert_eq!(debug_type_label(0), "unknown");
        assert_eq!(debug_type_label(1), "coff");
        assert_eq!(debug_type_label(2), "codeview");
        assert_eq!(debug_type_label(13), "pogo");
        assert_eq!(debug_type_label(14), "iltcg");
        assert_eq!(debug_type_label(16), "repro");
        assert_eq!(debug_type_label(20), "ex_dllcharacteristics");
    }

    #[test]
    fn debug_type_label_unknown_value_falls_back_to_other() {
        // Microsoft never assigned this value; reserve room for future
        // expansion without crashing on real-world toolchain extensions.
        assert_eq!(debug_type_label(99), "other");
        assert_eq!(debug_type_label(u32::MAX), "other");
    }

    #[test]
    fn debug_type_label_misc_distinguished_from_other() {
        // `misc` is a real `IMAGE_DEBUG_TYPE_*` constant (4) — not a
        // catch-all. The fallback "other" should kick in only outside
        // the canonical 0..=16/20 range.
        assert_eq!(debug_type_label(4), "misc");
        assert_eq!(debug_type_label(17), "other");
    }

    /// Pin the PDB path, GUID, age, and the debug entry type vector
    /// for `test.exe`. Drift in the CodeView decoder, GUID byteswap,
    /// or entry walker will trip this test. Regenerate values via
    /// `cargo run --bin filefacts -- ../cleave/tests/fixtures/test.exe`.
    #[test]
    fn debug_directory_decodes_test_exe_to_known_values() {
        let bytes = std::fs::read("../cleave/tests/fixtures/test.exe")
            .expect("test.exe fixture is required");
        let mut v = crate::output::Values::new();
        let mut s = crate::Strings::default();
        let mut m = crate::output::Metrics::new();
        let mut sections = Vec::new();
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut errors = crate::output::Errors::new();
        crate::formats::pe::extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut functions,
            &mut errors,
        )
        .unwrap();

        // PDB metadata — the high-signal CodeView fields.
        assert_eq!(
            v.get("pe.debug.pdb.path").and_then(|x| x.as_str()),
            Some("C:\\Users\\forveined\\Documents\\nil\\x64\\Release\\Nil.pdb"),
        );
        assert_eq!(
            v.get("pe.debug.pdb.guid").and_then(|x| x.as_str()),
            Some("73c36a97-cc89-44b8-ba8e-75d173799591"),
        );
        assert_eq!(v.get("pe.debug.pdb.age").and_then(|x| x.as_u64()), Some(1));
        assert_eq!(
            v.get("pe.debug.pdb.timestamp").and_then(|x| x.as_i64()),
            Some(1_720_640_421),
        );

        // Entry array — type labels in directory order.
        let entries = v
            .get("pe.debug.entries")
            .and_then(|x| x.as_array())
            .expect("entries populated for a CodeView-bearing PE");
        let types: Vec<&str> = entries
            .iter()
            .filter_map(|e| e.get("type").and_then(|t| t.as_str()))
            .collect();
        assert_eq!(types, vec!["codeview", "vc_feature", "pogo", "iltcg"]);
    }
}
