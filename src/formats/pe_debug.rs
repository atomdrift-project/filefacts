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
    CodeviewPDB70DebugInfo, DebugData, IMAGE_DEBUG_TYPE_CODEVIEW, ImageDebugDirectory,
};
use serde_json::Value as JsonValue;

use crate::Stage;
use crate::formats::common::{basename, format_guid, put_i64, put_str, put_u64, stem};
use crate::formats::goblin_safe;
use crate::output::{Errors, Values};
use crate::value_key;

/// Emit the PDB path and its derived basename + stem. The path itself
/// is the forensic anchor; basename and stem are the comparison
/// surfaces traits use to flag mismatches against the binary's own
/// filename (build-pipeline anomaly / commodity-malware repacks reuse
/// PDB stems across renamed binaries).
fn put_pdb_path(values: &mut Values, path: &str, path_offset: Option<u64>) {
    put_str(values, value_key!("pe.debug.pdb.path"), path);
    // Anchor the value at the filename string in the CodeView blob so a
    // `type: value` match on `pe.debug.pdb.path` renders in the hex view.
    if let Some(off) = path_offset {
        put_u64(values, "pe.debug.pdb.path_offset", off);
    }
    let name = basename(path);
    if !name.is_empty() {
        put_str(values, "pe.debug.pdb.basename", name);
        put_str(values, "pe.debug.pdb.stem", stem(name));
    }
}

pub(super) fn extract(debug: &DebugData<'_>, values: &mut Values, errors_out: &mut Errors) {
    // goblin reads each directory entry lazily; walk them once, guarded,
    // for every reader below.
    let directory = goblin_safe::drain_or_record(
        debug.entries().filter_map(Result::ok),
        errors_out,
        Stage::PeParse,
    );
    // Enumerate every directory entry so a consumer can see the full
    // set of debug-information shapes the binary carries.
    let entries: Vec<JsonValue> = directory
        .iter()
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
        codeview_pdb70(cv, &directory, values);
    }
    // PDB 2.0 (NB10) is the older format — rare today; report when seen
    // without the GUID since it uses a 32-bit signature instead.
    if let Some(ref cv) = debug.codeview_pdb20_debug_info {
        if let Ok(path) = std::str::from_utf8(cv.filename) {
            let path = path.trim_end_matches('\0');
            if !path.is_empty() {
                // NB10 header: CvSignature + Offset + Signature + Age = 16 bytes
                // before the filename.
                let path_offset = find_codeview_entry(&directory)
                    .map(|idd| u64::from(idd.pointer_to_raw_data) + 16);
                put_pdb_path(values, path, path_offset);
            }
        }
        put_u64(values, "pe.debug.pdb.age", u64::from(cv.age));
    }
}

fn codeview_pdb70(
    cv: &CodeviewPDB70DebugInfo<'_>,
    directory: &[ImageDebugDirectory],
    values: &mut Values,
) {
    if let Ok(path) = std::str::from_utf8(cv.filename) {
        // The PDB filename is null-terminated inside the codeview blob;
        // trim the trailing NULs before exposing.
        let path = path.trim_end_matches('\0');
        if !path.is_empty() {
            // RSDS header: CvSignature(4) + Signature/GUID(16) + Age(4) = 24
            // bytes before the filename string.
            let path_offset =
                find_codeview_entry(directory).map(|idd| u64::from(idd.pointer_to_raw_data) + 24);
            put_pdb_path(values, path, path_offset);
        }
    }
    put_str(values, "pe.debug.pdb.guid", format_guid(&cv.signature));
    put_u64(values, "pe.debug.pdb.age", u64::from(cv.age));

    // Pair the GUID with the originating debug-entry timestamp so
    // consumers can build the same `<GUID><age>` PE-debug fingerprint
    // tools like symchk/symbol-server use to look the PDB up.
    if let Some(idd) = find_codeview_entry(directory) {
        put_i64(
            values,
            "pe.debug.pdb.timestamp",
            i64::from(idd.time_date_stamp),
        );
    }
}

fn find_codeview_entry(directory: &[ImageDebugDirectory]) -> Option<&ImageDebugDirectory> {
    directory
        .iter()
        .find(|e| e.data_type == IMAGE_DEBUG_TYPE_CODEVIEW)
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
    use super::debug_type_label;
    use crate::output::Values;

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
    /// `cargo run --bin filefacts -- tests/fixtures/test.exe`.
    #[test]
    fn debug_directory_decodes_test_exe_to_known_values() {
        let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture is required");
        let mut v = crate::output::Values::new();
        let mut s = crate::output::Strings::default();
        let mut m = crate::output::Metrics::new();
        let mut sections = Vec::new();
        let mut symbols = crate::Symbols::new();
        let mut errors = crate::output::Errors::new();
        crate::formats::pe::extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut symbols,
            &mut errors,
        )
        .unwrap();

        // PDB metadata — the high-signal CodeView fields.
        assert_eq!(
            v.get("pe.debug.pdb.path").and_then(|x| x.as_str()),
            Some("C:\\Users\\forveined\\Documents\\nil\\x64\\Release\\Nil.pdb"),
        );
        // Derived basename / stem — comparison surfaces for traits that
        // flag PDB / binary filename mismatches.
        assert_eq!(
            v.get("pe.debug.pdb.basename").and_then(|x| x.as_str()),
            Some("Nil.pdb"),
        );
        assert_eq!(
            v.get("pe.debug.pdb.stem").and_then(|x| x.as_str()),
            Some("Nil"),
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

    /// Helper to drive `put_pdb_path` without standing up a full debug
    /// blob; returns the populated path / basename / stem triple as
    /// `(path, basename, stem)`.
    fn pdb_facts(path: &str) -> (Option<String>, Option<String>, Option<String>) {
        let mut v = Values::new();
        super::put_pdb_path(&mut v, path, Some(0x1234));
        (
            v.get("pe.debug.pdb.path")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            v.get("pe.debug.pdb.basename")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            v.get("pe.debug.pdb.stem")
                .and_then(|x| x.as_str())
                .map(str::to_string),
        )
    }

    #[test]
    fn pdb_facts_windows_absolute_path() {
        let (p, b, s) = pdb_facts("C:\\Users\\bob\\stealer.pdb");
        assert_eq!(p.as_deref(), Some("C:\\Users\\bob\\stealer.pdb"));
        assert_eq!(b.as_deref(), Some("stealer.pdb"));
        assert_eq!(s.as_deref(), Some("stealer"));
    }

    #[test]
    fn pdb_facts_unix_path() {
        let (_p, b, s) = pdb_facts("/build/agent/out/foo.pdb");
        assert_eq!(b.as_deref(), Some("foo.pdb"));
        assert_eq!(s.as_deref(), Some("foo"));
    }

    #[test]
    fn pdb_facts_no_directory() {
        let (_p, b, s) = pdb_facts("loader.pdb");
        assert_eq!(b.as_deref(), Some("loader.pdb"));
        assert_eq!(s.as_deref(), Some("loader"));
    }

    #[test]
    fn pdb_facts_mixed_slashes() {
        // PE PDBs are usually pure backslash, but CI builds can leak
        // forward-slash paths on cross-compiles. Either separator must
        // peel cleanly.
        let (_p, b, s) = pdb_facts("C:/work\\release/mixed.pdb");
        assert_eq!(b.as_deref(), Some("mixed.pdb"));
        assert_eq!(s.as_deref(), Some("mixed"));
    }

    #[test]
    fn pdb_facts_path_with_no_extension() {
        // Unusual but valid: PDB name with no `.pdb` suffix. Stem
        // collapses to basename.
        let (_p, b, s) = pdb_facts("C:\\proj\\OUTPUT");
        assert_eq!(b.as_deref(), Some("OUTPUT"));
        assert_eq!(s.as_deref(), Some("OUTPUT"));
    }
}
