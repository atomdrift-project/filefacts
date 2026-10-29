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
use crate::formats::common::{basename, format_guid, hex_encode, put_i64, put_str, put_u64, stem};
use crate::formats::goblin_safe;
use crate::metric;
use crate::output::{Errors, Metrics, Values};
use crate::value_key;

/// Emit the PDB path and its derived basename + stem. The path itself
/// is the forensic anchor; basename and stem are the comparison
/// surfaces traits use to flag mismatches against the binary's own
/// filename (build-pipeline anomaly / commodity-malware repacks reuse
/// PDB stems across renamed binaries).
///
/// `raw` is the CodeView filename field: the path runs to its first NUL, and
/// whatever the linker left after that is not part of it. Linkers write the
/// path in the build host's ANSI code page, so a username or project folder
/// in Cyrillic or CJK — the most telling attribution a PDB path carries — is
/// not UTF-8. It is decoded lossily rather than dropped, flagged with
/// `pe.debug.pdb.path_non_utf8`, and kept byte for byte in
/// `pe.debug.pdb.path_hex` so its code page can be recovered.
fn put_pdb_path(values: &mut Values, metrics: &mut Metrics, raw: &[u8], path_offset: Option<u64>) {
    let raw = raw.split(|&b| b == 0).next().unwrap_or_default();
    if raw.is_empty() {
        return;
    }
    let path = String::from_utf8_lossy(raw);
    if let std::borrow::Cow::Owned(_) = path {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "debug-directory",
            len = raw.len(),
            "PDB path is not UTF-8; decoded lossily"
        );
        metrics.insert(metric!("pe.debug.pdb.path_non_utf8"), 1.0);
        put_str(values, value_key!("pe.debug.pdb.path_hex"), hex_encode(raw));
    }
    put_str(values, value_key!("pe.debug.pdb.path"), &*path);
    // Anchor the value at the filename string in the CodeView blob so a
    // `type: value` match on `pe.debug.pdb.path` renders in the hex view.
    if let Some(off) = path_offset {
        put_u64(values, value_key!("pe.debug.pdb.path_offset"), off);
    }
    let name = basename(&path);
    if !name.is_empty() {
        put_str(values, value_key!("pe.debug.pdb.basename"), name);
        put_str(values, value_key!("pe.debug.pdb.stem"), stem(name));
    }
}

pub(super) fn extract(
    debug: &DebugData<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    errors_out: &mut Errors,
) {
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
        values.insert_key(value_key!("pe.debug.entries"), JsonValue::Array(entries));
    }

    if let Some(ref cv) = debug.codeview_pdb70_debug_info {
        codeview_pdb70(cv, &directory, values, metrics);
    }
    // PDB 2.0 (NB10) is the older format — rare today; report when seen
    // without the GUID since it uses a 32-bit signature instead.
    if let Some(ref cv) = debug.codeview_pdb20_debug_info {
        // NB10 header: CvSignature + Offset + Signature + Age = 16 bytes
        // before the filename.
        let path_offset =
            find_codeview_entry(&directory).map(|idd| u64::from(idd.pointer_to_raw_data) + 16);
        put_pdb_path(values, metrics, cv.filename, path_offset);
        put_u64(values, value_key!("pe.debug.pdb.age"), u64::from(cv.age));
    }
}

fn codeview_pdb70(
    cv: &CodeviewPDB70DebugInfo<'_>,
    directory: &[ImageDebugDirectory],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    // RSDS header: CvSignature(4) + Signature/GUID(16) + Age(4) = 24 bytes
    // before the filename string.
    let path_offset =
        find_codeview_entry(directory).map(|idd| u64::from(idd.pointer_to_raw_data) + 24);
    put_pdb_path(values, metrics, cv.filename, path_offset);
    put_str(
        values,
        value_key!("pe.debug.pdb.guid"),
        format_guid(&cv.signature),
    );
    put_u64(values, value_key!("pe.debug.pdb.age"), u64::from(cv.age));

    // Pair the GUID with the originating debug-entry timestamp so
    // consumers can build the same `<GUID><age>` PE-debug fingerprint
    // tools like symchk/symbol-server use to look the PDB up.
    if let Some(idd) = find_codeview_entry(directory) {
        put_i64(
            values,
            value_key!("pe.debug.pdb.timestamp"),
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
mod tests;
