use super::debug_type_label;
use crate::output::{Metrics, Values};

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
    let mut out = crate::formats::Sinks::default();
    crate::formats::pe::extract(&bytes, out.ctx()).unwrap();
    let v = out.values;

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
    super::put_pdb_path(&mut v, &mut Metrics::new(), path.as_bytes(), Some(0x1234));
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

/// The CodeView filename field runs past the path: the path ends at its
/// first NUL, and the junk a linker leaves after it is not part of it.
#[test]
fn pdb_path_ends_at_its_first_nul() {
    let mut v = Values::new();
    let mut m = Metrics::new();
    super::put_pdb_path(&mut v, &mut m, b"C:\\b\\x.pdb\0\x7fjunk\0\0", None);
    assert_eq!(
        v.get("pe.debug.pdb.path").and_then(|x| x.as_str()),
        Some("C:\\b\\x.pdb")
    );
    assert!(m.get("pe.debug.pdb.path_non_utf8").is_none());
    assert!(v.get("pe.debug.pdb.path_hex").is_none());
}

/// A path in the build host's ANSI code page — here a CP1251 Cyrillic
/// username — is kept, decoded lossily, flagged, and preserved byte for byte.
#[test]
fn ansi_code_page_pdb_path_is_kept_and_flagged() {
    let mut raw = b"C:\\Users\\".to_vec();
    raw.extend([0xC8, 0xE2, 0xE0, 0xED]); // "Иван" in CP1251
    raw.extend(b"\\x.pdb\0");
    let mut v = Values::new();
    let mut m = Metrics::new();
    super::put_pdb_path(&mut v, &mut m, &raw, None);
    assert_eq!(
        v.get("pe.debug.pdb.path").and_then(|x| x.as_str()),
        Some("C:\\Users\\\u{fffd}\u{fffd}\u{fffd}\u{fffd}\\x.pdb")
    );
    assert_eq!(
        v.get("pe.debug.pdb.basename").and_then(|x| x.as_str()),
        Some("x.pdb")
    );
    assert_eq!(m.get("pe.debug.pdb.path_non_utf8"), Some(1.0));
    assert_eq!(
        v.get("pe.debug.pdb.path_hex").and_then(|x| x.as_str()),
        Some(crate::formats::common::hex_encode(&raw[..raw.len() - 1]).as_str())
    );
}
