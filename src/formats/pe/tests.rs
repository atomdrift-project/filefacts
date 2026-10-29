use super::*;
use crate::output::{Metrics, Strings, Values};
use serde_json::Value as JsonValue;

#[test]
fn declares_export_directory_reads_the_export_slot() {
    use goblin::pe::data_directories::{DataDirectories, DataDirectory};
    use goblin::pe::optional_header::{OptionalHeader, StandardFields, WindowsFields};
    let header = |slot: Option<(u32, u32)>| {
        let mut dirs = DataDirectories::default();
        dirs.data_directories[0] = slot.map(|(virtual_address, size)| {
            let dir = DataDirectory {
                virtual_address,
                size,
            };
            (0, dir)
        });
        OptionalHeader {
            standard_fields: StandardFields::default(),
            windows_fields: WindowsFields::default(),
            data_directories: dirs,
        }
    };
    assert!(!declares_export_directory(None));
    assert!(!declares_export_directory(Some(&header(None))));
    assert!(!declares_export_directory(Some(&header(Some((0, 0))))));
    assert!(declares_export_directory(Some(&header(Some((
        0x2000, 0x40
    ))))));
}

fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
    let mut out = crate::formats::Sinks::default();
    let _ = extract(bytes, out.ctx());
    let crate::formats::Sinks {
        values: v,
        strings: s,
        metrics: m,
        ..
    } = out;
    (v, s, m)
}

pub(super) fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

#[test]
fn certificate_table_at_offset_zero_past_eof_does_not_panic() {
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let optional_offset = pe_offset + 24;
    let directory_offset = match u16::from_le_bytes(
        bytes[optional_offset..optional_offset + 2]
            .try_into()
            .unwrap(),
    ) {
        0x10b => optional_offset + 96,
        0x20b => optional_offset + 112,
        magic => panic!("unexpected fixture optional-header magic {magic:#x}"),
    };
    // Certificate table (directory 4): file offset 0, size past EOF.
    let cert_offset = directory_offset + 4 * 8;
    bytes[cert_offset..cert_offset + 4].fill(0);
    bytes[cert_offset + 4..cert_offset + 8].copy_from_slice(&0x7fff_ffff_u32.to_le_bytes());

    let (values, _, metrics) = run(&bytes);
    assert_eq!(
        metrics.get("pe.cert_table_size"),
        Some(f64::from(0x7fff_ffff_u32))
    );
    assert!(values.get("pe.signatures").is_none());
}

#[test]
fn malformed_declared_directory_is_preserved_as_a_fact() {
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let optional_offset = pe_offset + 24;
    let directory_offset = match u16::from_le_bytes(
        bytes[optional_offset..optional_offset + 2]
            .try_into()
            .unwrap(),
    ) {
        0x10b => optional_offset + 96,
        0x20b => optional_offset + 112,
        magic => panic!("unexpected fixture optional-header magic {magic:#x}"),
    };
    // Import directory: zero RVA with non-zero declared size. This must
    // not disappear just because the normal import walker cannot use it.
    let import_offset = directory_offset + 8;
    bytes[import_offset..import_offset + 4].fill(0);
    bytes[import_offset + 4..import_offset + 8].copy_from_slice(&0x40_u32.to_le_bytes());

    let (values, _, metrics) = run(&bytes);
    let anomalies = values
        .get("pe.data_directory_anomalies")
        .and_then(serde_json::Value::as_array)
        .expect("malformed directory must be preserved");
    assert!(anomalies.iter().any(|entry| {
        entry.get("name").and_then(serde_json::Value::as_str) == Some("import")
            && entry.get("kind").and_then(serde_json::Value::as_str)
                == Some("zero_rva_nonzero_size")
    }));
    assert_eq!(
        metrics.get("pe.data_directory_zero_rva_nonzero_size_count"),
        Some(1.0)
    );
}

#[test]
fn empty_input_doesnt_crash() {
    let (_, _, _) = run(&[]);
}

#[test]
fn non_pe_input_is_rejected_silently() {
    let (v, _, m) = run(b"\x00\x00\x00 not even MZ");
    assert!(v.is_empty() || v.get("pe.coff").is_none());
    assert!(m.get("binary.is_pie").is_none());
}

#[test]
fn truncated_pe_header_doesnt_crash() {
    let mut bytes = vec![0u8; 64];
    bytes[..2].copy_from_slice(b"MZ");
    let (_, _, _) = run(&bytes);
}

#[test]
fn end_to_end_parses_real_pe_fixture() {
    let bytes = read_fixture("test.exe");
    let (v, _, m) = run(&bytes);
    // COFF and optional-header fields land flat under `pe.*`.
    assert!(v.get("pe.coff").is_some() || v.get("pe.machine").is_some());
    // PIE flag derived from DLL_CHARACTERISTICS_DYNAMIC_BASE.
    assert!(m.get("binary.is_pie").is_some());
}

// Managed CLR extraction, end to end, against tiny C# libraries built from
// the same source with and without `csc /keyfile` (see tests/fixtures).
#[test]
fn clr_unsigned_fixture_reports_no_strong_name() {
    let (v, _, m) = run(&read_fixture("managed-unsigned.dll"));
    // STRONGNAMESIGNED bit clear -> metric 0 (the forgery-relevant state).
    assert_eq!(m.get("pe.clr.strong_name_signed"), Some(0.0));
    assert_eq!(m.get("pe.clr.is_il_only"), Some(1.0));
    assert_eq!(
        v.get("pe.clr.metadata_version").and_then(JsonValue::as_str),
        Some("v4.0.30319")
    );
    // MVID is a well-formed lowercase 8-4-4-4-12 GUID.
    let mvid = v
        .get("pe.clr.mvid")
        .and_then(JsonValue::as_str)
        .expect("mvid present");
    assert_eq!(mvid.len(), 36);
    assert_eq!(mvid.matches('-').count(), 4);
    assert!(mvid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    // Standard heaps, in order; a `#-`/`#Schema` stream would signal IL patching.
    let streams: Vec<&str> = v
        .get("pe.clr.streams")
        .and_then(JsonValue::as_array)
        .expect("streams present")
        .iter()
        .filter_map(JsonValue::as_str)
        .collect();
    assert_eq!(streams, ["#~", "#Strings", "#US", "#GUID", "#Blob"]);
}

#[test]
fn clr_signed_fixture_reports_strong_name() {
    // Same source, strong-name signed: the STRONGNAMESIGNED bit flips the metric.
    let (_, _, m) = run(&read_fixture("managed-signed.dll"));
    assert_eq!(m.get("pe.clr.strong_name_signed"), Some(1.0));
}

/// A normal local-export fixture has no forwarded exports —
/// every `Export.forward_to` is `None` and the
/// `pe.forwarded_export_count` metric is absent.
#[test]
fn normal_exports_emit_no_forward_to() {
    let bytes = read_fixture("test.exe");
    let mut out = crate::formats::Sinks::default();
    extract(&bytes, out.ctx()).unwrap();
    let crate::formats::Sinks {
        metrics: m,
        symbols,
        ..
    } = out;
    for sym in symbols.iter_kind(crate::SymbolKind::Export) {
        if let crate::Symbol::Export { forward_to, .. } = sym {
            assert!(
                forward_to.is_none(),
                "test.exe shouldn't have forwarded exports; got {forward_to:?}",
            );
        }
    }
    assert!(m.get("pe.forwarded_export_count").is_none());
}

/// Verifies the unified Symbols view is populated for PE imports and
/// that library names are normalised (lowercase, no `.dll`).
#[test]
fn typed_imports_and_exports_populated() {
    let bytes = read_fixture("test.exe");
    let mut out = crate::formats::Sinks::default();
    extract(&bytes, out.ctx()).unwrap();
    let symbols = out.symbols;
    let imports: Vec<&crate::Symbol> = symbols.iter_kind(crate::SymbolKind::Import).collect();
    assert!(!imports.is_empty(), "expected at least one PE import");
    for sym in imports {
        let crate::Symbol::Import { library, .. } = sym else {
            unreachable!("iter_kind(Import) yields only Import variants");
        };
        let lib = library.as_deref().expect("PE imports carry library");
        assert_eq!(lib, &lib.to_ascii_lowercase());
        assert!(
            !lib.ends_with(".dll") && !lib.ends_with(".ocx") && !lib.ends_with(".sys"),
            "library stem should drop extension: {lib}",
        );
    }
}

/// A clean MSVC-produced PE keeps the canonical "This program
/// cannot be run in DOS mode" banner and a non-zero stub. The
/// emitter must NOT raise either anomaly flag.
#[test]
fn dos_stub_anomalies_silent_on_clean_pe() {
    let bytes = read_fixture("test.exe");
    let (_, _, m) = run(&bytes);
    assert!(
        m.get("pe.dos_stub_modified").is_none(),
        "clean PE should not flag dos_stub_modified",
    );
    assert!(
        m.get("pe.dos_stub_zeroed").is_none(),
        "clean PE should not flag dos_stub_zeroed",
    );
}

/// Rewrite the DOS stub region of a real PE with zeros and verify
/// the emitter raises both anomaly bits. The PE remains parseable
/// because we only touch bytes 0x40..pe_offset.
#[test]
fn dos_stub_anomalies_fires_on_zeroed_stub() {
    let mut bytes = read_fixture("test.exe");
    // e_lfanew lives at 0x3C..0x40 as a little-endian u32 — locates
    // the PE header start, which is the upper bound of the stub
    // region the anomaly detector inspects.
    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    assert!(pe_offset > 0x40, "fixture should have a stub region");
    for b in bytes[0x40..pe_offset].iter_mut() {
        *b = 0;
    }
    let (_, _, m) = run(&bytes);
    assert!(
        m.get("pe.dos_stub_modified").is_some(),
        "zeroed stub should flag dos_stub_modified",
    );
    assert!(
        m.get("pe.dos_stub_zeroed").is_some(),
        "zeroed stub should flag dos_stub_zeroed",
    );
}

/// Overwrite the canonical banner with garbage but keep the stub
/// non-zero — `dos_stub_modified` should fire, `dos_stub_zeroed`
/// must not.
#[test]
fn dos_stub_modified_without_zeroed() {
    let mut bytes = read_fixture("test.exe");
    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    for b in bytes[0x40..pe_offset].iter_mut() {
        *b = 0xab;
    }
    let (_, _, m) = run(&bytes);
    assert!(
        m.get("pe.dos_stub_modified").is_some(),
        "missing canonical banner should flag dos_stub_modified",
    );
    assert!(
        m.get("pe.dos_stub_zeroed").is_none(),
        "non-zero garbage stub must NOT be flagged as zeroed",
    );
}

/// `pe.rich.entries` is the flat-path under which the Rich Header
/// emitter writes the decoded CompID tuples. The fixture is an
/// MSVC-linked PE so it carries a Rich header; the array must be
/// present and non-empty.
#[test]
fn rich_entries_populated_on_msvc_pe() {
    let bytes = read_fixture("test.exe");
    let (v, _, _) = run(&bytes);
    let entries = v
        .get("pe.rich.entries")
        .and_then(|x| x.as_array())
        .expect("MSVC-built fixture should carry pe.rich.entries");
    assert!(!entries.is_empty(), "rich entries should be non-empty");
    // `pe.rich.hash` and `pe.rich.key` must also be present whenever
    // entries are emitted — they're written in the same code path.
    assert!(v.get("pe.rich.hash").is_some());
    assert!(v.get("pe.rich.key").is_some());
}

/// The PE entry-section parity fields (mirroring ELF/Mach-O) emit on a
/// real binary and stay clean on a benign one: the entry resolves to a
/// toolchain code section, so no nonstandard-entry-section anomaly.
#[test]
fn pe_entry_parity_metrics_clean_on_fixture() {
    let bytes = read_fixture("test.exe");
    let (v, _, m) = run(&bytes);
    assert!(v.get("pe.entry_section").is_some());
    assert!(m.get("pe.entry_in_nonstandard_section").is_none());
}

/// `test.exe` with a real Authenticode signature — Tencent's, so its image
/// digest is not this file's — in its certificate table.
fn with_foreign_signature() -> Vec<u8> {
    const SIGNED_DATA: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode-digicert-tencent.p7b"
    ));
    let blob = crate::formats::cms::der_element(SIGNED_DATA).unwrap();
    let mut bytes = read_fixture("test.exe");
    let table = bytes.len().next_multiple_of(8);
    bytes.resize(table, 0);
    bytes.extend(u32::try_from(blob.len() + 8).unwrap().to_le_bytes());
    bytes.extend(0x0200_u16.to_le_bytes());
    bytes.extend(0x0002_u16.to_le_bytes());
    bytes.extend(blob);
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let size = u32::try_from(bytes.len() - table).unwrap();
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let magic = u16::from_le_bytes(bytes[pe_offset + 24..pe_offset + 26].try_into().unwrap());
    let slot =
        layout::data_directory_offset(pe_offset, magic, layout::CERTIFICATE_DIRECTORY).unwrap();
    bytes[slot..slot + 4].copy_from_slice(&u32::try_from(table).unwrap().to_le_bytes());
    bytes[slot + 4..slot + 8].copy_from_slice(&size.to_le_bytes());
    bytes
}

/// A fully parsed image is hashed, so a lifted signature is caught.
#[test]
fn foreign_signature_on_a_parsed_image_is_tampered() {
    let (v, _, _) = run(&with_foreign_signature());
    assert_eq!(v.get("pe.signatures[0].verified"), Some(&true.into()));
    assert_eq!(
        v.get("pe.signatures[0].digest_matches"),
        Some(&false.into())
    );
    assert_eq!(
        v.get("pe.signature_integrity").and_then(JsonValue::as_str),
        Some("tampered")
    );
}

/// The header-only fallback has no section table to hash the image with.
/// The same lifted signature still verifies as CMS, but nothing binds it to
/// this file, so it must read as unverifiable rather than intact.
#[test]
fn header_only_fallback_judges_signatures_unverifiable() {
    let mut bytes = with_foreign_signature();
    // A section count past what validation lets goblin walk forces the
    // header-only path.
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&500_u16.to_le_bytes());
    let (v, _, m) = run(&bytes);
    assert_eq!(m.get("pe.partial_parse"), Some(1.0));
    assert_eq!(v.get("pe.signatures[0].verified"), Some(&true.into()));
    assert!(v.get("pe.signatures[0].digest_matches").is_none());
    assert!(v.get("pe.image_hash").is_none());
    assert_eq!(
        v.get("pe.signature_integrity").and_then(JsonValue::as_str),
        Some("unverifiable")
    );
}
