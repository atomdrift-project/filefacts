use super::*;
use crate::output::Strings;

#[test]
fn rt_name_known() {
    assert_eq!(rt_name(16), "RT_VERSION");
    assert_eq!(rt_name(24), "RT_MANIFEST");
    assert_eq!(rt_name(3), "RT_ICON");
    assert_eq!(rt_name(99), "RT_UNKNOWN");
}

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

#[test]
fn parse_clr_streams_reads_standard_heaps() {
    // Minimal metadata root: BSJB, version "v4.0" (len 4), flags=0,
    // streams=2, then #GUID (offset 0x20, size 16) and #Blob headers.
    let mut md = Vec::new();
    md.extend_from_slice(b"BSJB");
    md.extend_from_slice(&1u16.to_le_bytes()); // major
    md.extend_from_slice(&1u16.to_le_bytes()); // minor
    md.extend_from_slice(&0u32.to_le_bytes()); // reserved
    md.extend_from_slice(&4u32.to_le_bytes()); // version_len
    md.extend_from_slice(b"v4.0"); // version (already 4-aligned)
    md.extend_from_slice(&0u16.to_le_bytes()); // flags
    md.extend_from_slice(&2u16.to_le_bytes()); // streams
    md.extend_from_slice(&0x20u32.to_le_bytes()); // #GUID offset
    md.extend_from_slice(&16u32.to_le_bytes()); // #GUID size
    md.extend_from_slice(b"#GUID\0\0\0"); // name, padded to 8
    md.extend_from_slice(&0x40u32.to_le_bytes()); // #Blob offset
    md.extend_from_slice(&8u32.to_le_bytes()); // #Blob size
    md.extend_from_slice(b"#Blob\0\0\0"); // name, padded to 8
    let (names, guid) = parse_clr_streams(&md).unwrap();
    assert_eq!(names, vec!["#GUID".to_string(), "#Blob".to_string()]);
    assert_eq!(guid, Some((0x20, 16)));
    assert!(parse_clr_streams(&b"NOPE"[..]).is_none());
    // Truncation fails softly wherever it cuts; only the last name's
    // two padding bytes are optional.
    for cut in 0..md.len() - 2 {
        assert!(parse_clr_streams(&md[..cut]).is_none(), "cut at {cut}");
    }
}

#[test]
fn delay_import_vas_resolve_against_the_full_image_base() {
    // RvaBased descriptors pass through untouched.
    assert_eq!(delay_import_rva(0x2000, true, 0x1_4000_0000), 0x2000);
    // Legacy VA-based descriptor in a PE32 image.
    assert_eq!(delay_import_rva(0x0040_2000, false, 0x0040_0000), 0x2000);
    // A PE32+ base is above every 32-bit VA. Truncating it to its low
    // half (0x4000_0000) would turn this forged VA into RVA 0x2000.
    assert_eq!(delay_import_rva(0x4000_2000, false, 0x1_4000_0000), 0);
}

#[test]
fn machine_string_known_values() {
    assert_eq!(machine_string(0x8664), "x86_64");
    assert_eq!(machine_string(0x014c), "i386");
    assert_eq!(machine_string(0xaa64), "arm64");
    assert_eq!(machine_string(0xffff), "unknown");
}

#[test]
fn dll_characteristics_bit_decomposition() {
    // dynamic_base | nx_compat | high_entropy_va
    let flags = 0x0040 | 0x0100 | 0x0020;
    let chars = dll_characteristics(flags);
    assert!(chars.contains(&"dynamic_base"));
    assert!(chars.contains(&"nx_compat"));
    assert!(chars.contains(&"high_entropy_va"));
}

#[test]
fn subsystem_string_known_values() {
    assert_eq!(subsystem_string(2), "windows_gui");
    assert_eq!(subsystem_string(3), "windows_cui");
    assert_eq!(subsystem_string(1), "native");
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

fn read_fixture(name: &str) -> Vec<u8> {
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
fn manual_resolver_code_signals_require_the_complete_mechanics() {
    // A bounds-checking export walker: MZ → e_lfanew → PE signature →
    // PE32 export-directory offset and size. Keep this independent from a fixture
    // so a future parser change cannot accidentally widen the detector.
    let checked_walk = [
        0x66, 0x81, 0x3f, 0x4d, 0x5a, 0x8b, 0x47, 0x3c, 0x81, 0x3c, 0x07, 0x50, 0x45, 0x00, 0x00,
        0x8b, 0x4c, 0x07, 0x78, 0x8b, 0x54, 0x07, 0x7c,
    ];
    assert_eq!(count_checked_export_walks_x86(&checked_walk), 1);
    assert_eq!(
        find_checked_export_walks_x86(&checked_walk),
        vec![CheckedExportWalk {
            mz_check: 0,
            e_lfanew: 5,
            pe_check: 8,
            export_rva: 15,
            export_size: 19,
        }]
    );
    assert_eq!(count_checked_export_walks_x86(&checked_walk[..8]), 0);

    // A byte-wise custom hash: multiply, byte load, XOR with the
    // accumulator and a constant, then rotate.
    let hash_loop = [
        0xb8, 0xdb, 0xf7, 0x26, 0xab, 0x80, 0xcd, 0x20, 0x80, 0xf9, 0x1a, 0x0f, 0x43, 0xcb, 0x69,
        0xd8, 0x7f, 0x85, 0x3b, 0x80, 0x0f, 0xb6, 0xc1, 0x31, 0xd8, 0x35, 0x38, 0x9f, 0x93, 0x87,
        0xc1, 0xc0, 0x09,
    ];
    assert_eq!(count_custom_byte_hash_loops_x86(&hash_loop), 1);
    assert_eq!(
        find_custom_byte_hash_profiles_x86(&hash_loop),
        vec![ApiHashProfile {
            loop_offset: 14,
            kind: "multiply_xor_rotate",
            seed: Some(0xab26f7db),
            multiplier: 0x803b857f,
            xor_constant: 0x87939f38,
            rotate_bits: 9,
            ascii_lowercase: true,
        }]
    );
    assert_eq!(count_custom_byte_hash_loops_x86(&hash_loop[..29]), 0);
}

#[test]
fn flattened_xor_rotate_multiply_hash_profile_recovers_seed_flow() {
    let hash_loop = [
        // seed -> stack slot 0x10
        0xc7, 0x44, 0x24, 0x10, 0xb5, 0xcf, 0x88, 0x11,
        // dispatcher copies slot 0x10 -> accumulator slot 0x1c
        0x8b, 0x44, 0x24, 0x10, 0x89, 0x44, 0x24, 0x1c,
        // lowercase normalization and accumulator update
        0x8b, 0x44, 0x24, 0x18, 0x0f, 0xb6, 0x0c, 0x07, 0x89, 0xca, 0x80, 0xc2, 0xbf, 0x88, 0xce,
        0x80, 0xce, 0x20, 0x80, 0xfa, 0x1a, 0x0f, 0xb6, 0xd6, 0x0f, 0x43, 0xd1, 0x8b, 0x4c, 0x24,
        0x1c, 0xbd, 0xa7, 0x79, 0x02, 0x34, 0x31, 0xe9, 0xc1, 0xc1, 0x15, 0x69, 0xc9, 0x59, 0x94,
        0x27, 0x85, 0x0f, 0xb6, 0xd2, 0x31, 0xca,
    ];
    let profiles = find_custom_byte_hash_profiles_x86(&hash_loop);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].kind, "xor_rotate_multiply_xor");
    assert_eq!(profiles[0].seed, Some(0x1188cfb5));
    assert_eq!(profiles[0].xor_constant, 0x340279a7);
    assert_eq!(profiles[0].multiplier, 0x85279459);
    assert_eq!(profiles[0].rotate_bits, 21);
    assert!(profiles[0].ascii_lowercase);
}

#[test]
fn recovered_profile_exactly_matches_native_api_name() {
    let profile = LocatedHashProfile {
        va: 0x40ed6d,
        kind: "xor_rotate_multiply_xor".to_string(),
        seed: 0x1188cfb5,
        multiplier: 0x85279459,
        xor_constant: 0x340279a7,
        rotate_bits: 21,
        ascii_lowercase: true,
    };
    assert_eq!(
        hash_windows_name(&profile, "NtQueryInformationProcess"),
        0x3b1471e8
    );
    assert_ne!(
        hash_windows_name(&profile, "NtQuerySystemInformation"),
        0x3b1471e8
    );
}

#[test]
fn recovers_immediate_and_constant_folded_hash_arguments() {
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let optional_offset = pe_offset + 24;
    assert_eq!(
        u16::from_le_bytes(
            bytes[optional_offset..optional_offset + 2]
                .try_into()
                .unwrap()
        ),
        0x20b
    );
    bytes[optional_offset + 24..optional_offset + 32]
        .copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    let pe = PE::parse(&bytes).expect("fixture PE");
    let section = pe
        .sections
        .iter()
        .find(|section| section.size_of_raw_data >= 0x100)
        .expect("fixture code section");
    let section_file = section.pointer_to_raw_data as usize;
    let section_va = pe.image_base + u64::from(section.virtual_address);
    drop(pe);

    let direct_offset = section_file + 0x20;
    bytes[direct_offset..direct_offset + 11]
        .copy_from_slice(&[0x68, 0xe8, 0x71, 0x14, 0x3b, 0x50, 0xe8, 0, 0, 0, 0]);

    let memory_offset = section_file + 0x80;
    bytes[memory_offset..memory_offset + 4].copy_from_slice(&0x0000bd87_u32.to_le_bytes());
    let memory_va = u32::try_from(section_va + 0x80).expect("PE32 fixture VA");
    let folded_offset = section_file + 0x40;
    let mut folded = vec![0xa1];
    folded.extend_from_slice(&memory_va.to_le_bytes());
    folded.push(0xb9);
    folded.extend_from_slice(&0x9bf7790b_u32.to_le_bytes());
    folded.extend_from_slice(&[0x31, 0xc8, 0x05]);
    folded.extend_from_slice(&0x9f1cad5c_u32.to_le_bytes());
    folded.extend_from_slice(&[0x50, 0xff, 0x74, 0x24, 0x0c, 0xe8, 0, 0, 0, 0]);
    bytes[folded_offset..folded_offset + folded.len()].copy_from_slice(&folded);
    let pe = PE::parse(&bytes).expect("mutated fixture PE");
    assert_eq!(
        recover_x86_hash_argument(&pe, &bytes, section_va + 0x26),
        Some((0x3b1471e8, "immediate"))
    );
    assert_eq!(
        recover_x86_hash_argument(&pe, &bytes, section_va + 0x40 + 22),
        Some((0x3b1471e8, "constant_folded_memory_xor_add"))
    );
}

#[test]
fn dll_characteristics_empty_when_zero() {
    let chars = dll_characteristics(0);
    assert!(chars.is_empty());
}

#[test]
fn dll_characteristics_picks_up_force_integrity_and_aslr() {
    // force_integrity (0x80) | dynamic_base (0x40) | guard_cf (0x4000)
    let chars = dll_characteristics(0x80 | 0x40 | 0x4000);
    assert!(chars.contains(&"force_integrity"));
    assert!(chars.contains(&"dynamic_base"));
    assert!(chars.contains(&"guard_cf"));
}

#[test]
fn subsystem_string_unknown_fallback() {
    assert_eq!(subsystem_string(99), "unknown");
}

#[test]
fn rt_name_covers_canonical_resource_types() {
    assert_eq!(rt_name(1), "RT_CURSOR");
    assert_eq!(rt_name(2), "RT_BITMAP");
    assert_eq!(rt_name(14), "RT_GROUP_ICON");
}

/// Every section header pointed at one executable run of `fs:[0x30]` loads:
/// the bytes are scanned once (not once per header), the count is exact, and
/// the per-site records stop at the cap with the cap reported.
#[test]
fn native_resolver_scan_clips_overlapping_sections_and_caps_sites() {
    const NEEDLE: &[u8] = b"\x64\xa1\x30\x00\x00\x00";
    const MATCHES: usize = MAX_NATIVE_SITES + 904;
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_offset + 4;
    let count = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_optional = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap());
    let table = coff + 20 + size_of_optional as usize;
    let region = bytes.len().next_multiple_of(0x200);
    let len = NEEDLE.len() * MATCHES;
    bytes.resize(region, 0);
    bytes.extend(NEEDLE.iter().copied().cycle().take(len));
    for i in 0..count {
        let header = table + i * 40;
        bytes[header + 16..header + 20].copy_from_slice(&(len as u32).to_le_bytes());
        bytes[header + 20..header + 24].copy_from_slice(&(region as u32).to_le_bytes());
        bytes[header + 36..header + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    }
    assert!(
        count > 1,
        "the fixture must have overlapping headers to clip"
    );

    let pe = PE::parse_with_opts(
        &bytes,
        &goblin::pe::options::ParseOptions::default()
            .with_parse_mode(goblin::options::ParseMode::Permissive)
            .with_parse_imports(false),
    )
    .expect("forged fixture parses");
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    native_resolver_signals(&pe, &bytes, &mut values, &mut metrics);
    assert_eq!(
        metrics.get("pe.peb_access_x86_count"),
        Some(MATCHES as f64),
        "each byte scanned once despite {count} overlapping headers"
    );
    let sites = values
        .get("pe.peb_access_sites")
        .and_then(serde_json::Value::as_array)
        .expect("sites");
    assert_eq!(sites.len(), MAX_NATIVE_SITES);
    assert_eq!(metrics.get("pe.native_resolver_sites_capped"), Some(1.0));
    assert_eq!(
        sites[1]["file_offset"],
        serde_json::json!(region + NEEDLE.len())
    );
}

/// The single RVA resolver follows the loader: a misaligned
/// `PointerToRawData` is rounded down to 512, the file-backed extent is the
/// raw size rounded to the file alignment, and the zero-filled virtual tail
/// past it has no file offset.
#[test]
fn rva_resolution_follows_the_loader() {
    use goblin::pe::section_table::SectionTable;
    let text = SectionTable {
        virtual_address: 0x1000,
        virtual_size: 0x2000,
        pointer_to_raw_data: 0x401,
        size_of_raw_data: 0x100,
        ..SectionTable::default()
    };
    let data = SectionTable {
        virtual_address: 0x4000,
        virtual_size: 0,
        pointer_to_raw_data: 0x800,
        size_of_raw_data: 0x200,
        ..SectionTable::default()
    };
    let sections = [text, data];
    let resolve = |rva| section_rva_to_file_offset(&sections, Some(0x200), rva);
    assert_eq!(resolve(0x1000), Some(0x400), "pointer rounded down to 512");
    // (0x401 + 0x100) rounded up to 0x200 is 0x600: 0x200 file-backed bytes.
    assert_eq!(resolve(0x11ff), Some(0x5ff));
    assert_eq!(resolve(0x1200), None, "virtual-only tail has no file bytes");
    assert_eq!(resolve(0x2fff), None);
    // Zero virtual size: the raw extent alone bounds it.
    assert_eq!(resolve(0x41ff), Some(0x9ff));
    assert_eq!(resolve(0x4200), None);
    assert_eq!(resolve(0x0fff), None, "before every section");
    // An invalid alignment keeps the unrounded raw extent.
    assert_eq!(
        section_rva_to_file_offset(&sections, Some(0x300), 0x1100),
        Some(0x500)
    );
    assert_eq!(
        section_rva_to_file_offset(&sections, Some(0x300), 0x1101),
        None
    );
    // Header values at the top of the range must not overflow.
    let edge = SectionTable {
        virtual_address: u32::MAX - 0x10,
        virtual_size: u32::MAX,
        pointer_to_raw_data: u32::MAX,
        size_of_raw_data: u32::MAX,
        ..SectionTable::default()
    };
    assert!(section_rva_to_file_offset(&[edge], Some(0x200), u32::MAX).is_some());
}

/// The resource facts are derived from ids drained out of goblin's walker,
/// outside its panic guard: counts, icons, and the deduplicated type list.
#[test]
fn resource_types_derive_from_drained_ids() {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    resource_types(
        &[Some(16), Some(3), None, Some(14), Some(3), Some(999)],
        &mut values,
        &mut metrics,
    );
    assert_eq!(metrics.get("pe.resource_count"), Some(6.0));
    assert_eq!(metrics.get("pe.icon_count"), Some(3.0));
    assert_eq!(
        values.get("pe.resource_types"),
        Some(&serde_json::json!([
            "RT_ICON",
            "RT_GROUP_ICON",
            "RT_VERSION",
            "RT_UNKNOWN"
        ]))
    );

    let mut values = Values::new();
    let mut metrics = Metrics::new();
    resource_types(&[], &mut values, &mut metrics);
    assert_eq!(metrics.get("pe.resource_count"), Some(0.0));
    assert!(metrics.get("pe.icon_count").is_none());
    assert!(values.get("pe.resource_types").is_none());
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
    // Pike-style flat schema for COFF + optional header.
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

/// Build a CLR resources blob from `[u32 len][bytes]` chunks.
fn resource_blob(chunks: &[&[u8]]) -> Vec<u8> {
    let mut b = Vec::new();
    for c in chunks {
        b.extend_from_slice(&(c.len() as u32).to_le_bytes());
        b.extend_from_slice(c);
    }
    b
}

#[test]
fn scan_resource_blob_counts_and_measures() {
    let low = vec![b'A'; 256]; // entropy 0
    let high: Vec<u8> = (0..=255u8).cycle().take(4096).collect(); // entropy ~8
    let blob = resource_blob(&[&low, &high]);
    let (count, max_entropy, max_size, entropy_span, size_span) = scan_resource_blob(&blob);
    assert_eq!(count, 2);
    assert_eq!(max_size, 4096);
    assert!(max_entropy > 7.0, "max_entropy {max_entropy}");
    assert_eq!(entropy_span.map(|s| s.offset), Some(264));
    assert_eq!(size_span.map(|s| s.offset), Some(264));
}

#[test]
fn scan_resource_blob_stops_on_bad_length() {
    // One good chunk, then a length that overruns the blob — the walk
    // counts the good chunk and stops rather than over-reading.
    let mut blob = resource_blob(&[b"hello there friend"]);
    blob.extend_from_slice(&u32::MAX.to_le_bytes());
    blob.extend_from_slice(b"trailing");
    let (count, _, max_size, _, _) = scan_resource_blob(&blob);
    assert_eq!(count, 1);
    assert_eq!(max_size, 18);
}

#[test]
fn scan_resource_blob_empty_and_truncated() {
    assert_eq!(scan_resource_blob(&[]), (0, 0.0, 0, None, None));
    assert_eq!(scan_resource_blob(&[0x10, 0x00]), (0, 0.0, 0, None, None)); // < 4 bytes
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
