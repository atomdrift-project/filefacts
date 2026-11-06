use super::*;

#[test]
fn partial_section_geometry_detects_overflow_only_with_complete_table() {
    let bytes = vec![0u8; 512];
    let section = |name: &str, size: u32, pointer: u32| SectionTable {
        real_name: Some(name.into()),
        size_of_raw_data: size,
        pointer_to_raw_data: pointer,
        ..SectionTable::default()
    };
    let sections = [section(".text", 64, 256), section(".rsrc", 500, 400)];
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    partial_section_overflows(&sections, 2, &bytes, &mut values, &mut metrics);
    assert_eq!(metrics.get("pe.section_overflow_count"), Some(1.0));
    assert_eq!(
        values.lookup(value_key!("pe.overflowing_sections")),
        Some(&serde_json::json!([".rsrc"]))
    );
    for (sections, count) in [(&sections[..1], 2), (&sections[..], 0)] {
        let mut absent = Metrics::new();
        partial_section_overflows(sections, count, &bytes, &mut Values::new(), &mut absent);
        assert!(absent.get("pe.section_overflow_count").is_none());
    }
}

/// `test.exe` with `overlay` bytes appended, and its PE signature offset.
fn with_overlay(overlay: usize) -> (Vec<u8>, usize) {
    let mut bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture");
    bytes.resize(bytes.len() + overlay, 0x5a);
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    (bytes, pe)
}

fn overlay_size(bytes: &[u8]) -> Option<f64> {
    let mut out = crate::formats::Sinks::default();
    crate::formats::pe::extract(bytes, out.ctx()).unwrap();
    out.metrics.get("pe.overlay_size")
}

/// The loader maps nothing from the file for a section with no raw data,
/// whatever its `PointerToRawData` says, so such a pointer past the end of
/// the file must not swallow the overlay.
#[test]
fn a_section_without_raw_data_does_not_hide_the_overlay() {
    let (mut bytes, pe) = with_overlay(1024);
    assert_eq!(overlay_size(&bytes), Some(1024.0));
    // A seventh section header after the fixture's six: uninitialized
    // data whose raw pointer lies far past the end of the file.
    let count = pe + 6;
    bytes[count] = 7;
    let at = pe + 24 + 0xf0 + 6 * 40;
    bytes[at..at + 4].copy_from_slice(b".bss");
    bytes[at + 8..at + 12].copy_from_slice(&0x1000_u32.to_le_bytes()); // VirtualSize
    bytes[at + 12..at + 16].copy_from_slice(&0x7000_u32.to_le_bytes()); // VirtualAddress
    bytes[at + 20..at + 24].copy_from_slice(&0xffff_fe00_u32.to_le_bytes()); // PointerToRawData
    bytes[at + 36..at + 40].copy_from_slice(&0xc000_0080_u32.to_le_bytes());
    assert_eq!(overlay_size(&bytes), Some(1024.0));
}

/// A certificate table is excluded from the overlay only where Authenticode
/// puts it, at the end of the file: one declared at the overlay's start
/// with data past it must not hide that data.
#[test]
fn a_certificate_table_short_of_the_end_does_not_hide_the_overlay() {
    let (mut bytes, pe) = with_overlay(1024);
    let start = (bytes.len() - 1024) as u32;
    // PE32+: the certificate directory is data directory 4.
    let cert = pe + 24 + 112 + 4 * 8;
    bytes[cert..cert + 4].copy_from_slice(&start.to_le_bytes());
    bytes[cert + 4..cert + 8].copy_from_slice(&8_u32.to_le_bytes());
    assert_eq!(overlay_size(&bytes), Some(1024.0));
    // A table running to the end of the file is the signature, no overlay.
    bytes[cert + 4..cert + 8].copy_from_slice(&1024_u32.to_le_bytes());
    assert_eq!(overlay_size(&bytes), None);
}
