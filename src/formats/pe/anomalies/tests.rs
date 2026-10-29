use super::*;
use crate::formats::goblin_safe;

#[test]
fn partial_section_geometry_detects_overflow_only_with_complete_table() {
    let mut bytes = vec![0u8; 512];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    let section = 0x98;
    bytes[section..section + 5].copy_from_slice(b".text");
    bytes[section + 16..section + 20].copy_from_slice(&64u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&256u32.to_le_bytes());
    let second = section + 40;
    bytes[second..second + 5].copy_from_slice(b".rsrc");
    bytes[second + 16..second + 20].copy_from_slice(&500u32.to_le_bytes());
    bytes[second + 20..second + 24].copy_from_slice(&400u32.to_le_bytes());
    let header = match goblin_safe::parse_pe_header(&bytes) {
        goblin_safe::GoblinOutcome::Ok(h) => h,
        _ => panic!("valid minimal header"),
    };
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    partial_section_overflows(&bytes, &header, &mut values, &mut metrics);
    assert_eq!(metrics.get("pe.section_overflow_count"), Some(1.0));
    assert_eq!(
        values.get_key(value_key!("pe.overflowing_sections")),
        Some(&serde_json::json!([".rsrc"]))
    );
    let mut absent = Metrics::new();
    partial_section_overflows(
        &bytes[..second + 20],
        &header,
        &mut Values::new(),
        &mut absent,
    );
    assert!(absent.get("pe.section_overflow_count").is_none());
}
