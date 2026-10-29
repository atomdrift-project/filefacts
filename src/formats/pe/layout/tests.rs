use super::*;

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
