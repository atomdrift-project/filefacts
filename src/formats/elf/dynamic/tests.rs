use super::*;

/// Slots resolve through keyed lookups — a direct pointer, a relative
/// relocation, and a GLOB_DAT through the symbol index — and the output
/// stops at the cap however many slots the section declares.
#[test]
fn init_array_slots_resolve_by_key_and_stop_at_the_cap() {
    let mut relocs = HashMap::new();
    let reloc = |kind, addend, sym_idx| InitReloc {
        addend,
        sym_idx,
        kind,
    };
    relocs.insert(0x1008, reloc(RelocKind::Relative, 0x500, 0));
    relocs.insert(0x1010, reloc(RelocKind::GlobDat, 0, 7));
    let index = DynsymAddressIndex {
        by_addr: HashMap::from([(0x400, "ctor"), (0x500, "reloc_ctor"), (0x600, "glob")]),
        by_index: HashMap::from([(7, 0x600)]),
    };
    let mut slots = 0x400_u64.to_le_bytes().to_vec();
    slots.extend([0; 16]);
    let mut names = NameBudget::new(1 << 20);
    let entries = init_array_entries(0x1000, &slots, &relocs, &index, &mut names);
    assert_eq!(
        entries,
        [
            serde_json::json!({"addr": "0x400", "symbol": "ctor"}),
            serde_json::json!({"addr": "0x500", "symbol": "reloc_ctor", "reloc": "relative"}),
            serde_json::json!({"addr": "0x600", "symbol": "glob", "reloc": "glob_dat"}),
        ]
    );

    let many = vec![0u8; (MAX_INIT_ARRAY_SLOTS + 100) * 8];
    let entries = init_array_entries(0x1000, &many, &relocs, &index, &mut names);
    assert_eq!(entries.len(), MAX_INIT_ARRAY_SLOTS);
}
