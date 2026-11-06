use super::*;

#[test]
fn export_early_calls_stop_at_control_flow_and_deduplicate() {
    // Two calls to 0x1010, then a jump; the call after the jump must not count.
    let code = [
        0xe8, 0x0b, 0, 0, 0, 0xe8, 0x06, 0, 0, 0, 0xeb, 0x05, 0xe8, 0x1f, 0, 0, 0, 0xc3,
    ];
    assert_eq!(early_direct_calls(&code, 0x1000, 64), vec![0x1010]);
    // An indirect call is not a statically known shared target.
    assert!(early_direct_calls(&[0xff, 0xd0, 0xc3], 0x1000, 64).is_empty());
}

/// The export facts are binform's: an export table whose names are past
/// goblin's walk budget, and so kept from goblin, still has its aliased
/// entries counted.
#[test]
fn aliased_exports_survive_an_export_table_kept_from_goblin() {
    let bytes = crate::formats::goblin_safe::tests::pe_with_exports(4, 64, 1 << 20, false);
    assert!(
        crate::formats::goblin_safe::prepare_pe(&bytes)
            .exports_skipped
            .is_some()
    );
    let mut sinks = crate::formats::Sinks::default();
    let _ = super::super::extract(&bytes, sinks.ctx());
    assert_eq!(sinks.metrics.get("pe.aliased_export_count"), Some(4.0));
}
