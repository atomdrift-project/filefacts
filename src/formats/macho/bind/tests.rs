use super::*;
use crate::formats::macho::tests::{macho_with_bind_tables, macho_with_dyld_info};

/// The first anomaly in the streams of `file`, parsed by goblin.
fn anomaly(file: &[u8]) -> Option<Anomaly> {
    let macho = MachO::parse(file, 0).expect("fixture parses");
    check(&macho, file)
}

#[test]
fn a_forged_repeat_count_is_an_anomaly() {
    // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, count 2^32 - 1, skip 0.
    let bind = [0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00];
    assert_eq!(
        anomaly(&macho_with_bind_tables(&bind)),
        Some(Anomaly::Oversized {
            stream: "bind",
            binds: u64::from(u32::MAX)
        })
    );
}

#[test]
fn a_well_formed_stream_is_no_anomaly() {
    // Symbol `_a`, ordinal 1, segment 0 offset 0, bound three times:
    // DO_BIND, DO_BIND_ADD_ADDR_IMM_SCALED and a ULEB repeat of 1.
    let bind = [
        0x11, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0xB1, 0xC0, 0x01, 0x00, 0x00,
    ];
    assert_eq!(anomaly(&macho_with_bind_tables(&bind)), None);
    // The special ordinals dyld defines: self, main executable, flat and
    // weak lookup.
    for special in [0x30, 0x3f, 0x3e, 0x3d] {
        let bind = [special, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00];
        assert_eq!(anomaly(&macho_with_bind_tables(&bind)), None, "{special:x}");
    }
}

/// An ordinal is the full ULEB value dyld reads, numbered from 1 over the
/// image's one dylib: none wraps to a valid one.
#[test]
fn dylib_ordinals_past_the_dylibs_are_anomalies() {
    let uleb = |ordinal: &[u8]| {
        let mut bind = vec![0x20];
        bind.extend_from_slice(ordinal);
        bind.extend_from_slice(&[0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00]);
        anomaly(&macho_with_bind_tables(&bind))
    };
    for (encoded, ordinal) in [
        (&[0x02][..], 2),
        (&[0x80, 0x02], 256),
        (&[0x82, 0x02], 258),
        (&[0xac, 0x02], 300),
    ] {
        assert_eq!(
            uleb(encoded),
            Some(Anomaly::DylibOutOfRange {
                stream: "bind",
                ordinal,
                len: 1
            })
        );
    }
    assert_eq!(uleb(&[0x01]), None);
    let immediate = [0x12, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00];
    assert_eq!(
        anomaly(&macho_with_bind_tables(&immediate))
            .map(|anomaly| anomaly.to_string())
            .as_deref(),
        Some("bind bind opcodes bind through dylib ordinal 2 of 1")
    );
    // The table-less fixture loads no dylib at all.
    assert!(anomaly(&macho_with_dyld_info(&immediate, &[])).is_some());
}

#[test]
fn unknown_special_ordinals_and_segments_are_anomalies() {
    let special = [0x3c, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0x90, 0x00];
    assert_eq!(
        anomaly(&macho_with_bind_tables(&special)),
        Some(Anomaly::UnknownSpecialOrdinal {
            stream: "bind",
            ordinal: -4
        })
    );
    let segment = [0x11, 0x40, b'_', b'a', 0x00, 0x73, 0x00, 0x90, 0x00];
    assert_eq!(
        anomaly(&macho_with_bind_tables(&segment)),
        Some(Anomaly::SegmentOutOfRange {
            stream: "bind",
            index: 3,
            len: 1
        })
    );
}

/// dyld stops the bind stream at its first `DONE`; what follows is not
/// read.
#[test]
fn the_bind_stream_ends_at_done() {
    let bind = [0x11, 0x00, 0x12];
    assert_eq!(anomaly(&macho_with_bind_tables(&bind)), None);
}

/// Each lazy entry ends at a `DONE`, and the next is read after it.
#[test]
fn lazy_entries_continue_past_done() {
    let tables = Tables {
        dylibs: 1,
        segments: 1,
    };
    assert_eq!(
        walk(&[0x11, 0x90, 0x00, 0x11, 0x90, 0x00], "lazy", tables, 0),
        Ok(2)
    );
    assert_eq!(
        walk(&[0x11, 0x90, 0x00, 0x12], "lazy", tables, 0),
        Err(Anomaly::DylibOutOfRange {
            stream: "lazy",
            ordinal: 2,
            len: 1
        })
    );
    // A truncated operand ends the walk, its bind uncounted.
    assert_eq!(walk(&[0x90, 0xA0, 0x80], "lazy", tables, 0), Ok(1));
    assert_eq!(walk(&[0xC0, 0x05], "lazy", tables, 0), Ok(0));
}
