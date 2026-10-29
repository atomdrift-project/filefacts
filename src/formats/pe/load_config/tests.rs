use super::*;
use crate::formats::goblin_safe;
use crate::formats::pe::tests::read_fixture;

/// `IMAGE_GUARD_*` bits as winnt.h defines them: the delay-load and
/// export-suppression flags sit in the 0x1000..0x8000 nibble, below the
/// longjmp and return-flow bits, and neither range shadows the other.
#[test]
fn guard_flag_names_follow_winnt() {
    assert_eq!(
        guard_flag_names(0x0000_F000),
        [
            "protect_delayload_iat",
            "delayload_iat_in_its_own_section",
            "export_suppression_info_present",
            "enable_export_suppression",
        ]
    );
    assert_eq!(
        guard_flag_names(0x000F_0000),
        [
            "longjump_table_present",
            "rf_instrumented",
            "rf_enable",
            "rf_strict"
        ]
    );
}

/// `test.exe` (PE32+) with a TLS directory registering `callbacks` callbacks.
fn pe_with_tls_callbacks(callbacks: usize) -> Vec<u8> {
    let put = |bytes: &mut Vec<u8>, at: usize, value: u64, width: usize| {
        bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    };
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_offset + 4;
    let sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_optional = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap());
    let optional = coff + 20;
    let image_base = u64::from_le_bytes(bytes[optional + 24..optional + 32].try_into().unwrap());
    let last = optional + size_of_optional as usize + (sections - 1) * 40;
    let va = u64::from(u32::from_le_bytes(
        bytes[last + 12..last + 16].try_into().unwrap(),
    ));
    let pointer = u32::from_le_bytes(bytes[last + 20..last + 24].try_into().unwrap()) as usize;

    let size = 40 + (callbacks + 1) * 8;
    bytes.resize(pointer + size, 0);
    bytes[pointer..pointer + size].fill(0);
    put(&mut bytes, last + 8, size as u64, 4); // virtual_size
    put(&mut bytes, last + 16, size as u64, 4); // size_of_raw_data
    // IMAGE_TLS_DIRECTORY64.AddressOfCallBacks, then the array itself, every
    // callback pointing back into this section.
    put(&mut bytes, pointer + 24, image_base + va + 40, 8);
    for i in 0..callbacks {
        put(&mut bytes, pointer + 40 + i * 8, image_base + va, 8);
    }
    // Data directory 9 is the TLS table; PE32+ puts the array at +112.
    put(&mut bytes, optional + 112 + 9 * 8, va, 4);
    put(&mut bytes, optional + 112 + 9 * 8 + 4, 40, 4);
    bytes
}

/// A callback array runs to its first null entry, so a forged one is as long
/// as the file allows; the records are capped and the count stays exact.
#[test]
fn tls_callback_records_are_capped() {
    for (callbacks, records) in [(3, 3), (100_000, MAX_TLS_CALLBACK_RECORDS)] {
        let bytes = pe_with_tls_callbacks(callbacks);
        let prepared = goblin_safe::prepare_pe(&bytes);
        let pe = goblin_safe::parse_pe(&prepared).ok().expect("parses");
        let (mut values, mut metrics) = (Values::new(), Metrics::new());
        tls_callbacks(&pe, &mut values, &mut metrics);
        assert_eq!(metrics.get("pe.tls_callback_count"), Some(callbacks as f64));
        let recorded = values.get("pe.tls_callbacks").and_then(JsonValue::as_array);
        assert_eq!(recorded.map(Vec::len), Some(records));
    }
}
