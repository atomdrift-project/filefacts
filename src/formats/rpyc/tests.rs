use std::io::Write as _;

use super::*;

/// An RPC2 file whose `slots` slot-table entries all name one zlib stream
/// that inflates to `inflated` zero bytes.
fn shared_slot_file(slots: u32, inflated: usize) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![0u8; inflated]).unwrap();
    let stream = encoder.finish().unwrap();
    let table = MAGIC.len() + 12 * (slots as usize + 1);
    let mut out = MAGIC.to_vec();
    for number in 1..=slots {
        for field in [number, table as u32, stream.len() as u32] {
            out.extend_from_slice(&field.to_le_bytes());
        }
    }
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&stream);
    out
}

fn slot_errors(values: &Values) -> Vec<String> {
    values
        .get("rpyc.slots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|slot| slot["error"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Slots may all name one small stream that inflates past the per-slot
/// cap. Each is refused, but only after inflating up to the cap, so that
/// work comes out of the file's total budget and the slots past it are not
/// inflated at all.
#[test]
fn refused_slots_spend_the_total_budget() {
    let bytes = shared_slot_file(4, MAX_SLOT_BYTES + 1);
    let mut values = Values::new();
    extract(&bytes, &mut values, &mut Metrics::new()).unwrap();
    assert_eq!(
        slot_errors(&values),
        [
            "decompressed slot limit exceeded",
            "decompressed slot limit exceeded",
            "total decompressed slot limit exceeded",
            "total decompressed slot limit exceeded",
        ]
    );
}

/// Slots within the budget still decode.
#[test]
fn small_slots_decode() {
    let bytes = shared_slot_file(2, 64);
    let mut values = Values::new();
    extract(&bytes, &mut values, &mut Metrics::new()).unwrap();
    assert_eq!(slot_errors(&values), ["", ""]);
    assert_eq!(
        values.get("rpyc.slots[1].decompressed_size"),
        Some(&json!(64))
    );
}
