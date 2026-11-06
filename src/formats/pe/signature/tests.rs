use serde_json::Value as JsonValue;

use crate::formats::pe::layout::{self, CERTIFICATE_DIRECTORY};
use crate::output::Values;

/// A real Authenticode blob, whose image digest a test rewrites.
const DIGICERT_TENCENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/authenticode-digicert-tencent.p7b"
));

fn values(bytes: &[u8]) -> Values {
    let mut out = crate::formats::Sinks::default();
    crate::formats::pe::extract(bytes, out.ctx()).unwrap();
    out.values
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// `blob` as the one record of a certificate table.
fn win_certificate(blob: &[u8]) -> Vec<u8> {
    let mut table = u32::try_from(blob.len() + 8)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    table.extend(0x0200_u16.to_le_bytes());
    table.extend(0x0002_u16.to_le_bytes());
    table.extend(blob);
    table.resize(table.len().next_multiple_of(8), 0);
    table
}

/// The image hash leaves out the last `size` bytes of the file, where the
/// certificate table belongs. A table the directory places anywhere else —
/// here in a gap between the headers and the first section — is not what
/// the hash left out: the gap is authenticated like any other physical
/// byte, so the table is hashed, and a signature cannot commit to a digest
/// of itself. The tail the hash did leave out is signed by nothing.
#[test]
fn a_digest_match_needs_the_table_where_the_hash_left_it_out() {
    let base = std::fs::read("tests/fixtures/test.exe").unwrap();
    let blob = crate::formats::cms::der_element(DIGICERT_TENCENT).unwrap();
    let table = win_certificate(blob);
    let gap = table.len().next_multiple_of(0x200);
    let headers = 0x400;

    // Open a gap after the headers and move every section past it.
    let mut file = base[..headers].to_vec();
    file.resize(headers + gap, 0);
    file.extend(&base[headers..]);
    let pe = u32_at(&file, 0x3c) as usize;
    let sections = u16::from_le_bytes([file[pe + 6], file[pe + 7]]);
    let optional_size = u16::from_le_bytes([file[pe + 20], file[pe + 21]]) as usize;
    let table_at = pe + 24 + optional_size;
    for i in 0..usize::from(sections) {
        let raw = table_at + 40 * i + 20;
        let moved = u32_at(&file, raw) + u32::try_from(gap).unwrap();
        put_u32(&mut file, raw, moved);
    }
    // The table sits in the gap; the directory sizes it as the payload
    // appended at the end, which the image hash therefore leaves out.
    file[headers..headers + table.len()].copy_from_slice(&table);
    let payload = vec![0xCC; table.len()];
    file.extend(&payload);
    let magic = u16::from_le_bytes([file[pe + 24], file[pe + 25]]);
    let dir = layout::data_directory_offset(pe, magic, CERTIFICATE_DIRECTORY).unwrap();
    put_u32(&mut file, dir, u32::try_from(headers).unwrap());
    put_u32(&mut file, dir + 4, u32::try_from(payload.len()).unwrap());

    // Try to commit the blob to the image hash: the gap is inside the hash,
    // so rewriting the digest there moves the hash it was meant to match.
    let image_hash = |file: &[u8]| {
        values(file)
            .get("pe.image_hash.sha256")
            .and_then(JsonValue::as_str)
            .unwrap()
            .to_string()
    };
    let hash = image_hash(&file);
    let sig = &values(&file).get("pe.signatures").unwrap()[0].clone();
    assert_eq!(sig["signature_digest_algorithm"], "sha256");
    let claimed = hex(sig["signature_digest"].as_str().unwrap());
    let at = file
        .windows(claimed.len())
        .position(|w| w == claimed.as_slice())
        .unwrap();
    file[at..at + claimed.len()].copy_from_slice(&hex(&hash));
    assert_ne!(image_hash(&file), hash);

    let v = values(&file);
    let sig = &v.get("pe.signatures").unwrap()[0];
    assert_eq!(sig["signature_digest"], hash.as_str());
    assert_ne!(sig["digest_matches"], true, "{sig}");
    assert_ne!(v.get("pe.signature_integrity").unwrap(), "intact");
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
