use super::*;
use std::io::Write;

fn dex() -> Vec<u8> {
    let mut bytes = vec![0u8; 112];
    bytes[..8].copy_from_slice(b"dex\n035\0");
    bytes[32..36].copy_from_slice(&112u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
    let hash = Sha1::digest(&bytes[32..]);
    bytes[12..32].copy_from_slice(&hash);
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &bytes[12..] {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    bytes[8..12].copy_from_slice(&((b << 16) | a).to_le_bytes());
    bytes
}

fn apply(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bytes = data.to_vec();
    Rc4::new(key).apply(&mut bytes);
    bytes
}

fn archive(dex: Option<&[u8]>) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("notes.txt", options).unwrap();
    writer.write_all(b"benign control").unwrap();
    if let Some(dex) = dex {
        writer.start_file("renamed-component.bin", options).unwrap();
        writer.write_all(dex).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn standard_rc4_vector() {
    assert_eq!(
        apply(b"Plaintext", b"Key"),
        [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
    );
}

#[test]
fn recovers_dex_with_varied_keys_and_checks_both_digests() {
    for key in [b"x".as_slice(), b"changed-key", "密钥".as_bytes(), b"a\0b"] {
        let data = dex();
        let recovered = recover(&apply(&data, key), key, None).unwrap();
        assert_eq!(recovered.kind, Kind::Dex);
        assert_eq!(recovered.data, data);
    }
    for at in [8, 12, 44] {
        let mut bad = dex();
        bad[at] ^= 1;
        assert!(recover(&apply(&bad, b"k"), b"k", None).is_none());
    }
}

#[test]
fn recovers_zip_with_renamed_dex_and_requires_dex_contents() {
    let zip = archive(Some(&dex()));
    let result = recover(&apply(&zip, b"new-key"), b"new-key", None).unwrap();
    assert_eq!(result.kind, Kind::Zip);
    assert_eq!(result.data, zip);
    assert!(recover(&apply(&archive(None), b"k"), b"k", None).is_none());
}

#[test]
fn rejects_wrong_key_truncation_and_invalid_zip_crc() {
    let zip = archive(Some(&dex()));
    let encrypted = apply(&zip, b"new-key");
    assert!(recover(&encrypted, b"wrong-key", None).is_none());
    assert!(recover(&encrypted[..encrypted.len() - 1], b"new-key", None).is_none());
    let mut bad = zip;
    let cd = bad.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
    bad[cd + 16] ^= 1;
    assert!(recover(&apply(&bad, b"k"), b"k", None).is_none());
}

#[test]
fn rejects_invalid_inner_dex_and_declared_expansion_budget() {
    let mut bad_dex = dex();
    bad_dex[12] ^= 1;
    assert!(recover(&apply(&archive(Some(&bad_dex)), b"k"), b"k", None).is_none());
    let mut zip = archive(Some(&dex()));
    let cd = zip.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
    zip[cd + 24..cd + 28].copy_from_slice(&(MAX_EXPANDED as u32 + 1).to_le_bytes());
    assert!(recover(&apply(&zip, b"k"), b"k", None).is_none());
}

#[test]
fn rejects_encrypted_members_and_excessive_directory_count() {
    let mut zip = archive(Some(&dex()));
    let cd = zip.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
    zip[cd + 8] |= 1;
    assert!(recover(&apply(&zip, b"k"), b"k", None).is_none());
    let mut zip = archive(Some(&dex()));
    let eocd = zip.windows(4).rposition(|v| v == b"PK\x05\x06").unwrap();
    for at in [eocd + 8, eocd + 10] {
        zip[at..at + 2].copy_from_slice(&129u16.to_le_bytes());
    }
    assert!(recover(&apply(&zip, b"k"), b"k", None).is_none());
}

#[test]
fn enforces_input_key_and_cancellation_limits() {
    let data = apply(&dex(), b"k");
    assert!(recover(&data, b"", None).is_none());
    assert!(recover(&data, &[1; 65], None).is_none());
    assert!(recover(&data[..31], b"k", None).is_none());
    assert!(recover(&vec![0; MAX_INPUT + 1], b"k", None).is_none());
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    assert!(recover(&data, b"k", Some(&cancelled)).is_none());
    let calls = std::cell::Cell::new(0);
    assert!(
        recover_until(&data, b"k", || {
            calls.set(calls.get() + 1);
            calls.get() > 2
        })
        .is_none()
    );
}
