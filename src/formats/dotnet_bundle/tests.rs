#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// A bundle carrying one member, `payload.py`, stored (or for v6, raw
/// DEFLATE when `compressed`) right after the marker.
fn fixture(major: u32, compressed_size: Option<u64>) -> Vec<u8> {
    let payload = b"print('bundle member')\n";
    let mut data = vec![0; 8];
    data.extend_from_slice(SIGNATURE);
    let offset = data.len() as u64;
    data.extend_from_slice(payload);
    let header = data.len() as u64;
    data[..8].copy_from_slice(&header.to_le_bytes());
    data.extend_from_slice(&major.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(b"\x02id");
    if major >= 2 {
        data.extend_from_slice(&[0; 40]);
    }
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    if major >= 6 {
        data.extend_from_slice(&compressed_size.unwrap_or(0).to_le_bytes());
    }
    data.push(1);
    data.extend_from_slice(b"\x0apayload.py");
    data
}

#[test]
fn every_supported_version_lists_its_members() {
    for (version, compressed) in [(1, None), (2, None), (6, None), (6, Some(17))] {
        let bundle = parse(&fixture(version, compressed)).unwrap();
        assert_eq!(bundle["version"], version);
        assert!(bundle.get("notes").is_none());
        let member = &bundle["members"][0];
        assert_eq!(member["path"], "payload.py");
        assert_eq!(member["offset"], 40);
        assert_eq!(member["size"], 23);
        assert_eq!(member["compressed_size"], compressed.unwrap_or(0));
    }
}

#[test]
fn unpatched_decoy_and_invalid_headers() {
    assert!(parse(b"not a bundle").is_none());
    let mut data = vec![0; 8];
    data.extend_from_slice(SIGNATURE);
    assert!(parse(&data).is_none(), "zero offset: unpatched apphost");
    data[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(parse(&data).unwrap().contains_key("error"));
    // A decoy marker before the real one does not hide it.
    let prefix = data.len();
    let mut valid = fixture(6, None);
    let header = u64::from_le_bytes(valid[..8].try_into().unwrap()) as usize;
    valid[..8].copy_from_slice(&((header + prefix) as u64).to_le_bytes());
    data.extend_from_slice(&valid);
    let bundle = parse(&data).unwrap();
    assert_eq!(bundle["members"][0]["path"], "payload.py");
}

#[test]
fn truncation_is_noted() {
    let mut data = fixture(6, None);
    data.pop();
    let bundle = parse(&data).unwrap();
    assert!(bundle["members"].as_array().unwrap().is_empty());
    assert!(!bundle["notes"].as_array().unwrap().is_empty());
}
