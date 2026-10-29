use super::*;

#[test]
fn parse_clr_streams_reads_standard_heaps() {
    // Minimal metadata root: BSJB, version "v4.0" (len 4), flags=0,
    // streams=2, then #GUID (offset 0x20, size 16) and #Blob headers.
    let mut md = Vec::new();
    md.extend_from_slice(b"BSJB");
    md.extend_from_slice(&1u16.to_le_bytes()); // major
    md.extend_from_slice(&1u16.to_le_bytes()); // minor
    md.extend_from_slice(&0u32.to_le_bytes()); // reserved
    md.extend_from_slice(&4u32.to_le_bytes()); // version_len
    md.extend_from_slice(b"v4.0"); // version (already 4-aligned)
    md.extend_from_slice(&0u16.to_le_bytes()); // flags
    md.extend_from_slice(&2u16.to_le_bytes()); // streams
    md.extend_from_slice(&0x20u32.to_le_bytes()); // #GUID offset
    md.extend_from_slice(&16u32.to_le_bytes()); // #GUID size
    md.extend_from_slice(b"#GUID\0\0\0"); // name, padded to 8
    md.extend_from_slice(&0x40u32.to_le_bytes()); // #Blob offset
    md.extend_from_slice(&8u32.to_le_bytes()); // #Blob size
    md.extend_from_slice(b"#Blob\0\0\0"); // name, padded to 8
    let (names, guid) = parse_clr_streams(&md).unwrap();
    assert_eq!(names, vec!["#GUID".to_string(), "#Blob".to_string()]);
    assert_eq!(guid, Some((0x20, 16)));
    assert!(parse_clr_streams(&b"NOPE"[..]).is_none());
    // Truncation fails softly wherever it cuts; only the last name's
    // two padding bytes are optional.
    for cut in 0..md.len() - 2 {
        assert!(parse_clr_streams(&md[..cut]).is_none(), "cut at {cut}");
    }
}

/// Build a CLR resources blob from `[u32 len][bytes]` chunks.
fn resource_blob(chunks: &[&[u8]]) -> Vec<u8> {
    let mut b = Vec::new();
    for c in chunks {
        b.extend_from_slice(&(c.len() as u32).to_le_bytes());
        b.extend_from_slice(c);
        b.resize((b.len() + 7) & !7, 0);
    }
    b
}

#[test]
fn scan_resource_blob_counts_and_measures() {
    let low = vec![b'A'; 256]; // entropy 0
    let high: Vec<u8> = (0..=255u8).cycle().take(4096).collect(); // entropy ~8
    let blob = resource_blob(&[&low, &high]);
    let (count, max_entropy, max_size, entropy_span, size_span) = scan_resource_blob(&blob);
    assert_eq!(count, 2);
    assert_eq!(max_size, 4096);
    assert!(max_entropy > 7.0, "max_entropy {max_entropy}");
    assert_eq!(entropy_span.map(|s| s.offset), Some(268));
    assert_eq!(size_span.map(|s| s.offset), Some(268));
}

#[test]
fn scan_resource_blob_stops_on_bad_length() {
    // One good chunk, then a length that overruns the blob — the walk
    // counts the good chunk and stops rather than over-reading.
    let mut blob = resource_blob(&[b"hello there friend"]);
    blob.extend_from_slice(&u32::MAX.to_le_bytes());
    blob.extend_from_slice(b"trailing");
    let (count, _, max_size, _, _) = scan_resource_blob(&blob);
    assert_eq!(count, 1);
    assert_eq!(max_size, 18);
}

#[test]
fn scan_resource_blob_empty_and_truncated() {
    assert_eq!(scan_resource_blob(&[]), (0, 0.0, 0, None, None));
    assert_eq!(scan_resource_blob(&[0x10, 0x00]), (0, 0.0, 0, None, None)); // < 4 bytes
}
