use super::*;
fn facts(chunks: &[u8]) -> (Values, Metrics) {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&((chunks.len() + 4) as u32).to_le_bytes());
    bytes.extend_from_slice(b"ACON");
    bytes.extend_from_slice(chunks);
    let (mut values, mut metrics) = (Values::default(), Metrics::default());
    extract(&bytes, &mut values, &mut metrics);
    (values, metrics)
}
#[test]
fn only_chunk_boundaries_count_as_headers() {
    let mut normal = b"anih\x24\0\0\0\x24\0\0\0".to_vec();
    normal.resize(44, 0);
    let mut body = b"anih\x64\0\0\0".to_vec();
    body.resize(100, 0);
    let mut chunks = normal.clone();
    chunks.extend_from_slice(b"JUNK");
    chunks.extend_from_slice(&(body.len() as u32).to_le_bytes());
    chunks.extend_from_slice(&body);
    let (_, m) = facts(&chunks);
    assert_eq!(m.get("ani.oversized_header_count"), Some(0.0));
    normal.extend_from_slice(&body);
    let (v, m) = facts(&normal);
    assert_eq!(m.get("ani.oversized_header_count"), Some(1.0));
    assert_eq!(m.get("ani.oversized_after_fixed_header_count"), Some(1.0));
    assert_eq!(v.get("ani.headers").unwrap().as_array().unwrap().len(), 2);
    for n in 0..normal.len() {
        let _ = facts(&normal[..n]);
    }
}
