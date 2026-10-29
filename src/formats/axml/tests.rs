use super::*;

/// Hand-build a minimal AXML document: header, UTF-8 string pool, and one
/// start element carrying a single string attribute.
fn doc() -> Vec<u8> {
    let strings = ["manifest", "package", "com.example.app"];
    // --- string pool ---
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        data.push(s.len() as u8); // utf16 len
        data.push(s.len() as u8); // utf8 len
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let header = 28 + offsets.len() * 4;
    let pool_size = header + data.len();
    let mut pool = Vec::new();
    pool.extend_from_slice(&TYPE_STRING_POOL.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&(pool_size as u32).to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // style count
    pool.extend_from_slice(&UTF8_FLAG.to_le_bytes());
    pool.extend_from_slice(&(header as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // styles start
    for o in &offsets {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);

    // --- start element: <manifest package="com.example.app"> ---
    let mut el = Vec::new();
    el.extend_from_slice(&TYPE_START_ELEMENT.to_le_bytes());
    el.extend_from_slice(&16u16.to_le_bytes());
    el.extend_from_slice(&(36u32 + 20).to_le_bytes());
    el.extend_from_slice(&1u32.to_le_bytes()); // line
    el.extend_from_slice(&u32::MAX.to_le_bytes()); // comment
    el.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
    el.extend_from_slice(&0u32.to_le_bytes()); // name -> "manifest"
    el.extend_from_slice(&20u16.to_le_bytes()); // attrStart
    el.extend_from_slice(&20u16.to_le_bytes()); // attrSize
    el.extend_from_slice(&1u16.to_le_bytes()); // attrCount
    el.extend_from_slice(&0u16.to_le_bytes()); // id
    el.extend_from_slice(&0u16.to_le_bytes()); // class
    el.extend_from_slice(&0u16.to_le_bytes()); // style
    el.extend_from_slice(&u32::MAX.to_le_bytes()); // attr ns
    el.extend_from_slice(&1u32.to_le_bytes()); // attr name -> "package"
    el.extend_from_slice(&2u32.to_le_bytes()); // raw -> "com.example.app"
    el.extend_from_slice(&8u16.to_le_bytes()); // size
    el.push(0); // res0
    el.push(0x03); // TYPE_STRING
    el.extend_from_slice(&2u32.to_le_bytes()); // data

    let mut out = Vec::new();
    out.extend_from_slice(&0x0003u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&((8 + pool.len() + el.len()) as u32).to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&el);
    out
}

#[test]
fn reads_element_and_attribute_from_a_utf8_pool() {
    let els = parse(&doc());
    assert_eq!(els.len(), 1);
    assert_eq!(els[0].name, "manifest");
    assert_eq!(
        els[0].attrs,
        vec![("package".to_string(), "com.example.app".to_string())]
    );
}

#[test]
fn a_zero_sized_chunk_does_not_hang_the_walk() {
    // A chunk claiming size 0 would loop forever if the walk trusted it.
    let mut b = vec![0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0];
    b.extend_from_slice(&[0x02, 0x01, 0x10, 0x00, 0, 0, 0, 0]);
    assert!(parse(&b).is_empty());
}

/// A UTF-16 string whose two-unit length claims 2^31 units reads as
/// truncated, like a UTF-8 string that runs past the pool, rather than
/// sizing a buffer from the claim.
#[test]
fn utf16_length_past_the_pool_is_truncated_not_allocated() {
    let mut chunk = vec![0u8; 28];
    chunk.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, b'a', 0]);
    assert_eq!(decode_string(&chunk, 28, false), None);
    // An in-bounds string still decodes.
    let mut chunk = vec![0u8; 28];
    chunk.extend_from_slice(&[2, 0, b'h', 0, b'i', 0, 0, 0]);
    assert_eq!(decode_string(&chunk, 28, false).as_deref(), Some("hi"));
}

/// A UTF-8 pool chunk with `count` offsets that all name one string of
/// `len` bytes.
fn pool_of_one_string(count: usize, len: usize) -> Vec<u8> {
    let strings_start = 28 + count * 4;
    let mut chunk = vec![0u8; 28];
    chunk[8..12].copy_from_slice(&(count as u32).to_le_bytes());
    chunk[16..20].copy_from_slice(&UTF8_FLAG.to_le_bytes());
    chunk[20..24].copy_from_slice(&(strings_start as u32).to_le_bytes());
    chunk.resize(strings_start, 0);
    let varint = [0x80 | (len >> 8) as u8, len as u8];
    chunk.extend_from_slice(&varint);
    chunk.extend_from_slice(&varint);
    chunk.resize(chunk.len() + len, b'x');
    chunk
}

/// 65,536 offsets naming one 32 KiB string decoded 2 GiB of copies; the
/// pool budget keeps the first `MAX_POOL_TEXT` of them.
#[test]
fn repeated_pool_offsets_stop_at_the_text_budget() {
    let len = 0x7fff;
    let chunk = pool_of_one_string(65_536, len);
    let mut budget = MAX_POOL_TEXT;
    let pool = parse_string_pool(&chunk, &mut budget);
    assert_eq!(pool.len(), MAX_POOL_TEXT / len);
    assert!(pool.iter().map(String::len).sum::<usize>() <= MAX_POOL_TEXT);
}

/// Attributes all naming the largest pool entry stop resolving once the
/// element-text budget is spent, and the element is dropped.
#[test]
fn element_text_stops_at_the_budget() {
    let pool = vec!["x".repeat(1000)];
    let attrs = 512_usize;
    let mut el = vec![0u8; 36 + attrs * 20];
    el[24..26].copy_from_slice(&20u16.to_le_bytes());
    el[26..28].copy_from_slice(&20u16.to_le_bytes());
    el[28..30].copy_from_slice(&(attrs as u16).to_le_bytes());
    // Element name, attribute names and raw values are all index 0.
    let mut budget = usize::MAX;
    let full = parse_start_element(&el, &pool, &mut budget).unwrap();
    assert_eq!(full.attrs.len(), attrs);
    assert_eq!(usize::MAX - budget, 1000 * (1 + 2 * attrs));

    let mut budget = 100_000;
    assert!(parse_start_element(&el, &pool, &mut budget).is_none());
    assert_eq!(budget, 0);
}

#[test]
fn truncated_input_yields_what_was_read() {
    let full = doc();
    for cut in [8, 20, 40, full.len() / 2] {
        // Must not panic on any prefix.
        let _ = parse(&full[..cut.min(full.len())]);
    }
}
