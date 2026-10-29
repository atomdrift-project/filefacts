use super::*;
fn uleb(mut n: u32) -> Vec<u8> {
    let mut b = Vec::new();
    loop {
        let v = (n & 127) as u8;
        n >>= 7;
        b.push(v | if n > 0 { 128 } else { 0 });
        if n == 0 {
            return b;
        }
    }
}
fn sleb(mut n: i32) -> Vec<u8> {
    let mut b = Vec::new();
    loop {
        let v = (n & 127) as u8;
        n >>= 7;
        let end = (n == 0 && v & 64 == 0) || (n == -1 && v & 64 != 0);
        b.push(v | if end { 0 } else { 128 });
        if end {
            return b;
        }
    }
}
fn constant(b: &mut Vec<u8>, n: i32) {
    b.push(0x41);
    b.extend(sleb(n));
}
fn section(b: &mut Vec<u8>, id: u8, body: &[u8]) {
    b.push(id);
    b.extend(uleb(body.len() as u32));
    b.extend(body);
}
fn fixture(address: i32, dest: i32, key: i32, text: &[u8], active: bool) -> Vec<u8> {
    let mut f = vec![0];
    constant(&mut f, 0);
    f.extend([0x21, 0, 0x03, 0x40, 0x20, 0]);
    constant(&mut f, text.len() as i32);
    f.extend([0x49, 0x04, 0x40, 0x20, 0, 0x20, 0]);
    constant(&mut f, address);
    f.extend([0x6a, 0x2d, 0, 0]);
    constant(&mut f, key);
    f.extend([0x20, 0]);
    constant(&mut f, 3);
    f.push(0x71);
    constant(&mut f, 3);
    f.extend([0x74, 0x76, 0x73, 0x3a, 0]);
    f.extend(uleb(dest as u32));
    f.extend([0x20, 0]);
    constant(&mut f, 1);
    f.extend([0x6a, 0x21, 0, 0x0c, 1, 0x0b, 0x0b, 0x0b]);
    let mut code = vec![1];
    code.extend(uleb(f.len() as u32));
    code.extend(f);
    let mut data = vec![1, if active { 0 } else { 1 }];
    if active {
        constant(&mut data, address);
        data.push(0x0b);
    }
    data.extend(uleb(text.len() as u32));
    let k = key.to_le_bytes();
    data.extend(text.iter().enumerate().map(|(i, b)| b ^ k[i & 3]));
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    section(&mut out, 10, &code);
    section(&mut out, 11, &data);
    out
}
#[test]
fn varying_addresses_and_keys() {
    for (a, k) in [(200, 0x12345678), (0x218b9, -726414543), (64, 0x7e)] {
        let b = fixture(a, a, k, b"hello world", true);
        let got = recover(&b);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].bytes, b"hello world");
        assert!(got[0].offset < b.len());
    }
}
#[test]
fn rejects_zero_key() {
    assert!(recover(&fixture(256, 256, 0, b"hello world", true)).is_empty());
}
#[test]
fn rejects_unbound_destination() {
    assert!(recover(&fixture(256, 257, 7, b"hello world", true)).is_empty());
}
#[test]
fn rejects_passive_data() {
    assert!(recover(&fixture(256, 256, 7, b"hello world", false)).is_empty());
}
#[test]
fn truncation_never_panics() {
    let b = fixture(0x20000, 0x20000, 0x12345678, b"a longer test message", true);
    for n in 0..b.len() {
        let _ = recover(&b[..n]);
    }
}
