#![allow(clippy::unwrap_used)]
use super::*;

/// Obfuscate `plain` the way the launcher's builder does: the inverse of
/// [`Deobfuscate`], with the key restarting every `block` bytes.
fn obfuscate(plain: &[u8], name: &str, block: usize) -> Vec<u8> {
    let key = entry_key(name);
    plain
        .iter()
        .enumerate()
        .map(|(i, &p)| (!p ^ key[(i % block) % key.len()]).rotate_left(4))
        .collect()
}

fn zlib(plain: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).unwrap();
    encoder.finish().unwrap()
}

/// One raw table entry: header, UTF-16LE name, data as given.
fn raw_entry(name: &str, flags: u32, data: &[u8], declared_len: u32) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut entry = Vec::new();
    entry.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
    entry.extend_from_slice(&flags.to_le_bytes());
    entry.extend_from_slice(&[0; 2]);
    entry.extend_from_slice(&declared_len.to_le_bytes());
    entry.extend_from_slice(&[0; 8]);
    entry.extend_from_slice(&1u16.to_le_bytes());
    entry.extend_from_slice(&name);
    entry.extend_from_slice(data);
    entry
}

/// An entry holding `plain`, zlib-compressed and obfuscated in 1024-byte
/// blocks, as real launchers store their files.
fn entry(name: &str, plain: &[u8]) -> Vec<u8> {
    let data = obfuscate(&zlib(plain), name, BLOCK_LEN);
    raw_entry(
        name,
        FLAG_OBFUSCATED | FLAG_OBFUSCATED_BLOCKS,
        &data,
        u32::try_from(data.len()).unwrap(),
    )
}

fn stream(declared_count: u16, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = MAGIC.to_vec();
    stream.extend_from_slice(&declared_count.to_le_bytes());
    stream.extend_from_slice(&3u32.to_le_bytes());
    stream.resize(HEADER_LEN, 0);
    for entry in entries {
        stream.extend_from_slice(entry);
    }
    stream
}

/// Every entry of `stream`, decoded under `limit`.
fn decode_all(stream: &[u8], limit: u64) -> Vec<(String, Result<Vec<u8>, Error>)> {
    entries(stream)
        .unwrap()
        .entries
        .iter()
        .map(|entry| {
            let mut out = Vec::new();
            let result = decode_entry(stream, entry, &mut out, limit).map(|_| out);
            (entry.name.clone(), result)
        })
        .collect()
}

#[test]
fn lists_and_decodes_obfuscated_zlib_entries() {
    // Longer than one block, so the per-block key restart is exercised.
    let msi: Vec<u8> = (0..5000u32).flat_map(|i| (i * 7).to_le_bytes()).collect();
    let ini: Vec<u8> = "[Startup]\r\nProduct=Example\r\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data = stream(
        2,
        &[entry("Example Product.msi", &msi), entry("Setup.ini", &ini)],
    );
    let listing = entries(&data).unwrap();
    assert!(listing.complete);
    assert_eq!(listing.declared, 2);
    assert_eq!(listing.entries[0].name, "Example Product.msi");
    assert_eq!(listing.entries[0].offset, HEADER_LEN + 24 + 38);
    let decoded = decode_all(&data, 1 << 20);
    assert_eq!(decoded[0].1.as_ref().unwrap(), &msi);
    assert_eq!(decoded[1].1.as_ref().unwrap(), &ini);
}

#[test]
fn whole_run_obfuscation_and_plain_entries() {
    let whole = obfuscate(&zlib(b"whole run"), "a.txt", usize::MAX);
    let data = stream(
        2,
        &[
            raw_entry(
                "a.txt",
                FLAG_OBFUSCATED,
                &whole,
                u32::try_from(whole.len()).unwrap(),
            ),
            raw_entry("b.txt", 0, b"stored as is", 12),
        ],
    );
    let decoded = decode_all(&data, 1 << 20);
    assert_eq!(decoded[0].1.as_ref().unwrap(), b"whole run");
    assert_eq!(decoded[1].1.as_ref().unwrap(), b"stored as is");
}

#[test]
fn rejects_non_streams_and_truncated_headers() {
    assert!(entries(b"MZ\x90\x00").is_err());
    assert!(entries(&MAGIC[..10]).is_err());
    assert!(entries(&stream(1, &[])[..20]).is_err());
    // A header that declares entries but holds none lists nothing.
    let listing = entries(&stream(5, &[])).unwrap();
    assert!(listing.entries.is_empty());
    assert!(!listing.complete);
}

#[test]
fn truncated_tables_keep_the_entries_before_the_cut() {
    let mut data = stream(
        2,
        &[
            entry("first.bin", b"kept"),
            entry("second.bin", &[0x5a; 4096]),
        ],
    );
    data.truncate(data.len() - 10);
    let listing = entries(&data).unwrap();
    assert!(!listing.complete);
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(decode_all(&data, 64)[0].1.as_ref().unwrap(), b"kept");
}

#[test]
fn oversized_declared_lengths_fail_gracefully() {
    // Data length far past the end of the input.
    let listing = entries(&stream(1, &[raw_entry("big.bin", 0, b"tiny", u32::MAX)])).unwrap();
    assert!(listing.entries.is_empty());
    // Name length past the end of the input and past the name limit.
    let mut huge_name = raw_entry("n", 0, b"", 0);
    huge_name[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        entries(&stream(1, &[huge_name]))
            .unwrap()
            .entries
            .is_empty()
    );
    // More entries declared than the limit allows.
    let many = u16::try_from(MAX_ENTRIES + 1).unwrap();
    assert!(entries(&stream(many, &[entry("a", b"a")])).is_err());
    // An entry describing bytes outside the slice it is decoded from.
    let outside = Entry {
        name: "x".into(),
        flags: 0,
        offset: usize::MAX - 1,
        stored_size: 4,
    };
    assert!(decode_entry(b"short", &outside, &mut Vec::new(), 64).is_err());
}

#[test]
fn corrupt_payloads_bombs_and_unnamed_keys_are_errors() {
    // A zlib header whose body is garbage.
    let mut corrupt = zlib(&[7; 4096]);
    let mid = corrupt.len() / 2;
    corrupt[mid..].fill(0xff);
    // An obfuscated entry with no name has no key.
    let unnamed = raw_entry("", FLAG_OBFUSCATED, b"xx", 2);
    // A small stream expanding far past the limit.
    let bomb = zlib(&vec![0u8; 4 << 20]);
    let data = stream(
        4,
        &[
            raw_entry(
                "corrupt.bin",
                0,
                &corrupt,
                u32::try_from(corrupt.len()).unwrap(),
            ),
            unnamed,
            raw_entry("bomb.bin", 0, &bomb, u32::try_from(bomb.len()).unwrap()),
            entry("fine.bin", b"fine"),
        ],
    );
    let decoded = decode_all(&data, 1 << 20);
    assert!(decoded[0].1.is_err(), "corrupt deflate");
    assert!(decoded[1].1.is_err(), "no key");
    assert!(decoded[2].1.is_err(), "past the limit");
    assert_eq!(decoded[3].1.as_ref().unwrap(), b"fine");
}

#[test]
fn find_skips_magic_without_a_table() {
    // The launcher's own code names the magic before the real stream.
    let mut data = b"MZ....".to_vec();
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(&[0xff; 64]);
    let at = data.len();
    data.extend_from_slice(&stream(1, &[entry("Setup.ini", b"x")]));
    assert_eq!(find(&data), Some(at));
    assert_eq!(find(b"no stream here"), None);
}

#[test]
fn key_matches_the_launcher_scheme() {
    assert_eq!(
        entry_key("splash.bmp")[..4],
        [b's' ^ 0x13, b'p' ^ 0x35, b'l' ^ 0x86, b'a' ^ 0x07]
    );
    // Characters outside Latin-1 narrow to `?` before keying.
    assert_eq!(entry_key("\u{4e2d}")[..], [b'?' ^ 0x13]);
    assert!(is_zlib(&[0x78, 0x9c]));
    assert!(!is_zlib(&[0x78, 0x9d]));
    assert!(!is_zlib(b"MZ"));
}

/// A launcher is named `installshield` with its table in the values.
#[test]
fn installer_values_list_the_stream() {
    let mut data = b"MZ".to_vec();
    data.resize(256, 0);
    let at = data.len();
    data.extend_from_slice(&stream(
        2,
        &[entry("Setup.ini", b"x"), entry("Product.msi", b"y")],
    ));
    assert_eq!(
        super::super::detect(&data, &[]),
        Some(("installshield", Some(at)))
    );
    let mut values = crate::output::Values::default();
    super::super::emit(&data, &[], &mut values);
    let installer = values
        .lookup(crate::value_key!("binary.installer"))
        .unwrap();
    assert_eq!(installer["kind"], "installshield");
    assert_eq!(installer["entry_count"], 2);
    assert_eq!(installer["entries"][1]["name"], "Product.msi");
    let offset = usize::try_from(installer["entries"][0]["offset"].as_u64().unwrap()).unwrap();
    assert_eq!(offset, at + HEADER_LEN + 24 + 18);
}
