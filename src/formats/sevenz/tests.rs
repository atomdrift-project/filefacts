use super::*;

const ID_LZMA2: &[u8] = &[0x21];

/// A 7z NUMBER in its longest form: an all-ones lead byte, then eight
/// little-endian bytes.
fn number(n: u64) -> Vec<u8> {
    let mut out = vec![0xFF];
    out.extend_from_slice(&n.to_le_bytes());
    out
}

/// Signature header pointing at `next_header`, which follows `packed`
/// directly, with every CRC valid so only the sizes are under test.
fn archive_with_packed(packed: &[u8], next_header: &[u8], declared_size: u64) -> Vec<u8> {
    let mut start = Vec::new();
    start.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    start.extend_from_slice(&declared_size.to_le_bytes());
    start.extend_from_slice(&crc32fast::hash(next_header).to_le_bytes());
    let mut out = SIGNATURE.to_vec();
    out.extend_from_slice(&[0, 4]);
    out.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(packed);
    out.extend_from_slice(next_header);
    out
}

fn archive_with(next_header: &[u8], declared_size: u64) -> Vec<u8> {
    archive_with_packed(&[], next_header, declared_size)
}

/// One property of a `FilesInfo` block: id, size, body.
fn property(id: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(number(body.len() as u64));
    out.extend_from_slice(body);
    out
}

/// One bit per flag, most significant first.
fn bits(flags: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; flags.len().div_ceil(8)];
    for (i, _) in flags.iter().enumerate().filter(|(_, f)| **f) {
        out[i / 8] |= 0x80 >> (i % 8);
    }
    out
}

/// A member of a fixture archive: its name, and the size of its data
/// stream (`None` for a directory).
struct Entry<'a> {
    name: &'a str,
    stream: Option<&'a [u8]>,
}

/// A header with one folder whose coder chain is `coders` (the first is the
/// final decoder, each later one feeding the one before), unpacking into one
/// stream per entry with data, over `packed_len` packed bytes. `mtime` is the
/// FILETIME every entry records, if any.
fn header(coders: &[&[u8]], entries: &[Entry<'_>], packed_len: u64, mtime: Option<u64>) -> Vec<u8> {
    let streams: Vec<&[u8]> = entries.iter().filter_map(|e| e.stream).collect();
    let total: u64 = streams.iter().map(|s| s.len() as u64).sum();
    let mut h = vec![K_HEADER];
    if !streams.is_empty() {
        h.extend_from_slice(&[K_MAIN_STREAMS_INFO, K_PACK_INFO]);
        h.extend(number(0));
        h.extend(number(1));
        h.push(K_SIZE);
        h.extend(number(packed_len));
        h.extend_from_slice(&[K_END, K_UNPACK_INFO, K_FOLDER]);
        h.extend(number(1));
        h.push(0);
        h.extend(number(coders.len() as u64));
        for id in coders {
            h.push(u8::try_from(id.len()).unwrap());
            h.extend_from_slice(id);
        }
        for i in 1..coders.len() as u64 {
            h.extend(number(i - 1));
            h.extend(number(i));
        }
        h.push(K_CODERS_UNPACK_SIZE);
        for _ in coders {
            h.extend(number(total));
        }
        h.extend_from_slice(&[K_END, K_SUB_STREAMS_INFO, K_NUM_UNPACK_STREAM]);
        h.extend(number(streams.len() as u64));
        h.push(K_SIZE);
        for s in streams.iter().take(streams.len() - 1) {
            h.extend(number(s.len() as u64));
        }
        h.extend_from_slice(&[K_CRC, 1]);
        for s in &streams {
            h.extend_from_slice(&crc32fast::hash(s).to_le_bytes());
        }
        h.extend_from_slice(&[K_END, K_END]);
    }
    h.push(K_FILES_INFO);
    h.extend(number(entries.len() as u64));
    let empty: Vec<bool> = entries.iter().map(|e| e.stream.is_none()).collect();
    if empty.contains(&true) {
        h.extend(property(K_EMPTY_STREAM, &bits(&empty)));
    }
    let mut names = vec![0u8];
    for e in entries {
        for unit in e.name.encode_utf16().chain([0]) {
            names.extend_from_slice(&unit.to_le_bytes());
        }
    }
    h.extend(property(K_NAME, &names));
    if let Some(ticks) = mtime {
        let mut body = vec![1, 0];
        for _ in entries {
            body.extend_from_slice(&ticks.to_le_bytes());
        }
        h.extend(property(K_MTIME, &body));
    }
    h.extend_from_slice(&[K_END, K_END]);
    h
}

/// An archive holding `entries` under the coder chain `coders`. The packed
/// bytes are filler: the walk never decodes them.
fn archive(coders: &[&[u8]], entries: &[Entry<'_>]) -> Vec<u8> {
    let packed = [0x5a; 20];
    let h = header(coders, entries, packed.len() as u64, None);
    archive_with_packed(&packed, &h, h.len() as u64)
}

fn run(bytes: &[u8]) -> Result<(Values, Metrics, Vec<ArchiveMember>), Error> {
    let (mut values, mut metrics, mut members) = (Values::new(), Metrics::new(), Vec::new());
    extract(bytes, &mut values, &mut metrics, &mut members)?;
    Ok((values, metrics, members))
}

fn rejected_because(bytes: &[u8], why: &str) {
    let err = run(bytes).expect_err("hostile header must be refused");
    assert!(err.to_string().contains(why), "{err}");
}

/// A next header the file cannot back is refused before it is read.
#[test]
fn next_header_size_past_the_file_is_refused() {
    let header = [K_HEADER, K_END];
    rejected_because(
        &archive_with(&header, 1 << 40),
        "next header larger than cap",
    );
    rejected_because(&archive_with(&header, 1 << 20), "next header overruns file");
}

/// An encoded header's folder declares the decoded size; one past the cap
/// is refused before decoding a byte.
#[test]
fn encoded_header_unpack_size_over_cap_is_refused() {
    let mut header = vec![K_ENCODED_HEADER, K_PACK_INFO, 0, 1, K_SIZE, 1, K_END];
    // One folder, one simple COPY coder.
    header.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER, 1, 0, 1, 0x01, 0x00]);
    header.push(K_CODERS_UNPACK_SIZE);
    header.extend(number(1 << 40));
    header.extend_from_slice(&[K_END, K_END]);
    let len = header.len() as u64;
    rejected_because(
        &archive_with(&header, len),
        "decoded header larger than cap",
    );
}

/// Per-file tables are sized by the declared file count up front.
#[test]
fn file_count_the_header_cannot_hold_is_refused() {
    let mut header = vec![K_HEADER, K_FILES_INFO];
    header.extend(number(1 << 40));
    header.extend_from_slice(&[K_END, K_END]);
    let len = header.len() as u64;
    rejected_because(
        &archive_with(&header, len),
        "declared count exceeds header size",
    );
}

/// A zeroed start header leaves nothing to locate the header by.
#[test]
fn zeroed_start_header_is_refused() {
    let mut bytes = SIGNATURE.to_vec();
    bytes.extend_from_slice(&[0, 4]);
    bytes.extend_from_slice(&[0; 24]);
    bytes.extend_from_slice(&[K_HEADER, K_END]);
    rejected_because(&bytes, "start header is zeroed");
}

#[test]
fn header_walk_emits_members_without_reading_payloads() {
    let body = b"not an executable";
    let bytes = archive(
        &[ID_LZMA2],
        &[
            Entry {
                name: "drop",
                stream: None,
            },
            Entry {
                name: "drop\\Setup.exe",
                stream: Some(body),
            },
        ],
    );
    let (values, metrics, typed_members) = run(&bytes).unwrap();

    let members = values.get("archive.members").unwrap().as_array().unwrap();
    let setup = members
        .iter()
        .find(|member| {
            member["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("Setup.exe"))
        })
        .unwrap();
    assert_eq!(setup["path"].as_str(), Some("drop/Setup.exe"));
    assert_eq!(setup["size_bytes"].as_u64(), Some(17));
    assert_eq!(setup["entry_type"].as_str(), Some("regular"));
    assert_eq!(setup["compression_method"].as_str(), Some("lzma2"));
    assert_eq!(setup["compressed_size"].as_u64(), Some(20));
    assert_eq!(
        setup["crc32"].as_u64(),
        Some(u64::from(crc32fast::hash(body)))
    );
    assert_eq!(members[0]["entry_type"].as_str(), Some("directory"));
    assert_eq!(
        values
            .get("archive.format.kind")
            .and_then(serde_json::Value::as_str),
        Some("7z")
    );
    assert_eq!(metrics.get("archive.file_count"), Some(1.0));
    // Emitted even when nothing is encrypted: a rule gated on `min: 1`
    // and the ML feature both need absence to be a reported zero rather
    // than a missing key.
    assert_eq!(metrics.get("archive.security.encrypted_count"), Some(0.0));
    assert_eq!(typed_members.len(), members.len());
}

/// Several files share one folder's output; each gets its own size and CRC,
/// and the folder's packed size is charged to its first file only.
#[test]
fn solid_folder_streams_split_by_substream_sizes() {
    let bytes = archive(
        &[ID_LZMA2],
        &[
            Entry {
                name: "a",
                stream: Some(b"aaaa"),
            },
            Entry {
                name: "b",
                stream: Some(b"bb"),
            },
        ],
    );
    let (_, metrics, members) = run(&bytes).unwrap();
    assert_eq!(members[0].size_bytes, 4);
    assert_eq!(members[1].size_bytes, 2);
    assert_eq!(members[1].crc32, Some(crc32fast::hash(b"bb")));
    assert_eq!(members[0].compression.compressed_size, Some(20));
    assert_eq!(members[1].compression.compressed_size, None);
    assert_eq!(metrics.get("archive.uncompressed_size"), Some(6.0));
}

/// Past the shared member cap, files are counted in the limit, not
/// listed.
#[test]
fn members_past_the_cap_are_not_listed() {
    let total = MAX_ARCHIVE_MEMBERS + 3;
    let names: Vec<String> = (0..total).map(|i| format!("f{i}")).collect();
    let entries: Vec<Entry<'_>> = names
        .iter()
        .map(|name| Entry { name, stream: None })
        .collect();
    let bytes = archive(&[ID_LZMA2], &entries);

    let (values, _, typed_members) = run(&bytes).unwrap();
    assert_eq!(typed_members.len(), MAX_ARCHIVE_MEMBERS);
    let limits = values
        .get("7z.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("member-cap"));
    assert_eq!(
        limits[0]["reason"].as_str(),
        Some(format!("listed {MAX_ARCHIVE_MEMBERS} of {total} members").as_str())
    );
}

/// The shape the malicious bundles use: AES-encrypted payload streams with
/// the header left in the clear, so the member table still reads without a
/// password. 7z expresses that through the folder's coder chain rather than
/// a per-entry flag, which is why it needs its own count.
#[test]
fn aes_payload_streams_are_counted_as_encrypted() {
    let bytes = archive(
        &[ID_LZMA2, ID_AES256SHA256],
        &[Entry {
            name: "Setup.exe",
            stream: Some(b"not an executable"),
        }],
    );
    let (_, metrics, typed_members) = run(&bytes).unwrap();
    assert_eq!(metrics.get("archive.security.encrypted_count"), Some(1.0));
    assert!(typed_members.iter().all(|member| member.encrypted));
    assert_eq!(
        typed_members[0].compression.method.as_deref(),
        Some("lzma2+aes256sha256")
    );
}

/// Modification times are FILETIMEs, reported as Unix seconds.
#[test]
fn mtimes_convert_from_filetime() {
    let entries = [Entry {
        name: "a",
        stream: None,
    }];
    // 2001-09-09T01:46:40Z.
    let ticks = (1_000_000_000 + FILETIME_UNIX_DIFF_SECS as u64) * 10_000_000;
    let h = header(&[ID_LZMA2], &entries, 0, Some(ticks));
    let (_, _, members) = run(&archive_with(&h, h.len() as u64)).unwrap();
    assert_eq!(members[0].mtime_unix, Some(1_000_000_000));
}

/// The header 7-Zip writes by default is itself LZMA-packed; it is decoded
/// and read the same way.
#[test]
fn lzma_encoded_header_is_decoded() {
    let entries = [Entry {
        name: "inner.txt",
        stream: Some(b"hello"),
    }];
    let plain = header(&[ID_LZMA2], &entries, 20, None);
    let options = lzma_rust2::LzmaOptions::with_preset(6);
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &options, false).unwrap();
    let props = writer.props();
    std::io::Write::write_all(&mut writer, &plain).unwrap();
    let packed_header = writer.finish().unwrap();

    // Payload filler, then the packed header, then the EncodedHeader that
    // points at it.
    let mut packed = vec![0x5a; 20];
    let header_pos = packed.len() as u64;
    packed.extend_from_slice(&packed_header);
    let mut encoded = vec![K_ENCODED_HEADER, K_PACK_INFO];
    encoded.extend(number(header_pos));
    encoded.extend(number(1));
    encoded.push(K_SIZE);
    encoded.extend(number(packed_header.len() as u64));
    encoded.extend_from_slice(&[K_END, K_UNPACK_INFO, K_FOLDER]);
    encoded.extend(number(1));
    encoded.push(0);
    encoded.extend(number(1));
    // A simple coder with properties: id length 3, `0x20` for the props.
    encoded.push(0x20 | 3);
    encoded.extend_from_slice(ID_LZMA);
    encoded.extend(number(5));
    encoded.push(props);
    encoded.extend_from_slice(&(1u32 << 20).to_le_bytes());
    encoded.push(K_CODERS_UNPACK_SIZE);
    encoded.extend(number(plain.len() as u64));
    encoded.extend_from_slice(&[K_END, K_END]);
    let bytes = archive_with_packed(&packed, &encoded, encoded.len() as u64);

    let (_, _, members) = run(&bytes).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].path, "inner.txt");
    assert_eq!(members[0].size_bytes, 5);
}

/// An encrypted header has no member table to read without the password.
#[test]
fn encrypted_header_is_malformed() {
    let mut encoded = vec![K_ENCODED_HEADER, K_PACK_INFO, 0, 1, K_SIZE, 1, K_END];
    encoded.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER, 1, 0, 1, 0x04]);
    encoded.extend_from_slice(ID_AES256SHA256);
    encoded.push(K_CODERS_UNPACK_SIZE);
    encoded.extend(number(16));
    encoded.extend_from_slice(&[K_END, K_END]);
    rejected_because(
        &archive_with_packed(&[0], &encoded, encoded.len() as u64),
        "header is encrypted",
    );
}
