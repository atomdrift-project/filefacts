use std::io::Write as _;

use super::*;

const KEY: u32 = 0x4242_4242;

/// A protocol-2 pickle of `{name: [(offset ^ KEY, length ^ KEY, b"")]}`, the
/// index shape Ren'Py writes.
fn index_pickle(name: &str, offset: u32, length: u32) -> Vec<u8> {
    let mut p = vec![0x80, 2, b'}', b'('];
    p.push(b'X');
    p.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
    p.extend_from_slice(name.as_bytes());
    p.extend_from_slice(b"](");
    for field in [offset ^ KEY, length ^ KEY] {
        p.push(b'J');
        p.extend_from_slice(&field.to_le_bytes());
    }
    p.extend_from_slice(&[b'C', 0, b't', b'a', b'u', b'.']);
    p
}

/// An RPA-3.0 archive holding one member, `a.txt` = `hello`, with `index`
/// as its compressed index.
fn archive(index: &[u8]) -> Vec<u8> {
    let payload = b"hello";
    let index_offset = 34 + payload.len();
    let mut out = format!("RPA-3.0 {index_offset:016x} {KEY:08x}\n").into_bytes();
    assert_eq!(out.len(), 34);
    out.extend_from_slice(payload);
    out.extend_from_slice(index);
    out
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn run(bytes: &[u8]) -> (Result<(), Error>, Values, Metrics, Vec<ArchiveMember>) {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut members = Vec::new();
    let result = extract(bytes, &mut values, &mut metrics, &mut members);
    (result, values, metrics, members)
}

#[test]
fn reads_the_index_and_reports_its_members() {
    let bytes = archive(&zlib(&index_pickle("a.txt", 34, 5)));
    let (result, values, metrics, members) = run(&bytes);
    result.expect("well-formed archive");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].path, "a.txt");
    assert_eq!(members[0].size_bytes, 5);
    assert_eq!(members[0].offsets.data, Some(34));
    assert_eq!(metrics.get("rpa.member_count"), Some(1.0));
    assert_eq!(metrics.get("rpa.version"), Some(3.0));
    assert_eq!(metrics.get("rpa.unreferenced_payload_bytes"), Some(0.0));
    assert_eq!(
        values
            .get("rpa.key_is_default")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        values
            .get("rpa.members[0].chunks[0].payload_hex_preview")
            .and_then(JsonValue::as_str),
        Some("68656c6c6f")
    );
    assert_eq!(
        values
            .get("rpa.index.pickle_protocol")
            .and_then(JsonValue::as_u64),
        Some(2)
    );
}

#[test]
fn damaged_index_keeps_the_header_facts() {
    let bytes = archive(b"not zlib at all");
    let (result, values, _, members) = run(&bytes);
    let error = result.expect_err("the index cannot be read");
    assert!(error.to_string().contains("invalid zlib index"), "{error}");
    assert!(members.is_empty());
    assert_eq!(
        values.get("rpa.complete").and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(
        values.get("rpa.index_offset").and_then(JsonValue::as_u64),
        Some(39)
    );
}

#[test]
fn executable_pickle_is_refused() {
    // GLOBAL (`c`) would import a Python callable; the reader never does.
    let mut pickle = vec![0x80, 2];
    pickle.extend_from_slice(b"cos\nsystem\n.");
    let (result, ..) = run(&archive(&zlib(&pickle)));
    let error = result.expect_err("GLOBAL is not interpreted");
    assert!(error.to_string().contains("opcode 0x63"), "{error}");
}

#[test]
fn extent_outside_the_payload_region_is_refused() {
    let bytes = archive(&zlib(&index_pickle("a.txt", 34, 500)));
    let (result, ..) = run(&bytes);
    assert!(result.is_err());
}

#[test]
fn bad_header_is_malformed() {
    let (result, values, ..) = run(b"RPA-3.0 zzzzzzzzzzzzzzzz 42424242\n");
    assert!(result.is_err());
    assert!(values.get("rpa").is_none());
}

/// The public index reader hands a host each member's runs, through the
/// crate-root `rpa` module.
#[test]
fn public_members_name_each_run() {
    let bytes = archive(&zlib(&index_pickle("a.txt", 34, 5)));
    let members = crate::rpa::members(&bytes).expect("well-formed archive");
    assert_eq!(
        members,
        [Member {
            path: "a.txt".into(),
            chunks: vec![Chunk {
                offset: 34,
                length: 5,
                prefix: Vec::new(),
            }],
            size: 5,
        }]
    );
    assert!(crate::rpa::members(b"not an archive").is_err());
}
