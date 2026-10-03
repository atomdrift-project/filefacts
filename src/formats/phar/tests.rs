use super::*;
use crate::FileType;

/// One packaged file for [`build`].
struct Member<'a> {
    name: &'a str,
    content: &'a [u8],
    flags: u32,
    metadata: &'a [u8],
}

fn member<'a>(name: &'a str, content: &'a [u8]) -> Member<'a> {
    Member {
        name,
        content,
        flags: 0o644,
        metadata: b"",
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// A native phar as PHP writes one: `stub`, the manifest, the contents, and
/// (with `signature`, a phar signature kind) a digest trailer.
fn build(stub: &[u8], members: &[Member<'_>], metadata: &[u8], signature: Option<u32>) -> Vec<u8> {
    let mut manifest = Vec::new();
    put_u32(&mut manifest, members.len() as u32);
    manifest.extend_from_slice(&[0x11, 0x00]);
    put_u32(
        &mut manifest,
        if signature.is_some() {
            FLAG_SIGNATURE
        } else {
            0
        },
    );
    put_prefixed(&mut manifest, b"test.phar");
    put_prefixed(&mut manifest, metadata);
    for m in members {
        put_prefixed(&mut manifest, m.name.as_bytes());
        put_u32(&mut manifest, m.content.len() as u32);
        put_u32(&mut manifest, 1_700_000_000);
        put_u32(&mut manifest, m.content.len() as u32);
        put_u32(&mut manifest, crc32fast::hash(m.content));
        put_u32(&mut manifest, m.flags);
        put_prefixed(&mut manifest, m.metadata);
    }
    let mut out = stub.to_vec();
    put_prefixed(&mut out, &manifest);
    for m in members {
        out.extend_from_slice(m.content);
    }
    if let Some(kind) = signature {
        let digest = match kind {
            0x02 => Sha1::digest(&out).to_vec(),
            0x03 => Sha256::digest(&out).to_vec(),
            other => panic!("no test digest for kind {other}"),
        };
        out.extend_from_slice(&digest);
        put_u32(&mut out, kind);
        out.extend_from_slice(SIGNATURE_MAGIC);
    }
    out
}

const STUB: &[u8] = b"<?php Phar::mapPhar('test.phar'); __HALT_COMPILER(); ?>\r\n";

fn run(data: &[u8]) -> (Values, Metrics, Vec<ArchiveMember>) {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut members = Vec::new();
    extract(data, &mut values, &mut metrics, &mut members).unwrap();
    (values, metrics, members)
}

/// Every packaged file is listed at its byte range, after the stub, which is
/// listed too: it is the code PHP runs first.
#[test]
fn lists_the_stub_and_every_member_at_its_offset() {
    let data = build(
        STUB,
        &[
            member("index.php", b"<?php echo 1;"),
            member("lib/a.php", b"<?php a();"),
        ],
        b"",
        Some(0x02),
    );
    let (values, metrics, members) = run(&data);

    assert_eq!(
        values
            .get("archive.format.kind")
            .and_then(JsonValue::as_str),
        Some("phar")
    );
    assert_eq!(
        values.get("phar.api_version").and_then(JsonValue::as_str),
        Some("1.1.0")
    );
    assert_eq!(
        values.get("phar.alias").and_then(JsonValue::as_str),
        Some("test.phar")
    );
    assert_eq!(metrics.get("phar.stub_size"), Some(STUB.len() as f64));
    assert_eq!(metrics.get("archive.member_count"), Some(3.0));

    let paths: Vec<_> = members.iter().map(|m| m.path.as_str()).collect();
    assert_eq!(paths, [STUB_NAME, "index.php", "lib/a.php"]);
    for m in &members {
        let start = m.offsets.data.unwrap() as usize;
        let slice = &data[start..start + m.size_bytes as usize];
        match m.path.as_str() {
            STUB_NAME => assert_eq!(slice, STUB),
            "index.php" => assert_eq!(slice, b"<?php echo 1;"),
            _ => assert_eq!(slice, b"<?php a();"),
        }
    }
}

/// The digest trailer is checked against the bytes it covers.
#[test]
fn a_signature_is_verified_and_tampering_breaks_it() {
    for kind in [0x02, 0x03] {
        let data = build(STUB, &[member("a.php", b"<?php ok();")], b"", Some(kind));
        let (values, ..) = run(&data);
        let signature = values.get("phar.signature").unwrap();
        assert_eq!(signature["valid"], JsonValue::Bool(true), "{signature}");

        let mut tampered = data.clone();
        let at = tampered.len() - 30 - if kind == 0x03 { 12 } else { 0 };
        tampered[at] ^= 0x20;
        let (values, ..) = run(&tampered);
        assert_eq!(
            values.get("phar.signature").unwrap()["valid"],
            JsonValue::Bool(false)
        );
    }
}

/// Metadata is unserialized whenever the archive is opened through
/// `phar://`, so the objects it would build are named.
#[test]
fn serialized_objects_in_metadata_are_named() {
    let mut gadget = member("a.php", b"<?php");
    gadget.metadata = br#"a:1:{i:0;O:11:"Evil\Gadget":1:{s:3:"cmd";s:2:"id";}}"#;
    let data = build(STUB, &[gadget], br#"O:8:"stdClass":0:{}"#, None);
    let (values, metrics, _) = run(&data);
    assert_eq!(
        values.get("phar.metadata_classes"),
        Some(&json!(["stdClass", "Evil\\Gadget"]))
    );
    assert_eq!(metrics.get("phar.metadata_object_count"), Some(2.0));
}

/// `O:` and `C:` that are not a well-formed object header are not counted.
#[test]
fn class_names_need_a_well_formed_object_header() {
    let mut classes = Vec::new();
    let count = serialized_classes(br#"s:5:"O:1:x";O:3:"Foo"O:9:"Bar":0:{}"#, &mut classes);
    assert_eq!(
        (count, classes.as_slice()),
        (1, ["Foo".to_string()].as_slice())
    );
}

/// A compressed member says so, and its range is its compressed size.
#[test]
fn compressed_members_carry_their_method() {
    let mut deflated = member("big.php", b"\x01\x02\x03");
    deflated.flags = ENTRY_DEFLATE | 0o644;
    let data = build(STUB, &[deflated], b"", None);
    let (_, metrics, members) = run(&data);
    let m = &members[1];
    assert_eq!(
        m.compression.as_ref().and_then(|c| c.method.as_deref()),
        Some("deflate")
    );
    assert_eq!(
        metrics.get("archive.compression.method_counts.deflate"),
        Some(1.0)
    );
}

/// A member whose bytes would run past the end of the file is listed but not
/// offered for slicing.
#[test]
fn members_past_the_end_are_not_sliceable() {
    let mut data = build(STUB, &[member("a.php", b"<?php 123456789;")], b"", None);
    data.truncate(data.len() - 4);
    let (values, _, members) = run(&data);
    assert_eq!(members.len(), 1, "only the stub");
    let limits = values
        .get("phar.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits[0]["stage"], "truncated");
}

/// The stub ends where PHP's reader says: a ` ?>` after the token is part of
/// it, as is one newline after that, and nothing else is.
#[test]
fn the_stub_ends_where_php_says() {
    for (tail, extra) in [
        (&b""[..], 0),
        (b" ?>", 3),
        (b" ?>\n", 4),
        (b" ?>\r\n", 5),
        (b"\n?>\n", 4),
        (b"\n", 0),
    ] {
        let mut data = b"<?php __HALT_COMPILER();".to_vec();
        let token_end = data.len();
        data.extend_from_slice(tail);
        data.extend_from_slice(b"rest");
        assert_eq!(stub_end(&data, token_end), token_end + extra, "{tail:?}");
    }
}

/// A PHP file that merely contains the token is not a phar.
#[test]
fn the_token_alone_is_not_a_phar() {
    assert!(!is_phar(
        b"<?php echo 'x'; __HALT_COMPILER(); trailing data"
    ));
    assert!(!is_phar(b"<?php echo 'no token here';"));
    assert!(!is_phar(b"plain text that ends in GBMB"));
}

/// Detection: a native phar is a phar whatever its stub, and a `.phar` name on
/// a zip- or tar-based one is not a mismatch.
#[test]
fn identified_as_phar_whatever_the_stub() {
    let php = build(STUB, &[member("a.php", b"<?php")], b"", None);
    let id = crate::fileid::FileId::from_path_and_bytes(std::path::Path::new("tool.phar"), &php);
    assert_eq!(id.file_type(), FileType::Phar);
    assert!(!id.extension_mismatch());

    let shebang = build(
        b"#!/usr/bin/env php\n<?php __HALT_COMPILER();",
        &[member("a.php", b"<?php")],
        b"",
        None,
    );
    let id = crate::fileid::FileId::from_path_and_bytes(std::path::Path::new("tool"), &shebang);
    assert_eq!(id.file_type(), FileType::Phar);

    // An image header in front: still the archive `phar://` opens.
    let mut stub = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00".to_vec();
    stub.extend_from_slice(b"<?php __HALT_COMPILER(); ?>");
    let polyglot = build(&stub, &[member("x.php", b"<?php")], b"", Some(0x02));
    let id =
        crate::fileid::FileId::from_path_and_bytes(std::path::Path::new("avatar.jpg"), &polyglot);
    assert_eq!(id.file_type(), FileType::Phar);
    assert!(id.extension_mismatch());
}

#[test]
fn a_zip_named_phar_is_consistent() {
    let mut zip = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut zip));
        w.start_file(".phar/stub.php", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut w, b"<?php __HALT_COMPILER();").unwrap();
        w.finish().unwrap();
    }
    let id = crate::fileid::FileId::from_path_and_bytes(std::path::Path::new("tool.phar"), &zip);
    assert_eq!(id.file_type(), FileType::Zip);
    assert!(!id.extension_mismatch());
}
