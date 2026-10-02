use super::*;

fn entry(out: &mut Vec<u8>, magic: &str, name: &str, body: &[u8], mode: u32) {
    if magic == "070707" {
        out.extend_from_slice(
            format!(
                "070707{:06o}{:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                0,
                1,
                2,
                3,
                1,
                0,
                4,
                name.len() + 1,
                body.len()
            )
            .as_bytes(),
        );
    } else {
        out.extend_from_slice(magic.as_bytes());
        for value in [
            1,
            mode,
            2,
            3,
            1,
            4,
            body.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ] {
            out.extend_from_slice(format!("{value:08x}").as_bytes());
        }
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    if magic != "070707" {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    out.extend_from_slice(body);
    if magic != "070707" {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
}

fn fixture(magic: &str) -> Vec<u8> {
    let mut data = Vec::new();
    entry(&mut data, magic, "./padding", b"x", 0o100644);
    entry(
        &mut data,
        magic,
        "./postinstall",
        b"#!/bin/sh\necho ready\n",
        0o100755,
    );
    entry(&mut data, magic, "TRAILER!!!", b"", 0);
    data
}

#[test]
fn ascii_variants_index_exact_extents_and_identity() {
    for magic in ["070707", "070701", "070702"] {
        let bytes = fixture(magic);
        let parsed = crate::FileId::from_path_and_bytes(std::path::Path::new("Scripts"), &bytes);
        assert_eq!(parsed.file_type(), crate::FileType::Cpio);
        assert!(parsed.file_type().is_archive());
        assert_eq!(
            parsed.file_type().archive_format(),
            Some(crate::ArchiveFormat::Cpio)
        );
        let mut values = Values::new();
        let mut members = Vec::new();
        extract(&bytes, &mut values, &mut Metrics::new(), &mut members).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[1].path, "./postinstall");
        assert_eq!(
            members[1].ownership.as_ref().unwrap().mode_octal,
            Some(0o100755)
        );
        let start = members[1].offsets.data.unwrap() as usize;
        assert_eq!(
            &bytes[start..start + members[1].size_bytes as usize],
            b"#!/bin/sh\necho ready\n"
        );
    }
}

#[test]
fn digit_runs_that_are_not_cpio_headers_keep_their_own_identity() {
    // The six-digit magic is six ordinary characters, so content detection
    // must see a complete, well-formed first header before claiming CPIO.
    for text in [
        b"070701,cost,units\n070702,12,3\n".as_slice(),
        b"070707 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        b"070707",
    ] {
        let parsed = crate::FileId::from_path_and_bytes(std::path::Path::new("report.csv"), text);
        assert_ne!(parsed.file_type(), crate::FileType::Cpio, "{text:?}");
    }
    // A header whose fields are outside its radix is not claimed either.
    let mut bytes = fixture("070701");
    bytes[109] = b'g';
    assert_ne!(
        crate::FileId::from_path_and_bytes(std::path::Path::new("x"), &bytes).file_type(),
        crate::FileType::Cpio
    );
}

#[test]
fn every_truncated_prefix_reports_incomplete() {
    for magic in ["070707", "070701", "070702"] {
        let bytes = fixture(magic);
        for end in 0..bytes.len() {
            assert!(
                extract(
                    &bytes[..end],
                    &mut Values::new(),
                    &mut Metrics::new(),
                    &mut Vec::new()
                )
                .is_err(),
                "{magic}, {end}"
            );
        }
    }
}

#[test]
fn bounded_metadata_and_partial_results() {
    let bytes = fixture("070707");
    let mut members = Vec::new();
    assert!(
        index(
            &bytes,
            &mut Values::new(),
            &mut members,
            1,
            MAX_METADATA_BYTES
        )
        .is_err()
    );
    assert_eq!(members.len(), 1);
    assert!(index(&bytes, &mut Values::new(), &mut Vec::new(), MAX_ENTRIES, 80).is_err());
    let mut bytes = fixture("070701");
    bytes[94..102].copy_from_slice(b"ffffffff");
    assert!(
        extract(
            &bytes,
            &mut Values::new(),
            &mut Metrics::new(),
            &mut Vec::new()
        )
        .is_err()
    );

    let mut bytes = Vec::new();
    entry(&mut bytes, "070707", "link", &[b'x'; 4096], 0o120777);
    entry(&mut bytes, "070707", "TRAILER!!!", b"", 0);
    let mut members = Vec::new();
    assert!(index(&bytes, &mut Values::new(), &mut members, MAX_ENTRIES, 500).is_err());
    assert!(
        members.is_empty(),
        "link allocation must obey metadata budget"
    );
}

#[test]
fn public_api_retains_partial_members_and_completion_state() {
    let mut bytes = fixture("070707");
    let parsed = crate::open(&bytes);
    assert_eq!(
        parsed.values().get("cpio.complete"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(parsed.archive_members().len(), 2);
    assert!(parsed.errors().is_empty());
    bytes.pop();
    let parsed = crate::open(&bytes);
    assert_eq!(
        parsed.values().get("cpio.complete"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(parsed.archive_members().len(), 2);
    assert!(!parsed.errors().is_empty());
    assert_eq!(
        crate::FileType::from_label("cpio"),
        Some(crate::FileType::Cpio)
    );
}

/// Members get the shared `archive.*` aggregates and an `archive.members`
/// value, including the members indexed before a truncation.
#[test]
fn members_and_aggregates_are_published_even_when_incomplete() {
    let mut bytes = fixture("070701");
    for complete in [true, false] {
        let (mut values, mut metrics, mut members) = (Values::new(), Metrics::new(), Vec::new());
        let result = extract(&bytes, &mut values, &mut metrics, &mut members);
        assert_eq!(result.is_ok(), complete);
        let listed = values
            .get("archive.members")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1]["path"], "./postinstall");
        assert_eq!(listed[1]["mode_octal"], 0o100755);
        assert_eq!(metrics.get("archive.member_count"), Some(2.0));
        assert_eq!(metrics.get("archive.file_count"), Some(2.0));
        // `./postinstall` is executable by mode alone.
        assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
        assert_eq!(metrics.get("archive.hidden_file_count"), Some(0.0));
        bytes.pop();
    }
}

#[test]
fn missing_body_padding_does_not_hide_the_complete_member() {
    let mut bytes = Vec::new();
    entry(&mut bytes, "070701", "postinstall", b"x", 0o100755);
    // Newc's one-byte body has three alignment bytes after it.
    bytes.truncate(bytes.len() - 3);
    let parsed = crate::open(&bytes);
    assert_eq!(parsed.archive_members().len(), 1);
    let member = &parsed.archive_members()[0];
    assert_eq!(member.path, "postinstall");
    assert_eq!(bytes[member.offsets.data.unwrap() as usize], b'x');
    assert_eq!(
        parsed.values().get("cpio.complete"),
        Some(&serde_json::json!(false))
    );
    assert!(!parsed.errors().is_empty());
}

#[test]
fn path_and_link_metadata_remain_unmodified() {
    let mut bytes = Vec::new();
    for name in ["../outside", "/absolute", "same", "same"] {
        entry(&mut bytes, "070707", name, b"../target", 0o120777);
    }
    entry(&mut bytes, "070707", "TRAILER!!!", b"", 0);
    let mut members = Vec::new();
    extract(
        &bytes,
        &mut Values::new(),
        &mut Metrics::new(),
        &mut members,
    )
    .unwrap();
    assert_eq!(
        members.iter().map(|m| m.path.as_str()).collect::<Vec<_>>(),
        ["../outside", "/absolute", "same", "same"]
    );
    assert!(
        members
            .iter()
            .all(|m| m.linkname.as_deref() == Some("../target"))
    );
}

#[test]
fn invalid_fields_names_and_trailers_are_errors() {
    let mut bytes = fixture("070707");
    bytes[18] = b'8';
    assert!(
        extract(
            &bytes,
            &mut Values::new(),
            &mut Metrics::new(),
            &mut Vec::new()
        )
        .is_err()
    );
    let mut bytes = fixture("070707");
    bytes[76] = 0;
    assert!(
        extract(
            &bytes,
            &mut Values::new(),
            &mut Metrics::new(),
            &mut Vec::new()
        )
        .is_err()
    );
    let mut bytes = Vec::new();
    entry(&mut bytes, "070701", "TRAILER!!!", b"x", 0);
    assert!(
        extract(
            &bytes,
            &mut Values::new(),
            &mut Metrics::new(),
            &mut Vec::new()
        )
        .is_err()
    );
    let mut bytes = fixture("070707");
    bytes.extend_from_slice(b"extra");
    assert!(
        extract(
            &bytes,
            &mut Values::new(),
            &mut Metrics::new(),
            &mut Vec::new()
        )
        .is_err()
    );
}
