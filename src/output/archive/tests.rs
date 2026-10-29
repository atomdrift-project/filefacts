use super::*;

/// The serde form is the flat `archive.members[]` object, and it reads
/// back to the same member.
#[test]
fn member_serializes_flat_and_round_trips() {
    let member = ArchiveMember {
        mtime_unix: Some(5),
        crc32: Some(7),
        compression: ArchiveCompression::new(Some(2), Some("deflate".into())),
        ownership: ArchiveOwnership {
            uid: Some(1),
            ..ArchiveOwnership::mode(0o644)
        },
        offsets: ArchiveOffsets {
            header: Some(0),
            data: Some(30),
            central_header: None,
        },
        ..ArchiveMember::new("a.txt".into(), 4, EntryType::Regular)
    };
    let json = serde_json::to_value(&member).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "path": "a.txt",
            "size_bytes": 4,
            "entry_type": "regular",
            "mtime_unix": 5,
            "crc32": 7,
            "compressed_size": 2,
            "compression_method": "deflate",
            "mode_octal": 0o644,
            "uid": 1,
            "header_offset": 0,
            "data_offset": 30,
        })
    );
    assert_eq!(
        serde_json::from_value::<ArchiveMember>(json).unwrap(),
        member
    );
    let encrypted = ArchiveMember {
        encrypted: true,
        ..ArchiveMember::new("b".into(), 0, EntryType::CharDevice)
    };
    let json = serde_json::to_value(&encrypted).unwrap();
    assert_eq!(json["encrypted"], true);
    assert_eq!(json["entry_type"], "char-device");
    assert_eq!(
        serde_json::from_value::<ArchiveMember>(json).unwrap(),
        encrypted
    );
}
