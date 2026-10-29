use super::*;

fn fixture() -> Vec<u8> {
    let header = br#"{"files":{"main.js":{"size":18,"offset":"0"},"package.json":{"size":2,"offset":"18"},"lib":{"files":{"inner.js":{"size":3,"offset":"20"}}}}}"#;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&((header.len() + 8) as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(b"console.log('x');{}abc");
    bytes
}

#[test]
fn extracts_asar_archive_members() {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut members = Vec::new();
    extract(&fixture(), &mut values, &mut metrics, &mut members).unwrap();

    assert_eq!(
        values
            .get("archive.format.kind")
            .and_then(JsonValue::as_str),
        Some("asar")
    );
    assert_eq!(metrics.get("archive.member_count"), Some(3.0));
    assert_eq!(metrics.get("archive.directory_count"), Some(1.0));
    assert_eq!(metrics.get("archive.script_count"), Some(2.0));
    assert_eq!(members.len(), 3);
    let main = members.iter().find(|m| m.path == "main.js").unwrap();
    assert_eq!(main.offsets.data, Some(header_len_for_test()));
}

/// Past the shared member cap, files are counted, not listed.
#[test]
fn members_past_the_cap_are_not_listed() {
    let total = MAX_ARCHIVE_MEMBERS + 3;
    let mut header = String::from(r#"{"files":{"#);
    for i in 0..total {
        if i > 0 {
            header.push(',');
        }
        header.push_str(&format!(r#""f{i}":{{"size":0,"offset":"0"}}"#));
    }
    header.push_str("}}");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&((header.len() + 8) as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(header.as_bytes());

    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut members = Vec::new();
    extract(&bytes, &mut values, &mut metrics, &mut members).unwrap();
    assert_eq!(members.len(), MAX_ARCHIVE_MEMBERS);
    let limits = values
        .get("asar.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("member-cap"));
}

/// Every file below a deep chain of long directory names repeats the
/// chain in its path; the walk stops when the paths outgrow the budget.
#[test]
fn walk_stops_at_the_path_budget() {
    let long = "d".repeat(200);
    let mut header = String::new();
    for _ in 0..20 {
        header.push_str(&format!(r#"{{"files":{{"{long}":"#));
    }
    header.push_str(r#"{"files":{"a":{"size":1,"offset":"0"},"b":{"size":1,"offset":"0"}}}"#);
    for _ in 0..20 {
        header.push_str("}}");
    }
    let JsonValue::Object(root) = serde_json::from_str::<JsonValue>(&header).unwrap() else {
        panic!("header is an object");
    };
    let files = root["files"].as_object().unwrap();
    // Room for the 20 directory paths and one of the two files.
    let dir_paths: usize = (1..=20).map(|depth| 201 * depth - 1).sum();
    let file_path = 20 * 201 + 1;
    let mut walk = Walk {
        data_offset: 0,
        members: Vec::new(),
        stats: ArchiveStats::new(AGGS),
        directory_count: 0,
        unlisted: 0,
        path_budget: dir_paths + file_path + file_path / 2,
        path_capped: false,
    };
    let mut members = Vec::new();
    walk_files("", files, &mut walk, &mut members);
    assert!(walk.path_capped);
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].path.len(), file_path);
}

fn header_len_for_test() -> u64 {
    let header = br#"{"files":{"main.js":{"size":18,"offset":"0"},"package.json":{"size":2,"offset":"18"},"lib":{"files":{"inner.js":{"size":3,"offset":"20"}}}}}"#;
    (header.len() + 16) as u64
}
