use super::*;

fn scan(bytes: &[u8], pdb: Option<&str>) -> Values {
    let mut values = Values::new();
    emit(bytes, pdb, &mut values);
    values
}

fn text<'a>(values: &'a Values, key: &str) -> Option<&'a str> {
    values.get(key).and_then(JsonValue::as_str)
}

fn source_paths(values: &Values) -> Vec<&str> {
    values
        .get("build.source_paths")
        .and_then(JsonValue::as_array)
        .map(|paths| paths.iter().filter_map(JsonValue::as_str).collect())
        .unwrap_or_default()
}

#[test]
fn unix_home_path_names_the_builder() {
    let values = scan(b"..\0/home/alice/projects/sample/main.go\0more", None);
    assert_eq!(text(&values, "build.username"), Some("alice"));
    assert_eq!(text(&values, "build.user_home"), Some("/home/alice"));
    assert_eq!(
        source_paths(&values),
        ["/home/alice/projects/sample/main.go"]
    );
}

#[test]
fn macos_and_windows_homes_name_the_builder() {
    let mac = scan(b"\0/Users/bob/src/app/main.c\0", None);
    assert_eq!(text(&mac, "build.username"), Some("bob"));
    assert_eq!(text(&mac, "build.user_home"), Some("/Users/bob"));
    let win = scan(b"\0C:\\Users\\charlie\\source\\app.cpp\0", None);
    assert_eq!(text(&win, "build.username"), Some("charlie"));
    assert_eq!(text(&win, "build.user_home"), Some("C:\\Users\\charlie"));
}

/// A CI account is not a person, but its home is what attributes a pipeline
/// build: `/home/runner` alone is a GitHub Actions runner.
#[test]
fn ci_runner_home_is_reported_without_a_username() {
    let values = scan(b"\0/home/runner/work/app/app/main.go\0", None);
    assert_eq!(text(&values, "build.username"), None);
    assert_eq!(text(&values, "build.user_home"), Some("/home/runner"));
}

/// A person alongside a CI home: the person and their home win.
#[test]
fn named_builder_home_wins_over_ci_home() {
    let values = scan(
        b"\0/home/runner/go/pkg/mod/x.go\0/home/zed/src/app/main.go\0",
        None,
    );
    assert_eq!(text(&values, "build.username"), Some("zed"));
    assert_eq!(text(&values, "build.user_home"), Some("/home/zed"));
}

#[test]
fn several_builders_name_nobody() {
    let values = scan(
        b"\0/home/alice/a.go\0/home/bob/b.go\0/Users/carol/c.go\0",
        None,
    );
    assert_eq!(text(&values, "build.username"), None);
    assert_eq!(text(&values, "build.user_home"), None);
    assert_eq!(source_paths(&values).len(), 3);
}

#[test]
fn repeated_paths_are_kept_once_and_capped() {
    let mut bytes = Vec::new();
    for _ in 0..100 {
        bytes.extend_from_slice(b"\0/home/alice/src/main.go\0");
    }
    for i in 0..(MAX_SOURCE_PATHS * 2) {
        bytes.extend_from_slice(format!("\0/home/alice/src/f{i}.go\0").as_bytes());
    }
    let values = scan(&bytes, None);
    let paths = source_paths(&values);
    assert_eq!(paths.len(), MAX_SOURCE_PATHS);
    assert_eq!(
        paths
            .iter()
            .filter(|p| **p == "/home/alice/src/main.go")
            .count(),
        1
    );
}

#[test]
fn path_ends_at_a_non_path_byte() {
    let values = scan(b"\0/home/alice/src/main.go\" glued text\0", None);
    assert_eq!(source_paths(&values), ["/home/alice/src/main.go"]);
}

#[test]
fn pdb_username_wins_over_the_scan() {
    let values = scan(
        b"\0C:\\Users\\scanned\\proj\\a.cpp\0",
        Some("C:\\Users\\dev\\source\\repos\\app\\Release\\app.pdb"),
    );
    assert_eq!(text(&values, "build.username"), Some("dev"));
    // The scan saw a different home; the PDB user's home is unknown.
    assert_eq!(text(&values, "build.user_home"), None);
}

#[test]
fn pdb_username_parsing() {
    assert_eq!(
        username_from_pdb("C:/Users/alice/proj/x.pdb").as_deref(),
        Some("alice")
    );
    assert!(username_from_pdb("C:\\Users\\runner\\work\\x.pdb").is_none());
    assert!(username_from_pdb("D:\\agent\\build\\sample.pdb").is_none());
    assert!(username_from_pdb("C:\\Users\\").is_none());
}

#[test]
fn nothing_to_report_without_builder_paths() {
    let values = scan(b"\0/usr/lib/libc.so.6\0/home/\0", None);
    assert!(values.get("build.username").is_none());
    assert!(values.get("build.user_home").is_none());
    assert!(values.get("build.source_paths").is_none());
}
