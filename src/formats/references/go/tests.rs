use super::*;

#[test]
fn go_directives_handle_comments_quotes_and_adjacent_arrow() {
    assert_eq!(
        words("replace example.test/lib=>../fork// comment").unwrap(),
        ["replace", "example.test/lib", "=>", "../fork"]
    );
    assert_eq!(
        words("use \"./folder//name\" // comment").unwrap(),
        ["use", "./folder//name"]
    );
    assert!(words("use \"unfinished").is_none());
    assert!(words(&"token ".repeat(65)).is_none());
}

#[test]
fn go_vendor_truncation_is_explicit() {
    let text = "# example.test/lib v1.0.0\n".repeat(20_001);
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("vendor/modules.txt"))
        .open(text.as_bytes());
    assert!(
        parsed
            .references()
            .iter()
            .any(|r| r.source == source::INCOMPLETE)
    );
}
