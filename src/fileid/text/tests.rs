use super::*;

#[test]
fn one_classifier_for_text_and_scripts() {
    // A line of plain text, and one with ANSI colour that only a script
    // grammar excuses.
    let colour = b"echo \x1b[31mred\x1b[0m \x1b[32mgreen\x1b[0m \x1b[1mbold\x1b[0m";
    assert!(!is_binary(b"plain text with a\ttab\r\n", Controls::Text));
    assert!(is_binary(colour, Controls::Text));
    assert!(!is_binary(colour, Controls::Script));
    // Object code is binary under either reading.
    let code = [0xb4, 0x4e, 0xba, 0x10, 0x01, 0xcd, 0x21, 0x00, 0x00, 0x01];
    assert!(is_binary(&code, Controls::Text));
    assert!(is_binary(&code, Controls::Script));
    // Too short to judge, and high bytes are never control bytes.
    assert!(!is_binary(b"\x00\x01", Controls::Text));
    assert_eq!(control_bytes("caf\u{e9}".as_bytes(), Controls::Text), 0);
}

#[test]
fn case_insensitive_search() {
    assert_eq!(find_ci(b"xx<SCRIPT", b"<script"), Some(2));
    assert_eq!(find_ci(b"<scrip", b"<script"), None);
    assert!(contains(b"a needle here", b"needle"));
    assert!(!contains(b"a Needle here", b"needle"));
    assert!(contains_ci(b"a Needle here", b"needle"));
    assert!(starts_ci(b"REM x", b"rem"));
    assert!(!contains(b"anything", b""));
}
