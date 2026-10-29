use super::*;

fn run(content: &str) -> Metrics {
    let mut m = Metrics::new();
    emit(content, &mut m);
    m
}

#[test]
fn empty_content_emits_nothing() {
    let m = run("");
    assert!(m.is_empty());
}

#[test]
fn invisible_chars_carry_their_byte_positions() {
    // "ab<ZWSP>cd<ZWJ>ef": ZWSP (U+200B, 3 bytes) at byte 2, ZWJ (U+200D)
    // at byte 7. The count is exact and the spans pinpoint each char.
    let m = run("ab\u{200B}cd\u{200D}ef");
    assert_eq!(m.get("text.invisible_chars"), Some(2.0));
    assert_eq!(
        m.fact("text.invisible_chars").unwrap().spans,
        vec![Span::new(2, 3), Span::new(7, 3)]
    );
}

#[test]
fn max_line_length_locates_the_longest_line() {
    // "ab\nABCDE\nx": longest line "ABCDE" (5) starts at byte 3.
    let m = run("ab\nABCDE\nx");
    assert_eq!(m.get("text.max_line_length"), Some(5.0));
    assert_eq!(
        m.fact("text.max_line_length").unwrap().spans,
        vec![Span::new(3, 5)]
    );
}

#[test]
fn max_line_length_offset_survives_crlf() {
    // CRLF terminators: "a\r\nLONGER\r\n" → "LONGER" (6) starts at byte 3
    // ("a"=1 + "\r\n"=2). Locks the terminator-byte accounting.
    let m = run("a\r\nLONGER\r\n");
    assert_eq!(m.get("text.max_line_length"), Some(6.0));
    assert_eq!(
        m.fact("text.max_line_length").unwrap().spans,
        vec![Span::new(3, 6)]
    );
}

#[test]
fn adjacent_invisible_chars_coalesce_into_one_span() {
    // "a<ZWSP><ZWSP>b": two ZWSP (U+200B, 3 bytes each) at bytes 1 and 4 —
    // contiguous, so one span [1, 6); the count still reflects both chars.
    let m = run("a\u{200B}\u{200B}b");
    assert_eq!(m.get("text.invisible_chars"), Some(2.0));
    assert_eq!(
        m.fact("text.invisible_chars").unwrap().spans,
        vec![Span::new(1, 6)]
    );
}

#[test]
fn simple_content_emits_line_count_and_entropy() {
    let m = run("hello world\n");
    assert_eq!(m.get("text.lines"), Some(1.0));
    assert!(m.get("text.char_entropy").unwrap_or(0.0) > 0.0);
}

#[test]
fn long_lines_are_counted() {
    let long_line = "x".repeat(250);
    let content = format!("{}\n{}\nshort", long_line, long_line);
    let m = run(&content);
    assert_eq!(m.get("text.lines_over_200"), Some(2.0));
    assert!(m.get("text.lines_over_500").is_none());
}

#[test]
fn hex_escapes_are_counted() {
    let m = run(r#"buf = "\x90\x90\x90\x41\x42""#);
    assert!(m.get("text.hex_escape_count").unwrap_or(0.0) >= 5.0);
}

#[test]
fn repeated_sequences_are_counted() {
    let m = run("aaaaaaaaaaaaa normal bbbbbbbbbbbbb");
    assert_eq!(m.get("text.repeated_char_sequences"), Some(2.0));
}

#[test]
fn whitespace_metrics_emit() {
    let m = run("  spaces\n\ttabs\n");
    assert!(m.get("text.tab_count").unwrap_or(0.0) > 0.0);
    assert!(m.get("text.space_count").unwrap_or(0.0) > 0.0);
    assert_eq!(m.get("text.mixed_indent"), Some(1.0));
}

#[test]
fn max_inline_whitespace_run_detects_payload_padding() {
    let padded = format!("export default config;{}global['!']=1;", " ".repeat(500));
    let m = run(&padded);
    assert_eq!(m.get("text.max_whitespace_run"), Some(500.0));

    // Leading indent should not count.
    let indented = format!("{}function foo() {{}}", " ".repeat(200));
    let m = run(&indented);
    assert_eq!(m.get("text.max_whitespace_run"), Some(1.0));
}
