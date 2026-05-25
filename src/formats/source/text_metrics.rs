//! Language-agnostic text metrics.
//!
//! Emits `text.*` metrics derived purely from the byte stream — character
//! distribution, line statistics, whitespace forensics, escape-sequence
//! density, invisible-character stego signals. None of these need a
//! tree-sitter parse, so the helper runs on any source-text input.
//!
//! Ported from cleave's `analyzers/text_metrics.rs` as part of the
//! cleave→filefacts architecture migration. The original built a typed
//! `TextMetrics` struct and flattened it into a metric map; here we
//! emit straight into [`Metrics`] under the canonical `text.*` keys.

use crate::output::Metrics;

/// Emit `text.*` metrics computed from `content`.
///
/// Pure byte/character analysis: no AST required, language-agnostic.
/// Each metric is only written when its value is non-zero — keeps the
/// flat metric map sparse and matches the legacy `skip_serializing_if`
/// behaviour from cleave's typed-struct era.
pub(super) fn emit(content: &str, metrics: &mut Metrics) {
    if content.is_empty() {
        return;
    }

    emit_byte_metrics(content.as_bytes(), metrics);
    emit_line_metrics(content, metrics);
    emit_char_metrics(content, metrics);
    emit_escape_metrics(content, metrics);
}

fn emit_byte_metrics(bytes: &[u8], metrics: &mut Metrics) {
    let total = bytes.len();
    if total == 0 {
        return;
    }

    let mut freq = [0u64; 256];
    let mut non_ascii = 0usize;
    let mut non_printable = 0usize;
    let mut null_count = 0u32;
    let mut high_byte = 0usize;

    for &b in bytes {
        freq[b as usize] += 1;
        if b == 0 {
            null_count += 1;
        }
        if b > 127 {
            non_ascii += 1;
            high_byte += 1;
        }
        if (b < 32 && b != 9 && b != 10 && b != 13) || b == 127 {
            non_printable += 1;
        }
    }

    let unique_chars = freq.iter().filter(|&&c| c > 0).count() as u32;
    let entropy = crate::scan::entropy::shannon_from_histogram(&freq, total);

    // Most common non-whitespace byte
    let most_common = freq
        .iter()
        .enumerate()
        .filter(|&(b, &count)| count > 0 && !matches!(b as u8, b' ' | b'\t' | b'\n' | b'\r'))
        .max_by_key(|&(_, &count)| count)
        .map(|(b, _)| b as u8);

    let most_common_ratio = most_common
        .map(|c| freq[c as usize] as f64 / total as f64)
        .unwrap_or(0.0);

    if entropy > 0.0 {
        metrics.insert("text.char_entropy", entropy);
    }
    if unique_chars > 0 {
        metrics.insert("text.unique_chars", f64::from(unique_chars));
    }
    if let Some(c) = most_common {
        metrics.insert("text.most_common_char_codepoint", f64::from(c));
        metrics.insert(
            "text.most_common_char_is_null",
            if c == 0 { 1.0 } else { 0.0 },
        );
    }
    if most_common_ratio > 0.0 {
        metrics.insert("text.most_common_ratio", most_common_ratio);
    }
    if non_ascii > 0 {
        metrics.insert("text.non_ascii_ratio", non_ascii as f64 / total as f64);
    }
    if non_printable > 0 {
        metrics.insert(
            "text.non_printable_ratio",
            non_printable as f64 / total as f64,
        );
    }
    if null_count > 0 {
        metrics.insert("text.null_byte_count", f64::from(null_count));
    }
    if high_byte > 0 {
        metrics.insert("text.high_byte_ratio", high_byte as f64 / total as f64);
    }
}

fn emit_line_metrics(content: &str, metrics: &mut Metrics) {
    let mut total_lines = 0u32;
    let mut mean = 0.0f64;
    let mut m2 = 0.0f64;
    let mut max_line_length = 0u32;
    let mut lines_over_200 = 0u32;
    let mut lines_over_500 = 0u32;
    let mut lines_over_1000 = 0u32;
    let mut last_line_length = 0u32;
    let mut empty_lines = 0u32;
    let mut lines_with_tab_indent = 0u32;
    let mut lines_with_space_indent = 0u32;
    let mut trailing_whitespace_lines = 0u32;
    let mut max_inline_whitespace_run = 0u32;
    let mut ascii_art_lines = 0u32;

    for line in content.lines() {
        total_lines += 1;

        let len = line.len() as u32;
        max_line_length = max_line_length.max(len);

        // Welford's online algorithm for variance.
        let len_f = f64::from(len);
        let count_f = f64::from(total_lines);
        let delta = len_f - mean;
        mean += delta / count_f;
        let delta2 = len_f - mean;
        m2 += delta * delta2;

        if len > 200 {
            lines_over_200 += 1;
        }
        if len > 500 {
            lines_over_500 += 1;
        }
        if len > 1000 {
            lines_over_1000 += 1;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            empty_lines += 1;
        } else {
            last_line_length = len;
        }

        if !line.is_empty() && line.ends_with(|c: char| c.is_whitespace()) {
            trailing_whitespace_lines += 1;
        }

        let (has_tab_indent, has_space_indent, inline_ws_run) = scan_line_whitespace(line);
        if has_tab_indent {
            lines_with_tab_indent += 1;
        }
        if has_space_indent {
            lines_with_space_indent += 1;
        }
        max_inline_whitespace_run = max_inline_whitespace_run.max(inline_ws_run);

        if is_ascii_art_line(line) {
            ascii_art_lines += 1;
        }
    }

    if total_lines == 0 {
        return;
    }

    metrics.insert("text.total_lines", f64::from(total_lines));
    metrics.insert("text.avg_line_length", mean);
    metrics.insert("text.max_line_length", f64::from(max_line_length));
    if total_lines > 0 {
        let stddev = (m2 / f64::from(total_lines)).sqrt();
        if stddev > 0.0 {
            metrics.insert("text.line_length_stddev", stddev);
        }
    }
    if lines_over_200 > 0 {
        metrics.insert("text.lines_over_200", f64::from(lines_over_200));
    }
    if lines_over_500 > 0 {
        metrics.insert("text.lines_over_500", f64::from(lines_over_500));
    }
    if lines_over_1000 > 0 {
        metrics.insert("text.lines_over_1000", f64::from(lines_over_1000));
    }
    if last_line_length > 0 {
        metrics.insert("text.last_line_length", f64::from(last_line_length));
    }
    if empty_lines > 0 {
        metrics.insert(
            "text.empty_line_ratio",
            f64::from(empty_lines) / f64::from(total_lines),
        );
    }
    if lines_with_tab_indent > 0 && lines_with_space_indent > 0 {
        metrics.insert("text.mixed_indent", 1.0);
    }
    if trailing_whitespace_lines > 0 {
        metrics.insert(
            "text.trailing_whitespace_lines",
            f64::from(trailing_whitespace_lines),
        );
    }
    if max_inline_whitespace_run > 0 {
        metrics.insert(
            "text.max_inline_whitespace_run",
            f64::from(max_inline_whitespace_run),
        );
    }
    if ascii_art_lines > 0 {
        metrics.insert("text.ascii_art_lines", f64::from(ascii_art_lines));
    }
}

fn emit_char_metrics(content: &str, metrics: &mut Metrics) {
    let mut whitespace_count = 0usize;
    let mut tabs = 0u32;
    let mut spaces = 0u32;
    let mut unusual_whitespace = 0u32;
    let mut invisible_chars = 0u32;
    let mut current_token_bytes = 0usize;
    let mut long_token_count = 0u32;
    let mut prev_char = None;
    let mut run_length = 0u32;
    let mut repeated_char_sequences = 0u32;
    let mut digits = 0usize;
    let mut alphanumeric = 0usize;
    let mut is_first_char = true;

    for c in content.chars() {
        if c.is_whitespace() {
            whitespace_count += 1;
            match c {
                '\t' => tabs += 1,
                ' ' => spaces += 1,
                _ => {}
            }
            if is_unusual_whitespace(c) {
                unusual_whitespace += 1;
            }
            if current_token_bytes > 100 {
                long_token_count += 1;
            }
            current_token_bytes = 0;
        } else {
            current_token_bytes += c.len_utf8();
        }

        if is_invisible_char(c, is_first_char) {
            invisible_chars = invisible_chars.saturating_add(1);
        }

        if c.is_ascii_digit() {
            digits += 1;
            alphanumeric += 1;
        } else if c.is_ascii_alphabetic() {
            alphanumeric += 1;
        }

        if Some(c) == prev_char {
            run_length += 1;
        } else {
            if run_length >= 10 {
                repeated_char_sequences += 1;
            }
            prev_char = Some(c);
            run_length = 1;
        }

        is_first_char = false;
    }

    if current_token_bytes > 100 {
        long_token_count += 1;
    }
    if run_length >= 10 {
        repeated_char_sequences += 1;
    }

    let total = content.len();
    if total == 0 {
        return;
    }
    if whitespace_count > 0 {
        metrics.insert(
            "text.whitespace_ratio",
            whitespace_count as f64 / total as f64,
        );
    }
    if tabs > 0 {
        metrics.insert("text.tab_count", f64::from(tabs));
    }
    if spaces > 0 {
        metrics.insert("text.space_count", f64::from(spaces));
    }
    if unusual_whitespace > 0 {
        metrics.insert("text.unusual_whitespace", f64::from(unusual_whitespace));
    }
    if invisible_chars > 0 {
        metrics.insert("text.invisible_chars", f64::from(invisible_chars));
    }
    if long_token_count > 0 {
        metrics.insert("text.long_token_count", f64::from(long_token_count));
    }
    if repeated_char_sequences > 0 {
        metrics.insert(
            "text.repeated_char_sequences",
            f64::from(repeated_char_sequences),
        );
    }
    if alphanumeric > 0 && digits > 0 {
        metrics.insert("text.digit_ratio", digits as f64 / alphanumeric as f64);
    }
}

fn emit_escape_metrics(content: &str, metrics: &mut Metrics) {
    let bytes = content.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return;
    }
    let mut hex_count = 0u32;
    let mut unicode_count = 0u32;
    let mut octal_count = 0u32;
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'x' if i + 3 < len
                    && bytes[i + 2].is_ascii_hexdigit()
                    && bytes[i + 3].is_ascii_hexdigit() =>
                {
                    hex_count += 1;
                    i += 4;
                    continue;
                }
                b'u' if i + 5 < len => {
                    unicode_count += 1;
                    i += 2;
                    continue;
                }
                b'U' if i + 9 < len => {
                    unicode_count += 1;
                    i += 2;
                    continue;
                }
                b'0'..=b'7' => {
                    octal_count += 1;
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }

    if hex_count > 0 {
        metrics.insert("text.hex_escape_count", f64::from(hex_count));
    }
    if unicode_count > 0 {
        metrics.insert("text.unicode_escape_count", f64::from(unicode_count));
    }
    if octal_count > 0 {
        metrics.insert("text.octal_escape_count", f64::from(octal_count));
    }
    let total_escapes = hex_count + unicode_count + octal_count;
    if total_escapes > 0 {
        metrics.insert(
            "text.escape_density",
            (f64::from(total_escapes) / len as f64) * 100.0,
        );
    }
}

fn scan_line_whitespace(line: &str) -> (bool, bool, u32) {
    let mut has_tab_indent = false;
    let mut has_space_indent = false;

    for c in line.chars() {
        if c == '\t' {
            has_tab_indent = true;
        } else if c == ' ' {
            has_space_indent = true;
        } else {
            break;
        }
    }

    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return (has_tab_indent, has_space_indent, 0);
    }

    let mut current_run = 0u32;
    let mut max_run = 0u32;
    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            current_run += 1;
        } else {
            max_run = max_run.max(current_run);
            current_run = 0;
        }
    }

    (has_tab_indent, has_space_indent, max_run)
}

fn is_unusual_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}' | '\u{2000}'..='\u{200B}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

fn is_invisible_char(c: char, is_first_char: bool) -> bool {
    let cp = c as u32;
    if is_first_char && cp == 0xFEFF {
        return false;
    }

    (0xFE00..=0xFE0F).contains(&cp)
        || (0xE0100..=0xE01EF).contains(&cp)
        || (0xE0001..=0xE007F).contains(&cp)
        || matches!(cp, 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF)
}

fn is_ascii_art_line(line: &str) -> bool {
    let art_chars = ['=', '-', '*', '#', '+', '|', '/', '\\', '_', '.'];
    let trimmed = line.trim();
    if trimmed.len() < 20 {
        return false;
    }

    let art_count = trimmed
        .bytes()
        .filter(|b| art_chars.contains(&(*b as char)))
        .count();
    art_count as f64 / trimmed.len() as f64 > 0.7
}

#[cfg(test)]
mod tests {
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
    fn simple_content_emits_line_count_and_entropy() {
        let m = run("hello world\n");
        assert_eq!(m.get("text.total_lines"), Some(1.0));
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
        assert_eq!(m.get("text.max_inline_whitespace_run"), Some(500.0));

        // Leading indent should not count.
        let indented = format!("{}function foo() {{}}", " ".repeat(200));
        let m = run(&indented);
        assert_eq!(m.get("text.max_inline_whitespace_run"), Some(1.0));
    }
}
