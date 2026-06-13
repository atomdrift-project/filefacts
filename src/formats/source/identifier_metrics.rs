//! Identifier metrics ported from cleave.
//!
//! Walks the tree once collecting identifier nodes for the configured
//! language, then emits `identifiers.*` keys describing length, entropy,
//! naming patterns, and obfuscation indicators (single-char, hex-like,
//! base64-like, sequential, keyboard, repeated-character).

use std::collections::HashSet;

use tree_sitter::Node;

use crate::output::Metrics;

use super::langs::LangConfig;

/// Keyboard row patterns for detecting keyboard-walk names.
const KEYBOARD_PATTERNS: &[&str] = &[
    "qwerty", "qwert", "asdf", "asdfg", "zxcv", "zxcvb", "qazwsx", "qaz", "wsx", "edc", "rfv",
    "ytrewq", "fdsa", "gfdsa", "vcxz",
];

/// Collect identifier strings from the tree for the configured grammar.
pub(super) fn collect_identifiers<'a>(
    root: Node<'a>,
    source: &'a str,
    config: &LangConfig,
) -> Vec<&'a str> {
    let mut idents = Vec::new();
    let bytes = source.as_bytes();
    let mut stack: Vec<Node<'a>> = vec![root];
    while let Some(node) = stack.pop() {
        if config.identifier_kinds.contains(&node.kind()) {
            if let Ok(text) = node.utf8_text(bytes) {
                if !text.is_empty() {
                    idents.push(text);
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    idents
}

/// Emit `identifiers.*` metrics for the collected list.
pub(super) fn emit(identifiers: &[&str], metrics: &mut Metrics) {
    if identifiers.is_empty() {
        return;
    }

    let total = identifiers.len() as u32;
    let unique: HashSet<&str> = identifiers.iter().copied().collect();
    let unique_count = unique.len() as u32;

    metrics.insert("identifiers.total", f64::from(total));
    metrics.insert("identifiers.unique_count", f64::from(unique_count));
    if total > 0 {
        metrics.insert(
            "identifiers.reuse_ratio",
            f64::from(unique_count) / f64::from(total),
        );
    }

    // Length analysis over the unique set.
    let lengths: Vec<usize> = unique.iter().map(|s| s.len()).collect();
    if !lengths.is_empty() {
        let total_len: usize = lengths.iter().sum();
        let avg_length = total_len as f64 / lengths.len() as f64;
        metrics.insert("identifiers.avg_length", avg_length);
        metrics.insert(
            "identifiers.min_length",
            *lengths.iter().min().unwrap_or(&0) as f64,
        );
        metrics.insert(
            "identifiers.max_length",
            *lengths.iter().max().unwrap_or(&0) as f64,
        );

        let variance: f64 = lengths
            .iter()
            .map(|&len| {
                let diff = len as f64 - avg_length;
                diff * diff
            })
            .sum::<f64>()
            / lengths.len() as f64;
        let stddev = variance.sqrt();
        if stddev > 0.0 {
            metrics.insert("identifiers.length_stddev", stddev);
        }
    }

    let mut single_char = 0u32;
    let mut all_lowercase = 0u32;
    let mut all_uppercase = 0u32;
    let mut has_digit = 0u32;
    let mut underscore_prefix = 0u32;
    let mut double_underscore = 0u32;
    let mut numeric_suffix = 0u32;
    let mut hex_like = 0u32;
    let mut base64_like = 0u32;
    let mut sequential = 0u32;
    let mut keyboard_pattern = 0u32;
    let mut repeated_char = 0u32;
    let mut high_entropy = 0u32;
    let mut entropy_sum = 0.0f64;

    for ident in &unique {
        let s = *ident;
        let len = s.len();

        if len == 1 {
            single_char += 1;
        }
        if s.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            all_lowercase += 1;
        }
        if s.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            all_uppercase += 1;
        }
        if s.chars().any(|c| c.is_ascii_digit()) {
            has_digit += 1;
        }
        if s.starts_with('_') {
            underscore_prefix += 1;
        }
        if s.starts_with("__") && s.ends_with("__") && len > 4 {
            double_underscore += 1;
        }
        if len > 1
            && s.chars().last().is_some_and(|c| c.is_ascii_digit())
            && s.chars().take(len - 1).any(|c| c.is_ascii_alphabetic())
        {
            numeric_suffix += 1;
        }
        if is_hex_like(s) {
            hex_like += 1;
        }
        if is_base64_like(s) {
            base64_like += 1;
        }
        if is_sequential(s) {
            sequential += 1;
        }
        let lower = s.to_ascii_lowercase();
        if KEYBOARD_PATTERNS.iter().any(|p| lower.contains(p)) {
            keyboard_pattern += 1;
        }
        if len >= 3 {
            if let Some(first_char) = s.chars().next() {
                if s.chars().all(|c| c == first_char) {
                    repeated_char += 1;
                }
            }
        }

        let entropy = string_entropy(s);
        entropy_sum += entropy;
        if entropy > 3.5 {
            high_entropy += 1;
        }
    }

    let denom = f64::from(unique_count);
    if single_char > 0 {
        metrics.insert("identifiers.single_char_count", f64::from(single_char));
        metrics.insert(
            "identifiers.single_char_ratio",
            f64::from(single_char) / denom,
        );
    }
    if all_lowercase > 0 {
        metrics.insert(
            "identifiers.all_lowercase_ratio",
            f64::from(all_lowercase) / denom,
        );
    }
    if all_uppercase > 0 {
        metrics.insert(
            "identifiers.all_uppercase_ratio",
            f64::from(all_uppercase) / denom,
        );
    }
    if has_digit > 0 {
        metrics.insert("identifiers.has_digit_ratio", f64::from(has_digit) / denom);
    }
    if underscore_prefix > 0 {
        metrics.insert(
            "identifiers.underscore_prefix_count",
            f64::from(underscore_prefix),
        );
    }
    if double_underscore > 0 {
        metrics.insert(
            "identifiers.double_underscore_count",
            f64::from(double_underscore),
        );
    }
    if numeric_suffix > 0 {
        metrics.insert(
            "identifiers.numeric_suffix_count",
            f64::from(numeric_suffix),
        );
    }
    if hex_like > 0 {
        metrics.insert("identifiers.hex_like_names", f64::from(hex_like));
    }
    if base64_like > 0 {
        metrics.insert("identifiers.base64_like_names", f64::from(base64_like));
    }
    if sequential > 0 {
        metrics.insert("identifiers.sequential_names", f64::from(sequential));
    }
    if keyboard_pattern > 0 {
        metrics.insert(
            "identifiers.keyboard_pattern_names",
            f64::from(keyboard_pattern),
        );
    }
    if repeated_char > 0 {
        metrics.insert("identifiers.repeated_char_names", f64::from(repeated_char));
    }
    if denom > 0.0 {
        metrics.insert("identifiers.avg_entropy", entropy_sum / denom);
    }
    if high_entropy > 0 {
        metrics.insert("identifiers.high_entropy_count", f64::from(high_entropy));
        metrics.insert(
            "identifiers.high_entropy_ratio",
            f64::from(high_entropy) / denom,
        );
    }
}

/// Shannon entropy in bits over the byte distribution of `s`.
/// Thin wrapper around [`crate::scan::entropy::shannon`] so the
/// math stays in one place and any future tweak (e.g. lazy
/// histogram construction) lands once.
pub(super) fn string_entropy(s: &str) -> f64 {
    crate::scan::entropy::shannon(s.as_bytes())
}

fn is_hex_like(s: &str) -> bool {
    if s.len() < 6 {
        return false;
    }
    let hex_chars = s.bytes().filter(u8::is_ascii_hexdigit).count();
    let ratio = hex_chars as f64 / s.len() as f64;
    ratio > 0.9 && s.len() % 2 == 0
}

fn is_base64_like(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    let ratio = base64_chars as f64 / s.len() as f64;
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    ratio > 0.95 && has_upper && has_lower && has_digit
}

fn is_sequential(s: &str) -> bool {
    if s.len() <= 2 {
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(a), None) if a.is_ascii_alphabetic() => return true,
            (Some(a), Some(b)) if a.is_ascii_alphabetic() && b.is_ascii_digit() => return true,
            _ => {}
        }
    }
    if s.len() >= 2 {
        if let Some(last) = s.chars().last() {
            if last.is_ascii_digit() {
                // The final ASCII digit is one byte, so the byte before it is a
                // char boundary — slice the prefix instead of reallocating it.
                let prefix = &s[..s.len() - 1];
                let common = [
                    "var", "tmp", "temp", "arg", "param", "item", "val", "x", "y", "z", "i", "j",
                    "k",
                ];
                if common.iter().any(|p| prefix.eq_ignore_ascii_case(p)) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_identifiers_emit_nothing() {
        let mut m = Metrics::new();
        emit(&[], &mut m);
        assert!(m.is_empty());
    }

    #[test]
    fn basic_counts() {
        let mut m = Metrics::new();
        emit(&["foo", "bar", "baz", "foo"], &mut m);
        assert_eq!(m.get("identifiers.total"), Some(4.0));
        assert_eq!(m.get("identifiers.unique_count"), Some(3.0));
    }

    #[test]
    fn single_char_detection() {
        let mut m = Metrics::new();
        emit(&["a", "b", "c", "x", "y", "longName"], &mut m);
        assert_eq!(m.get("identifiers.single_char_count"), Some(5.0));
    }

    #[test]
    fn hex_like_detection() {
        let mut m = Metrics::new();
        emit(&["deadbeef", "cafebabe", "normalName"], &mut m);
        assert_eq!(m.get("identifiers.hex_like_names"), Some(2.0));
    }
}
