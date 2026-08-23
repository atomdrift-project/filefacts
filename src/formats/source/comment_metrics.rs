//! Comment metrics ported from cleave.
//!
//! Extracts comments from the source text using a language-specific
//! comment style, then emits `comments.*` keys describing comment
//! count/size, annotation patterns (TODO/FIXME/HACK/XXX), and
//! suspicious payloads (high-entropy text, embedded code, URLs,
//! base64 blobs).

use crate::output::Metrics;

use super::identifier_metrics::string_entropy;

/// Per-language comment delimiter style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommentStyle {
    /// `//` and `/* */` (C, Java, Rust, PHP, C#, …).
    CStyle,
    /// `//` and `/* */` plus backtick-delimited string literals — template
    /// literals (JavaScript, TypeScript) and raw strings (Go). Backtick
    /// contents are skipped so a `//` or `/*` inside a template/raw string
    /// (e.g. a URL like `https://…` in an error-message template) is not
    /// misread as a comment.
    CStyleTemplate,
    /// `#` (Python, Shell, …).
    Hash,
    /// `--` line comments (Lua, SQL, Haskell, …).
    DoubleDash,
    /// `;` line comments (Clojure / Lisp family). `#` is a reader macro in
    /// Clojure, not a comment, so Hash would mis-scan it.
    Semicolon,
    /// `REM` and `::` line comments (Windows Batch / CMD).
    Batch,
}

/// Emit `comments.*` metrics for `content` parsed with `style`.
pub(super) fn emit(
    content: &str,
    style: CommentStyle,
    metrics: &mut Metrics,
    comments_out: &mut crate::output::Comments,
) {
    let comments = extract_comments(content, style);
    if comments.is_empty() {
        return;
    }

    // Expose each non-empty comment body as a matchable fact so rules
    // can match keywords scoped to comments (lowest false positives —
    // a keyword in code or a string never reaches this tier).
    for comment in &comments {
        let trimmed = comment.trim();
        if !trimmed.is_empty() {
            comments_out.push(crate::output::ExtractedString {
                text: trimmed.to_string(),
                ..Default::default()
            });
        }
    }

    let total = comments.len() as u32;
    metrics.insert("comments.count", f64::from(total));

    let mut total_chars: u64 = 0;
    let mut comment_lines: u32 = 0;
    let mut todo_count: u32 = 0;
    let mut fixme_count: u32 = 0;
    let mut hack_count: u32 = 0;
    let mut xxx_count: u32 = 0;
    let mut empty_comments: u32 = 0;
    let mut high_entropy_comments: u32 = 0;
    let mut code_in_comments: u32 = 0;
    let mut url_in_comments: u32 = 0;
    let mut base64_in_comments: u32 = 0;

    for comment in &comments {
        let trimmed = comment.trim();
        total_chars += comment.len() as u64;
        comment_lines += comment.lines().count() as u32;

        if trimmed.is_empty() {
            empty_comments += 1;
            continue;
        }

        let upper = trimmed.to_uppercase();
        if upper.contains("TODO") {
            todo_count += 1;
        }
        if upper.contains("FIXME") {
            fixme_count += 1;
        }
        if upper.contains("HACK") {
            hack_count += 1;
        }
        if upper.contains("XXX") {
            xxx_count += 1;
        }

        let entropy = string_entropy(trimmed);
        if entropy > 4.5 && trimmed.len() > 20 {
            high_entropy_comments += 1;
        }
        if has_code_patterns(trimmed) {
            code_in_comments += 1;
        }
        if trimmed.contains("http://") || trimmed.contains("https://") || trimmed.contains("ftp://")
        {
            url_in_comments += 1;
        }
        if has_base64_pattern(trimmed) {
            base64_in_comments += 1;
        }
    }

    if comment_lines > 0 {
        metrics.insert("comments.lines", f64::from(comment_lines));
    }
    if total_chars > 0 {
        metrics.insert("comments.chars", total_chars as f64);
    }
    let total_lines = content.lines().count() as f64;
    let code_lines = total_lines - f64::from(comment_lines);
    if code_lines > 0.0 {
        metrics.insert(
            "comments.to_code_ratio",
            f64::from(comment_lines) / code_lines,
        );
    }
    if todo_count > 0 {
        metrics.insert("comments.todo_count", f64::from(todo_count));
    }
    if fixme_count > 0 {
        metrics.insert("comments.fixme_count", f64::from(fixme_count));
    }
    if hack_count > 0 {
        metrics.insert("comments.hack_count", f64::from(hack_count));
    }
    if xxx_count > 0 {
        metrics.insert("comments.xxx_count", f64::from(xxx_count));
    }
    if empty_comments > 0 {
        metrics.insert("comments.empty", f64::from(empty_comments));
    }
    if high_entropy_comments > 0 {
        metrics.insert(
            "comments.high_entropy",
            f64::from(high_entropy_comments),
        );
    }
    if code_in_comments > 0 {
        metrics.insert("comments.code", f64::from(code_in_comments));
    }
    if url_in_comments > 0 {
        metrics.insert("comments.url_in_comments", f64::from(url_in_comments));
    }
    if base64_in_comments > 0 {
        metrics.insert("comments.base64", f64::from(base64_in_comments));
    }
}

fn extract_comments(content: &str, style: CommentStyle) -> Vec<String> {
    match style {
        CommentStyle::CStyle => extract_c_style_comments(content, false),
        CommentStyle::CStyleTemplate => extract_c_style_comments(content, true),
        CommentStyle::Hash => extract_hash_comments(content),
        CommentStyle::DoubleDash => extract_double_dash_comments(content),
        CommentStyle::Semicolon => extract_semicolon_comments(content),
        CommentStyle::Batch => extract_batch_comments(content),
    }
}

/// Extract Windows Batch line comments: a line whose first non-space token is
/// `::` or `rem` (case-insensitive). Whole-line constructs, so no string-state
/// tracking is needed.
fn extract_batch_comments(content: &str) -> Vec<String> {
    let mut comments = Vec::new();
    for line in content.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("::") {
            comments.push(rest.to_string());
        } else if t
            .as_bytes()
            .get(..3)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"rem"))
        {
            // Byte-compare, not `t[..3]`: a trimmed line can begin with a
            // multi-byte char (e.g. CJK source comments), and slicing a str at
            // byte 3 would panic mid-char. On a match bytes 0..2 are ASCII
            // r/e/m, so byte 3 is a valid boundary and `&t[3..]` is safe.
            let after = &t[3..];
            if after.is_empty() || after.starts_with([' ', '\t']) {
                comments.push(after.trim_start().to_string());
            }
        }
    }
    comments
}

/// Extract `;`-to-end-of-line comments (Clojure / Lisp). Skips `"..."` string
/// literals so a `;` inside a string isn't read as a comment.
fn extract_semicolon_comments(content: &str) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut comments = Vec::new();
    let mut i = 0;
    while i < len {
        if chars[i] == '"' {
            i += 1;
            while i < len && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if chars[i] == ';' {
            let start = i + 1;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            comments.push(chars[start..i].iter().collect());
            continue;
        }
        i += 1;
    }
    comments
}

fn extract_double_dash_comments(content: &str) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut comments = Vec::new();
    let mut i = 0;
    while i < len {
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            i += 1;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if i + 1 < len && chars[i] == '-' && chars[i + 1] == '-' {
            let start = i + 2;
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            comments.push(chars[start..i].iter().collect());
            continue;
        }
        i += 1;
    }
    comments
}

fn extract_c_style_comments(content: &str, template_strings: bool) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut comments = Vec::new();
    let mut i = 0;
    while i < len {
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            i += 1;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        // Backtick template literals (JS/TS) and raw strings (Go) routinely
        // embed `//` and `/*` inside their text (URLs, escapes). Skip the
        // whole backtick span so those bytes aren't misread as comments.
        // `${…}` interpolation is treated as opaque string content, matching
        // how the `"`/`'` branches above ignore their contents.
        if template_strings && chars[i] == '`' {
            i += 1;
            while i < len && chars[i] != '`' {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
            let start = i + 2;
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            comments.push(chars[start..i].iter().collect());
            continue;
        }
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            let start = i + 2;
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            comments.push(chars[start..i].iter().collect());
            i += 2;
            continue;
        }
        i += 1;
    }
    comments
}

fn extract_hash_comments(content: &str) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut comments = Vec::new();
    let mut i = 0;
    while i < len {
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            if i + 2 < len && chars[i + 1] == quote && chars[i + 2] == quote {
                i += 3;
                while i + 2 < len
                    && !(chars[i] == quote && chars[i + 1] == quote && chars[i + 2] == quote)
                {
                    i += 1;
                }
                i += 3;
                continue;
            }
            i += 1;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if chars[i] == '#' {
            let start = i + 1;
            i += 1;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            comments.push(chars[start..i].iter().collect());
            continue;
        }
        i += 1;
    }
    comments
}

fn has_code_patterns(s: &str) -> bool {
    let patterns = [
        "function(",
        "def ",
        "class ",
        "if (",
        "for (",
        "while (",
        "return ",
        "import ",
        "require(",
        "var ",
        "let ",
        "const ",
        "eval(",
        "exec(",
        "= function",
        "=> {",
    ];
    // Patterns are already lowercase literals, so match against the
    // lowercased input directly without re-lowercasing each one.
    let lower = s.to_lowercase();
    let count = patterns.iter().filter(|p| lower.contains(*p)).count();
    count >= 2
}

fn has_base64_pattern(s: &str) -> bool {
    for word in s.split_whitespace() {
        if word.len() < 20 {
            continue;
        }
        let base64_chars = word
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count();
        if base64_chars as f64 / word.len() as f64 > 0.9 {
            let has_upper = word.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = word.chars().any(|c| c.is_ascii_lowercase());
            if has_upper && has_lower {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_style_comments_are_extracted() {
        let comments = extract_c_style_comments("// foo\n/* bar */\nx = 1; // inline\n", false);
        assert_eq!(comments.len(), 3);
    }

    #[test]
    fn template_literal_contents_are_not_comments() {
        // A `//` inside a JS template literal (here a URL) must not be read as
        // a line comment that swallows the rest of the line.
        let src = "const e=`see https://react.dev/errors/ for details`;\n// real\n";
        // Without template awareness the old scanner treated `//react.dev/...`
        // as a comment running to the newline.
        let with_templates = extract_c_style_comments(src, true);
        assert_eq!(
            with_templates.len(),
            1,
            "only the genuine `// real` comment, got {with_templates:?}"
        );
        assert_eq!(with_templates[0].trim(), "real");

        // The plain C-style mode (no backtick strings) still sees both.
        let without = extract_c_style_comments(src, false);
        assert_eq!(without.len(), 2);
    }

    #[test]
    fn template_literal_block_comment_marker_ignored() {
        // `/*` inside a template literal must not open a block comment.
        let src = "const g=`glob /* not a comment */ pattern`;\nx=1;\n";
        let comments = extract_c_style_comments(src, true);
        assert!(
            comments.is_empty(),
            "no comments expected, got {comments:?}"
        );
    }

    #[test]
    fn hash_comments_are_extracted() {
        let comments = extract_hash_comments("# foo\nx = 1  # inline\n\"# not a comment\"\n");
        assert_eq!(comments.len(), 2);
    }

    #[test]
    fn todo_fixme_detection() {
        let mut m = Metrics::new();
        let mut comments = crate::output::Comments::new();
        emit(
            "// TODO fix\n// FIXME broken\n",
            CommentStyle::CStyle,
            &mut m,
            &mut comments,
        );
        assert_eq!(m.get("comments.todo_count"), Some(1.0));
        assert_eq!(m.get("comments.fixme_count"), Some(1.0));
        assert_eq!(comments.len(), 2, "both comment bodies exposed as facts");
    }

    #[test]
    fn batch_comments_are_extracted() {
        // `::` keeps text verbatim (leading space preserved); `rem` trims.
        let comments =
            extract_batch_comments(":: colon comment\nREM upper\n  rem indented\ncode\n");
        assert_eq!(comments, vec![" colon comment", "upper", "indented"]);
        // `rem` must be a whole token: `remove` is code, not a comment.
        assert!(extract_batch_comments("remove x\n").is_empty());
    }

    #[test]
    fn batch_comment_multibyte_line_does_not_panic() {
        // A trimmed line can begin with a multi-byte char (CJK source comments
        // are common in real packages). The `rem` check must not byte-slice at
        // index 3 — `语言` splits mid-char there and used to panic. Regression
        // for the matrixone scan crash (filefacts comment_metrics:181).
        let got = extract_batch_comments("语言 test\nREM ok\n");
        assert_eq!(got, vec!["ok"], "multibyte line ignored, real REM kept");
    }
}
