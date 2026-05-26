//! Markdown extractor — identity claims and outbound references.
//!
//! Markdown is full of edge cases that a full parser must handle; this
//! extractor deliberately doesn't. The goal is to lift a small set of
//! identity-signal facts that supply-chain anomaly traits can compare
//! against the package's declared identity:
//!
//! - `markdown.first_heading` — text of the first ATX heading
//!    (`# foo` or `## foo`), with leading hashes stripped and surrounding
//!    whitespace trimmed. Inline emphasis (`*`, `_`, backticks) is also
//!    stripped so the value reads as a plain identity claim.
//! - `markdown.github_repos[]` — deduped, ordered list of
//!    `github.com/owner/repo` references extracted from the document.
//!    Sub-paths (`.../blob/main/foo`, `.../issues/1`) collapse to the
//!    `owner/repo` form.
//!
//! ATX-style fenced code blocks (``` ``` ``` and `~~~`) are skipped so
//! headings inside code samples don't show up as identity claims.
//! Setext-style headings (underline form) are intentionally not
//! supported — every real-world README this signal targets uses ATX.
//!
//! No values are emitted when the document has no heading and no
//! GitHub references; the file simply contributes nothing to the
//! `markdown.*` namespace.
use std::collections::BTreeSet;

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::put_str;
use crate::output::{Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    _metrics: &mut Metrics,
) -> Result<(), Error> {
    // Markdown is UTF-8 by spec; fall back to lossy decode for safety.
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => std::borrow::Cow::Borrowed(s),
        Err(_) => String::from_utf8_lossy(bytes),
    };

    if let Some(heading) = first_atx_heading(&text) {
        put_str(values, "markdown.first_heading", heading);
    }

    let repos = github_repos(&text);
    if !repos.is_empty() {
        let arr = repos.into_iter().map(JsonValue::String).collect::<Vec<_>>();
        values.insert("markdown.github_repos", JsonValue::Array(arr));
    }

    Ok(())
}

/// Find the first ATX heading (`#` ... `######`) outside of fenced
/// code blocks. Returns the heading text with leading hashes, trailing
/// `#`s, and inline emphasis stripped.
fn first_atx_heading(text: &str) -> Option<String> {
    let mut in_fence: Option<char> = None;
    for line in text.lines() {
        // Track fenced code blocks. CommonMark requires the fence to
        // start at column 0 or after up to three spaces; allow any
        // leading whitespace here — a heading inside an indented
        // example is still "inside a fence" for our purposes.
        let trimmed = line.trim_start();
        if let Some(fence_char) = in_fence {
            if is_fence_line(trimmed, fence_char) {
                in_fence = None;
            }
            continue;
        }
        if trimmed.starts_with("```") {
            in_fence = Some('`');
            continue;
        }
        if trimmed.starts_with("~~~") {
            in_fence = Some('~');
            continue;
        }

        if let Some(text) = parse_atx_heading(trimmed) {
            return Some(text);
        }
    }
    None
}

/// True if a trimmed line is a closing fence for `fence_char`
/// (at least 3 consecutive fence characters).
fn is_fence_line(trimmed: &str, fence_char: char) -> bool {
    let count = trimmed.chars().take_while(|c| *c == fence_char).count();
    count >= 3
}

/// Parse a single ATX heading line. Returns `Some(text)` if the line
/// starts with `#`...`######` followed by a space; otherwise `None`.
fn parse_atx_heading(line: &str) -> Option<String> {
    let mut chars = line.chars();
    let mut hashes = 0;
    for ch in chars.by_ref() {
        if ch == '#' {
            hashes += 1;
            if hashes > 6 {
                return None;
            }
        } else if ch == ' ' || ch == '\t' {
            if hashes == 0 {
                return None;
            }
            break;
        } else {
            return None;
        }
    }
    if hashes == 0 {
        return None;
    }
    let body: String = chars.collect();
    let body = body.trim();
    // Trim CommonMark optional trailing `#` markers ("# foo #").
    let body = body.trim_end_matches(|c: char| c == '#' || c.is_whitespace());
    if body.is_empty() {
        return None;
    }
    Some(strip_inline_emphasis(body))
}

/// Strip inline emphasis markers (`*`, `_`, backticks) from a heading.
/// We don't reconstruct nested emphasis — we just remove the marker
/// bytes so `**Foo**` and `` `bar` `` read as `Foo` and `bar`.
fn strip_inline_emphasis(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '*' | '_' | '`'))
        .collect::<String>()
        .trim()
        .to_string()
}

/// Find every `github.com/<owner>/<repo>` reference and return them
/// deduped in first-seen order. Sub-paths past `<repo>` are dropped.
fn github_repos(text: &str) -> Vec<String> {
    const NEEDLE: &str = "github.com/";
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = text[cursor..].find(NEEDLE) {
        let start = cursor + rel + NEEDLE.len();
        cursor = start;
        let owner = take_path_segment(&text[start..]);
        let owner = match owner {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let after_owner = start + owner.len();
        // Require an explicit '/' between owner and repo (anchors,
        // queries, whitespace, eol all disqualify).
        if text.as_bytes().get(after_owner) != Some(&b'/') {
            continue;
        }
        let repo_start = after_owner + 1;
        let repo = take_path_segment(&text[repo_start..]);
        let repo = match repo {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        // Trim a trailing `.git` so `github.com/foo/bar.git` and
        // `github.com/foo/bar` collapse to the same value.
        let repo_clean = repo.strip_suffix(".git").unwrap_or(repo.as_str());
        let joined = format!("github.com/{}/{}", owner, repo_clean);
        if seen.insert(joined.clone()) {
            out.push(joined);
        }
    }
    out
}

/// Consume the longest prefix of a path segment from `s`. Stops at
/// `/`, whitespace, or any character not allowed in GitHub owner/repo
/// names. Returns `None` if `s` starts with a disallowed character.
fn take_path_segment(s: &str) -> Option<String> {
    let mut out = String::new();
    for ch in s.chars() {
        if ch == '/' || ch.is_whitespace() {
            break;
        }
        if is_path_segment_char(ch) {
            out.push(ch);
        } else {
            break;
        }
    }
    Some(out)
}

/// GitHub permits ASCII alphanumerics plus `-`, `_`, and `.` in owner
/// and repository names. Anything else (parens, brackets, query
/// chars) terminates the segment.
fn is_path_segment_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Metrics, Values};

    fn run(input: &str) -> Values {
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        extract(input.as_bytes(), &mut values, &mut metrics).unwrap();
        values
    }

    fn get_str(values: &Values, path: &str) -> Option<String> {
        values
            .get(path)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    fn get_arr(values: &Values, path: &str) -> Vec<String> {
        values
            .get(path)
            .and_then(JsonValue::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn first_heading_simple() {
        let v = run("# Hello\n\nbody text\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("Hello")
        );
    }

    #[test]
    fn first_heading_with_leading_blank_lines() {
        let v = run("\n\n   # Hello   \nrest\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("Hello")
        );
    }

    #[test]
    fn first_heading_h2_counts() {
        let v = run("## Subhead\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("Subhead")
        );
    }

    #[test]
    fn first_heading_wins_over_later_ones() {
        let v = run("# First\n\n## Second\n\n### Third\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("First")
        );
    }

    #[test]
    fn first_heading_strips_trailing_hashes() {
        let v = run("# Hello ###\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("Hello")
        );
    }

    #[test]
    fn first_heading_strips_inline_emphasis() {
        let v = run("# **Bold** *and* `code`\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("Bold and code")
        );
    }

    #[test]
    fn first_heading_clob_case() {
        let v = run("# `@img/sharp-win32-x64`\n\nLong description.\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("@img/sharp-win32-x64")
        );
    }

    #[test]
    fn no_heading_no_value() {
        let v = run("Just a paragraph.\n");
        assert_eq!(get_str(&v, "markdown.first_heading"), None);
    }

    #[test]
    fn empty_heading_no_value() {
        let v = run("# \n# Real heading\n");
        // The empty `# ` is rejected; the real heading wins.
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("Real heading")
        );
    }

    #[test]
    fn heading_inside_fence_is_skipped() {
        let v = run("```\n# not a heading\n```\n\n# real heading\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("real heading")
        );
    }

    #[test]
    fn heading_inside_tilde_fence_is_skipped() {
        let v = run("~~~\n# not a heading\n~~~\n\n# real heading\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("real heading")
        );
    }

    #[test]
    fn rejects_more_than_six_hashes() {
        let v = run("####### too deep\n# real heading\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("real heading")
        );
    }

    #[test]
    fn requires_space_after_hashes() {
        let v = run("#noSpace\n# real heading\n");
        assert_eq!(
            get_str(&v, "markdown.first_heading").as_deref(),
            Some("real heading")
        );
    }

    #[test]
    fn github_repos_basic() {
        let v = run("See https://github.com/lovell/sharp for details.\n");
        assert_eq!(
            get_arr(&v, "markdown.github_repos"),
            vec!["github.com/lovell/sharp"]
        );
    }

    #[test]
    fn github_repos_strips_subpaths() {
        let v = run(
            "See https://github.com/lovell/sharp/issues/123 and https://github.com/lovell/sharp/blob/main/README.md\n",
        );
        // Two refs, but both collapse to the same owner/repo and dedup.
        assert_eq!(
            get_arr(&v, "markdown.github_repos"),
            vec!["github.com/lovell/sharp"]
        );
    }

    #[test]
    fn github_repos_strips_dotgit_suffix() {
        let v =
            run("git clone https://github.com/foo/bar.git\nWebsite https://github.com/foo/bar\n");
        assert_eq!(
            get_arr(&v, "markdown.github_repos"),
            vec!["github.com/foo/bar"]
        );
    }

    #[test]
    fn github_repos_deduped_preserves_first_seen_order() {
        let v = run(
            "https://github.com/aaa/one https://github.com/bbb/two https://github.com/aaa/one\n",
        );
        assert_eq!(
            get_arr(&v, "markdown.github_repos"),
            vec!["github.com/aaa/one", "github.com/bbb/two"]
        );
    }

    #[test]
    fn github_repos_handles_no_repo() {
        let v = run("https://github.com/orgonly\nhttps://github.com/\n");
        assert!(get_arr(&v, "markdown.github_repos").is_empty());
    }

    #[test]
    fn github_repos_none_no_value() {
        let v = run("# No links here\n");
        assert!(v.get("markdown.github_repos").is_none());
    }

    #[test]
    fn handles_invalid_utf8_gracefully() {
        // Stray byte should not panic.
        let mut bytes = b"# Heading\n".to_vec();
        bytes.push(0xff);
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        extract(&bytes, &mut values, &mut metrics).unwrap();
        assert_eq!(
            get_str(&values, "markdown.first_heading").as_deref(),
            Some("Heading")
        );
    }
}
