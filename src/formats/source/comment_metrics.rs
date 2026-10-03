//! Comment metrics ported from cleave.
//!
//! Takes the comment nodes the source walk found, strips their delimiters,
//! then emits `comments.*` keys describing comment count/size, annotation
//! patterns (TODO/FIXME/HACK/XXX), and suspicious payloads (high-entropy
//! text, embedded code, URLs, base64 blobs). The grammar decides what is a
//! comment, so a `#` inside `${#x}`, a `//` inside a regex or template, or a
//! heredoc line is never mistaken for one.

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;

use crate::metric;
use crate::output::Metrics;
use crate::scan::classify;

use super::identifier_metrics::string_entropy;

/// A comment's body, without its delimiters, and the byte offset in the
/// source where the body starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Comment<'a> {
    offset: usize,
    body: &'a str,
}

/// Annotation markers, matched case-insensitively.
const ANNOTATIONS: [&str; 4] = ["TODO", "FIXME", "HACK", "XXX"];

/// Code fragments, matched case-insensitively. Two distinct ones in a
/// comment suggest commented-out or smuggled code.
const CODE_PATTERNS: [&str; 16] = [
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

/// Bit `i` of a [`pattern_hits`] mask is pattern `i` of [`ANNOTATIONS`]
/// followed by [`CODE_PATTERNS`].
const CODE_PATTERN_BITS: u32 = ((1 << CODE_PATTERNS.len()) - 1) << ANNOTATIONS.len();

/// [`ANNOTATIONS`] and [`CODE_PATTERNS`] in one automaton, so a comment is
/// scanned once instead of once per pattern and without a case-folded copy.
static COMMENT_PATTERNS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(ANNOTATIONS.iter().chain(CODE_PATTERNS.iter()))
        .expect("comment patterns are a valid Aho-Corasick set")
});

/// URL schemes, matched case-sensitively.
static URL_SCHEMES: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(["http://", "https://", "ftp://"])
        .expect("URL schemes are a valid Aho-Corasick set")
});

/// Which of [`ANNOTATIONS`] and [`CODE_PATTERNS`] occur in `text`, as a
/// bitmask in their combined order.
fn pattern_hits(text: &str) -> u32 {
    if text.is_ascii() {
        // Overlapping, so `= function(` counts both of its patterns.
        return COMMENT_PATTERNS
            .find_overlapping_iter(text)
            .fold(0, |hits, m| hits | 1 << m.pattern().as_u32());
    }
    // Unicode case mapping can produce ASCII from other letters (`ſ`
    // uppercases to `S`, the Kelvin sign lowercases to `k`), which ASCII
    // case-insensitive matching would miss. Such comments keep the full
    // mapping.
    let upper = text.to_uppercase();
    let lower = text.to_lowercase();
    let annotations = ANNOTATIONS.iter().map(|p| upper.contains(p));
    let code = CODE_PATTERNS.iter().map(|p| lower.contains(p));
    annotations
        .chain(code)
        .enumerate()
        .fold(0, |hits, (i, hit)| hits | u32::from(hit) << i)
}

/// The body of a comment node's `text`, its delimiters stripped, and the
/// body's byte offset within `text`. The grammar has already decided `text`
/// is a comment, so its opening delimiter says which closing one to strip:
/// block forms lose both ends (an unterminated one only its opener), line
/// forms their marker. Anything else (Ruby's `=begin`, Perl POD) is kept
/// whole.
fn comment_body(text: &str) -> (usize, &str) {
    for (open, close) in [("/*", "*/"), ("<#", "#>"), ("<!--", "-->")] {
        if let Some(rest) = text.strip_prefix(open) {
            return (open.len(), rest.strip_suffix(close).unwrap_or(rest));
        }
    }
    // Lua long comments: `--[[ … ]]`, `--[==[ … ]==]`.
    if let Some(level) = text
        .strip_prefix("--[")
        .map(|rest| rest.bytes().take_while(|&b| b == b'=').count())
        .filter(|&level| text.as_bytes().get(3 + level) == Some(&b'['))
    {
        let open = 4 + level;
        let close = format!("]{}]", "=".repeat(level));
        let rest = text.get(open..).unwrap_or_default();
        return (open, rest.strip_suffix(close.as_str()).unwrap_or(rest));
    }
    // Line forms end at the newline, which some grammars (Rust's) include in
    // the node.
    for marker in ["//", "--", "#", ";", "::"] {
        if let Some(rest) = text.strip_prefix(marker) {
            return (marker.len(), rest.strip_suffix('\n').unwrap_or(rest));
        }
    }
    // Batch `REM`, or `@REM` with echo suppressed, then the whitespace after
    // it.
    let rem = text.strip_prefix('@').unwrap_or(text);
    if let Some((keyword, after)) = rem.split_at_checked(3)
        && keyword.eq_ignore_ascii_case("rem")
        && (after.is_empty() || after.starts_with([' ', '\t']))
    {
        let body = after.trim_start();
        let body = body.strip_suffix('\n').unwrap_or(body);
        return (text.len() - after.trim_start().len(), body);
    }
    (0, text)
}

/// Emit `comments.*` metrics for the comment nodes `found` (each its start
/// offset in `content` and its text, delimiters included).
pub(super) fn emit(
    found: &[(usize, &str)],
    content: &str,
    metrics: &mut Metrics,
    comments_out: &mut crate::output::Comments,
) {
    let comments: Vec<Comment<'_>> = found
        .iter()
        .map(|&(start, text)| {
            let (skip, body) = comment_body(text);
            Comment {
                offset: start + skip,
                body,
            }
        })
        .collect();
    if comments.is_empty() {
        return;
    }

    let total = crate::bytes::sat_u32(comments.len());
    metrics.insert(metric!("comments.count"), f64::from(total));

    let mut total_chars: u64 = 0;
    let mut comment_lines: u32 = 0;
    let mut annotation_counts = [0u32; ANNOTATIONS.len()];
    let mut empty_comments: u32 = 0;
    let mut high_entropy_comments: u32 = 0;
    let mut code_in_comments: u32 = 0;
    let mut url_in_comments: u32 = 0;
    let mut base64_in_comments: u32 = 0;

    for comment in &comments {
        let body = comment.body;
        total_chars += body.len() as u64;
        comment_lines = comment_lines.saturating_add(crate::bytes::sat_u32(body.lines().count()));

        let trimmed = body.trim();
        if trimmed.is_empty() {
            empty_comments += 1;
            continue;
        }

        // Expose each non-empty comment body as a matchable fact so rules
        // can match keywords scoped to comments (lowest false positives —
        // a keyword in code or a string never reaches this tier).
        comments_out.push(crate::output::ExtractedString {
            value: trimmed.to_string(),
            offset: comment.offset + (body.len() - body.trim_start().len()),
            ..Default::default()
        });

        let hits = pattern_hits(trimmed);
        for (i, count) in annotation_counts.iter_mut().enumerate() {
            *count += hits >> i & 1;
        }
        if (hits & CODE_PATTERN_BITS).count_ones() >= 2 {
            code_in_comments += 1;
        }

        let entropy = string_entropy(trimmed);
        if entropy > 4.5 && trimmed.len() > 20 {
            high_entropy_comments += 1;
        }
        if URL_SCHEMES.is_match(trimmed) {
            url_in_comments += 1;
        }
        if trimmed
            .split_whitespace()
            .any(classify::is_base64_comment_word)
        {
            base64_in_comments += 1;
        }
    }

    if comment_lines > 0 {
        metrics.insert(metric!("comments.lines"), f64::from(comment_lines));
    }
    if total_chars > 0 {
        metrics.insert(metric!("comments.chars"), total_chars as f64);
    }
    let total_lines = content.lines().count() as f64;
    let code_lines = total_lines - f64::from(comment_lines);
    if code_lines > 0.0 {
        metrics.insert(
            metric!("comments.to_code_ratio"),
            f64::from(comment_lines) / code_lines,
        );
    }
    let [todo_count, fixme_count, hack_count, xxx_count] = annotation_counts;
    if todo_count > 0 {
        metrics.insert(metric!("comments.todo_count"), f64::from(todo_count));
    }
    if fixme_count > 0 {
        metrics.insert(metric!("comments.fixme_count"), f64::from(fixme_count));
    }
    if hack_count > 0 {
        metrics.insert(metric!("comments.hack_count"), f64::from(hack_count));
    }
    if xxx_count > 0 {
        metrics.insert(metric!("comments.xxx_count"), f64::from(xxx_count));
    }
    if empty_comments > 0 {
        metrics.insert(metric!("comments.empty"), f64::from(empty_comments));
    }
    if high_entropy_comments > 0 {
        metrics.insert(
            metric!("comments.high_entropy"),
            f64::from(high_entropy_comments),
        );
    }
    if code_in_comments > 0 {
        metrics.insert(metric!("comments.code"), f64::from(code_in_comments));
    }
    if url_in_comments > 0 {
        metrics.insert(metric!("comments.url_count"), f64::from(url_in_comments));
    }
    if base64_in_comments > 0 {
        metrics.insert(metric!("comments.base64"), f64::from(base64_in_comments));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The comment-tier texts filefacts reports for `source` named `path`.
    fn comments(path: &str, source: &str) -> Vec<String> {
        crate::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(source.as_bytes())
            .comments()
            .iter()
            .map(|c| c.value.clone())
            .collect()
    }

    fn metrics(path: &str, source: &str) -> crate::Metrics {
        crate::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(source.as_bytes())
            .metrics()
            .clone()
    }

    #[test]
    fn delimiters_are_stripped() {
        assert_eq!(comment_body("// a"), (2, " a"));
        assert_eq!(comment_body("/* b */"), (2, " b "));
        assert_eq!(comment_body("/* open"), (2, " open"));
        assert_eq!(comment_body("# c"), (1, " c"));
        assert_eq!(comment_body("-- d"), (2, " d"));
        assert_eq!(comment_body("--[==[ e ]==]"), (6, " e "));
        assert_eq!(comment_body("--[[ f ]]"), (4, " f "));
        assert_eq!(comment_body("; g"), (1, " g"));
        assert_eq!(comment_body(":: h"), (2, " h"));
        assert_eq!(comment_body("REM   i"), (6, "i"));
        assert_eq!(comment_body("@rem i"), (5, "i"));
        assert_eq!(comment_body("// line\n"), (2, " line"));
        assert_eq!(comment_body("<# j #>"), (2, " j "));
        assert_eq!(comment_body("<!-- k -->"), (4, " k "));
        assert_eq!(comment_body("=begin\nl\n=end"), (0, "=begin\nl\n=end"));
    }

    #[test]
    fn c_style_comments_are_found() {
        assert_eq!(
            comments("a.c", "int x = 1; // line\n/* block */ int y;\n"),
            ["line", "block"]
        );
    }

    #[test]
    fn comment_offsets_point_at_their_bodies() {
        let src = "int x; //   spaced\n/* b */\n";
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("a.c"))
            .open(src.as_bytes());
        for comment in parsed.comments() {
            let at = usize::try_from(comment.offset).unwrap();
            assert!(src[at..].starts_with(&comment.value), "{comment:?}");
        }
    }

    /// The grammar, not a scanner, decides: `//` and `/*` inside template
    /// literals, strings and regexes are not comments.
    #[test]
    fn javascript_strings_templates_and_regexes_hide_their_contents() {
        let src = "const u = `see https://x.test/* not */`; const r = /\\/\\//; const s = \"// no\"; // yes\n";
        assert_eq!(comments("a.js", src), ["yes"]);
    }

    #[test]
    fn rust_lifetimes_chars_raw_strings_and_nested_blocks() {
        assert_eq!(
            comments("a.rs", "fn f(s: &'static str) { // SECRET\n}\n"),
            ["SECRET"]
        );
        assert_eq!(
            comments(
                "a.rs",
                "fn g() { let c = '\"'; let r = r#\"// no\"#; } // real\n"
            ),
            ["real"]
        );
        assert_eq!(
            comments("a.rs", "/* outer /* inner */ still */ fn h() {}\n"),
            ["outer /* inner */ still"]
        );
    }

    /// `#` in a parameter expansion or a heredoc is not a comment.
    #[test]
    fn shell_comments_only() {
        let src = "n=${#x} # length\ncat <<EOF\n# not a comment\nEOF\n";
        assert_eq!(comments("a.sh", src), ["length"]);
    }

    #[test]
    fn hash_double_dash_and_semicolon_comments() {
        assert_eq!(comments("a.py", "x = '#no' # yes\n"), ["yes"]);
        assert_eq!(
            comments("a.lua", "x = '--no' -- yes\n--[[ block ]]\n"),
            ["yes", "block"]
        );
        assert_eq!(comments("a.clj", "(def s \";no\") ; yes\n"), ["yes"]);
    }

    #[test]
    fn batch_comments_are_found() {
        let found = comments(
            "a.bat",
            "@echo off\nREM first\n:: second\n@rem third\necho rem not\n",
        );
        assert_eq!(found, ["first", "second", "third"]);
        // A multi-byte character right after the marker does not split a char.
        assert_eq!(comments("a.bat", "REM 語\n"), ["語"]);
    }

    #[test]
    fn todo_fixme_detection() {
        let m = metrics(
            "a.c",
            "// TODO: fix\n// FIXME later\n/* HACK */\n// xxx\nint x;\n",
        );
        assert_eq!(m.get("comments.count"), Some(4.0));
        assert_eq!(m.get("comments.todo_count"), Some(1.0));
        assert_eq!(m.get("comments.fixme_count"), Some(1.0));
        assert_eq!(m.get("comments.hack_count"), Some(1.0));
        assert_eq!(m.get("comments.xxx_count"), Some(1.0));
    }

    #[test]
    fn pattern_hits_match_case_folded_contains() {
        let corpus = [
            "TODO: remove eval(x) and exec(y)",
            "x = function() { return 1 }",
            "if (a) for (b) while (c)",
            "Hack around XXX-12; see FixMe",
            "const a = () => { import x }",
            "plain prose with no code at all",
            "défini: let x; var y",
            "ſtrange xxx",
            "",
        ];
        for text in corpus {
            let upper = text.to_uppercase();
            let lower = text.to_lowercase();
            let expected = ANNOTATIONS
                .iter()
                .map(|p| upper.contains(p))
                .chain(CODE_PATTERNS.iter().map(|p| lower.contains(p)))
                .enumerate()
                .fold(0, |hits, (i, hit)| hits | u32::from(hit) << i);
            assert_eq!(pattern_hits(text), expected, "{text}");
        }
        // `= function(` holds two overlapping patterns.
        let hits = pattern_hits("x = function(a)");
        assert_eq!((hits & CODE_PATTERN_BITS).count_ones(), 2);
    }
}
