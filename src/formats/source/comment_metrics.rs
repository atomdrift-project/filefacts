//! Comment metrics ported from cleave.
//!
//! Extracts comments from the source text using a language-specific
//! comment style, then emits `comments.*` keys describing comment
//! count/size, annotation patterns (TODO/FIXME/HACK/XXX), and
//! suspicious payloads (high-entropy text, embedded code, URLs,
//! base64 blobs).

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;

use crate::metric;
use crate::output::Metrics;
use crate::scan::classify;

use super::identifier_metrics::string_entropy;

/// Per-language comment delimiter style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommentStyle {
    /// `//` and `/* */`, with `'` delimiting a char or string literal (C,
    /// Java, PHP, C#, …).
    CStyle,
    /// `//` and `/* */` plus backtick-delimited string literals — template
    /// literals (JavaScript, TypeScript) and raw strings (Go). Backtick
    /// contents are skipped so a `//` or `/*` inside a template/raw string
    /// (e.g. a URL like `https://…` in an error-message template) is not
    /// misread as a comment.
    CStyleTemplate,
    /// Rust: `//` and nesting `/* */`. A `'` opens a char literal only when
    /// one follows; otherwise it marks a lifetime or label (`&'static str`),
    /// which `CStyle` misread as a string swallowing the comments after it.
    /// Raw strings (`r#"…"#`) are skipped whole, backslashes included.
    Rust,
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
            text: trimmed.to_string(),
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

fn extract_comments(content: &str, style: CommentStyle) -> Vec<Comment<'_>> {
    let mut scanner = Scanner::new(content);
    match style {
        CommentStyle::CStyle => scanner.c_style(false),
        CommentStyle::CStyleTemplate => scanner.c_style(true),
        CommentStyle::Rust => scanner.rust(),
        CommentStyle::Hash => scanner.hash(),
        CommentStyle::DoubleDash => scanner.double_dash(),
        CommentStyle::Semicolon => scanner.semicolon(),
        CommentStyle::Batch => return extract_batch_comments(content),
    }
    scanner.comments
}

/// Extract Windows Batch line comments: a line whose first non-space token is
/// `::` or `rem` (case-insensitive). Whole-line constructs, so no string-state
/// tracking is needed.
fn extract_batch_comments(content: &str) -> Vec<Comment<'_>> {
    let mut comments = Vec::new();
    let mut line_start = 0;
    for raw in content.split_inclusive('\n') {
        // The lines `str::lines` yields: without `\n` or `\r\n`.
        let line = raw
            .strip_suffix('\n')
            .map_or(raw, |l| l.strip_suffix('\r').unwrap_or(l));
        let t = line.trim_start();
        let t_start = line_start + (line.len() - t.len());
        if let Some(rest) = t.strip_prefix("::") {
            comments.push(Comment {
                offset: t_start + 2,
                body: rest,
            });
        } else if let Some((keyword, after)) = t.split_at_checked(3)
            && keyword.eq_ignore_ascii_case("rem")
            && (after.is_empty() || after.starts_with([' ', '\t']))
        {
            // `split_at_checked`, not `t[..3]`: a trimmed line can begin with
            // a multi-byte char (e.g. CJK source comments), and slicing a str
            // at byte 3 would panic mid-char.
            let body = after.trim_start();
            comments.push(Comment {
                offset: t_start + 3 + (after.len() - body.len()),
                body,
            });
        }
        line_start += raw.len();
    }
    comments
}

/// A comment scanner over the source's bytes. Every delimiter is ASCII, and
/// UTF-8 never uses an ASCII byte inside a multi-byte character, so a byte
/// scan finds exactly the delimiters a char scan does and every cut it makes
/// is a char boundary — without first copying the source into a `Vec<char>`.
struct Scanner<'a> {
    text: &'a str,
    at: usize,
    comments: Vec<Comment<'a>>,
}

impl<'a> Scanner<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            at: 0,
            comments: Vec::new(),
        }
    }

    fn byte(&self, ahead: usize) -> Option<u8> {
        self.text.as_bytes().get(self.at + ahead).copied()
    }

    fn at_str(&self, s: &str) -> bool {
        self.text
            .as_bytes()
            .get(self.at..)
            .is_some_and(|rest| rest.starts_with(s.as_bytes()))
    }

    /// Record `start..end` as a comment body; `end` is clamped to the text.
    fn push(&mut self, start: usize, end: usize) {
        let end = end.min(self.text.len());
        if let Some(body) = self.text.get(start..end) {
            self.comments.push(Comment {
                offset: start,
                body,
            });
        }
    }

    /// Skip a string opened by the `quote` under the cursor, through its
    /// closing quote. A backslash escapes the byte after it; an unterminated
    /// string runs to the end.
    fn skip_string(&mut self, quote: u8) {
        self.at += 1;
        while let Some(b) = self.byte(0) {
            self.at += 1;
            if b == quote {
                return;
            }
            if b == b'\\' && self.byte(0).is_some() {
                self.at += 1;
            }
        }
    }

    /// Skip a string opened by three `quote`s under the cursor through the
    /// next three. No escapes, as in Python's triple-quoted strings.
    fn skip_triple_string(&mut self, quote: u8) {
        let close = [quote; 3];
        self.at += 3;
        let rest = self.text.as_bytes().get(self.at..).unwrap_or_default();
        self.at += memchr::memmem::find(rest, &close).map_or(rest.len(), |at| at + 3);
    }

    /// A comment from after the `delimiter_len`-byte delimiter under the
    /// cursor to the end of the line; the cursor stops on the newline.
    fn line_comment(&mut self, delimiter_len: usize) {
        let start = self.at + delimiter_len;
        let rest = self.text.as_bytes().get(start..).unwrap_or_default();
        let end = start + memchr::memchr(b'\n', rest).unwrap_or(rest.len());
        self.push(start, end);
        self.at = end;
    }

    /// A `/* */` comment from the `/*` under the cursor. With `nested`, as in
    /// Rust, each inner `/*` needs its own `*/`. Unterminated, it runs to the
    /// end.
    fn block_comment(&mut self, nested: bool) {
        let start = self.at + 2;
        self.at = start;
        let mut depth = 1usize;
        while self.byte(0).is_some() {
            if self.at_str("*/") {
                depth -= 1;
                if depth == 0 {
                    self.push(start, self.at);
                    self.at += 2;
                    return;
                }
                self.at += 2;
            } else if nested && self.at_str("/*") {
                depth += 1;
                self.at += 2;
            } else {
                self.at += 1;
            }
        }
        self.push(start, self.at);
    }

    fn c_style(&mut self, template_strings: bool) {
        while let Some(b) = self.byte(0) {
            match b {
                b'"' | b'\'' => self.skip_string(b),
                // Backtick template literals (JS/TS) and raw strings (Go)
                // routinely embed `//` and `/*` inside their text (URLs,
                // escapes). Skip the whole backtick span so those bytes
                // aren't misread as comments. `${…}` interpolation is treated
                // as opaque string content, matching how the `"`/`'` strings
                // ignore their contents.
                b'`' if template_strings => self.skip_string(b'`'),
                b'/' if self.at_str("//") => self.line_comment(2),
                b'/' if self.at_str("/*") => self.block_comment(false),
                _ => self.at += 1,
            }
        }
    }

    fn rust(&mut self) {
        while let Some(b) = self.byte(0) {
            match b {
                b'"' => self.skip_string(b'"'),
                b'\'' => self.skip_rust_quote(),
                b'r' if !self.follows_identifier_char() && self.skip_rust_raw_string() => {}
                b'/' if self.at_str("//") => self.line_comment(2),
                b'/' if self.at_str("/*") => self.block_comment(true),
                _ => self.at += 1,
            }
        }
    }

    /// Whether the byte before the cursor continues an identifier, so an `r`
    /// under the cursor is part of a name rather than a raw-string prefix.
    /// A `b` before it is the byte-string prefix of `br"…"`, not a name.
    fn follows_identifier_char(&self) -> bool {
        let Some(before) = self.at.checked_sub(1) else {
            return false;
        };
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80;
        match self.text.as_bytes().get(before) {
            Some(b'b') => before
                .checked_sub(1)
                .and_then(|i| self.text.as_bytes().get(i))
                .is_some_and(|&b| is_ident(b)),
            Some(&b) => is_ident(b),
            None => false,
        }
    }

    /// Skip a raw string (`r"…"`, `r#"…"#`) whose `r` is under the cursor.
    /// Returns false, moving nothing, when no raw string starts here.
    fn skip_rust_raw_string(&mut self) -> bool {
        let bytes = self.text.as_bytes();
        let hashes = bytes
            .get(self.at + 1..)
            .unwrap_or_default()
            .iter()
            .take_while(|&&b| b == b'#')
            .count();
        let open = self.at + 1 + hashes;
        if bytes.get(open) != Some(&b'"') {
            return false;
        }
        let close: Vec<u8> = std::iter::once(b'"')
            .chain(std::iter::repeat_n(b'#', hashes))
            .collect();
        let body = bytes.get(open + 1..).unwrap_or_default();
        self.at =
            open + 1 + memchr::memmem::find(body, &close).map_or(body.len(), |at| at + close.len());
        true
    }

    /// Skip the `'` under the cursor. It opens a char or byte literal only
    /// when an escape, or one char and a closing quote, follows; otherwise it
    /// marks a lifetime or loop label and opens nothing.
    fn skip_rust_quote(&mut self) {
        let rest = self.text.get(self.at + 1..).unwrap_or_default();
        let literal_len = if let Some(escape) = rest.strip_prefix('\\') {
            // The longest escape body, `u{10FFFF}`, is 9 bytes.
            escape
                .bytes()
                .skip(1)
                .take(9)
                .position(|b| b == b'\'')
                .map(|close| 1 + 1 + 1 + close + 1)
        } else {
            rest.chars()
                .next()
                .filter(|&c| c != '\'' && c != '\n')
                .filter(|c| rest.as_bytes().get(c.len_utf8()) == Some(&b'\''))
                .map(|c| 1 + c.len_utf8() + 1)
        };
        self.at += literal_len.unwrap_or(1);
    }

    fn hash(&mut self) {
        while let Some(b) = self.byte(0) {
            match b {
                b'"' | b'\'' if self.byte(1) == Some(b) && self.byte(2) == Some(b) => {
                    self.skip_triple_string(b);
                }
                b'"' | b'\'' => self.skip_string(b),
                b'#' => self.line_comment(1),
                _ => self.at += 1,
            }
        }
    }

    fn double_dash(&mut self) {
        while let Some(b) = self.byte(0) {
            match b {
                b'"' | b'\'' => self.skip_string(b),
                b'-' if self.at_str("--") => self.line_comment(2),
                _ => self.at += 1,
            }
        }
    }

    /// `;`-to-end-of-line comments (Clojure / Lisp). Skips `"..."` string
    /// literals so a `;` inside a string isn't read as a comment.
    fn semicolon(&mut self) {
        while let Some(b) = self.byte(0) {
            match b {
                b'"' => self.skip_string(b'"'),
                b';' => self.line_comment(1),
                _ => self.at += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bodies(content: &str, style: CommentStyle) -> Vec<&str> {
        extract_comments(content, style)
            .into_iter()
            .map(|c| c.body)
            .collect()
    }

    #[test]
    fn c_style_comments_are_extracted() {
        let comments = bodies(
            "// foo\n/* bar */\nx = 1; // inline\n",
            CommentStyle::CStyle,
        );
        assert_eq!(comments, vec![" foo", " bar ", " inline"]);
    }

    #[test]
    fn comment_offsets_point_at_their_bodies() {
        let src = "x = 1; // inline\n/* block */\n";
        for comment in extract_comments(src, CommentStyle::CStyle) {
            assert_eq!(&src[comment.offset..][..comment.body.len()], comment.body);
        }
        let mut metrics = Metrics::new();
        let mut out = crate::output::Comments::new();
        emit(src, CommentStyle::CStyle, &mut metrics, &mut out);
        let offsets: Vec<_> = out.iter().map(|c| (c.offset, c.text.as_str())).collect();
        assert_eq!(offsets, vec![(10, "inline"), (20, "block")]);
    }

    #[test]
    fn template_literal_contents_are_not_comments() {
        // A `//` inside a JS template literal (here a URL) must not be read as
        // a line comment that swallows the rest of the line.
        let src = "const e=`see https://react.dev/errors/ for details`;\n// real\n";
        // Without template awareness the old scanner treated `//react.dev/...`
        // as a comment running to the newline.
        let with_templates = bodies(src, CommentStyle::CStyleTemplate);
        assert_eq!(
            with_templates,
            vec![" real"],
            "only the genuine `// real` comment"
        );

        // The plain C-style mode (no backtick strings) still sees both.
        assert_eq!(bodies(src, CommentStyle::CStyle).len(), 2);
    }

    #[test]
    fn template_literal_block_comment_marker_ignored() {
        // `/*` inside a template literal must not open a block comment.
        let src = "const g=`glob /* not a comment */ pattern`;\nx=1;\n";
        let comments = bodies(src, CommentStyle::CStyleTemplate);
        assert!(
            comments.is_empty(),
            "no comments expected, got {comments:?}"
        );
    }

    #[test]
    fn unterminated_block_comment_runs_to_the_end() {
        assert_eq!(bodies("x /* abc", CommentStyle::CStyle), vec![" abc"]);
    }

    /// A lifetime's `'` was read as an opening quote, so everything up to the
    /// next `'` — often the rest of the file — vanished from the comment view.
    #[test]
    fn rust_lifetimes_do_not_hide_comments() {
        let src = "fn f(s: &'static str) { // SECRET\n}\n";
        assert_eq!(bodies(src, CommentStyle::Rust), vec![" SECRET"]);
        let src = "fn g<'a, 'b>(x: &'a str) -> &'b str { 'outer: loop {} } /* note */\n";
        assert_eq!(bodies(src, CommentStyle::Rust), vec![" note "]);
    }

    #[test]
    fn rust_char_literals_still_hide_their_contents() {
        let src = "let a = '/'; let b = '\\''; let c = b'\"'; let d = '\\u{1F600}'; // real\n";
        assert_eq!(bodies(src, CommentStyle::Rust), vec![" real"]);
        assert_eq!(
            bodies("let s = '語'; // x\n", CommentStyle::Rust),
            vec![" x"]
        );
    }

    #[test]
    fn rust_raw_strings_and_nested_blocks() {
        let src = "let p = r\"C:\\dir\\\"; // after\nlet q = r#\"say \"// no\"\"#;\n";
        assert_eq!(bodies(src, CommentStyle::Rust), vec![" after"]);
        let src = "/* outer /* inner */ still outer */ x // tail\n";
        assert_eq!(
            bodies(src, CommentStyle::Rust),
            vec![" outer /* inner */ still outer ", " tail"]
        );
        // An identifier ending in `r` is not a raw-string prefix.
        let src = "let ptr = bar\"x\"; // c\n";
        assert_eq!(bodies(src, CommentStyle::Rust), vec![" c"]);
    }

    #[test]
    fn hash_comments_are_extracted() {
        let comments = bodies(
            "# foo\nx = 1  # inline\n\"# not a comment\"\n'''# nor\nthis'''\n",
            CommentStyle::Hash,
        );
        assert_eq!(comments, vec![" foo", " inline"]);
    }

    #[test]
    fn double_dash_and_semicolon_comments() {
        assert_eq!(
            bodies("x = '--no' -- yes\n", CommentStyle::DoubleDash),
            vec![" yes"]
        );
        assert_eq!(
            bodies("(def s \";no\") ; yes\n", CommentStyle::Semicolon),
            vec![" yes"]
        );
    }

    #[test]
    fn todo_fixme_detection() {
        let mut m = Metrics::new();
        let mut comments = crate::output::Comments::new();
        emit(
            "// TODO fix\n// fixme broken\n",
            CommentStyle::CStyle,
            &mut m,
            &mut comments,
        );
        assert_eq!(m.get("comments.todo_count"), Some(1.0));
        assert_eq!(m.get("comments.fixme_count"), Some(1.0));
        assert_eq!(comments.len(), 2, "both comment bodies exposed as facts");
    }

    /// The automaton must find what per-pattern case-folded `contains` found,
    /// including overlapping patterns, and non-ASCII comments keep the full
    /// Unicode case mapping.
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

    #[test]
    fn batch_comments_are_extracted() {
        // `::` keeps text verbatim (leading space preserved); `rem` trims.
        let src = ":: colon comment\nREM upper\n  rem indented\r\ncode\n";
        let comments = extract_batch_comments(src);
        let found: Vec<_> = comments.iter().map(|c| c.body).collect();
        assert_eq!(found, vec![" colon comment", "upper", "indented"]);
        for comment in comments {
            assert_eq!(&src[comment.offset..][..comment.body.len()], comment.body);
        }
        // `rem` must be a whole token: `remove` is code, not a comment.
        assert!(extract_batch_comments("remove x\n").is_empty());
    }

    #[test]
    fn batch_comment_multibyte_line_does_not_panic() {
        // A trimmed line can begin with a multi-byte char (CJK source comments
        // are common in real packages). The `rem` check must not byte-slice at
        // index 3 — `语言` splits mid-char there and used to panic. Regression
        // for the matrixone scan crash (filefacts comment_metrics:181).
        let got: Vec<_> = extract_batch_comments("语言 test\nREM ok\n")
            .into_iter()
            .map(|c| c.body)
            .collect();
        assert_eq!(got, vec!["ok"], "multibyte line ignored, real REM kept");
    }
}
