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
//! - `markdown.install_packages[]` — deduped, ordered list of the package
//!    names a README tells the reader to install (`npm install foo`,
//!    `yarn add foo`, `pip install foo`, ...). This is the most load-bearing
//!    identity claim a README makes: "type this to get me". A clone-and-rename
//!    republication routinely forgets to update it, leaving the upstream name
//!    in the instructions while the manifest carries the new one, so cleave
//!    compares the two (`consistency.manifest_readme_name_mismatch`).
//!    Unlike `markdown.npm_packages`, which reads registry *links* (badges
//!    frequently point at an unrelated project), this reads *imperatives*.
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

    let pkgs = npm_packages(&text);
    if !pkgs.is_empty() {
        let arr = pkgs.into_iter().map(JsonValue::String).collect::<Vec<_>>();
        values.insert("markdown.npm_packages", JsonValue::Array(arr));
    }

    let installs = install_packages(&text);
    if !installs.is_empty() {
        let arr = installs
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        values.insert("markdown.install_packages", JsonValue::Array(arr));
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
    let stripped: String = s
        .chars()
        .filter(|c| !matches!(c, '*' | '_' | '`'))
        .collect();
    stripped.trim().to_owned()
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
        if !seen.contains(joined.as_str()) {
            seen.insert(joined.clone());
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

/// Deduped, ordered list of npm package names a README points at, lifted from
/// the two forms a package's own README uses to name itself: the registry link
/// `npmjs.com/package/<name>` and the shields.io version badge `/npm/v/<name>`.
/// Scoped names (`@scope/name`) are kept whole. A legit package always names
/// itself here (its badge, its install link); a byte-clean starjack that keeps
/// the upstream README names the *upstream* package instead, so a supply-chain
/// trait can compare this against the manifest's declared `name`.
fn npm_packages(text: &str) -> Vec<String> {
    // `/npm/v/<pkg>` is a shields.io version badge, and its URL commonly carries
    // the image format as an extension: `/npm/v/etag.svg`. Keeping the suffix
    // made every badge name a package that does not exist, so a rule comparing
    // the manifest name against this list saw a mismatch for `etag`, `js-yaml`,
    // `commander` and every other project that badges itself this way.
    fn strip_badge_extension(name: &str) -> &str {
        for ext in [".svg", ".png", ".json"] {
            if let Some(base) = name.strip_suffix(ext) {
                return base;
            }
        }
        name
    }
    const NEEDLES: [&str; 2] = ["npmjs.com/package/", "/npm/v/"];
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for needle in NEEDLES {
        let mut cursor = 0;
        while let Some(rel) = text[cursor..].find(needle) {
            let start = cursor + rel + needle.len();
            cursor = start;
            if let Some(name) = take_npm_name(&text[start..]) {
                let name = strip_badge_extension(&name).to_string();
                if name.is_empty() {
                    continue;
                }
                if !seen.contains(name.as_str()) {
                    seen.insert(name.clone());
                    out.push(name);
                }
            }
        }
    }
    out
}

/// Take one npm package name from the start of `s`. Handles a `@scope/name`
/// pair as a single value; otherwise a bare unscoped segment. Returns `None`
/// for an empty or malformed name.
/// Package names a README instructs the reader to install.
///
/// Scans every line (inside fenced blocks too — install commands almost always
/// live in one) for a package-manager install imperative and takes the first
/// argument that is not a flag. Flags are skipped rather than terminating the
/// scan so `npm install --save-dev foo` still yields `foo`.
///
/// Deliberately conservative about what counts as a name: anything holding a
/// path separator, a URL scheme, a version pin, or a shell metacharacter is a
/// local path, a tarball or a piped command rather than a registry name, and is
/// dropped. A line that yields nothing simply contributes nothing.
fn install_packages(text: &str) -> Vec<String> {
    // (command, install verbs). Two-token prefixes: the manager then the verb.
    const COMMANDS: [(&str, &[&str]); 6] = [
        ("npm", &["install", "i", "add"]),
        ("yarn", &["add"]),
        ("pnpm", &["add", "install", "i"]),
        ("bun", &["add", "install"]),
        ("pip", &["install"]),
        ("pip3", &["install"]),
    ];

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        // Strip a leading shell prompt or markdown list/quote marker so
        // `$ npm install foo` and `- npm install foo` both parse.
        let line = line
            .trim_start()
            .trim_start_matches(['$', '>', '-', '*', ' ']);
        let mut tokens = line.split_whitespace();
        let Some(cmd) = tokens.next() else { continue };
        let Some((_, verbs)) = COMMANDS.iter().find(|(name, _)| *name == cmd) else {
            continue;
        };
        let Some(verb) = tokens.next() else { continue };
        if !verbs.contains(&verb) {
            continue;
        }
        // A line carrying shell punctuation is a pipeline, not a plain install
        // instruction (`npm install foo | sh`, `npm i foo && ./run`). The
        // metacharacter is its own whitespace-separated token, so it has to be
        // caught here rather than in the per-argument check. Abstain on the
        // whole line: the point of this fact is an unambiguous identity claim.
        let args: Vec<&str> = tokens.collect();
        if args.iter().any(|a| {
            a.chars()
                .any(|c| matches!(c, '|' | ';' | '&' | '`' | '$' | '(' | ')' | '<' | '>'))
        }) {
            continue;
        }
        // First non-flag argument is the package. Global/dev flags and their
        // detached values (`--registry <url>`) are not names.
        for arg in args {
            if arg.starts_with('-') {
                continue;
            }
            if let Some(name) = install_argument_name(arg) {
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
            break;
        }
    }
    out
}

/// Reduce one install argument to a bare registry name, or reject it.
///
/// Rejects paths (`./pkg`, `/tmp/x`), URLs and git specs, tarballs, and
/// anything carrying shell punctuation. A version suffix is trimmed
/// (`foo@1.2.3` -> `foo`) while a scope is preserved (`@scope/pkg`).
fn install_argument_name(arg: &str) -> Option<String> {
    if arg.is_empty() || arg.contains("://") || arg.contains('\\') {
        return None;
    }
    if arg
        .chars()
        .any(|c| matches!(c, '|' | ';' | '&' | '`' | '$' | '(' | ')' | '"' | '\''))
    {
        return None;
    }
    // Trim a version pin, keeping a leading scope marker intact.
    let body = arg.strip_prefix('@').map_or(arg, |rest| rest);
    let trimmed = match body.find('@') {
        Some(at) => &arg[..arg.len() - (body.len() - at)],
        None => arg,
    };
    if trimmed.starts_with('.') || trimmed.starts_with('/') {
        return None;
    }
    // A non-scoped name has no slash; a scoped one has exactly one.
    let name = take_npm_name(trimmed)?;
    if name.len() != trimmed.len() {
        return None;
    }
    Some(name)
}

fn take_npm_name(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_prefix('@') {
        let scope = take_path_segment(rest)?;
        if scope.is_empty() {
            return None;
        }
        let after_scope = 1 + scope.len();
        if s.as_bytes().get(after_scope) != Some(&b'/') {
            return None;
        }
        let name = take_path_segment(&s[after_scope + 1..])?;
        if name.is_empty() {
            return None;
        }
        Some(format!("@{}/{}", scope, name))
    } else {
        let name = take_npm_segment(s)?;
        if name.is_empty() { None } else { Some(name) }
    }
}

/// Like `take_path_segment`, but stops at a URL fragment/query as well so a
/// shields badge such as `/npm/v/foo?style=flat` yields `foo`.
fn take_npm_segment(s: &str) -> Option<String> {
    let mut out = String::new();
    for ch in s.chars() {
        if ch == '/' || ch == '?' || ch == '#' || ch.is_whitespace() {
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
    fn npm_packages_registry_link() {
        let v = run("Install from https://www.npmjs.com/package/tailwindcss-3d today.\n");
        assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["tailwindcss-3d"]);
    }

    #[test]
    fn npm_packages_shields_badge_and_dedup() {
        let v = run(
            "![v](https://img.shields.io/npm/v/tailwindcss-3d?style=flat) \
             see https://www.npmjs.com/package/tailwindcss-3d\n",
        );
        assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["tailwindcss-3d"]);
    }

    #[test]
    fn npm_packages_strips_shields_badge_extension() {
        // `img.shields.io/npm/v/etag.svg` names `etag`, not `etag.svg`.
        let v = run("![v](https://img.shields.io/npm/v/etag.svg)\n");
        assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["etag"]);
        let v = run("![v](https://img.shields.io/npm/v/js-yaml.png)\n");
        assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["js-yaml"]);
    }

    #[test]
    fn npm_packages_keeps_a_real_dotted_name() {
        // `punycode.js` is a real package name; only image suffixes are stripped.
        let v = run("https://www.npmjs.com/package/punycode.js\n");
        assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["punycode.js"]);
    }

    #[test]
    fn npm_packages_scoped_name() {
        let v = run("https://www.npmjs.com/package/@scope/pkg-name\n");
        assert_eq!(
            get_arr(&v, "markdown.npm_packages"),
            vec!["@scope/pkg-name"]
        );
    }

    #[test]
    fn npm_packages_none_no_value() {
        let v = run("# A README with no npm references\n");
        assert!(v.get("markdown.npm_packages").is_none());
    }

    #[test]
    fn install_packages_npm_install() {
        let v = run("Install it:\n\n```\nnpm install theta-registry\n```\n");
        assert_eq!(
            get_arr(&v, "markdown.install_packages"),
            vec!["theta-registry"]
        );
    }

    #[test]
    fn install_packages_skips_flags_and_handles_managers() {
        let v = run(
            "npm i --save-dev eslint\nyarn add react\npnpm add -D vitest\npip install requests\n",
        );
        assert_eq!(
            get_arr(&v, "markdown.install_packages"),
            vec!["eslint", "react", "vitest", "requests"]
        );
    }

    #[test]
    fn install_packages_scoped_name_and_version_pin() {
        let v = run("npm install @scope/pkg-name@1.2.3\n");
        assert_eq!(
            get_arr(&v, "markdown.install_packages"),
            vec!["@scope/pkg-name"]
        );
    }

    #[test]
    fn install_packages_strips_prompt_and_list_marker() {
        let v = run("$ npm install alpha\n- yarn add beta\n");
        assert_eq!(
            get_arr(&v, "markdown.install_packages"),
            vec!["alpha", "beta"]
        );
    }

    #[test]
    fn install_packages_rejects_paths_urls_and_shell() {
        // Local paths, tarball URLs and piped commands are not registry names.
        let v =
            run("npm install ./local\nnpm install https://x.test/a.tgz\nnpm install foo | sh\n");
        assert!(v.get("markdown.install_packages").is_none());
    }

    #[test]
    fn install_packages_dedupes_preserving_order() {
        let v = run("npm install foo\nyarn add foo\nnpm install bar\n");
        assert_eq!(get_arr(&v, "markdown.install_packages"), vec!["foo", "bar"]);
    }

    #[test]
    fn install_packages_none_no_value() {
        let v = run("# A README that never says how to install\n");
        assert!(v.get("markdown.install_packages").is_none());
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
