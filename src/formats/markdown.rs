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
//! - `markdown.install_extensions[]` — the same imperative for editor
//!    extensions (`code --install-extension publisher.ext`, `...
//!    my-ext-1.2.3.vsix`), reduced to the bare extension name. Kept in its own
//!    list rather than folded into `install_packages`, because the two claims
//!    are not interchangeable: an extension's README routinely tells you to
//!    `pip install` the language server it drives, which names a companion
//!    program and says nothing about the extension's own identity. Only the
//!    editor-CLI form claims "this is the extension you are installing", so
//!    only it can contradict the manifest.
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

use crate::formats::common::put_str;
use crate::output::{Metrics, Values};
use crate::value_key;

pub(super) fn extract(bytes: &[u8], values: &mut Values, _metrics: &mut Metrics) {
    // Markdown is UTF-8 by spec; fall back to lossy decode for safety.
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => std::borrow::Cow::Borrowed(s),
        Err(_) => String::from_utf8_lossy(bytes),
    };

    if let Some(heading) = first_atx_heading(&text) {
        put_str(values, value_key!("markdown.first_heading"), heading);
    }

    let repos = github_repos(&text);
    if !repos.is_empty() {
        let arr = repos.into_iter().map(JsonValue::String).collect::<Vec<_>>();
        values.insert_key(value_key!("markdown.github_repos"), JsonValue::Array(arr));
    }

    let pkgs = npm_packages(&text);
    if !pkgs.is_empty() {
        let arr = pkgs.into_iter().map(JsonValue::String).collect::<Vec<_>>();
        values.insert_key(value_key!("markdown.npm_packages"), JsonValue::Array(arr));
    }

    let (installs, extensions) = install_packages(&text);
    if !installs.is_empty() {
        let arr = installs
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        values.insert_key(
            value_key!("markdown.install_packages"),
            JsonValue::Array(arr),
        );
    }
    if !extensions.is_empty() {
        let arr = extensions
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        values.insert_key(
            value_key!("markdown.install_extensions"),
            JsonValue::Array(arr),
        );
    }
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
        let Some(owner) = take_path_segment(&text[start..]) else {
            continue;
        };
        let after_owner = start + owner.len();
        // Require an explicit '/' between owner and repo (anchors,
        // queries, whitespace, eol all disqualify).
        if text.as_bytes().get(after_owner) != Some(&b'/') {
            continue;
        }
        let repo_start = after_owner + 1;
        let Some(repo) = take_path_segment(&text[repo_start..]) else {
            continue;
        };
        // Trim a trailing `.git` so `github.com/foo/bar.git` and
        // `github.com/foo/bar` collapse to the same value.
        let repo_clean = repo.strip_suffix(".git").unwrap_or(repo);
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
fn take_path_segment(s: &str) -> Option<&str> {
    let end = s
        .find(|ch: char| ch == '/' || ch.is_whitespace() || !is_path_segment_char(ch))
        .unwrap_or(s.len());
    s.get(..end).filter(|seg| !seg.is_empty())
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
/// Returns `(registry packages, editor extensions)` — see the module docs for
/// why the editor-CLI form is kept apart rather than merged into the first.
fn install_packages(text: &str) -> (Vec<String>, Vec<String>) {
    // (command, install verbs). Two-token prefixes: the manager then the verb.
    const COMMANDS: [(&str, &[&str]); 6] = [
        ("npm", &["install", "i", "add"]),
        ("yarn", &["add"]),
        ("pnpm", &["add", "install", "i"]),
        ("bun", &["add", "install"]),
        ("pip", &["install"]),
        ("pip3", &["install"]),
    ];

    // Editor CLIs that install a VS Code extension. These need their own table
    // because the verb is a flag rather than a subcommand, and because the
    // argument names an extension rather than a registry package. `code` is the
    // Microsoft build; the rest are the forks that kept the same CLI surface, so
    // a README cloned between marketplaces still parses.
    const EXTENSION_COMMANDS: [&str; 7] = [
        "code",
        "code-insiders",
        "code-oss",
        "codium",
        "cursor",
        "windsurf",
        "trae",
    ];
    const EXTENSION_VERB: &str = "--install-extension";

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut seen_ext = BTreeSet::new();
    let mut out_ext = Vec::new();
    for line in text.lines() {
        // Strip a leading shell prompt or markdown list/quote marker so
        // `$ npm install foo` and `- npm install foo` both parse.
        let line = line
            .trim_start()
            .trim_start_matches(['$', '>', '-', '*', ' ']);
        let mut tokens = line.split_whitespace();
        let Some(cmd) = tokens.next() else { continue };
        let editor = EXTENSION_COMMANDS.contains(&cmd);
        let verbs: &[&str] = if editor {
            &[EXTENSION_VERB]
        } else {
            match COMMANDS.iter().find(|(name, _)| *name == cmd) {
                Some((_, verbs)) => verbs,
                None => continue,
            }
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
            if editor {
                if let Some(name) = extension_argument_name(arg) {
                    if seen_ext.insert(name.clone()) {
                        out_ext.push(name);
                    }
                }
            } else if let Some(name) = install_argument_name(arg) {
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
            break;
        }
    }
    (out, out_ext)
}

/// Reduce a `--install-extension` argument to the extension's own name.
///
/// Two forms appear in the wild, and both name the same thing:
///
/// - a marketplace id, `publisher.extension` — only the second half is the
///   package's name, which is what `package.json::name` carries;
/// - a packaged file, `my-ext-1.2.3.vsix`, or the `my-ext-x.x.x.vsix`
///   placeholder that `vsce`'s own docs use. The basename carries the identity;
///   the version and extension are noise.
///
/// Reducing both to the bare name is what lets the value be compared directly
/// against the manifest. A republished extension keeps the upstream install
/// line — "install sugar-extension-pack" in a package shipped as
/// `krabt-extension-pack` — because the instructions were never part of the
/// branding the repackager set out to change.
fn extension_argument_name(arg: &str) -> Option<String> {
    if arg.is_empty() || arg.contains("://") {
        return None;
    }
    if arg
        .chars()
        .any(|c| matches!(c, '|' | ';' | '&' | '`' | '$' | '(' | ')' | '"' | '\''))
    {
        return None;
    }
    // A packaged file may be given by path; only the basename carries identity.
    let base = arg.rsplit(['/', '\\']).next()?;
    let vsix = base.len() > 5 && base[base.len() - 5..].eq_ignore_ascii_case(".vsix");
    let name = if vsix {
        strip_version_suffix(&base[..base.len() - 5])
    } else {
        // Marketplace id: publisher.extension. A bare token with no publisher
        // half is taken as-is.
        match base.split_once('.') {
            Some((publisher, ext)) if !publisher.is_empty() && !ext.is_empty() => ext,
            _ => base,
        }
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    Some(name.to_string())
}

/// Trim a trailing `-1.2.3` / `-x.x.x` version from a packaged filename stem.
///
/// Requires a dot in the trailing segment so that a name whose last component
/// merely happens to be numeric (`vscode-icons-2`) keeps it: a version this
/// function should remove always has at least one separator.
fn strip_version_suffix(stem: &str) -> &str {
    let Some(dash) = stem.rfind('-') else {
        return stem;
    };
    let tail = &stem[dash + 1..];
    if !tail.contains('.') {
        return stem;
    }
    let versionish = tail.split('.').all(|seg| {
        !seg.is_empty()
            && seg
                .chars()
                .all(|c| c.is_ascii_digit() || c == 'x' || c == 'X')
    });
    if versionish { &stem[..dash] } else { stem }
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
        let after_scope = 1 + scope.len();
        if s.as_bytes().get(after_scope) != Some(&b'/') {
            return None;
        }
        let name = take_path_segment(&s[after_scope + 1..])?;
        Some(format!("@{}/{}", scope, name))
    } else {
        take_npm_segment(s).map(str::to_owned)
    }
}

/// Like `take_path_segment`, but stops at a URL fragment/query as well so a
/// shields badge such as `/npm/v/foo?style=flat` yields `foo`.
fn take_npm_segment(s: &str) -> Option<&str> {
    let end = s
        .find(|ch: char| {
            ch == '/' || ch == '?' || ch == '#' || ch.is_whitespace() || !is_path_segment_char(ch)
        })
        .unwrap_or(s.len());
    s.get(..end).filter(|seg| !seg.is_empty())
}

#[cfg(test)]
mod tests;
