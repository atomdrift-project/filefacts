//! Unmistakable marks: one needle, one format. Checked before the language
//! scorer, which a document quoting another language's keywords can fool.

use super::{
    FileType,
    heuristics::SCAN_LIMIT,
    scripts,
    sniff::Sniff,
    text::{
        Controls, UTF8_BOM, contains, contains_ci, find_ci, is_binary, starts_ci, strip_utf8_bom,
    },
};

/// How much of a body [`unmistakable`] reads for most marks.
const MARK_WINDOW: usize = 2048;

/// A mark that belongs to one format and almost nothing else.
///
/// Checked against a short prefix of [`Sniff::text`], in order, case-folded
/// where the format itself is. This is not the language scorer: in a
/// weighted token fight, a page full of embedded code scores as that code.
/// One needle, one type.
pub(super) fn unmistakable(sniff: &Sniff<'_>) -> Option<FileType> {
    let data = sniff.text();
    let head = data.get(..MARK_WINDOW).unwrap_or(data);
    // The whole-file answer reads these same bytes when the body fits the
    // window, so it is reused rather than computed again.
    let git_config =
        if sniff.decoded().is_none() && head.len() == data.len() && !head.starts_with(UTF8_BOM) {
            sniff.looks_like_git_config()
        } else {
            looks_like_git_config(head)
        };
    if git_config {
        return Some(FileType::Text);
    }
    // Manual pages are troff input, not source code. Roff's short requests
    // (for example `.B`, `.I`, and `.PP`) collide with source-language
    // tokens, so recognize a page title together with several distinct
    // requests before the language scorer can mistake prose for JavaScript.
    if looks_like_roff_man_page(head) {
        return Some(FileType::Text);
    }
    // Makefile fragments often have no canonical basename, and media-like
    // suffixes are used for library-specific include fragments (for example,
    // `makefile.jpeg` and `makefile.png`). Strong make syntax in the bytes is
    // more reliable than that suffix; a valid media signature has already
    // won in the signature stage before this heuristic runs.
    if looks_like_makefile(head) {
        return Some(FileType::Makefile);
    }
    // `<%@ Page Language="C#"` is ASP.NET. `<%@ page` / `<%@page` otherwise
    // is JSP. Classic ASP is `<%@ Language` with no `page` word. The ASP
    // forms have to win, or the shared `<%@ page` prefix swallows them.
    if looks_like_asp_directive(head) {
        return Some(FileType::Asp);
    }
    // A page directive is markup, so it opens a line; one quoted inside a
    // string literal does not make the file a page.
    if head.split(|&b| b == b'\n').any(|line| {
        let line = line.trim_ascii_start();
        starts_ci(line, b"<%@page") || starts_ci(line, b"<%@ page")
    }) || contains(head, b"<jsp:root")
        || contains(head, b"<jsp:directive.page")
    {
        return Some(FileType::Jsp);
    }
    if contains_ci(head, b"<cfset")
        || contains_ci(head, b"<cfoutput")
        || contains_ci(head, b"<cfscript")
        || contains_ci(head, b"<cfquery")
        || contains_ci(head, b"<cfparam")
    {
        return Some(FileType::Cfml);
    }
    if let Some(irc) = scripts::irc_mark(sniff, data.get(..4096).unwrap_or(data)) {
        return Some(irc);
    }
    if contains(head, b"\\documentclass")
        || contains(head, b"\\NeedsTeXFormat")
        || contains(head, b"\\ProvidesClass")
        || contains(head, b"\\ProvidesPackage")
    {
        return Some(FileType::Tex);
    }
    if looks_like_yara(head) {
        return Some(FileType::Yara);
    }
    None
}

/// Recognize Git's config syntax from a bounded prefix. `.git/config` has no
/// extension and content is its only reliable identity; content must also win
/// over a misleading filename such as `Makefile` or `settings.py`.
pub(super) fn looks_like_git_config(data: &[u8]) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        Core,
        Remote,
        Branch,
        Filter,
        User,
        Other,
    }

    let data = strip_utf8_bom(data);
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    if head.is_empty() || is_binary(head, Controls::Text) {
        return false;
    }

    let mut section = Section::Other;
    let mut recognized_section = false;
    let mut recognized_key = false;
    let mut meaningful_lines = 0usize;
    let mut config_lines = 0usize;

    for raw_line in head.split(|&byte| byte == b'\n') {
        let line = raw_line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            continue;
        }
        meaningful_lines += 1;

        if let Some(name) = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")) {
            section = if name.eq_ignore_ascii_case(b"core") {
                recognized_section = true;
                Section::Core
            } else if git_config_subsection(name, b"remote") {
                recognized_section = true;
                Section::Remote
            } else if git_config_subsection(name, b"branch") {
                recognized_section = true;
                Section::Branch
            } else if git_config_subsection(name, b"filter") {
                recognized_section = true;
                Section::Filter
            } else if name.eq_ignore_ascii_case(b"user") {
                recognized_section = true;
                Section::User
            } else {
                Section::Other
            };
            config_lines += 1;
            continue;
        }

        let Some(key) = line
            .iter()
            .position(|&byte| byte == b'=')
            .and_then(|equal| line.get(..equal))
        else {
            continue;
        };
        let key = key.trim_ascii();
        if key.is_empty()
            || !key
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.'))
        {
            continue;
        }
        config_lines += 1;
        let known = match section {
            Section::Core => [
                b"repositoryformatversion".as_slice(),
                b"filemode",
                b"bare",
                b"logallrefupdates",
                b"ignorecase",
                b"precomposeunicode",
                b"symlinks",
                b"worktree",
                b"fsmonitor",
                b"hookspath",
                b"excludesfile",
            ]
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Remote => [
                b"url".as_slice(),
                b"fetch",
                b"pushurl",
                b"mirror",
                b"tagopt",
            ]
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Branch => [b"remote".as_slice(), b"merge", b"rebase", b"pushremote"]
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Filter => [b"clean".as_slice(), b"smudge", b"process", b"required"]
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::User => [b"name".as_slice(), b"email", b"signingkey"]
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Other => false,
        };
        recognized_key |= known;
    }

    recognized_section
        && recognized_key
        && meaningful_lines >= 2
        && config_lines * 10 >= meaningful_lines * 9
}

fn git_config_subsection(header: &[u8], name: &[u8]) -> bool {
    let Some((prefix, rest)) = header.split_at_checked(name.len()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case(name)
        && rest.starts_with(b" \"")
        && rest.len() > 3
        && rest.ends_with(b"\"")
}

/// Recognize traditional `man` pages by their title request and a varied set
/// of formatting requests. A single `.TH` or `.SH` line in code or prose is
/// too weak; distinct requests make the roff document structure explicit.
fn looks_like_roff_man_page(head: &[u8]) -> bool {
    const REQUESTS: [&[u8]; 19] = [
        b"TH", b"SH", b"SS", b"PP", b"LP", b"P", b"TP", b"IP", b"B", b"I", b"BR", b"BI", b"RB",
        b"IR", b"nf", b"fi", b"de", b"ds", b"sp",
    ];

    let mut seen = [false; REQUESTS.len()];
    let mut distinct = 0usize;
    let mut has_title = false;

    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some((&control, rest)) = line.split_first() else {
            continue;
        };
        if control != b'.' && control != b'\'' {
            continue;
        }
        let request = rest.split(u8::is_ascii_whitespace).next().unwrap_or(rest);
        if request == b"TH" {
            has_title = true;
        }
        if let Some(index) = REQUESTS.iter().position(|known| *known == request)
            && let Some(seen) = seen.get_mut(index)
            && !*seen
        {
            *seen = true;
            distinct += 1;
        }
    }

    has_title && distinct >= 5
}

/// Recognize compact Makefile fragments from independent make-language
/// structures. The assignment plus `$(shell ...)` form covers
/// library-specific include fragments; a target followed by a tab-indented
/// recipe covers ordinary build files.
fn looks_like_makefile(head: &[u8]) -> bool {
    let mut assignments = 0usize;
    let mut shell_functions = 0usize;
    let mut include_directives = 0usize;
    let mut has_target = false;
    let mut has_recipe = false;
    // A column-zero Python import plus a tab-indented try/else/finally
    // suite is source code, not a make target and recipe. Imports inside a
    // tab-indented make recipe do not satisfy this independent evidence.
    let python_import = head.split(|&byte| byte == b'\n').any(|line| {
        line.starts_with(b"import ")
            || (line.starts_with(b"from ") && line.windows(8).any(|word| word == b" import "))
    });

    for line in head.split(|&byte| byte == b'\n') {
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }
        if line.starts_with(b"\t") {
            has_recipe = true;
        }
        if trimmed.starts_with(b"include ") || trimmed.starts_with(b"-include ") {
            include_directives += 1;
        }
        if trimmed.windows(8).any(|window| window == b"$(shell ") {
            shell_functions += 1;
        }

        let operators = [
            b"?=".as_slice(),
            b":=".as_slice(),
            b"+=".as_slice(),
            b"=".as_slice(),
        ];
        if let Some(index) = operators
            .iter()
            .find_map(|operator| trimmed.windows(operator.len()).position(|w| w == *operator))
        {
            let name = trimmed.get(..index).unwrap_or_default().trim_ascii_end();
            if !name.is_empty()
                && name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                assignments += 1;
            }
        } else if line == trimmed && !trimmed.starts_with(b"//") {
            // Make target definitions start in column zero. Requiring that
            // also prevents indented source comments such as `//post:` from
            // combining with unrelated tab-indented code into a false match.
            let Some(target) = trimmed
                .iter()
                .position(|&byte| byte == b':')
                .and_then(|colon| trimmed.get(..colon))
            else {
                continue;
            };
            let python_suite = python_import && matches!(target, b"try" | b"else" | b"finally");
            if !target.is_empty() && !target.iter().any(u8::is_ascii_whitespace) && !python_suite {
                has_target = true;
            }
        }
    }

    (assignments >= 2 && (shell_functions > 0 || include_directives > 0))
        || (has_target && has_recipe)
}

fn looks_like_asp_directive(head: &[u8]) -> bool {
    // Classic ASP's own directives. `<%@codepage=936%>` opens a good share of
    // the Chinese-language webshells.
    let mut rest = head;
    while let Some(at) = find_ci(rest, b"<%@") {
        let Some(after) = rest.get(at + 3..) else {
            break;
        };
        let name = after.trim_ascii_start();
        let directive = [
            &b"language"[..],
            b"codepage",
            b"enablesessionstate",
            b"lcid",
            b"transaction",
        ]
        .iter()
        .any(|d| {
            name.get(..d.len())
                .is_some_and(|n| n.eq_ignore_ascii_case(d))
        });
        if directive {
            return true;
        }
        rest = after;
    }
    let page = contains_ci(head, b"<%@page") || contains_ci(head, b"<%@ page");
    page && (contains_ci(head, b"language=\"c#\"")
        || contains_ci(head, b"language=\"vb\"")
        || contains_ci(head, b"language=\"jscript\"")
        || contains_ci(head, b"language='c#'")
        || contains_ci(head, b"language='vb'")
        || contains_ci(head, b"language='jscript'"))
}

/// `rule <name>` plus both section labels. YARA keywords are lowercase;
/// requiring all three keeps an English sentence that says "rule" from matching.
fn looks_like_yara(head: &[u8]) -> bool {
    let rule = head.split(|&b| b == b'\n').any(|line| {
        let line = line.trim_ascii_start();
        line.starts_with(b"rule ")
            || line.starts_with(b"private rule ")
            || line.starts_with(b"global rule ")
    });
    rule && contains(head, b"strings:") && contains(head, b"condition:")
}
