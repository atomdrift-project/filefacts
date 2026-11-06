//! Unmistakable marks: one needle, one format. Checked before the language
//! scorer, which a document quoting another language's keywords can fool.

use super::{
    FileType, scripts,
    sniff::Sniff,
    text::{Controls, contains, contains_ci, find_ci, is_binary, starts_ci},
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
    const OPERATORS: [&[u8]; 4] = [b"?=", b":=", b"+=", b"="];
    if is_binary(head, Controls::Text) {
        return false;
    }
    let mut assignments = 0usize;
    let mut shell_functions = 0usize;
    let mut include_directives = 0usize;
    let mut make_variable_lines = 0usize;
    let mut pending_target = false;
    let mut target_with_recipe = false;
    // A column-zero Python import plus a tab-indented try/except/else/finally
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
            target_with_recipe |= pending_target;
            continue;
        }
        pending_target = false;
        if trimmed.starts_with(b"include ") || trimmed.starts_with(b"-include ") {
            include_directives += 1;
        }
        if trimmed.windows(8).any(|window| window == b"$(shell ") {
            shell_functions += 1;
        }
        if trimmed.windows(2).enumerate().any(|(at, pair)| {
            if pair != b"$(" {
                return false;
            }
            let Some(rest) = trimmed.get(at + 2..) else {
                return false;
            };
            rest.iter().position(|&b| b == b')').is_some_and(|end| {
                end > 0
                    && rest.get(..end).is_some_and(|name| {
                        name.iter()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
                    })
            })
        }) {
            make_variable_lines += 1;
        }

        if let Some(index) = OPERATORS
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
        } else if !line.first().is_some_and(u8::is_ascii_whitespace) && !trimmed.starts_with(b"//")
        {
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
            let python_suite =
                python_import && matches!(target, b"try" | b"except" | b"else" | b"finally");
            // A colon inside quoted/subscripted source expressions is not
            // evidence of a make target (e.g. exec(code, {'stream': s})).
            let source_expression = target
                .iter()
                .any(|b| matches!(b, b'\'' | b'"' | b'[' | b']'))
                || target.starts_with(b"-(")
                || target.starts_with(b"+(");
            let mail_header = [
                b"content-type".as_slice(),
                b"content-disposition",
                b"received",
            ]
            .iter()
            .any(|header| target.eq_ignore_ascii_case(header));
            if !target.is_empty()
                && !target.iter().any(u8::is_ascii_whitespace)
                && !source_expression
                && !python_suite
                && !mail_header
            {
                pending_target = true;
            }
        }
    }

    (assignments >= 2
        && (shell_functions > 0 || include_directives > 0 || make_variable_lines >= 2))
        || target_with_recipe
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

#[cfg(test)]
mod tests;
