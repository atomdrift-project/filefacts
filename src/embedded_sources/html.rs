//! A page's inline `<script>` bodies as one JavaScript view.
//!
//! The view has the page's length and line breaks: each executable script
//! body is copied in place and every other byte is blanked, so an offset or
//! a line in the view is the same offset or line in the page. Classic scripts
//! share one global scope in the browser, so one view also keeps a function
//! defined in one script visible where another script calls it.
//!
//! The scan follows the HTML tokenizer only as far as finding scripts needs:
//! comments are skipped, raw-text elements (`<textarea>`, `<style>`, …) are
//! skipped whole, and a script body ends at `</script` followed by
//! whitespace, `/` or `>`. Nothing is decoded: script content is raw text.

use super::EmbeddedSource;
use crate::FileType;
use std::borrow::Cow;
use std::ops::Range;

/// The `type` essences a browser runs as a classic script (HTML Standard,
/// "JavaScript MIME type essence match"); `module` is handled separately.
const JAVASCRIPT_TYPES: &[&str] = &[
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
];

/// Elements whose content the tokenizer reads as text, so a `<script>` inside
/// one is not a script. `<noscript>` is text whenever scripting is on, which
/// is the only case in which a script would run.
const RAW_TEXT_ELEMENTS: &[&[u8]] = &[
    b"iframe",
    b"noembed",
    b"noframes",
    b"noscript",
    b"style",
    b"textarea",
    b"title",
    b"xmp",
];

/// Written into the gap after each body that another follows. JavaScript ends
/// a `//` comment at U+2028 and reads it as whitespace, but line counters do
/// not count it: with the `;`, a trailing comment or a missing semicolon in
/// one script cannot run into the next, and no later line moves. The gap
/// always starts with the 8-byte `</script`, so it has room.
const SEPARATOR: &[u8] = "\u{2028};".as_bytes();

/// The inline-script view of an HTML or SVG page, or `None` when the page has
/// no executable script.
pub(crate) fn inline_scripts(page: Option<(&[u8], FileType)>) -> Option<EmbeddedSource<'static>> {
    let (page, file_type) = page?;
    let xml = file_type == FileType::Svg;
    let bodies = script_bodies(page, xml);
    if bodies
        .iter()
        .all(|body| span(page, body.clone()).iter().all(u8::is_ascii_whitespace))
    {
        return None;
    }
    Some(EmbeddedSource {
        pointer: "/html/scripts".to_owned(),
        source: Cow::Owned(view(page, &bodies)?),
        file_type: Some(FileType::JavaScript),
        layer: true,
    })
}

/// `page` from `at` on; empty past its end.
fn tail(page: &[u8], at: usize) -> &[u8] {
    page.get(at..).unwrap_or_default()
}

/// `page` over `range`; empty when the range does not fit.
fn span(page: &[u8], range: Range<usize>) -> &[u8] {
    page.get(range).unwrap_or_default()
}

/// The byte range of every executable script body, in page order.
pub(super) fn script_bodies(page: &[u8], xml: bool) -> Vec<Range<usize>> {
    let mut bodies = Vec::new();
    let mut at = 0;
    while let Some(found) = memchr::memchr(b'<', tail(page, at)) {
        let start = at + found;
        let rest = tail(page, start);
        if rest.starts_with(b"<!--") {
            at = memchr::memmem::find(tail(rest, 4), b"-->")
                .map_or(page.len(), |i| start + 4 + i + 3);
            continue;
        }
        if xml && rest.starts_with(b"<![CDATA[") {
            at = memchr::memmem::find(rest, b"]]>").map_or(page.len(), |i| start + i + 3);
            continue;
        }
        let Some(tag) = start_tag(page, start) else {
            at = start + 1;
            continue;
        };
        let Some(end) = tag.end else {
            // A tag the page never closes swallows the rest of it.
            break;
        };
        if tag.name.eq_ignore_ascii_case(b"script") {
            if xml && tag.self_closing {
                at = end;
                continue;
            }
            let close = end_tag(page, end, b"script").unwrap_or(page.len());
            if is_executable(tag.kind.as_deref(), tag.language.as_deref()) {
                bodies.push(end..close);
            }
            at = close;
        } else if !xml && tag.name.eq_ignore_ascii_case(b"plaintext") {
            break;
        } else if !xml
            && RAW_TEXT_ELEMENTS
                .iter()
                .any(|name| tag.name.eq_ignore_ascii_case(name))
        {
            at = end_tag(page, end, tag.name).unwrap_or(page.len());
        } else {
            at = end;
        }
    }
    bodies
}

/// What a start tag says about the element it opens.
struct StartTag<'a> {
    name: &'a [u8],
    /// The `type` attribute, if present.
    kind: Option<String>,
    /// The legacy `language` attribute, if present.
    language: Option<String>,
    /// The tag ends `/>`. HTML ignores it; XML does not.
    self_closing: bool,
    /// Just past the closing `>`, or `None` when the page ends first.
    end: Option<usize>,
}

/// The start tag at `start` (a `<`), or `None` when none opens there.
fn start_tag(page: &[u8], start: usize) -> Option<StartTag<'_>> {
    let name_start = start + 1;
    if !page.get(name_start)?.is_ascii_alphabetic() {
        return None;
    }
    let name_end = tail(page, name_start)
        .iter()
        .position(|&b| b.is_ascii_whitespace() || b == b'/' || b == b'>')
        .map_or(page.len(), |i| name_start + i);
    let mut tag = StartTag {
        name: span(page, name_start..name_end),
        kind: None,
        language: None,
        self_closing: false,
        end: None,
    };
    let skip_space = |mut i: usize| {
        while page.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        i
    };
    let mut i = name_end;
    loop {
        i = skip_space(i);
        match page.get(i) {
            None => return Some(tag),
            Some(b'>') => {
                tag.self_closing = span(page, 0..i).ends_with(b"/");
                tag.end = Some(i + 1);
                return Some(tag);
            }
            Some(b'/') => {
                i += 1;
                continue;
            }
            Some(_) => {}
        }
        let attr_start = i;
        while page
            .get(i)
            .is_some_and(|&b| !b.is_ascii_whitespace() && !matches!(b, b'=' | b'>' | b'/'))
        {
            i += 1;
        }
        let attr = span(page, attr_start..i);
        i = skip_space(i);
        if page.get(i) != Some(&b'=') {
            continue;
        }
        i = skip_space(i + 1);
        let value = match page.get(i) {
            Some(&quote @ (b'"' | b'\'')) => {
                let value_start = i + 1;
                let Some(len) = memchr::memchr(quote, tail(page, value_start)) else {
                    return Some(tag);
                };
                i = value_start + len + 1;
                span(page, value_start..value_start + len)
            }
            _ => {
                let value_start = i;
                while page
                    .get(i)
                    .is_some_and(|&b| !b.is_ascii_whitespace() && b != b'>')
                {
                    i += 1;
                }
                span(page, value_start..i)
            }
        };
        let value = || Some(String::from_utf8_lossy(value).trim().to_ascii_lowercase());
        if attr.eq_ignore_ascii_case(b"type") {
            tag.kind = value();
        } else if attr.eq_ignore_ascii_case(b"language") {
            tag.language = value();
        }
    }
}

/// The offset of the end tag `</name` at or after `from`, as the tokenizer
/// ends a raw-text element: the name in any case, then whitespace, `/`, `>`
/// or the end of the page.
fn end_tag(page: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut at = from;
    while let Some(found) = memchr::memmem::find(tail(page, at), b"</") {
        let start = at + found;
        let name_end = start + 2 + name.len();
        if page
            .get(start + 2..name_end)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
            && page
                .get(name_end)
                .is_none_or(|&b| b.is_ascii_whitespace() || b == b'/' || b == b'>')
        {
            return Some(start);
        }
        at = start + 2;
    }
    None
}

/// Whether a browser runs a script with this `type` and `language`, by the
/// HTML Standard's rule: `type` decides when present (empty means
/// JavaScript), else a non-empty `language` names `text/<language>`.
fn is_executable(kind: Option<&str>, language: Option<&str>) -> bool {
    let essence = match (kind, language) {
        (Some(kind), _) => kind.split(';').next().unwrap_or_default().trim().to_owned(),
        (None, Some(language)) if !language.is_empty() => format!("text/{language}"),
        (None, _) => return true,
    };
    essence.is_empty() || essence == "module" || JAVASCRIPT_TYPES.contains(&essence.as_str())
}

/// The page with every byte outside `bodies` blanked: line breaks are kept and
/// everything else becomes a space. Inside a body, an XML `<![CDATA[ … ]]>`
/// wrapper is blanked and bytes that are not UTF-8 become `?`, one for one.
fn view(page: &[u8], bodies: &[Range<usize>]) -> Option<String> {
    let mut out: Vec<u8> = page
        .iter()
        .map(|&b| if matches!(b, b'\n' | b'\r') { b } else { b' ' })
        .collect();
    for (index, body) in bodies.iter().enumerate() {
        let inner = without_cdata(page, body.clone());
        let mut at = inner.start;
        for chunk in span(page, inner).utf8_chunks() {
            let valid = chunk.valid().as_bytes();
            out.get_mut(at..at + valid.len())?.copy_from_slice(valid);
            at += valid.len();
            out.get_mut(at..at + chunk.invalid().len())?.fill(b'?');
            at += chunk.invalid().len();
        }
        if index + 1 < bodies.len() && tail(page, body.end).starts_with(b"</") {
            out.get_mut(body.end..body.end + SEPARATOR.len())?
                .copy_from_slice(SEPARATOR);
        }
    }
    String::from_utf8(out).ok()
}

/// `body` without a `<![CDATA[` opening its text or a `]]>` closing it.
fn without_cdata(page: &[u8], body: Range<usize>) -> Range<usize> {
    let text = span(page, body.clone());
    let lead = text.iter().take_while(|b| b.is_ascii_whitespace()).count();
    let trail = text
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_whitespace())
        .count();
    let trimmed = span(text, lead..text.len().saturating_sub(trail).max(lead));
    match trimmed
        .strip_prefix(b"<![CDATA[")
        .and_then(|t| t.strip_suffix(b"]]>"))
    {
        Some(inner) => {
            let start = body.start + lead + "<![CDATA[".len();
            start..start + inner.len()
        }
        None => body,
    }
}

#[cfg(test)]
mod tests;
