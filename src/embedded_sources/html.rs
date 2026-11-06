//! A page's inline `<script>` bodies, one source unit each.
//!
//! A browser parses every inline script on its own, so a comment or template
//! literal left open in one ends with it and cannot hide the next; each
//! executable body is therefore a separate [`EmbeddedSource`] that records
//! where it sits in the page. Classic scripts still share the page's global
//! scope, which [`ScriptScope::Classic`] tells the consumer.
//!
//! The scan follows the HTML tokenizer as far as finding scripts needs:
//! comments are skipped, raw-text elements (`<textarea>`, `<style>`, …) are
//! skipped whole, and a script body ends where the tokenizer's script-data
//! states end it, including the escaped and double-escaped states that `<!--`
//! and a nested `<script` enter. HTML script content is raw text and is not
//! decoded.
//!
//! An SVG page is XML. There a body ends at the first `</script` outside a
//! CDATA section, comment or processing instruction; that markup is blanked
//! in the body, and character references and the predefined entities are
//! decoded as the XML parser decodes them.

use super::{EmbeddedSource, Origin, ScriptScope};
use crate::FileType;
use std::borrow::Cow;
use std::ops::Range;

/// The JavaScript MIME type essence strings (HTML Standard). A `type` runs as
/// a classic script only when it is one of these exactly, ignoring ASCII case
/// and surrounding ASCII whitespace: a parameter such as `; charset=utf-8`
/// makes it a data block.
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

/// One `<script>` element found in a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Script {
    /// The body's byte range in the page.
    pub(super) body: Range<usize>,
    /// How a browser runs it, or `None` when it is a data block.
    pub(super) scope: Option<ScriptScope>,
}

/// The executable inline scripts of an HTML or SVG page, in page order. The
/// pointer's index counts every `<script>` element, run or not.
pub(crate) fn inline_scripts(
    page: Option<(&[u8], FileType)>,
) -> impl Iterator<Item = EmbeddedSource<'_>> {
    let (page, xml) = page.map_or((&[][..], false), |(page, file_type)| {
        (page, file_type == FileType::Svg)
    });
    script_bodies(page, xml)
        .into_iter()
        .enumerate()
        .filter_map(move |(index, script)| {
            let scope = script.scope?;
            let raw = span(page, script.body.clone());
            let (source, aligned) = if xml {
                let (text, aligned) = xml_text(raw);
                (Cow::Owned(text), aligned)
            } else {
                (one_for_one(raw), true)
            };
            if source.trim_ascii().is_empty() {
                return None;
            }
            Some(EmbeddedSource {
                pointer: format!("/html/scripts/{index}"),
                source,
                file_type: Some(FileType::JavaScript),
                origin: Origin::Script {
                    offset: script.body.start,
                    scope,
                    aligned,
                },
            })
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

/// Whitespace as the HTML tokenizer ends a tag name on it.
fn is_tag_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

/// The offset just past the first `needle` in `page` at or after `from`, or
/// the page's end when there is none.
fn past(page: &[u8], from: usize, needle: &[u8]) -> usize {
    memchr::memmem::find(tail(page, from), needle).map_or(page.len(), |i| from + i + needle.len())
}

/// Every `<script>` element's body, in page order.
pub(super) fn script_bodies(page: &[u8], xml: bool) -> Vec<Script> {
    let mut scripts = Vec::new();
    let mut at = 0;
    while let Some(found) = memchr::memchr(b'<', tail(page, at)) {
        let start = at + found;
        let rest = tail(page, start);
        if rest.starts_with(b"<!--") {
            at = comment_end(page, start + 4, xml);
            continue;
        }
        if xml && rest.starts_with(b"<![CDATA[") {
            at = past(page, start + 9, b"]]>");
            continue;
        }
        if rest.starts_with(b"<!") || rest.starts_with(b"<?") {
            // A doctype, processing instruction or bogus comment: it ends at
            // the first `>` (`?>` in XML).
            at = past(
                page,
                start + 2,
                if xml && rest.starts_with(b"<?") {
                    b"?>"
                } else {
                    b">"
                },
            );
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
            let close = if xml && tag.self_closing {
                // An empty element: no body, but still a script element.
                Some(end)
            } else if xml {
                xml_script_end(page, end)
            } else {
                html_script_end(page, end)
            }
            .unwrap_or(page.len());
            scripts.push(Script {
                body: end..close,
                scope: script_scope(tag.kind.as_deref(), tag.language.as_deref()),
            });
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
    scripts
}

/// Just past the comment whose text starts at `from` (after `<!--`). HTML also
/// ends a comment at `--!>` and at an abrupt `<!-->` or `<!--->`; XML only at
/// `-->`.
fn comment_end(page: &[u8], from: usize, xml: bool) -> usize {
    if xml {
        return past(page, from, b"-->");
    }
    let rest = tail(page, from);
    if rest.starts_with(b">") {
        return from + 1;
    }
    if rest.starts_with(b"->") {
        return from + 2;
    }
    let close = past(page, from, b"-->");
    let bang = past(page, from, b"--!>");
    close.min(bang)
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
        let value = || Some(String::from_utf8_lossy(value).to_ascii_lowercase());
        if attr.eq_ignore_ascii_case(b"type") {
            tag.kind = value();
        } else if attr.eq_ignore_ascii_case(b"language") {
            tag.language = value();
        }
    }
}

/// Whether an end tag `</name`, in any case and followed by whitespace, `/`,
/// `>` or the end of the page, starts at `at`.
fn is_end_tag(page: &[u8], at: usize, name: &[u8]) -> bool {
    let name_end = at + 2 + name.len();
    tail(page, at).starts_with(b"</")
        && page
            .get(at + 2..name_end)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        && page
            .get(name_end)
            .is_none_or(|&b| is_tag_space(b) || b == b'/' || b == b'>')
}

/// The offset of the end tag `</name` at or after `from`, as the tokenizer
/// ends a raw-text element.
fn end_tag(page: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut at = from;
    while let Some(found) = memchr::memmem::find(tail(page, at), b"</") {
        let start = at + found;
        if is_end_tag(page, start, name) {
            return Some(start);
        }
        at = start + 2;
    }
    None
}

/// The tokenizer's script-data states (HTML Standard §13.2.5.4 onward),
/// reduced to what decides where the body ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptData {
    Plain,
    Escaped,
    EscapedDash,
    EscapedDashDash,
    DoubleEscaped,
    DoubleEscapedDash,
    DoubleEscapedDashDash,
}

/// The offset of the `</script` that ends an HTML script body starting at
/// `from`. Inside `<!--` an end tag still ends the script unless a nested
/// `<script` has entered the double-escaped state, which only its own
/// `</script` or a `-->` leaves.
fn html_script_end(page: &[u8], from: usize) -> Option<usize> {
    use ScriptData::{
        DoubleEscaped, DoubleEscapedDash, DoubleEscapedDashDash, Escaped, EscapedDash,
        EscapedDashDash, Plain,
    };
    // The run of ASCII letters starting at `at` names `script` and ends at a
    // tag delimiter; returns the offset just past that delimiter.
    let names_script = |at: usize| {
        let len = tail(page, at)
            .iter()
            .take_while(|b| b.is_ascii_alphabetic())
            .count();
        let delimiter = page.get(at + len).copied();
        (span(page, at..at + len).eq_ignore_ascii_case(b"script")
            && delimiter.is_some_and(|b| is_tag_space(b) || b == b'/' || b == b'>'))
        .then_some(at + len + 1)
    };
    let mut state = Plain;
    let mut i = from;
    loop {
        if state == Plain {
            i += memchr::memchr(b'<', tail(page, i))?;
        }
        let b = *page.get(i)?;
        match (state, b) {
            (Plain, _) => {
                if is_end_tag(page, i, b"script") {
                    return Some(i);
                }
                if tail(page, i).starts_with(b"<!--") {
                    state = EscapedDashDash;
                    i += 4;
                } else {
                    i += 1;
                }
                continue;
            }
            (Escaped | EscapedDash | EscapedDashDash, b'<') => {
                if is_end_tag(page, i, b"script") {
                    return Some(i);
                }
                match names_script(i + 1) {
                    Some(next) => {
                        state = DoubleEscaped;
                        i = next;
                    }
                    None => {
                        state = Escaped;
                        i += 1;
                    }
                }
                continue;
            }
            (DoubleEscaped | DoubleEscapedDash | DoubleEscapedDashDash, b'<') => {
                if page.get(i + 1) == Some(&b'/')
                    && let Some(next) = names_script(i + 2)
                {
                    state = Escaped;
                    i = next;
                } else {
                    state = DoubleEscaped;
                    i += 1;
                }
                continue;
            }
            (Escaped, b'-') => state = EscapedDash,
            (EscapedDash | EscapedDashDash, b'-') => state = EscapedDashDash,
            (DoubleEscaped, b'-') => state = DoubleEscapedDash,
            (DoubleEscapedDash | DoubleEscapedDashDash, b'-') => state = DoubleEscapedDashDash,
            (EscapedDashDash | DoubleEscapedDashDash, b'>') => state = Plain,
            (Escaped | EscapedDash | EscapedDashDash, _) => state = Escaped,
            (DoubleEscaped | DoubleEscapedDash | DoubleEscapedDashDash, _) => {
                state = DoubleEscaped;
            }
        }
        i += 1;
    }
}

/// The offset of the `</script` that ends an SVG (XML) script body starting
/// at `from`: the first one outside a CDATA section, comment or processing
/// instruction.
fn xml_script_end(page: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(found) = memchr::memchr(b'<', tail(page, at)) {
        let start = at + found;
        let rest = tail(page, start);
        at = if rest.starts_with(b"<![CDATA[") {
            past(page, start + 9, b"]]>")
        } else if rest.starts_with(b"<!--") {
            past(page, start + 4, b"-->")
        } else if rest.starts_with(b"<?") {
            past(page, start + 2, b"?>")
        } else if is_end_tag(page, start, b"script") {
            return Some(start);
        } else {
            start + 1
        };
    }
    None
}

/// How a browser runs a script with this `type` and `language` (HTML
/// Standard, "prepare the script element"), or `None` for a data block. An
/// empty or absent `type`, with no non-empty `language`, is JavaScript; a
/// `type` is stripped of ASCII whitespace and must then match exactly; a
/// `language` alone names `text/<language>`.
fn script_scope(kind: Option<&str>, language: Option<&str>) -> Option<ScriptScope> {
    let type_string = match (kind, language) {
        (Some(""), _) | (None, None | Some("")) => return Some(ScriptScope::Classic),
        (Some(kind), _) => kind.trim_matches(|c: char| u8::try_from(c).is_ok_and(is_tag_space)),
        (None, Some(language)) => &format!("text/{language}"),
    };
    if JAVASCRIPT_TYPES.contains(&type_string) {
        Some(ScriptScope::Classic)
    } else if type_string == "module" {
        Some(ScriptScope::Module)
    } else {
        None
    }
}

/// `raw` as text of the same width: every byte that is not UTF-8 becomes `?`.
fn one_for_one(raw: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(raw) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(raw.len());
    for chunk in raw.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(std::iter::repeat_n('?', chunk.invalid().len()));
    }
    Cow::Owned(out)
}

/// An SVG script body's text as the XML parser delivers it: CDATA content
/// verbatim, references decoded, and the markup around them (CDATA markers,
/// comments, processing instructions, child tags) blanked with line breaks
/// kept. The flag is whether every byte kept its offset, which decoding a
/// reference breaks.
fn xml_text(raw: &[u8]) -> (String, bool) {
    let blank = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend(
            bytes
                .iter()
                .map(|&b| if matches!(b, b'\n' | b'\r') { b } else { b' ' }),
        );
    };
    let mut out = Vec::with_capacity(raw.len());
    let mut aligned = true;
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        let rest = tail(raw, i);
        match b {
            b'<' if rest.starts_with(b"<![CDATA[") => {
                blank(&mut out, b"<![CDATA[");
                let len = memchr::memmem::find(tail(rest, 9), b"]]>").unwrap_or(rest.len() - 9);
                out.extend_from_slice(span(rest, 9..9 + len));
                let end = (9 + len + 3).min(rest.len());
                blank(&mut out, span(rest, 9 + len..end));
                i += end;
            }
            b'<' => {
                let close: &[u8] = if rest.starts_with(b"<!--") {
                    b"-->"
                } else if rest.starts_with(b"<?") {
                    b"?>"
                } else {
                    b">"
                };
                let end = past(rest, 1, close);
                blank(&mut out, span(rest, 0..end));
                i += end;
            }
            b'&' => match xml_reference(rest) {
                Some((c, len)) => {
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    aligned = false;
                    i += len;
                }
                None => {
                    out.push(b'&');
                    i += 1;
                }
            },
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    let text =
        String::from_utf8(out).unwrap_or_else(|error| one_for_one(error.as_bytes()).into_owned());
    (text, aligned)
}

/// The character a reference at the start of `text` (`&#97;`, `&#x61;`,
/// `&lt;`) stands for and the reference's length, or `None` when none does.
/// Entities a DTD declares are left as written.
fn xml_reference(text: &[u8]) -> Option<(char, usize)> {
    // The longest reference to a valid character is `&#x0010FFFF;`-sized.
    let len = text.iter().take(16).position(|&b| b == b';')?;
    let name = std::str::from_utf8(span(text, 1..len)).ok()?;
    let c = match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let (digits, radix) = match name.strip_prefix("#x") {
                Some(hex) => (hex, 16),
                None => (name.strip_prefix('#')?, 10),
            };
            if !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            let code = u32::from_str_radix(digits, radix).ok()?;
            // XML's Char production: no NUL, other C0 controls than tab and
            // line breaks, surrogates or U+FFFE/U+FFFF.
            char::from_u32(code)
                .filter(|&c| !matches!(c, '\0'..='\x08' | '\x0B' | '\x0C' | '\x0E'..='\x1F'))
                .filter(|&c| !matches!(c, '\u{FFFE}' | '\u{FFFF}'))?
        }
    };
    Some((c, len + 1))
}

#[cfg(test)]
mod tests;
