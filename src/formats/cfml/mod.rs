//! Bounded CFML syntax support for the shared symbol/flow producer.
//! Tags borrow source ranges; no regular-expression passes or external parser.
mod flow;
mod markup;
mod script;
pub(crate) use flow::{Parsed, parse};

use std::ops::Range;

pub(super) const MAX_BYTES: usize = 1024 * 1024;
const MAX_TAGS: usize = 20_000;
const MAX_COMMENT_DEPTH: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Tag {
    pub name: Range<usize>,
    pub body: Range<usize>,
    pub span: Range<usize>,
    pub closing: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Limit {
    Bytes,
    Tags,
    CommentDepth,
    Truncated,
    Script,
    Encrypted,
}

#[derive(Debug, Default)]
pub(super) struct Syntax {
    pub tags: Vec<Tag>,
    pub scripts: Vec<Range<usize>>,
    pub limitation: Option<Limit>,
    pub markup_limited: bool,
    pub output_expressions: Vec<Range<usize>>,
}

// Find the actual script closing tag. Apparent tags inside strings and
// comments are opaque. Script semantics are handled separately from tag scan.
fn script_end(bytes: &[u8], mut at: usize) -> Result<usize, Limit> {
    while let Some(&byte) = bytes.get(at) {
        if starts(bytes, at, b"</cfscript")
            && bytes
                .get(at + 10)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>')
        {
            return Ok(at);
        }
        if matches!(byte, b'\'' | b'"') {
            if !quoted(bytes, &mut at) {
                return Err(Limit::Truncated);
            }
        } else if starts(bytes, at, b"//") {
            while bytes.get(at).is_some_and(|b| !matches!(b, b'\n' | b'\r')) {
                at += 1;
            }
        } else if starts(bytes, at, b"/*") {
            at += 2;
            while at < bytes.len() && !starts(bytes, at, b"*/") {
                at += 1;
            }
            if at == bytes.len() {
                return Err(Limit::Truncated);
            }
            at += 2;
        } else if starts(bytes, at, b"<!---") {
            at += 5;
            let mut depth = 1;
            while depth > 0 {
                if at == bytes.len() {
                    return Err(Limit::Truncated);
                }
                if starts(bytes, at, b"<!---") {
                    depth += 1;
                    if depth > MAX_COMMENT_DEPTH {
                        return Err(Limit::CommentDepth);
                    }
                    at += 5;
                } else if starts(bytes, at, b"--->") {
                    depth -= 1;
                    at += 4;
                } else {
                    at += 1;
                }
            }
        } else {
            at += 1;
        }
    }
    Err(Limit::Truncated)
}

fn starts(bytes: &[u8], at: usize, value: &[u8]) -> bool {
    bytes
        .get(at..at.saturating_add(value.len()))
        .is_some_and(|s| s.eq_ignore_ascii_case(value))
}

// CFML doubles quotes inside strings. Hash expressions can themselves contain
// quoted strings, including the outer attribute's quote character.
fn quoted(bytes: &[u8], at: &mut usize) -> bool {
    let Some(&quote) = bytes.get(*at) else {
        return false;
    };
    *at += 1;
    while let Some(&byte) = bytes.get(*at) {
        match byte {
            b'#' if bytes.get(*at + 1) == Some(&b'#') => *at += 2,
            b'#' => {
                *at += 1;
                if !interpolation(bytes, at) {
                    return false;
                }
            }
            c if c == quote => {
                *at += 1;
                if bytes.get(*at) == Some(&quote) {
                    *at += 1;
                } else {
                    return true;
                }
            }
            _ => *at += 1,
        }
    }
    false
}

fn interpolation(bytes: &[u8], at: &mut usize) -> bool {
    while let Some(&byte) = bytes.get(*at) {
        match byte {
            b'#' => {
                *at += 1;
                return true;
            }
            quote @ (b'\'' | b'"') => {
                // Expression string contents are opaque here. Avoid recursive
                // string/interpolation calls on attacker-controlled nesting.
                *at += 1;
                loop {
                    let Some(&c) = bytes.get(*at) else {
                        return false;
                    };
                    *at += 1;
                    if c == quote {
                        if bytes.get(*at) == Some(&quote) {
                            *at += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => *at += 1,
        }
    }
    false
}

pub(super) fn scan(bytes: &[u8]) -> Syntax {
    let mut out = Syntax::default();
    if bytes.len() > MAX_BYTES {
        out.limitation = Some(Limit::Bytes);
        return out;
    }
    if bytes.starts_with(b"Allaire Cold Fusion Template") {
        out.limitation = Some(Limit::Encrypted);
        return out;
    }
    let mut at = 0;
    let mut markup = markup::Markup::default();
    while let Some(&byte) = bytes.get(at) {
        if starts(bytes, at, b"<!---") {
            at += 5;
            let mut depth = 1;
            while depth > 0 {
                if at == bytes.len() {
                    out.limitation = Some(Limit::Truncated);
                    return out;
                }
                if starts(bytes, at, b"<!---") {
                    depth += 1;
                    if depth > MAX_COMMENT_DEPTH {
                        out.limitation = Some(Limit::CommentDepth);
                        return out;
                    }
                    at += 5;
                } else if starts(bytes, at, b"--->") {
                    depth -= 1;
                    at += 4;
                } else {
                    at += 1;
                }
            }
            continue;
        }
        if markup.output_depth > 0 && byte == b'#' {
            if bytes.get(at + 1) == Some(&b'#') {
                at += 2;
                continue;
            }
            let begin = at + 1;
            let inside_tag = at < markup.control_until;
            at += 1;
            if !interpolation(bytes, &mut at) {
                out.limitation = Some(Limit::Truncated);
                return out;
            }
            // Control attributes are already parsed with their containing tag.
            if !inside_tag {
                if out.output_expressions.len() == MAX_TAGS {
                    out.limitation = Some(Limit::Tags);
                    return out;
                }
                out.output_expressions.push(begin..at - 1);
            }
            continue;
        }
        if byte != b'<' {
            markup.step(bytes, at);
            out.markup_limited |= markup.limited;
            at += 1;
            continue;
        }
        let start = at;
        let closing = bytes.get(at + 1) == Some(&b'/');
        let name_start = at + 1 + usize::from(closing);
        if !starts(bytes, name_start, b"cf") {
            if let Some(tag) = markup.step(bytes, at) {
                if out.tags.len() == MAX_TAGS {
                    out.limitation = Some(Limit::Tags);
                    return out;
                }
                out.tags.push(tag);
            }
            out.markup_limited |= markup.limited;
            at += 1;
            continue;
        }
        at = name_start;
        while bytes
            .get(at)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        {
            at += 1;
        }
        let name_end = at;
        if name_end == name_start + 2
            || !bytes
                .get(at)
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
        {
            continue;
        }
        let body_start = at;
        loop {
            let Some(&c) = bytes.get(at) else {
                out.limitation = Some(Limit::Truncated);
                return out;
            };
            if c == b'>' {
                break;
            }
            if c == b'\'' || c == b'"' {
                if !quoted(bytes, &mut at) {
                    out.limitation = Some(Limit::Truncated);
                    return out;
                }
            } else {
                at += 1;
            }
        }
        if out.tags.len() == MAX_TAGS {
            out.limitation = Some(Limit::Tags);
            return out;
        }
        let tag = Tag {
            name: name_start..name_end,
            body: body_start..at,
            span: start..at + 1,
            closing,
        };
        markup.cf_tag(bytes, &tag);
        out.tags.push(tag);
        at += 1;
        if !closing
            && bytes
                .get(name_start..name_end)
                .is_some_and(|name| name.eq_ignore_ascii_case(b"cfscript"))
        {
            match script_end(bytes, at) {
                Ok(end) => {
                    out.scripts.push(at..end);
                    out.limitation = Some(Limit::Script);
                    at = end;
                }
                Err(limit) => {
                    out.limitation = Some(limit);
                    return out;
                }
            }
        }
    }
    out
}

#[derive(Debug)]
pub(super) struct Attribute {
    pub name: Range<usize>,
    pub value: Range<usize>,
    pub quoted: bool,
}

/// The attribute syntax a tag is read with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dialect {
    /// CFML tags: every attribute has a value, quotes double to escape
    /// themselves, and `#…#` always interpolates.
    Cfml,
    /// HTML tags: boolean attributes are allowed and quotes do not escape.
    /// `#…#` interpolates only while an enclosing CFOUTPUT is active.
    Html { interpolate: bool },
}

const MAX_ATTRIBUTES: usize = 64;

/// The attributes of `tag`, in source order. A malformed or duplicate
/// attribute invalidates the whole tag: a consumer must not make a call from a
/// partially recognized argument list.
pub(super) fn attributes(bytes: &[u8], tag: &Tag, dialect: Dialect) -> Option<Vec<Attribute>> {
    let mut out: Vec<Attribute> = Vec::new();
    let mut at = tag.body.start;
    let end = tag.body.end;
    // Everything through the body; indexing it past `end` yields `None`.
    let body = bytes.get(..end)?;
    if at > end {
        return None;
    }
    let name_byte = |b: &u8| match dialect {
        Dialect::Cfml => b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'),
        Dialect::Html { .. } => {
            !b.is_ascii_whitespace()
                && !matches!(b, b'=' | b'/' | b'>' | b'\'' | b'"' | b'<' | b'`')
        }
    };
    while at < end {
        while body.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        if at == end || (at + 1 == end && body.get(at) == Some(&b'/')) {
            break;
        }
        if out.len() == MAX_ATTRIBUTES {
            return None;
        }
        let begin = at;
        while body.get(at).is_some_and(name_byte) {
            at += 1;
        }
        if at == begin {
            return None;
        }
        let name = begin..at;
        let name_text = body.get(name.clone())?;
        if out.iter().any(|a| {
            body.get(a.name.clone())
                .is_some_and(|n| n.eq_ignore_ascii_case(name_text))
        }) {
            return None;
        }
        while body.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        if body.get(at) != Some(&b'=') {
            if dialect == Dialect::Cfml {
                return None;
            }
            out.push(Attribute {
                name,
                value: at..at,
                quoted: false,
            });
            continue;
        }
        at += 1;
        while body.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        let &first = body.get(at)?;
        let quote = matches!(first, b'\'' | b'"').then_some(first);
        let value = match dialect {
            Dialect::Cfml => cfml_value(body, &mut at, quote.is_some())?,
            Dialect::Html { interpolate } => html_value(body, &mut at, quote, interpolate)?,
        };
        if quote.is_some()
            && body
                .get(at)
                .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'/')
        {
            return None;
        }
        out.push(Attribute {
            name,
            value,
            quoted: quote.is_some(),
        });
    }
    Some(out)
}

/// A CFML attribute value starting at `*at`, without its quotes.
fn cfml_value(body: &[u8], at: &mut usize, is_quoted: bool) -> Option<Range<usize>> {
    if is_quoted {
        let begin = *at + 1;
        return quoted(body, at).then(|| begin..*at - 1);
    }
    let begin = *at;
    while let Some(&b) = body.get(*at)
        && !b.is_ascii_whitespace()
    {
        *at += 1;
        if b == b'#' && !interpolation(body, at) {
            return None;
        }
    }
    Some(begin..*at)
}

/// An HTML attribute value starting at `*at`, without its quotes.
fn html_value(
    body: &[u8],
    at: &mut usize,
    quote: Option<u8>,
    interpolate: bool,
) -> Option<Range<usize>> {
    if quote.is_some() {
        *at += 1;
    }
    let begin = *at;
    while let Some(&b) = body.get(*at) {
        if quote == Some(b) || (quote.is_none() && b.is_ascii_whitespace()) {
            break;
        }
        if interpolate && b == b'#' {
            if body.get(*at + 1) == Some(&b'#') {
                *at += 2;
                continue;
            }
            *at += 1;
            if !interpolation(body, at) {
                return None;
            }
        } else {
            if quote.is_none() && matches!(b, b'\'' | b'"' | b'<' | b'=' | b'`') {
                return None;
            }
            *at += 1;
        }
    }
    let value = begin..*at;
    if let Some(q) = quote {
        if body.get(*at) != Some(&q) {
            return None;
        }
        *at += 1;
    }
    Some(value)
}

#[cfg(test)]
mod specimens;
#[cfg(test)]
mod tests;
