//! Bounded source markup observations, not an HTML DOM or execution model.
//! CFML scanning remains independent, including inside HTML attributes/raw text.
use super::{Attribute, Tag, interpolation, starts};
use std::ops::Range;

#[derive(Default)]
pub(super) struct Markup {
    until: usize,
    control_until: usize,
    comment: bool,
    raw: Option<Range<usize>>,
    output_depth: usize,
    pub limited: bool,
}

impl Markup {
    pub(super) fn in_output(&self) -> bool {
        self.output_depth > 0
    }
    pub(super) fn inside_tag(&self, at: usize) -> bool {
        at < self.control_until
    }

    pub(super) fn cf_tag(&mut self, bytes: &[u8], tag: &Tag) {
        if bytes
            .get(tag.name.clone())
            .is_some_and(|name| name.eq_ignore_ascii_case(b"cfoutput"))
        {
            if tag.closing {
                self.output_depth = self.output_depth.saturating_sub(1);
            } else {
                self.output_depth = self.output_depth.saturating_add(1);
            }
        }
    }

    pub(super) fn step(&mut self, bytes: &[u8], at: usize) -> Option<Tag> {
        if at < self.until {
            return None;
        }
        if self.comment {
            if starts(bytes, at, b"-->") || starts(bytes, at, b"--!>") {
                self.comment = false;
                self.until = at + if starts(bytes, at, b"--!>") { 4 } else { 3 };
            } else if bytes.get(at) == Some(&b'>')
                && (at == self.until
                    || (at == self.until + 1 && bytes.get(self.until) == Some(&b'-')))
            {
                self.comment = false;
                self.until = at + 1;
            }
            return None;
        }
        if let Some(raw) = &self.raw {
            let raw = bytes.get(raw.clone()).unwrap_or_default();
            if raw.eq_ignore_ascii_case(b"plaintext") {
                return None;
            }
            if !starts(bytes, at, b"</")
                || !starts(bytes, at + 2, raw)
                || !bytes
                    .get(at + 2 + raw.len())
                    .is_some_and(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
            {
                return None;
            }
            self.raw = None;
        }
        if starts(bytes, at, b"<!--") {
            self.comment = true;
            self.until = at + 4;
            return None;
        }
        if starts(bytes, at, b"<!") || starts(bytes, at, b"<?") {
            // Declarations and processing instructions cannot declare inputs.
            // DOCTYPE quoted identifiers may themselves contain angle brackets.
            let doctype = starts(bytes, at, b"<!doctype");
            let mut end = at + 2;
            let mut quote = None;
            while let Some(&b) = bytes.get(end) {
                if quote == Some(b) {
                    quote = None;
                } else if quote.is_none() {
                    if doctype && matches!(b, b'\'' | b'"') {
                        quote = Some(b);
                    } else if b == b'>' {
                        break;
                    }
                }
                end += 1;
            }
            self.until = end.saturating_add(1);
            return None;
        }
        if bytes.get(at) != Some(&b'<') {
            return None;
        }
        let closing = bytes.get(at + 1) == Some(&b'/');
        let start = at + 1 + usize::from(closing);
        if !bytes.get(start).is_some_and(u8::is_ascii_alphabetic) {
            return None;
        }
        let mut end = start;
        while bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
        {
            end += 1;
        }
        if !bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
        {
            return None;
        }
        let body_start = end;
        let mut quote = None;
        let mut prefix_end = None;
        let mut condition_depth = 0usize;
        let mut mixed_unknown = false;
        while let Some(&b) = bytes.get(end) {
            if quote.is_none() && (starts(bytes, end, b"<cf") || starts(bytes, end, b"</cf")) {
                let cf_start = end;
                let cf_closing = bytes.get(end + 1) == Some(&b'/');
                let cf_name = end + 1 + usize::from(cf_closing);
                end = cf_name;
                while bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
                    end += 1;
                }
                let cf = bytes.get(cf_name..end).unwrap_or_default();
                if cf.eq_ignore_ascii_case(b"cfif") {
                    prefix_end.get_or_insert(cf_start);
                    if cf_closing {
                        if condition_depth == 0 {
                            mixed_unknown = true;
                        }
                        condition_depth = condition_depth.saturating_sub(1);
                    } else {
                        condition_depth += 1;
                        if condition_depth > 64 {
                            self.limited = true;
                            self.until = bytes.len();
                            return None;
                        }
                    }
                } else if !cf_closing
                    && condition_depth > 0
                    && (cf.eq_ignore_ascii_case(b"cfelse") || cf.eq_ignore_ascii_case(b"cfelseif"))
                {
                } else {
                    mixed_unknown = true;
                }
                while let Some(&c) = bytes.get(end)
                    && c != b'>'
                {
                    if matches!(c, b'\'' | b'"') {
                        if !super::quoted(bytes, &mut end) {
                            self.limited = true;
                            self.until = bytes.len();
                            return None;
                        }
                    } else {
                        end += 1;
                    }
                }
                if end < bytes.len() {
                    end += 1;
                }
                continue;
            }
            if self.output_depth > 0 && b == b'#' {
                if bytes.get(end + 1) == Some(&b'#') {
                    end += 2;
                    continue;
                }
                end += 1;
                if !interpolation(bytes, &mut end) {
                    self.limited = true;
                    self.until = bytes.len();
                    return None;
                }
                continue;
            }
            if quote == Some(b) {
                quote = None;
            } else if quote.is_none() {
                if matches!(b, b'\'' | b'"') {
                    quote = Some(b);
                } else if b == b'>' {
                    break;
                }
            }
            end += 1;
        }
        self.until = end.saturating_add(1);
        if end == bytes.len() {
            self.limited = true;
            return None;
        }
        let name = bytes.get(start..body_start).unwrap_or_default();
        if !closing
            && [
                b"script".as_slice(),
                b"style",
                b"textarea",
                b"title",
                b"xmp",
                b"iframe",
                b"noembed",
                b"noframes",
                b"plaintext",
            ]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
        {
            self.raw = Some(start..body_start);
        }
        if closing
            || ![b"input".as_slice(), b"textarea", b"select", b"button"]
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n))
        {
            return None;
        }
        // A conditional suffix can add attributes. Keep only the unconditional
        // prefix; its fields are observations, not a complete attribute map.
        let known_end = prefix_end.unwrap_or(end);
        if mixed_unknown
            || condition_depth != 0
            || bytes
                .get(body_start..known_end)
                .is_some_and(|body| body.windows(3).any(|w| w.eq_ignore_ascii_case(b"<cf")))
            || bytes
                .get(body_start..end)
                .is_some_and(|body| body.windows(5).any(|w| w == b"<!---"))
        {
            self.limited = true;
            return None;
        }
        self.limited |= prefix_end.is_some();
        self.control_until = prefix_end.unwrap_or(end + 1);
        Some(Tag {
            name: start..body_start,
            body: body_start..known_end,
            span: at..end + 1,
            closing: false,
        })
    }
}

// HTML allows boolean attributes and does not double quote characters to escape
// them. Hash expressions apply only while the containing CFOUTPUT is active.
pub(super) fn attributes(bytes: &[u8], tag: &Tag, interpolate: bool) -> Option<Vec<Attribute>> {
    let mut out: Vec<Attribute> = Vec::new();
    let mut at = tag.body.start;
    let end = tag.body.end;
    // Everything through the body; indexing it past `end` yields `None`.
    let body = bytes.get(..end)?;
    while at < end {
        while body.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        if at == end || (at + 1 == end && body.get(at) == Some(&b'/')) {
            break;
        }
        if out.len() == 64 {
            return None;
        }
        let start = at;
        while body.get(at).is_some_and(|b| {
            !b.is_ascii_whitespace()
                && !matches!(b, b'=' | b'/' | b'>' | b'\'' | b'"' | b'<' | b'`')
        }) {
            at += 1;
        }
        if at == start {
            return None;
        }
        let name = start..at;
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
        if quote.is_some() {
            at += 1;
        }
        let start = at;
        while let Some(&b) = body.get(at) {
            if quote == Some(b) || (quote.is_none() && b.is_ascii_whitespace()) {
                break;
            }
            if interpolate && b == b'#' {
                if bytes.get(at + 1) == Some(&b'#') {
                    at += 2;
                    continue;
                }
                at += 1;
                if !interpolation(body, &mut at) {
                    return None;
                }
            } else {
                if quote.is_none() && matches!(b, b'\'' | b'"' | b'<' | b'=' | b'`') {
                    return None;
                }
                at += 1;
            }
        }
        let value = start..at;
        if let Some(q) = quote {
            if body.get(at) != Some(&q) {
                return None;
            }
            at += 1;
            if body
                .get(at)
                .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'/')
            {
                return None;
            }
        }
        out.push(Attribute {
            name,
            value,
            quoted: quote.is_some(),
        });
    }
    Some(out)
}

// Numeric references cover ASCII name obfuscation without an HTML entity table.
// Unsupported named references produce an explicit unknown. Decoding only shrinks.
pub(super) fn decode_references(text: &str) -> Result<Option<String>, ()> {
    if !text.contains('&') {
        return Ok(None);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        let mut decoded = None;
        for (entity, value) in [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ] {
            if rest.starts_with(entity) {
                decoded = Some((entity.len(), value));
                break;
            }
        }
        if rest.starts_with("&#") {
            let hex = rest
                .as_bytes()
                .get(2)
                .is_some_and(|b| matches!(b, b'x' | b'X'));
            let start = if hex { 3 } else { 2 };
            let mut end = start;
            while rest.as_bytes().get(end).is_some_and(|b| {
                if hex {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            }) {
                end += 1;
            }
            if end > start {
                // HTML numeric references use replacement for invalid scalar
                // values and the legacy Windows-1252 mapping for C1 codes.
                const C1: [u32; 32] = [
                    0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030,
                    0x160, 0x2039, 0x152, 0x8d, 0x17d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d,
                    0x2022, 0x2013, 0x2014, 0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e,
                    0x178,
                ];
                let mut value = u32::from_str_radix(&rest[start..end], if hex { 16 } else { 10 })
                    .unwrap_or(0xfffd);
                if let Some(&windows_1252) = value
                    .checked_sub(0x80)
                    .and_then(|index| C1.get(usize::try_from(index).ok()?))
                {
                    value = windows_1252;
                }
                let value = char::from_u32(value)
                    .filter(|c| *c != '\0')
                    .unwrap_or('\u{fffd}');
                decoded = Some((
                    end + usize::from(rest.as_bytes().get(end) == Some(&b';')),
                    value,
                ));
            }
        }
        if decoded.is_none()
            && rest.starts_with('&')
            && rest.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
        {
            return Err(());
        }
        let len = if let Some((len, value)) = decoded {
            out.push(value);
            len
        } else {
            out.push(c);
            c.len_utf8()
        };
        rest = rest.get(len..).unwrap_or_default();
    }
    Ok((out != text).then_some(out))
}

#[cfg(test)]
mod tests;
