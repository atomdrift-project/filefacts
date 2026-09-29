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
    while at < bytes.len() {
        if starts(bytes, at, b"</cfscript")
            && bytes
                .get(at + 10)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>')
        {
            return Ok(at);
        }
        if matches!(bytes[at], b'\'' | b'"') {
            if !quoted(bytes, &mut at) {
                return Err(Limit::Truncated);
            }
        } else if starts(bytes, at, b"//") {
            while at < bytes.len() && !matches!(bytes[at], b'\n' | b'\r') {
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
    let quote = bytes[*at];
    *at += 1;
    while *at < bytes.len() {
        match bytes[*at] {
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
    while *at < bytes.len() {
        match bytes[*at] {
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
    while at < bytes.len() {
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
        if markup.in_output() && bytes[at] == b'#' {
            if bytes.get(at + 1) == Some(&b'#') {
                at += 2;
                continue;
            }
            let begin = at + 1;
            let inside_tag = markup.inside_tag(at);
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
        if bytes[at] != b'<' {
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
        out.tags.push(Tag {
            name: name_start..name_end,
            body: body_start..at,
            span: start..at + 1,
            closing,
        });
        markup.cf_tag(bytes, out.tags.last().unwrap());
        at += 1;
        if !closing && bytes[name_start..name_end].eq_ignore_ascii_case(b"cfscript") {
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

// A malformed or duplicate attribute invalidates the whole tag. Consumers
// must not make a call from a partially recognized argument list.
pub(super) fn attributes(bytes: &[u8], tag: &Tag) -> Option<Vec<Attribute>> {
    let mut out: Vec<Attribute> = Vec::new();
    let mut at = tag.body.start;
    let end = tag.body.end;
    if end > bytes.len() || at > end {
        return None;
    }
    while at < end {
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at == end || (at + 1 == end && bytes[at] == b'/') {
            break;
        }
        if out.len() == 64 {
            return None;
        }
        let begin = at;
        while at < end && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'-')) {
            at += 1;
        }
        if at == begin {
            return None;
        }
        let name = begin..at;
        if out
            .iter()
            .any(|a| bytes[a.name.clone()].eq_ignore_ascii_case(&bytes[name.clone()]))
        {
            return None;
        }
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if bytes.get(at) != Some(&b'=') {
            return None;
        }
        at += 1;
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at == end {
            return None;
        }
        let is_quoted = matches!(bytes[at], b'\'' | b'"');

        let value = if is_quoted {
            let begin = at + 1;
            if !quoted(&bytes[..end], &mut at) {
                return None;
            }
            begin..at - 1
        } else {
            let begin = at;
            while at < end && !bytes[at].is_ascii_whitespace() {
                if bytes[at] == b'#' {
                    at += 1;
                    if !interpolation(&bytes[..end], &mut at) {
                        return None;
                    }
                } else {
                    at += 1;
                }
            }
            begin..at
        };
        if at < end && !bytes[at].is_ascii_whitespace() && bytes[at] != b'/' {
            return None;
        }
        out.push(Attribute {
            name,
            value,
            quoted: is_quoted,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_offsets_case_and_closing_tags() {
        let b = b"abc<CFEXECUTE name='x'>body</CfExecute>";
        let s = scan(b);
        assert_eq!(s.limitation, None);
        assert_eq!(s.tags.len(), 2);
        assert_eq!(s.tags[0].span, 3..23);
        assert_eq!(&b[s.tags[0].name.clone()], b"CFEXECUTE");
        assert_eq!(&b[s.tags[0].body.clone()], b" name='x'");
        assert!(s.tags[1].closing);
    }

    #[test]
    fn nested_cfcomments_hide_tags() {
        let s = scan(b"<!--- <cfset x=1> <!--- <cfexecute> ---> ---><cfoutput>");
        assert_eq!(s.limitation, None);
        assert_eq!(s.tags.len(), 1);
    }

    #[test]
    fn quoted_tags_and_greater_than_are_opaque() {
        let b = b"<cfset x='a > '' <cfexecute> b'><cfoutput>";
        let s = scan(b);
        assert_eq!(s.limitation, None);
        assert_eq!(s.tags.len(), 2);
        assert_eq!(&b[s.tags[0].body.clone()], b" x='a > '' <cfexecute> b'");
    }

    #[test]
    fn interpolation_quotes_and_escaped_hashes() {
        let b = br###"<cfexecute name="#form["a>b"]#" arguments="##literal##">"###;
        let s = scan(b);
        assert_eq!(s.limitation, None);
        assert_eq!(s.tags.len(), 1);
        assert_eq!(s.tags[0].span.end, b.len());
    }

    #[test]
    fn partial_tokens_and_script_are_explicit() {
        for b in [
            b"<cfset x='no".as_slice(),
            b"<!--- open",
            b"<cfexecute name=",
            b"<cfset x='#form.x'",
        ] {
            assert_eq!(scan(b).limitation, Some(Limit::Truncated));
        }
        let s = scan(b"<cfscript>x='<cfexecute>';</cfscript><cfexecute>");
        assert_eq!(s.limitation, Some(Limit::Script));
        assert_eq!(s.tags.len(), 3);
        assert_eq!(s.scripts.len(), 1);
    }

    #[test]
    fn script_boundaries_ignore_strings_and_comment_contents() {
        let source = br##"<cfscript>
        x="</cfscript><cfexecute name='fake'>";
        y='double '' quote </cfscript>';
        // </cfscript><cfexecute name='fake'>
        /* </cfscript><cfexecute name='fake'> */
        <!--- nested <!--- </cfscript> ---> --->
        </CFSCRIPT ><cfexecute name='real'>"##;
        let s = scan(source);
        assert_eq!(s.limitation, Some(Limit::Script));
        assert_eq!(s.tags.len(), 3);
        assert_eq!(s.scripts.len(), 1);
        assert_eq!(&source[s.tags[2].name.clone()], b"cfexecute");
        assert_eq!(&source[s.tags[2].body.clone()], b" name='real'");
        assert_eq!(s.scripts[0].end, s.tags[1].span.start);
    }

    #[test]
    fn script_boundaries_are_bounded_and_truncation_is_explicit() {
        for source in [
            b"<cfscript>x='unterminated".as_slice(),
            b"<cfscript>/* </cfscript>",
            b"<cfscript>// </cfscript>",
            b"<cfscript><!--- </cfscript>",
            b"<cfscript></cfscriptExtra>",
        ] {
            assert_eq!(scan(source).limitation, Some(Limit::Truncated));
        }
        let source = format!("<cfscript>{}", "<!---".repeat(MAX_COMMENT_DEPTH + 1));
        assert_eq!(
            scan(source.as_bytes()).limitation,
            Some(Limit::CommentDepth)
        );
        let source = b"<cfscript>/* x */ a='</cfscript>'; // x\n</cfscript><cfexecute name='real'>";
        for end in 0..=source.len() {
            let s = scan(&source[..end]);
            assert!(s.tags.iter().all(|t| t.span.end <= end));
            assert!(s.scripts.iter().all(|r| r.start <= r.end && r.end <= end));
        }
        let s = scan(b"<cfscript>x=1;</cfscript><cfscript>y=2;</cfscript><cfexecute>");
        assert_eq!(s.scripts.len(), 2);
        assert_eq!(s.tags.len(), 5);
    }

    #[test]
    fn budgets_and_every_prefix_are_bounded() {
        assert_eq!(
            scan(&vec![b'x'; MAX_BYTES + 1]).limitation,
            Some(Limit::Bytes)
        );
        assert_eq!(
            scan(&b"<cfset>".repeat(MAX_TAGS + 1)).limitation,
            Some(Limit::Tags)
        );
        assert_eq!(
            scan(&b"<!---".repeat(MAX_COMMENT_DEPTH + 1)).limitation,
            Some(Limit::CommentDepth)
        );
        let b = br###"<!--- nested <!--- x ---> ---><cfset x="#form["p"]#"><cfexecute>"###;
        for end in 0..=b.len() {
            let s = scan(&b[..end]);
            for tag in s.tags {
                assert!(tag.span.end <= end);
            }
        }
    }
    #[test]
    fn retained_original_tag_offsets() {
        use sha2::{Digest, Sha256};
        let decoded = include_bytes!("../../../testdata/cfml/encrypted_shell_decoded.cfm");
        assert_eq!(
            format!("{:x}", Sha256::digest(decoded)),
            "110db2340e0aecb5c59d73b15617b28999d941f974ae04acf4d53ddcf945e9dc"
        );
        let s = scan(decoded);
        assert_eq!(s.limitation, None);
        assert_eq!(
            s.tags
                .iter()
                .filter(|t| starts(decoded, t.name.start, b"cf"))
                .count(),
            332
        );
        assert!(s.tags.iter().any(|t| &decoded[t.name.clone()] == b"input"));
        let calls: Vec<_> = s
            .tags
            .iter()
            .filter(|t| !t.closing && decoded[t.name.clone()].eq_ignore_ascii_case(b"cfexecute"))
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].span.start, 12558);
        let direct = include_bytes!("../../../testdata/cfml/datasource_shell.cfm");
        assert_eq!(
            format!("{:x}", Sha256::digest(direct)),
            "987de3c74aaa5371c98365b281fdc3c4b680558aae5b4c9895ec6b8c9fc083d2"
        );
        let s = scan(direct);
        assert_eq!(s.limitation, Some(Limit::Script));
        assert_eq!(s.scripts.len(), 1);
        assert!(
            direct[s.scripts[0].clone()]
                .windows(b"getDatasources".len())
                .any(|s| s == b"getDatasources")
        );
        assert!(
            s.tags
                .last()
                .is_some_and(|t| t.closing && &direct[t.name.clone()] == b"cfoutput")
        );
        let calls: Vec<_> = s
            .tags
            .iter()
            .filter(|t| !t.closing && direct[t.name.clone()].eq_ignore_ascii_case(b"cfexecute"))
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].span.start, 878);
    }
    #[test]
    fn attributes_preserve_order_ranges_and_interpolation() {
        let b = br###"<CFEXECUTE timeout=10 arguments="#form["opts"]#" NAME = '#selected#' />"###;
        let tags = scan(b);
        let attrs = attributes(b, &tags.tags[0]).unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(&b[attrs[0].name.clone()], b"timeout");
        assert_eq!(&b[attrs[0].value.clone()], b"10");
        assert!(!attrs[0].quoted);
        assert_eq!(&b[attrs[1].value.clone()], br###"#form["opts"]#"###);
        assert!(attrs[1].quoted);
        assert_eq!(&b[attrs[2].value.clone()], b"#selected#");
    }

    #[test]
    fn attributes_reject_duplicates_partial_and_excessive_lists() {
        for b in [
            b"<cfexecute name='a' NAME='b'>".as_slice(),
            b"<cfexecute name>",
            b"<cfexecute name=>",
            b"<cfexecute name='a'arguments='b'>",
        ] {
            let s = scan(b);
            assert!(attributes(b, &s.tags[0]).is_none());
        }
        let mut b = String::from("<cfexecute");
        for i in 0..65 {
            b.push_str(&format!(" a{i}='x'"));
        }
        b.push('>');
        let s = scan(b.as_bytes());
        assert!(attributes(b.as_bytes(), &s.tags[0]).is_none());
    }
    #[test]
    fn encrypted_templates_need_decoding_before_syntax() {
        let original = include_bytes!("../../../testdata/cfml/encrypted_shell_original.cfm");
        let s = scan(original);
        assert_eq!(s.limitation, Some(Limit::Encrypted));
        assert!(s.tags.is_empty());
    }
}
