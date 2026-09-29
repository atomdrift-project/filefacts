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
        if bytes[tag.name.clone()].eq_ignore_ascii_case(b"cfoutput") {
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
            } else if bytes[at] == b'>'
                && (at == self.until || (at == self.until + 1 && bytes[self.until] == b'-'))
            {
                self.comment = false;
                self.until = at + 1;
            }
            return None;
        }
        if let Some(raw) = &self.raw {
            if bytes[raw.clone()].eq_ignore_ascii_case(b"plaintext") {
                return None;
            }
            if !starts(bytes, at, b"</")
                || !starts(bytes, at + 2, &bytes[raw.clone()])
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
            while end < bytes.len() {
                let b = bytes[end];
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
        while end < bytes.len() {
            let b = bytes[end];
            if quote.is_none() && (starts(bytes, end, b"<cf") || starts(bytes, end, b"</cf")) {
                let cf_start = end;
                let cf_closing = bytes.get(end + 1) == Some(&b'/');
                let cf_name = end + 1 + usize::from(cf_closing);
                end = cf_name;
                while bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
                    end += 1;
                }
                let cf = &bytes[cf_name..end];
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
                while end < bytes.len() && bytes[end] != b'>' {
                    if matches!(bytes[end], b'\'' | b'"') {
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
        let name = &bytes[start..body_start];
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
            || bytes[body_start..known_end]
                .windows(3)
                .any(|w| w.eq_ignore_ascii_case(b"<cf"))
            || bytes[body_start..end].windows(5).any(|w| w == b"<!---")
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
        let start = at;
        while at < end
            && !bytes[at].is_ascii_whitespace()
            && !matches!(bytes[at], b'=' | b'/' | b'>' | b'\'' | b'"' | b'<' | b'`')
        {
            at += 1;
        }
        if at == start {
            return None;
        }
        let name = start..at;
        if out
            .iter()
            .any(|a| bytes[a.name.clone()].eq_ignore_ascii_case(&bytes[name.clone()]))
        {
            return None;
        }
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at == end || bytes[at] != b'=' {
            out.push(Attribute {
                name,
                value: at..at,
                quoted: false,
            });
            continue;
        }
        at += 1;
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at == end {
            return None;
        }
        let quote = matches!(bytes[at], b'\'' | b'"').then_some(bytes[at]);
        if quote.is_some() {
            at += 1;
        }
        let start = at;
        while at < end {
            if quote == Some(bytes[at]) || (quote.is_none() && bytes[at].is_ascii_whitespace()) {
                break;
            }
            if interpolate && bytes[at] == b'#' {
                if bytes.get(at + 1) == Some(&b'#') {
                    at += 2;
                    continue;
                }
                at += 1;
                if !interpolation(&bytes[..end], &mut at) {
                    return None;
                }
            } else {
                if quote.is_none() && matches!(bytes[at], b'\'' | b'"' | b'<' | b'=' | b'`') {
                    return None;
                }
                at += 1;
            }
        }
        let value = start..at;
        if let Some(q) = quote {
            if at == end || bytes[at] != q {
                return None;
            }
            at += 1;
            if at < end && !bytes[at].is_ascii_whitespace() && bytes[at] != b'/' {
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
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
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
                if (0x80..=0x9f).contains(&value) {
                    value = C1[(value - 0x80) as usize];
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
        if let Some((len, value)) = decoded {
            out.push(value);
            at += len;
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            at += c.len_utf8();
        }
    }
    Ok((out != text).then_some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Arg, Symbol};
    use std::collections::BTreeSet;

    fn controls(source: &[u8]) -> BTreeSet<(String, String)> {
        let p = super::super::parse(source);
        p.flow
            .values
            .iter()
            .filter(|v| {
                v.kind == "call"
                    && v.target.as_deref().is_some_and(|t| {
                        t.starts_with("html:") || matches!(t, "cfinput" | "cftextarea" | "cfselect")
                    })
            })
            .flat_map(|call| {
                p.flow
                    .complete_values(call.inputs[0], Some("name"), 1000)
                    .values
                    .into_iter()
                    .filter_map(|id| match &p.flow.values[id.value].literal {
                        Some(Arg::String { value }) => {
                            Some((call.target.clone().unwrap(), value.clone()))
                        }
                        _ => None,
                    })
            })
            .collect()
    }

    #[test]
    fn markup_targets_cannot_collide_with_cfscript_member_calls() {
        let p = super::super::parse(b"<cfscript>html.input('cmd');</cfscript><input name='cmd'>");
        for target in ["html.input", "html:input"] {
            assert_eq!(p.symbols.iter().filter(|s| matches!(s, Symbol::Call {target: t, ..} if t.as_deref() == Some(target))).count(), 1);
        }
    }
    #[test]
    fn declarations_and_comment_edges_do_not_invent_controls() {
        // Three opening dashes are a server-side CFML comment, not HTML's
        // abruptly closed empty comment. CFML precedence must be preserved.
        assert!(controls(b"<!---><input name='cmd'>").is_empty());
        for source in [
            r#"<!unknown <input name='cmd'>>"#,
            r#"<?example <input name='cmd'>>"#,
            r#"<!DOCTYPE html PUBLIC "<input name='cmd'><input name='opts'>">"#,
        ] {
            assert!(controls(source.as_bytes()).is_empty(), "{source}");
        }
        for prefix in ["<!-->", "<!-- text --!>"] {
            let source = format!("{prefix}<input name='cmd'>");
            assert!(
                controls(source.as_bytes()).contains(&("html:input".into(), "cmd".into())),
                "{prefix}"
            );
        }
    }
    #[test]
    fn conditional_attribute_suffix_keeps_only_unconditional_fields() {
        let source = br##"<cfoutput><input name="cmd" <cfif enabled>value="#f('x')#"<cfelse>value="fixed"</cfif>></cfoutput>"##;
        assert_eq!(
            controls(source),
            BTreeSet::from([("html:input".into(), "cmd".into())])
        );
        let p = super::super::parse(source);
        let call = p
            .flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("html:input"))
            .unwrap();
        assert!(!p.flow.values[call.inputs[0]].fields.contains_key("value"));
        assert!(p.flow.limitations.contains("markup-syntax-unavailable"));
        assert_eq!(
            p.symbols
                .iter()
                .filter(
                    |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("f"))
                )
                .count(),
            1
        );
        assert!(controls(br##"<input <cfif enabled>name="cmd"</cfif>>"##).is_empty());
        assert!(controls(br##"<input name="cmd" <cfif enabled>value="fixed">"##).is_empty());
    }

    #[test]
    fn retained_datasource_shell_has_conditional_command_controls() {
        let source = include_bytes!("../../../testdata/cfml/datasource_shell.cfm");
        let names = controls(source);
        for name in ["cmd", "opts", "timeout"] {
            assert!(
                names.contains(&("html:input".into(), name.into())),
                "{name}"
            );
        }
    }
    #[test]
    fn numeric_references_follow_html_scalar_and_c1_rules() {
        for (source, expected) in [
            ("&#x80;", "€"),
            ("&#159;", "Ÿ"),
            ("&#xD800;", "\u{fffd}"),
            ("&#0;", "\u{fffd}"),
            ("&#999999999999999999999;", "\u{fffd}"),
            ("&#0000000000000000000099;md", "cmd"),
            ("&#x1f600;", "😀"),
        ] {
            assert_eq!(
                decode_references(source).unwrap().as_deref(),
                Some(expected),
                "{source}"
            );
        }
    }
    #[test]
    fn server_expressions_in_non_control_attributes_remain_visible() {
        let source = br##"<cfoutput><div title="#f('cmd')#"></div></cfoutput><!-- <cfinput name='cmd'> -->"##;
        let p = super::super::parse(source);
        assert_eq!(
            p.symbols
                .iter()
                .filter(
                    |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("f"))
                )
                .count(),
            1
        );
        assert!(controls(source).contains(&("cfinput".into(), "cmd".into())));
    }

    #[test]
    fn entity_and_interpolation_allocations_share_the_constant_budget() {
        let source = format!(
            "<cfset v='{}'><cfoutput>{}</cfoutput>",
            "&amp;".repeat(10_000),
            "<input name='#v#'>".repeat(200)
        );
        let p = super::super::parse(source.as_bytes());
        assert!(
            p.flow.limitations.contains("constant-string-budget")
                || p.flow.limitations.contains("markup-entity-budget")
        );
        let computed: usize = p
            .flow
            .values
            .iter()
            .filter(|v| v.kind == "concat")
            .filter_map(|v| match &v.literal {
                Some(Arg::String { value }) => Some(value.len()),
                _ => None,
            })
            .sum();
        assert!(computed <= super::super::MAX_BYTES);
    }
    #[test]
    fn controls_and_boolean_attributes_have_names_and_real_offsets() {
        for (tag, target) in [
            ("input", "html:input"),
            ("textarea", "html:textarea"),
            ("select", "html:select"),
            ("button", "html:button"),
            ("cfinput", "cfinput"),
            ("cftextarea", "cftextarea"),
            ("cfselect", "cfselect"),
        ] {
            let source = format!("<cfoutput>abc<{tag} name='cmd'></{tag}></cfoutput>");
            assert_eq!(
                controls(source.as_bytes()),
                BTreeSet::from([(target.into(), "cmd".into())])
            );
            let p = super::super::parse(source.as_bytes());
            assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call {target: t, offset: Some(13), ..} if t.as_deref() == Some(target))), "{tag}");
        }
        assert_eq!(
            controls(b"<INPUT disabled NAME=cmd readonly>"),
            BTreeSet::from([("html:input".into(), "cmd".into())])
        );
    }

    #[test]
    fn comments_strings_attributes_and_unrelated_tags_are_not_controls() {
        for source in [
            r#"<!-- <input name='cmd'> -->"#,
            r#"<!--- <input name='cmd'> <!--- <cfinput name='cmd'> ---> --->"#,
            r#"<cfset text="<input name='cmd'>">"#,
            r#"<cfscript>x="<input name='cmd'>";</cfscript>"#,
            r#"<div title="<input name='cmd'>">Text</div>"#,
            r#"<meta name='cmd'>"#,
            r#"<inputExtra name='cmd'>"#,
            r#"&lt;input name='cmd'&gt;"#,
            r##"<cfoutput>#'<input name="cmd">'#</cfoutput>"##,
        ] {
            assert!(controls(source.as_bytes()).is_empty(), "{source}");
        }
    }

    #[test]
    fn raw_text_hides_controls_without_hiding_server_operations() {
        for tag in [
            "script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes",
        ] {
            let source = format!(
                "<{tag}>text <input name='fake'><cfexecute name='#form.command#'></{tag}><input name='real'>"
            );
            assert_eq!(
                controls(source.as_bytes()),
                BTreeSet::from([("html:input".into(), "real".into())]),
                "{tag}"
            );
            let p = super::super::parse(source.as_bytes());
            assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfexecute"))), "{tag}");
        }
        for source in [
            r#"<!-- <input name='fake'><cfexecute name='#form.command#'> -->"#,
            r#"<div title="<cfexecute name='#form.command#'>"></div>"#,
            r#"<plaintext><input name='fake'><cfexecute name='#form.command#'>"#,
        ] {
            assert!(controls(source.as_bytes()).is_empty());
            assert!(super::super::parse(source.as_bytes()).symbols.iter().any(
                |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfexecute"))
            ));
        }
    }

    #[test]
    fn interpolation_is_scoped_and_keeps_generated_markup_opaque() {
        let source = br##"<cfset field='cmd'><input name='#field#'><cfoutput><input name='#field#'></cfoutput><input name='#field#'>"##;
        assert_eq!(
            controls(source),
            BTreeSet::from([
                ("html:input".into(), "#field#".into()),
                ("html:input".into(), "cmd".into())
            ])
        );
        let source = br##"<cfoutput>#createObject('java', 'Example')# #'<cfexecute name="fake">'#<input name='#f("cmd")#'></cfoutput>"##;
        let p = super::super::parse(source);
        for (target, count) in [("createobject", 1), ("f", 1), ("cfexecute", 0)] {
            assert_eq!(p.symbols.iter().filter(|s| matches!(s, Symbol::Call {target: t, ..} if t.as_deref() == Some(target))).count(), count, "{target}");
        }
        assert!(controls(source).is_empty());
    }

    #[test]
    fn entity_decoding_does_not_change_bindings_or_literal_hashes() {
        for name in [
            "c&#109;d",
            "c&#x6d;d",
            "c&#X6D;d",
            "&#99;&#109;&#100;",
            "&#99md",
        ] {
            let source = format!("<input name='{name}'>");
            assert_eq!(
                controls(source.as_bytes()),
                BTreeSet::from([("html:input".into(), "cmd".into())]),
                "{name}"
            );
        }
        assert_eq!(
            controls(b"<input name='##cmd##'>"),
            BTreeSet::from([("html:input".into(), "##cmd##".into())])
        );
        let source = br##"<cfset value='c&##109;d'><cfoutput><input name='#value#'></cfoutput><cfinput name='#value#'>"##;
        assert_eq!(
            controls(source),
            BTreeSet::from([
                ("html:input".into(), "cmd".into()),
                ("cfinput".into(), "c&#109;d".into())
            ])
        );
        assert_eq!(decode_references("&unknown;"), Err(()));
        let p = super::super::parse(b"<input name='c&unknown;md'>");
        assert!(
            p.flow
                .limitations
                .contains("markup-named-entity-unavailable")
        );
        assert!(controls(b"<input name='c&unknown;md'>").is_empty());
    }

    #[test]
    fn malformed_attributes_and_mixed_start_tags_are_conservative() {
        for source in [
            r#"<input name='cmd' NAME='other'>"#,
            r#"<input name="cmd>"#,
            r#"<input name=>"#,
            r#"<input name='cmd'bad='x'>"#,
            r#"<input name='cmd' value='<cfset x=1>'>"#,
        ] {
            assert!(controls(source.as_bytes()).is_empty(), "{source}");
        }
        let source = r#"<input name='cmd' value="<cfexecute name='fixed'>">"#;
        let p = super::super::parse(source.as_bytes());
        assert!(p.flow.limitations.contains("markup-syntax-unavailable"));
        assert!(p.symbols.iter().any(
            |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfexecute"))
        ));
    }

    #[test]
    fn markup_limits_and_every_prefix_are_bounded() {
        let source = br##"<!-- <cfexecute name='#form.command#'> --><cfset field='cmd'><cfoutput><input disabled name='#field#' <cfif enabled>value='#f("x")#'<cfelse>value='fixed'</cfif>>#f('x')#</cfoutput><textarea name='body'><input name='fake'></textarea>"##;
        for end in 0..=source.len() {
            let p = super::super::parse(&source[..end]);
            assert!(p.flow.values.len() <= 20_000);
            for v in &p.flow.values {
                assert!(v.offset <= end);
                assert!(v.inputs.iter().all(|id| *id < p.flow.values.len()));
                assert!(v.fields.values().all(|id| *id < p.flow.values.len()));
            }
        }
        let source = format!(
            "<input name=cmd {}>",
            (0..65).map(|i| format!("a{i}='x' ")).collect::<String>()
        );
        assert!(controls(source.as_bytes()).is_empty());
        let s = super::super::scan(&b"<input name=cmd>".repeat(super::super::MAX_TAGS + 1));
        assert_eq!(s.limitation, Some(super::super::Limit::Tags));
    }

    #[test]
    fn retained_shell_has_real_command_control() {
        let source = include_bytes!("../../../testdata/cfml/encrypted_shell_decoded.cfm");
        assert!(controls(source).contains(&("html:input".into(), "command".into())));
        let p = super::super::parse(source);
        assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call {target, offset: Some(offset), ..} if target.as_deref() == Some("html:input") && source[*offset as usize..].starts_with(b"<input type=\"text\" name=\"command\""))));
    }
}
