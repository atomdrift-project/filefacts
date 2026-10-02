use super::*;
use crate::{Arg, FlowKind, Symbol};
use std::collections::BTreeSet;

fn controls(source: &[u8]) -> BTreeSet<(String, String)> {
    let p = super::super::parse(source);
    p.flow
        .values
        .iter()
        .filter(|v| {
            v.kind == FlowKind::Call
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
        assert_eq!(
            p.symbols
                .iter()
                .filter(
                    |s| matches!(s, Symbol::Call {target: t, ..} if t.as_deref() == Some(target))
                )
                .count(),
            1
        );
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
            .filter(|s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("f")))
            .count(),
        1
    );
    assert!(controls(br##"<input <cfif enabled>name="cmd"</cfif>>"##).is_empty());
    assert!(controls(br##"<input name="cmd" <cfif enabled>value="fixed">"##).is_empty());
}

#[test]
fn retained_datasource_shell_has_conditional_command_controls() {
    let source = include_bytes!("../../../../testdata/cfml/datasource_shell.cfm");
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
    let source =
        br##"<cfoutput><div title="#f('cmd')#"></div></cfoutput><!-- <cfinput name='cmd'> -->"##;
    let p = super::super::parse(source);
    assert_eq!(
        p.symbols
            .iter()
            .filter(|s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("f")))
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
        .filter(|v| v.kind == FlowKind::Concat)
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
        assert!(
            p.symbols.iter().any(
                |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfexecute"))
            ),
            "{tag}"
        );
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
        assert_eq!(
            p.symbols
                .iter()
                .filter(
                    |s| matches!(s, Symbol::Call {target: t, ..} if t.as_deref() == Some(target))
                )
                .count(),
            count,
            "{target}"
        );
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
    assert!(
        p.symbols.iter().any(
            |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfexecute"))
        )
    );
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
    let source = include_bytes!("../../../../testdata/cfml/encrypted_shell_decoded.cfm");
    assert!(controls(source).contains(&("html:input".into(), "command".into())));
    let p = super::super::parse(source);
    assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call {target, offset: Some(offset), ..} if target.as_deref() == Some("html:input") && source[*offset as usize..].starts_with(b"<input type=\"text\" name=\"command\""))));
}
