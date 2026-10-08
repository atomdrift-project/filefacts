use super::*;
/// A call receiver ends at the `.` byte in the source. Lossy decoding
/// widens each invalid byte to three, so the `.` offset in the decoded
/// prefix used to address past the end of the input and panic.
#[test]
fn invalid_utf8_call_receiver_stays_within_the_source() {
    let invalid = [0xff; 100];
    for (open, close) in [
        (b"<cfset a = ".as_slice(), b".foo()>".as_slice()),
        (b"<cfoutput>#", b".foo()#</cfoutput>"),
    ] {
        let source = [open, &invalid, close].concat();
        let p = parse(&source);
        assert!(
            p.flow.limitations.contains("unsupported-call-target"),
            "{:?}",
            p.flow.limitations
        );
        assert!(
            p.flow
                .values
                .iter()
                .all(|v| !v.target.as_deref().is_some_and(|t| t.ends_with("foo")))
        );
    }
}
#[test]
fn ordinary_tag_attribute_text_is_consistent_across_call_kinds() {
    for (tag, field, expected) in [
        ("cfhttp", "method", "POST"),
        ("cfdirectory", "action", "delete"),
        ("cffile", "action", "read"),
        ("cfexecute", "name", "cmd.exe"),
        ("cfexecute", "timeout", "30"),
        ("cfhttp", "throwonerror", "true"),
    ] {
        for quoted in [false, true] {
            let attribute = if quoted {
                format!("\"{expected}\"")
            } else {
                expected.into()
            };
            let source = format!("<{tag} {field}={attribute}>");
            let p = parse(source.as_bytes());
            let call = p
                .flow
                .values
                .iter()
                .find(|v| v.target.as_deref() == Some(tag))
                .unwrap();
            let values = p.flow.complete_values(call.inputs[0], Some(field), 1000);
            assert_eq!(values.values.len(), 1, "{source}");
            assert!(
                matches!(&p.flow.values[values.values.iter().next().unwrap().value].literal, Some(Arg::String {value}) if value == expected),
                "{source}"
            );
        }
    }
}
#[test]
fn unquoted_tag_values_are_literals_unless_interpolated() {
    for (source, expected) in [
        ("<cffile action=read>", "read"),
        ("<cfset read='delete'><cffile action=read>", "read"),
        ("<cfset action='read'><cffile action=#action#>", "read"),
        ("<cffile action=#'re' & 'ad'#>", "read"),
        ("<cffile action=re#'ad'#>", "read"),
        ("<cffile action=##read##>", "#read#"),
    ] {
        let (values, incomplete) = action_values(source.as_bytes());
        assert_eq!(values, BTreeSet::from([expected.into()]), "{source}");
        assert!(!incomplete, "{source}");
    }
}
#[test]
fn unquoted_literals_do_not_invent_request_or_function_origins() {
    for value in ["form.command", "url.command", "alias", "getCommand()"] {
        let source = format!("<cfset alias=form.command><cfexecute name={value}>");
        let p = parse(source.as_bytes());
        let call = p
            .flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("cfexecute"))
            .unwrap();
        let values = p.flow.complete_values(call.inputs[0], Some("name"), 1000);
        assert_eq!(values.values.len(), 1, "{value}");
        assert!(
            matches!(&p.flow.values[values.values.iter().next().unwrap().value].literal, Some(Arg::String {value: actual}) if actual == value)
        );
        assert!(
            !targets(source.as_bytes()).contains("form.command"),
            "{value}"
        );
        assert!(!p.symbols.iter().any(
            |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("getcommand"))
        ));
    }
    for value in ["#form.command#", "#alias#", "prefix#form.command#suffix"] {
        let source = format!("<cfset alias=form.command><cfexecute name={value}>");
        assert!(
            targets(source.as_bytes()).contains("form.command"),
            "{value}"
        );
    }
}
#[test]
fn unquoted_attribute_offsets_and_all_prefixes_remain_valid() {
    let source = b"<cfset action='delete'><cfdirectory directory=#form.path# action=#action#><cfhttp method=POST url=https://example.invalid/>";
    for end in 0..=source.len() {
        let p = parse(&source[..end]);
        assert!(p.flow.values.len() <= MAX_VALUES);
        for value in &p.flow.values {
            assert!(value.offset <= end as u64);
            assert!(value.inputs.iter().all(|id| *id < p.flow.values.len()));
            assert!(value.fields.values().all(|id| *id < p.flow.values.len()));
        }
    }
    let p = parse(b"<cffile action=read file=fixed>");
    let literal = p
        .flow
        .values
        .iter()
        .find(|v| matches!(&v.literal, Some(Arg::String {value}) if value == "read"))
        .unwrap();
    assert_eq!(literal.offset, 15);
}
#[test]
fn retained_shell_directory_creation_has_request_path_origins() {
    let p = parse(include_bytes!(
        "../../../../testdata/cfml/encrypted_shell_decoded.cfm"
    ));
    let call = p.flow.values.iter().find(|v| v.target.as_deref() == Some("cfdirectory") && p.flow.complete_values(v.inputs[0], Some("action"), 1000).values.iter().any(|id| matches!(&p.flow.values[id.value].literal, Some(Arg::String {value}) if value == "create"))).unwrap();
    let origins = p.flow.field_origins(call.inputs[0], "directory", &[], 1000);
    for expected in ["form.dir", "form.cr_dir"] {
        assert!(
            origins
                .values
                .iter()
                .any(|id| p.flow.values[id.value].target.as_deref() == Some(expected)),
            "{expected}"
        );
    }
}
#[test]
fn assignment_shapes_describe_syntax_not_resolved_values() {
    for (rhs, expected) in [
        ("'secret'", ArgShape::String),
        ("''", ArgShape::String),
        ("'it''s ##literal##'", ArgShape::String),
        ("'#form.password#'", ArgShape::Template),
        ("'prefix' & 'suffix'", ArgShape::Expression),
        ("alias", ArgShape::Identifier),
        ("form.password", ArgShape::Identifier),
        ("1", ArgShape::Number),
        ("-1.25", ArgShape::Number),
        (".5", ArgShape::Number),
        ("2e3", ArgShape::Number),
        ("true", ArgShape::Bool),
        ("FALSE", ArgShape::Bool),
        ("f()", ArgShape::Call),
        ("1invalid", ArgShape::Expression),
        ("form..password", ArgShape::Expression),
        ("", ArgShape::Expression),
    ] {
        let source = format!("<cfset alias='fixed'><cfset Variables.MyPwd={rhs}>");
        let p = parse(source.as_bytes());
        let bindings: Vec<_> = p
            .symbols
            .iter()
            .filter_map(|s| match s {
                Symbol::Bind {
                    target,
                    shape,
                    offset,
                } => Some((target, shape, *offset)),
                _ => None,
            })
            .collect();
        assert_eq!(bindings.len(), 2, "{rhs}");
        assert_eq!(bindings[1].0, "mypwd");
        assert_eq!(*bindings[1].1, expected, "{rhs}");
        assert_eq!(&source[bindings[1].2 as usize..][..15], "Variables.MyPwd");
    }
}
#[test]
fn assignments_exclude_comments_strings_and_invalid_targets() {
    for source in [
        "<!--- <cfset pwd='x'> --->",
        "<cfoutput><cfset 1pwd='x'></cfoutput>",
        "<cfset session..pwd='x'>",
        "<cfset pwd[1]='x'>",
    ] {
        assert!(
            !parse(source.as_bytes())
                .symbols
                .iter()
                .any(|s| matches!(s, Symbol::Bind { .. })),
            "{source}"
        );
    }
}
#[test]
fn simple_condition_comparisons_keep_names_values_and_offsets_separate() {
    for (condition, left, right) in [
        ("session.PWD neq MyPwd", "session.pwd", "mypwd"),
        ("MyPwd!=session.PWD", "mypwd", "session.pwd"),
        ("session.bearing NEQ compass", "session.bearing", "compass"),
    ] {
        let source = format!("<cfif {condition}></cfif>");
        let p = parse(source.as_bytes());
        let (args, offset) = p
            .symbols
            .iter()
            .find_map(|s| match s {
                Symbol::Call {
                    target,
                    args,
                    offset,
                } if target.as_deref() == Some("cfif") => Some((args, offset)),
                _ => None,
            })
            .unwrap();
        assert_eq!(*offset, Some(0));
        assert!(matches!(&args[0], Arg::Identifier {name} if name == left));
        assert!(matches!(&args[1], Arg::String {value} if value == "neq"));
        assert!(matches!(&args[2], Arg::Identifier {name} if name == right));
        let call = p
            .flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("cfif"))
            .unwrap();
        assert_eq!(call.inputs.len(), 3);
        let operator = &p.flow.values[call.inputs[1]];
        assert!(
            source[operator.offset as usize..].starts_with("neq")
                || source[operator.offset as usize..].starts_with("NEQ")
                || source[operator.offset as usize..].starts_with("!=")
        );
    }
}
#[test]
fn comparison_excludes_quoted_compound_and_malformed_conditions() {
    for condition in [
        "'session.pwd' neq pwd",
        "session.pwd neq 'pwd'",
        "session.pwd neq pwd AND enabled",
        "session.pwd eq pwd",
        "session..pwd neq pwd",
        "session.pwd!=pwd!=other",
        "session.pwd neq",
        "1pwd neq session.pwd",
    ] {
        let source = format!("<cfif {condition}></cfif>");
        assert!(
            !parse(source.as_bytes()).symbols.iter().any(
                |s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfif"))
            ),
            "{condition}"
        );
    }
    let p = parse(b"<!--- <cfif session.pwd neq pwd></cfif> ---><cfscript>x='<cfif session.pwd neq pwd>';</cfscript>");
    assert!(
        !p.symbols
            .iter()
            .any(|s| matches!(s, Symbol::Call {target, ..} if target.as_deref() == Some("cfif")))
    );
}
#[test]
fn retained_devshell_has_password_binding_and_session_inequality() {
    let p = parse(include_bytes!(
        "../../../../testdata/cfml/encrypted_shell_decoded.cfm"
    ));
    assert!(p.symbols.iter().any(
        |s| matches!(s, Symbol::Bind {target, shape: ArgShape::String, ..} if target == "mypwd")
    ));
    assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call {target, args, ..} if target.as_deref() == Some("cfif") && matches!(&args[0], Arg::Identifier {name} if name == "session.pwd") && matches!(&args[2], Arg::Identifier {name} if name == "mypwd"))));
}
#[test]
fn conditional_calls_are_observed_outside_comments_and_strings() {
    let source = br##"<!--- <cfif IsDefined('session.fake')> --->
        <cfif IsDefined("session.actual") eq "No"><cfset x=1>
        <cfelseif IsDefined("session.other")><cfset x=2></cfif>
        <cfif 'IsDefined("session.fake") eq "No"'></cfif>"##;
    let p = parse(source);
    let calls: Vec<_> = p
        .flow
        .values
        .iter()
        .filter(|v| v.target.as_deref() == Some("isdefined"))
        .collect();
    assert_eq!(calls.len(), 2);
    for (call, expected) in calls.iter().zip(["session.actual", "session.other"]) {
        assert_eq!(
            &source[call.offset as usize..call.offset as usize + 9],
            b"IsDefined"
        );
        assert!(
            matches!(&p.flow.values[call.inputs[0]].literal, Some(Arg::String { value }) if value == expected)
        );
    }
}
#[test]
fn elseif_calls_use_entry_bindings_not_sibling_assignments() {
    let p = parse(br##"<cfset name="form.flag"><cfif flag><cfset name="session.flag"><cfelseif IsDefined(name)></cfif>"##);
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("isdefined"))
        .unwrap();
    assert!(
        matches!(&p.flow.values[call.inputs[0]].literal, Some(Arg::String { value }) if value == "form.flag")
    );
}
#[test]
fn retained_devshell_has_condition_call_with_session_literal() {
    let bytes = include_bytes!("../../../../testdata/cfml/encrypted_shell_decoded.cfm");
    let p = parse(bytes);
    assert!(p.flow.values.iter().any(|v| v.target.as_deref() == Some("isdefined")
            && v.inputs.first().is_some_and(|id| matches!(&p.flow.values[*id].literal, Some(Arg::String { value }) if value == "session.in"))));
    let truncated = b"<cfif IsDefined('session.flag'><cfexecute name='x'>";
    let p = parse(truncated);
    assert!(
        p.flow
            .limitations
            .contains("condition-call-syntax-or-budget")
    );
    assert!(!p.symbols.iter().any(
        |s| matches!(s, Symbol::Call { target, .. } if target.as_deref() == Some("isdefined"))
    ));
}
#[test]
fn retained_script_calls_and_password_origin_have_original_offsets() {
    let bytes = include_bytes!("../../../../testdata/cfml/datasource_shell.cfm");
    let p = parse(bytes);
    for target in [
        "createobject",
        "createobject.getdatasourceservice.getdatasources",
        "decrypt",
    ] {
        assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call { target: t, offset: Some(offset), .. } if t.as_deref() == Some(target) && (*offset as usize) < bytes.len())), "{target}");
    }
    let decrypt = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("decrypt"))
        .unwrap();
    assert_eq!(
        &bytes[decrypt.offset as usize..decrypt.offset as usize + 7],
        b"Decrypt"
    );
    let origins = p.flow.origins(decrypt.inputs[0], &[], 1000);
    assert!(
        origins
            .values
            .iter()
            .any(|v| p.flow.values[v.value].target.as_deref() == Some("datasourceobb[*].password"))
    );
    assert_eq!(decrypt.inputs.len(), 4);
}
#[test]
fn script_comments_strings_and_wrong_password_arguments_are_separate() {
    let source = br##"<cfscript>
        // createobject('java','Fake'); Decrypt(data[i]['password'],'k');
        /* getDatasourceService().getDatasources(); */
        text="Decrypt(data[i]['password'],'k')";
        actual=CreateObject(/* note */'java', 'Real');
        result=Decrypt(data[i]['username'],data[i]['password']);
        </cfscript>"##;
    let p = parse(source);
    assert_eq!(
        p.symbols
            .iter()
            .filter(|s| matches!(s, Symbol::Call { .. }))
            .count(),
        2
    );
    let decrypt = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("decrypt"))
        .unwrap();
    let first = p.flow.origins(decrypt.inputs[0], &[], 1000);
    assert!(!first.values.iter().any(|v| {
        p.flow.values[v.value]
            .target
            .as_deref()
            .is_some_and(|s| s.ends_with(".password"))
    }));
    let second = p.flow.origins(decrypt.inputs[1], &[], 1000);
    assert!(
        second
            .values
            .iter()
            .any(|v| p.flow.values[v.value].target.as_deref() == Some("data[*].password"))
    );
    let create = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("createobject"))
        .unwrap();
    assert!(
        matches!(&p.flow.values[create.inputs[0]].literal, Some(Arg::String { value }) if value == "java")
    );
    let p = parse(b"<cfscript>factory . getDatasourceService ( ) . getDatasources ( );</cfscript>");
    assert!(p.symbols.iter().any(|s| matches!(s, Symbol::Call { target, .. } if target.as_deref() == Some("factory.getdatasourceservice.getdatasources"))));
}
#[test]
fn indexed_members_are_canonical_bounded_and_respect_known_overwrites() {
    for (expression, expected) in [
        ("data[i]['PASSWORD']", "data[*].password"),
        ("data['entry']['password']", "data.entry.password"),
        ("data[i].password", "data[*].password"),
        ("Form['job']", "form.job"),
    ] {
        let source = format!("<cfexecute name=\"#{expression}#\">");
        assert!(
            targets(source.as_bytes()).contains(expected),
            "{expression}"
        );
    }
    assert!(
        !targets(br##"<cfset Form.job='fixed'><cfexecute name="#Form['job']#">"##)
            .contains("form.job")
    );
    for expr in [
        "data[]['password']",
        "data[i]['password'",
        "data[i].9password",
        "data[i]['pass' & 'word']",
    ] {
        let p = parse(format!("<cfset x=Decrypt({expr},'key')>").as_bytes());
        assert!(
            !p.flow.values.iter().any(|v| v.kind == FlowKind::Member
                && v.target
                    .as_deref()
                    .is_some_and(|s| s.ends_with(".password"))),
            "{expr}"
        );
    }
    let p = parse(format!("<cfset x=data{}i{}>", "[".repeat(40), "]".repeat(40)).as_bytes());
    assert!(p.flow.limitations.contains("expression-depth"));
}
#[test]
fn skipped_tag_functions_do_not_shift_later_script_ranges() {
    let p = parse(b"<cffunction name='hidden'><cfscript>fake();</cfscript></cffunction><cfscript>actual();</cfscript>");
    assert!(
        p.symbols.iter().any(
            |s| matches!(s, Symbol::Call { target, .. } if target.as_deref() == Some("actual"))
        )
    );
    assert!(
        !p.symbols
            .iter()
            .any(|s| matches!(s, Symbol::Call { target, .. } if target.as_deref() == Some("fake")))
    );
}
#[test]
fn calls_after_script_are_visible_without_preserving_stale_bindings() {
    let source = br##"<cfset alias=form.job><cfscript>
            text="</cfscript><cfexecute name='fake'>";
            alias='fixed';
        </cfscript><cfexecute name="#alias#"><cffile action="read" file="#form.path#">"##;
    let p = parse(source);
    assert!(p.flow.limitations.contains("script-block-local-flow-only"));
    assert_eq!(
        p.symbols
            .iter()
            .filter(|s| matches!(s, Symbol::Call { .. }))
            .count(),
        2
    );
    assert_eq!(
        p.symbols
            .iter()
            .filter(|s| matches!(s, Symbol::Bind { .. }))
            .count(),
        3
    );
    assert!(!targets(source).contains("form.job"));
    let file = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cffile"))
        .unwrap();
    let values = p.flow.field_origins(file.inputs[0], "file", &[], 1000);
    assert!(
        values
            .values
            .iter()
            .any(|id| p.flow.values[id.value].target.as_deref() == Some("form.path"))
    );
}
fn action_values(source: &[u8]) -> (BTreeSet<String>, bool) {
    let p = parse(source);
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cffile"))
        .unwrap();
    let found = p.flow.complete_values(call.inputs[0], Some("action"), 1000);
    let values = found
        .values
        .iter()
        .filter_map(|id| match &p.flow.values[id.value].literal {
            Some(Arg::String { value }) => Some(value.clone()),
            _ => None,
        })
        .collect();
    (values, found.incomplete)
}
#[test]
fn complete_strings_fold_concatenation_and_interpolation_not_fragments() {
    for (source, expected) in [
        (r#"<cffile action='read'>"#, "read"),
        (r##"<cffile action="#'re' & 'ad'#">"##, "read"),
        (r##"<cffile action="re#'ad'#">"##, "read"),
        (r##"<cffile action="#'read'#Bogus">"##, "readBogus"),
        (r##"<cffile action="#'read' & 'Bogus'#">"##, "readBogus"),
        (r###"<cffile action="##read#''#">"###, "#read"),
        (r##"<cffile action="a""b#'c'#">"##, "a\"bc"),
        (r##"<cfset a='re' & 'ad'><cffile action="#a#">"##, "read"),
    ] {
        let (values, incomplete) = action_values(source.as_bytes());
        assert_eq!(values, BTreeSet::from([expected.to_string()]), "{source}");
        assert!(!incomplete, "{source}");
    }
}
#[test]
fn complete_values_keep_alternatives_but_not_unknown_compositions() {
    let source =
        br##"<cfif x><cfset a='read'><cfelse><cfset a='write'></cfif><cffile action="#a#">"##;
    assert_eq!(
        action_values(source),
        (BTreeSet::from(["read".into(), "write".into()]), false)
    );
    for source in [
        br##"<cffile action="#'read' & url.suffix#">"##.as_slice(),
        br##"<cffile action="read#url.suffix#">"##,
        br##"<cffile action="#opaque('read')#">"##,
        br##"<cfset a='read'><cfset a=url.action><cffile action="#a#">"##,
    ] {
        assert_eq!(action_values(source), (BTreeSet::new(), true));
    }
    assert!(targets(br##"<cfexecute name="prefix#form.job#suffix">"##).contains("form.job"));
}
#[test]
fn complete_values_bound_traversal_and_keep_legacy_merges_opaque() {
    let mut p = parse(
        br##"<cfif x><cfset a='read'><cfelse><cfset a='write'></cfif><cffile action="#a#">"##,
    );
    let id = p
        .flow
        .values
        .iter()
        .position(|v| v.kind == FlowKind::Alternative)
        .unwrap();
    assert!(p.flow.complete_values(id, None, 0).incomplete);
    assert!(p.flow.complete_values(usize::MAX, None, 10).incomplete);
    p.flow.values[id].kind = FlowKind::Merge;
    let result = p.flow.complete_values(id, None, 100);
    assert!(result.values.is_empty() && result.incomplete);
    p.flow.values[id].kind = FlowKind::Alternative;
    p.flow.values[id].inputs = vec![id];
    assert!(p.flow.complete_values(id, None, 100).values.is_empty());
    let literal = p
        .flow
        .values
        .iter()
        .position(|v| v.literal.is_some())
        .unwrap();
    p.flow.values[literal].literal = Some(Arg::Template {
        value: "read".into(),
    });
    let found = p.flow.complete_values(literal, None, 100);
    assert!(found.values.is_empty() && found.incomplete);
    p.flow.values[id].inputs = vec![literal; 100];
    assert!(p.flow.complete_values(id, None, 10).incomplete);
}
#[test]
fn computed_and_copied_literals_have_cumulative_budgets() {
    let source = format!("<cffile action=\"{}\">", "a#url.x#".repeat(70));
    assert!(
        parse(source.as_bytes())
            .flow
            .limitations
            .contains("expression-parts")
    );
    let source = format!(
        "<cfset a='x'>{}<cffile action='#a#'>",
        "<cfset a=a&a>".repeat(25)
    );
    let p = parse(source.as_bytes());
    assert!(p.flow.limitations.contains("constant-string-budget"));
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
    let source = format!(
        "<cfset a='{}'>{}",
        "x".repeat(20_000),
        "<cfset b=opaque(a)>".repeat(80)
    );
    let p = parse(source.as_bytes());
    assert!(p.flow.limitations.contains("symbol-literal-budget"));
    let copied: usize = p
        .symbols
        .iter()
        .filter_map(|s| match s {
            Symbol::Call { args, .. } => Some(args),
            _ => None,
        })
        .flatten()
        .filter_map(|a| match a {
            Arg::String { value } => Some(value.len()),
            _ => None,
        })
        .sum();
    assert!(copied <= super::super::MAX_BYTES);
}
fn targets(source: &[u8]) -> BTreeSet<String> {
    let p = parse(source);
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cfexecute"))
        .unwrap();
    let origins = p.flow.field_origins(call.inputs[0], "name", &[], 10_000);
    origins
        .values
        .iter()
        .filter_map(|v| p.flow.values[v.value].target.clone())
        .collect()
}
#[test]
fn direct_and_renamed_aliases_have_real_origins() {
    assert!(targets(b"<cfexecute name='#FORM.job#'>").contains("form.job"));
    assert!(
        targets(b"<cfset a=FORM.job><cfset Renamed=a><cfexecute name='#renamed#'>")
            .contains("form.job")
    );
}
#[test]
fn expression_calls_keep_arguments_and_receivers_separate() {
    let p = parse(br##"<cfset p=getPageContext().getRequest().getParameter('file')><cffile action="read" file="#p#">"##);
    let (id, call) = p
        .flow
        .values
        .iter()
        .enumerate()
        .find(|(_, v)| v.target.as_deref() == Some("getpagecontext.getrequest.getparameter"))
        .unwrap();
    assert_eq!(call.inputs.len(), 1);
    assert!(
        matches!(&p.flow.values[call.inputs[0]].literal, Some(Arg::String { value }) if value == "file")
    );
    let request = &p.flow.values[call.receiver.unwrap()];
    assert_eq!(request.target.as_deref(), Some("getpagecontext.getrequest"));
    assert!(request.inputs.is_empty());
    let context = &p.flow.values[request.receiver.unwrap()];
    assert_eq!(context.target.as_deref(), Some("getpagecontext"));
    assert_eq!(context.receiver, None);
    let sink = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cffile"))
        .unwrap();
    let origins = p.flow.field_origins(sink.inputs[0], "file", &[], 1000);
    assert!(origins.values.iter().any(|v| v.value == id));
    assert!(!origins.values.iter().any(|v| v.value == call.inputs[0]));
}

#[test]
fn expression_symbols_agree_with_flow_and_ignore_quoted_code() {
    let source = br#"<!--- <cfset a=fake()> ---><cfset quoted='fake()'><cfset a=encrypt(getPageContext().getRequest().getRequestURL().toString(),'key','AES')>"#;
    let p = parse(source);
    assert_eq!(
        p.symbols
            .iter()
            .filter(|s| matches!(s, Symbol::Call { .. }))
            .count(),
        5
    );
    assert_eq!(
        p.symbols
            .iter()
            .filter(|s| matches!(s, Symbol::Bind { .. }))
            .count(),
        2
    );
    for symbol in p
        .symbols
        .iter()
        .filter(|s| matches!(s, Symbol::Call { .. }))
    {
        let Symbol::Call {
            target,
            args,
            offset,
        } = symbol
        else {
            panic!()
        };
        assert!(p.flow.values.iter().any(|v| v.kind == FlowKind::Call
            && &v.target == target
            && Some(v.offset) == *offset
            && v.inputs.len() == args.len()));
        assert_ne!(target.as_deref(), Some("fake"));
        if target.as_deref() == Some("encrypt") {
            assert!(matches!(args[0], Arg::Call));
            assert!(matches!(&args[1], Arg::String { value } if value == "key"));
            assert!(matches!(&args[2], Arg::String { value } if value == "AES"));
        }
    }
}

#[test]
fn retained_devshell_exposes_encrypt_argument_provenance() {
    let bytes = include_bytes!("../../../../testdata/cfml/encrypted_shell_decoded.cfm");
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("decoded.cfm"))
        .file_type(crate::FileType::Cfml)
        .open(bytes);
    let flow = parsed.flow().unwrap();
    let symbol = parsed
        .symbols()
        .iter()
        .find(|s| matches!(s, Symbol::Call { target, .. } if target.as_deref() == Some("encrypt")))
        .unwrap();
    let Symbol::Call { offset, args, .. } = symbol else {
        panic!()
    };
    assert_eq!(args.len(), 4);
    let call = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("encrypt") && Some(v.offset) == *offset)
        .unwrap();
    let origins = flow.origins(call.inputs[0], &[], 1000);
    assert!(
        origins
            .values
            .iter()
            .any(|v| flow.values[v.value].target.as_deref()
                == Some("getpagecontext.getrequest.getrequesturl.tostring"))
    );
}

#[test]
fn expression_transfers_require_explicit_models() {
    let p = parse(br##"<cfset p=Replace(Form.nfile,Form.old_name,Form.new_name)><cffile action="write" file="#p#" output="#Form.text#">"##);
    let sink = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cffile"))
        .unwrap();
    let plain = p.flow.field_origins(sink.inputs[0], "file", &[], 1000);
    assert!(
        !plain
            .values
            .iter()
            .any(|v| p.flow.values[v.value].kind == FlowKind::Member)
    );
    let models = [crate::FlowTransfer {
        call: "replace".into(),
        arguments: vec![0, 2],
        receiver: false,
    }];
    let modeled = p.flow.field_origins(sink.inputs[0], "file", &models, 1000);
    let targets: BTreeSet<_> = modeled
        .values
        .iter()
        .filter_map(|v| p.flow.values[v.value].target.as_deref())
        .collect();
    assert!(targets.contains("form.nfile"));
    assert!(targets.contains("form.new_name"));
    assert!(!targets.contains("form.old_name"));
    assert!(!targets.contains("form.text"));
}

#[test]
fn concatenation_parentheses_and_quoted_delimiters() {
    assert!(
        targets(br#"<cfset a=('prefix,(&)' & Form.path) & '/tail'><cfexecute name='#a#'>"#)
            .contains("form.path")
    );
    let p = parse(br#"<cfset a=replace('a,b)', 'b', 'c&d')><cfexecute name='#a#'>"#);
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("replace"))
        .unwrap();
    assert_eq!(call.inputs.len(), 3);
    assert!(
        call.inputs
            .iter()
            .all(|id| p.flow.values[*id].kind == FlowKind::Literal)
    );
    assert!(
        !targets(br#"<cfset a='Form.path & getParameter(x)'><cfexecute name='#a#'>"#)
            .contains("form.path")
    );
}

#[test]
fn expressions_reject_malformed_and_bound_width_depth() {
    for expression in [
        "form.path && form.other",
        "replace(form.path,)",
        "replace(,form.path)",
        "f(form.path))",
        "f((form.path)",
        "f()junk(form.path)",
    ] {
        let source = format!("<cfset a={expression}><cfexecute name='#a#'>");
        assert!(
            !targets(source.as_bytes()).contains("form.path"),
            "{expression}"
        );
        assert!(
            parse(source.as_bytes()).flow.limitations.len() > 1,
            "{expression}"
        );
    }
    for expression in [
        vec!["form.path"; 70].join("&"),
        format!("f({})", vec!["form.path"; 70].join(",")),
    ] {
        let p = parse(format!("<cfset a={expression}>").as_bytes());
        assert!(p.flow.limitations.contains("expression-parts"));
    }
    let source = format!("<cfset a={}form.path{}>", "f(".repeat(40), ")".repeat(40));
    assert!(
        parse(source.as_bytes())
            .flow
            .limitations
            .contains("expression-depth")
    );
    let source = br#"<cfset a=getPageContext().getRequest().getParameter('file') & replace(form.x,'a','b')><cffile action='read' file='#a#'>"#;
    for end in 0..=source.len() {
        let p = parse(&source[..end]);
        for value in &p.flow.values {
            assert!(value.inputs.iter().all(|id| *id < p.flow.values.len()));
            assert!(value.receiver.is_none_or(|id| id < p.flow.values.len()));
        }
    }
}

#[test]
fn retained_devshell_has_request_chain_and_replace_write() {
    let p = parse(include_bytes!(
        "../../../../testdata/cfml/encrypted_shell_decoded.cfm"
    ));
    let mut request_reads = 0;
    let mut replace_writes = 0;
    for sink in p
        .flow
        .values
        .iter()
        .filter(|v| v.target.as_deref() == Some("cffile"))
    {
        let origins = p.flow.field_origins(sink.inputs[0], "file", &[], 1000);
        for origin in origins.values {
            match p.flow.values[origin.value].target.as_deref() {
                Some("getpagecontext.getrequest.getparameter") => request_reads += 1,
                Some("replace") => replace_writes += 1,
                _ => {}
            }
        }
    }
    assert!(request_reads >= 1);
    assert_eq!(replace_writes, 1);
}
#[test]
fn overwrites_and_unrelated_aliases_do_not_flow() {
    for s in [
        b"<cfset a=form.job><cfset a='fixed'><cfexecute name='#a#'>".as_slice(),
        b"<cfset a=form.job><cfset b='fixed'><cfexecute name='#b#'>",
        b"<cfset a=form.job><cfset a=opaque()><cfexecute name='#a#'>",
    ] {
        assert!(!targets(s).contains("form.job"));
    }
}
#[test]
fn branches_merge_alternatives_without_sibling_leakage() {
    assert!(
        targets(b"<cfset a='fixed'><cfif x><cfset a=form.job></cfif><cfexecute name='#a#'>")
            .contains("form.job")
    );
    assert!(
        targets(
            b"<cfif x><cfset a=form.job><cfelse><cfset a='fixed'></cfif><cfexecute name='#a#'>"
        )
        .contains("form.job")
    );
    assert!(
        !targets(b"<cfif x><cfset a=form.job><cfelse><cfexecute name='#a#'></cfif>")
            .contains("form.job")
    );
}
#[test]
fn escaped_hash_is_literal_and_attributes_are_separate() {
    assert!(
        !targets(b"<cfexecute name='##form.job##' arguments='#form.job#'>").contains("form.job")
    );
    let p = parse(b"<cfexecute arguments='#form.job#' name='fixed'>");
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cfexecute"))
        .unwrap();
    assert!(
        p.flow
            .field_origins(call.inputs[0], "arguments", &[], 100)
            .values
            .iter()
            .any(|v| p.flow.values[v.value].target.as_deref() == Some("form.job"))
    );
}
#[test]
fn symbol_and_flow_call_offsets_agree() {
    let p = parse(b"  <cfexecute name='#form.job#'>");
    let Symbol::Call {
        offset,
        args,
        target,
    } = &p.symbols.as_slice()[0]
    else {
        panic!()
    };
    assert_eq!(*offset, Some(2));
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.kind == FlowKind::Call)
        .unwrap();
    assert_eq!(call.offset, 2);
    assert_eq!(&call.target, target);
    assert_eq!(call.inputs.len(), args.len());
}
#[test]
fn malformed_tags_and_unknown_statements_do_not_keep_aliases() {
    assert!(
        !targets(b"<cfset a=form.job><cfinclude template='x'><cfexecute name='#a#'>")
            .contains("form.job")
    );
    assert!(parse(b"<cfexecute name='a' NAME='b'>").symbols.is_empty());
    assert!(
        parse(b"<cfif x>")
            .flow
            .limitations
            .contains("unclosed-branch")
    );
    assert!(
        parse(b"<cfelse>")
            .flow
            .limitations
            .contains("unbalanced-branch")
    );
}
#[test]
fn scoped_overwrite_and_literal_unquoting() {
    assert!(
        !targets(b"<cfset form.job='fixed'><cfexecute name='#form.job#'>").contains("form.job")
    );
    let p = parse(b"<cfexecute name='can''t'>");
    assert!(
        p.flow
            .values
            .iter()
            .any(|v| matches!(&v.literal, Some(Arg::String { value }) if value == "can't"))
    );
}

#[test]
fn function_bodies_do_not_mutate_outer_bindings() {
    assert!(!targets(b"<cfset a='fixed'><cffunction name='f'><cfset a=form.job></cffunction><cfexecute name='#a#'>").contains("form.job"));
}

#[test]
fn public_views_share_parse_and_original_calls() {
    for bytes in [
        include_bytes!("../../../../testdata/cfml/datasource_shell.cfm").as_slice(),
        include_bytes!("../../../../testdata/cfml/encrypted_shell_decoded.cfm").as_slice(),
    ] {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(crate::FileType::Cfml)
            .open(bytes);
        let flow = parsed.flow().unwrap();
        assert_eq!(flow.producer, "cfml-tags");
        assert!(std::ptr::eq(flow, parsed.flow().unwrap()));
        let mut count = 0;
        for sym in parsed.symbols().iter() {
            if let Symbol::Call {
                target,
                offset,
                args,
            } = sym
            {
                if target.as_deref() != Some("cfexecute") {
                    continue;
                }
                count += 1;
                assert!(flow.values.iter().any(|v| v.kind == FlowKind::Call
                    && Some(v.offset) == *offset
                    && &v.target == target
                    && v.inputs.len() == args.len()));
            }
        }
        assert_eq!(count, 1);
        let call = flow
            .values
            .iter()
            .find(|v| v.kind == FlowKind::Call && v.target.as_deref() == Some("cfexecute"))
            .unwrap();
        let origins = flow.field_origins(call.inputs[0], "name", &[], 10_000);
        assert!(origins.values.iter().any(|v| matches!(
            flow.values[v.value].target.as_deref(),
            Some("form.cmd" | "form.sp")
        )));
        assert!(parsed.parse_count() <= 1);
    }
    let plain = crate::OpenOptions::new()
        .path(std::path::Path::new("a.txt"))
        .file_type(crate::FileType::Text)
        .open(b"hello");
    assert!(plain.flow().is_none());
}

#[test]
fn flow_limits_and_all_prefixes() {
    let mut source = String::new();
    for i in 0..=MAX_BINDINGS {
        source.push_str(&format!("<cfset a{i}=form.job>"));
    }
    assert!(
        parse(source.as_bytes())
            .flow
            .limitations
            .contains("binding-budget")
    );
    assert!(
        parse(&b"<cfif x>".repeat(MAX_BRANCHES + 1))
            .flow
            .limitations
            .contains("branch-depth")
    );
    let source = b"<cfset a=form.job><cfif session.pwd neq a><cfset a='fixed'><cfelseif a!=session.pwd><cfset b=a><cfelse><cfset a='it''s ##literal##'></cfif><cfexecute name='#a#'>";
    for end in 0..=source.len() {
        let p = parse(&source[..end]);
        assert!(p.flow.values.len() <= MAX_VALUES);
        for v in &p.flow.values {
            assert!(v.inputs.iter().all(|i| *i < p.flow.values.len()));
            assert!(v.fields.values().all(|i| *i < p.flow.values.len()));
        }
    }
}
#[test]
fn node_expression_and_branch_union_budgets() {
    let p = parse(&b"<cfexecute name='#form.job#'>".repeat(8000));
    assert!(p.flow.limitations.contains("node-budget"));
    assert_eq!(p.flow.values.len(), MAX_VALUES);
    let source = format!("<cfset a={}form.job{}>", "#".repeat(40), "#".repeat(40));
    assert!(
        parse(source.as_bytes())
            .flow
            .limitations
            .contains("expression-depth")
    );
    let mut source = String::from("<cfif x>");
    for i in 0..MAX_BINDINGS {
        source.push_str(&format!("<cfset a{i}=form.job>"));
    }
    source.push_str("<cfelse>");
    for i in 0..MAX_BINDINGS {
        source.push_str(&format!("<cfset b{i}=form.job>"));
    }
    source.push_str("</cfif>");
    assert!(
        parse(source.as_bytes())
            .flow
            .limitations
            .contains("binding-budget")
    );
}
#[test]
fn guarded_implicit_inputs_respect_scope_and_branch_lifetime() {
    assert!(
        targets(b"<cfif IsDefined('FORM.job')><cfexecute name='#job#'></cfif>")
            .contains("form.job")
    );
    for source in [
        b"<cfif IsDefined('form.job')><cfelse><cfexecute name='#job#'></cfif>".as_slice(),
        b"<cfif IsDefined('form.job')></cfif><cfexecute name='#job#'>",
        b"<cfif NOT IsDefined('form.job')><cfexecute name='#job#'></cfif>",
        b"<cfif IsDefined('form.job') eq 'No'><cfexecute name='#job#'></cfif>",
        b"<cfset variables.job='fixed'><cfif IsDefined('form.job')><cfexecute name='#job#'></cfif>",
        b"<cfset job='fixed'><cfif IsDefined('form.job')><cfexecute name='#variables.job#'></cfif>",
        b"<cfset form.job='fixed'><cfif IsDefined('form.job')><cfexecute name='#job#'></cfif>",
        b"<cfif IsDefined('form.job')><cfexecute name='#variables.job#'></cfif>",
    ] {
        assert!(!targets(source).contains("form.job"), "{:?}", source);
    }
}

#[test]
fn implicit_lookup_setting_is_explicit_and_conservative() {
    for (setting, expected) in [
        ("true", true),
        ("yes", true),
        ("1", true),
        ("false", false),
        ("no", false),
        ("0", false),
        ("#configuration#", false),
    ] {
        let source = format!(
            "<cfapplication searchimplicitscopes='{setting}'><cfif IsDefined('form.job')><cfexecute name='#job#'></cfif>"
        );
        assert_eq!(
            targets(source.as_bytes()).contains("form.job"),
            expected,
            "{setting}"
        );
    }
    let p = parse(b"<cfif IsDefined('form.job')><cfexecute arguments='/c #job#'></cfif>");
    assert!(
        p.flow
            .limitations
            .contains("implicit-scope-runtime-dependent")
    );
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cfexecute"))
        .unwrap();
    assert!(
        p.flow
            .field_origins(call.inputs[0], "arguments", &[], 100)
            .values
            .iter()
            .any(|v| p.flow.values[v.value].target.as_deref() == Some("form.job"))
    );
}
#[test]
fn retained_implicit_shell_has_guarded_argument_origin() {
    let bytes = include_bytes!("../../../../testdata/cfml/implicit_command_shell.cmf");
    let p = parse(bytes);
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cfexecute"))
        .unwrap();
    let origins = p.flow.field_origins(call.inputs[0], "arguments", &[], 1000);
    assert!(
        origins
            .values
            .iter()
            .any(|v| p.flow.values[v.value].target.as_deref() == Some("form.cmd"))
    );
}
#[test]
fn file_reads_replace_prior_request_values_with_call_results() {
    for action in ["read", "READBINARY", "#'re' & 'ad'#"] {
        for variable in ["command", "VARIABLES.command", "#'command'#"] {
            let source = format!(
                "<cfset command=form.cmd><cffile action=\"{action}\" file='/fixed' variable=\"{variable}\"><cfexecute name='#command#'>"
            );
            let observed = targets(source.as_bytes());
            assert!(observed.contains("cffile:read-result"), "{source}");
            assert!(!observed.contains("form.cmd"), "{source}");
            let parsed = parse(source.as_bytes());
            assert!(parsed.symbols.iter().any(
                |s| matches!(s,Symbol::Bind {target,shape:ArgShape::Call,..} if target=="command")
            ));
        }
    }
}
#[test]
fn file_result_actions_and_dynamic_targets_do_not_preserve_stale_values() {
    for tag in [
        "<cffile action='#url.action#' file='/fixed' variable='command'>",
        "<cffile action='read' file='/fixed' variable='#url.result#'>",
        r##"<cffile action='read' file='/fixed' variable="command#url.suffix#">"##,
        "<cffile attributeCollection='#url.options#'>",
        "<cffile action='read' file='/fixed' variable='session.command'>",
    ] {
        let source = format!("<cfset command=form.cmd>{tag}<cfexecute name='#command#'>");
        let observed = targets(source.as_bytes());
        assert!(!observed.contains("form.cmd"), "{source}");
        assert!(!observed.contains("cffile:read-result"), "{source}");
    }
    for tag in [
        "<cffile action='write' file='/fixed' variable='command'>",
        r##"<cffile action="#'read' & 'Bogus'#" file='/fixed' variable='command'>"##,
        "<!--- <cffile action='read' file='/fixed' variable='command'> --->",
    ] {
        let source = format!("<cfset command=form.cmd>{tag}<cfexecute name='#command#'>");
        assert!(targets(source.as_bytes()).contains("form.cmd"), "{source}");
    }
}
#[test]
fn file_result_flow_respects_source_order_and_branch_alternatives() {
    let source=b"<cffile action='read' file='/fixed' variable='command'><cfset command=form.cmd><cfexecute name='#command#'>";
    assert!(targets(source).contains("form.cmd"));
    let source=b"<cfset command=form.cmd><cfif flag><cffile action='read' file='/fixed' variable='command'></cfif><cfexecute name='#command#'>";
    let values = targets(source);
    assert!(values.contains("form.cmd") && values.contains("cffile:read-result"));
    let source=b"<cfset command=form.cmd><cfif flag><cffile action='read' file='/a' variable='command'><cfelse><cffile action='readBinary' file='/b' variable='command'></cfif><cfexecute name='#command#'>";
    let values = targets(source);
    assert!(!values.contains("form.cmd") && values.contains("cffile:read-result"));
}
#[test]
fn original_devshell_has_three_read_result_bindings() {
    let source = include_bytes!("../../../../testdata/cfml/encrypted_shell_decoded.cfm");
    let p = parse(source);
    let binds: Vec<_> = p
        .symbols
        .iter()
        .filter_map(|s| match s {
            Symbol::Bind {
                target,
                shape: ArgShape::Call,
                offset,
            } if target == "filecontent" => Some(*offset as usize),
            _ => None,
        })
        .collect();
    assert_eq!(binds.len(), 3);
    for at in binds {
        assert!(source[at..].starts_with(b"<cffile"));
    }
}

#[test]
fn http_parameters_bind_only_to_their_closed_nearest_owner() {
    let source = br##"<cfset data=encrypt(getPageContext().getRequest().getRequestURL(), 'key')><cfhttp method='POST' url='outer'><cfhttpparam type='formfield' value='#data#'><cfhttp method='GET' url='inner'><cfhttpparam type='formfield' value='inner-data'></cfhttp></cfhttp><cfhttpparam type='formfield' value='#data#'>"##;
    let p = parse(source);
    let calls: Vec<_> = p
        .flow
        .values
        .iter()
        .filter(|v| v.target.as_deref() == Some("cfhttp:param"))
        .collect();
    assert_eq!(calls.len(), 2);
    let mut pairs = BTreeSet::new();
    for call in calls {
        assert_eq!(call.inputs.len(), 2);
        let parent = &p.flow.values[call.inputs[1]];
        let url = *parent.fields.get("url").unwrap();
        let Some(Arg::String { value: url }) = &p.flow.values[url].literal else {
            panic!("URL literal missing")
        };
        let child = &p.flow.values[call.inputs[0]];
        assert!(child.fields.contains_key("type") && child.fields.contains_key("value"));
        pairs.insert(url.as_str());
    }
    assert_eq!(pairs, BTreeSet::from(["inner", "outer"]));
}

#[test]
fn malformed_open_or_self_closed_http_does_not_own_later_parameters() {
    for source in [
        "<cfhttp method='POST' url='x'/><cfhttpparam type='formfield' value='#form.x#'>",
        "<cfhttp method='POST' url='x'><cfhttpparam type='formfield' value='#form.x#'>",
        "<cfhttp method='POST' METHOD='GET'><cfhttpparam type='formfield' value='#form.x#'></cfhttp>",
        "<!--- <cfhttp method='POST'><cfhttpparam type='formfield' value='#form.x#'></cfhttp> --->",
        r##"<cfset text="<cfhttp method='POST'><cfhttpparam type='formfield' value='#form.x#'></cfhttp>">"##,
    ] {
        let p = parse(source.as_bytes());
        assert!(
            !p.flow
                .values
                .iter()
                .any(|v| v.target.as_deref() == Some("cfhttp:param")),
            "{source}"
        );
    }
}

#[test]
fn http_parameter_attribute_origins_are_captured_before_reassignment() {
    let p = parse(br##"<cfset data=form.input><cfhttp method='POST'><cfhttpparam value='#data#'><cfset data='fixed'></cfhttp>"##);
    let call = p
        .flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("cfhttp:param"))
        .unwrap();
    let origins = p.flow.field_origins(call.inputs[0], "value", &[], 1000);
    assert!(
        origins
            .values
            .iter()
            .any(|v| p.flow.values[v.value].target.as_deref() == Some("form.input"))
    );
}

#[test]
fn self_closed_set_keeps_call_and_alias_provenance() {
    for ending in [">", "/>", " / >"] {
        let source = format!(
            r##"<cfset tool=form.program{ending}<cfset cls=CreateObject("java","java.nio.ByteBuffer"){ending}<cfexecute name="#tool#">"##
        );
        let p = parse(source.as_bytes());
        assert!(
            p.symbols.iter().any(
                |s| matches!(s, Symbol::Call {target,..} if target.as_deref()==Some("createobject"))
            ),
            "{source}"
        );
        let call = p
            .flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("cfexecute"))
            .unwrap();
        let origins = p.flow.field_origins(call.inputs[0], "name", &[], 1000);
        assert!(
            origins
                .values
                .iter()
                .any(|v| p.flow.values[v.value].target.as_deref() == Some("form.program")),
            "{source}"
        );
    }
}
#[test]
fn self_closed_set_does_not_reinterpret_quoted_calls_or_division() {
    for source in [
        r##"<cfset a='CreateObject("java","java.nio.ByteBuffer")' />"##,
        r##"<cfset a=4/2 />"##,
        r##"<cfset a='/srv/path/' />"##,
    ] {
        let p = parse(source.as_bytes());
        assert!(
            !p.symbols.iter().any(
                |s| matches!(s,Symbol::Call {target,..} if target.as_deref()==Some("createobject"))
            ),
            "{source}"
        );
    }
}
