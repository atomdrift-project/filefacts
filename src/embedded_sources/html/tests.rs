use super::*;

/// The executable script bodies of an HTML page, as raw page text.
fn bodies(page: &str) -> Vec<&str> {
    script_bodies(page.as_bytes(), false)
        .into_iter()
        .filter(|s| s.scope.is_some())
        .map(|s| &page[s.body])
        .collect()
}

fn units(page: &str, file_type: FileType) -> Vec<EmbeddedSource<'_>> {
    inline_scripts(Some((page.as_bytes(), file_type))).collect()
}

fn sources(page: &str, file_type: FileType) -> Vec<String> {
    units(page, file_type)
        .into_iter()
        .map(|s| s.source.into_owned())
        .collect()
}

/// The call targets JavaScript analysis finds in `source`.
fn calls(source: &str) -> Vec<String> {
    let parsed = crate::OpenOptions::new()
        .cache(false)
        .path(std::path::Path::new("unit.js"))
        .open(source.as_bytes());
    serde_json::to_value(parsed.symbols())
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["kind"] == "call")
        .filter_map(|s| s["target"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn script_bodies_are_found_in_any_case_and_with_attributes() {
    let page = r#"<html><SCRIPT>a()</SCRIPT><script defer
        src="x.js" data-x='>'>b()</script ><Script type="text/javascript">c()</sCrIpT>"#;
    assert_eq!(bodies(page), ["a()", "b()", "c()"]);
}

#[test]
fn a_quoted_gt_does_not_end_the_tag() {
    assert_eq!(
        bodies(r#"<script data-a="1 > 0" data-b='>'>x()</script>"#),
        ["x()"]
    );
}

#[test]
fn a_script_ends_only_at_a_real_end_tag() {
    // `</scripts` is not `</script`; `</script` must be followed by
    // whitespace, `/` or `>`.
    let page = "<script>var s = '</scripts>'; t()</script>";
    assert_eq!(bodies(page), ["var s = '</scripts>'; t()"]);
    // The browser ends the script at `</script>` even inside a string.
    assert_eq!(bodies("<script>a('</script>')</script>"), ["a('"]);
}

#[test]
fn an_unterminated_script_runs_to_the_end_of_the_page() {
    assert_eq!(bodies("<p>x</p><script>last()"), ["last()"]);
}

#[test]
fn comments_and_raw_text_elements_hide_scripts() {
    let page = "<!-- <script>no1()</script> -->\
        <textarea><script>no2()</script></textarea>\
        <noscript><script>no3()</script></noscript>\
        <title><script>no4()</script></TITLE >\
        <style>p{}</style><script>yes()</script>";
    assert_eq!(bodies(page), ["yes()"]);
}

#[test]
fn abrupt_and_bang_comments_end_where_the_browser_ends_them() {
    // `<!-->` and `<!--->` are whole comments; `--!>` closes one.
    assert_eq!(
        bodies("<!--><script>a()</script><!---><script>b()</script>"),
        ["a()", "b()"]
    );
    assert_eq!(bodies("<!-- x --!><script>c()</script><!-- -->"), ["c()"]);
}

#[test]
fn plaintext_ends_the_scan() {
    assert!(bodies("<plaintext><script>no()</script>").is_empty());
}

#[test]
fn only_types_a_browser_runs_are_kept() {
    let page = r#"<script type="application/json">{"a":1}</script>
        <script type="application/ld+json">{}</script>
        <script type="importmap">{}</script>
        <script type="text/template"><div></div></script>
        <script type="module">m()</script>
        <script type=" Text/JavaScript ">t()</script>
        <script type="">e()</script>
        <script language="VBScript">MsgBox 1</script>
        <script language="JavaScript">l()</script>
        <script language="">n()</script>"#;
    assert_eq!(bodies(page), ["m()", "t()", "e()", "l()", "n()"]);
}

#[test]
fn a_type_with_parameters_is_a_data_block() {
    // The HTML Standard matches the whole stripped `type` against the
    // JavaScript MIME type essence strings; a parameter breaks the match.
    assert!(bodies(r#"<script type="text/javascript; charset=utf-8">t()</script>"#).is_empty());
    assert!(bodies(r#"<script type="module; x">m()</script>"#).is_empty());
}

#[test]
fn module_scripts_are_their_own_scope() {
    let page = r#"<script>a()</script><script type="module">b()</script>"#;
    let scopes: Vec<_> = units(page, FileType::Html)
        .into_iter()
        .map(|s| s.origin)
        .collect();
    assert!(matches!(
        scopes.as_slice(),
        [
            Origin::Script {
                scope: ScriptScope::Classic,
                ..
            },
            Origin::Script {
                scope: ScriptScope::Module,
                ..
            },
        ]
    ));
}

#[test]
fn each_unit_records_its_place_in_the_page() {
    let page =
        "<html>\r\n<head><title>é</title>\n<script>\n  go(1);\n</script></head>\n<body>ü</body>";
    let units = units(page, FileType::Html);
    let [unit] = units.as_slice() else {
        panic!("{units:?}")
    };
    let Origin::Script {
        offset, aligned, ..
    } = unit.origin
    else {
        panic!("{unit:?}")
    };
    assert!(aligned);
    assert_eq!(&page[offset..offset + unit.source.len()], unit.source);
    assert_eq!(unit.source, "\n  go(1);\n");
    assert_eq!(unit.pointer, "/html/scripts/0");
}

#[test]
fn the_pointer_counts_every_script_element() {
    let page = "<script type=application/json>{}</script><script> </script><script>go()</script>";
    let pointers: Vec<_> = units(page, FileType::Html)
        .into_iter()
        .map(|s| s.pointer)
        .collect();
    assert_eq!(pointers, ["/html/scripts/2"]);
}

#[test]
fn consecutive_scripts_cannot_run_into_each_other() {
    let page = "<script>a() // note</script><script>b()</script>";
    assert_eq!(sources(page, FileType::Html), ["a() // note", "b()"]);
}

#[test]
fn an_unclosed_block_comment_cannot_hide_the_next_script() {
    // The browser parses each script alone: the `/*` ends with the first
    // script and `evil()` runs.
    let page = "<script>/*</script><script>evil()/**/</script>";
    let found: Vec<String> = sources(page, FileType::Html)
        .iter()
        .flat_map(|s| calls(s))
        .collect();
    assert!(found.iter().any(|c| c == "evil"), "{found:?}");
}

#[test]
fn an_unclosed_template_literal_cannot_hide_the_next_script() {
    let page = "<script>x = `</script><script>evil(); y = `</script>";
    let found: Vec<String> = sources(page, FileType::Html)
        .iter()
        .flat_map(|s| calls(s))
        .collect();
    assert!(found.iter().any(|c| c == "evil"), "{found:?}");
}

#[test]
fn each_unit_parses_as_javascript_with_every_call() {
    let page = "<html><body>\n<script>var ua = navigator.userAgent // first\n\
        </script><script>if (ua.includes('FBAN')) { leave() } run(1)</script>\n</body></html>";
    let found: Vec<String> = sources(page, FileType::Html)
        .iter()
        .flat_map(|s| calls(s))
        .collect();
    for call in ["ua.includes", "leave", "run"] {
        assert!(
            found.iter().any(|c| c == call),
            "{call} missing from {found:?}"
        );
    }
}

#[test]
fn an_escaped_nested_script_does_not_end_the_body() {
    // `<!--` enters the escaped state, `<script>` the double-escaped one, in
    // which `</script>` only steps back out; `-->` returns to plain script
    // data and the next `</script>` ends the body.
    let page = "<script><!--<script>a()</script>b()--></script><p>after</p>";
    assert_eq!(bodies(page), ["<!--<script>a()</script>b()-->"]);
}

#[test]
fn script_data_escape_states_follow_the_tokenizer() {
    // Inside `<!--` alone, `</script>` still ends the body.
    assert_eq!(bodies("<script><!-- a() </script>b()"), ["<!-- a() "]);
    // `-->` inside the double-escaped state also returns to plain data.
    assert_eq!(
        bodies("<script><!--<script>a()-->b()</script>c()"),
        ["<!--<script>a()-->b()"]
    );
    // `<scripts>` is not a nested script; `<!-->` closes at once.
    assert_eq!(bodies("<script><!--<scripts></script>x"), ["<!--<scripts>"]);
    assert_eq!(bodies("<script><!--><script></script>x"), ["<!--><script>"]);
    // A nested script's end tag leaves double escaping only when it is one.
    assert_eq!(
        bodies("<script><!--<script></scriptx></script>a()--></script>"),
        ["<!--<script></scriptx></script>a()-->"]
    );
}

#[test]
fn svg_scripts_lose_their_cdata_wrapper_and_may_self_close() {
    let page = "<svg><script href='x.js'/><script type=\"application/ecmascript\">\
        <![CDATA[ if (a < b) go() ]]></script></svg>";
    let units = units(page, FileType::Svg);
    let [unit] = units.as_slice() else {
        panic!("{units:?}")
    };
    assert_eq!(unit.source.trim(), "if (a < b) go()");
    assert_eq!(unit.pointer, "/html/scripts/1");
    let Origin::Script {
        offset, aligned, ..
    } = unit.origin
    else {
        panic!("{unit:?}")
    };
    assert!(aligned);
    let at = page.find("if (a").unwrap();
    assert_eq!(&unit.source[at - offset..at - offset + 2], "if");
}

#[test]
fn an_svg_end_tag_inside_cdata_does_not_end_the_body() {
    let page = "<svg><script><![CDATA[ s = '</script>'; ]]>evil()</script></svg>";
    let found: Vec<String> = sources(page, FileType::Svg)
        .iter()
        .flat_map(|s| calls(s))
        .collect();
    assert!(found.iter().any(|c| c == "evil"), "{found:?}");
}

#[test]
fn svg_cdata_sections_anywhere_in_the_body_are_unwrapped() {
    let page = "<svg><script>a();<![CDATA[ if (x < y) b(); ]]>c();<!-- d() --></script></svg>";
    let [source] = sources(page, FileType::Svg).try_into().unwrap();
    assert_eq!(
        source.len(),
        page.find("</script").unwrap() - "<svg><script>".len()
    );
    let words: Vec<_> = source.split_whitespace().collect();
    assert_eq!(words, ["a();", "if", "(x", "<", "y)", "b();", "c();"]);
}

#[test]
fn svg_character_references_are_decoded() {
    let page = "<svg><script>ev&#97;l(x &amp;&amp; y);w&#x69;ndow&lt;1</script></svg>";
    let units = units(page, FileType::Svg);
    let [unit] = units.as_slice() else {
        panic!("{units:?}")
    };
    assert_eq!(unit.source, "eval(x && y);window<1");
    assert!(matches!(unit.origin, Origin::Script { aligned: false, .. }));
    // Unknown entities and malformed references stay as written; HTML
    // script text is never decoded.
    assert_eq!(
        sources(
            "<svg><script>a&nbsp;&#xZZ;&#+9;&#0;</script></svg>",
            FileType::Svg
        ),
        ["a&nbsp;&#xZZ;&#+9;&#0;"]
    );
    assert_eq!(
        sources("<script>ev&#97;l()</script>", FileType::Html),
        ["ev&#97;l()"]
    );
}

#[test]
fn bytes_that_are_not_utf8_keep_their_width() {
    let mut page = b"<script>s = '".to_vec();
    page.extend_from_slice(&[0xE9, 0xFF]);
    page.extend_from_slice(b"'; go()</script>");
    let [unit] = inline_scripts(Some((&page, FileType::Html)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(unit.source, "s = '??'; go()");
}

#[test]
fn a_page_without_executable_script_has_no_units() {
    for page in [
        "<p>hi</p><script type='application/json'>{}</script>",
        "<script>  \n </script>",
        "<script src='x.js'></script>",
    ] {
        assert!(units(page, FileType::Html).is_empty(), "{page}");
    }
    assert!(units("<svg><script><![CDATA[ ]]></script></svg>", FileType::Svg).is_empty());
}

#[test]
fn scanning_ends_on_hostile_input() {
    for page in [
        "<script",
        "<script type=\"",
        "<<<<",
        "<!--",
        "<!-",
        "<textarea>",
        "</script>",
        "<script>",
        "<script><!--",
        "<script><!--<script",
        "<script><!--<script></",
        "<svg><script><![CDATA[",
        "<svg><script>&#",
        "<svg><script>&#x110000;&#xD800;<",
        "<a b=c d='e' f=\"g\"/ >",
    ] {
        let _ = script_bodies(page.as_bytes(), false);
        let _ = script_bodies(page.as_bytes(), true);
        let _ = units(page, FileType::Html);
        let _ = units(page, FileType::Svg);
    }
}
