use super::*;

fn bodies(page: &str) -> Vec<&str> {
    script_bodies(page.as_bytes(), false)
        .into_iter()
        .map(|r| &page[r])
        .collect()
}

fn view_of(page: &str, file_type: FileType) -> Option<String> {
    inline_scripts(Some((page.as_bytes(), file_type))).map(|s| s.source.into_owned())
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
        <script type=" Text/JavaScript; charset=utf-8 ">t()</script>
        <script type="">e()</script>
        <script language="VBScript">MsgBox 1</script>
        <script language="JavaScript">l()</script>
        <script language="">n()</script>"#;
    assert_eq!(bodies(page), ["m()", "t()", "e()", "l()", "n()"]);
}

#[test]
fn the_view_keeps_the_pages_length_and_line_breaks() {
    let page =
        "<html>\r\n<head><title>é</title>\n<script>\n  go(1);\n</script></head>\n<body>ü</body>";
    let view = view_of(page, FileType::Html).unwrap();
    assert_eq!(view.len(), page.len());
    let breaks = |s: &str| {
        s.bytes()
            .enumerate()
            .filter(|(_, b)| matches!(b, b'\n' | b'\r'))
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    };
    assert_eq!(breaks(&view), breaks(page));
    let at = page.find("go(1)").unwrap();
    assert_eq!(&view[at..at + 5], "go(1)");
    assert!(view.find("title").is_none() && view.find("body").is_none());
}

#[test]
fn consecutive_scripts_cannot_run_into_each_other() {
    let page = "<script>a() // note</script><script>b()</script>";
    let view = view_of(page, FileType::Html).unwrap();
    assert_eq!(view.len(), page.len());
    assert!(view.contains("a() // note\u{2028};"), "{view:?}");
    assert!(!view.contains('\n'));
    assert!(view.trim_end().ends_with("b()"));
}

#[test]
fn the_view_parses_as_javascript_with_every_call() {
    let page = "<html><body>\n<script>var ua = navigator.userAgent // first\n\
        </script><script>if (ua.includes('FBAN')) { leave() } run(1)</script>\n</body></html>";
    let view = view_of(page, FileType::Html).unwrap();
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("view.js"))
        .open(view.as_bytes());
    let calls: Vec<String> = serde_json::to_value(parsed.symbols())
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["kind"] == "call")
        .filter_map(|s| s["target"].as_str().map(str::to_owned))
        .collect();
    for call in ["ua.includes", "leave", "run"] {
        assert!(
            calls.iter().any(|c| c == call),
            "{call} missing from {calls:?}"
        );
    }
}

#[test]
fn svg_scripts_lose_their_cdata_wrapper_and_may_self_close() {
    let page = "<svg><script href='x.js'/><script type=\"application/ecmascript\">\
        <![CDATA[ if (a < b) go() ]]></script></svg>";
    let view = view_of(page, FileType::Svg).unwrap();
    assert_eq!(view.len(), page.len());
    assert_eq!(view.trim(), "if (a < b) go()");
}

#[test]
fn bytes_that_are_not_utf8_keep_their_width() {
    let mut page = b"<script>s = '".to_vec();
    page.extend_from_slice(&[0xE9, 0xFF]);
    page.extend_from_slice(b"'; go()</script>");
    let view = inline_scripts(Some((&page, FileType::Html)))
        .unwrap()
        .source;
    assert_eq!(view.len(), page.len());
    assert!(view.contains("s = '??'; go()"));
}

#[test]
fn a_page_without_executable_script_has_no_view() {
    assert!(
        view_of(
            "<p>hi</p><script type='application/json'>{}</script>",
            FileType::Html
        )
        .is_none()
    );
    assert!(view_of("<script>  \n </script>", FileType::Html).is_none());
    assert!(view_of("<script src='x.js'></script>", FileType::Html).is_none());
}

#[test]
fn scanning_ends_on_hostile_input() {
    for page in [
        "<script",
        "<script type=\"",
        "<<<<",
        "<!--",
        "<textarea>",
        "</script>",
        "<script>",
        "<a b=c d='e' f=\"g\"/ >",
    ] {
        let _ = script_bodies(page.as_bytes(), false);
        let _ = script_bodies(page.as_bytes(), true);
        let _ = view_of(page, FileType::Html);
    }
}
