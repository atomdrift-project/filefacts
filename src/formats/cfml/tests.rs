use super::*;
use crate::formats::cfml::specimens;

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
fn specimen_tag_counts_and_command_offsets() {
    use sha2::{Digest, Sha256};
    let decoded = specimens::encrypted_shell_decoded();
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
    let direct = specimens::datasource_shell();
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
    let attrs = attributes(b, &tags.tags[0], Dialect::Cfml).unwrap();
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
        assert!(attributes(b, &s.tags[0], Dialect::Cfml).is_none());
    }
    let mut b = String::from("<cfexecute");
    for i in 0..65 {
        b.push_str(&format!(" a{i}='x'"));
    }
    b.push('>');
    let s = scan(b.as_bytes());
    assert!(attributes(b.as_bytes(), &s.tags[0], Dialect::Cfml).is_none());
}
#[test]
fn encrypted_templates_need_decoding_before_syntax() {
    let original = specimens::encrypted_shell_original();
    let s = scan(original);
    assert_eq!(s.limitation, Some(Limit::Encrypted));
    assert!(s.tags.is_empty());
}
