use super::*;

/// The comment-tier texts filefacts reports for `source` named `path`.
fn comments(path: &str, source: &str) -> Vec<String> {
    crate::OpenOptions::new()
        .path(std::path::Path::new(path))
        .open(source.as_bytes())
        .comments()
        .iter()
        .map(|c| c.value.clone())
        .collect()
}

fn metrics(path: &str, source: &str) -> crate::Metrics {
    crate::OpenOptions::new()
        .path(std::path::Path::new(path))
        .open(source.as_bytes())
        .metrics()
        .clone()
}

#[test]
fn delimiters_are_stripped() {
    assert_eq!(comment_body("// a"), (2, " a"));
    assert_eq!(comment_body("/* b */"), (2, " b "));
    assert_eq!(comment_body("/* open"), (2, " open"));
    assert_eq!(comment_body("# c"), (1, " c"));
    assert_eq!(comment_body("-- d"), (2, " d"));
    assert_eq!(comment_body("--[==[ e ]==]"), (6, " e "));
    assert_eq!(comment_body("--[[ f ]]"), (4, " f "));
    assert_eq!(comment_body("; g"), (1, " g"));
    assert_eq!(comment_body(":: h"), (2, " h"));
    assert_eq!(comment_body("REM   i"), (6, "i"));
    assert_eq!(comment_body("@rem i"), (5, "i"));
    assert_eq!(comment_body("// line\n"), (2, " line"));
    assert_eq!(comment_body("<# j #>"), (2, " j "));
    assert_eq!(comment_body("<!-- k -->"), (4, " k "));
    assert_eq!(comment_body("=begin\nl\n=end"), (0, "=begin\nl\n=end"));
}

#[test]
fn c_style_comments_are_found() {
    assert_eq!(
        comments("a.c", "int x = 1; // line\n/* block */ int y;\n"),
        ["line", "block"]
    );
}

#[test]
fn comment_offsets_point_at_their_bodies() {
    let src = "int x; //   spaced\n/* b */\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("a.c"))
        .open(src.as_bytes());
    for comment in parsed.comments() {
        let at = usize::try_from(comment.offset).unwrap();
        assert!(src[at..].starts_with(&comment.value), "{comment:?}");
    }
}

/// The grammar, not a scanner, decides: `//` and `/*` inside template
/// literals, strings and regexes are not comments.
#[test]
fn javascript_strings_templates_and_regexes_hide_their_contents() {
    let src = "const u = `see https://x.test/* not */`; const r = /\\/\\//; const s = \"// no\"; // yes\n";
    assert_eq!(comments("a.js", src), ["yes"]);
}

#[test]
fn rust_lifetimes_chars_raw_strings_and_nested_blocks() {
    assert_eq!(
        comments("a.rs", "fn f(s: &'static str) { // SECRET\n}\n"),
        ["SECRET"]
    );
    assert_eq!(
        comments(
            "a.rs",
            "fn g() { let c = '\"'; let r = r#\"// no\"#; } // real\n"
        ),
        ["real"]
    );
    assert_eq!(
        comments("a.rs", "/* outer /* inner */ still */ fn h() {}\n"),
        ["outer /* inner */ still"]
    );
}

/// `#` in a parameter expansion or a heredoc is not a comment.
#[test]
fn shell_comments_only() {
    let src = "n=${#x} # length\ncat <<EOF\n# not a comment\nEOF\n";
    assert_eq!(comments("a.sh", src), ["length"]);
}

#[test]
fn hash_double_dash_and_semicolon_comments() {
    assert_eq!(comments("a.py", "x = '#no' # yes\n"), ["yes"]);
    assert_eq!(
        comments("a.lua", "x = '--no' -- yes\n--[[ block ]]\n"),
        ["yes", "block"]
    );
    assert_eq!(comments("a.clj", "(def s \";no\") ; yes\n"), ["yes"]);
}

#[test]
fn batch_comments_are_found() {
    let found = comments(
        "a.bat",
        "@echo off\nREM first\n:: second\n@rem third\necho rem not\n",
    );
    assert_eq!(found, ["first", "second", "third"]);
    // A multi-byte character right after the marker does not split a char.
    assert_eq!(comments("a.bat", "REM 語\n"), ["語"]);
}

#[test]
fn todo_fixme_detection() {
    let m = metrics(
        "a.c",
        "// TODO: fix\n// FIXME later\n/* HACK */\n// xxx\nint x;\n",
    );
    assert_eq!(m.get("comments.count"), Some(4.0));
    assert_eq!(m.get("comments.todo_count"), Some(1.0));
    assert_eq!(m.get("comments.fixme_count"), Some(1.0));
    assert_eq!(m.get("comments.hack_count"), Some(1.0));
    assert_eq!(m.get("comments.xxx_count"), Some(1.0));
}

#[test]
fn pattern_hits_match_case_folded_contains() {
    let corpus = [
        "TODO: remove eval(x) and exec(y)",
        "x = function() { return 1 }",
        "if (a) for (b) while (c)",
        "Hack around XXX-12; see FixMe",
        "const a = () => { import x }",
        "plain prose with no code at all",
        "défini: let x; var y",
        "ſtrange xxx",
        "",
    ];
    for text in corpus {
        let upper = text.to_uppercase();
        let lower = text.to_lowercase();
        let expected = ANNOTATIONS
            .iter()
            .map(|p| upper.contains(p))
            .chain(CODE_PATTERNS.iter().map(|p| lower.contains(p)))
            .enumerate()
            .fold(0, |hits, (i, hit)| hits | u32::from(hit) << i);
        assert_eq!(pattern_hits(text), expected, "{text}");
    }
    // `= function(` holds two overlapping patterns.
    let hits = pattern_hits("x = function(a)");
    assert_eq!((hits & CODE_PATTERN_BITS).count_ones(), 2);
}
