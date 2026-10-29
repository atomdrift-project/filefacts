use super::*;

fn shell(target: &str) -> TargetKind {
    classify(target, Lang::Bash)
}

#[test]
fn clean_literals_are_clean() {
    for t in ["echo", "base64", "sh", "set", "alias", "printf", "git", "f"] {
        assert_eq!(shell(t), TargetKind::Clean, "{t}");
    }
}

#[test]
fn benign_variable_and_path_commands() {
    // Interpreter-in-a-variable and path-prefixed commands are NOT
    // obfuscation; the bare ones are merely dynamic.
    assert_eq!(shell("$CC"), TargetKind::Dynamic);
    assert_eq!(shell("$1"), TargetKind::Dynamic);
    assert_eq!(shell("${PYTHON}"), TargetKind::Dynamic);
    assert_eq!(shell("$HOME/bin/tool"), TargetKind::Clean);
    assert_eq!(shell("${PREFIX}/sbin/daemon"), TargetKind::Clean);
    // A single expansion welded onto a real word (versioned interpreter)
    // reads as an ordinary name — neither obfuscated nor flag-worthy.
    assert_eq!(shell("python${VER}"), TargetKind::Clean);
    // Resolver command substitutions are dynamic, not obfuscated.
    assert_eq!(shell("$(command -v python)"), TargetKind::Dynamic);
    assert_eq!(shell("$(which gcc)"), TargetKind::Dynamic);
    // A quoted variable command (best practice) is dynamic, not shattered.
    assert_eq!(shell("\"$SANE_SH\""), TargetKind::Dynamic);
    assert_eq!(shell("\"$python_version\""), TargetKind::Dynamic);
    // A quoted literal command unwraps to a plain name.
    assert_eq!(shell("\"ls\""), TargetKind::Clean);
    // Default/alternate parameter command fallbacks are a standard idiom.
    assert_eq!(shell("${filt:-cat}"), TargetKind::Dynamic);
    assert_eq!(shell("${PAGER:-less}"), TargetKind::Dynamic);
    // A single leading backslash is the benign alias-bypass idiom.
    assert_eq!(shell("\\rm"), TargetKind::Clean);
}

#[test]
fn obfuscated_command_names() {
    for t in [
        "\\b\\u\\n",                // 02 backslash escapes
        "$A$B",                     // 04 glued expansions
        "b$@u$n",                   // 08 $@ glue
        "b$*u$n",                   // 09 $* glue
        "b${UNSET}u${NOPE}n",       // 10 empty-var glue
        "$(echo bun)",              // 12 command-sub decoder
        "$(printf \"\\142\\165\")", // 13 octal-escape decoder
        "$(printf \"\\x62\")",      // 14 hex-escape decoder
    ] {
        assert_eq!(shell(t), TargetKind::Obfuscated, "{t}");
    }
}

#[test]
fn quote_shatter_and_format_printf_are_not_metric_obfuscated() {
    // Quote-shattered literals unwrap to a plain name here (the text
    // char-split traits own that signal); a printf format string and an
    // error message with embedded quotes must not be flagged.
    assert_eq!(shell("\"b\"'u'\"n\""), TargetKind::Clean);
    assert_eq!(
        shell("`printf '%sX\\n' \"$1\" | sed \"$e\"`"),
        TargetKind::Dynamic
    );
    assert_eq!(
        shell("\"Failed to start 'pamcat' process\""),
        TargetKind::Clean
    );
    // A spaced/multi-line "target" is a mis-parsed string argument, not a
    // welded command name — backslash continuations must not trip it.
    assert_eq!(
        shell("pgmtoppm \\\"$colorlist[0]\\\" >$outfile"),
        TargetKind::Clean
    );
    // `echo "$x" | sed` indent plumbing is not a decoder.
    assert_eq!(
        shell("`echo \"$indent\" | sed 's|.| |g'`"),
        TargetKind::Dynamic
    );
}

#[test]
fn default_param_command_is_dynamic_not_obfuscated() {
    // `${b:-bun}` (sample 19) is structurally identical to the benign
    // `${PAGER:-less}` idiom, so it must classify as dynamic, never
    // obfuscated — there is no FP-safe way to flag it.
    assert_eq!(shell("${b:-bun}"), TargetKind::Dynamic);
}

#[test]
fn non_shell_languages_emit_nothing_yet() {
    assert_eq!(classify("$A$B", Lang::JavaScript), TargetKind::Clean);
    assert_eq!(classify("foo.bar", Lang::Python), TargetKind::Clean);
}

#[test]
fn emit_counts_into_metrics() {
    let calls = vec![
        Symbol::Call {
            target: Some("$A$B".to_string()),
            args: vec![],
            offset: None,
        },
        Symbol::Call {
            target: Some("$CC".to_string()),
            args: vec![],
            offset: None,
        },
        Symbol::Call {
            target: Some("echo".to_string()),
            args: vec![],
            offset: None,
        },
    ];
    let mut metrics = Metrics::default();
    emit(&calls, Lang::Bash, &mut metrics);
    assert_eq!(metrics.get("calls.obfuscated_target_count"), Some(1.0));
    assert_eq!(metrics.get("calls.dynamic_target_count"), Some(1.0));
}
