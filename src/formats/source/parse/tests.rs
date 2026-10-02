use super::*;

fn count_case_flip_nodes(node: tree_sitter::Node<'_>, source: &str) -> usize {
    let mut count = usize::from(
        node.kind() == "expansion"
            && source
                .get(node.start_byte()..node.end_byte())
                .is_some_and(|text| text.contains('~')),
    );
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        count += count_case_flip_nodes(child, source);
    }
    count
}

#[test]
fn bash_53_case_modifications_parse_with_original_source_ranges() {
    let source = r#"printf '%s' "${value~}" "${@~~[[:lower:]]}""#;
    let parsed = TreeCache::parse(source.as_bytes(), FileType::Shell, None);
    let cache = parsed
        .cache()
        .expect("Bash 5.3 syntax should retain AST facts");
    assert!(!cache.tree().root_node().has_error());
    assert_eq!(cache.source(), source);
    assert_eq!(
        count_case_flip_nodes(cache.tree().root_node(), cache.source()),
        2
    );
}

#[test]
fn bash_53_normalizer_leaves_other_double_tildes_alone() {
    let source = "echo ${value/~~/x} ${fallback:-~~} ~~";
    assert!(normalize_bash_case_modification(source).is_none());
    assert!(normalize_bash_case_modification("echo ${value^^}").is_none());
}

#[test]
fn bash_53_normalizer_handles_special_indirect_and_array_parameters() {
    let source = "echo ${!~~} ${!value~~} ${array[@]~~[[:lower:]]}";
    assert_eq!(
        normalize_bash_case_modification(source).as_deref(),
        Some("echo ${!^^} ${!value^^} ${array[@]^^[[:lower:]]}")
    );
}

#[test]
fn bash_53_normalizer_is_linear_on_unterminated_openers() {
    // Each opener used to rescan the rest of the input for `]` or `}`.
    let unterminated = "${a[".repeat(64 * 1024) + "~}";
    assert!(normalize_bash_case_modification(&unterminated).is_none());
    let far_close = "${a~".repeat(64 * 1024) + "}";
    assert_eq!(
        normalize_bash_case_modification(&far_close),
        Some("${a^".repeat(64 * 1024) + "}")
    );
    let long_subscript = format!("${{a[{}]~}}", "1".repeat(MAX_BASH_SUBSCRIPT));
    assert!(normalize_bash_case_modification(&long_subscript).is_none());
}

#[test]
fn bash_53_obfuscated_shell_regression_parses_without_losing_original_offsets() {
    let source = include_bytes!("../../../../testdata/shell/bash53-case-inversion/4a5376aa6c33.sh");
    let parsed = TreeCache::parse(source, FileType::Shell, None);
    let cache = parsed
        .cache()
        .expect("Bash 5.3 operator should not discard shell AST facts");
    assert!(!cache.tree().root_node().has_error());
    let source = std::str::from_utf8(source).expect("sample is ASCII");
    assert_eq!(cache.source(), source);
    assert_eq!(count_case_flip_nodes(cache.tree().root_node(), source), 2);
}

#[test]
fn skips_oversized_source() {
    let huge = "x = 1\n".repeat(MAX_MODELED_AST_FILE_BYTES / 6 + 1);
    assert!(would_overflow_scanner_state(FileType::Python, &huge));
}

#[test]
fn bounded_javascript_has_thirty_two_mibibyte_cap_while_python_stays_tighter() {
    assert_eq!(
        parse_cap_bytes(scanner_audit(FileType::JavaScript)),
        32 * 1024 * 1024
    );
    assert_eq!(
        parse_cap_bytes(scanner_audit(FileType::Python)),
        4 * 1024 * 1024
    );
    // JavaScript's external scanner serializes no state, so ordinary
    // bundled source beyond the former 16 MiB cap is not scanner-state pressure.
    let source = format!("/*{}*/\nconst value = 1;", "x".repeat(20 * 1024 * 1024));
    assert!(source.len() > 16 * 1024 * 1024);
    assert!(source.len() < MAX_AST_FILE_BYTES);
    assert!(!would_overflow_scanner_state(FileType::JavaScript, &source));
}

#[test]
fn parses_javascript_above_the_old_sixteen_mibibyte_cap() {
    let source = format!("/*{}*/\nconst value = 1;", "x".repeat(20 * 1024 * 1024));
    assert!(source.len() > 16 * 1024 * 1024);
    let parsed = TreeCache::parse(source.as_bytes(), FileType::JavaScript, None);
    assert!(
        parsed.cache().is_some(),
        "audited JavaScript below 32 MiB should retain AST facts"
    );
}

#[test]
fn bounded_javascript_still_refuses_source_above_thirty_two_mibibytes() {
    let source = "x".repeat(MAX_AST_FILE_BYTES + 1);
    assert!(would_overflow_scanner_state(FileType::JavaScript, &source));
}

/// Parse with the work budget overridden to `polls`.
fn parse_with_work_budget(source: &[u8], file_type: FileType, polls: u64) -> TreeParse<'_> {
    PARSE_WORK_OVERRIDE.set(polls);
    let parsed = TreeCache::parse(source, file_type, None);
    PARSE_WORK_OVERRIDE.set(0);
    parsed
}

/// An exhausted budget must degrade to a diagnostic, not a panic: the
/// caller still emits generic/text facts for the file.
#[test]
fn exhausted_work_budget_degrades_to_a_diagnostic() {
    // One poll is spent long before 40k lines are parsed, so this
    // exercises the budget path without needing adversarial input.
    let source = "def f():\n    return 1\n".repeat(20_000);
    let parsed = parse_with_work_budget(source.as_bytes(), FileType::Python, 1);
    let diagnostic = parsed
        .diagnostic()
        .expect("an abandoned parse yields no tree");
    assert_eq!(
        diagnostic.metric.as_str(),
        "source.ast_unavailable.parse_timeout"
    );
    assert!(diagnostic.message.contains("work budget"));
}

/// The point of a work budget: the same input stops at the same place no
/// matter how fast the machine is running, so the facts (and the disk
/// cache entry built from them) are a function of the bytes alone. A
/// single-line Perl chain is genuinely pathological — its scanner
/// re-scans the line on every token — and an unrelated parse in between
/// shows the reused thread-local parser carries nothing over.
#[test]
fn exhausted_work_budget_stops_at_the_same_point_every_time() {
    let source = format!("my $x = 1{};\n", "+1".repeat(5_000));
    let stop_message = || {
        let parsed = parse_with_work_budget(source.as_bytes(), FileType::Perl, 50);
        parsed
            .diagnostic()
            .expect("50 polls cannot cover a 10k-token line")
            .message
            .clone()
    };
    let first = stop_message();
    let other = "sub f { return 1 }\n".repeat(1_000);
    assert!(
        TreeCache::parse(other.as_bytes(), FileType::Perl, None)
            .cache()
            .is_some()
    );
    assert_eq!(first, stop_message());
    assert!(
        first.contains("work budget of 50 progress polls at byte "),
        "{first}"
    );
}

/// A raised cancellation flag abandons the parse and reports separately
/// from a timeout.
#[test]
fn a_raised_cancellation_flag_abandons_the_parse() {
    use std::sync::atomic::AtomicBool;

    let flag = AtomicBool::new(true);
    let source = "def f():\n    return 1\n".repeat(20_000);
    let parsed = TreeCache::parse(source.as_bytes(), FileType::Python, Some(&flag));
    let diagnostic = parsed
        .diagnostic()
        .expect("a cancelled parse yields no tree");
    assert_eq!(
        diagnostic.metric.as_str(),
        "source.ast_unavailable.parse_cancelled"
    );
}

/// A flag that stays false must be invisible — the guard against a poll
/// that accidentally cancels healthy work.
#[test]
fn an_unraised_cancellation_flag_changes_nothing() {
    use std::sync::atomic::AtomicBool;

    let flag = AtomicBool::new(false);
    let source = "def f():\n    return 1\n".repeat(20_000);
    let parsed = TreeCache::parse(source.as_bytes(), FileType::Python, Some(&flag));
    assert!(
        parsed.cache().is_some(),
        "an un-raised flag must not disturb the parse"
    );
}

/// The default budget is a backstop, not a throughput limiter: ordinary
/// source must parse untouched. Guards against a future edit that makes the
/// budget fire on normal files and silently sheds detection.
#[test]
fn default_budget_does_not_disturb_an_ordinary_parse() {
    let source = "def f():\n    return 1\n".repeat(20_000);
    let parsed = TreeCache::parse(source.as_bytes(), FileType::Python, None);
    assert!(
        parsed.cache().is_some(),
        "a normal parse must not hit the work budget"
    );
}

/// The calibration promise: an ordinary large file fits in a tenth of
/// its budget. A 4 MiB minified bundle is close to the densest real
/// source measured (about 0.02 polls per byte).
#[test]
fn ordinary_large_file_parses_within_a_tenth_of_its_budget() {
    let mut source = String::new();
    let mut i = 0;
    while source.len() < 4 * 1024 * 1024 {
        source.push_str(&format!(
                "function a{i}(e,t,n){{var r=n({i}),o=n.n(r);return e.exports=Object.assign({{}},t,{{x{i}:[1,2,3].map(function(u){{return u*{i}}}),y:\"s{i}\"+t.q}}),o}}"
            ));
        i += 1;
    }
    let tenth = parse_work_budget(source.len()) / 10;
    let parsed = parse_with_work_budget(source.as_bytes(), FileType::JavaScript, tenth);
    assert!(
        parsed.cache().is_some(),
        "an ordinary 4 MiB bundle must parse within a tenth of its budget"
    );
}

#[test]
fn skips_deep_python_indentation() {
    // Indent levels alone large enough to exceed the budget when
    // even a tiny delimiter stack is added on top.
    let mut source = String::new();
    for depth in 0..600 {
        source.push_str(&" ".repeat(depth * 2));
        source.push_str("if True:\n");
    }
    assert!(would_overflow_scanner_state(FileType::Python, &source));
}

/// Adversarial Python that pushes BOTH the indent stack and the
/// delimiter stack hard enough that the combined serialized state
/// exceeds the 1024-byte buffer — even though each stack on its
/// own would stay under the upstream serializer's clamps. The
/// pre-existing indent-only guard at 450 levels missed this
/// scenario; the budget-based check catches it.
#[test]
fn skips_combined_indent_and_fstring_pressure() {
    let mut source = String::new();
    // Bury an open f-string deep enough that the delimiter stack
    // carries 255 entries when the indent stack is also large.
    for _ in 0..255 {
        source.push_str("f\"{");
    }
    for depth in 0..400 {
        source.push_str(&" ".repeat(depth + 1));
        source.push_str("if True:\n");
    }
    assert!(would_overflow_scanner_state(FileType::Python, &source));
}

#[test]
fn allows_normal_python() {
    let source = "def f():\n    return 1\n";
    assert!(!would_overflow_scanner_state(FileType::Python, source));
}

#[test]
fn allows_realistic_fstring_usage() {
    let source = r#"
def greet(name, count):
    return f"hello {name}, you have {count} messages, {f'~{count*2}~'} doubled"
"#;
    assert!(!would_overflow_scanner_state(FileType::Python, source));
}

#[test]
fn deep_indentation_ignored_for_non_python() {
    let mut source = String::new();
    for depth in 0..600 {
        source.push_str(&" ".repeat(depth * 2));
        source.push_str("echo hi\n");
    }
    assert!(!would_overflow_scanner_state(FileType::Shell, &source));
}

#[test]
fn unaudited_grammars_use_tight_cap() {
    // Unrecognized text has no grammar audit entry. Keep it below
    // the normal parser cap until a grammar is added and audited.
    let source = "1;\n".repeat(80_000); // ~240 KB.
    assert!(source.len() > UNAUDITED_GRAMMAR_CAP_BYTES);
    assert!(source.len() < MAX_AST_FILE_BYTES);
    assert!(would_overflow_scanner_state(FileType::Text, &source));
    // The same source under an audited, self-guarded grammar passes.
    assert!(!would_overflow_scanner_state(FileType::Shell, &source));
}

#[test]
fn parses_large_perl_source_with_self_guarded_scanner() {
    assert_eq!(scanner_audit(FileType::Perl), ScannerAudit::SelfGuarded);
    assert_eq!(
        parse_cap_bytes(scanner_audit(FileType::Perl)),
        MAX_AST_FILE_BYTES
    );

    // Mirrors ordinary installed tooling such as Wine's 95 KB winemaker
    // script: large source size alone does not imply a deep quote stack.
    let source = format!("#{}\nmy $value = 1;\n", "x".repeat(95_000));
    assert!(source.len() > UNAUDITED_GRAMMAR_CAP_BYTES);
    assert!(!would_overflow_scanner_state(FileType::Perl, &source));
    let parsed = TreeCache::parse(source.as_bytes(), FileType::Perl, None);
    let cache = parsed
        .cache()
        .expect("large Perl source should retain AST facts");
    assert!(!cache.tree().root_node().has_error());
}

#[test]
fn deeply_nested_perl_quotes_stay_within_scanner_serialization_buffer() {
    let mut source = String::from("my $value = ");
    for _ in 0..80 {
        source.push_str("qq{ ${\\ ");
    }
    source.push_str("'value'");
    for _ in 0..80 {
        source.push_str(" }}");
    }
    source.push_str(";\n");

    assert!(!would_overflow_scanner_state(FileType::Perl, &source));
    let parsed = TreeCache::parse(source.as_bytes(), FileType::Perl, None);
    assert!(parsed.cache().is_some());
}

#[test]
fn audit_lookup_covers_every_wired_grammar() {
    // Every file type that has a `LangConfig` in `langs::config_for`
    // must have an explicit audit entry — falling into the
    // `_ => Unaudited` catch-all should be deliberate, not
    // accidental. This test pins the audit table to the current
    // grammar set so a new `FileType` doesn't silently get the
    // tight cap.
    let audited: &[FileType] = &[
        FileType::C,
        FileType::CSharp,
        FileType::Elixir,
        FileType::Go,
        FileType::Groovy,
        FileType::Java,
        FileType::JavaScript,
        FileType::Kotlin,
        FileType::Lua,
        FileType::Makefile,
        FileType::ObjectiveC,
        FileType::Perl,
        FileType::Php,
        FileType::PowerShell,
        FileType::Python,
        FileType::Ruby,
        FileType::Rust,
        FileType::Scala,
        FileType::Shell,
        FileType::Swift,
        FileType::TypeScript,
        FileType::Zig,
    ];
    for ft in audited {
        // Bounded/SelfGuarded/Modeled — anything but Unaudited
        // counts as an explicit scanner audit entry.
        let audit = scanner_audit(*ft);
        assert_ne!(
            audit,
            ScannerAudit::Unaudited,
            "{ft:?} fell through to Unaudited — add explicit audit entry"
        );
    }
}

#[test]
fn scanner_bytes_estimator_tracks_both_stacks() {
    let plain = "x = 1\n";
    let n_plain = estimated_python_scanner_bytes(plain);
    // 2-byte header + 0 delimiter + 0 indent (single line, no block).
    assert_eq!(n_plain, 2);

    let nested = "x = f\"{f\"{1}\"}\"\n";
    let n_nested = estimated_python_scanner_bytes(nested);
    // 2 header + 2 delimiters + 0 indent.
    assert_eq!(n_nested, 4);
}
