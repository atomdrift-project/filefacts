//! Source-code extractors.
//!
//! Source files are parsed once with tree-sitter. The resulting tree
//! is cached on the [`ParsedFile`] and shared by every view that needs
//! it: typed symbol views read imports / functions / classes,
//! `strings` reads literal nodes, `metrics` reads the node count, and
//! `ast` reads the call-graph projection. No view ever causes a re-parse.
//!
//! [`ParsedFile`]: crate::ParsedFile

mod ast_walk;
mod comment_metrics;
mod function_metrics;
mod identifier_metrics;
mod import_metrics;
mod langs;
pub(crate) mod parse;
mod string_metrics;
mod text_metrics;

use tree_sitter::{Node, QueryCursor, StreamingIterator};

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ExtractedString, Metrics, Strings, Values};

use serde_json::Value as JsonValue;

pub(crate) use parse::TreeCache;

// The dispatcher in `formats::extract` requires every format
// extractor to return `Result<(), Error>` even when the impl can't
// fail; uniformity is more valuable than removing one always-Ok arm.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn extract(
    _bytes: &[u8],
    _file_type: FileType,
    tree_cache: Option<&TreeCache<'_>>,
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) -> Result<(), Error> {
    let Some(cache) = tree_cache else {
        // Even without a parse, the byte stream still has language-agnostic
        // text features worth surfacing — emit `text.*` metrics from the
        // raw bytes when they decode as UTF-8.
        if let Ok(content) = std::str::from_utf8(_bytes) {
            text_metrics::emit(content, metrics);
        }
        return Ok(());
    };
    let config =
        langs::config_for(cache.file_type()).expect("tree_cache implies config_for is Some");
    let source = cache.source();
    let root = cache.tree().root_node();

    // Byte-level / line-level / whitespace text metrics — language-agnostic.
    text_metrics::emit(source, metrics);

    // Comment metrics use the language's comment style; no AST.
    comment_metrics::emit(source, config.comment_style, metrics);

    extract_strings(root, source, config, strings, metrics);
    let imports = collect_query(config.language, source, root, config.import_query);
    let functions = collect_query(config.language, source, root, config.function_query);
    let classes = collect_query(config.language, source, root, config.class_query);

    // Identifier metrics — walk the tree once, emit `identifiers.*`.
    let identifiers = identifier_metrics::collect_identifiers(root, source, config);
    identifier_metrics::emit(&identifiers, metrics);

    // String-literal metrics — operate on the literals we already
    // extracted into the `strings` view.
    let literal_refs: Vec<&str> = strings.literals.iter().map(|s| s.text.as_str()).collect();
    string_metrics::emit(&literal_refs, metrics);

    // Import metrics — feed the canonical language name so stdlib
    // classification works.
    let import_refs: Vec<&str> = imports.iter().map(|(n, _)| n.as_str()).collect();
    import_metrics::emit(&import_refs, config.name, metrics);

    // Function metrics — single AST walk over function-definition nodes.
    let total_lines = source.lines().count() as u32;
    function_metrics::emit(root, source, config, total_lines, metrics);

    // Cross-component text ratios computed from the sub-metrics we just
    // emitted. Pure division — no extra parsing.
    emit_text_ratios(metrics, total_lines);

    // Push source-language imports / functions / classes into the
    // unified Symbols view. `library` stays unset — source-language
    // imports are module-scoped strings, not library-tagged. Source
    // tag is the language name (`"javascript"`, `"python"`, `"go"`,
    // …) so trait matchers can filter by language without consulting
    // file_type.
    for (name, offset) in &imports {
        symbols_out.push(crate::Symbol::Import {
            name: name.clone(),
            library: None,
            source: config.name.into(),
            offset: Some(*offset),
            ordinal: None,
        });
    }
    if !functions.is_empty() {
        metrics.insert("source.function_count", functions.len() as f64);
    }
    for (name, offset) in &functions {
        symbols_out.push(crate::Symbol::Function {
            name: name.clone(),
            source: config.name.into(),
            offset: Some(*offset),
            decl: Some("function".into()),
            complexity: None,
            basic_blocks: None,
            edges: None,
            instructions: None,
            stack_frame: None,
            recursive: None,
            noreturn: None,
            is_linear: None,
            callees: Vec::new(),
        });
    }
    if !classes.is_empty() {
        metrics.insert("source.class_count", classes.len() as f64);
    }
    // Class declarations surface as `Symbol::Function` with
    // `decl: "class"` — the symbol axis is "things declared here",
    // regardless of whether the declaration is a function or a class.
    // Consumers that need the distinction read the decl field.
    for (name, offset) in &classes {
        symbols_out.push(crate::Symbol::Function {
            name: name.clone(),
            source: config.name.into(),
            offset: Some(*offset),
            decl: Some("class".into()),
            complexity: None,
            basic_blocks: None,
            edges: None,
            instructions: None,
            stack_frame: None,
            recursive: None,
            noreturn: None,
            is_linear: None,
            callees: Vec::new(),
        });
    }

    values.insert(
        "source.language",
        JsonValue::String(config.name.to_string()),
    );

    Ok(())
}

/// Walk the tree-sitter parse and push every `Symbol::Call`,
/// `Symbol::Member`, and `Symbol::Bind` into `symbols_out`. Replaces
/// the prior `build_ast` which materialised a separate `Ast` struct.
pub(crate) fn build_symbols(
    cache: &TreeCache,
    symbols_out: &mut crate::Symbols,
    metrics: &mut Metrics,
) {
    let config =
        langs::config_for(cache.file_type()).expect("tree_cache implies config_for is Some");
    let source = cache.source();
    let root = cache.tree().root_node();
    ast_walk::walk(root, source, config, symbols_out, metrics);
}

fn extract_strings(
    root: Node<'_>,
    source: &str,
    config: &langs::LangConfig,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    let mut count: u64 = 0;
    let mut cursor = root.walk();
    let mut stack: Vec<Node<'_>> = vec![root];
    while let Some(node) = stack.pop() {
        if config.string_kinds.contains(&node.kind()) {
            if let Some(text) = decode_string_literal(node, source) {
                strings.literals.push(ExtractedString {
                    text,
                    offset: node.start_byte(),
                    ..ExtractedString::default()
                });
                count += 1;
            }
            continue;
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    if count > 0 {
        metrics.insert("ast.string_literal_count", count as f64);
    }
}

fn decode_string_literal(node: Node<'_>, source: &str) -> Option<String> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    if raw.is_empty() {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut start = 0_usize;
    let mut end = bytes.len();
    while start < end && is_string_prefix(bytes[start]) {
        start += 1;
    }
    if start >= end {
        return None;
    }
    let open = bytes[start];
    if !matches!(open, b'"' | b'\'' | b'`') {
        return Some(raw.to_string());
    }
    if end > start + 1 && bytes[end - 1] == open {
        start += 1;
        end -= 1;
    } else {
        return None;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(str::to_string)
}

fn is_string_prefix(b: u8) -> bool {
    matches!(b, b'b' | b'B' | b'r' | b'R' | b'f' | b'F' | b'u' | b'U')
}

fn collect_query(
    language_fn: fn() -> tree_sitter::Language,
    source: &str,
    root: Node<'_>,
    query_src: &'static str,
) -> Vec<(String, u64)> {
    if query_src.is_empty() {
        return Vec::new();
    }
    let Ok(query) = tree_sitter::Query::new(&language_fn(), query_src) else {
        return Vec::new();
    };
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    // De-duplicate by name, keeping the first (smallest) offset for
    // each. A repeated `import os` shows up once; the offset points
    // at its first occurrence, which is the most useful answer for
    // proximity-style matchers.
    let mut seen: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut matches = cursor.matches(&query, root, source.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            let name = capture_names.get(cap.index as usize).copied().unwrap_or("");
            if name.starts_with('_') {
                continue;
            }
            if let Ok(text) = cap.node.utf8_text(source.as_bytes()) {
                let cleaned = strip_quotes(text);
                if cleaned.is_empty() {
                    continue;
                }
                let offset = cap.node.start_byte() as u64;
                seen.entry(cleaned).or_insert(offset);
            }
        }
    }
    seen.into_iter().collect()
}

fn strip_quotes(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && matches!(first, b'"' | b'\'' | b'`') {
            return std::str::from_utf8(&bytes[1..bytes.len() - 1])
                .unwrap_or(s)
                .to_string();
        }
    }
    s.to_string()
}

/// True when this file type is a source language filefacts can parse.
pub(crate) fn supports(file_type: FileType) -> bool {
    langs::config_for(file_type).is_some()
}

/// Resolve `file_type` to its tree-sitter [`Language`]. Used by callers
/// that want to compile a tree-sitter query against the same grammar
/// filefacts uses internally — e.g. rule-engine load-time validation.
pub(crate) fn tree_sitter_language(file_type: FileType) -> Option<tree_sitter::Language> {
    langs::config_for(file_type).map(|config| (config.language)())
}

/// Emit text-level metrics (`text.*`) without a tree-sitter parse.
///
/// Called from the format dispatcher for text-like languages that
/// don't yet have a [`LangConfig`] entry (Vbs, Batch, …). Only emits
/// the byte-level / line-level / whitespace metrics that don't need
/// an AST — language-agnostic by construction.
pub(crate) fn extract_text_only(bytes: &[u8], metrics: &mut Metrics) {
    if let Ok(content) = std::str::from_utf8(bytes) {
        text_metrics::emit(content, metrics);
    }
}

/// Compute cross-component ratios on `text.*` from already-emitted
/// sub-metrics (`identifiers.*` / `strings.*` / `comments.*` /
/// `functions.*` / `imports.*`). Pure division — no parsing.
fn emit_text_ratios(metrics: &mut Metrics, total_lines: u32) {
    let m = metrics.clone();
    let get = |k: &str| m.get(k).unwrap_or(0.0);

    let functions_total = get("functions.total");
    let strings_total = get("strings.total");
    let identifiers_total = get("identifiers.total");
    let identifiers_unique = get("identifiers.unique_count");
    let imports_total = get("imports.total");
    let functions_anonymous = get("functions.anonymous");

    if functions_total > 0.0 {
        metrics.insert(
            "text.strings_to_functions_ratio",
            strings_total / functions_total,
        );
        metrics.insert(
            "text.identifiers_to_functions_ratio",
            identifiers_unique / functions_total,
        );
        if imports_total > 0.0 {
            metrics.insert(
                "text.imports_to_functions_ratio",
                imports_total / functions_total,
            );
        }
        if functions_anonymous > 0.0 {
            metrics.insert(
                "text.anonymous_function_ratio",
                functions_anonymous / functions_total,
            );
        }
    }

    if total_lines > 0 {
        let lines_f = f64::from(total_lines);
        if identifiers_total > 0.0 {
            metrics.insert("text.identifier_density", identifiers_total / lines_f);
        }
        if strings_total > 0.0 {
            metrics.insert("text.string_density", strings_total / lines_f);
        }
        if imports_total > 0.0 {
            metrics.insert("text.import_density", (imports_total * 100.0) / lines_f);
        }
        let lines_sqrt = lines_f.sqrt();
        if lines_sqrt > 0.0 {
            if functions_total > 0.0 {
                metrics.insert(
                    "text.normalized_function_count",
                    functions_total / lines_sqrt,
                );
            }
            if imports_total > 0.0 {
                metrics.insert("text.normalized_import_count", imports_total / lines_sqrt);
            }
            if strings_total > 0.0 {
                metrics.insert("text.normalized_string_count", strings_total / lines_sqrt);
            }
        }
        let lines_log = lines_f.log2();
        if lines_log > 0.0 && identifiers_unique > 0.0 {
            metrics.insert(
                "text.normalized_unique_identifiers",
                identifiers_unique / lines_log,
            );
        }
    }

    // Obfuscation indicator ratios.
    if identifiers_unique > 0.0 {
        let suspicious = get("identifiers.hex_like_names")
            + get("identifiers.base64_like_names")
            + get("identifiers.sequential_names")
            + get("identifiers.keyboard_pattern_names")
            + get("identifiers.repeated_char_names");
        if suspicious > 0.0 {
            metrics.insert(
                "text.suspicious_identifier_ratio",
                suspicious / identifiers_unique,
            );
        }
    }

    if strings_total > 0.0 {
        let encoded = get("strings.base64_candidates")
            + get("strings.hex_strings")
            + get("strings.url_encoded_strings");
        if encoded > 0.0 {
            metrics.insert("text.encoded_string_ratio", encoded / strings_total);
        }
        let suspicious = get("strings.embedded_code_candidates")
            + get("strings.shell_command_strings")
            + get("strings.sql_strings");
        if suspicious > 0.0 {
            metrics.insert("text.suspicious_string_ratio", suspicious / strings_total);
        }
        let dynamic = get("strings.concat_operations")
            + get("strings.char_construction")
            + get("strings.array_join_construction");
        if dynamic > 0.0 {
            metrics.insert("text.dynamic_string_ratio", dynamic / strings_total);
        }
    }

    let comments_total = get("comments.total");
    if comments_total > 0.0 {
        let suspicious = get("comments.high_entropy_comments") + get("comments.base64_in_comments");
        if suspicious > 0.0 {
            metrics.insert("text.suspicious_comment_ratio", suspicious / comments_total);
        }
    }

    if imports_total > 0.0 {
        let dynamic = get("imports.dynamic_imports") + get("imports.conditional_imports");
        if dynamic > 0.0 {
            metrics.insert("text.dynamic_import_ratio", dynamic / imports_total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_quotes_handles_three_quote_kinds() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
        assert_eq!(strip_quotes("'hello'"), "hello");
        assert_eq!(strip_quotes("`hello`"), "hello");
        assert_eq!(strip_quotes("hello"), "hello");
    }

    /// Python `import os` / `from sys import path` populate the
    /// unified [`crate::Symbols`] view with the language name as
    /// `source` and a non-zero byte offset.
    #[test]
    fn python_imports_populate_typed_view() {
        let src = b"import os\nfrom sys import path\nimport hashlib\n";
        // open_with_path so fileid classifies as Python via the
        // `.py` extension hint — without it the bytes look like
        // plain text and the source extractor never runs.
        let parsed = crate::open_with_path(std::path::Path::new("test.py"), src).unwrap();
        let _ = parsed.values();
        let imports: Vec<(&str, Option<&str>, bool)> = parsed
            .symbols()
            .iter_kind(crate::SymbolKind::Import)
            .filter_map(|s| match s {
                crate::Symbol::Import {
                    name,
                    library,
                    source,
                    offset,
                    ..
                } if source == "python" => {
                    Some((name.as_str(), library.as_deref(), offset.is_some()))
                }
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
        for (_, lib, has_offset) in &imports {
            assert!(lib.is_none());
            assert!(*has_offset);
        }
    }

    /// Helper: parse `src` as a source file with the given extension
    /// and return the import names + (function name, decl) pairs from
    /// the unified [`crate::Symbols`] view. Asserts the file classified
    /// to a non-text-only source extractor (i.e. `text.*` metrics
    /// fired) so callers can focus on language-specific structural facts.
    fn parse_source(name: &str, src: &[u8]) -> (Vec<String>, Vec<(String, Option<String>)>) {
        let parsed = crate::open_with_path(std::path::Path::new(name), src).unwrap();
        let _ = parsed.values();
        let imports: Vec<String> = parsed
            .symbols()
            .iter_kind(crate::SymbolKind::Import)
            .filter_map(|s| match s {
                crate::Symbol::Import { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        let functions: Vec<(String, Option<String>)> = parsed
            .symbols()
            .iter_kind(crate::SymbolKind::Function)
            .filter_map(|s| match s {
                crate::Symbol::Function { name, decl, .. } => Some((name.clone(), decl.clone())),
                _ => None,
            })
            .collect();
        assert!(
            parsed.metrics().get("text.total_lines").unwrap_or(0.0) > 0.0,
            "expected text.total_lines metric to fire for {name}"
        );
        (imports, functions)
    }

    #[test]
    fn ruby_imports_and_definitions() {
        let src = b"require 'json'\nrequire_relative './lib'\nclass Greeter\n  def hello; end\nend\nmodule M; end\n";
        let (imports, functions) = parse_source("app.rb", src);
        assert!(imports.iter().any(|s| s == "json"), "got {imports:?}");
        let names: std::collections::HashMap<&str, Option<String>> = functions
            .iter()
            .map(|(n, k)| (n.as_str(), k.clone()))
            .collect();
        assert_eq!(
            names.get("hello").cloned(),
            Some(Some("function".to_string()))
        );
        assert_eq!(
            names.get("Greeter").cloned(),
            Some(Some("class".to_string()))
        );
        assert_eq!(names.get("M").cloned(), Some(Some("class".to_string())));
    }

    #[test]
    fn lua_imports_and_definitions() {
        let src = b"local M = require(\"socket\")\nfunction greet(name)\n  return name\nend\nlocal function add(a, b) return a + b end\n";
        let (imports, functions) = parse_source("script.lua", src);
        assert!(imports.iter().any(|s| s == "socket"), "got {imports:?}");
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
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
        let names: std::collections::HashMap<&str, Option<String>> = functions
            .iter()
            .map(|(n, k)| (n.as_str(), k.clone()))
            .collect();
        assert_eq!(
            names.get("Hello").cloned(),
            Some(Some("function".to_string()))
        );
        assert_eq!(names.get("Bar").cloned(), Some(Some("class".to_string())));
    }

    #[test]
    fn c_imports_and_definitions() {
        let src = b"#include <stdio.h>\n#include \"local.h\"\nint add(int a, int b) { return a + b; }\nstruct P { int x; };\n";
        let (imports, functions) = parse_source("main.c", src);
        assert!(!imports.is_empty(), "expected C #include imports");
        let names: std::collections::HashMap<&str, Option<String>> = functions
            .iter()
            .map(|(n, k)| (n.as_str(), k.clone()))
            .collect();
        assert_eq!(
            names.get("add").cloned(),
            Some(Some("function".to_string()))
        );
        assert_eq!(names.get("P").cloned(), Some(Some("class".to_string())));
    }

    #[test]
    fn scala_imports_and_definitions() {
        let src = b"import scala.collection.mutable\nclass Greeter { def hello() = 1 }\nobject O { def add(a: Int, b: Int) = a + b }\n";
        let (imports, functions) = parse_source("App.scala", src);
        assert!(!imports.is_empty(), "expected scala imports");
        let names: std::collections::HashMap<&str, Option<String>> = functions
            .iter()
            .map(|(n, k)| (n.as_str(), k.clone()))
            .collect();
        assert_eq!(
            names.get("hello").cloned(),
            Some(Some("function".to_string()))
        );
        assert_eq!(
            names.get("Greeter").cloned(),
            Some(Some("class".to_string()))
        );
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
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"hello"), "got {names:?}");
        assert!(names.contains(&"add"), "got {names:?}");
    }

    #[test]
    fn swift_imports_and_definitions() {
        let src = b"import Foundation\nclass Greeter {\n  func hello() -> Int { return 1 }\n}\nfunc add(a: Int, b: Int) -> Int { return a + b }\n";
        let (imports, functions) = parse_source("app.swift", src);
        assert!(imports.iter().any(|s| s == "Foundation"), "got {imports:?}");
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"add"), "got {names:?}");
    }

    #[test]
    fn perl_imports_and_definitions() {
        let src = b"use strict;\nuse warnings;\nuse Foo::Bar;\npackage My::Class;\nsub greet { return 1 }\nsub add { my ($a, $b) = @_; return $a + $b }\n";
        let (imports, functions) = parse_source("app.pl", src);
        assert!(imports.iter().any(|s| s == "Foo::Bar"), "got {imports:?}");
        let names: std::collections::HashMap<&str, Option<String>> = functions
            .iter()
            .map(|(n, k)| (n.as_str(), k.clone()))
            .collect();
        assert_eq!(
            names.get("greet").cloned(),
            Some(Some("function".to_string()))
        );
        assert_eq!(
            names.get("add").cloned(),
            Some(Some("function".to_string()))
        );
        assert_eq!(
            names.get("My::Class").cloned(),
            Some(Some("class".to_string()))
        );
    }

    #[test]
    fn groovy_imports_and_definitions() {
        let src = b"package com.example\nimport java.util.List\nimport groovy.json.*\nclass Greeter {\n  def hello(name) { return \"hi\" }\n}\n";
        let (imports, functions) = parse_source("App.groovy", src);
        assert!(
            imports.iter().any(|s| s == "java.util.List"),
            "got {imports:?}"
        );
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"Greeter"), "got {names:?}");
    }

    #[test]
    fn zig_imports_and_definitions() {
        let src = b"const std = @import(\"std\");\nfn main() void {\n  std.debug.print(\"hi\\n\", .{});\n}\ntest \"smoke\" { try std.testing.expect(true); }\n";
        let (imports, functions) = parse_source("main.zig", src);
        assert!(imports.iter().any(|s| s == "std"), "got {imports:?}");
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
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
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
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
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.iter().any(|n| *n == "all" || *n == "build"),
            "got {names:?}"
        );
    }

    #[test]
    fn powershell_functions_extracted() {
        let src =
            b"function Get-Greeting {\n  param([string]$Name)\n  Write-Output \"Hi $Name\"\n}\n";
        let (_imports, functions) = parse_source("script.ps1", src);
        let names: Vec<&str> = functions.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"Get-Greeting"), "got {names:?}");
    }

    /// Python `def foo()` / `class Bar:` populate the unified
    /// [`crate::Symbols`] view with `decl: "function"` / `"class"`.
    #[test]
    fn python_functions_and_classes_populate_typed_view() {
        let src = b"def hello():\n    pass\n\nclass Greeter:\n    pass\n";
        let parsed = crate::open_with_path(std::path::Path::new("test.py"), src).unwrap();
        let _ = parsed.values();
        let functions: Vec<(&str, Option<&str>, &str)> = parsed
            .symbols()
            .iter_kind(crate::SymbolKind::Function)
            .filter_map(|s| match s {
                crate::Symbol::Function {
                    name, decl, source, ..
                } => Some((name.as_str(), decl.as_deref(), source.as_str())),
                _ => None,
            })
            .collect();
        let names: std::collections::HashMap<&str, Option<&str>> =
            functions.iter().map(|(n, d, _)| (*n, *d)).collect();
        assert_eq!(names.get("hello").copied(), Some(Some("function")));
        assert_eq!(names.get("Greeter").copied(), Some(Some("class")));
        for (_, _, src) in &functions {
            assert_eq!(*src, "python");
        }
    }
}
