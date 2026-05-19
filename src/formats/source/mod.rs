//! Source-code extractors.
//!
//! Source files are parsed once with tree-sitter. The resulting tree
//! is cached on the [`ParsedFile`] and shared by every view that needs
//! it: `values` reads imports / functions / classes, `strings` reads
//! literal nodes, `metrics` reads the node count, `ast` reads the
//! call-graph projection. No view ever causes a re-parse.
//!
//! [`ParsedFile`]: crate::ParsedFile

mod ast_walk;
mod langs;
pub(crate) mod parse;

use tree_sitter::{Node, QueryCursor, StreamingIterator};

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ExtractedString, Metrics, StringCategory, Strings, Values};

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
    imports_out: &mut crate::Imports,
    functions_out: &mut crate::Functions,
) -> Result<(), Error> {
    let Some(cache) = tree_cache else {
        return Ok(());
    };
    let config = langs::config_for(cache.file_type())
        .expect("tree_cache implies config_for is Some");
    let source = cache.source();
    let root = cache.tree().root_node();

    extract_strings(root, source, config, strings, metrics);
    let imports = collect_query(config.language, source, root, config.import_query);
    let functions = collect_query(config.language, source, root, config.function_query);
    let classes = collect_query(config.language, source, root, config.class_query);

    if !imports.is_empty() {
        // Mirror into the typed Imports view with byte offsets from
        // tree-sitter. `library` stays unset — source-language imports
        // are module-scoped strings, not library-tagged. Source tag is
        // the language name (`"javascript"`, `"python"`, `"go"`, …) so
        // trait matchers can filter by language without consulting
        // file_type. See expose/src/output/symbols.rs for the
        // source-tag taxonomy.
        for (name, offset) in &imports {
            imports_out.push(crate::Import {
                name: name.clone(),
                library: None,
                source: config.name,
                offset: Some(*offset),
                ordinal: None,
            });
        }
        values.insert(
            "imports",
            JsonValue::Array(
                imports
                    .iter()
                    .map(|(n, _)| JsonValue::String(n.clone()))
                    .collect(),
            ),
        );
    }
    if !functions.is_empty() {
        metrics.insert("source.function_count", functions.len() as f64);
        for (name, offset) in &functions {
            functions_out.push(crate::Function {
                name: name.clone(),
                source: config.name,
                offset: Some(*offset),
                kind: Some("function"),
            });
        }
        values.insert(
            "functions",
            JsonValue::Array(
                functions
                    .iter()
                    .map(|(n, _)| JsonValue::String(n.clone()))
                    .collect(),
            ),
        );
    }
    if !classes.is_empty() {
        metrics.insert("source.class_count", classes.len() as f64);
        // Class declarations also surface as `Function` records
        // tagged `kind: "class"` — the symbol axis is "things
        // declared here", regardless of whether they're a function
        // or a class. Consumers that need the distinction read the
        // kind field; consumers that just want "is name X declared
        // here?" iterate one collection.
        for (name, offset) in &classes {
            functions_out.push(crate::Function {
                name: name.clone(),
                source: config.name,
                offset: Some(*offset),
                kind: Some("class"),
            });
        }
        values.insert(
            "classes",
            JsonValue::Array(
                classes
                    .iter()
                    .map(|(n, _)| JsonValue::String(n.clone()))
                    .collect(),
            ),
        );
    }

    values.insert(
        "source.language",
        JsonValue::String(config.name.to_string()),
    );

    Ok(())
}

/// Single-pass AST projection. Always returns a fully-built `Ast` —
/// empty when the tree has no calls or member chains, never absent.
pub(crate) fn build_ast(
    cache: &TreeCache,
    metrics: &mut Metrics,
) -> crate::output::Ast {
    let config = langs::config_for(cache.file_type())
        .expect("tree_cache implies config_for is Some");
    let source = cache.source();
    let root = cache.tree().root_node();
    ast_walk::walk(root, source, config, metrics)
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
                    category: StringCategory::Literal,
                    text,
                    offset: node.start_byte(),
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
    std::str::from_utf8(&bytes[start..end]).ok().map(str::to_string)
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
    let mut seen: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut matches = cursor.matches(&query, root, source.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            let name = capture_names
                .get(cap.index as usize)
                .copied()
                .unwrap_or("");
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

/// True when this file type is a source language expose can parse.
pub(crate) fn supports(file_type: FileType) -> bool {
    langs::config_for(file_type).is_some()
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
    /// typed `Imports` view with the language name as `source` and
    /// a non-zero byte offset.
    #[test]
    fn python_imports_populate_typed_view() {
        let src = b"import os\nfrom sys import path\nimport hashlib\n";
        // open_with_path so fileid classifies as Python via the
        // `.py` extension hint — without it the bytes look like
        // plain text and the source extractor never runs.
        let parsed = crate::open_with_path(
            std::path::Path::new("test.py"),
            src,
        )
        .unwrap();
        let _ = parsed.values();
        let imports = parsed.imports();
        assert!(!imports.is_empty(), "expected python imports to populate typed view");
        let names: std::collections::HashSet<&str> =
            imports.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains("os"), "got names {names:?}");
        assert!(names.contains("hashlib"));
        for imp in imports.iter() {
            assert_eq!(imp.source, "python");
            assert!(imp.library.is_none());
            assert!(imp.offset.is_some());
        }
    }

    /// Python `def foo()` / `class Bar:` populate the typed
    /// `Functions` view with `kind: "function"` / `"class"`.
    #[test]
    fn python_functions_and_classes_populate_typed_view() {
        let src = b"def hello():\n    pass\n\nclass Greeter:\n    pass\n";
        let parsed = crate::open_with_path(
            std::path::Path::new("test.py"),
            src,
        )
        .unwrap();
        let _ = parsed.values();
        let functions = parsed.functions();
        let names: std::collections::HashMap<&str, Option<&str>> = functions
            .iter()
            .map(|f| (f.name.as_str(), f.kind))
            .collect();
        assert_eq!(names.get("hello").copied(), Some(Some("function")));
        assert_eq!(names.get("Greeter").copied(), Some(Some("class")));
        for f in functions.iter() {
            assert_eq!(f.source, "python");
        }
    }
}
