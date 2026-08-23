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
mod call_target_metrics;
mod comment_metrics;
mod function_metrics;
mod identifier_metrics;
mod import_metrics;
mod langs;
pub(crate) mod parse;
mod string_metrics;
mod text_metrics;

use std::cell::Cell;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use tree_sitter::{Node, QueryCursor, StreamingIterator};

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ExtractedString, Metrics, Strings, Values};

use serde_json::Value as JsonValue;

pub(crate) use parse::{TreeCache, TreeParse, TreeSitterDiagnostic};

const SOURCE_QUERY_MATCH_LIMIT: u32 = 50_000;
const SOURCE_QUERY_BYTE_LIMIT: usize = 2 * 1024 * 1024;
const SOURCE_QUERY_WALL_BUDGET: Duration = Duration::from_millis(250);
const SOURCE_QUERY_OUTPUT_LIMIT: usize = 10_000;

fn source_query_wall_budget() -> Duration {
    if cfg!(test) {
        Duration::from_secs(5)
    } else {
        SOURCE_QUERY_WALL_BUDGET
    }
}

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

    // Comment metrics use the language's comment style; no AST. Also
    // collects comment bodies into the comment-scoped string tier.
    comment_metrics::emit(source, config.comment_style, metrics, &mut strings.comments);

    extract_strings(root, source, config, strings);
    let imports = collect_imports(config.language, source, root, config.import_query);
    let functions = collect_query(config.language, source, root, config.function_query);
    let classes = collect_query(config.language, source, root, config.class_query);
    emit_query_limit_metrics(metrics, "imports", &imports);
    emit_query_limit_metrics(metrics, "functions", &functions);
    emit_query_limit_metrics(metrics, "classes", &classes);

    // Identifier metrics — walk the tree once, emit `identifiers.*`.
    let identifiers = identifier_metrics::collect_identifiers(root, source, config);
    identifier_metrics::emit(&identifiers, metrics);

    // String-literal metrics — operate on the literals we already
    // extracted into the `strings` view.
    let literal_refs: Vec<&str> = strings.literals.iter().map(|s| s.text.as_str()).collect();
    string_metrics::emit(&literal_refs, metrics);

    // Import metrics — feed the canonical language name so stdlib
    // classification works.
    let import_refs: Vec<&str> = imports.items.iter().map(|(n, _)| n.as_str()).collect();
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
    for (name, offset) in &imports.items {
        // Source-language aliased imports arrive as `module as local` (the raw
        // `aliased_import` node text). Split so the symbol name is the bare
        // module and the alias is a structured field — no whitespace in the
        // symbol, and trait authors can match the alias directly.
        let (bare, alias) = match name.split_once(" as ") {
            Some((module, local)) => (module.trim().to_string(), Some(local.trim().to_string())),
            None => (name.clone(), None),
        };
        symbols_out.push(crate::Symbol::Import {
            name: bare,
            alias,
            library: None,
            offset: Some(*offset),
            ordinal: None,
        });
    }
    if !functions.items.is_empty() {
        metrics.insert("source.function_count", functions.items.len() as f64);
    }
    for (name, offset) in &functions.items {
        symbols_out.push(crate::Symbol::Function {
            name: name.clone(),
            offset: Some(*offset),
            complexity: None,
            callees: Vec::new(),
        });
    }
    if !classes.items.is_empty() {
        metrics.insert("source.class_count", classes.items.len() as f64);
    }
    // Class declarations surface as `Symbol::Function` too — the symbol
    // axis is "things declared here", regardless of function vs class.
    for (name, offset) in &classes.items {
        symbols_out.push(crate::Symbol::Function {
            name: name.clone(),
            offset: Some(*offset),
            complexity: None,
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
) {
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
            }
            continue;
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
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

/// Compile-once cache for tree-sitter queries. `Query::new` is non-trivial
/// (parses the S-expression and builds matcher state) and was re-run for all
/// three queries on *every* source file; the compiled `Query` is immutable and
/// reusable, so we build each (language, query) once and share it. Keyed by the
/// language function pointer and the `&'static` query-source pointer — both are
/// stable per query, so identical queries hit the cache without re-parsing.
fn cached_query(
    language_fn: fn() -> tree_sitter::Language,
    query_src: &'static str,
) -> Option<std::sync::Arc<tree_sitter::Query>> {
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, RwLock};
    static CACHE: LazyLock<RwLock<HashMap<(usize, usize), Option<Arc<tree_sitter::Query>>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
    let key = (language_fn as usize, query_src.as_ptr() as usize);
    if let Ok(cache) = CACHE.read()
        && let Some(entry) = cache.get(&key)
    {
        return entry.clone();
    }
    let compiled = tree_sitter::Query::new(&language_fn(), query_src)
        .ok()
        .map(Arc::new);
    if let Ok(mut cache) = CACHE.write() {
        return cache.entry(key).or_insert(compiled).clone();
    }
    compiled
}

#[derive(Default)]
struct QueryCollection {
    items: Vec<(String, u64)>,
    timed_out: bool,
    match_limited: bool,
    output_limited: bool,
}

impl QueryCollection {
    fn limited(&self) -> bool {
        self.timed_out || self.match_limited || self.output_limited
    }
}

fn emit_query_limit_metrics(metrics: &mut Metrics, label: &str, result: &QueryCollection) {
    if !result.limited() {
        return;
    }
    metrics.insert("source.query_limited", 1.0);
    metrics.insert(format!("source.query_limited.{label}"), 1.0);
    if result.timed_out {
        metrics.insert(format!("source.query_limited.{label}.timeout"), 1.0);
    }
    if result.match_limited {
        metrics.insert(format!("source.query_limited.{label}.match_limit"), 1.0);
    }
    if result.output_limited {
        metrics.insert(format!("source.query_limited.{label}.output_limit"), 1.0);
    }
}

fn collect_query(
    language_fn: fn() -> tree_sitter::Language,
    source: &str,
    root: Node<'_>,
    query_src: &'static str,
) -> QueryCollection {
    if query_src.is_empty() {
        return QueryCollection::default();
    }
    let Some(query) = cached_query(language_fn, query_src) else {
        return QueryCollection::default();
    };
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    cursor.set_match_limit(SOURCE_QUERY_MATCH_LIMIT);
    cursor.set_byte_range(0..source.len().min(SOURCE_QUERY_BYTE_LIMIT));
    // De-duplicate by name, keeping the first (smallest) offset for
    // each. A repeated `import os` shows up once; the offset points
    // at its first occurrence, which is the most useful answer for
    // proximity-style matchers.
    let mut seen: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let query_start = Instant::now();
    let timed_out = Cell::new(false);
    let output_limited = Cell::new(false);
    let mut progress_cb = |_state: &tree_sitter::QueryCursorState| -> ControlFlow<()> {
        if query_start.elapsed() > source_query_wall_budget() {
            timed_out.set(true);
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    {
        let mut matches = cursor.matches_with_options(&query, root, source.as_bytes(), options);
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
                    if seen.len() >= SOURCE_QUERY_OUTPUT_LIMIT {
                        output_limited.set(true);
                        break;
                    }
                }
            }
            if output_limited.get() {
                break;
            }
        }
    }
    QueryCollection {
        items: seen.into_iter().collect(),
        timed_out: timed_out.get(),
        match_limited: cursor.did_exceed_match_limit(),
        output_limited: output_limited.get(),
    }
}

/// Collect import symbols, qualifying Python relative-import members with
/// their relative module prefix.
///
/// Tree-sitter records `from .pkg import name` as two separate captures: the
/// relative module (`.pkg`) and the imported member (`name`). The bare member
/// is indistinguishable from a top-level `import name`, so `from . import
/// requests` would otherwise masquerade as an import of the PyPI `requests`
/// library. Rejoining the member to its relative module (`.requests`,
/// `.pkg.requests`) keeps the symbol relative-prefixed: it counts as a
/// relative import and no library matcher anchored on `^name` matches a local
/// submodule. Non-relative imports and other languages pass through unchanged.
fn collect_imports(
    language_fn: fn() -> tree_sitter::Language,
    source: &str,
    root: Node<'_>,
    query_src: &'static str,
) -> QueryCollection {
    if query_src.is_empty() {
        return QueryCollection::default();
    }
    let Some(query) = cached_query(language_fn, query_src) else {
        return QueryCollection::default();
    };
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    cursor.set_match_limit(SOURCE_QUERY_MATCH_LIMIT);
    cursor.set_byte_range(0..source.len().min(SOURCE_QUERY_BYTE_LIMIT));
    let mut seen: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let query_start = Instant::now();
    let timed_out = Cell::new(false);
    let output_limited = Cell::new(false);
    let mut progress_cb = |_state: &tree_sitter::QueryCursorState| -> ControlFlow<()> {
        if query_start.elapsed() > source_query_wall_budget() {
            timed_out.set(true);
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    {
        let mut matches = cursor.matches_with_options(&query, root, source.as_bytes(), options);
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
                    let qualified = qualify_relative_member(cap.node, cleaned, source);
                    let offset = cap.node.start_byte() as u64;
                    seen.entry(qualified).or_insert(offset);
                    if seen.len() >= SOURCE_QUERY_OUTPUT_LIMIT {
                        output_limited.set(true);
                        break;
                    }
                }
            }
            if output_limited.get() {
                break;
            }
        }
    }
    QueryCollection {
        items: seen.into_iter().collect(),
        timed_out: timed_out.get(),
        match_limited: cursor.did_exceed_match_limit(),
        output_limited: output_limited.get(),
    }
}

/// When `node` is the imported-member field of a Python relative
/// `import_from_statement` (`from .pkg import member`), return the member
/// joined to its relative module prefix (`.pkg.member`); otherwise return
/// `cleaned` unchanged. The relative module node itself already starts with
/// `.`, so it is left as-is, and absolute imports (`from os import path`) are
/// untouched because their `module_name` is a `dotted_name`, not a
/// `relative_import`.
fn qualify_relative_member(node: Node<'_>, cleaned: String, source: &str) -> String {
    if cleaned.starts_with('.') {
        return cleaned;
    }
    let Some(parent) = node.parent() else {
        return cleaned;
    };
    if parent.kind() != "import_from_statement" {
        return cleaned;
    }
    let Some(module) = parent.child_by_field_name("module_name") else {
        return cleaned;
    };
    if module.kind() != "relative_import" {
        return cleaned;
    }
    let Ok(prefix) = module.utf8_text(source.as_bytes()) else {
        return cleaned;
    };
    let prefix = prefix.trim();
    // `.`/`..` end in a dot already; `.pkg` needs a joining dot.
    if prefix.ends_with('.') {
        format!("{prefix}{cleaned}")
    } else {
        format!("{prefix}.{cleaned}")
    }
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
    let strings_total = get("strings.count");
    let identifiers_total = get("identifiers.count");
    let identifiers_unique = get("identifiers.unique");
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
            + get("strings.hex")
            + get("strings.url_encoded");
        if encoded > 0.0 {
            metrics.insert("text.encoded_string_ratio", encoded / strings_total);
        }
        let suspicious = get("strings.embedded_code_candidates")
            + get("strings.shell")
            + get("strings.sql");
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

    let comments_total = get("comments.count");
    if comments_total > 0.0 {
        let suspicious = get("comments.high_entropy") + get("comments.base64");
        if suspicious > 0.0 {
            metrics.insert("text.suspicious_comment_ratio", suspicious / comments_total);
        }
    }

    if imports_total > 0.0 {
        let dynamic = get("imports.dynamic") + get("imports.conditional_imports");
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
        let result = collect_query(
            javascript_language,
            &src,
            tree.root_node(),
            "(identifier) @name",
        );

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
        for (_, lib, has_offset) in &imports {
            assert!(lib.is_none());
            assert!(*has_offset);
        }
    }

    /// Python relative imports (`from . import requests`) must carry their
    /// relative prefix so a local submodule named `requests` is not recorded
    /// as an import of the PyPI `requests` library. Absolute imports of the
    /// same name stay bare.
    #[test]
    fn python_relative_import_member_keeps_prefix() {
        let src = b"from . import requests\nfrom .graph import responses\nimport os\n";
        let parsed = crate::open_with_path(std::path::Path::new("rel.py"), src).unwrap();
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

    /// Helper: parse `src` as a source file with the given extension
    /// and return the import names + (function name, decl) pairs from
    /// the unified [`crate::Symbols`] view. Asserts the file classified
    /// to a non-text-only source extractor (i.e. `text.*` metrics
    /// fired) so callers can focus on language-specific structural facts.
    fn parse_source(name: &str, src: &[u8]) -> (Vec<String>, Vec<String>) {
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
        let src =
            b"function Get-Greeting {\n  param([string]$Name)\n  Write-Output \"Hi $Name\"\n}\n";
        let (_imports, functions) = parse_source("script.ps1", src);
        let names: Vec<&str> = functions.iter().map(String::as_str).collect();
        assert!(names.contains(&"Get-Greeting"), "got {names:?}");
    }

    /// Python `def foo()` / `class Bar:` populate the unified
    /// [`crate::Symbols`] view with `decl: "function"` / `"class"`.
    #[test]
    fn python_functions_and_classes_populate_typed_view() {
        let src = b"def hello():\n    pass\n\nclass Greeter:\n    pass\n";
        let parsed = crate::open_with_path(std::path::Path::new("test.py"), src).unwrap();
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
                let parsed = crate::open_with_path(std::path::Path::new("deep.js"), src.as_bytes())
                    .expect("parse deep js");
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
                let parsed = crate::open_with_path(std::path::Path::new(&path), src.as_bytes())
                    .expect("parse deep source");
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
        let parsed = crate::open_with_path(std::path::Path::new("o.js"), src.as_bytes())
            .expect("parse obfuscated js");
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
}
