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
mod batch_concat;
mod call_target_metrics;
mod comment_metrics;
mod escapes;
mod go_syntax;
mod payload_flow;
mod python_module_calls;
mod value_flow;
pub use payload_flow::go_package_payload_flow;
mod rust_syntax;

/// Decode the escape sequences a parsed source string literal carries, so a
/// consumer sees the text the program will actually use rather than the way the
/// source spelled it.
///
/// Re-exported from the crate root because cleave maintains its own AST
/// string-literal corpus — the one `type: literal` rules match against — and has
/// to land on the same value this crate reports from `cleave facts literals`.
/// When those two disagree, a rule author who checks the facts (as the rule
/// guide instructs) sees a string that no rule they write can match.
pub fn decode_source_escapes(literal: &str) -> String {
    escapes::decode(literal)
}
mod function_metrics;
mod identifier_metrics;
mod import_metrics;
mod langs;
pub(crate) mod parse;
mod string_metrics;
mod text_metrics;
mod visit;

use crate::metric;
use crate::value_key;
use std::cell::Cell;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use tree_sitter::{Node, Query, QueryCursor, StreamingIterator};

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{MetricKey, Metrics, Strings, Values};

use langs::{Lang, QueryKind};
use serde_json::Value as JsonValue;

pub(crate) use parse::{TreeCache, TreeParse, TreeSitterDiagnostic};

/// Recursion bound shared by the payload- and value-flow evaluators, which
/// recurse once per syntax level they descend.
const MAX_FLOW_DEPTH: usize = 96;

/// The named children of `node`, in order, read through one cursor rather
/// than collected.
fn named_children(node: Node<'_>) -> NamedChildren<'_> {
    NamedChildren {
        cursor: node.walk(),
        started: false,
    }
}

struct NamedChildren<'t> {
    cursor: tree_sitter::TreeCursor<'t>,
    started: bool,
}

impl<'t> Iterator for NamedChildren<'t> {
    type Item = Node<'t>;

    fn next(&mut self) -> Option<Node<'t>> {
        loop {
            let moved = if self.started {
                self.cursor.goto_next_sibling()
            } else {
                self.started = true;
                self.cursor.goto_first_child()
            };
            if !moved {
                // Parked on the last child, the next call fails again.
                return None;
            }
            let node = self.cursor.node();
            if node.is_named() {
                return Some(node);
            }
        }
    }
}

// Tree-sitter's query match limit bounds simultaneous in-progress matches,
// protecting against recursive/ambiguous query triggers. Allow ordinary
// large source files more headroom while retaining a finite ceiling.
const SOURCE_QUERY_MATCH_LIMIT: u32 = 100_000;
const SOURCE_QUERY_BYTE_LIMIT: usize = 2 * 1024 * 1024;
const SOURCE_QUERY_OUTPUT_LIMIT: usize = 10_000;

/// Work budget for one query, counted in progress polls. tree-sitter polls
/// the query progress callback once per 100 cursor steps
/// (`OP_COUNT_PER_QUERY_CALLBACK_CHECK` in `query.c`), so the same tree always
/// stops at the same match, however loaded the machine is. The 250 ms
/// wall-clock budget this replaced fired on ordinary large files under load,
/// and the content-keyed disk cache then kept the truncated symbols.
///
/// Fixed rather than scaled: [`SOURCE_QUERY_BYTE_LIMIT`] already bounds how
/// much tree a query walks. The heaviest query over about 68k real source
/// files and generated 1–30 MiB sources took 40.6k polls (a minified bundle),
/// an eighth of this budget.
const SOURCE_QUERY_WORK_BUDGET: u64 = 500_000;

/// Deepest node at which a query pattern may start matching. Cursor steps
/// cost more as nesting deepens: tree-sitter keeps a partial match open for
/// every enclosing node a pattern could still complete at, and revisits each
/// of them on every step, so the cost of a query grows with the square of the
/// depth. 20k nested arrow functions took 14.6 s on one query while using 8k
/// polls, and a 1M-link Ruby or Elixir method chain ran for more than ten
/// minutes. With this cap the cursor stops descending once no partial match
/// needs it, and those inputs take at most about 0.1 s per query, even on a
/// heavily loaded machine.
///
/// The deepest match in the calibration corpus started at depth 227 (error
/// recovery over concatenated Swift), under a tenth of the cap. Trees deeper
/// than the cap are already past `ast_walk::MAX_AST_DEPTH`, so they are
/// reported as `ast.depth_capped`.
const SOURCE_QUERY_MAX_START_DEPTH: u32 = 2_500;

/// Wall-clock backstop for one query, separate from the work budget, set so
/// ordinary files never reach it. Steps are not equally expensive: the
/// cursor walks up through hidden grammar nodes on every step, so a 30 MiB
/// generated byte table (one array, millions of elements) took 20 s of CPU
/// per query within its usual 27k polls. Real source took at most 0.4 s.
///
/// What it does stop is input where each step is expensive while the step
/// count stays small: wide trees nested just under
/// [`SOURCE_QUERY_MAX_START_DEPTH`], and deeply nested hidden nodes (100k
/// nested Perl parentheses ran for minutes per query). Whether those stop
/// can depend on load.
const SOURCE_QUERY_WALL_BACKSTOP: Duration = Duration::from_secs(60);

fn source_query_cursor() -> QueryCursor {
    let mut cursor = QueryCursor::new();
    cursor.set_match_limit(SOURCE_QUERY_MATCH_LIMIT);
    cursor.set_max_start_depth(Some(SOURCE_QUERY_MAX_START_DEPTH));
    cursor
}

#[cfg(test)]
thread_local! {
    /// Work budget override in progress polls; `0` means
    /// [`SOURCE_QUERY_WORK_BUDGET`]. Thread-local so one test's tiny budget
    /// cannot cut short a query in another test running in parallel.
    static QUERY_WORK_OVERRIDE: Cell<u64> = const { Cell::new(0) };
}

fn query_work_budget() -> u64 {
    #[cfg(test)]
    if let polls @ 1.. = QUERY_WORK_OVERRIDE.get() {
        return polls;
    }
    SOURCE_QUERY_WORK_BUDGET
}

/// Progress-callback state for one query: counts polls against the work
/// budget, with the wall-clock backstop behind it.
struct QueryBudget {
    polls: Cell<u64>,
    budget: u64,
    deadline: Instant,
    exhausted: Cell<bool>,
}

impl QueryBudget {
    fn new() -> Self {
        Self {
            polls: Cell::new(0),
            budget: query_work_budget(),
            deadline: Instant::now() + SOURCE_QUERY_WALL_BACKSTOP,
            exhausted: Cell::new(false),
        }
    }

    fn poll(&self) -> ControlFlow<()> {
        self.polls.set(self.polls.get() + 1);
        if self.polls.get() > self.budget || Instant::now() >= self.deadline {
            self.exhausted.set(true);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

// The dispatcher in `formats::extract` requires every format
// extractor to return `Result<(), Error>` even when the impl can't
// fail; uniformity is more valuable than removing one always-Ok arm.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn extract(
    bytes: &[u8],
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
        if let Ok(content) = std::str::from_utf8(bytes) {
            text_metrics::emit(content, metrics);
        }
        return Ok(());
    };
    let config = cache.config();
    let source = cache.source();
    let root = cache.tree().root_node();

    // Byte-level / line-level / whitespace text metrics — language-agnostic.
    text_metrics::emit(source, metrics);
    if config.lang == Lang::Batch {
        batch_concat::emit(source, metrics);
    }

    // One walk for every collector that only reads each node once.
    let mut walked = visit::Collectors {
        comments: Some(visit::Comments::default()),
        literals: Some(visit::Literals::default()),
        identifiers: Some(visit::Identifiers::default()),
        functions: Some(function_metrics::Collector::default()),
        ast: Some(ast_walk::State::default()),
        payload: payload_flow::Collector::new(source, config.lang),
    };
    visit::walk(root, source, config, &mut walked);
    // Comment metrics over the comment nodes the walk found; also fills the
    // comment-scoped string tier with their bodies.
    comment_metrics::emit(
        &walked.comments.take().unwrap_or_default().found,
        source,
        metrics,
        &mut strings.comments,
    );
    for literal in walked.literals.take().unwrap_or_default().found {
        strings.literals.push(literal);
    }
    // `build_symbols` emits the symbol walk's facts after extraction.
    if let Some(ast) = walked.ast.take() {
        cache.stash_ast_walk(ast);
    }
    let (mut imports, import_libraries) = config
        .query(QueryKind::Imports)
        .map(|query| collect_imports(query, source, root))
        .unwrap_or_default();
    if config.lang == Lang::Rust {
        imports.items = rust_syntax::imports(root, source);
    }
    let functions = config
        .query(QueryKind::Functions)
        .map(|query| collect_query(query, source, root))
        .unwrap_or_default();
    let classes = config
        .query(QueryKind::Classes)
        .map(|query| collect_query(query, source, root))
        .unwrap_or_default();
    emit_query_limit_metrics(metrics, "imports", &imports);
    emit_query_limit_metrics(metrics, "functions", &functions);
    emit_query_limit_metrics(metrics, "classes", &classes);

    // Identifier metrics — emit `identifiers.*`.
    let identifiers = walked.identifiers.take().unwrap_or_default().found;
    identifier_metrics::emit(&identifiers, metrics);

    // String-literal metrics — operate on the literals we already
    // extracted into the `strings` view.
    let literal_refs: Vec<&str> = strings.literals.iter().map(|s| s.value.as_str()).collect();
    string_metrics::emit(&literal_refs, metrics);

    // Import metrics — feed the canonical language name so stdlib
    // classification works.
    let import_refs: Vec<&str> = imports.items.iter().map(|(n, _)| n.as_str()).collect();
    import_metrics::emit(&import_refs, config.lang, metrics);

    // Function metrics over the function-definition nodes the walk found.
    let total_lines = crate::bytes::sat_u32(source.lines().count());
    let functions_total = function_metrics::emit(
        walked.functions.take().unwrap_or_default(),
        total_lines,
        metrics,
    );

    // Cross-component text ratios computed from the sub-metrics we just
    // emitted. Pure division — no extra parsing.
    emit_text_ratios(metrics, total_lines, functions_total, imports.items.len());

    // Push source-language imports / functions / classes into the
    // unified Symbols view. Python from-import members retain their owning
    // module, including its relative prefix. Module imports remain standalone
    // facts, preserving module-level matching alongside the member bindings.
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
            library: import_libraries.get(offset).cloned(),
            offset: Some(*offset),
            ordinal: None,
        });
    }
    if !functions.items.is_empty() {
        metrics.insert(
            metric!("source.function_count"),
            functions.items.len() as f64,
        );
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
        metrics.insert(metric!("source.class_count"), classes.items.len() as f64);
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

    values.insert_key(
        value_key!("source.language"),
        JsonValue::String(config.name().to_string()),
    );
    if config.lang == Lang::Python {
        python_module_calls::emit(root, source, values);
    }
    payload_flow::emit(
        root,
        source,
        config.lang,
        values,
        walked.payload.map(payload_flow::Collector::into_collected),
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
    let config = cache.config();
    let source = cache.source();
    let root = cache.tree().root_node();
    // Extraction normally collected the walk already.
    match cache.take_ast_walk() {
        Some(state) => ast_walk::finish(state, config, symbols_out, metrics),
        None => ast_walk::walk(root, source, config, symbols_out, metrics),
    }
    if config.lang == Lang::Rust {
        rust_syntax::resolve_calls(symbols_out);
    }
}

pub(crate) fn build_value_flow(cache: &TreeCache<'_>, symbols: &crate::Symbols) -> crate::Flow {
    value_flow::build(
        cache.tree().root_node(),
        cache.source(),
        cache.config(),
        symbols,
    )
}

/// The package clause of a parsed Go file, `""` when it has none, read from
/// the syntax tree alone. `None` for any other language.
pub(crate) fn go_package_name<'a>(ast: &crate::SourceAst<'a>) -> Option<&'a str> {
    (ast.file_type == FileType::Go)
        .then(|| go_syntax::package_name(ast.tree.root_node(), ast.source))
}

pub(super) fn looks_like_protocolless_url(value: &str) -> bool {
    if value.contains("://") || value.is_empty() {
        return false;
    }
    let Some((host, path)) = value.split_once('/') else {
        return false;
    };
    if host.is_empty() || path.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        || labels
            .last()
            .is_none_or(|tld| tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return false;
    }
    path.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '-' | '_' | '.' | '/' | '?' | '&' | '=' | '%' | '#')
    })
}

/// The value a quoted string literal denotes: any `b`/`r`/`f`/`u` prefix and
/// the quotes stripped, escapes decoded unless the literal is raw. Shared by
/// the literal tier, call arguments, subscript folding and value flow so all
/// of them agree on what `f"…"` or `b'…'` holds.
///
/// `None` when the node is not a complete quoted literal: an unterminated
/// one, or an unquoted form such as a heredoc body, Perl `q{…}` or Lua
/// `[[…]]`, whose text callers treat as they see fit.
fn decode_string_literal(
    node: Node<'_>,
    source: &str,
    config: &langs::LangConfig,
) -> Option<String> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    if config.lang == Lang::Elixir && (raw.starts_with("\"\"\"") || raw.starts_with("'''")) {
        return escapes::decode_elixir_heredoc(raw);
    }
    let quoted = raw.trim_start_matches(is_string_prefix);
    let prefix = &raw[..raw.len() - quoted.len()];
    let open = quoted
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\'' | '`'))?;
    let body = quoted[1..].strip_suffix(open)?;
    // A raw literal (Python `r"..."`, Rust `r#"..."#`, Go backticks) carries
    // the backslash as data, so decoding it would corrupt the value.
    let raw_literal = prefix.contains(['r', 'R'])
        || node.kind().contains("raw")
        || node.kind().contains("verbatim");
    if raw_literal {
        return Some(body.to_string());
    }
    Some(escapes::decode(body))
}

/// Source text of a string-kind node that has no opening quote at all, which
/// [`decode_string_literal`] leaves to its caller.
fn unquoted_literal<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    let first = raw.trim_start_matches(is_string_prefix).chars().next()?;
    (!matches!(first, '"' | '\'' | '`')).then_some(raw)
}

fn is_string_prefix(c: char) -> bool {
    matches!(c, 'b' | 'B' | 'r' | 'R' | 'f' | 'F' | 'u' | 'U')
}

#[derive(Default)]
struct QueryCollection {
    items: Vec<(String, u64)>,
    /// The work budget ran out, or the wall-clock backstop fired. Reported
    /// under the historical `timeout` name ([`crate::QueryLimit::Timeout`]).
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
    metrics.insert(metric!("source.query_limited"), 1.0);
    metrics.insert(
        crate::source_query_limited(label, crate::QueryLimit::Any),
        1.0,
    );
    if result.timed_out {
        metrics.insert(
            crate::source_query_limited(label, crate::QueryLimit::Timeout),
            1.0,
        );
    }
    if result.match_limited {
        metrics.insert(
            crate::source_query_limited(label, crate::QueryLimit::Match),
            1.0,
        );
    }
    if result.output_limited {
        metrics.insert(
            crate::source_query_limited(label, crate::QueryLimit::Output),
            1.0,
        );
    }
}

fn collect_query(query: &Query, source: &str, root: Node<'_>) -> QueryCollection {
    let capture_names = query.capture_names();
    let mut cursor = source_query_cursor();
    cursor.set_byte_range(0..source.len().min(SOURCE_QUERY_BYTE_LIMIT));
    // De-duplicate by name, keeping the first (smallest) offset for
    // each. A repeated `import os` shows up once; the offset points
    // at its first occurrence, which is the most useful answer for
    // proximity-style matchers.
    let mut seen: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let budget = QueryBudget::new();
    let output_limited = Cell::new(false);
    let mut progress_cb = |_: &tree_sitter::QueryCursorState| budget.poll();
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    {
        let mut matches = cursor.matches_with_options(query, root, source.as_bytes(), options);
        while let Some(m) = matches.next() {
            for cap in m.captures() {
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
        timed_out: budget.exhausted.get(),
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
    query: &Query,
    source: &str,
    root: Node<'_>,
) -> (QueryCollection, std::collections::HashMap<u64, String>) {
    let capture_names = query.capture_names();
    let mut cursor = source_query_cursor();
    cursor.set_byte_range(0..source.len().min(SOURCE_QUERY_BYTE_LIMIT));
    // Keep equal member names from distinct modules separate.
    let mut seen = std::collections::BTreeMap::new();
    let mut libraries = std::collections::HashMap::new();
    let budget = QueryBudget::new();
    let output_limited = Cell::new(false);
    let mut progress_cb = |_: &tree_sitter::QueryCursorState| budget.poll();
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    {
        let mut matches = cursor.matches_with_options(query, root, source.as_bytes(), options);
        while let Some(m) = matches.next() {
            for cap in m.captures() {
                let name = capture_names.get(cap.index as usize).copied().unwrap_or("");
                if name.starts_with('_') {
                    continue;
                }
                if let Ok(text) = cap.node.utf8_text(source.as_bytes()) {
                    let cleaned = strip_quotes(text);
                    if cleaned.is_empty() {
                        continue;
                    }
                    // Read alias fields structurally: Python permits tabs,
                    // repeated spaces and line continuations around `as`.
                    let cleaned = if cap.node.kind() == "aliased_import" {
                        match (
                            cap.node.child_by_field_name("name"),
                            cap.node.child_by_field_name("alias"),
                        ) {
                            (Some(module), Some(alias)) => format!(
                                "{} as {}",
                                module.utf8_text(source.as_bytes()).unwrap_or("").trim(),
                                alias.utf8_text(source.as_bytes()).unwrap_or("").trim()
                            ),
                            _ => cleaned,
                        }
                    } else {
                        cleaned
                    };
                    let qualified = qualify_relative_member(cap.node, cleaned, source);
                    let offset = cap.node.start_byte() as u64;
                    let library = python_import_library(cap.node, source);
                    if let Some(library) = &library {
                        libraries.insert(offset, library.clone());
                    }
                    seen.entry((qualified, library)).or_insert(offset);
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
    (
        QueryCollection {
            items: seen
                .into_iter()
                .map(|((name, _), offset)| (name, offset))
                .collect(),
            timed_out: budget.exhausted.get(),
            match_limited: cursor.did_exceed_match_limit(),
            output_limited: output_limited.get(),
        },
        libraries,
    )
}

/// The owner of a Python from-import member, never the module capture itself.
fn python_import_library(node: Node<'_>, source: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "import_from_statement" {
        return None;
    }
    let module = parent.child_by_field_name("module_name")?;
    if module.id() == node.id() {
        return None;
    }
    Some(module.utf8_text(source.as_bytes()).ok()?.trim().to_string())
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
    if let [first, inner @ .., last] = s.as_bytes()
        && first == last
        && matches!(first, b'"' | b'\'' | b'`')
    {
        return std::str::from_utf8(inner).unwrap_or(s).to_string();
    }
    s.to_string()
}

/// True when this file type is a source language filefacts can parse.
pub(crate) fn supports(file_type: FileType) -> bool {
    langs::config_for(file_type).is_some()
}

/// Resolve `file_type` to its tree-sitter [`Language`](tree_sitter::Language). Used by callers
/// that want to compile a tree-sitter query against the same grammar
/// filefacts uses internally — e.g. rule-engine load-time validation.
pub(crate) fn tree_sitter_language(file_type: FileType) -> Option<tree_sitter::Language> {
    langs::config_for(file_type).map(|config| (config.language)())
}

/// The file type of the language labelled `name`, the value published under
/// `values.source.language` (e.g. `"python"`, `"bash"`, `"objc"`).
pub(crate) fn file_type_for_language(name: &str) -> Option<FileType> {
    langs::file_type_named(name)
}

/// Emit text-level metrics (`text.*`) without a tree-sitter parse.
///
/// Called from the format dispatcher for text-like languages that
/// don't yet have a [`LangConfig`](langs::LangConfig) entry (Vbs, Batch, …). Only emits
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
fn emit_text_ratios(
    metrics: &mut Metrics,
    total_lines: u32,
    functions_total: usize,
    imports_total: usize,
) {
    let m = metrics.clone();
    let get = |key: MetricKey| m.get_key(&key).unwrap_or(0.0);

    // Counted by the caller: `functions.count` / `imports.count` are only
    // emitted later, from the unified symbols view.
    let functions_total = functions_total as f64;
    let strings_total = get(metric!("strings.count"));
    let identifiers_total = get(metric!("identifiers.count"));
    let identifiers_unique = get(metric!("identifiers.unique"));
    let imports_total = imports_total as f64;
    let functions_anonymous = get(metric!("functions.anonymous"));

    if functions_total > 0.0 {
        metrics.insert(
            metric!("text.strings_to_functions_ratio"),
            strings_total / functions_total,
        );
        metrics.insert(
            metric!("text.identifiers_to_functions_ratio"),
            identifiers_unique / functions_total,
        );
        if imports_total > 0.0 {
            metrics.insert(
                metric!("text.imports_to_functions_ratio"),
                imports_total / functions_total,
            );
        }
        if functions_anonymous > 0.0 {
            metrics.insert(
                metric!("text.anonymous_function_ratio"),
                functions_anonymous / functions_total,
            );
        }
    }

    if total_lines > 0 {
        let lines_f = f64::from(total_lines);
        if identifiers_total > 0.0 {
            metrics.insert(
                metric!("text.identifier_density"),
                identifiers_total / lines_f,
            );
        }
        if strings_total > 0.0 {
            metrics.insert(metric!("text.string_density"), strings_total / lines_f);
        }
        if imports_total > 0.0 {
            metrics.insert(
                metric!("text.import_density"),
                (imports_total * 100.0) / lines_f,
            );
        }
        let lines_sqrt = lines_f.sqrt();
        if lines_sqrt > 0.0 {
            if functions_total > 0.0 {
                metrics.insert(
                    metric!("text.normalized_function_count"),
                    functions_total / lines_sqrt,
                );
            }
            if imports_total > 0.0 {
                metrics.insert(
                    metric!("text.normalized_import_count"),
                    imports_total / lines_sqrt,
                );
            }
            if strings_total > 0.0 {
                metrics.insert(
                    metric!("text.normalized_string_count"),
                    strings_total / lines_sqrt,
                );
            }
        }
        let lines_log = lines_f.log2();
        if lines_log > 0.0 && identifiers_unique > 0.0 {
            metrics.insert(
                metric!("text.normalized_unique_identifiers"),
                identifiers_unique / lines_log,
            );
        }
    }

    // Obfuscation indicator ratios.
    if identifiers_unique > 0.0 {
        let suspicious = get(metric!("identifiers.hex_like_names"))
            + get(metric!("identifiers.base64_like_names"))
            + get(metric!("identifiers.sequential_names"))
            + get(metric!("identifiers.keyboard_pattern_names"))
            + get(metric!("identifiers.repeated_char_names"));
        if suspicious > 0.0 {
            metrics.insert(
                metric!("text.suspicious_identifier_ratio"),
                suspicious / identifiers_unique,
            );
        }
    }

    if strings_total > 0.0 {
        let encoded = get(metric!("strings.base64_candidates"))
            + get(metric!("strings.hex"))
            + get(metric!("strings.url_encoded"));
        if encoded > 0.0 {
            metrics.insert(
                metric!("text.encoded_string_ratio"),
                encoded / strings_total,
            );
        }
        let suspicious = get(metric!("strings.embedded_code_candidates"))
            + get(metric!("strings.shell"))
            + get(metric!("strings.sql"));
        if suspicious > 0.0 {
            metrics.insert(
                metric!("text.suspicious_string_ratio"),
                suspicious / strings_total,
            );
        }
    }

    let comments_total = get(metric!("comments.count"));
    if comments_total > 0.0 {
        let suspicious = get(metric!("comments.high_entropy")) + get(metric!("comments.base64"));
        if suspicious > 0.0 {
            metrics.insert(
                metric!("text.suspicious_comment_ratio"),
                suspicious / comments_total,
            );
        }
    }

    if imports_total > 0.0 {
        let dynamic = get(metric!("imports.dynamic"));
        if dynamic > 0.0 {
            metrics.insert(
                metric!("text.dynamic_import_ratio"),
                dynamic / imports_total,
            );
        }
    }
}

#[cfg(test)]
mod tests;

// Shared byte-preserving AST source view for downstream query engines.
pub(crate) use parse::utf8_source;
