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
mod batch_commands;
mod batch_concat;
mod batch_cycles;
mod batch_lines;
mod call_target_metrics;
mod comment_metrics;
mod data_only;
pub(crate) mod embedded_sources;
mod escapes;
mod function_metrics;
pub(crate) mod go_syntax;
mod identifier_metrics;
mod import_metrics;
mod langs;
mod literal;
pub(crate) mod parse;
mod payload_flow;
mod python_module_calls;
mod runtime_imports;
mod rust_syntax;
mod scope;
mod shell_fifo;
mod string_metrics;
mod text_metrics;
mod value_flow;
mod visit;

pub use payload_flow::go_package_payload_flow;
pub(crate) use payload_flow::{Budget, GoMember, package_flow};

/// Decode the escape sequences of a parsed short-string body by the rules
/// of `file_type`'s language, so a consumer sees the text the program will
/// actually use rather than the way the source spelled it. Lua's decimal
/// byte escapes differ from the C and Python forms every other language
/// shares.
///
/// Public so a consumer that builds its own literal corpus from the syntax
/// tree lands on the same values this crate reports in the literal tier; if
/// the two disagree, a rule written against the reported facts cannot match.
pub fn decode_source_escapes_for_type(literal: &str, file_type: crate::FileType) -> String {
    if file_type == crate::FileType::Lua {
        escapes::decode_lua(literal)
    } else {
        escapes::decode(literal)
    }
}

use crate::metric;
use crate::value_key;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use tree_sitter::{Node, Query, QueryCursor, StreamingIterator};

use crate::fileid::FileType;
use crate::output::{MetricKey, Metrics, Strings, Values};

use langs::{Lang, QueryKind};
use literal::{decode_string_literal, unquoted_literal};
use serde_json::Value as JsonValue;

pub(crate) use parse::{TreeCache, TreeParse, TreeSitterDiagnostic};

/// Recursion bound shared by the payload- and value-flow evaluators, which
/// recurse once per syntax level they descend.
const MAX_FLOW_DEPTH: usize = 96;

/// Longest import path an alias expands to. The flow analyses and Rust call
/// resolution copy the path into every name read through the alias, so one
/// long path named by many short references would multiply; real import
/// paths are a few dozen bytes.
const MAX_ALIAS_BYTES: usize = 512;

/// `name` with its first segment (up to `.`, `:` or `(`) replaced by the
/// import path `alias` resolves it to; `None` when it resolves none. An empty
/// path marks conflicting imports and resolves nothing, and one longer than
/// [`MAX_ALIAS_BYTES`] is not expanded.
fn expand_alias<'a>(name: &str, alias: impl FnOnce(&str) -> Option<&'a str>) -> Option<String> {
    let end = name.find(['.', ':', '(']).unwrap_or(name.len());
    let prefix = alias(&name[..end])
        .filter(|prefix| !prefix.is_empty() && prefix.len() <= MAX_ALIAS_BYTES)?;
    Some(format!("{prefix}{}", &name[end..]))
}

/// The source text `node` spans. Empty when the range does not fall on
/// character boundaries of `source`, which a tree parsed from it never does.
fn text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    source.get(node.byte_range()).unwrap_or("")
}

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
/// the query progress callback after 1,000 work units, charging each cursor
/// step for itself and its in-progress matches
/// (`WORK_PER_QUERY_CALLBACK_CHECK` in `query.c`), so the same tree always
/// stops at the same match, however loaded the machine is. A wall-clock
/// budget would cut ordinary large files short under load, and the
/// content-keyed disk cache would then keep the truncated symbols.
///
/// Fixed rather than scaled: [`SOURCE_QUERY_BYTE_LIMIT`] already bounds how
/// much tree a query walks. Ordinary large-file queries must fit in a tenth
/// of this budget; the calibration test checks that against the current
/// tree-sitter work accounting.
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
        #[cfg(test)]
        let budget = match QUERY_WORK_OVERRIDE.get() {
            0 => SOURCE_QUERY_WORK_BUDGET,
            polls => polls,
        };
        #[cfg(not(test))]
        let budget = SOURCE_QUERY_WORK_BUDGET;
        Self {
            polls: Cell::new(0),
            budget,
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

/// Extract a source file's facts from its one parse: text, comment, string,
/// identifier, import and function metrics, the literal and comment string
/// tiers, symbols, and the per-language relation facts. Without a parse only
/// the text metrics remain.
pub(super) fn extract(
    bytes: &[u8],
    tree_cache: Option<&TreeCache<'_>>,
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    let Some(cache) = tree_cache else {
        extract_text_only(bytes, metrics);
        return;
    };
    let config = cache.config();
    let source = cache.source();
    let root = cache.tree().root_node();
    let lang = config.lang;

    // Byte-level / line-level / whitespace text metrics — language-agnostic.
    text_metrics::emit(source, metrics);
    if lang == Lang::Batch {
        let lines = batch_lines::Lines::new(source).inspect_err(|why| {
            tracing::debug!(
                target: "filefacts::source",
                format = "batch",
                len = source.len(),
                reason = ?why,
                "batch: file not modelled"
            );
        });
        batch_concat::emit(&lines, metrics);
        batch_cycles::emit(&lines, metrics);
    }

    let mut walked = visit::Collectors {
        comments: Some(visit::Comments::default()),
        literals: Some(visit::Literals::default()),
        identifiers: Some(visit::Identifiers::default()),
        functions: Some(function_metrics::Collector::default()),
        ast: Some(ast_walk::State::default()),
        rust: (lang == Lang::Rust).then(rust_syntax::Items::default),
        payload: payload_flow::Collector::new(source, lang),
        batch_commands: (lang == Lang::Batch).then(batch_commands::Collector::default),
        runtime_imports: lang
            .is_ecmascript()
            .then(runtime_imports::Collector::default),
        python: (lang == Lang::Python)
            .then(|| python_module_calls::Collector::new(source, cache.cancel())),
        shell: (lang == Lang::Bash).then(|| shell_fifo::Collector::new(cache.cancel())),
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
    let identifiers = walked.identifiers.take().unwrap_or_default().found;
    // `build_symbols` emits the symbol walk's facts after extraction.
    if let Some(mut ast) = walked.ast.take() {
        ast.add_identifiers(&identifiers);
        cache.stash_ast_walk(ast);
    }

    // Imports, computed once: the symbols, metrics and payload flow below
    // all read these.
    let go_imports = (lang == Lang::Go).then(|| go_syntax::imports(root, source));
    let mut rust = walked.rust.take();
    let mut imports = if let Some(rust) = &mut rust {
        QueryCollection {
            items: std::mem::take(&mut rust.imports),
            output_limited: rust.imports_limited,
            ..QueryCollection::default()
        }
    } else if let Some(go_imports) = &go_imports {
        let items = go_imports
            .iter()
            .map(|import| {
                let name = match import.name {
                    Some(local) => format!("{} as {local}", import.path),
                    None => import.path.to_string(),
                };
                (name, import.offset as u64)
            })
            .collect();
        QueryCollection {
            items,
            ..QueryCollection::default()
        }
    } else {
        config
            .query(QueryKind::Imports)
            .map(|query| collect_query(query, QueryKind::Imports, source, root))
            .unwrap_or_default()
    };
    if lang == Lang::Lua {
        for (name, _) in &mut imports.items {
            *name = escapes::decode_lua(name);
        }
    }
    let [functions, classes] = [QueryKind::Functions, QueryKind::Classes].map(|kind| {
        config
            .query(kind)
            .map(|query| collect_query(query, kind, source, root))
            .unwrap_or_default()
    });
    emit_query_limit_metrics(metrics, "imports", &imports);
    emit_query_limit_metrics(metrics, "functions", &functions);
    emit_query_limit_metrics(metrics, "classes", &classes);

    let identifier_names: Vec<&str> = identifiers.iter().map(|&(name, _)| name).collect();
    identifier_metrics::emit(&identifier_names, metrics);

    // String-literal metrics — operate on the literals we already
    // extracted into the `strings` view.
    let literal_refs: Vec<&str> = strings.literals.iter().map(|s| s.value.as_str()).collect();
    string_metrics::emit(&literal_refs, metrics);

    // Import metrics — feed the canonical language name so stdlib
    // classification works.
    let import_refs: Vec<&str> = imports.items.iter().map(|(n, _)| n.as_str()).collect();
    import_metrics::emit(&import_refs, lang, metrics);

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
        // Aliased imports arrive as `module as local`. Split so the symbol
        // name is the bare module and the alias is a structured field — no
        // whitespace in the symbol, and rules can match the alias directly.
        let (bare, alias) = match name.split_once(" as ") {
            Some((module, local)) => (module.trim().to_string(), Some(local.trim().to_string())),
            None => (name.clone(), None),
        };
        symbols_out.push(crate::Symbol::Import {
            name: bare,
            alias,
            library: imports.libraries.get(offset).cloned(),
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
    if !classes.items.is_empty() {
        metrics.insert(metric!("source.class_count"), classes.items.len() as f64);
    }
    // Class declarations surface as `Symbol::Function` too — the symbol
    // axis is "things declared here", regardless of function vs class.
    for (name, offset) in functions.items.into_iter().chain(classes.items) {
        symbols_out.push(crate::Symbol::Function {
            name,
            offset: Some(offset),
            complexity: None,
            callees: Vec::new(),
        });
    }

    values.insert_key(
        value_key!("source.language"),
        JsonValue::String(config.name().to_string()),
    );
    if data_only::is_data_only(root, source, lang) {
        metrics.insert(metric!("source.data_only"), 1.0);
    }
    if let Some(imports) = walked.runtime_imports.take() {
        imports.emit(values);
    }
    if let Some(python) = walked.python.take() {
        python.emit(values);
    }
    if let Some(commands) = walked.batch_commands.take() {
        commands.emit(values);
    }
    if let Some(shell) = walked.shell.take() {
        shell.emit(values);
    }
    // Execution facts are read from syntax at any size; only the payload
    // analysis has a source-size gate.
    let mut test_only = HashSet::new();
    if let Some(rust) = &mut rust {
        rust.emit(values);
        test_only = std::mem::take(&mut rust.test_only);
    }
    if lang == Lang::Go {
        go_syntax::execution_facts(root, source, values);
    }
    let payload_imports = match (&rust, &go_imports) {
        (Some(_), _) => payload_flow::Imports::Rust(&imports.items),
        (_, Some(go)) => payload_flow::Imports::Go(go),
        _ => payload_flow::Imports::None,
    };
    if let Some(payload) = walked.payload.take() {
        payload_flow::emit(
            root,
            source,
            config,
            values,
            payload.into_collected(test_only),
            &payload_imports,
        );
    }
}

/// Walk the tree-sitter parse and push every `Symbol::Call`,
/// `Symbol::Member`, and `Symbol::Bind` into `symbols_out`.
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

#[derive(Default)]
struct QueryCollection {
    items: Vec<(String, u64)>,
    /// Python from-import member offset → owning module.
    libraries: HashMap<u64, String>,
    /// The work budget ran out, or the wall-clock backstop fired; reported as
    /// [`crate::QueryLimit::Timeout`].
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
    for (limit, hit) in [
        (crate::QueryLimit::Any, true),
        (crate::QueryLimit::Timeout, result.timed_out),
        (crate::QueryLimit::Match, result.match_limited),
        (crate::QueryLimit::Output, result.output_limited),
    ] {
        if hit {
            metrics.insert(crate::source_query_limited(label, limit), 1.0);
        }
    }
}

/// Run a surface query, keeping each captured name once with its first
/// offset: a repeated `import os` shows up once, at its first occurrence,
/// the most useful answer for proximity-style matchers.
///
/// An import query's names are qualified as imports, and its
/// [`QueryCollection::libraries`] map each Python from-import member's offset
/// to its owning module. Tree-sitter
/// records `from .pkg import name` as two captures, the relative module and
/// the member; the bare member is indistinguishable from a top-level
/// `import name`, so `from . import requests` would otherwise masquerade as
/// an import of the PyPI `requests` library. Rejoining the member to its
/// relative module (`.requests`, `.pkg.requests`) keeps it relative, so no
/// library matcher anchored on `^name` matches a local submodule. Equal
/// member names from distinct modules stay separate.
fn collect_query(query: &Query, kind: QueryKind, source: &str, root: Node<'_>) -> QueryCollection {
    let imports = kind == QueryKind::Imports;
    let capture_names = query.capture_names();
    let mut cursor = source_query_cursor();
    cursor.set_byte_range(0..source.len().min(SOURCE_QUERY_BYTE_LIMIT));
    let mut seen: BTreeMap<(String, Option<String>), u64> = BTreeMap::new();
    let mut libraries = HashMap::new();
    let budget = QueryBudget::new();
    let mut output_limited = false;
    let mut progress_cb = |_: &tree_sitter::QueryCursorState| budget.poll();
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    {
        let mut matches = cursor.matches_with_options(query, root, source.as_bytes(), options);
        'matches: while let Some(m) = matches.next() {
            for cap in m.captures() {
                let name = capture_names.get(cap.index as usize).copied().unwrap_or("");
                if name.starts_with('_') {
                    continue;
                }
                // Escaped source-map fragments can recover as import statements
                // whose source is an entire embedded module. Keep valid sibling
                // imports, but do not publish sources from malformed statements.
                if imports
                    && cap.node.parent().is_some_and(|parent| {
                        parent.kind() == "import_statement" && parent.has_error()
                    })
                {
                    continue;
                }
                let cleaned = strip_quotes(text(cap.node, source));
                if cleaned.is_empty() {
                    continue;
                }
                let offset = cap.node.start_byte() as u64;
                let key = if imports {
                    let library = python_import_library(cap.node, source);
                    if let Some(library) = &library {
                        libraries.insert(offset, library.clone());
                    }
                    (import_name(cap.node, cleaned, source), library)
                } else {
                    (cleaned.to_owned(), None)
                };
                seen.entry(key).or_insert(offset);
                if seen.len() >= SOURCE_QUERY_OUTPUT_LIMIT {
                    output_limited = true;
                    break 'matches;
                }
            }
        }
    }
    let collection = QueryCollection {
        items: seen
            .into_iter()
            .map(|((name, _), offset)| (name, offset))
            .collect(),
        libraries,
        timed_out: budget.exhausted.get(),
        match_limited: cursor.did_exceed_match_limit(),
        output_limited,
    };
    if collection.limited() {
        tracing::debug!(
            target: "filefacts::source",
            query = kind.label(),
            timed_out = collection.timed_out,
            match_limited = collection.match_limited,
            output_limited = collection.output_limited,
            "surface query stopped early; its symbols are incomplete"
        );
    }
    collection
}

/// An import capture's name: `module as alias` for a Python aliased import,
/// read structurally since Python permits tabs, repeated spaces and line
/// continuations around `as`, and a relative from-import member qualified
/// with its module.
fn import_name(node: Node<'_>, cleaned: &str, source: &str) -> String {
    let cleaned = match (
        node.child_by_field_name("name")
            .filter(|_| node.kind() == "aliased_import"),
        node.child_by_field_name("alias"),
    ) {
        (Some(module), Some(alias)) => format!(
            "{} as {}",
            text(module, source).trim(),
            text(alias, source).trim()
        ),
        _ => cleaned.to_owned(),
    };
    qualify_relative_member(node, cleaned, source)
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
    Some(text(module, source).trim().to_string())
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
    let prefix = text(module, source).trim();
    // `.`/`..` end in a dot already; `.pkg` needs a joining dot.
    if prefix.ends_with('.') {
        format!("{prefix}{cleaned}")
    } else {
        format!("{prefix}.{cleaned}")
    }
}

fn strip_quotes(s: &str) -> &str {
    if let [first, .., last] = s.as_bytes()
        && first == last
        && matches!(first, b'"' | b'\'' | b'`')
    {
        // ASCII quotes, so both cuts fall on character boundaries.
        return s.get(1..s.len() - 1).unwrap_or(s);
    }
    s
}

/// True when this file type is a source language filefacts can parse.
pub(crate) fn supports(file_type: FileType) -> bool {
    langs::config_for(file_type).is_some()
}

/// Resolve a source dialect label to its tree-sitter [`Language`](tree_sitter::Language). Used by callers
/// that want to compile a tree-sitter query against the same grammar
/// filefacts uses internally — e.g. rule-engine load-time validation. C and
/// C++ have distinct grammars despite sharing the external C-family type.
pub(crate) fn tree_sitter_language_named(name: &str) -> Option<tree_sitter::Language> {
    langs::config_named(name).map(|config| (config.language)())
}

/// The file type of the language labelled `name`, the value published under
/// `values.source.language` (e.g. `"python"`, `"bash"`, `"objc"`).
#[cfg(test)]
pub(crate) fn file_type_for_language(name: &str) -> Option<FileType> {
    langs::file_type_named(name)
}

/// Emit text-level metrics (`text.*`) without a tree-sitter parse.
///
/// Called for text-like languages without a [`LangConfig`](langs::LangConfig)
/// entry (VBScript, …), and for a source file whose parse is unavailable.
/// Only emits the byte-level / line-level / whitespace metrics that don't
/// need an AST — language-agnostic by construction.
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
    let get = |metrics: &Metrics, key: MetricKey| metrics.lookup(&key).unwrap_or(0.0);

    // Counted by the caller: `functions.count` / `imports.count` are only
    // emitted later, from the unified symbols view.
    let functions_total = functions_total as f64;
    let strings_total = get(metrics, metric!("strings.count"));
    let identifiers_total = get(metrics, metric!("identifiers.count"));
    let identifiers_unique = get(metrics, metric!("identifiers.unique"));
    let imports_total = imports_total as f64;
    let functions_anonymous = get(metrics, metric!("functions.anonymous"));

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
        let suspicious = get(metrics, metric!("identifiers.hex_like_names"))
            + get(metrics, metric!("identifiers.base64_like_names"))
            + get(metrics, metric!("identifiers.sequential_names"))
            + get(metrics, metric!("identifiers.keyboard_pattern_names"))
            + get(metrics, metric!("identifiers.repeated_char_names"));
        if suspicious > 0.0 {
            metrics.insert(
                metric!("text.suspicious_identifier_ratio"),
                suspicious / identifiers_unique,
            );
        }
    }

    if strings_total > 0.0 {
        let encoded = get(metrics, metric!("strings.base64_candidates"))
            + get(metrics, metric!("strings.hex"))
            + get(metrics, metric!("strings.url_encoded"));
        if encoded > 0.0 {
            metrics.insert(
                metric!("text.encoded_string_ratio"),
                encoded / strings_total,
            );
        }
        let suspicious = get(metrics, metric!("strings.embedded_code_candidates"))
            + get(metrics, metric!("strings.shell"))
            + get(metrics, metric!("strings.sql"));
        if suspicious > 0.0 {
            metrics.insert(
                metric!("text.suspicious_string_ratio"),
                suspicious / strings_total,
            );
        }
    }

    let comments_total = get(metrics, metric!("comments.count"));
    if comments_total > 0.0 {
        let suspicious = get(metrics, metric!("comments.high_entropy"))
            + get(metrics, metric!("comments.base64"));
        if suspicious > 0.0 {
            metrics.insert(
                metric!("text.suspicious_comment_ratio"),
                suspicious / comments_total,
            );
        }
    }

    if imports_total > 0.0 {
        let dynamic = get(metrics, metric!("imports.dynamic"));
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
