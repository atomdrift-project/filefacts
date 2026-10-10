//! One read-only traversal of a source tree, shared by every collector that
//! only needs to look at each node once.
//!
//! Extraction used to walk the same tree once per concern: string literals,
//! identifier metrics, function metrics, the payload-flow function index (and
//! its `#[cfg(test)]` scan), and the symbol walk in [`super::ast_walk`], plus
//! a re-walk of every function's subtree to find nested functions. [`walk`]
//! visits each node once, in source order, and hands it to whichever of
//! those collectors are enabled. Each keeps exactly the output its own walk
//! produced, including its order:
//!
//! - The symbol walk and function metrics were pre-order, left to right, and
//!   stopped below [`MAX_AST_DEPTH`]; their collectors act on entry and
//!   skip deeper nodes.
//! - The literal, identifier and payload-flow walks popped an explicit stack,
//!   which visits children right to left. That order is the reverse of a
//!   left-to-right post-order, so those collectors record on exit and reverse
//!   their output at the end.
//!
//! The three surface queries ([`super::QueryKind`]) run in tree-sitter's own
//! cursor, and value flow ([`super::value_flow`]) evaluates expressions
//! recursively under a step budget, lazily, when the flow view is read; both
//! keep their own traversal.
//!
//! Node kinds are compared as grammar symbol ids ([`NodeIds`]): `Node::kind`
//! measures and validates a C string on every call.

use std::sync::OnceLock;

use tree_sitter::{Language, Node, TreeCursor};

use crate::output::ExtractedString;

use super::ast_walk::{self, MAX_AST_DEPTH};
use super::function_metrics;
use super::langs::{Lang, LangConfig};
use super::payload_flow;

/// A set of node kinds as grammar symbol ids. Built from kind names by
/// checking every symbol of the grammar, so membership agrees exactly with
/// comparing `Node::kind` against the names: `Node::kind_id` is the public
/// symbol behind that name, and a name used for both a named and an anonymous
/// node (Python's `lambda`) matches both, as the string comparison did.
pub(super) struct KindSet(Box<[u64]>);

impl KindSet {
    fn new(language: &Language, kinds: &[&str]) -> Self {
        let count = language.node_kind_count();
        let mut bits = vec![0u64; count.div_ceil(64)];
        for id in 0..count {
            let Ok(id) = u16::try_from(id) else { break };
            if language
                .node_kind_for_id(id)
                .is_some_and(|name| kinds.contains(&name))
            {
                if let Some(word) = bits.get_mut(usize::from(id) / 64) {
                    *word |= 1 << (id % 64);
                }
            }
        }
        Self(bits.into_boxed_slice())
    }

    /// Every named kind whose name `keep` accepts.
    fn named_where(language: &Language, keep: impl Fn(&str) -> bool) -> Self {
        let count = language.node_kind_count();
        let mut bits = vec![0u64; count.div_ceil(64)];
        for id in 0..count {
            let Ok(id) = u16::try_from(id) else { break };
            if language.node_kind_is_named(id) && language.node_kind_for_id(id).is_some_and(&keep) {
                if let Some(word) = bits.get_mut(usize::from(id) / 64) {
                    *word |= 1 << (id % 64);
                }
            }
        }
        Self(bits.into_boxed_slice())
    }

    #[inline]
    pub(super) fn contains(&self, id: u16) -> bool {
        self.0
            .get(usize::from(id) / 64)
            .is_some_and(|word| word >> (id % 64) & 1 == 1)
    }
}

/// The node kinds and fields a language's collectors test on every node,
/// resolved once per language.
pub(super) struct NodeIds {
    pub(super) string: KindSet,
    pub(super) identifier: KindSet,
    pub(super) call: KindSet,
    pub(super) member_or_subscript: KindSet,
    pub(super) assignment: KindSet,
    pub(super) array: KindSet,
    pub(super) number: KindSet,
    pub(super) binary_op: KindSet,
    pub(super) function_definition: KindSet,
    pub(super) infinite_loop_candidate: KindSet,
    pub(super) sequence: KindSet,
    pub(super) metric_function: KindSet,
    pub(super) payload_function: KindSet,
    pub(super) variable_declarator: KindSet,
    pub(super) python_import: KindSet,
    pub(super) attribute_item: KindSet,
    /// Comment nodes: every named kind with `comment` in its name
    /// (`comment`, `line_comment`, `block_comment`, `multiline_comment`,
    /// `html_comment`, …). The grammar has already told comments from the
    /// strings, regexes and heredocs around them.
    comment: KindSet,
    generic_token: KindSet,
    command_elements: KindSet,
    pub(super) operator_field: Option<u16>,
    pub(super) left_field: Option<u16>,
    pub(super) right_field: Option<u16>,
}

impl NodeIds {
    fn new(config: &LangConfig) -> Self {
        let language = (config.language)();
        let set = |kinds: &[&str]| KindSet::new(&language, kinds);
        let field = |name: &str| language.field_id_for_name(name).map(u16::from);
        let member_or_subscript: Vec<&str> = config
            .member_kinds
            .iter()
            .chain(ast_walk::SUBSCRIPT_KINDS)
            .copied()
            .collect();
        Self {
            string: set(config.string_kinds),
            identifier: set(config.identifier_kinds),
            call: set(config.call_kinds),
            member_or_subscript: set(&member_or_subscript),
            assignment: set(ast_walk::ASSIGNMENT_KINDS),
            array: set(config.array_kinds),
            number: set(config.number_kinds),
            binary_op: set(config.binary_op_kinds),
            function_definition: set(ast_walk::FUNCTION_DEFINITION_KINDS),
            infinite_loop_candidate: set(ast_walk::INFINITE_LOOP_KINDS),
            sequence: set(&["sequence_expression"]),
            metric_function: set(function_metrics::function_kinds_for(config.lang)),
            payload_function: set(payload_flow::FUNCTION_KINDS),
            variable_declarator: set(&["variable_declarator"]),
            python_import: set(&["import_statement", "import_from_statement"]),
            attribute_item: set(&["attribute_item"]),
            comment: KindSet::named_where(&language, |name| name.contains("comment")),
            generic_token: set(&["generic_token"]),
            command_elements: set(&["command_elements"]),
            operator_field: field("operator"),
            left_field: field("left"),
            right_field: field("right"),
        }
    }
}

/// The [`NodeIds`] for `config`'s language, built on first use.
pub(super) fn node_ids(config: &LangConfig) -> &'static NodeIds {
    static IDS: [OnceLock<NodeIds>; Lang::COUNT] = [const { OnceLock::new() }; Lang::COUNT];
    IDS.get(config.lang as usize)
        .expect("`Lang::COUNT` covers every `Lang`")
        .get_or_init(|| NodeIds::new(config))
}

/// One node as the walk reaches it.
#[derive(Clone, Copy)]
pub(super) struct Visit<'t> {
    pub(super) node: Node<'t>,
    pub(super) kind_id: u16,
    pub(super) named: bool,
    /// Distance from the root, which is at depth 0.
    pub(super) depth: u32,
    /// The parent's kind id; `None` at the root.
    pub(super) parent_kind_id: Option<u16>,
    /// Position among the parent's named children; meaningful only when
    /// `named`.
    pub(super) named_index: usize,
}

/// What a source file's extraction needs from the one walk. A collector left
/// `None` costs nothing.
#[derive(Default)]
pub(super) struct Collectors<'t> {
    pub(super) comments: Option<Comments<'t>>,
    pub(super) literals: Option<Literals>,
    pub(super) identifiers: Option<Identifiers<'t>>,
    pub(super) functions: Option<function_metrics::Collector>,
    pub(super) ast: Option<ast_walk::State>,
    pub(super) payload: Option<payload_flow::Collector<'t>>,
}

/// Visit every node under `root` once, depth first, left to right, and pass
/// it to each enabled collector. Iterative, so tree depth is bounded only by
/// memory; the collectors that recursed before keep their own depth caps.
pub(super) fn walk<'t>(
    root: Node<'t>,
    source: &'t str,
    config: &'static LangConfig,
    collectors: &mut Collectors<'t>,
) {
    let ids = node_ids(config);
    let mut cursor = root.walk();
    // For collectors that look at a node's children: reset onto each node in
    // turn, so the walk allocates no cursor per node.
    let mut scratch = root.walk();
    // The open ancestors of the cursor's node, root first, each with the
    // number of its named children entered so far.
    let mut open: Vec<(Visit<'t>, usize)> = Vec::new();
    let mut walk = Walk {
        source,
        config,
        ids,
        scratch: &mut scratch,
        collectors,
    };
    walk.enter(root, &mut open);
    loop {
        if cursor.goto_first_child() {
            walk.enter(cursor.node(), &mut open);
            continue;
        }
        loop {
            if let Some((visit, _)) = open.pop() {
                walk.collectors.exit(&visit, source, config, ids);
            }
            if cursor.goto_next_sibling() {
                walk.enter(cursor.node(), &mut open);
                break;
            }
            if !cursor.goto_parent() {
                walk.collectors.finish();
                return;
            }
        }
    }
}

/// The state [`walk`] threads through every node.
struct Walk<'w, 't> {
    source: &'t str,
    config: &'static LangConfig,
    ids: &'static NodeIds,
    scratch: &'w mut TreeCursor<'t>,
    collectors: &'w mut Collectors<'t>,
}

impl<'t> Walk<'_, 't> {
    fn enter(&mut self, node: Node<'t>, open: &mut Vec<(Visit<'t>, usize)>) {
        let named = node.is_named();
        let (parent_kind_id, named_index) = match open.last_mut() {
            Some((parent, seen)) => {
                let index = *seen;
                if named {
                    *seen += 1;
                }
                (Some(parent.kind_id), index)
            }
            None => (None, 0),
        };
        let visit = Visit {
            node,
            kind_id: node.kind_id(),
            named,
            depth: u32::try_from(open.len()).unwrap_or(u32::MAX),
            parent_kind_id,
            named_index,
        };
        self.collectors
            .enter(&visit, self.source, self.config, self.ids, self.scratch);
        open.push((visit, 0));
    }
}

impl<'t> Collectors<'t> {
    fn enter(
        &mut self,
        visit: &Visit<'t>,
        source: &'t str,
        config: &LangConfig,
        ids: &NodeIds,
        scratch: &mut TreeCursor<'t>,
    ) {
        if let Some(comments) = &mut self.comments {
            comments.enter(visit, source, ids);
        }
        if let Some(literals) = &mut self.literals {
            literals.enter(visit, ids);
        }
        if let Some(functions) = &mut self.functions {
            functions.enter(visit, source, ids);
        }
        if visit.depth <= MAX_AST_DEPTH {
            if let Some(ast) = &mut self.ast {
                ast.visit(visit, source, config, ids, scratch);
            }
        }
        if let Some(payload) = &mut self.payload {
            payload.enter(visit, ids);
        }
    }

    fn exit(&mut self, visit: &Visit<'t>, source: &'t str, config: &LangConfig, ids: &NodeIds) {
        if let Some(comments) = &mut self.comments {
            comments.exit(visit);
        }
        if let Some(literals) = &mut self.literals {
            literals.exit(visit, source, config, ids);
        }
        if let Some(identifiers) = &mut self.identifiers {
            identifiers.exit(visit, source, ids);
        }
        if let Some(functions) = &mut self.functions {
            functions.exit(visit);
        }
        if let Some(payload) = &mut self.payload {
            payload.exit(visit, ids);
        }
    }

    fn finish(&mut self) {
        if let Some(literals) = &mut self.literals {
            literals.found.reverse();
        }
        if let Some(identifiers) = &mut self.identifiers {
            identifiers.found.reverse();
        }
        if let Some(payload) = &mut self.payload {
            payload.finish();
        }
    }
}

/// The literal tier: every string-kind node not inside another, and on
/// PowerShell, host/path-shaped bareword command arguments.
#[derive(Default)]
pub(super) struct Literals {
    pub(super) found: Vec<ExtractedString>,
    /// Depth of the string node being skipped through: a literal's own
    /// children are not literals.
    inside: Option<u32>,
}

impl Literals {
    fn enter(&mut self, visit: &Visit<'_>, ids: &NodeIds) {
        if self.inside.is_none() && ids.string.contains(visit.kind_id) {
            self.inside = Some(visit.depth);
        }
    }

    fn exit(&mut self, visit: &Visit<'_>, source: &str, config: &LangConfig, ids: &NodeIds) {
        match self.inside {
            Some(depth) if depth == visit.depth => {
                self.inside = None;
                // Unquoted forms (heredoc bodies, Perl `q{…}`, Lua `[[…]]`)
                // have no quotes to strip, so this tier keeps their text.
                if let Some(text) = super::decode_string_literal(visit.node, source, config)
                    .or_else(|| super::unquoted_literal(visit.node, source).map(str::to_string))
                {
                    self.found.push(ExtractedString {
                        value: text,
                        offset: visit.node.start_byte(),
                        ..ExtractedString::default()
                    });
                }
            }
            Some(_) => {}
            None => {
                // PowerShell command arguments are often unquoted barewords.
                // The grammar exposes `cdn.example/path` as a generic token
                // rather than a string literal, even though the command
                // receives it as a string. Promote only host/path-shaped
                // tokens that are direct command elements; ordinary
                // identifiers and dotted member names stay out of the precise
                // literal tier.
                if config.lang == Lang::PowerShell
                    && ids.generic_token.contains(visit.kind_id)
                    && visit
                        .parent_kind_id
                        .is_some_and(|parent| ids.command_elements.contains(parent))
                {
                    if let Ok(text) = visit.node.utf8_text(source.as_bytes()) {
                        if super::looks_like_protocolless_url(text) {
                            self.found.push(ExtractedString {
                                value: text.to_string(),
                                offset: visit.node.start_byte(),
                                ..ExtractedString::default()
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Every outermost comment node's text and start offset, in source order,
/// for [`super::comment_metrics`]. A comment's own children (Rust's doc
/// markers, a grammar's `comment_content`) are not comments of their own.
#[derive(Default)]
pub(super) struct Comments<'t> {
    pub(super) found: Vec<(usize, &'t str)>,
    /// Depth of the comment node being skipped through.
    inside: Option<u32>,
}

impl<'t> Comments<'t> {
    fn enter(&mut self, visit: &Visit<'t>, source: &'t str, ids: &NodeIds) {
        if self.inside.is_none() && ids.comment.contains(visit.kind_id) {
            self.inside = Some(visit.depth);
            if let Ok(text) = visit.node.utf8_text(source.as_bytes()) {
                self.found.push((visit.node.start_byte(), text));
            }
        }
    }

    fn exit(&mut self, visit: &Visit<'t>) {
        if self.inside == Some(visit.depth) {
            self.inside = None;
        }
    }
}

/// Identifier text [`Identifiers`] keeps, in bytes per source byte, on top of
/// [`IDENTIFIER_TEXT_FLOOR`]. Identifier kinds can nest (bash `command_name`
/// around `$( … )`), so the summed text of every identifier grows with the
/// square of the nesting depth: 20k nested `"$(` spent 26 s in
/// [`super::identifier_metrics`]. Real source sums to about its own size.
const IDENTIFIER_TEXT_PER_SOURCE_BYTE: usize = 4;

/// Identifier text kept regardless of source size, in bytes.
const IDENTIFIER_TEXT_FLOOR: usize = 64 * 1024;

/// Every identifier-kind node's text, repeats included, for
/// [`super::identifier_metrics`], up to [`IDENTIFIER_TEXT_PER_SOURCE_BYTE`].
/// Nodes exit innermost first, so a nest drops its longest, outer names.
#[derive(Default)]
pub(super) struct Identifiers<'t> {
    pub(super) found: Vec<&'t str>,
    /// Summed length of `found`.
    bytes: usize,
    /// An identifier was dropped for the text budget.
    pub(super) truncated: bool,
}

impl<'t> Identifiers<'t> {
    fn exit(&mut self, visit: &Visit<'t>, source: &'t str, ids: &NodeIds) {
        if ids.identifier.contains(visit.kind_id) {
            if let Ok(text) = visit.node.utf8_text(source.as_bytes()) {
                if text.is_empty() {
                    return;
                }
                let budget = source
                    .len()
                    .saturating_mul(IDENTIFIER_TEXT_PER_SOURCE_BYTE)
                    .saturating_add(IDENTIFIER_TEXT_FLOOR);
                let bytes = self.bytes.saturating_add(text.len());
                if bytes > budget {
                    self.truncated = true;
                    return;
                }
                self.bytes = bytes;
                self.found.push(text);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open<'a>(path: &str, source: &'a str) -> crate::ParsedFile<'a> {
        crate::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(source.as_bytes())
    }

    /// A kind name used for both a named and an anonymous node matches both,
    /// as comparing `Node::kind` did.
    #[test]
    fn kind_sets_match_every_symbol_with_the_name() {
        let language: Language = tree_sitter_python::LANGUAGE.into();
        let set = KindSet::new(&language, &["lambda"]);
        let named = language.id_for_node_kind("lambda", true);
        let anonymous = language.id_for_node_kind("lambda", false);
        assert_ne!(named, anonymous);
        assert!(set.contains(named) && set.contains(anonymous));
        assert!(!set.contains(language.id_for_node_kind("identifier", true)));
        assert!(!set.contains(u16::MAX), "ERROR is in no set");
    }

    /// Literals keep the order of the stack walk they came from: the last
    /// statement first, an array's elements right to left.
    #[test]
    fn literals_keep_the_original_walk_order() {
        let parsed = open("a.py", "x = 'a'\ny = ['b', 'c']\n");
        let texts: Vec<&str> = parsed.literals().iter().map(|l| l.value.as_str()).collect();
        assert_eq!(texts, ["c", "b", "a"]);
    }

    /// A function counts as nested-containing when any function lies
    /// anywhere inside it, found in the same walk rather than by re-walking
    /// each function's subtree.
    #[test]
    fn nested_functions_are_found_during_the_walk() {
        let parsed = open(
            "a.js",
            "function a() { if (x) { while (y) { function b() {} } } }\nfunction c() { return 1; }\n",
        );
        let metrics = parsed.metrics();
        assert_eq!(metrics.get("functions.nested"), Some(1.0));
        assert_eq!(metrics.get("functions.max_nesting_depth"), Some(1.0));
    }

    /// The payload-flow index stops where its old stack walk stopped: once
    /// more than 10,000 nodes are pending.
    #[test]
    fn payload_index_stops_where_the_stack_walk_did() {
        let truncated = |statements: usize| {
            let source = "x = 1\n".repeat(statements);
            let parsed = open("a.py", &source);
            parsed
                .values()
                .get("source.payload_flow.truncated")
                .and_then(serde_json::Value::as_bool)
        };
        // The root's 9,999 statements are pending while the walk visits the
        // last one's assignment, which adds its two named children.
        assert_eq!(truncated(9_999), Some(false));
        assert_eq!(truncated(10_000), Some(true));
    }

    /// Nested identifier nodes cannot make identifier metrics read more text
    /// than the budget allows: each `"$(` level is a `command_name` spanning
    /// every level inside it.
    #[test]
    fn nested_identifier_text_is_budgeted() {
        let depth = 4_000;
        let source = format!("x={}echo{}\n", "\"$(".repeat(depth), ")\"".repeat(depth));
        let parsed = open("a.sh", &source);
        let metrics = parsed.metrics();
        let unique = metrics.get("identifiers.unique").expect("identifiers");
        let avg = metrics.get("identifiers.avg_length").expect("identifiers");
        let budget = source.len() * IDENTIFIER_TEXT_PER_SOURCE_BYTE + IDENTIFIER_TEXT_FLOOR;
        assert!(unique * avg <= budget as f64, "{unique} × {avg} > {budget}");

        // Ordinary source keeps every identifier.
        let parsed = open("a.sh", "echo hi\nls -l\n");
        assert_eq!(parsed.metrics().get("identifiers.count"), Some(6.0));
    }
}
