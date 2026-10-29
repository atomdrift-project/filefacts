//! One read-only traversal of a source tree, shared by every collector that
//! only needs to look at each node once: literals, comments, identifiers,
//! function metrics, the symbol walk ([`super::ast_walk`]), Rust items, the
//! payload-flow index, and the per-language command and import facts.
//! [`walk`] visits each node once, depth first, left to right, and hands it
//! to whichever collectors are enabled, on entry and again on exit.
//!
//! Three things keep a traversal of their own. The surface queries
//! ([`super::QueryKind`]) run in tree-sitter's query cursor. The two flow
//! analyses ([`super::payload_flow`], [`super::value_flow`]) evaluate
//! expressions recursively under step budgets, value flow lazily when the
//! flow view is read. The Batch line grammars ([`super::batch_lines`]) read
//! lines, not the tree.
//!
//! Node kinds are compared as grammar symbol ids ([`NodeIds`]): `Node::kind`
//! measures and validates a C string on every call.

use std::sync::OnceLock;

use tree_sitter::{Language, Node, TreeCursor};

use crate::output::ExtractedString;

use super::ast_walk::{self, MAX_AST_DEPTH};
use super::langs::{Lang, LangConfig};
use super::{
    batch_commands, function_metrics, payload_flow, python_module_calls, runtime_imports,
    rust_syntax, shell_fifo,
};

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
    /// [`LangConfig::function_kinds`].
    pub(super) function: KindSet,
    pub(super) infinite_loop_candidate: KindSet,
    pub(super) sequence: KindSet,
    pub(super) variable_declarator: KindSet,
    pub(super) python_import: KindSet,
    pub(super) attribute_item: KindSet,
    pub(super) use_declaration: KindSet,
    /// Rust items whose kind [`rust_syntax::Items`] reads: functions and
    /// modules.
    pub(super) rust_item: KindSet,
    pub(super) batch_command: KindSet,
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
            function: set(config.function_kinds),
            infinite_loop_candidate: set(ast_walk::INFINITE_LOOP_KINDS),
            sequence: set(&["sequence_expression"]),
            variable_declarator: set(&["variable_declarator"]),
            python_import: set(&["import_statement", "import_from_statement"]),
            attribute_item: set(&["attribute_item"]),
            use_declaration: set(&["use_declaration"]),
            rust_item: set(&["function_item", "mod_item"]),
            batch_command: set(&["cmd"]),
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
    /// Entered before `payload`, which skips the test-only items it finds.
    pub(super) rust: Option<rust_syntax::Items>,
    pub(super) payload: Option<payload_flow::Collector<'t>>,
    pub(super) batch_commands: Option<batch_commands::Collector>,
    pub(super) runtime_imports: Option<runtime_imports::Collector>,
    pub(super) python: Option<python_module_calls::Collector>,
    pub(super) shell: Option<shell_fifo::Collector>,
}

/// Visit every node under `root` once, depth first, left to right, and pass
/// it to each enabled collector. Iterative, so tree depth is bounded only by
/// memory; collectors that need one keep their own depth caps.
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
    // The open ancestors of the cursor's node, root first.
    let mut open: Vec<Visit<'t>> = Vec::new();
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
            if let Some(visit) = open.pop() {
                walk.collectors.exit(&visit);
            }
            if cursor.goto_next_sibling() {
                walk.enter(cursor.node(), &mut open);
                break;
            }
            if !cursor.goto_parent() {
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
    fn enter(&mut self, node: Node<'t>, open: &mut Vec<Visit<'t>>) {
        let visit = Visit {
            node,
            kind_id: node.kind_id(),
            named: node.is_named(),
            depth: u32::try_from(open.len()).unwrap_or(u32::MAX),
            parent_kind_id: open.last().map(|parent| parent.kind_id),
        };
        self.collectors
            .enter(&visit, self.source, self.config, self.ids, self.scratch);
        open.push(visit);
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
            literals.enter(visit, source, config, ids);
        }
        if let Some(identifiers) = &mut self.identifiers {
            identifiers.enter(visit, source, ids);
        }
        if let Some(functions) = &mut self.functions {
            functions.enter(visit, source, ids);
        }
        if visit.depth <= MAX_AST_DEPTH {
            if let Some(ast) = &mut self.ast {
                ast.visit(visit, source, config, ids, scratch);
            }
        }
        if let Some(rust) = &mut self.rust {
            rust.enter(visit, source, ids);
        }
        if let Some(payload) = &mut self.payload {
            payload.enter(visit, ids, self.rust.as_ref().map(|rust| &rust.test_only));
        }
        if let Some(commands) = &mut self.batch_commands {
            commands.enter(visit, source, ids);
        }
        if let Some(imports) = &mut self.runtime_imports {
            imports.enter(visit, source);
        }
        if let Some(python) = &mut self.python {
            python.enter(visit, source);
        }
        if let Some(shell) = &mut self.shell {
            shell.enter(visit, source);
        }
    }

    fn exit(&mut self, visit: &Visit<'t>) {
        if let Some(comments) = &mut self.comments {
            comments.exit(visit);
        }
        if let Some(literals) = &mut self.literals {
            literals.exit(visit);
        }
        if let Some(functions) = &mut self.functions {
            functions.exit(visit);
        }
        if let Some(rust) = &mut self.rust {
            rust.exit();
        }
        if let Some(payload) = &mut self.payload {
            payload.exit();
        }
    }
}

/// The literal tier, in source order: every string-kind node not inside
/// another, and on PowerShell, host/path-shaped bareword command arguments.
#[derive(Default)]
pub(super) struct Literals {
    pub(super) found: Vec<ExtractedString>,
    /// Depth of the string node being skipped through: a literal's own
    /// children are not literals.
    inside: Option<u32>,
}

impl Literals {
    fn enter(&mut self, visit: &Visit<'_>, source: &str, config: &LangConfig, ids: &NodeIds) {
        if self.inside.is_some() {
            return;
        }
        if ids.string.contains(visit.kind_id) {
            self.inside = Some(visit.depth);
            // Unquoted forms (heredoc bodies, Perl `q{…}`, Lua `[[…]]`) have
            // no quotes to strip, so this tier keeps their text.
            if let Some(text) = super::decode_string_literal(visit.node, source, config)
                .or_else(|| super::unquoted_literal(visit.node, source).map(str::to_string))
            {
                self.found.push(ExtractedString {
                    value: text,
                    offset: visit.node.start_byte(),
                    ..ExtractedString::default()
                });
            }
            return;
        }
        // PowerShell command arguments are often unquoted barewords. The
        // grammar exposes `cdn.example/path` as a generic token rather than a
        // string literal, even though the command receives it as a string.
        // Promote only host/path-shaped tokens that are direct command
        // elements; ordinary identifiers and dotted member names stay out of
        // the precise literal tier.
        if config.lang == Lang::PowerShell
            && ids.generic_token.contains(visit.kind_id)
            && visit
                .parent_kind_id
                .is_some_and(|parent| ids.command_elements.contains(parent))
        {
            let text = super::text(visit.node, source);
            if super::looks_like_protocolless_url(text) {
                self.found.push(ExtractedString {
                    value: text.to_string(),
                    offset: visit.node.start_byte(),
                    ..ExtractedString::default()
                });
            }
        }
    }

    fn exit(&mut self, visit: &Visit<'_>) {
        if self.inside == Some(visit.depth) {
            self.inside = None;
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

/// Every leaf identifier's text, repeats included, in source order, for
/// [`super::identifier_metrics`] and the symbol walk's
/// [`Symbol::Identifier`](crate::Symbol::Identifier) facts. A leaf has no
/// named children: qualified wrappers (`os.path`, Bash `command_name`) are
/// left to the member and call facts, and the summed text of every leaf is
/// at most the source's size.
#[derive(Default)]
pub(super) struct Identifiers<'t> {
    pub(super) found: Vec<(&'t str, usize)>,
}

impl<'t> Identifiers<'t> {
    fn enter(&mut self, visit: &Visit<'t>, source: &'t str, ids: &NodeIds) {
        if ids.identifier.contains(visit.kind_id) && visit.node.named_child_count() == 0 {
            let text = super::text(visit.node, source);
            if !text.is_empty() {
                self.found.push((text, visit.node.start_byte()));
            }
        }
    }
}

#[cfg(test)]
mod tests;
