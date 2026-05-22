//! Single-pass AST projection walker.
//!
//! Walks the entire tree once and emits, in source order:
//!
//! - every call site (`ast.calls[]`),
//! - the sorted-unique set of static call targets (`ast.targets[]`),
//! - the sorted-unique set of dotted member-access chains
//!   (`ast.members[]`),
//! - the per-target list of string-literal arguments
//!   (`ast.call_strings`).
//!
//! While walking we also tally numeric features into the caller's
//! [`Metrics`] map. Counts and depths live there, not on the `Ast`
//! view — `Ast` carries *facts about what the source contains*; the
//! quantitative summary is a separate concern.
//!
//! The walker is language-driven by the [`LangConfig`] passed in; it
//! contains no language-specific code itself. To support a new
//! language, add a [`LangConfig`] entry — the walker handles it
//! without modification.
//!
//! [`Metrics`]: crate::Metrics
//! [`LangConfig`]: super::langs::LangConfig

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use crate::output::{ArgShape, Assignment, Ast, Call, Metrics};

use super::langs::LangConfig;

pub(super) fn walk(
    root: Node<'_>,
    source: &str,
    config: &LangConfig,
    metrics: &mut Metrics,
) -> Ast {
    let mut state = State::default();
    state.walk_node(root, source, config, 0);

    let unique_targets: BTreeSet<String> = state
        .calls
        .iter()
        .filter_map(|c| c.target.clone())
        .collect();

    let ast = Ast {
        calls: state.calls,
        targets: unique_targets.into_iter().collect(),
        members: state.members.into_iter().collect(),
        call_strings: state
            .literal_args
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect::<Vec<_>>()))
            .collect(),
        binds: state.binds,
    };

    metrics.insert("ast.node_count", state.node_count as f64);
    metrics.insert("ast.max_depth", f64::from(state.max_depth));
    metrics.insert("ast.call_count", ast.calls.len() as f64);
    metrics.insert("ast.target_count", ast.targets.len() as f64);
    if state.max_member_chain_depth > 0 {
        metrics.insert(
            "ast.member_depth_max",
            f64::from(state.max_member_chain_depth),
        );
    }
    if state.max_string_concat_chain > 1 {
        metrics.insert(
            "ast.string_concat_chain_max_length",
            f64::from(state.max_string_concat_chain),
        );
    }
    if state.max_array_literal_length > 0 {
        metrics.insert(
            "ast.array_literal_max_length",
            f64::from(state.max_array_literal_length),
        );
    }
    if !ast.binds.is_empty() {
        metrics.insert("ast.bind_count", ast.binds.len() as f64);
        let string_binds = ast.binds.iter().filter(|a| a.string.is_some()).count();
        if string_binds > 0 {
            metrics.insert("ast.string_bind_count", string_binds as f64);
        }
    }

    ast
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    binds: Vec<Assignment>,
    members: BTreeSet<String>,
    literal_args: BTreeMap<String, BTreeSet<String>>,
    scopes: Vec<&'static str>,
    node_count: u64,
    max_depth: u32,
    max_member_chain_depth: u32,
    max_string_concat_chain: u32,
    max_array_literal_length: u32,
}

impl State {
    fn walk_node(&mut self, node: Node<'_>, source: &str, config: &LangConfig, depth: u32) {
        self.node_count += 1;
        if depth > self.max_depth {
            self.max_depth = depth;
        }

        let pushed_scope = if is_class_scope(node.kind(), config.name) {
            self.scopes.push("class");
            true
        } else if is_function_scope(node.kind()) {
            self.scopes.push("function");
            true
        } else {
            false
        };

        // Member chains we treat as a property of the *outermost* member
        // expression in a chain — descending into nested member nodes
        // would duplicate the chain prefix. The walker is therefore
        // structured so member-access nodes record their full chain
        // here and then skip child traversal for the chain segments.
        if config.member_kinds.contains(&node.kind()) {
            if let Some(chain) = static_dotted_chain(node, source, config) {
                let depth_n = u32::try_from(chain.matches('.').count()).unwrap_or(u32::MAX) + 1;
                if depth_n > self.max_member_chain_depth {
                    self.max_member_chain_depth = depth_n;
                }
                self.members.insert(chain);
            }
            // Continue walking children so we still find string
            // literals, call expressions, etc. inside member chains —
            // we only suppress *recording the inner member nodes* by
            // emitting from the top-most call site.
        }

        if config.call_kinds.contains(&node.kind()) {
            self.record_call(node, source, config);
        }

        if is_assignment_kind(node.kind()) {
            self.record_assignment(node, source, config);
        }

        if config.array_kinds.contains(&node.kind()) {
            let len = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
            if len > self.max_array_literal_length {
                self.max_array_literal_length = len;
            }
        }

        // String concatenation chains: `a + b + c + ...` builds
        // left-leaning nested binary expressions in every grammar we
        // support. Measure the chain length when we hit the *outermost*
        // node (the one whose parent isn't also a `+` binary
        // expression), then skip recursion into the chain.
        if is_string_concat_root(node, config) {
            let len = string_concat_chain_length(node, config);
            if len > self.max_string_concat_chain {
                self.max_string_concat_chain = len;
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_node(child, source, config, depth + 1);
        }

        if pushed_scope {
            self.scopes.pop();
        }
    }

    fn record_call(&mut self, node: Node<'_>, source: &str, config: &LangConfig) {
        let callee = node
            .child_by_field_name(config.callee_field)
            .or_else(|| first_named_child(node));
        let args_node = node.child_by_field_name(config.arguments_field);

        let target = callee.and_then(|c| static_dotted_chain(c, source, config));
        if config.name == "bash" && target.as_deref().is_some_and(|t| t.starts_with('-')) {
            return;
        }

        let mut shapes: Vec<ArgShape> = Vec::new();
        let mut literal_strings: Vec<String> = Vec::new();
        if config.arguments_field == "argument" {
            let mut cursor = node.walk();
            for arg in node.children_by_field_name(config.arguments_field, &mut cursor) {
                shapes.push(arg_shape(arg, config));
                collect_string_literals(arg, source, config, &mut literal_strings);
            }
        } else if let Some(args) = args_node {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                if arg.kind() == "command_argument_sep" {
                    continue;
                }
                shapes.push(arg_shape(arg, config));
                collect_string_literals(arg, source, config, &mut literal_strings);
            }
        }

        if let Some(t) = &target {
            if !literal_strings.is_empty() {
                let entry = self.literal_args.entry(t.clone()).or_default();
                for s in literal_strings {
                    entry.insert(s);
                }
            }
        }

        self.calls.push(Call {
            target,
            args: shapes,
        });
    }

    fn record_assignment(&mut self, node: Node<'_>, source: &str, config: &LangConfig) {
        let Some(target_node) = assignment_target(node) else {
            return;
        };
        let Some(value_node) = assignment_value(node) else {
            return;
        };
        let Some(target) = static_dotted_chain(target_node, source, config) else {
            return;
        };
        let string = if config.string_kinds.contains(&value_node.kind()) {
            decode_string_literal(value_node, source)
        } else {
            None
        };
        self.binds.push(Assignment {
            target,
            scope: self.scopes.last().copied().unwrap_or("module"),
            shape: arg_shape(value_node, config),
            string,
            offset: target_node.start_byte() as u64,
        });
    }
}

fn arg_shape(node: Node<'_>, config: &LangConfig) -> ArgShape {
    let k = node.kind();
    if config.string_kinds.contains(&k) {
        ArgShape::String
    } else if config.number_kinds.contains(&k) {
        ArgShape::Number
    } else if config.bool_kinds.contains(&k) {
        ArgShape::Bool
    } else if config.null_kinds.contains(&k) {
        ArgShape::Null
    } else if config.identifier_kinds.contains(&k) {
        ArgShape::Identifier
    } else if config.object_kinds.contains(&k) {
        ArgShape::Object
    } else if config.array_kinds.contains(&k) {
        ArgShape::Array
    } else if config.function_kinds.contains(&k) {
        ArgShape::Function
    } else if config.template_kinds.contains(&k) {
        ArgShape::Template
    } else if config.call_kinds.contains(&k) {
        ArgShape::Call
    } else {
        ArgShape::Expression
    }
}

/// Resolve a callee or member-access node into its static dotted path,
/// `a.b.c`. Returns `None` for any chain that contains a non-static
/// element (computed property, call result, parenthesised expression
/// other than the leftmost root, …).
fn static_dotted_chain(node: Node<'_>, source: &str, config: &LangConfig) -> Option<String> {
    if config.identifier_kinds.contains(&node.kind()) {
        return node.utf8_text(source.as_bytes()).ok().map(str::to_string);
    }
    if config.member_kinds.contains(&node.kind()) {
        let object = node.child_by_field_name(config.member_object_field)?;
        let prop = node.child_by_field_name(config.member_property_field)?;
        let object_path = static_dotted_chain(object, source, config)?;
        let prop_text = prop.utf8_text(source.as_bytes()).ok()?;
        if prop_text.is_empty() {
            return None;
        }
        return Some(format!("{object_path}.{prop_text}"));
    }
    if config.call_kinds.contains(&node.kind()) {
        let callee = node
            .child_by_field_name(config.callee_field)
            .or_else(|| first_named_child(node))?;
        let target = static_dotted_chain(callee, source, config)?;
        return Some(format!("{target}()"));
    }
    None
}

fn collect_string_literals(
    node: Node<'_>,
    source: &str,
    config: &LangConfig,
    out: &mut Vec<String>,
) {
    if config.string_kinds.contains(&node.kind()) {
        if let Some(text) = decode_string_literal(node, source) {
            out.push(text);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if config.function_kinds.contains(&child.kind())
            || config.call_kinds.contains(&child.kind())
        {
            continue;
        }
        collect_string_literals(child, source, config, out);
    }
}

fn is_assignment_kind(kind: &str) -> bool {
    matches!(
        kind,
        "assignment"
            | "assignment_expression"
            | "augmented_assignment"
            | "assignment_statement"
            | "variable_declarator"
            | "variable_assignment"
            | "operator_assignment"
            | "global_variable"
    )
}

fn assignment_target(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| node.child_by_field_name("variable"))
}

fn assignment_value(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))
}

fn is_function_scope(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "function_declaration"
            | "generator_function_declaration"
            | "method_definition"
            | "method_declaration"
            | "constructor_declaration"
            | "function_expression"
            | "arrow_function"
            | "lambda"
            | "method"
            | "singleton_method"
            | "function_statement"
    )
}

fn is_class_scope(kind: &str, language: &str) -> bool {
    if kind == "module" {
        return language == "ruby";
    }
    matches!(
        kind,
        "class_definition"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "class"
            | "class_statement"
    )
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next();
    first
}

fn is_string_concat_root(node: Node<'_>, config: &LangConfig) -> bool {
    if !config.binary_op_kinds.contains(&node.kind()) {
        return false;
    }
    let op_text = node
        .child_by_field_name("operator")
        .and_then(NodeOpExt::utf8_text_lossy_static)
        .unwrap_or("");
    if op_text != "+" {
        return false;
    }
    // Root only if the parent isn't also a `+` binary expression
    // (otherwise we'd record the chain at every level).
    !matches!(
        node.parent(),
        Some(p) if config.binary_op_kinds.contains(&p.kind())
    )
}

fn string_concat_chain_length(node: Node<'_>, config: &LangConfig) -> u32 {
    // Count leaves under a nested `+` chain. The chain looks like
    // `(a + b) + c + d` → BinaryExpr(BinaryExpr(BinaryExpr(a, b), c), d).
    fn descend(node: Node<'_>, config: &LangConfig, acc: &mut u32) {
        if config.binary_op_kinds.contains(&node.kind()) {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                descend(child, config, acc);
            }
        } else {
            *acc += 1;
        }
    }
    let mut acc = 0;
    descend(node, config, &mut acc);
    acc
}

fn decode_string_literal(node: Node<'_>, source: &str) -> Option<String> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    if raw.len() < 2 {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut start = 0_usize;
    while start < bytes.len()
        && matches!(
            bytes[start],
            b'b' | b'B' | b'r' | b'R' | b'f' | b'F' | b'u' | b'U'
        )
    {
        start += 1;
    }
    let mut end = bytes.len();
    if start >= end {
        return None;
    }
    let open = bytes[start];
    if !matches!(open, b'"' | b'\'' | b'`') {
        return None;
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

/// Helper trait for nodes that lets us pull the operator text without
/// importing tree-sitter throughout this module. The static-lifetime
/// `&'static str` is required because the operator in our grammars is
/// always a literal token; we accept that we'll borrow it.
trait NodeOpExt {
    fn utf8_text_lossy_static(self) -> Option<&'static str>;
}

impl NodeOpExt for Node<'_> {
    fn utf8_text_lossy_static(self) -> Option<&'static str> {
        // The `operator` field on binary-expression nodes is an anonymous
        // node whose kind name *is* the operator string in every grammar
        // we use ("+", "-", etc.). `kind()` returns a `&'static str`,
        // which is what we want here.
        Some(self.kind())
    }
}
