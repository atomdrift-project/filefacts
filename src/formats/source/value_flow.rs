//! Source-language producer for the shared flow view.
use super::langs::{Lang, LangConfig};
use super::{MAX_FLOW_DEPTH, ast_walk, named_children};
use crate::{Arg, Flow, FlowFunction, FlowKind, FlowValue, Symbol, Symbols};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

const NODE_LIMIT: usize = 20_000;
const STEP_LIMIT: usize = 100_000;

struct Builder<'a> {
    source: &'a str,
    config: &'a LangConfig,
    aliases: BTreeMap<String, String>,
    flow: Flow,
    steps: usize,
    in_function: bool,
}

fn definition(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_item"
            | "function_definition"
            | "function_declaration"
            | "method_declaration"
            | "method_definition"
            | "function_expression"
            | "arrow_function"
            | "func_literal"
            | "method"
            | "singleton_method"
            | "local_function"
            | "lambda"
    )
}

fn field_nested<'a>(mut node: Node<'a>, field: &str) -> Option<Node<'a>> {
    for _ in 0..32 {
        if let Some(value) = node.child_by_field_name(field) {
            return Some(value);
        }
        node = node.child_by_field_name("declarator")?;
    }
    None
}

fn function_name(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..32 {
        if let Some(name) = node.child_by_field_name("name") {
            return Some(name);
        }
        node = node.child_by_field_name("declarator")?;
        if node.kind().ends_with("identifier") {
            return Some(node);
        }
    }
    None
}

impl Builder<'_> {
    fn text(&self, n: Node<'_>) -> &str {
        &self.source[n.byte_range()]
    }
    /// A Python f-string decodes as a string argument, but its `{…}`
    /// interpolations carry values, so it is evaluated as an expression.
    fn interpolates(&self, node: Node<'_>) -> bool {
        self.config.lang == Lang::Python
            && named_children(node)
                .iter()
                .any(|child| child.kind() == "interpolation")
    }
    fn add(&mut self, kind: FlowKind, node: Node<'_>, inputs: Vec<usize>) -> usize {
        if self.flow.values.len() >= NODE_LIMIT {
            self.flow.limitations.insert("node-budget".into());
            return 0;
        }
        let id = self.flow.values.len();
        self.flow.values.push(FlowValue {
            kind,
            offset: node.start_byte(),
            literal: None,
            target: None,
            inputs,
            receiver: None,
            fields: BTreeMap::new(),
        });
        id
    }
    fn bind(&self, node: Node<'_>, value: usize, bindings: &mut BTreeMap<String, usize>) {
        if self.config.identifier_kinds.contains(&node.kind()) {
            bindings.insert(self.text(node).to_string(), value);
        } else if matches!(
            node.kind(),
            "expression_list" | "pattern_list" | "tuple_pattern"
        ) {
            for child in named_children(node) {
                self.bind(child, value, bindings);
            }
        } else if let Some(declarator) = node.child_by_field_name("declarator") {
            self.bind(declarator, value, bindings);
        }
    }
    fn eval(
        &mut self,
        node: Node<'_>,
        bindings: &mut BTreeMap<String, usize>,
        returns: &mut Vec<usize>,
        depth: usize,
    ) -> usize {
        if self.steps == STEP_LIMIT
            || depth > MAX_FLOW_DEPTH
            || self.flow.values.len() >= NODE_LIMIT
        {
            self.flow.limitations.insert("analysis-budget".into());
            return 0;
        }
        self.steps += 1;
        if definition(node) {
            // The outer function walk deliberately stops at named functions.
            // Anonymous definitions encountered while evaluating their bodies
            // must report the same limitation as top-level callbacks, rather
            // than silently omitting all calls inside the callback.
            if function_name(node).is_none() {
                self.flow.limitations.insert("anonymous-function".into());
            } else if self.in_function {
                self.flow.limitations.insert("nested-function".into());
            }
            return 0;
        }
        if node.kind().contains("comment")
            || node.kind().starts_with("import")
            || node.kind() == "use_declaration"
        {
            return 0;
        }
        if self.config.identifier_kinds.contains(&node.kind()) {
            return bindings.get(self.text(node)).copied().unwrap_or(0);
        }
        let literal = ast_walk::build_arg(node, self.source, self.config);
        if matches!(
            literal,
            Arg::String { .. }
                | Arg::Number { .. }
                | Arg::Bool { .. }
                | Arg::Null
                | Arg::Template { .. }
        ) && !self.interpolates(node)
        {
            let id = self.add(FlowKind::Literal, node, Vec::new());
            if id != 0
                && let Some(value) = self.flow.values.get_mut(id)
            {
                value.literal = Some(literal);
            }
            return id;
        }
        // Some grammars name the `+=` form directly; others reuse the plain
        // assignment kind and hang the operator off it. Each kind is named
        // once here so the two spellings cannot drift apart.
        let augmented = matches!(
            node.kind(),
            "augmented_assignment_expression" | "augmented_assignment" | "compound_assignment_expr"
        );
        if augmented
            || matches!(
                node.kind(),
                "assignment"
                    | "assignment_expression"
                    | "assignment_statement"
                    | "short_var_declaration"
                    | "let_declaration"
                    | "let_condition"
                    | "variable_declarator"
                    | "var_spec"
                    | "init_declarator"
            )
        {
            let target = node
                .child_by_field_name("left")
                .or_else(|| node.child_by_field_name("pattern"))
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| node.child_by_field_name("declarator"));
            let value = node
                .child_by_field_name("right")
                .or_else(|| node.child_by_field_name("value"));
            if let (Some(target), Some(value)) = (target, value) {
                let compound = augmented
                    || node
                        .child_by_field_name("operator")
                        .is_some_and(|operator| !matches!(self.text(operator), "=" | ":="));
                let previous = if compound {
                    // Go wraps even a single assignment place in an
                    // expression_list. Do not treat that wrapper as a new name.
                    let place =
                        if target.kind() == "expression_list" && target.named_child_count() == 1 {
                            target.named_child(0).unwrap_or(target)
                        } else {
                            target
                        };
                    if self.config.identifier_kinds.contains(&place.kind()) {
                        bindings.get(self.text(place)).copied().unwrap_or(0)
                    } else {
                        self.flow
                            .limitations
                            .insert("compound-assignment-target".into());
                        0
                    }
                } else {
                    0
                };
                let value_id = self.eval(value, bindings, returns, depth + 1);
                let id = if compound {
                    self.add(FlowKind::Merge, node, vec![previous, value_id])
                } else {
                    value_id
                };
                self.bind(target, id, bindings);
                return id;
            }
        }
        if self.config.call_kinds.contains(&node.kind()) {
            let callee = self.config.callee(node);
            let mut inputs = Vec::new();
            if self.config.arguments_field == "argument" {
                let mut cursor = node.walk();
                for arg in node.children_by_field_name("argument", &mut cursor) {
                    inputs.push(self.eval(arg, bindings, returns, depth + 1));
                }
            } else if let Some(args) = self.config.argument_list(node) {
                if self.config.is_single_argument(args) {
                    inputs.push(self.eval(args, bindings, returns, depth + 1));
                } else {
                    for arg in named_children(args) {
                        inputs.push(self.eval(arg, bindings, returns, depth + 1));
                    }
                }
            }
            let receiver = callee
                .and_then(|n| n.child_by_field_name(self.config.member_object_field))
                .map(|n| self.eval(n, bindings, returns, depth + 1));
            let id = self.add(FlowKind::Call, node, inputs);
            // Nested calls can have the same start offset (f().g()). Resolve
            // this callee with the symbol extractor's shared syntax helper;
            // an offset-to-single-target map would conflate the calls.
            let mut target =
                callee.and_then(|n| ast_walk::static_dotted_chain(n, self.source, self.config, 0));
            if let Some(raw) = target.as_ref() {
                let end = raw.find(['.', ':', '(']).unwrap_or(raw.len());
                if !bindings.contains_key(&raw[..end]) {
                    if let Some(prefix) = self.aliases.get(&raw[..end]) {
                        target = Some(format!("{prefix}{}", &raw[end..]));
                    }
                }
            }
            if id != 0
                && let Some(value) = self.flow.values.get_mut(id)
            {
                value.target = target;
                value.receiver = receiver;
            }
            return id;
        }
        if self.config.object_kinds.contains(&node.kind()) || node.kind() == "keyword_argument" {
            let mut fields = BTreeMap::new();
            let entries = if node.kind() == "keyword_argument" {
                vec![node]
            } else {
                named_children(node)
            };
            for entry in entries {
                let key = entry
                    .child_by_field_name("key")
                    .or_else(|| entry.child_by_field_name("name"));
                if let (Some(key), Some(value)) = (key, entry.child_by_field_name("value")) {
                    let key = self.text(key).trim_matches(['\'', '"']).to_string();
                    fields.insert(key, self.eval(value, bindings, returns, depth + 1));
                } else if entry.kind() == "shorthand_property_identifier" {
                    fields.insert(
                        self.text(entry).into(),
                        bindings.get(self.text(entry)).copied().unwrap_or(0),
                    );
                } else {
                    self.flow
                        .limitations
                        .insert("unresolved-object-field".into());
                }
            }
            let kind = if node.kind() == "keyword_argument" {
                FlowKind::Keyword
            } else {
                FlowKind::Object
            };
            let id = self.add(kind, node, Vec::new());
            if id != 0
                && let Some(value) = self.flow.values.get_mut(id)
            {
                value.fields = fields;
            }
            return id;
        }
        if matches!(node.kind(), "if_statement" | "if_expression") {
            // Go's initializer executes before the condition and is visible
            // in both branches. Short declarations belong to the implicit if
            // scope; ordinary assignments still update the surrounding scope.
            let mut shadowed = BTreeMap::new();
            if self.config.lang == Lang::Go {
                if let Some(initializer) = node.child_by_field_name("initializer") {
                    if initializer.kind() == "short_var_declaration" {
                        if let Some(pattern) = initializer.child_by_field_name("left") {
                            let mut declared = BTreeMap::new();
                            self.bind(pattern, 0, &mut declared);
                            for name in declared.into_keys() {
                                let previous = bindings.get(&name).copied();
                                shadowed.insert(name, previous);
                            }
                        }
                    }
                    self.eval(initializer, bindings, returns, depth + 1);
                }
            }
            if let Some(condition) = node.child_by_field_name("condition") {
                self.eval(condition, bindings, returns, depth + 1);
            }
            let mut merged = bindings.clone();
            let mut values = Vec::new();
            for field in ["consequence", "alternative"] {
                if let Some(branch) = node.child_by_field_name(field) {
                    let mut local = bindings.clone();
                    values.push(self.eval(branch, &mut local, returns, depth + 1));
                    for (name, id) in local {
                        if let Some(previous) = merged.get(&name).copied() {
                            if previous != id {
                                merged.insert(
                                    name,
                                    self.add(FlowKind::Merge, branch, vec![previous, id]),
                                );
                            }
                        } else {
                            merged.insert(name, id);
                        }
                    }
                }
            }
            for (name, previous) in shadowed {
                if let Some(id) = previous {
                    merged.insert(name, id);
                } else {
                    merged.remove(&name);
                }
            }
            *bindings = merged;
            return self.add(FlowKind::Merge, node, values);
        }
        let sequential = matches!(
            node.kind(),
            "source_file"
                | "program"
                | "module"
                | "block"
                | "statement_block"
                | "compound_statement"
        );
        let scoped = sequential
            && !matches!(node.kind(), "source_file" | "program" | "module")
            && matches!(
                self.config.lang,
                Lang::Rust
                    | Lang::Go
                    | Lang::JavaScript
                    | Lang::TypeScript
                    | Lang::C
                    | Lang::Java
                    | Lang::CSharp
            );
        let before = if scoped {
            bindings.clone()
        } else {
            BTreeMap::new()
        };
        let mut declared = BTreeMap::new();
        if scoped {
            for child in named_children(node) {
                let declarations = if matches!(
                    child.kind(),
                    "lexical_declaration"
                        | "var_declaration"
                        | "local_variable_declaration"
                        | "declaration"
                ) {
                    named_children(child)
                } else {
                    vec![child]
                };
                for declaration in declarations {
                    if matches!(
                        declaration.kind(),
                        "let_declaration"
                            | "short_var_declaration"
                            | "variable_declarator"
                            | "var_spec"
                            | "init_declarator"
                    ) {
                        if let Some(pattern) = declaration
                            .child_by_field_name("pattern")
                            .or_else(|| declaration.child_by_field_name("left"))
                            .or_else(|| declaration.child_by_field_name("name"))
                            .or_else(|| declaration.child_by_field_name("declarator"))
                        {
                            self.bind(pattern, 0, &mut declared);
                        }
                    }
                }
            }
        }
        let mut inputs = Vec::new();
        for child in named_children(node) {
            inputs.push(self.eval(child, bindings, returns, depth + 1));
        }
        for name in declared.keys() {
            if let Some(previous) = before.get(name) {
                bindings.insert(name.clone(), *previous);
            } else {
                bindings.remove(name);
            }
        }
        if node.kind().starts_with("return") {
            returns.extend(inputs.iter().copied());
        }
        if sequential {
            return inputs.last().copied().unwrap_or(0);
        }
        match inputs.as_slice() {
            [] => 0,
            [only] => *only,
            _ => self.add(FlowKind::Merge, node, inputs),
        }
    }
}

pub(super) fn build(root: Node<'_>, source: &str, config: &LangConfig, symbols: &Symbols) -> Flow {
    let mut builder = Builder {
        source,
        config,
        aliases: BTreeMap::new(),
        flow: Flow {
            version: 1,
            producer: "tree-sitter".into(),
            language: config.name().into(),
            ..Default::default()
        },
        steps: 0,
        in_function: false,
    };
    builder
        .flow
        .limitations
        .insert("source-local-may-flow-not-reachability".into());
    if config.lang == Lang::Go {
        builder.aliases = super::go_syntax::imports(root, source)
            .into_iter()
            .collect();
    }
    for symbol in symbols {
        if let Symbol::Import { name, alias, .. } = symbol {
            let alias = alias.clone().or_else(|| {
                (config.lang == Lang::Rust)
                    .then(|| name.rsplit("::").next().unwrap_or(name).to_string())
            });
            if let Some(alias) = alias.filter(|alias| alias != "*") {
                builder.aliases.insert(alias, name.clone());
            }
        }
    }
    if source.len() > 2 * 1024 * 1024 {
        builder.flow.limitations.insert("source-byte-budget".into());
    } else {
        builder.add(FlowKind::Unknown, root, Vec::new());
        let mut globals = BTreeMap::new();
        builder.eval(root, &mut globals, &mut Vec::new(), 0);
        let mut stack = vec![root];
        let mut duplicate_names = BTreeSet::new();
        while let Some(node) = stack.pop() {
            if builder.steps >= STEP_LIMIT {
                builder.flow.limitations.insert("analysis-budget".into());
                break;
            }
            if definition(node) {
                let Some(name) = function_name(node) else {
                    builder.flow.limitations.insert("anonymous-function".into());
                    continue;
                };
                let name = builder.text(name).to_string();
                let mut function = FlowFunction::default();
                let mut bindings = globals.clone();
                if let Some(params) = field_nested(node, "parameters") {
                    for param in named_children(params) {
                        let pattern = param
                            .child_by_field_name("pattern")
                            .or_else(|| param.child_by_field_name("name"))
                            .or_else(|| param.child_by_field_name("declarator"))
                            .unwrap_or(param);
                        let id = builder.add(FlowKind::Parameter, param, Vec::new());
                        builder.bind(pattern, id, &mut bindings);
                        function.parameters.push(id);
                    }
                }
                if let Some(body) = node.child_by_field_name("body") {
                    builder.in_function = true;
                    let tail = builder.eval(body, &mut bindings, &mut function.returns, 0);
                    builder.in_function = false;
                    if config.lang == Lang::Rust {
                        function.returns.push(tail);
                    }
                }
                if builder
                    .flow
                    .functions
                    .insert(name.clone(), function)
                    .is_some()
                {
                    duplicate_names.insert(name);
                }
                continue;
            }
            stack.extend(named_children(node));
        }
        for name in duplicate_names {
            builder.flow.functions.remove(&name);
            builder.flow.limitations.insert("ambiguous-helper".into());
        }
        if root.has_error() {
            builder.flow.limitations.insert("parse-error".into());
        }
    }
    builder.flow
}

#[cfg(test)]
mod tests;
