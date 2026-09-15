//! Source-language producer for the shared flow view.
use super::{ast_walk, langs::LangConfig};
use crate::{Arg, Flow, FlowFunction, FlowValue, Symbol, Symbols};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tree_sitter::Node;

const NODE_LIMIT: usize = 20_000;
const STEP_LIMIT: usize = 100_000;

struct Builder<'a> {
    source: &'a str,
    config: &'a LangConfig,
    aliases: HashMap<String, String>,
    flow: Flow,
    steps: usize,
    in_function: bool,
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
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
    fn add(&mut self, kind: &str, node: Node<'_>, inputs: Vec<usize>) -> usize {
        if self.flow.values.len() >= NODE_LIMIT {
            self.flow.limitations.insert("node-budget".into());
            return 0;
        }
        let id = self.flow.values.len();
        self.flow.values.push(FlowValue {
            kind: kind.into(),
            offset: node.start_byte(),
            literal: None,
            target: None,
            inputs,
            receiver: None,
            fields: BTreeMap::new(),
        });
        id
    }
    fn bind(&self, node: Node<'_>, value: usize, bindings: &mut HashMap<String, usize>) {
        if self.config.identifier_kinds.contains(&node.kind()) {
            bindings.insert(self.text(node).to_string(), value);
        } else if matches!(
            node.kind(),
            "expression_list" | "pattern_list" | "tuple_pattern"
        ) {
            for child in children(node) {
                self.bind(child, value, bindings);
            }
        } else if let Some(declarator) = node.child_by_field_name("declarator") {
            self.bind(declarator, value, bindings);
        }
    }
    fn eval(
        &mut self,
        node: Node<'_>,
        bindings: &mut HashMap<String, usize>,
        returns: &mut Vec<usize>,
        depth: usize,
    ) -> usize {
        if self.steps == STEP_LIMIT || depth > 96 || self.flow.values.len() >= NODE_LIMIT {
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
        ) {
            let id = self.add("literal", node, Vec::new());
            if id != 0 {
                self.flow.values[id].literal = Some(literal);
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
                    self.add("merge", node, vec![previous, value_id])
                } else {
                    value_id
                };
                self.bind(target, id, bindings);
                return id;
            }
        }
        if self.config.call_kinds.contains(&node.kind()) {
            let callee = if self.config.name == "perl" && node.kind() == "method_call_expression" {
                Some(node)
            } else {
                node.child_by_field_name(self.config.callee_field)
            };
            let mut inputs = Vec::new();
            if self.config.arguments_field == "argument" {
                let mut cursor = node.walk();
                for arg in node.children_by_field_name("argument", &mut cursor) {
                    inputs.push(self.eval(arg, bindings, returns, depth + 1));
                }
            } else if let Some(args) = self.config.argument_list(node) {
                if self.config.name == "perl" && args.kind() != "list_expression" {
                    inputs.push(self.eval(args, bindings, returns, depth + 1));
                } else {
                    for arg in children(args) {
                        inputs.push(self.eval(arg, bindings, returns, depth + 1));
                    }
                }
            }
            let receiver = callee
                .and_then(|n| n.child_by_field_name(self.config.member_object_field))
                .map(|n| self.eval(n, bindings, returns, depth + 1));
            let id = self.add("call", node, inputs);
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
            if id != 0 {
                self.flow.values[id].target = target;
                self.flow.values[id].receiver = receiver;
            }
            return id;
        }
        if self.config.object_kinds.contains(&node.kind()) || node.kind() == "keyword_argument" {
            let mut fields = BTreeMap::new();
            let entries = if node.kind() == "keyword_argument" {
                vec![node]
            } else {
                children(node)
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
                "keyword"
            } else {
                "object"
            };
            let id = self.add(kind, node, Vec::new());
            if id != 0 {
                self.flow.values[id].fields = fields;
            }
            return id;
        }
        if matches!(node.kind(), "if_statement" | "if_expression") {
            // Go's initializer executes before the condition and is visible
            // in both branches. Short declarations belong to the implicit if
            // scope; ordinary assignments still update the surrounding scope.
            let mut shadowed = HashMap::new();
            if self.config.name == "go" {
                if let Some(initializer) = node.child_by_field_name("initializer") {
                    if initializer.kind() == "short_var_declaration" {
                        if let Some(pattern) = initializer.child_by_field_name("left") {
                            let mut declared = HashMap::new();
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
                                merged.insert(name, self.add("merge", branch, vec![previous, id]));
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
            return self.add("merge", node, values);
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
                self.config.name,
                "rust" | "go" | "javascript" | "typescript" | "c" | "java" | "csharp"
            );
        let before = if scoped {
            bindings.clone()
        } else {
            HashMap::new()
        };
        let mut declared = HashMap::new();
        if scoped {
            for child in children(node) {
                let declarations = if matches!(
                    child.kind(),
                    "lexical_declaration"
                        | "var_declaration"
                        | "local_variable_declaration"
                        | "declaration"
                ) {
                    children(child)
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
        for child in children(node) {
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
        if inputs.len() == 1 {
            return inputs[0];
        }
        if inputs.is_empty() {
            return 0;
        }
        self.add("merge", node, inputs)
    }
}

pub(super) fn build(root: Node<'_>, source: &str, config: &LangConfig, symbols: &Symbols) -> Flow {
    let mut builder = Builder {
        source,
        config,
        aliases: HashMap::new(),
        flow: Flow {
            version: 1,
            producer: "tree-sitter".into(),
            language: config.name.into(),
            ..Default::default()
        },
        steps: 0,
        in_function: false,
    };
    builder
        .flow
        .limitations
        .insert("source-local-may-flow-not-reachability".into());
    if config.name == "go" {
        builder.aliases = super::go_syntax::imports(root, source);
    }
    for symbol in symbols {
        if let Symbol::Import { name, alias, .. } = symbol {
            let alias = alias.clone().or_else(|| {
                (config.name == "rust")
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
        builder.add("unknown", root, Vec::new());
        let mut globals = HashMap::new();
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
                    for param in children(params) {
                        let pattern = param
                            .child_by_field_name("pattern")
                            .or_else(|| param.child_by_field_name("name"))
                            .or_else(|| param.child_by_field_name("declarator"))
                            .unwrap_or(param);
                        let id = builder.add("parameter", param, Vec::new());
                        builder.bind(pattern, id, &mut bindings);
                        function.parameters.push(id);
                    }
                }
                if let Some(body) = node.child_by_field_name("body") {
                    builder.in_function = true;
                    let tail = builder.eval(body, &mut bindings, &mut function.returns, 0);
                    builder.in_function = false;
                    if config.name == "rust" {
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
            stack.extend(children(node));
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
mod tests {
    use super::*;
    use crate::FlowTransfer;
    fn graph(path: &str, source: &str) -> Flow {
        let file = crate::open_with_path(std::path::Path::new(path), source.as_bytes()).unwrap();
        file.flow().unwrap().clone()
    }
    fn reaches(flow: &Flow, sink: &str, source: &str) -> bool {
        flow.values
            .iter()
            .filter(|v| v.target.as_deref() == Some(sink))
            .any(|v| {
                v.inputs.iter().any(|id| {
                    flow.origins(*id, &[], 1000)
                        .values
                        .iter()
                        .any(|id| flow.values[id.value].target.as_deref() == Some(source))
                })
            })
    }
    #[test]
    fn anonymous_function_limitations_survive_named_function_boundaries() {
        for (path, source) in [
            ("a.js", "register(() => send(acquire()));"),
            (
                "a.js",
                "function activate(){register(() => send(acquire()));}",
            ),
            (
                "a.js",
                "function activate(){register(function(){send(acquire());});}",
            ),
            (
                "a.ts",
                "function activate(){register(() => send(acquire()));}",
            ),
            (
                "a.py",
                "def activate():\n register(lambda: send(acquire()))\n",
            ),
            (
                "a.go",
                "package p\nfunc activate(){register(func(){send(acquire())})}",
            ),
        ] {
            let flow = graph(path, source);
            assert!(
                !flow.limitations.contains("parse-error"),
                "{path}: {flow:?}"
            );
            assert!(
                flow.limitations.contains("anonymous-function"),
                "{path}: {flow:?}"
            );
            assert!(
                flow.values
                    .iter()
                    .any(|v| v.target.as_deref() == Some("register")),
                "{path}"
            );
            // This diagnostic repair must not invent a modeled callback body.
            assert!(
                !flow
                    .values
                    .iter()
                    .any(|v| v.target.as_deref() == Some("send")),
                "{path}"
            );
        }
        let direct = graph("a.js", "function activate(){send(acquire());}");
        assert!(!direct.limitations.contains("anonymous-function"));
        assert!(reaches(&direct, "send", "acquire"));
        assert!(!direct.limitations.contains("nested-function"));
        let nested = graph(
            "a.js",
            "function outer(){function inner(){register(() => send(acquire()));} inner();}",
        );
        assert!(nested.limitations.contains("nested-function"));
        assert!(!nested.functions.contains_key("inner"));
        assert!(
            !nested
                .values
                .iter()
                .any(|v| v.target.as_deref() == Some("send"))
        );
    }
    #[test]
    fn shared_assignment_and_helper_contract() {
        for (path, source) in [
            (
                "a.py",
                "def identity(x):\n return x\ndef main():\n value=acquire()\n send(identity(value))\n",
            ),
            (
                "a.js",
                "function identity(x){return x} function main(){let value=acquire();send(identity(value));}",
            ),
            (
                "a.ts",
                "function identity(x:string){return x} function main(){let value=acquire();send(identity(value));}",
            ),
            (
                "a.rs",
                "fn identity(x:Data)->Data{x} fn main(){let value=acquire();send(identity(value));}",
            ),
            (
                "a.go",
                "package p\nfunc identity(x string)string{return x}\nfunc main(){value:=acquire();send(identity(value))}",
            ),
            (
                "a.c",
                "char *identity(char *x){return x;} void run(){char *value=acquire();send(identity(value));}",
            ),
        ] {
            let flow = graph(path, source);
            assert!(reaches(&flow, "send", "acquire"), "{path}: {flow:?}");
        }
    }

    #[test]
    fn compound_assignments_preserve_both_operands_and_later_overwrites() {
        for (path, prefix, initial, suffix) in [
            ("a.js", "function run(){", "let value=left();", "}"),
            ("a.ts", "function run(){", "let value=left();", "}"),
            ("a.py", "def run():\n ", "value=left();", "\n"),
            ("a.go", "package p\nfunc run(){", "value:=left();", "}"),
            ("a.rs", "fn run(){", "let mut value=left();", "}"),
            ("a.c", "void run(){", "int value=left();", "}"),
        ] {
            for (tail, left_expected, right_expected) in [
                ("value+=right();send(value);", true, true),
                ("value=right();send(value);", false, true),
                ("value+=right();value=0;send(value);", false, false),
                ("value+=right();send(0);", false, false),
                ("value+=opaque(right());send(value);", true, false),
            ] {
                let source = format!("{prefix}{initial}{tail}{suffix}");
                let flow = graph(path, &source);
                assert!(
                    !flow.limitations.contains("parse-error"),
                    "{path}: {source}"
                );
                assert_eq!(
                    reaches(&flow, "send", "left"),
                    left_expected,
                    "{path}: {source}"
                );
                assert_eq!(
                    reaches(&flow, "send", "right"),
                    right_expected,
                    "{path}: {source}"
                );
            }
        }
        let ordered = graph(
            "a.js",
            "function run(){let value=left();value+=(value=right());send(value);}",
        );
        assert!(reaches(&ordered, "send", "left"));
        assert!(reaches(&ordered, "send", "right"));
        for target in ["left", "right"] {
            assert_eq!(
                ordered
                    .values
                    .iter()
                    .filter(|v| v.target.as_deref() == Some(target))
                    .count(),
                1
            );
        }
        let member = graph(
            "a.js",
            "function run(){let obj={};obj.value+=right();send(obj.value);}",
        );
        assert!(member.limitations.contains("compound-assignment-target"));
        assert!(!reaches(&member, "send", "right"));
    }

    #[test]
    fn go_if_initializers_preserve_flow_and_lexical_scope() {
        for (body, sink, expected) in [
            (
                "if value := acquire(); value != nil { send(value) }",
                "send",
                true,
            ),
            ("if value := acquire(); check(value) {}", "check", true),
            (
                "if value := acquire(); flag { } else { send(value) }",
                "send",
                true,
            ),
            (
                "if value := acquire(); flag { } else if other { send(value) }",
                "send",
                true,
            ),
            (
                "if value, ok := acquire(); ok { send(value) }",
                "send",
                true,
            ),
            (
                "value := \"public\"; if value = acquire(); flag {}; send(value)",
                "send",
                true,
            ),
            (
                "value := \"public\"; if value := acquire(); flag { check(value) }; send(value)",
                "send",
                false,
            ),
            (
                "value := acquire(); if value := \"public\"; flag { check(value) }; send(value)",
                "send",
                true,
            ),
            (
                "if value := acquire(); flag { value = \"public\"; send(value) }",
                "send",
                false,
            ),
            (
                "if value := acquire(); flag { value := \"public\"; send(value) }",
                "send",
                false,
            ),
        ] {
            let source = format!("package p\nfunc run(){{ {body} }}");
            let flow = graph("a.go", &source);
            assert!(!flow.limitations.contains("parse-error"), "{body}");
            assert_eq!(reaches(&flow, sink, "acquire"), expected, "{body}");
            assert_eq!(
                flow.values
                    .iter()
                    .filter(|v| v.target.as_deref() == Some("acquire"))
                    .count(),
                1,
                "initializer calls must be retained exactly once: {body}",
            );
        }
    }
    #[test]
    fn helper_calls_do_not_contaminate_each_other() {
        let flow = graph(
            "a.js",
            "function identity(x){return x} function main(){identity(acquire());send(identity('constant'));}",
        );
        assert!(!reaches(&flow, "send", "acquire"));
        let flow = graph(
            "a.js",
            "function main(){let x='constant';{let x=acquire();}send(x);}",
        );
        assert!(!reaches(&flow, "send", "acquire"));
        let flow = graph(
            "a.js",
            "function main(){let x=acquire();{let x='constant';}send(x);}",
        );
        assert!(reaches(&flow, "send", "acquire"));
        let flow = graph(
            "a.js",
            "function main(){let x=acquire();x='constant';send(x);}",
        );
        assert!(!reaches(&flow, "send", "acquire"));
        let flow = graph("a.js", "function main(){send(opaque(acquire()));}");
        assert!(!reaches(&flow, "send", "acquire"));
    }

    #[test]
    fn transfer_models_and_budgets_are_explicit() {
        let flow = graph("a.js", "function run(){send(wrap(acquire()));}");
        let sink = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("send"))
            .unwrap()
            .inputs[0];
        let models = [FlowTransfer {
            call: "wrap".into(),
            arguments: vec![0],
            receiver: false,
        }];
        let found = flow.origins(sink, &models, 1000);
        assert!(
            found
                .values
                .iter()
                .any(|i| flow.values[i.value].target.as_deref() == Some("acquire"))
        );
        assert!(flow.origins(sink, &models, 0).incomplete);
        assert!(flow.origins(usize::MAX, &[], 1).incomplete);
    }

    #[test]
    fn object_fields_keep_authentication_separate_from_body() {
        let flow = graph(
            "a.js",
            "function run(){let token=acquire();send({headers:{Authorization:token},body:'status'});}",
        );
        let sink = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("send"))
            .unwrap();
        let object = &flow.values[sink.inputs[0]];
        let body = object.fields["body"];
        assert!(
            !flow
                .origins(body, &[], 1000)
                .values
                .iter()
                .any(|i| flow.values[i.value].target.as_deref() == Some("acquire"))
        );
    }

    #[test]
    fn helper_returned_fields_preserve_invocation_and_ignore_headers() {
        for (path, source) in [
            (
                "a.js",
                "function options(name){return {headers:{Authorization:acquire('TOKEN')},body:acquire(name)}} function run(){options('TOKEN');send(options('PUBLIC'))}",
            ),
            (
                "a.ts",
                "function options(name:string){return {headers:{Authorization:acquire('TOKEN')},body:acquire(name)}} function run(){options('TOKEN');send(options('PUBLIC'))}",
            ),
            (
                "a.py",
                "def options(name):\n    return {'headers': {'Authorization': acquire('TOKEN')}, 'body': acquire(name)}\ndef run():\n    options('TOKEN')\n    send(options('PUBLIC'))\n",
            ),
        ] {
            let flow = graph(path, source);
            let sink = flow
                .values
                .iter()
                .find(|v| v.target.as_deref() == Some("send"))
                .unwrap();
            let models = [FlowTransfer {
                call: "acquire".into(),
                arguments: vec![],
                receiver: false,
            }];
            let found = flow.field_origins(sink.inputs[0], "body", &models, 1000);
            assert!(!found.incomplete, "{path}: {found:?}");
            let mut literals = Vec::new();
            for origin in &found.values {
                if flow.values[origin.value].target.as_deref() == Some("acquire") {
                    for argument in flow.argument_origins(origin, 0, &models, 1000).values {
                        if let Some(Arg::String { value }) = &flow.values[argument.value].literal {
                            literals.push(value.as_str());
                        }
                    }
                }
            }
            assert_eq!(literals, ["PUBLIC"], "{path}");
            assert!(
                flow.field_origins(sink.inputs[0], "body", &models, 0)
                    .incomplete
            );
        }
    }

    #[test]
    fn external_field_shapes_are_opaque_even_with_value_transfer_models() {
        let flow = graph("a.js", "function run(){send(opaque({body:acquire()}));}");
        let sink = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("send"))
            .unwrap();
        let models = [FlowTransfer {
            call: "opaque".into(),
            arguments: vec![0],
            receiver: false,
        }];
        let found = flow.field_origins(sink.inputs[0], "body", &models, 1000);
        assert!(found.incomplete);
        assert!(found.values.is_empty());
    }

    /// A method on a call result is its own value with its own target, and its
    /// receiver points at the inner call. The target is a plain dotted path —
    /// `acquire.unwrap`, not `acquire().unwrap` — because a call contributes
    /// only the name of what it called; the receiver link, not the spelling,
    /// is what records that a call sat in the middle.
    #[test]
    fn chained_calls_have_distinct_targets_and_receivers() {
        let flow = graph("a.rs", "fn run(){send(acquire(\"key\").unwrap());}");
        let outer = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("acquire.unwrap"))
            .unwrap();
        let inner = &flow.values[outer.receiver.unwrap()];
        assert_eq!(inner.offset, outer.offset);
        assert_eq!(inner.target.as_deref(), Some("acquire"));
        assert_eq!(inner.inputs.len(), 1);
        assert!(outer.inputs.is_empty());
    }

    #[test]
    fn argument_observations_preserve_helper_invocation_context() {
        for literal in ["PRIVATE", "PUBLIC"] {
            let source = format!(
                "function read(name){{return acquire(name)}} function run(){{read('OTHER');send(read('{literal}'));}}"
            );
            let flow = graph("a.js", &source);
            let sink = flow
                .values
                .iter()
                .find(|v| v.target.as_deref() == Some("send"))
                .unwrap()
                .inputs[0];
            let origins = flow.origins(sink, &[], 1000);
            let acquire = origins
                .values
                .iter()
                .find(|v| flow.values[v.value].target.as_deref() == Some("acquire"))
                .unwrap();
            let arguments = flow.argument_origins(acquire, 0, &[], 1000);
            let strings: Vec<_> = arguments
                .values
                .iter()
                .filter_map(|v| match flow.values[v.value].literal.as_ref() {
                    Some(Arg::String { value }) => Some(value.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(strings, vec![literal]);
        }
    }

    #[test]
    fn flow_is_lazy_cached_and_uses_the_existing_parse() {
        let file =
            crate::open_with_path(std::path::Path::new("a.py"), b"send(acquire())\n").unwrap();
        file.symbols();
        assert!(file.flow.get().is_none());
        let first = file.flow().unwrap();
        assert!(std::ptr::eq(first, file.flow().unwrap()));
        assert_eq!(file.parse_count(), 1);
        assert!(
            file.values().get("source.value_flow").is_none(),
            "typed facts must not be duplicated into values"
        );
    }
}
