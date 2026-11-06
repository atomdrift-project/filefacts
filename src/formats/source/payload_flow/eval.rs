//! The evaluator: which payload bits each syntax node carries.

use super::model::Body;
use super::{
    AUTHPATH, Analysis, Bindings, Bits, CARGO, CARGOHOME, CARGOPATH, CLIENT, CREDFILE,
    CREDFILENAME, CURL_COMMAND, CURL_DATA_NEXT, ENV, ENV_OBJECT, ENV_VALUE, FILE, PARAM_BITS,
    PARAM_COUNT, PARAM_START, REQUEST, SECRET, SECRETPATH, Summary, add_bits, python_imports,
};
use crate::formats::source::langs::Lang;
use crate::formats::source::{
    MAX_FLOW_DEPTH, decode_string_literal, expand_alias, named_children, text,
};
use std::collections::BTreeMap;
use tree_sitter::Node;

/// Path fragments of credential files.
const SECRET_PATHS: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    "id_rsa",
    "id_ed25519",
    ".env",
    ".kube/config",
    "application_default_credentials.json",
    ".terraform.d/credentials",
    "credentials.tfrc.json",
];
/// Path fragment of Cargo's credential file.
const CARGO_CREDENTIAL_PATH: &str = ".cargo/credentials";
/// File names that are Cargo's credential file once joined to `CARGO_HOME`.
const CARGO_CREDENTIAL_NAMES: &[&str] = &["credentials", "credentials.toml"];
/// Environment variable name fragments that hold secrets.
const SECRET_VARIABLES: &[&str] = &[
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
];

impl<'s> Analysis<'s> {
    fn text(&self, node: Node<'_>) -> &'s str {
        text(node, self.source)
    }

    pub(super) fn canonical(&self, name: &str) -> String {
        expand_alias(name, |head| self.aliases.get(head).map(String::as_str))
            .unwrap_or_else(|| name.to_string())
    }

    pub(super) fn bind(&self, pattern: Node<'_>, bits: Bits, bindings: &mut Bindings<'_>) {
        let mut stack = vec![pattern];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                bindings.insert(self.text(node).to_string(), bits);
            } else if !matches!(node.kind(), "type_identifier" | "scoped_identifier") {
                stack.extend(named_children(node));
            }
        }
    }

    /// Whether `node` starts `x.len()` or another
    /// [`super::model::Model::metadata_methods`] call written as tokens, inside a macro's
    /// token tree.
    fn metadata_tokens(&self, node: Node<'_>) -> bool {
        node.kind() == "identifier"
            && node.next_sibling().is_some_and(|dot| {
                self.text(dot) == "."
                    && dot.next_sibling().is_some_and(|method| {
                        self.model.metadata_methods.contains(&self.text(method))
                            && method
                                .next_sibling()
                                .is_some_and(|args| self.text(args) == "()")
                    })
            })
    }

    pub(super) fn eval(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        if self.budget == 0 || depth > MAX_FLOW_DEPTH {
            self.truncated = true;
            return 0;
        }
        self.budget -= 1;
        // Measured once: `Node::kind` measures and validates a C string.
        let kind = node.kind();
        if self.test_only.contains(&node.id())
            || self.config.is_function(node)
            || matches!(
                kind,
                "macro_definition" | "comment" | "line_comment" | "block_comment"
            )
        {
            return 0;
        }
        let text = self.text(node);
        if matches!(
            kind,
            "identifier" | "shorthand_field_identifier" | "shorthand_property_identifier"
        ) {
            return bindings.get(text).unwrap_or(0);
        }
        // Rust format! arguments are token trees rather than expression ASTs.
        // A metadata-only query consumes the source without returning its bytes.
        if self.language == Lang::Rust && kind == "token_tree" {
            let mut result = 0;
            for child in named_children(node) {
                if !self.metadata_tokens(child) {
                    result |= self.eval(child, bindings, out, depth + 1);
                }
            }
            return result;
        }
        if self.language == Lang::Rust && kind == "match_expression" {
            return self.match_expression(node, bindings, out, depth);
        }
        if kind == "macro_invocation"
            && node
                .child_by_field_name("macro")
                .is_some_and(|n| matches!(self.text(n), "format" | "format_args" | "std::format"))
        {
            return self.format_macro(node, bindings, out, depth);
        }
        if self.config.string_kinds.contains(&kind) {
            let value = decode_string_literal(node, self.source, self.config);
            let mut bits = path_bits(value.as_deref().unwrap_or(text));
            // A template's substitutions carry their own values.
            if self.config.template_kinds.contains(&kind) {
                for child in named_children(node) {
                    bits |= self.eval(child, bindings, out, depth + 1);
                }
            }
            return bits;
        }
        if matches!(kind, "import_statement" | "import_from_statement") {
            if self.language == Lang::Python {
                python_imports(node, self.source, &mut self.aliases);
            }
            return 0;
        }
        if matches!(
            kind,
            "let_declaration"
                | "let_condition"
                | "assignment"
                | "assignment_expression"
                | "variable_declarator"
                | "const_item"
                | "static_item"
                | "short_var_declaration"
                | "assignment_statement"
                | "var_spec"
        ) {
            let value = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("right"));
            let target = node
                .child_by_field_name("pattern")
                .or_else(|| node.child_by_field_name("left"))
                .or_else(|| node.child_by_field_name("name"));
            if let (Some(target), Some(value)) = (target, value) {
                if self.language == Lang::Go && target.kind() == "selector_expression" {
                    // `req.Body = …` replaces a request's body.
                    if target
                        .child_by_field_name("field")
                        .is_some_and(|n| self.text(n) == "Body")
                        && let Some(receiver) = target.child_by_field_name("operand")
                    {
                        let bits = self.eval(value, bindings, out, depth + 1);
                        let receiver = self.text(receiver);
                        if bindings
                            .get(receiver)
                            .is_some_and(|state| state & REQUEST != 0)
                        {
                            bindings.insert(receiver.to_string(), REQUEST | bits);
                        }
                    }
                    return 0;
                }
                let bits = self.eval(value, bindings, out, depth + 1);
                self.bind(target, bits, bindings);
                return 0;
            }
        }
        if matches!(
            kind,
            "for_expression" | "for_statement" | "for_in_statement" | "range_clause"
        ) {
            let iterable = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("right"));
            let pat = node
                .child_by_field_name("pattern")
                .or_else(|| node.child_by_field_name("left"));
            if let (Some(value), Some(pattern)) = (iterable, pat) {
                let bits = self.eval(value, bindings, out, depth + 1);
                self.bind(pattern, bits, bindings);
                if let Some(body) = node.child_by_field_name("body") {
                    self.eval(body, bindings, out, depth + 1);
                }
                return 0;
            }
        }
        if matches!(kind, "if_statement" | "if_expression") {
            return self.if_statement(node, bindings, out, depth);
        }
        if matches!(kind, "call_expression" | "call") {
            return self.call(node, bindings, out, depth + 1);
        }
        if kind == "return_statement" || kind == "return_expression" {
            let bits = self.all(node, bindings, out, depth + 1);
            out.returns |= bits;
            return bits;
        }
        if matches!(
            kind,
            "attribute"
                | "member_expression"
                | "subscript"
                | "subscript_expression"
                | "selector_expression"
        ) && let Some(bits) = self.member(node, bindings, out, depth)
        {
            return bits;
        }
        if self.language == Lang::Go
            && kind == "composite_literal"
            && node.child_by_field_name("type").is_some_and(|n| {
                self.model
                    .client_types
                    .contains(&self.canonical(self.text(n)).as_str())
            })
        {
            return CLIENT;
        }
        if matches!(
            kind,
            "block" | "statement_block" | "source_file" | "module" | "program"
        ) {
            return self.block(node, bindings, out, depth);
        }
        self.all(node, bindings, out, depth + 1)
    }

    fn match_expression(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let input = node
            .child_by_field_name("value")
            .map_or(0, |value| self.eval(value, bindings, out, depth + 1));
        let mut result = 0;
        let mut merged: BTreeMap<String, Bits> = BTreeMap::new();
        if let Some(body) = node.child_by_field_name("body") {
            for arm in named_children(body).filter(|n| n.kind() == "match_arm") {
                let mut branch = Bindings::under(bindings);
                let mut pattern_names = Bindings::default();
                if let Some(pattern) = arm.child_by_field_name("pattern") {
                    self.bind(pattern, input, &mut branch);
                    self.bind(pattern, 0, &mut pattern_names);
                }
                if let Some(value) = arm.child_by_field_name("value") {
                    result |= self.eval(value, &mut branch, out, depth + 1);
                }
                // Arm-local pattern bindings never escape the match.
                for (name, bits) in branch.bound() {
                    if pattern_names.get(name).is_none() {
                        *merged.entry(name.clone()).or_default() |= bits;
                    }
                }
            }
        }
        for (name, bits) in merged {
            add_bits(bindings, &name, bits);
        }
        result
    }

    /// `format!` and friends: the arguments, plus every binding named inline
    /// in a format string (`"{token}"`).
    fn format_macro(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let mut bits = self.all(node, bindings, out, depth + 1);
        let mut stack: Vec<_> = named_children(node).collect();
        while let Some(child) = stack.pop() {
            if child.kind() != "string_literal" {
                stack.extend(named_children(child));
                continue;
            }
            let literal = self.text(child);
            let bytes = literal.as_bytes();
            let mut index = 0;
            while let Some(&byte) = bytes.get(index) {
                if byte == b'{' {
                    if bytes.get(index + 1) == Some(&b'{') {
                        index += 2;
                        continue;
                    }
                    let start = index + 1;
                    let mut end = start;
                    while bytes
                        .get(end)
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    {
                        end += 1;
                    }
                    if end > start && matches!(bytes.get(end), Some(b'}' | b':')) {
                        bits |= literal
                            .get(start..end)
                            .and_then(|name| bindings.get(name))
                            .unwrap_or(0);
                    }
                }
                index += 1;
            }
        }
        bits
    }

    fn if_statement(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let condition = node.child_by_field_name("condition");
        // A literal boolean determines which branch can produce a payload.
        // Keep the alternative of `if false`; dropping both branches loses
        // real sends. Other conditions remain conservative branch unions.
        let constant = condition.and_then(|mut n| {
            while n.kind() == "parenthesized_expression" {
                n = n.named_child(0)?;
            }
            self.config
                .bool_kinds
                .contains(&n.kind())
                .then(|| self.text(n).eq_ignore_ascii_case("true"))
        });
        if let Some(condition) = condition {
            self.eval(condition, bindings, out, depth + 1);
        }
        // What the branches bind, unioned into the bindings before the `if`.
        // A name a branch leaves alone keeps its bits there, so only the
        // branch's own layer can add any.
        let mut merged: BTreeMap<String, Bits> = BTreeMap::new();
        let mut result = 0;
        for field in ["consequence", "alternative"] {
            if constant.is_some_and(|value| value != (field == "consequence")) {
                continue;
            }
            if let Some(branch) = node.child_by_field_name(field) {
                let mut branch_bindings = Bindings::under(bindings);
                result |= self.eval(branch, &mut branch_bindings, out, depth + 1);
                for (name, bits) in branch_bindings.bound() {
                    *merged.entry(name.clone()).or_default() |= bits;
                }
            }
        }
        for (name, bits) in merged {
            add_bits(bindings, &name, bits);
        }
        result
    }

    /// A member or subscript read, or `None` to evaluate it as an ordinary
    /// expression.
    fn member(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Option<Bits> {
        let text = self.text(node);
        let canonical = self.canonical(text);
        if self.model.client_members.contains(&canonical.as_str()) {
            return Some(CLIENT);
        }
        if self.model.environ_members.contains(&canonical.as_str()) {
            return Some(if self.language.is_ecmascript() {
                ENV_OBJECT
            } else {
                ENV | SECRET
            });
        }
        let selects_variable = self
            .model
            .env_var_members
            .iter()
            .any(|prefix| canonical.starts_with(prefix));
        if !self.language.is_ecmascript() {
            return selects_variable.then(|| env_bits(text));
        }
        let object = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("value"));
        let property = node
            .child_by_field_name("property")
            .or_else(|| node.child_by_field_name("field"));
        let object_bits = object.map(|object| self.eval(object, bindings, out, depth + 1));
        if object_bits.is_some_and(|bits| bits & ENV_OBJECT != 0) {
            if let Some(property) = property {
                return Some(env_bits(self.text(property)));
            }
            let index = node
                .child_by_field_name("index")
                .or_else(|| node.child_by_field_name("subscript"));
            if let Some(index) = index {
                let key = self.text(index).trim_matches(['\'', '"', '`']);
                if key != self.text(index) {
                    return Some(env_bits(key));
                }
            }
            // A dynamic key may select a credential, so retain the
            // conservative source classification.
            return Some(ENV | SECRET);
        }
        if selects_variable {
            return Some(env_bits(text));
        }
        // `object` is already evaluated; letting the fallback `all` evaluate
        // it again would double the work at every link of a member chain.
        Some(
            named_children(node)
                .filter(|child| Some(*child) != object)
                .fold(object_bits.unwrap_or(0), |bits, child| {
                    bits | self.eval(child, bindings, out, depth + 1)
                }),
        )
    }

    fn block(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let mut tail = 0;
        let scoped = self.config.block_scoped && matches!(node.kind(), "block" | "statement_block");
        // The names the block declares are restored after it.
        let mut declared = Bindings::default();
        if scoped {
            for child in named_children(node) {
                if child.kind() == "let_declaration"
                    && let Some(pattern) = child.child_by_field_name("pattern")
                {
                    self.bind(pattern, 0, &mut declared);
                }
                if child.kind() == "lexical_declaration" {
                    for declaration in named_children(child) {
                        if let Some(name) = declaration.child_by_field_name("name") {
                            self.bind(name, 0, &mut declared);
                        }
                    }
                }
            }
        }
        let saved = bindings.save(declared.into_names());
        for child in named_children(node) {
            tail = self.eval(child, bindings, out, depth + 1);
        }
        bindings.restore(saved);
        tail
    }

    fn all(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        named_children(node).fold(0, |bits, n| bits | self.eval(n, bindings, out, depth + 1))
    }

    fn call(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let model = self.model;
        let Some(mut callee) = node.child_by_field_name("function") else {
            return 0;
        };
        while callee.kind() == "generic_function" {
            let Some(function) = callee.child_by_field_name("function") else {
                break;
            };
            callee = function;
        }
        let raw = self.text(callee);
        let prefix = raw.split([':', '.']).next().unwrap_or(raw);
        let name = if bindings.get(prefix).is_some() {
            raw.to_string()
        } else {
            self.canonical(raw)
        };
        let receiver = callee
            .child_by_field_name("value")
            .or_else(|| callee.child_by_field_name("object"))
            .or_else(|| callee.child_by_field_name("operand"));
        let recv = receiver.map_or(0, |n| self.eval(n, bindings, out, depth + 1));
        let method = callee
            .child_by_field_name("field")
            .or_else(|| callee.child_by_field_name("attribute"))
            .or_else(|| callee.child_by_field_name("property"))
            .map(|n| self.text(n))
            .unwrap_or_else(|| name.rsplit("::").next().unwrap_or(&name));
        let args = node
            .child_by_field_name("arguments")
            .map(|args| named_children(args).collect::<Vec<_>>())
            .unwrap_or_default();
        let bits: Vec<Bits> = args
            .iter()
            .map(|&n| self.eval(n, bindings, out, depth + 1))
            .collect();
        let all = bits.iter().fold(0, |a, b| a | b);
        let is = |names: &[&str]| names.contains(&name.as_str());
        if receiver.is_some() && args.is_empty() && model.metadata_methods.contains(&method) {
            return 0;
        }
        if is(model.process_calls)
            && args
                .first()
                .is_some_and(|n| self.text(*n).trim_matches('"') == "curl")
        {
            return CURL_COMMAND;
        }
        if recv & CURL_COMMAND != 0 {
            return self.curl_arguments(recv, method, &args, bindings, out, depth);
        }
        if is(model.environ_calls) {
            return ENV | SECRET;
        }
        if is(model.env_var_calls) {
            let bits = args.first().map_or(0, |n| env_bits(self.text(*n))) | ENV_VALUE;
            out.reads |= bits;
            return bits;
        }
        if is(model.request_calls) {
            return REQUEST | bits.last().copied().unwrap_or(0);
        }
        if is(model.client_calls) {
            return CLIENT;
        }
        let on_client = recv & CLIENT != 0
            || model
                .client_modules
                .iter()
                .any(|module| name.starts_with(module));
        let sent = model.sends.iter().find(|send| {
            if send.on_client {
                on_client && method == send.name
            } else {
                name == send.name
            }
        });
        if let Some(send) = sent {
            out.http = true;
            match send.body {
                Body::None => {}
                Body::Arg(index) => {
                    out.body |= bits.get(index).copied().unwrap_or(0);
                    return 0;
                }
                Body::Request => {
                    out.body |= bits.first().copied().unwrap_or(0) & !REQUEST;
                    return 0;
                }
                Body::Keywords => {
                    for (index, (arg, arg_bits)) in args.iter().zip(&bits).enumerate() {
                        let body = if arg.kind() == "keyword_argument" {
                            arg.child_by_field_name("name")
                                .is_some_and(|n| model.keyword_bodies.contains(&self.text(n)))
                        } else {
                            index == 1
                        };
                        if body {
                            out.body |= arg_bits;
                        }
                    }
                }
                Body::Options => {
                    if let Some(options) = args.get(1) {
                        for pair in named_children(*options) {
                            if pair
                                .child_by_field_name("key")
                                .is_some_and(|n| self.text(n).trim_matches(['\'', '"']) == "body")
                                && let Some(value) = pair.child_by_field_name("value")
                            {
                                out.body |= self.eval(value, bindings, out, depth + 1);
                            }
                        }
                    }
                }
            }
        }
        if model.auth_methods.contains(&method)
            || model
                .header_selectors
                .iter()
                .any(|selector| raw.contains(selector))
        {
            return 0;
        }
        if (recv & REQUEST != 0 && model.body_methods.contains(&method))
            || (recv & CLIENT != 0 && model.client_body_methods.contains(&method))
        {
            out.body |= all;
        }
        let read_method = model.file_read_methods.contains(&method);
        if is(model.file_read_calls) || read_method {
            let path = all | recv;
            let bits = (path & PARAM_BITS) | FILE | credential_bits(path);
            out.reads |= bits;
            if receiver.is_some()
                && read_method
                && let Some(buffer) = args.first()
            {
                self.bind(*buffer, bits, bindings);
            }
            return bits;
        }
        if is(model.file_write_calls) {
            out.write_path |= bits.first().copied().unwrap_or(0);
            return 0;
        }
        if model.append_methods.contains(&method)
            && let Some(receiver) = receiver
        {
            add_bits(bindings, self.text(receiver), all);
            return 0;
        }
        if let Some(summary) = self.summaries.get(&name).cloned() {
            out.body |= substitute(summary.body, &bits);
            out.write_path |= substitute(summary.write_path, &bits);
            out.http |= summary.http;
            out.reads |= substitute(summary.reads, &bits);
            return substitute(summary.returns, &bits);
        }
        if sent.is_some() && model.sends_return_builders {
            return REQUEST;
        }
        // An immediately invoked closure executes its body; an uncalled or
        // exported closure was skipped by eval above.
        let mut closure = callee;
        while closure.kind() == "parenthesized_expression" {
            let Some(child) = closure.named_child(0) else {
                break;
            };
            closure = child;
        }
        if self.config.is_function(closure)
            && let Some(body) = closure.child_by_field_name("body")
        {
            return self.eval(body, bindings, out, depth + 1);
        }
        // Authentication never taints a builder's body. A body operation also
        // does not turn response bytes into the originally submitted secret.
        if recv & (CLIENT | REQUEST) != 0 {
            return recv & (CLIENT | REQUEST);
        }
        let mut result = recv | all;
        if result & CARGOHOME != 0 && result & CREDFILENAME != 0 {
            result |= CARGOPATH | SECRETPATH;
        }
        result
    }

    /// `.arg(…)`/`.args(…)` on a `curl` command: the value after a data flag
    /// is the request body.
    fn curl_arguments(
        &mut self,
        recv: Bits,
        method: &str,
        args: &[Node<'_>],
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let mut state = recv;
        let command_args = if method == "args" {
            args.first()
                .map(|n| {
                    let mut n = *n;
                    while n.kind() == "reference_expression" {
                        let Some(child) = n.named_child(0) else { break };
                        n = child;
                    }
                    named_children(n).collect()
                })
                .unwrap_or_default()
        } else {
            args.to_vec()
        };
        if matches!(method, "arg" | "args") {
            for arg in command_args {
                if state & CURL_DATA_NEXT != 0 {
                    out.body |= self.eval(arg, bindings, out, depth + 1);
                    out.http = true;
                    state &= !CURL_DATA_NEXT;
                } else if matches!(
                    self.text(arg).trim_matches('"'),
                    "-d" | "--data" | "--data-raw" | "--data-binary" | "--json" | "-F" | "--form"
                ) {
                    state |= CURL_DATA_NEXT;
                }
            }
        }
        state
    }
}

/// The credential bits a file read of `path` adds.
fn credential_bits(path: Bits) -> Bits {
    let mut bits = 0;
    if path & SECRETPATH != 0 {
        bits |= CREDFILE | SECRET;
    }
    if path & CARGOPATH != 0 {
        bits |= CARGO | CREDFILE | SECRET;
    }
    bits
}

/// The path bits a string literal's decoded value carries, with Windows
/// separators read as `/`.
fn path_bits(value: &str) -> Bits {
    let path = value.replace('\\', "/");
    let mut bits = 0;
    if path.contains(CARGO_CREDENTIAL_PATH) {
        bits |= CARGOPATH | SECRETPATH;
    }
    if SECRET_PATHS.iter().any(|p| path.contains(p)) {
        bits |= SECRETPATH;
    }
    if path.contains("authorized_keys") {
        bits |= AUTHPATH;
    }
    if CARGO_CREDENTIAL_NAMES.contains(&path.as_str()) {
        bits |= CREDFILENAME;
    }
    bits
}

pub(super) fn substitute(value: Bits, args: &[Bits]) -> Bits {
    let mut result = value & !PARAM_BITS;
    for index in 0..PARAM_COUNT {
        if value & (1 << (PARAM_START + index)) != 0 {
            result |= args.get(index).copied().unwrap_or(0);
        }
    }
    if result & FILE != 0 {
        result |= credential_bits(result);
    }
    result
}

fn env_bits(name: &str) -> Bits {
    if name.contains("CARGO_REGISTRY_TOKEN")
        || name.contains("CARGO_REGISTRIES_") && name.contains("_TOKEN")
    {
        CARGO | SECRET
    } else if name.contains("CARGO_HOME") {
        CARGOHOME
    } else if SECRET_VARIABLES.iter().any(|s| name.contains(s)) {
        SECRET
    } else {
        0
    }
}
