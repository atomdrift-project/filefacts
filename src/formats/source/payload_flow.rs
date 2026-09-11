//! Bounded, source-local payload provenance. These are capabilities, not
//! reachability proofs or malware verdicts. No package code is executed.
//!
//! Track assignments and local helper summaries, keeping HTTP authentication
//! separate from request bodies. Unknown code is not assumed to be an HTTP
//! client. Analysis limits are surfaced rather than reported as clean scans.
use crate::Values;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use tree_sitter::Node;

type Bits = u64;
const ENV: Bits = 1;
const SECRET: Bits = 2;
const CARGO: Bits = 4;
const FILE: Bits = 8;
const CREDFILE: Bits = 16;
const CARGOPATH: Bits = 32;
const SECRETPATH: Bits = 64;
const AUTHPATH: Bits = 128;
const CLIENT: Bits = 256;
const REQUEST: Bits = 512;
const CARGOHOME: Bits = 1024;
const CREDFILENAME: Bits = 2048;
const CURL_COMMAND: Bits = 4096;
const CURL_DATA_NEXT: Bits = 8192;
const PARAM_START: usize = 24;
const PARAM_COUNT: usize = 16;
const LIMIT: usize = 200_000;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Summary {
    returns: Bits,
    body: Bits,
    write_path: Bits,
    http: bool,
    reads: Bits,
}

struct Analysis<'s, 't> {
    source: &'s str,
    language: &'s str,
    aliases: HashMap<String, String>,
    functions: BTreeMap<String, Node<'t>>,
    summaries: BTreeMap<String, Summary>,
    budget: usize,
    truncated: bool,
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn function(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_item"
            | "function_definition"
            | "function_declaration"
            | "generator_function_declaration"
    )
}

fn excluded(node: Node<'_>, source: &str) -> bool {
    let mut previous = node.prev_named_sibling();
    while let Some(attr) = previous {
        if attr.kind() != "attribute_item" {
            break;
        }
        let text = source[attr.byte_range()]
            .split_whitespace()
            .collect::<String>();
        if text == "#[cfg(test)]" || text == "#[test]" {
            return true;
        }
        previous = attr.prev_named_sibling();
    }
    false
}

pub(super) fn emit(root: Node<'_>, source: &str, language: &str, values: &mut Values) {
    emit_seeded(
        root,
        source,
        language,
        values,
        &BTreeMap::new(),
        &HashMap::new(),
    );
}

fn emit_seeded(
    root: Node<'_>,
    source: &str,
    language: &str,
    values: &mut Values,
    seeds: &BTreeMap<String, Summary>,
    global_seeds: &HashMap<String, Bits>,
) -> (BTreeMap<String, Summary>, HashMap<String, Bits>) {
    if !matches!(
        language,
        "rust" | "python" | "javascript" | "typescript" | "go"
    ) {
        return (BTreeMap::new(), HashMap::new());
    }
    if source.len() > 2 * 1024 * 1024 {
        values.insert("source.payload_flow.truncated", json!(true));
        return (BTreeMap::new(), HashMap::new());
    }
    let mut a = Analysis {
        source,
        language,
        aliases: HashMap::new(),
        functions: BTreeMap::new(),
        summaries: seeds.clone(),
        budget: LIMIT,
        truncated: false,
    };
    if language == "rust" {
        super::rust_syntax::execution_facts(root, source, values);
    }
    if language == "go" {
        super::go_syntax::execution_facts(root, source, values);
        a.aliases = super::go_syntax::imports(root, source);
    }
    if language == "rust" {
        for (import, _) in super::rust_syntax::imports(root, source) {
            let (name, local) = import
                .split_once(" as ")
                .unwrap_or_else(|| (&import, import.rsplit("::").next().unwrap_or("")));
            // Conflicting aliases are deliberately not canonicalized.
            a.aliases
                .entry(local.to_string())
                .and_modify(|old| {
                    if old != name {
                        old.clear();
                    }
                })
                .or_insert_with(|| name.to_string());
        }
    }
    let mut stack = vec![root];
    let mut ambiguous = Vec::new();
    while let Some(node) = stack.pop() {
        if excluded(node, source) {
            continue;
        }
        if function(node) {
            if let Some(name) = node.child_by_field_name("name") {
                let key = if language == "go" && a.text(name) == "init" {
                    format!("init@{}", node.start_byte())
                } else {
                    a.text(name).to_string()
                };
                if a.functions.insert(key.clone(), node).is_some() {
                    ambiguous.push(key);
                }
            }
            // Nested definitions have separate lexical scopes, not global names.
            continue;
        }
        if node.kind() == "variable_declarator" {
            if let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                if matches!(value.kind(), "arrow_function" | "function_expression") {
                    let key = a.text(name).to_string();
                    if a.functions.insert(key.clone(), value).is_some() {
                        ambiguous.push(key);
                    }
                    continue;
                }
            }
        }
        if node.kind() == "import_statement" || node.kind() == "import_from_statement" {
            a.python_imports(node);
        }
        stack.extend(children(node));
        if stack.len() > 10_000 {
            a.truncated = true;
            break;
        }
    }
    for name in ambiguous {
        a.functions.remove(&name);
    }
    let functions = a.functions.clone();
    // Fixed point handles helper declaration order and bounded recursion.
    for iteration in 0..8 {
        let before = a.summaries.clone();
        let mut globals = global_seeds.clone();
        if language == "go" {
            a.eval(root, &mut globals, &mut Summary::default(), 0);
        }
        for (name, node) in &functions {
            let mut bindings = globals.clone();
            if let Some(params) = node.child_by_field_name("parameters") {
                for (index, param) in children(params).into_iter().enumerate().take(PARAM_COUNT) {
                    let pat = param
                        .child_by_field_name("pattern")
                        .or_else(|| param.child_by_field_name("name"))
                        .unwrap_or(param);
                    let mut bits = 1 << (PARAM_START + index);
                    if let Some(mut ty) = param.child_by_field_name("type") {
                        while let Some(inner) = ty.child_by_field_name("type") {
                            ty = inner;
                        }
                        let ty = a.canonical(a.text(ty));
                        if matches!(
                            ty.as_str(),
                            "reqwest::Client"
                                | "reqwest::blocking::Client"
                                | "curl::easy::Easy"
                                | "net/http.Client"
                        ) {
                            bits |= CLIENT;
                        }
                    }
                    a.bind(pat, bits, &mut bindings);
                }
            }
            let mut summary = Summary::default();
            if let Some(body) = node.child_by_field_name("body") {
                let tail = a.eval(body, &mut bindings, &mut summary, 0);
                if language == "rust" {
                    summary.returns |= tail;
                }
            }
            a.summaries.insert(name.clone(), summary);
        }
        if a.summaries == before {
            break;
        }
        if iteration == 7 {
            a.truncated = true;
        }
    }
    let mut events = Vec::new();
    for name in functions.keys() {
        let Some(summary) = a.summaries.get(name) else {
            continue;
        };
        let offset = functions.get(name).map_or(0, Node::start_byte);
        events.extend(events_for(summary, name, offset));
    }
    let mut top = Summary::default();
    let mut globals = global_seeds.clone();
    a.eval(root, &mut globals, &mut top, 0);
    events.extend(events_for(&top, "<module>", 0));
    if language == "go" {
        let mut startup = top.clone();
        for name in functions.keys() {
            let Some(summary) = a.summaries.get(name) else {
                continue;
            };
            if name.starts_with("init@") {
                startup.body |= summary.body;
                startup.http |= summary.http;
                startup.write_path |= summary.write_path;
            }
        }
        values.insert("source.go.initialization_http", json!(startup.http));
        values.insert(
            "source.go.initialization_events",
            json!(events_for(&startup, "<initialization>", 0)),
        );
    }
    events.sort_by_key(|event| event.to_string());
    events.dedup();
    values.insert("source.payload_flow.events", json!(events));
    values.insert("source.payload_flow.truncated", json!(a.truncated));
    // Top-level facts include direct calls and calls to resolved local helpers,
    // but not merely exported/uninvoked functions or constant-false branches.
    if matches!(language, "javascript" | "typescript") {
        values.insert("source.execution.module_http", json!(top.http));
    }
    (
        a.summaries
            .into_iter()
            .filter(|(name, _)| functions.contains_key(name) && !name.starts_with("init@"))
            .collect(),
        globals,
    )
}

/// Reanalyze same-package Go files with source-local import scopes and shared
/// package function/global summaries. The caller supplies only one directory
/// and package variant. No imports are fetched and no source is executed.
/// Results are bounded; `truncated` means coverage is incomplete, not clean.
pub fn go_package_payload_flow(sources: &[(&str, &str)]) -> serde_json::Value {
    if sources.len() > 128 || sources.iter().map(|(_, s)| s.len()).sum::<usize>() > 2 * 1024 * 1024
    {
        return json!({"files":[], "truncated":true});
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .is_err()
    {
        return json!({"files":[], "truncated":true});
    }
    let trees: Vec<_> = sources.iter().map(|(_, s)| parser.parse(s, None)).collect();
    let mut seeds = BTreeMap::new();
    let mut globals = HashMap::new();
    let mut result = Vec::new();
    let mut truncated = false;
    for iteration in 0..8 {
        let mut next = BTreeMap::new();
        let mut next_globals = globals.clone();
        let mut duplicates = Vec::new();
        result.clear();
        for ((path, source), tree) in sources.iter().zip(&trees) {
            let Some(tree) = tree else {
                truncated = true;
                continue;
            };
            let mut values = Values::new();
            let (summaries, bindings) = emit_seeded(
                tree.root_node(),
                source,
                "go",
                &mut values,
                &seeds,
                &globals,
            );
            truncated |= values
                .get("source.payload_flow.truncated")
                .and_then(|v| v.as_bool())
                == Some(true);
            for (name, summary) in summaries {
                if next.insert(name.clone(), summary).is_some() {
                    duplicates.push(name);
                }
            }
            next_globals.extend(bindings);
            result.push(json!({"path":path,"facts":values.as_json()}));
        }
        for name in duplicates {
            next.remove(&name);
            truncated = true;
        }
        if seeds == next && globals == next_globals {
            break;
        }
        seeds = next;
        globals = next_globals;
        if iteration == 7 {
            truncated = true;
        }
    }
    json!({"files":result,"truncated":truncated})
}

fn events_for(summary: &Summary, name: &str, offset: usize) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    for (bit, kind) in [
        (ENV, "environment-http-body"),
        (SECRET, "secret-http-body"),
        (CARGO, "cargo-credential-http-body"),
        (FILE, "file-http-body"),
        (CREDFILE, "credential-file-http-body"),
    ] {
        if summary.body & bit != 0 {
            events.push(json!({"kind":kind,"function":name,"offset":offset}));
        }
    }
    if summary.write_path & AUTHPATH != 0 {
        events.push(json!({"kind":"ssh-authorized-keys-write","function":name,"offset":offset}));
    }
    if summary.reads & CARGO != 0 {
        events.push(json!({"kind":"cargo-credential-read","function":name,"offset":offset}));
    }
    events
}

impl<'s, 't> Analysis<'s, 't> {
    fn text(&self, node: Node<'_>) -> &'s str {
        &self.source[node.byte_range()]
    }
    fn canonical(&self, name: &str) -> String {
        let end = name.find([':', '.']).unwrap_or(name.len());
        match self.aliases.get(&name[..end]).filter(|s| !s.is_empty()) {
            Some(prefix) => format!("{prefix}{}", &name[end..]),
            None => name.to_string(),
        }
    }
    fn python_imports(&mut self, node: Node<'_>) {
        if self.language != "python" {
            return;
        }
        let module = node
            .child_by_field_name("module_name")
            .map(|n| self.text(n).to_string());
        for child in children(node) {
            if Some(child) == node.child_by_field_name("module_name") {
                continue;
            }
            let (name, alias) = if child.kind() == "aliased_import" {
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                let Some(alias) = child.child_by_field_name("alias") else {
                    continue;
                };
                (self.text(name).to_string(), self.text(alias).to_string())
            } else if child.kind() == "dotted_name" {
                (self.text(child).to_string(), self.text(child).to_string())
            } else {
                continue;
            };
            self.aliases.insert(
                alias,
                module
                    .as_ref()
                    .map_or(name.clone(), |m| format!("{m}.{name}")),
            );
        }
    }
    fn bind(&self, pattern: Node<'_>, bits: Bits, bindings: &mut HashMap<String, Bits>) {
        let mut stack = vec![pattern];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                bindings.insert(self.text(node).to_string(), bits);
            } else if !matches!(node.kind(), "type_identifier" | "scoped_identifier") {
                stack.extend(children(node));
            }
        }
    }
    fn eval(
        &mut self,
        node: Node<'t>,
        bindings: &mut HashMap<String, Bits>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        if self.budget == 0 || depth > 96 {
            self.truncated = true;
            return 0;
        }
        self.budget -= 1;
        if excluded(node, self.source)
            || function(node)
            || matches!(
                node.kind(),
                "arrow_function"
                    | "function_expression"
                    | "closure_expression"
                    | "func_literal"
                    | "macro_definition"
                    | "comment"
                    | "line_comment"
                    | "block_comment"
            )
        {
            return 0;
        }
        let text = self.text(node);
        if matches!(
            node.kind(),
            "identifier" | "shorthand_field_identifier" | "shorthand_property_identifier"
        ) {
            return bindings.get(text).copied().unwrap_or(0);
        }
        if node.kind() == "macro_invocation"
            && node
                .child_by_field_name("macro")
                .is_some_and(|n| matches!(self.text(n), "format" | "format_args" | "std::format"))
        {
            let mut bits = self.all(node, bindings, out, depth + 1);
            let mut stack = children(node);
            while let Some(child) = stack.pop() {
                if child.kind() == "string_literal" {
                    let literal = self.text(child);
                    let bytes = literal.as_bytes();
                    let mut index = 0;
                    while index < bytes.len() {
                        if bytes[index] == b'{' {
                            if bytes.get(index + 1) == Some(&b'{') {
                                index += 2;
                                continue;
                            }
                            let start = index + 1;
                            let mut end = start;
                            while end < bytes.len()
                                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                            {
                                end += 1;
                            }
                            if end > start && matches!(bytes.get(end), Some(b'}' | b':')) {
                                bits |= bindings.get(&literal[start..end]).copied().unwrap_or(0);
                            }
                        }
                        index += 1;
                    }
                } else {
                    stack.extend(children(child));
                }
            }
            return bits;
        }
        if matches!(
            node.kind(),
            "string"
                | "string_literal"
                | "raw_string_literal"
                | "interpreted_string_literal"
                | "string_fragment"
        ) {
            let mut bits = 0;
            if text.contains(".cargo/credentials") || text.contains(".cargo\\\\credentials") {
                bits |= CARGOPATH | SECRETPATH;
            }
            if [
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
            ]
            .iter()
            .any(|p| text.contains(p))
            {
                bits |= SECRETPATH;
            }
            if text.contains("authorized_keys") {
                bits |= AUTHPATH;
            }
            if matches!(
                text.trim_matches(['\'', '"']),
                "credentials" | "credentials.toml"
            ) {
                bits |= CREDFILENAME;
            }
            return bits;
        }
        if matches!(node.kind(), "import_statement" | "import_from_statement") {
            self.python_imports(node);
            return 0;
        }
        if matches!(
            node.kind(),
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
                if self.language == "go" && target.kind() == "selector_expression" {
                    if target
                        .child_by_field_name("field")
                        .is_some_and(|n| self.text(n) == "Body")
                    {
                        if let Some(receiver) = target.child_by_field_name("operand") {
                            let bits = self.eval(value, bindings, out, depth + 1);
                            if let Some(state) = bindings.get_mut(self.text(receiver)) {
                                if *state & REQUEST != 0 {
                                    *state = REQUEST | bits;
                                }
                            }
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
            node.kind(),
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
        if matches!(node.kind(), "if_statement" | "if_expression") {
            let condition = node.child_by_field_name("condition");
            // Reachability is enforced only for the module-execution fact.
            if matches!(self.language, "javascript" | "typescript")
                && condition.is_some_and(|n| self.text(n).trim_matches(['(', ')', ' ']) == "false")
            {
                return 0;
            }
            if let Some(condition) = condition {
                self.eval(condition, bindings, out, depth + 1);
            }
            let mut merged = bindings.clone();
            let mut result = 0;
            for field in ["consequence", "alternative"] {
                if let Some(branch) = node.child_by_field_name(field) {
                    let mut branch_bindings = bindings.clone();
                    result |= self.eval(branch, &mut branch_bindings, out, depth + 1);
                    for (name, bits) in branch_bindings {
                        *merged.entry(name).or_default() |= bits;
                    }
                }
            }
            *bindings = merged;
            return result;
        }
        if matches!(node.kind(), "call_expression" | "call") {
            return self.call(node, bindings, out, depth + 1);
        }
        if node.kind() == "return_statement" || node.kind() == "return_expression" {
            let bits = self.all(node, bindings, out, depth + 1);
            out.returns |= bits;
            return bits;
        }
        if matches!(
            node.kind(),
            "attribute"
                | "member_expression"
                | "subscript"
                | "subscript_expression"
                | "selector_expression"
        ) {
            let canonical = self.canonical(text);
            if self.language == "go" && canonical == "net/http.DefaultClient" {
                return CLIENT;
            }
            if canonical == "os.environ" || canonical == "process.env" {
                return ENV | SECRET;
            }
            if canonical.starts_with("os.environ[")
                || canonical.starts_with("process.env.")
                || canonical.starts_with("process.env[")
            {
                return env_bits(text);
            }
        }
        if self.language == "go" && node.kind() == "composite_literal" {
            if node
                .child_by_field_name("type")
                .is_some_and(|n| self.canonical(self.text(n)) == "net/http.Client")
            {
                return CLIENT;
            }
        }
        if matches!(
            node.kind(),
            "block" | "statement_block" | "source_file" | "module" | "program"
        ) {
            let mut tail = 0;
            let scoped = matches!(self.language, "rust" | "javascript" | "typescript")
                && matches!(node.kind(), "block" | "statement_block");
            let before = if scoped {
                bindings.clone()
            } else {
                HashMap::new()
            };
            let mut declared = HashMap::new();
            for child in children(node) {
                if scoped && child.kind() == "let_declaration" {
                    if let Some(pattern) = child.child_by_field_name("pattern") {
                        self.bind(pattern, 0, &mut declared);
                    }
                }
                if scoped && child.kind() == "lexical_declaration" {
                    for declaration in children(child) {
                        if let Some(name) = declaration.child_by_field_name("name") {
                            self.bind(name, 0, &mut declared);
                        }
                    }
                }
                tail = self.eval(child, bindings, out, depth + 1);
            }
            for name in declared.keys() {
                if let Some(old) = before.get(name) {
                    bindings.insert(name.clone(), *old);
                } else {
                    bindings.remove(name);
                }
            }
            return tail;
        }
        self.all(node, bindings, out, depth + 1)
    }
    fn all(
        &mut self,
        node: Node<'t>,
        bindings: &mut HashMap<String, Bits>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        children(node)
            .into_iter()
            .fold(0, |bits, n| bits | self.eval(n, bindings, out, depth + 1))
    }
    fn call(
        &mut self,
        node: Node<'t>,
        bindings: &mut HashMap<String, Bits>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
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
        let name = if bindings.contains_key(prefix) {
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
            .map(children)
            .unwrap_or_default();
        let bits: Vec<Bits> = args
            .iter()
            .map(|&n| self.eval(n, bindings, out, depth + 1))
            .collect();
        let all = bits.iter().fold(0, |a, b| a | b);
        if self.language == "go" {
            if name == "os.Environ" {
                return ENV | SECRET;
            }
            if matches!(name.as_str(), "os.Getenv" | "os.LookupEnv") {
                return args.first().map_or(0, |n| env_bits(self.text(*n)));
            }
            if matches!(
                name.as_str(),
                "net/http.NewRequest" | "net/http.NewRequestWithContext"
            ) {
                return REQUEST | bits.last().copied().unwrap_or(0);
            }
            if name == "net/http.Post" || recv & CLIENT != 0 && method == "Post" {
                out.http = true;
                out.body |= bits.get(2).copied().unwrap_or(0);
                return 0;
            }
            if name == "net/http.PostForm" || recv & CLIENT != 0 && method == "PostForm" {
                out.http = true;
                out.body |= bits.get(1).copied().unwrap_or(0);
                return 0;
            }
            if recv & CLIENT != 0 && method == "Do" {
                out.http = true;
                out.body |= bits.first().copied().unwrap_or(0) & !REQUEST;
                return 0;
            }
            // Headers/authentication are not body mutations. Only builders of
            // form/body data carry Set/Add/Write arguments into later Encode.
            if matches!(method, "SetBasicAuth" | "AddCookie") || raw.contains(".Header.") {
                return 0;
            }
            if matches!(method, "Set" | "Add" | "Write" | "WriteString") {
                if let Some(receiver) = receiver {
                    *bindings.entry(self.text(receiver).to_string()).or_default() |= all;
                }
                return 0;
            }
        }
        if matches!(name.as_str(), "std::process::Command::new" | "Command::new")
            && args
                .first()
                .is_some_and(|n| self.text(*n).trim_matches('"') == "curl")
        {
            return CURL_COMMAND;
        }
        if recv & CURL_COMMAND != 0 {
            let mut state = recv;
            let command_args = if method == "args" {
                args.first()
                    .map(|n| {
                        let mut n = *n;
                        while n.kind() == "reference_expression" {
                            let Some(child) = n.named_child(0) else { break };
                            n = child;
                        }
                        children(n)
                    })
                    .unwrap_or_default()
            } else {
                args.clone()
            };
            if matches!(method, "arg" | "args") {
                for arg in command_args {
                    if state & CURL_DATA_NEXT != 0 {
                        out.body |= self.eval(arg, bindings, out, depth + 1);
                        out.http = true;
                        state &= !CURL_DATA_NEXT;
                    } else if matches!(
                        self.text(arg).trim_matches('"'),
                        "-d" | "--data"
                            | "--data-raw"
                            | "--data-binary"
                            | "--json"
                            | "-F"
                            | "--form"
                    ) {
                        state |= CURL_DATA_NEXT;
                    }
                }
            }
            return state;
        }
        if matches!(
            name.as_str(),
            "std::env::vars" | "std::env::vars_os" | "env::vars" | "env::vars_os"
        ) {
            return ENV | SECRET;
        }
        if matches!(
            name.as_str(),
            "std::env::var"
                | "std::env::var_os"
                | "env::var"
                | "env::var_os"
                | "os.getenv"
                | "os.environ.get"
        ) {
            let bits = args.first().map_or(0, |n| env_bits(self.text(*n)));
            out.reads |= bits;
            return bits;
        }
        if name.contains("reqwest::")
            && (name.ends_with("Client::new") || name.ends_with("Client::builder"))
            || name == "requests.Session"
            || name == "httpx.Client"
            || name == "httpx.AsyncClient"
            || name == "curl::easy::Easy::new"
        {
            return CLIENT;
        }
        let python_http = name.starts_with("requests.") || name.starts_with("httpx.");
        let request = (recv & CLIENT != 0
            && matches!(method, "post" | "put" | "patch" | "get" | "request"))
            || name.starts_with("ureq::") && matches!(method, "post" | "put" | "get" | "patch")
            || python_http;
        if request {
            out.http = true;
        }
        if (recv & REQUEST != 0
            && matches!(
                method,
                "body"
                    | "json"
                    | "form"
                    | "multipart"
                    | "send_json"
                    | "send_form"
                    | "send_bytes"
                    | "send_string"
                    | "send"
            ))
            || (recv & CLIENT != 0 && method == "post_fields_copy")
        {
            out.body |= all;
        }
        if (python_http || recv & CLIENT != 0)
            && matches!(
                method.rsplit('.').next().unwrap_or(method),
                "post" | "put" | "patch" | "request"
            )
        {
            for (index, arg) in args.iter().enumerate() {
                if arg.kind() == "keyword_argument"
                    && arg
                        .child_by_field_name("name")
                        .is_some_and(|n| matches!(self.text(n), "data" | "json" | "files"))
                    || self.language == "python" && index == 1 && arg.kind() != "keyword_argument"
                {
                    out.body |= bits[index];
                }
            }
        }
        if name == "fetch" {
            out.http = true;
            if let Some(options) = args.get(1) {
                for pair in children(*options) {
                    if pair
                        .child_by_field_name("key")
                        .is_some_and(|n| self.text(n).trim_matches(['\'', '"']) == "body")
                    {
                        if let Some(value) = pair.child_by_field_name("value") {
                            out.body |= self.eval(value, bindings, out, depth + 1);
                        }
                    }
                }
            }
        }
        let file_read = matches!(
            name.as_str(),
            "std::fs::read"
                | "std::fs::read_to_string"
                | "fs::read"
                | "fs::read_to_string"
                | "open"
                | "fs.readFileSync"
                | "fs.readFile"
                | "os.ReadFile"
                | "io/ioutil.ReadFile"
                | "os.Open"
                | "io.ReadAll"
                | "io/ioutil.ReadAll"
        ) || matches!(
            method,
            "read_text" | "read_bytes" | "read_to_end" | "read_to_string"
        );
        if file_read {
            let path = all | recv;
            let bits = (path & (((1 << PARAM_COUNT) - 1) << PARAM_START))
                | FILE
                | if path & SECRETPATH != 0 {
                    CREDFILE | SECRET
                } else {
                    0
                }
                | if path & CARGOPATH != 0 {
                    CARGO | CREDFILE | SECRET
                } else {
                    0
                };
            out.reads |= bits;
            if receiver.is_some() && matches!(method, "read_to_end" | "read_to_string") {
                if let Some(buffer) = args.first() {
                    self.bind(*buffer, bits, bindings);
                }
            }
            return bits;
        }
        if matches!(
            name.as_str(),
            "std::fs::write" | "fs::write" | "os.WriteFile" | "io/ioutil.WriteFile"
        ) {
            out.write_path |= bits.first().copied().unwrap_or(0);
            return 0;
        }
        if matches!(method, "push" | "append" | "extend" | "insert") {
            if let Some(receiver) = receiver {
                *bindings.entry(self.text(receiver).to_string()).or_default() |= all;
            }
            return 0;
        }
        if let Some(summary) = self.summaries.get(&name).cloned() {
            out.body |= substitute(summary.body, &bits);
            out.write_path |= substitute(summary.write_path, &bits);
            out.http |= summary.http;
            out.reads |= substitute(summary.reads, &bits);
            return substitute(summary.returns, &bits);
        }
        if request && self.language == "rust" {
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
        if matches!(
            closure.kind(),
            "arrow_function" | "function_expression" | "func_literal"
        ) {
            if let Some(body) = closure.child_by_field_name("body") {
                return self.eval(body, bindings, out, depth + 1);
            }
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
}

fn substitute(value: Bits, args: &[Bits]) -> Bits {
    let mut result = value & !(((1 << PARAM_COUNT) - 1) << PARAM_START);
    for index in 0..PARAM_COUNT {
        let bit = 1 << (PARAM_START + index);
        if value & bit != 0 {
            result |= args.get(index).copied().unwrap_or(0);
        }
    }
    if result & FILE != 0 {
        if result & SECRETPATH != 0 {
            result |= CREDFILE | SECRET;
        }
        if result & CARGOPATH != 0 {
            result |= CARGO | CREDFILE | SECRET;
        }
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
    } else if [
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ]
    .iter()
    .any(|s| name.contains(s))
    {
        SECRET
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use crate::open_with_path;
    use std::path::Path;
    #[test]
    fn go_package_helpers_keep_file_import_scopes_and_initialization() {
        let values = super::go_package_payload_flow(&[
            (
                "p/a.go",
                "package p\nimport h \"net/http\"\nfunc send(data string){h.Post(endpoint,\"text/plain\",data)}",
            ),
            (
                "p/b.go",
                "package p\nimport h \"os\"\nfunc secret()string{return h.Getenv(\"GITHUB_TOKEN\")}",
            ),
            ("p/c.go", "package p\nfunc init(){send(secret())}"),
        ]);
        assert_eq!(values["truncated"], false);
        assert!(
            values["files"][2]["facts"]["source"]["go"]["initialization_events"]
                .to_string()
                .contains("secret-http-body"),
            "{values}"
        );
    }
    #[test]
    fn go_body_flow_alias_helpers_builders_and_initializers() {
        let imports = "package p\nimport (h \"net/http\"; o \"os\"; \"bytes\"; \"strings\"; \"context\"; \"io\"; \"net/url\")\n";
        for body in [
            "b,_:=o.ReadFile(\"/tmp/fixture/.npmrc\"); h.Post(endpoint,\"text/plain\",bytes.NewReader(b))",
            "b,_:=o.ReadFile(\"/tmp/fixture/.npmrc\"); r,_:=h.NewRequest(\"POST\",endpoint,bytes.NewReader(b)); h.DefaultClient.Do(r)",
            "b:=o.Getenv(\"GITHUB_TOKEN\"); r,_:=h.NewRequestWithContext(context.Background(),\"POST\",endpoint,strings.NewReader(b)); c:=&h.Client{}; c.Do(r)",
            "v:=url.Values{}; v.Set(\"token\",o.Getenv(\"GITHUB_TOKEN\")); h.PostForm(endpoint,v)",
            "go func(){ h.Post(endpoint,\"text/plain\",strings.NewReader(o.Getenv(\"GITHUB_TOKEN\"))) }()",
            "h.Post(endpoint,\"text/plain\",strings.NewReader(secret()))",
        ] {
            let source = format!(
                "{imports}func secret()string{{return o.Getenv(\"GITHUB_TOKEN\")}}\nfunc init(){{{body}}}\nfunc init(){{}}\n"
            );
            assert!(
                kinds("p.go", &source).contains("secret-http-body"),
                "{source}"
            );
            let parsed = open_with_path(Path::new("p.go"), source.as_bytes()).unwrap();
            assert!(
                parsed
                    .values()
                    .get("source.go.initialization_events")
                    .unwrap()
                    .to_string()
                    .contains("secret-http-body")
            );
        }
        for body in [
            "b:=o.Getenv(\"GITHUB_TOKEN\"); r,_:=h.NewRequest(\"POST\",endpoint,strings.NewReader(\"status\")); r.Header.Set(\"Authorization\",b); h.DefaultClient.Do(r)",
            "b:=o.Getenv(\"GITHUB_TOKEN\"); r,_:=h.NewRequest(\"POST\",endpoint,nil); r.SetBasicAuth(\"user\",b); h.DefaultClient.Do(r)",
            "b:=o.Getenv(\"GITHUB_TOKEN\"); b=\"status\"; h.Post(endpoint,\"text/plain\",strings.NewReader(b))",
            "b:=o.Getenv(\"GITHUB_TOKEN\"); h.NewRequest(\"POST\",endpoint,strings.NewReader(b))",
        ] {
            assert_eq!(
                kinds("p.go", &format!("{imports}func run(){{{body}}}")),
                "[]",
                "{body}"
            );
        }
        let source = format!(
            "{imports}var token=o.Getenv(\"GITHUB_TOKEN\")\nfunc init(){{h.Post(endpoint,\"text/plain\",strings.NewReader(token))}}"
        );
        assert!(kinds("p.go", &source).contains("secret-http-body"));
    }
    fn kinds(file: &str, source: &str) -> String {
        let parsed = open_with_path(Path::new(file), source.as_bytes()).unwrap();
        let events = parsed
            .values()
            .get("source.payload_flow.events")
            .unwrap()
            .as_array()
            .unwrap();
        serde_json::json!(
            events
                .iter()
                .filter(|e| e["kind"]
                    .as_str()
                    .is_some_and(|k| k.ends_with("http-body") || k == "ssh-authorized-keys-write"))
                .collect::<Vec<_>>()
        )
        .to_string()
    }
    #[test]
    fn rust_payload_bindings_aliases_and_authentication() {
        let positive = "use std::{env::{vars as harvest}}; use reqwest::blocking::Client; fn run(){let c=Client::new(); let data=harvest().collect(); c.post(endpoint).json(&data).send();}";
        assert!(kinds("lib.rs", positive).contains("environment-http-body"));
        for body in [
            "let token=std::env::var(\"CARGO_REGISTRY_TOKEN\"); c.get(endpoint).bearer_auth(token).send();",
            "let data=std::env::vars().collect(); c.post(endpoint).body(\"status\").send();",
            "let data=std::env::vars().collect(); let data=\"status\"; c.post(endpoint).body(data).send();",
        ] {
            assert_eq!(
                kinds(
                    "build.rs",
                    &format!("fn main(){{let c=reqwest::blocking::Client::new();{body}}}")
                ),
                "[]",
                "{body}"
            );
        }
    }
    #[test]
    fn lexical_shadowing_does_not_leak_or_erase_outer_payload() {
        assert!(kinds("lib.rs","fn run(){let data=std::env::vars(); {let data=\"constant\";} ureq::post(endpoint).send_json(data);}").contains("environment-http-body"));
        assert_eq!(
            kinds(
                "lib.rs",
                "fn run(){let data=\"constant\"; if flag {let data=std::env::vars();} ureq::post(endpoint).send_json(data);}"
            ),
            "[]"
        );
        assert_eq!(
            kinds(
                "lib.rs",
                "use reqwest::blocking::Client; fn run(Client:Custom){let c=Client::new();c.post(endpoint).body(std::env::vars());}"
            ),
            "[]"
        );
    }
    #[test]
    fn rust_helpers_ureq_cargo_home_and_write_path() {
        assert!(kinds("lib.rs","fn data(){std::env::vars().collect()} fn run(){ureq::post(endpoint).send_json(data());}").contains("environment-http-body"));
        assert!(kinds("lib.rs","fn run(){let root=std::env::var(\"CARGO_HOME\"); let path=root.join(\"credentials.toml\"); let data=std::fs::read(path); ureq::post(endpoint).send(data);}").contains("cargo-credential-http-body"));
        assert!(kinds("lib.rs","fn writer(path:&Path,data:&str){std::fs::write(path,data);} fn run(){let path=root.join(\"authorized_keys\");writer(&path, key);}").contains("ssh-authorized-keys-write"));
        assert_eq!(
            kinds(
                "lib.rs",
                "#[cfg(test)] mod tests {fn run(){ureq::post(endpoint).send_json(std::env::vars());}}"
            ),
            "[]"
        );
    }
    #[test]
    fn typed_http_helper_and_curl_payload_only() {
        assert!(kinds("lib.rs","use reqwest::blocking::Client; fn send(c:&Client,data:&str){c.post(endpoint).body(data).send();} fn run(){let c=Client::new();let data=std::fs::read(path);send(&c,&data);}").contains("file-http-body"));
        assert!(kinds("lib.rs","fn run(){let data=std::env::vars();std::process::Command::new(\"curl\").arg(\"--data\").arg(data).arg(endpoint).status();}").contains("environment-http-body"));
        assert_eq!(
            kinds(
                "lib.rs",
                "fn run(){let data=std::env::var(\"CARGO_REGISTRY_TOKEN\");std::process::Command::new(\"curl\").arg(\"--header\").arg(data).arg(endpoint).status();}"
            ),
            "[]"
        );
    }
    #[test]
    fn rust_mutable_read_buffer_and_format_capture() {
        assert!(kinds("lib.rs","fn run(){let mut f=std::fs::File::open(\"/tmp/input/.ssh/id_rsa\");let mut buf=Vec::new();f.read_to_end(&mut buf);ureq::post(endpoint).send(buf);}").contains("credential-file-http-body"));
        assert!(kinds("lib.rs","fn run(){let token=std::fs::read_to_string(\"/tmp/input/.terraform.d/credentials.tfrc.json\");ureq::post(endpoint).send(format!(\"{token}\"));}").contains("credential-file-http-body"));
    }
    #[test]
    fn rust_batched_struct_shorthand_payload() {
        let source = "use reqwest::blocking::Client; fn read(path:&Path){std::fs::read_to_string(path).ok()} fn send(client:&Client,items:&[Item]){let payload=Batch{items};client.post(endpoint).json(&payload).send();} fn run(paths:&[Path]){let client=Client::new();let mut items=Vec::new();for path in paths {if let Some(content)=read(path){items.push(Item{content});}}send(&client,&items);}";
        assert!(kinds("lib.rs", source).contains("file-http-body"));
    }
    #[test]
    fn helper_parameter_substitution_is_simultaneous() {
        use super::{PARAM_START, substitute};
        assert_eq!(
            substitute(1 << PARAM_START, &[1 << (PARAM_START + 2)]),
            1 << (PARAM_START + 2)
        );
        assert!(kinds("lib.rs", "fn identity(data:&str){data} fn middle(unused:usize,data:&str){ureq::post(endpoint).send(identity(data));} fn run(){middle(0,std::fs::read(path));}").contains("file-http-body"));
    }
    #[test]
    fn sensitive_path_passed_through_read_helper() {
        assert!(kinds("lib.rs", "fn read(path:&str){std::fs::read(path)} fn run(){ureq::post(endpoint).send(read(\"/tmp/fixture/.cargo/credentials.toml\"));}").contains("cargo-credential-http-body"));
    }
    #[test]
    fn rust_turbofish_preserves_receiver_payload() {
        assert!(kinds("lib.rs", "fn run(){let data=std::env::vars().map(|(k,v)|format!(\"{k}={v}\")).collect::<Vec<_>>().join(\"\\n\");std::process::Command::new(\"curl\").arg(\"--data\").arg(data).status();}").contains("environment-http-body"));
    }
    #[test]
    fn python_intermediate_helper_session_and_auth() {
        assert!(kinds("lib.py","import os\nimport requests\ndef harvest():\n return dict(os.environ)\ndef run():\n client=requests.Session()\n data=harvest()\n client.post(endpoint,json=data)\n").contains("environment-http-body"));
        assert_eq!(
            kinds(
                "lib.py",
                "import os\nimport requests\ndef run():\n token=os.getenv('CARGO_REGISTRY_TOKEN')\n requests.post(endpoint,headers={'Authorization':token},data='status')\n"
            ),
            "[]"
        );
    }
    #[test]
    fn javascript_import_execution_is_not_function_presence() {
        for (source, expected) in [
            (
                "async function f(){await fetch('https://example.invalid');} module.exports=f;",
                false,
            ),
            (
                "async function f(){await fetch('https://example.invalid');} if(false)f();",
                false,
            ),
            (
                "async function f(){await fetch('https://example.invalid');} f();",
                true,
            ),
            ("fetch('https://example.invalid');", true),
        ] {
            let parsed = open_with_path(Path::new("index.js"), source.as_bytes()).unwrap();
            assert_eq!(
                parsed
                    .values()
                    .get("source.execution.module_http")
                    .and_then(|v| v.as_bool()),
                Some(expected),
                "{source}"
            );
        }
    }
}
