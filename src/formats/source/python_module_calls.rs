//! Module-scope relations in Python source: calls through explicitly
//! imported names, and what module code does with retained temporary files
//! (what it writes to them, whether it closes them, and the commands that
//! launch them). Rules combine the relations.
//!
//! This records syntax and bindings, not successful execution or hostile
//! intent. There is no cross-function, conditional-branch, wildcard-import
//! or dynamic resolution: any statement that could rebind a name ends what
//! is known about it.
use super::visit::Visit;
use super::{TreeCache, named_children, text};
use crate::{FileType, Values, value_key};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tree_sitter::Node;

const MAX_STATEMENTS: usize = 10_000;
const MAX_CALLS: usize = 1_024;
const MAX_TEMPORARIES: usize = 256;
const MAX_EVENTS: usize = 64;
/// Largest file analysed.
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
/// Largest literal written to a temporary file that is parsed as Python.
const MAX_WRITTEN_SOURCE_BYTES: usize = 64 * 1024;
/// Callees that run a shell command given as their first argument.
const LAUNCHERS: &[&str] = &[
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
];

#[derive(Clone)]
struct Import {
    target: String,
    alias: String,
    offset: usize,
}

type Bindings = BTreeMap<String, Import>;

/// A `tempfile.NamedTemporaryFile(…)` bound to a module-scope name, and what
/// module code did with it until something could have touched it unseen.
#[derive(Clone)]
struct Temporary {
    variable: String,
    offset: usize,
    trigger: &'static str,
    /// The literal `delete=` argument; `None` when absent or not literal.
    delete: Option<bool>,
    /// The literal `mode=` argument.
    mode: Option<String>,
    events: Vec<Value>,
}

impl Temporary {
    fn event(&mut self, event: Value) {
        if self.events.len() < MAX_EVENTS {
            self.events.push(event);
        }
    }

    /// The finished fact; `ended` says what stopped the record, `None` at the
    /// end of the module.
    fn into_fact(self, ended: Option<(&str, usize)>) -> Value {
        json!({
            "variable": self.variable,
            "offset": self.offset,
            "trigger": self.trigger,
            "delete": self.delete,
            "mode": self.mode,
            "events": self.events,
            "ended": ended.map(|(reason, offset)| json!({"reason": reason, "offset": offset})),
        })
    }
}

/// The resolved callee of `call` when it is a direct dotted chain through
/// an import binding: the binding and the resolved name.
fn resolved<'b>(
    call: Node<'_>,
    source: &str,
    bindings: &'b Bindings,
) -> Option<(&'b Import, String)> {
    let function = call.child_by_field_name("function")?;
    let callee = text(function, source);
    let (head, tail) = callee.split_once('.').unwrap_or((callee, ""));
    let binding = bindings.get(head)?;
    // Only a direct dotted member chain; calls/subscripts in the receiver are
    // unresolved. Whitespace is rejected conservatively rather than normalized.
    if !matches!(function.kind(), "identifier" | "attribute")
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return None;
    }
    let name = if tail.is_empty() {
        binding.target.clone()
    } else {
        format!("{}.{tail}", binding.target)
    };
    Some((binding, name))
}

fn arguments(call: Node<'_>) -> Vec<Node<'_>> {
    call.child_by_field_name("arguments")
        .map(|args| named_children(args).collect())
        .unwrap_or_default()
}

/// The value of a plain or bytes string literal, escapes decoded unless it
/// is raw. `None` for f-strings and anything else.
fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = text(node, source);
    let quoted = raw.trim_start_matches(['b', 'B', 'r', 'R', 'u', 'U']);
    let prefix = &raw[..raw.len() - quoted.len()];
    let delimiter = ["\"\"\"", "'''", "\"", "'"]
        .into_iter()
        .find(|d| quoted.starts_with(d))?;
    let body = quoted.strip_prefix(delimiter)?.strip_suffix(delimiter)?;
    Some(if prefix.contains(['r', 'R']) {
        body.to_owned()
    } else {
        super::decode_source_escapes(body)
    })
}

fn is_bytes(node: Node<'_>, source: &str) -> bool {
    text(node, source).starts_with(['b', 'B'])
}

/// The URLs whose fetched response `code`, Python source, passes to `exec`
/// at module scope: `exec(urlopen("https://…").read())`, with `urlopen`
/// imported from `urllib.request` in that same code. The code is parsed,
/// never run.
fn remote_exec_urls(code: &str) -> Vec<String> {
    let mut urls = Vec::new();
    if code.len() > MAX_WRITTEN_SOURCE_BYTES {
        tracing::debug!(
            target: "filefacts::source",
            format = "python",
            len = code.len(),
            max = MAX_WRITTEN_SOURCE_BYTES,
            "python module calls: written literal too large to parse"
        );
        return urls;
    }
    let parsed = TreeCache::parse(code.as_bytes(), FileType::Python, None);
    let Some(cache) = parsed.cache() else {
        return urls;
    };
    let (root, code) = (cache.tree().root_node(), cache.source());
    let mut bindings = Bindings::new();
    for statement in named_children(root) {
        if matches!(
            statement.kind(),
            "import_statement" | "import_from_statement"
        ) {
            imports(statement, code, &mut bindings);
            continue;
        }
        let Some(exec) = named_children(statement)
            .next()
            .filter(|_| statement.kind() == "expression_statement")
        else {
            continue;
        };
        let callee = exec.child_by_field_name("function");
        if exec.kind() != "call"
            || callee.is_none_or(|f| text(f, code) != "exec")
            || bindings.contains_key("exec")
        {
            continue;
        }
        let [read] = arguments(exec)[..] else {
            continue;
        };
        let Some(method) = read
            .child_by_field_name("function")
            .filter(|_| read.kind() == "call" && arguments(read).is_empty())
        else {
            continue;
        };
        let Some(fetch) = method
            .child_by_field_name("object")
            .filter(|_| method.kind() == "attribute")
            .filter(|_| {
                method
                    .child_by_field_name("attribute")
                    .is_some_and(|a| text(a, code) == "read")
            })
        else {
            continue;
        };
        if fetch.kind() != "call"
            || resolved(fetch, code, &bindings).is_none_or(|(_, n)| n != "urllib.request.urlopen")
        {
            continue;
        }
        let [url] = arguments(fetch)[..] else {
            continue;
        };
        if is_bytes(url, code) {
            continue;
        }
        if let Some(url) = literal(url, code)
            .filter(|url| url.starts_with("https://") || url.starts_with("http://"))
        {
            urls.push(url);
        }
    }
    urls
}

/// A `tempfile.NamedTemporaryFile(…)` call's literal `delete=` and `mode=`.
fn temporary_constructor(
    call: Node<'_>,
    source: &str,
    bindings: &Bindings,
) -> Option<(Option<bool>, Option<String>)> {
    if resolved(call, source, bindings)?.1 != "tempfile.NamedTemporaryFile" {
        return None;
    }
    let (mut delete, mut mode) = (None, None);
    for arg in arguments(call) {
        let (Some(name), Some(value)) = (
            arg.child_by_field_name("name"),
            arg.child_by_field_name("value"),
        ) else {
            continue;
        };
        match text(name, source) {
            "delete" => {
                delete = match value.kind() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                };
            }
            "mode" => mode = literal(value, source),
            _ => {}
        }
    }
    Some((delete, mode))
}

/// A launch of a tracked temporary file: a [`LAUNCHERS`] call whose command
/// is an f-string interpolating `<temporary>.name`. Returns the temporary's
/// name and the launch fact.
fn launch(
    call: Node<'_>,
    source: &str,
    bindings: &Bindings,
    trigger: &str,
) -> Option<(String, Value)> {
    let (binding, launcher) = resolved(call, source, bindings)?;
    if !LAUNCHERS.contains(&launcher.as_str()) {
        return None;
    }
    let command = *arguments(call).first()?;
    if command.kind() != "string" || !text(command, source).starts_with(['f', 'F']) {
        return None;
    }
    let mut file = None;
    let mut interpreter = None;
    let mut windowless = false;
    let mut prefix = String::new();
    for piece in named_children(command) {
        match piece.kind() {
            "string_content" if file.is_none() && interpreter.is_none() => {
                prefix.push_str(text(piece, source));
            }
            "interpolation" => {
                let expr = piece.child_by_field_name("expression")?;
                if let Some(object) = expr
                    .child_by_field_name("object")
                    .filter(|_| expr.kind() == "attribute")
                    .filter(|_| {
                        expr.child_by_field_name("attribute")
                            .is_some_and(|a| text(a, source) == "name")
                    })
                    .filter(|o| o.kind() == "identifier")
                {
                    file.get_or_insert_with(|| text(object, source).to_string());
                } else if let Some((name, swap)) = interpreter_of(expr, source, bindings) {
                    interpreter = Some(name);
                    windowless |= swap;
                }
            }
            _ => {}
        }
    }
    let file = file?;
    Some((
        file,
        json!({
            "event": "launch",
            "offset": call.start_byte(),
            "launcher": launcher,
            "launcher_alias": binding.alias,
            "private_alias": binding.alias.starts_with('_'),
            "command_prefix": prefix,
            "interpreter": interpreter,
            "windowless_interpreter": windowless,
            "trigger": trigger,
        }),
    ))
}

/// The resolved name of an interpolated interpreter path, and whether it is
/// rewritten from `.exe` to `w.exe` (the Windows console-less interpreter).
fn interpreter_of(expr: Node<'_>, source: &str, bindings: &Bindings) -> Option<(String, bool)> {
    let resolve = |node: Node<'_>| {
        let name = text(node, source);
        let (head, tail) = name.split_once('.').unwrap_or((name, ""));
        let target = &bindings.get(head)?.target;
        Some(if tail.is_empty() {
            target.clone()
        } else {
            format!("{target}.{tail}")
        })
    };
    if matches!(expr.kind(), "identifier" | "attribute") {
        return Some((resolve(expr)?, false));
    }
    let method = expr.child_by_field_name("function")?;
    if expr.kind() != "call"
        || method.kind() != "attribute"
        || method
            .child_by_field_name("attribute")
            .is_none_or(|n| text(n, source) != "replace")
    {
        return None;
    }
    let name = resolve(method.child_by_field_name("object")?)?;
    let swap = match arguments(expr)[..] {
        [old, new] => {
            !is_bytes(old, source)
                && !is_bytes(new, source)
                && literal(old, source).as_deref() == Some(".exe")
                && literal(new, source).as_deref() == Some("w.exe")
        }
        _ => false,
    };
    Some((name, swap))
}

fn imports(statement: Node<'_>, source: &str, bindings: &mut Bindings) {
    let from = statement.child_by_field_name("module_name");
    for child in named_children(statement) {
        if from.is_some_and(|module| module.id() == child.id()) {
            continue;
        }
        let (name, alias) = if child.kind() == "aliased_import" {
            let (Some(name), Some(alias)) = (
                child.child_by_field_name("name"),
                child.child_by_field_name("alias"),
            ) else {
                continue;
            };
            (text(name, source), text(alias, source))
        } else if child.kind() == "dotted_name" {
            let name = text(child, source);
            (name, name.split('.').next().unwrap_or(name))
        } else {
            // Wildcard and malformed imports cannot establish a binding.
            continue;
        };
        let target = if let Some(module) = from {
            format!("{}.{}", text(module, source), name)
        } else if child.kind() != "aliased_import" {
            // `import os.path` binds os, not the full os.path name.
            alias.to_owned()
        } else {
            name.to_owned()
        };
        bindings.insert(
            alias.to_owned(),
            Import {
                target,
                alias: alias.to_owned(),
                offset: child.start_byte(),
            },
        );
    }
}

/// The module statements the shared walk ([`super::visit`]) reaches,
/// interpreted in order.
pub(super) struct Collector {
    bindings: Bindings,
    temporaries: BTreeMap<String, Temporary>,
    calls: Vec<Value>,
    files: Vec<Value>,
    budget: usize,
    parse_error: bool,
    skipped: bool,
}

impl Collector {
    pub(super) fn new(source: &str) -> Self {
        let skipped = source.len() > MAX_SOURCE_BYTES;
        if skipped {
            tracing::debug!(
                target: "filefacts::source",
                format = "python",
                len = source.len(),
                max = MAX_SOURCE_BYTES,
                "python module calls: source too large to analyse"
            );
        }
        Self {
            bindings: Bindings::new(),
            temporaries: BTreeMap::new(),
            calls: Vec::new(),
            files: Vec::new(),
            budget: MAX_STATEMENTS,
            parse_error: false,
            skipped,
        }
    }

    pub(super) fn enter(&mut self, visit: &Visit<'_>, source: &str) {
        if visit.depth == 0 && visit.node.has_error() {
            self.parse_error = true;
        }
        if visit.depth != 1 || self.skipped || self.parse_error || !visit.named {
            return;
        }
        let mut bindings = std::mem::take(&mut self.bindings);
        let mut temporaries = std::mem::take(&mut self.temporaries);
        self.statement(
            visit.node,
            source,
            &mut bindings,
            &mut temporaries,
            "module",
        );
        self.bindings = bindings;
        self.temporaries = temporaries;
    }

    /// End every tracked temporary at `offset` for `reason`.
    fn end(&mut self, temporaries: &mut BTreeMap<String, Temporary>, reason: &str, offset: usize) {
        for (_, temporary) in std::mem::take(temporaries) {
            self.finish(temporary, Some((reason, offset)));
        }
    }

    fn finish(&mut self, temporary: Temporary, ended: Option<(&str, usize)>) {
        if self.files.len() < MAX_TEMPORARIES {
            self.files.push(temporary.into_fact(ended));
        }
    }

    fn statement(
        &mut self,
        statement: Node<'_>,
        source: &str,
        bindings: &mut Bindings,
        temporaries: &mut BTreeMap<String, Temporary>,
        trigger: &'static str,
    ) {
        if self.budget == 0 {
            return;
        }
        self.budget -= 1;
        let offset = statement.start_byte();
        match statement.kind() {
            "comment" => {}
            "import_statement" | "import_from_statement" => {
                imports(statement, source, bindings);
                let rebound: Vec<String> = temporaries
                    .keys()
                    .filter(|name| bindings.contains_key(*name))
                    .cloned()
                    .collect();
                for name in rebound {
                    if let Some(temporary) = temporaries.remove(&name) {
                        self.finish(temporary, Some(("rebound", offset)));
                    }
                }
            }
            "expression_statement" => {
                for expression in named_children(statement) {
                    self.expression(expression, source, bindings, temporaries, trigger);
                }
            }
            "function_definition" | "class_definition" => {
                if let Some(name) = statement.child_by_field_name("name") {
                    let name = text(name, source);
                    bindings.remove(name);
                    if let Some(temporary) = temporaries.remove(name) {
                        self.finish(temporary, Some(("rebound", offset)));
                    }
                }
                // Bodies, decorators and default arguments are not analysed.
            }
            "try_statement" if trigger == "module" => {
                if let Some(body) = statement.child_by_field_name("body") {
                    let mut inner = bindings.clone();
                    let mut inner_temporaries = std::mem::take(temporaries);
                    for child in named_children(body) {
                        self.statement(
                            child,
                            source,
                            &mut inner,
                            &mut inner_temporaries,
                            "module_try",
                        );
                    }
                    // What the body showed about each file stands; an
                    // exception may skip any of it, so nothing carries on.
                    self.end(&mut inner_temporaries, "try", offset);
                } else {
                    self.end(temporaries, "try", offset);
                }
                bindings.clear();
            }
            _ => {
                // A branch, loop, delete, decorated definition or unsupported
                // statement can overwrite a name. Never carry it through.
                bindings.clear();
                self.end(temporaries, "control-flow", offset);
            }
        }
    }

    fn expression(
        &mut self,
        expression: Node<'_>,
        source: &str,
        bindings: &mut Bindings,
        temporaries: &mut BTreeMap<String, Temporary>,
        trigger: &'static str,
    ) {
        match expression.kind() {
            "call" => self.call(expression, source, bindings, temporaries, trigger),
            "assignment" => {
                let right = expression.child_by_field_name("right");
                let constructed = right.and_then(|right| {
                    let constructed = temporary_constructor(right, source, bindings);
                    if constructed.is_none() {
                        self.call(right, source, bindings, temporaries, trigger);
                    }
                    constructed
                });
                let Some(left) = expression.child_by_field_name("left") else {
                    return;
                };
                let offset = expression.start_byte();
                if left.kind() != "identifier" {
                    bindings.clear();
                    self.end(temporaries, "rebound", offset);
                    return;
                }
                let name = text(left, source);
                if let Some(temporary) = temporaries.remove(name) {
                    self.finish(temporary, Some(("rebound", offset)));
                }
                if let (Some((delete, mode)), Some(right)) = (constructed, right) {
                    temporaries.insert(
                        name.to_owned(),
                        Temporary {
                            variable: name.to_owned(),
                            offset: right.start_byte(),
                            trigger,
                            delete,
                            mode,
                            events: Vec::new(),
                        },
                    );
                }
                bindings.remove(name);
            }
            "augmented_assignment" => {
                bindings.clear();
                self.end(temporaries, "rebound", expression.start_byte());
            }
            _ => {}
        }
    }

    /// Record a call through an import binding.
    fn observe(&mut self, call: Node<'_>, source: &str, bindings: &Bindings, trigger: &str) {
        if self.calls.len() >= MAX_CALLS || call.kind() != "call" {
            return;
        }
        let Some((binding, resolved)) = resolved(call, source, bindings) else {
            return;
        };
        let callee = call
            .child_by_field_name("function")
            .map_or("", |n| text(n, source));
        self.calls.push(json!({
            "callee": callee,
            "resolved_callee": resolved,
            "alias": binding.alias,
            "private_alias": binding.alias.starts_with('_'),
            "import_offset": binding.offset,
            "call_offset": call.start_byte(),
            "trigger": trigger,
        }));
    }

    /// A call statement: a method of a tracked temporary file, a launch of
    /// one, or opaque code that may use any of them.
    fn call(
        &mut self,
        call: Node<'_>,
        source: &str,
        bindings: &Bindings,
        temporaries: &mut BTreeMap<String, Temporary>,
        trigger: &'static str,
    ) {
        if call.kind() != "call" {
            return;
        }
        self.observe(call, source, bindings, trigger);
        let offset = call.start_byte();
        let method = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "attribute")
            .and_then(|f| {
                f.child_by_field_name("object")
                    .zip(f.child_by_field_name("attribute"))
            });
        if let Some((object, method)) = method {
            if let Some(temporary) = temporaries.get_mut(text(object, source)) {
                let method = text(method, source);
                let args = arguments(call);
                let event = match (method, args.as_slice()) {
                    ("write", [data]) => {
                        let bytes = is_bytes(*data, source);
                        let written = literal(*data, source);
                        json!({
                            "event": "write",
                            "offset": offset,
                            "literal": written.is_some(),
                            "bytes": bytes,
                            "remote_exec_urls": written
                                .filter(|_| bytes)
                                .map(|code| remote_exec_urls(&code))
                                .unwrap_or_default(),
                        })
                    }
                    ("close", []) => json!({"event": "close", "offset": offset}),
                    _ => json!({"event": "call", "method": method, "offset": offset}),
                };
                temporary.event(event);
                return;
            }
        }
        if let Some((file, event)) = launch(call, source, bindings, trigger) {
            if let Some(temporary) = temporaries.get_mut(&file) {
                temporary.event(event);
                return;
            }
        }
        // Opaque calls may use the handle, including writes nested in an
        // argument.
        self.end(temporaries, "opaque-call", offset);
    }

    /// Write `source.python.*`.
    pub(super) fn emit(mut self, values: &mut Values) {
        for (_, temporary) in std::mem::take(&mut self.temporaries) {
            self.finish(temporary, None);
        }
        if self.budget == 0 {
            tracing::debug!(
                target: "filefacts::source",
                format = "python",
                max = MAX_STATEMENTS,
                "python module calls: statement budget exhausted"
            );
        }
        values.insert_key(
            value_key!("source.python.module_alias_calls"),
            Value::Array(self.calls),
        );
        values.insert_key(
            value_key!("source.python.temporary_files"),
            Value::Array(self.files),
        );
        values.insert_key(
            value_key!("source.python.module_calls_analysis"),
            json!({
                "parse_error": self.parse_error,
                "truncated": self.skipped || self.budget == 0,
            }),
        );
    }
}

#[cfg(test)]
mod tests;
