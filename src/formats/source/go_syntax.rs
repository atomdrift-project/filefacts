//! Go execution contexts. These are potential entry points, not proof that a
//! package is selected for a particular GOOS/GOARCH, build tag, or test run.
use super::{named_children, text};
use crate::Values;
use crate::value_key;
use serde_json::json;
use std::collections::HashMap;
use tree_sitter::Node;

/// The package clause's name as `go/build` reads it, without a parse: the
/// first token after whitespace and comments must be `package`, and the
/// name is the identifier after it. `""` when the source does not open with
/// a package clause.
pub(crate) fn package_clause(source: &str) -> &str {
    let mut rest = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut keyword = false;
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        if let Some(comment) = rest.strip_prefix("//") {
            rest = comment.find('\n').map_or("", |end| &comment[end..]);
        } else if let Some(comment) = rest.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else {
                return "";
            };
            rest = &comment[end + 2..];
        } else if keyword {
            let is_name = |c: char| c.is_alphanumeric() || c == '_';
            let len = rest.find(|c| !is_name(c)).unwrap_or(rest.len());
            let name = &rest[..len];
            return if name.starts_with(|c: char| c.is_numeric()) {
                ""
            } else {
                name
            };
        } else {
            match rest.strip_prefix("package") {
                Some(after) if !after.starts_with(|c: char| c.is_alphanumeric() || c == '_') => {
                    keyword = true;
                    rest = after;
                }
                _ => return "",
            }
        }
    }
}

/// The name in the file's package clause, `""` without one. A later clause
/// overrides an earlier one, as in [`execution_facts`].
pub(super) fn package_name<'s>(root: Node<'_>, source: &'s str) -> &'s str {
    let mut package = "";
    for node in named_children(root) {
        if node.kind() == "package_clause"
            && let Some(n) = node.named_child(0)
        {
            package = text(n, source);
        }
    }
    package
}

/// One `import` spec: the package path, and the local name when the spec
/// gives one (`_` and `.` included).
pub(super) struct Import<'s> {
    pub(super) path: &'s str,
    pub(super) name: Option<&'s str>,
    pub(super) offset: usize,
}

/// The file's imports, in source order. Imports are top-level declarations.
pub(super) fn imports<'s>(root: Node<'_>, source: &'s str) -> Vec<Import<'s>> {
    let mut out = Vec::new();
    for declaration in named_children(root).filter(|n| n.kind() == "import_declaration") {
        for spec in named_children(declaration) {
            let specs: Vec<Node<'_>> = if spec.kind() == "import_spec_list" {
                named_children(spec).collect()
            } else {
                vec![spec]
            };
            for spec in specs.into_iter().filter(|n| n.kind() == "import_spec") {
                let Some(path) = spec.child_by_field_name("path") else {
                    continue;
                };
                out.push(Import {
                    path: text(path, source).trim_matches(['"', '`']),
                    name: spec.child_by_field_name("name").map(|n| text(n, source)),
                    offset: path.start_byte(),
                });
            }
        }
    }
    out
}

// go generate uses Go-quoted arguments, not shell tokenization. No commands or
// environment expansion are performed by this analyzer. Variable arguments
// remain visibly unresolved. Single quotes are ordinary argument characters.
fn words(line: &str) -> Option<Vec<String>> {
    let mut rest = line.trim();
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.starts_with('"') {
            let mut escaped = false;
            let mut end = None;
            for (i, c) in rest.char_indices().skip(1) {
                if !escaped && c == '"' {
                    end = Some(i + 1);
                    break;
                }
                escaped = !escaped && c == '\\';
            }
            let end = end?;
            let word = &rest[..end];
            rest = &rest[end..];
            if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
                return None;
            }
            out.push(super::escapes::decode(&word[1..word.len() - 1]));
        } else {
            let end = rest.find([' ', '\t']).unwrap_or(rest.len());
            out.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        rest = rest.trim_start();
        if out.len() > 256 {
            return None;
        }
    }
    Some(out)
}

/// Bytes of `go:generate` argv recorded per file, summed over directives. A
/// `-command` alias is copied into every directive that names it, so without
/// a bound a long alias and many short directives multiply.
const MAX_GENERATE_ARGV_BYTES: usize = 1 << 20;

pub(super) fn execution_facts(root: Node<'_>, source: &str, values: &mut Values) {
    let mut init_count = 0;
    let mut globals = 0;
    let mut tests = Vec::new();
    for node in named_children(root) {
        match node.kind() {
            "function_declaration" => {
                if let Some(n) = node.child_by_field_name("name") {
                    let name = text(n, source);
                    if name == "init" {
                        init_count += 1;
                    }
                    if ["Test", "Benchmark", "Fuzz", "Example"]
                        .iter()
                        .any(|p| name.starts_with(p))
                    {
                        tests.push(name);
                    }
                }
            }
            "var_declaration" => {
                let mut stack: Vec<_> = named_children(node).collect();
                while let Some(n) = stack.pop() {
                    if n.kind() == "var_spec" && n.child_by_field_name("value").is_some() {
                        globals += 1;
                    } else {
                        stack.extend(named_children(n));
                    }
                }
            }
            _ => {}
        }
    }
    let mut directives = Vec::new();
    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    let mut malformed = false;
    let mut argv_bytes = 0usize;
    for (line, text) in source.lines().enumerate() {
        // Match cmd/go's exact line prefix, even inside raw strings: generate
        // explicitly does not parse Go source. Indented/examples do not execute.
        let Some(rest) = text
            .strip_prefix("//go:generate")
            .filter(|s| s.starts_with([' ', '\t']))
        else {
            continue;
        };
        let Some(mut args) = words(rest) else {
            malformed = true;
            continue;
        };
        if let [command, rest @ ..] = args.as_slice()
            && command == "-command"
        {
            if let [name, expansion @ ..] = rest
                && !expansion.is_empty()
            {
                aliases.insert(name.clone(), expansion.to_vec());
            } else {
                malformed = true;
            }
            continue;
        }
        if let Some(expanded) = args.first().and_then(|s| aliases.get(s)).cloned() {
            args.splice(..1, expanded);
        }
        argv_bytes = args
            .iter()
            .map(String::len)
            .fold(argv_bytes, usize::saturating_add);
        if argv_bytes > MAX_GENERATE_ARGV_BYTES {
            tracing::debug!(
                target: "filefacts::source",
                format = "go",
                line = line + 1,
                budget = MAX_GENERATE_ARGV_BYTES,
                "go:generate argv budget spent; later directives omitted"
            );
            malformed = true;
            break;
        }
        let Some(program) = args.first() else {
            continue;
        };
        let command = program.rsplit('/').next().unwrap_or(program);
        let shell = matches!(command, "sh" | "bash" | "dash" | "zsh");
        let body = if shell && args.get(1).is_some_and(|s| s == "-c") {
            args.get(2)
        } else {
            None
        };
        directives.push(json!({"line":line+1,"argv":args,"shell_body":body}));
        if directives.len() >= 1024 {
            malformed = true;
            break;
        }
    }
    values.insert_key(
        value_key!("source.go.package"),
        json!(package_name(root, source)),
    );
    values.insert_key(value_key!("source.go.init_count"), json!(init_count));
    values.insert_key(
        value_key!("source.go.global_initializer_count"),
        json!(globals),
    );
    values.insert_key(value_key!("source.go.test_entry_candidates"), json!(tests));
    values.insert_key(value_key!("source.go.generate"), json!(directives));
    values.insert_key(
        value_key!("source.go.generate_incomplete"),
        json!(malformed),
    );
}

#[cfg(test)]
mod tests;
