//! Rust use trees and scoped call names, without compiler execution.
use crate::{Symbol, Symbols};
use std::collections::HashMap;
use tree_sitter::Node;

pub(super) fn imports(root: Node<'_>, source: &str) -> Vec<(String, u64)> {
    let mut result = Vec::new();
    let mut nodes = vec![root];
    while let Some(node) = nodes.pop() {
        if result.len() >= 10_000 {
            break;
        }
        if node.kind() == "use_declaration" {
            if let Some(arg) = node.child_by_field_name("argument") {
                expand(arg, source, "", &mut result, 0);
            }
        } else {
            let mut cursor = node.walk();
            nodes.extend(node.named_children(&mut cursor));
        }
    }
    result.sort_by_key(|(_, offset)| *offset);
    result
}

fn expand(node: Node<'_>, source: &str, prefix: &str, out: &mut Vec<(String, u64)>, depth: usize) {
    if depth > 64 || out.len() >= 10_000 {
        return;
    }
    let text = |n: Node<'_>| n.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    match node.kind() {
        "scoped_use_list" => {
            let path = node
                .child_by_field_name("path")
                .map(text)
                .unwrap_or_default();
            let joined = join(prefix, &path);
            if let Some(list) = node.child_by_field_name("list") {
                expand(list, source, &joined, out, depth + 1);
            }
        }
        "use_list" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                expand(child, source, prefix, out, depth + 1);
            }
        }
        "use_as_clause" => {
            if let (Some(path), Some(alias)) = (
                node.child_by_field_name("path"),
                node.child_by_field_name("alias"),
            ) {
                out.push((
                    format!("{} as {}", join(prefix, &text(path)), text(alias)),
                    node.start_byte() as u64,
                ));
            }
        }
        "identifier" | "scoped_identifier" | "self" | "use_wildcard" => {
            out.push((join(prefix, &text(node)), node.start_byte() as u64));
        }
        _ => {}
    }
}

fn join(prefix: &str, tail: &str) -> String {
    if tail == "self" {
        prefix.to_string()
    } else if prefix.is_empty() {
        tail.to_string()
    } else {
        format!("{prefix}::{tail}")
    }
}

/// Attribute and module facts are syntax-derived, never matched in comments
/// or quoted examples. The consumer resolves modules against archive members.
pub(super) fn execution_facts(root: Node<'_>, source: &str, values: &mut crate::Values) {
    let mut modules = Vec::new();
    let mut initializers = Vec::new();
    let mut proc_macro = false;
    let mut stack = vec![(root, String::new())];
    while let Some((node, prefix)) = stack.pop() {
        if modules.len() + initializers.len() > 10_000 {
            break;
        }
        let mut attrs = Vec::new();
        let mut previous = node.prev_named_sibling();
        while let Some(attr) = previous.filter(|n| n.kind() == "attribute_item") {
            attrs.push(
                source[attr.byte_range()]
                    .split_whitespace()
                    .collect::<String>(),
            );
            previous = attr.prev_named_sibling();
        }
        if attrs.iter().any(|s| s == "#[cfg(test)]" || s == "#[test]") {
            continue;
        }
        if node.kind() == "function_item" {
            proc_macro |= attrs.iter().any(|s| {
                s == "#[proc_macro]"
                    || s == "#[proc_macro_attribute]"
                    || s.starts_with("#[proc_macro_derive(")
            });
        }
        for attr in &attrs {
            if attr.starts_with("#[ctor::ctor") || attr == "#[ctor]" {
                initializers.push("ctor");
            }
            if attr.starts_with("#[link_section=") || attr.starts_with("#[unsafe(link_section=") {
                if attr.contains("\".init_array\"") {
                    initializers.push("elf-init-array");
                }
                if attr.contains("__mod_init_func") {
                    initializers.push("macho-mod-init-func");
                }
                if attr.contains(".CRT$XCU") || attr.contains(".CRT$XCT") {
                    initializers.push("pe-crt-initializer");
                }
            }
        }
        let mut nested_prefix = prefix.clone();
        if node.kind() == "mod_item" {
            if let Some(name) = node.child_by_field_name("name") {
                let name = &source[name.byte_range()];
                if node.child_by_field_name("body").is_none() {
                    let override_path = attrs.iter().find_map(|s| {
                        s.strip_prefix("#[path=\"")
                            .and_then(|p| p.strip_suffix("\"]"))
                    });
                    modules.push(
                        serde_json::json!({"name":name,"prefix":prefix,"path":override_path}),
                    );
                    continue;
                }
                nested_prefix = format!("{prefix}{name}/");
            }
        }
        // Function-local module names cannot be resolved as crate siblings.
        if node.kind() == "function_item" {
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(
            node.named_children(&mut cursor)
                .map(|n| (n, nested_prefix.clone())),
        );
    }
    initializers.sort_unstable();
    initializers.dedup();
    values.insert("source.rust.modules", serde_json::json!(modules));
    values.insert("source.rust.proc_macro", serde_json::json!(proc_macro));
    values.insert("source.rust.initializers", serde_json::json!(initializers));
}

pub(super) fn resolve_calls(symbols: &mut Symbols) {
    let aliases: HashMap<String, String> = symbols
        .iter()
        .filter_map(|symbol| {
            if let Symbol::Import { name, alias, .. } = symbol {
                let local = alias
                    .clone()
                    .or_else(|| name.rsplit("::").next().map(str::to_string))?;
                (local != "*").then(|| (local, name.clone()))
            } else {
                None
            }
        })
        .collect();
    for symbol in symbols.iter_mut() {
        if let Symbol::Call {
            target: Some(target),
            ..
        } = symbol
        {
            let end = target.find([':', '.', '(']).unwrap_or(target.len());
            if let Some(qualified) = aliases.get(&target[..end]) {
                *target = format!("{}{}", qualified, &target[end..]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Symbol, open_with_path};
    use std::path::Path;
    #[test]
    fn rust_grouped_aliases_scoped_calls_and_let_binds() {
        let parsed=open_with_path(Path::new("lib.rs"),br#"
use std::{env::{vars as environment}, fs};
use reqwest::blocking::Client;
fn run() { let data=environment(); let client=Client::new(); client.post("https://example.invalid").json(&data).send(); }
"#).unwrap();
        let imports = parsed
            .symbols()
            .iter()
            .filter_map(|s| {
                if let Symbol::Import { name, alias, .. } = s {
                    Some((name.as_str(), alias.as_deref()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert!(
            imports.contains(&("std::env::vars", Some("environment"))),
            "{imports:?}"
        );
        assert!(imports.contains(&("std::fs", None)), "{imports:?}");
        assert!(
            imports.contains(&("reqwest::blocking::Client", None)),
            "{imports:?}"
        );
        assert!(
            parsed
                .symbols()
                .iter()
                .any(|s| matches!(s,Symbol::Call{target:Some(n),..} if n=="std::env::vars"))
        );
        assert!(parsed.symbols().iter().any(
            |s| matches!(s,Symbol::Call{target:Some(n),..} if n=="reqwest::blocking::Client::new")
        ));
        assert!(
            parsed
                .symbols()
                .iter()
                .any(|s| matches!(s,Symbol::Bind{target,..} if target=="data"))
        );
    }
}
