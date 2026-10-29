//! Rust use trees, item attributes and scoped call names, without compiler
//! execution.
use super::text;
use super::visit::{NodeIds, Visit};
use crate::value_key;
use crate::{Symbol, Symbols};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Push every path the `use` tree `node` imports, under `prefix`.
fn expand(node: Node<'_>, source: &str, prefix: &str, out: &mut Vec<(String, u64)>, depth: usize) {
    if depth > 64 || out.len() >= MAX_ITEMS {
        return;
    }
    let owned = |n: Node<'_>| text(n, source).to_string();
    match node.kind() {
        "scoped_use_list" => {
            let path = node
                .child_by_field_name("path")
                .map(owned)
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
                    format!("{} as {}", join(prefix, &owned(path)), owned(alias)),
                    node.start_byte() as u64,
                ));
            }
        }
        "identifier" | "scoped_identifier" | "self" | "use_wildcard" => {
            out.push((join(prefix, &owned(node)), node.start_byte() as u64));
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

/// Collected items past which [`Items`] stops recording, and imports past
/// which it stops expanding `use` trees.
const MAX_ITEMS: usize = 10_000;

/// What the shared walk ([`super::visit`]) collects from Rust source: `use`
/// trees, out-of-line `mod` declarations, initializer and proc-macro
/// attributes, and the test-only items every analysis skips.
///
/// Attribute and module facts are syntax-derived, never matched in comments
/// or quoted examples. Module paths are relative to the file; the consumer
/// resolves them against sibling members.
#[derive(Default)]
pub(super) struct Items {
    /// One per open node.
    frames: Vec<ItemFrame>,
    /// The module path below the open node, `a/b/` inside `mod a { mod b { … } }`.
    path: String,
    /// `use` paths in source order, `path as alias` when renamed.
    pub(super) imports: Vec<(String, u64)>,
    pub(super) imports_limited: bool,
    /// Node ids of items gated by a `#[cfg(test)]` or `#[test]` attribute.
    pub(super) test_only: HashSet<usize>,
    modules: Vec<serde_json::Value>,
    initializers: Vec<&'static str>,
    proc_macro: bool,
    limited: bool,
}

#[derive(Default)]
struct ItemFrame {
    /// The attributes of the run of `attribute_item`s among the named
    /// children entered so far, whitespace removed; they apply to the next
    /// named child.
    attributes: Vec<String>,
    /// Item facts are read below this node: it is not a function body, a
    /// test-only item or a module declared out of line.
    open: bool,
    /// Length of [`Items::path`] to restore on exit, for a module with a body.
    restore: Option<usize>,
}

impl Items {
    pub(super) fn enter(&mut self, visit: &Visit<'_>, source: &str, ids: &NodeIds) {
        let node = visit.node;
        let Some(parent) = self.frames.last_mut() else {
            self.frames.push(ItemFrame {
                open: true,
                ..ItemFrame::default()
            });
            return;
        };
        if !visit.named {
            self.frames.push(ItemFrame::default());
            return;
        }
        if ids.attribute_item.contains(visit.kind_id) {
            parent
                .attributes
                .push(text(node, source).split_whitespace().collect());
            self.frames.push(ItemFrame::default());
            return;
        }
        // Anything else between an attribute and its item, a comment
        // included, ends the run.
        let attributes = std::mem::take(&mut parent.attributes);
        let parent_open = parent.open;
        let mut frame = ItemFrame {
            open: parent_open,
            ..ItemFrame::default()
        };
        if attributes
            .iter()
            .any(|a| a == "#[cfg(test)]" || a == "#[test]")
        {
            self.test_only.insert(node.id());
            frame.open = false;
        }
        if ids.use_declaration.contains(visit.kind_id) {
            if let Some(argument) = node.child_by_field_name("argument") {
                expand(argument, source, "", &mut self.imports, 0);
                if self.imports.len() >= MAX_ITEMS {
                    self.imports_limited = true;
                }
            }
        }
        if frame.open && !self.limited {
            let kind = ids.rust_item.contains(visit.kind_id).then(|| node.kind());
            self.item(node, kind, source, &attributes, &mut frame);
        }
        self.frames.push(frame);
    }

    /// Record the facts of an item reached through open items.
    /// `kind` is the node's kind when it is a function or module.
    fn item(
        &mut self,
        node: Node<'_>,
        kind: Option<&str>,
        source: &str,
        attributes: &[String],
        frame: &mut ItemFrame,
    ) {
        if self.modules.len() + self.initializers.len() > MAX_ITEMS {
            tracing::debug!(
                target: "filefacts::source",
                format = "rust",
                offset = node.start_byte(),
                max = MAX_ITEMS,
                "rust items: item budget exhausted; later modules and initializers omitted"
            );
            self.limited = true;
            return;
        }
        for attribute in attributes {
            if attribute.starts_with("#[ctor::ctor") || attribute == "#[ctor]" {
                self.initializers.push("ctor");
            }
            if attribute.starts_with("#[link_section=")
                || attribute.starts_with("#[unsafe(link_section=")
            {
                if attribute.contains("\".init_array\"") {
                    self.initializers.push("elf-init-array");
                }
                if attribute.contains("__mod_init_func") {
                    self.initializers.push("macho-mod-init-func");
                }
                if attribute.contains(".CRT$XCU") || attribute.contains(".CRT$XCT") {
                    self.initializers.push("pe-crt-initializer");
                }
            }
        }
        match kind {
            // Function-local module names cannot be resolved as crate siblings.
            Some("function_item") => {
                self.proc_macro |= attributes.iter().any(|a| {
                    a == "#[proc_macro]"
                        || a == "#[proc_macro_attribute]"
                        || a.starts_with("#[proc_macro_derive(")
                });
                frame.open = false;
            }
            Some("mod_item") => {
                let Some(name) = node.child_by_field_name("name") else {
                    return;
                };
                let name = text(name, source);
                if node.child_by_field_name("body").is_some() {
                    frame.restore = Some(self.path.len());
                    self.path.push_str(name);
                    self.path.push('/');
                } else {
                    let path = attributes.iter().find_map(|a| {
                        a.strip_prefix("#[path=\"")
                            .and_then(|p| p.strip_suffix("\"]"))
                    });
                    self.modules
                        .push(serde_json::json!({"name": name, "prefix": self.path, "path": path}));
                    frame.open = false;
                }
            }
            _ => {}
        }
    }

    pub(super) fn exit(&mut self) {
        if let Some(restore) = self.frames.pop().and_then(|frame| frame.restore) {
            self.path.truncate(restore);
        }
    }

    /// Write `source.rust.*`.
    pub(super) fn emit(&mut self, values: &mut crate::Values) {
        self.initializers.sort_unstable();
        self.initializers.dedup();
        values.insert_key(
            value_key!("source.rust.modules"),
            serde_json::json!(self.modules),
        );
        values.insert_key(
            value_key!("source.rust.proc_macro"),
            serde_json::json!(self.proc_macro),
        );
        values.insert_key(
            value_key!("source.rust.initializers"),
            serde_json::json!(self.initializers),
        );
    }
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
mod tests;
