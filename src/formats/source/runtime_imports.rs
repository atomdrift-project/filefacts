//! Static ES module edges that can execute at runtime. Type-only imports and
//! exports are excluded; names and offsets are kept for dependency discovery.
use super::visit::Visit;
use super::{SOURCE_QUERY_OUTPUT_LIMIT, named_children, strip_quotes, text};
use crate::{Values, value_key};
use serde_json::Value;
use tree_sitter::Node;

/// The top-level `import`/`export … from` statements the shared walk
/// ([`super::visit`]) reaches, in source order.
#[derive(Default)]
pub(super) struct Collector {
    rows: Vec<Value>,
}

impl Collector {
    pub(super) fn enter(&mut self, visit: &Visit<'_>, source: &str) {
        let statement = visit.node;
        if visit.depth != 1
            || self.rows.len() >= SOURCE_QUERY_OUTPUT_LIMIT
            || !matches!(statement.kind(), "import_statement" | "export_statement")
        {
            return;
        }
        let Some(module) = statement.child_by_field_name("source") else {
            return;
        };
        if module.kind() != "string" || statement_has_type_only_clause(statement) {
            return;
        }
        let specifier = strip_quotes(text(module, source));
        if !specifier.is_empty() {
            self.rows
                .push(serde_json::json!({"specifier": specifier, "offset": module.start_byte()}));
        }
    }

    /// Write `source.js.runtime_imports`.
    pub(super) fn emit(self, values: &mut Values) {
        if !self.rows.is_empty() {
            values.insert_key(
                value_key!("source.js.runtime_imports"),
                Value::Array(self.rows),
            );
        }
    }
}

/// TypeScript allows both `import type {X}` and per-specifier `type X`.
/// A side-effect import, default binding, namespace binding, or any value
/// specifier makes the edge runtime. Empty clauses retain the module edge.
fn statement_has_type_only_clause(statement: Node<'_>) -> bool {
    let mut cursor = statement.walk();
    if statement.children(&mut cursor).any(|n| n.kind() == "type") {
        return true;
    }
    let Some(clause) =
        named_children(statement).find(|n| matches!(n.kind(), "import_clause" | "export_clause"))
    else {
        return false;
    };
    let list = if clause.kind() == "import_clause" {
        let children: Vec<_> = named_children(clause).collect();
        if children.iter().any(|n| n.kind() != "named_imports") {
            return false;
        }
        children.into_iter().find(|n| n.kind() == "named_imports")
    } else {
        Some(clause)
    };
    let Some(list) = list else { return false };
    let specs: Vec<_> = named_children(list)
        .filter(|n| matches!(n.kind(), "import_specifier" | "export_specifier"))
        .collect();
    !specs.is_empty()
        && specs.into_iter().all(|spec| {
            let mut cursor = spec.walk();
            spec.children(&mut cursor).any(|n| n.kind() == "type")
        })
}
