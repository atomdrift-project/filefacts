//! Whether a JavaScript, TypeScript or Python module holds only constant
//! data: quoted strings bound to names, and nothing that runs. A string in
//! such a module is data even when its text is source code, so a consumer
//! need not treat it as an embedded program. `source.data_only`.

use tree_sitter::Node;

use super::langs::Lang;

/// Largest source judged; anything larger is not reported as data-only.
const MAX_SOURCE: usize = 4 * 1024 * 1024;
/// Most top-level statements a data-only module may have.
const MAX_STATEMENTS: usize = 4096;

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect()
}

/// Whether the module `root` parses `source` into is data-only, for a
/// language this recognizes.
pub(super) fn is_data_only(root: Node<'_>, source: &str, lang: Lang) -> bool {
    if source.len() > MAX_SOURCE || root.has_error() {
        return false;
    }
    let statements = children(root);
    if statements.is_empty() || statements.len() > MAX_STATEMENTS {
        return false;
    }
    if lang.is_ecmascript() {
        ecmascript(&statements, source)
    } else if lang == Lang::Python {
        statements.into_iter().all(python_statement)
    } else {
        false
    }
}

/// `const name = 'text', …;` declarations only, or a lone
/// `module.exports = 'text';`. Exporting a literal exposes data; it does
/// not run the text inside it.
fn ecmascript(statements: &[Node<'_>], source: &str) -> bool {
    let text = |node: Node<'_>| source.get(node.byte_range()).unwrap_or("");
    if let [statement] = statements
        && statement.kind() == "expression_statement"
        && let [assignment] = children(*statement).as_slice()
        && assignment.kind() == "assignment_expression"
        && assignment
            .child_by_field_name("left")
            .is_some_and(|left| text(left) == "module.exports")
        && assignment
            .child_by_field_name("right")
            .is_some_and(|right| right.kind() == "string")
    {
        return true;
    }
    statements.iter().all(|&statement| {
        if statement.kind() != "lexical_declaration" || !text(statement).starts_with("const ") {
            return false;
        }
        let declarations = children(statement);
        !declarations.is_empty()
            && declarations.into_iter().all(|declarator| {
                declarator.kind() == "variable_declarator"
                    && declarator
                        .child_by_field_name("name")
                        .is_some_and(|name| name.kind() == "identifier")
                    && declarator
                        .child_by_field_name("value")
                        .is_some_and(|value| value.kind() == "string")
            })
    })
}

/// A string with no interpolation.
fn plain_python_string(node: Node<'_>) -> bool {
    node.kind() == "string"
        && children(node).into_iter().all(|child| {
            matches!(
                child.kind(),
                "string_start" | "string_content" | "string_end"
            )
        })
}

/// A docstring, or `name = 'text'` with no annotation.
fn python_statement(statement: Node<'_>) -> bool {
    if statement.kind() != "expression_statement" {
        return false;
    }
    let [expression] = children(statement)[..] else {
        return false;
    };
    plain_python_string(expression)
        || (expression.kind() == "assignment"
            && expression.child_by_field_name("type").is_none()
            && expression
                .child_by_field_name("left")
                .is_some_and(|left| left.kind() == "identifier")
            && expression
                .child_by_field_name("right")
                .is_some_and(plain_python_string))
}

#[cfg(test)]
mod tests;
