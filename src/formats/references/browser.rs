//! Statically known executable references in browser JavaScript.
use tree_sitter::Node;

use crate::formats::source::TreeCache;
use crate::output::{RefKind, RefLocator, Reference};

const MAX_REFERENCES: usize = 128;
const MAX_AST_NODES: usize = 250_000;
const MAX_SIBLINGS: usize = 8;

pub(crate) fn extend(cache: &TreeCache<'_>, references: &mut Vec<Reference>) {
    let source = cache.source();
    if !source.contains("http")
        || !["createElement", "import", "export"]
            .iter()
            .any(|keyword| source.contains(keyword))
    {
        return;
    }
    // Walking the cached tree keeps comments and quoted examples out of the
    // result. The cursor bounds memory independently of source nesting.
    let mut cursor = cache.tree().walk();
    let initial_count = references.len();
    for _ in 0..MAX_AST_NODES {
        let node = cursor.node();
        let target = match node.kind() {
            "variable_declarator" => {
                script_target(node, source).map(|url| (url, "browser.script.src"))
            }
            "call_expression" => import_target(node).map(|url| (url, "javascript.dynamic-import")),
            "import_statement" | "export_statement" => {
                module_source(node).map(|url| (url, "javascript.module-source"))
            }
            _ => None,
        };
        if let Some((url, origin)) = target
            && let Some(value) = literal(url, source)
            && is_http_url(value)
            && !references.iter().any(|r| {
                matches!(&r.locator, RefLocator::Url(existing) if existing == value)
                    && r.kind == RefKind::UrlFetch
            })
        {
            let mut reference = Reference::new(
                RefLocator::Url(value.into()),
                RefKind::UrlFetch,
                origin,
                value,
            );
            reference.offset = Some(url.start_byte() as u64 + 1);
            references.push(reference);
            if references.len() - initial_count == MAX_REFERENCES {
                break;
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

fn import_target(call: Node<'_>) -> Option<Node<'_>> {
    (call.child_by_field_name("function")?.kind() == "import").then(|| first_argument(call))?
}

fn module_source(statement: Node<'_>) -> Option<Node<'_>> {
    // TypeScript erases type-only imports and exports in emitted code.
    let mut cursor = statement.walk();
    if statement
        .children(&mut cursor)
        .any(|child| child.kind() == "type")
    {
        return None;
    }
    statement.child_by_field_name("source")
}

fn script_target<'tree>(declarator: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let name = declarator.child_by_field_name("name")?;
    let init = declarator.child_by_field_name("value")?;
    let (document, create) = member(init.child_by_field_name("function")?, source)?;
    if name.kind() != "identifier"
        || init.kind() != "call_expression"
        || text(document, source) != "document"
        || create != "createElement"
        || !literal(first_argument(init)?, source)?.eq_ignore_ascii_case("script")
    {
        return None;
    }
    let name = text(name, source);
    let mut statement = declarator.parent()?;
    // Multiple declarators may alias or mutate the element before insertion.
    if statement.named_child_count() != 1 {
        return None;
    }
    let mut url = None;
    for _ in 0..MAX_SIBLINGS {
        statement = statement.next_named_sibling()?;
        if statement.kind() == "comment" {
            continue;
        }
        if statement.kind() != "expression_statement" {
            return None;
        }
        let expression = statement.named_child(0)?;
        if expression.kind() == "call_expression" {
            let (parent, method) = member(expression.child_by_field_name("function")?, source)?;
            if matches!(
                method,
                "appendChild" | "insertBefore" | "append" | "prepend"
            ) && document_container(parent, source)
                && text(first_argument(expression)?, source) == name
            {
                return url;
            }
            return None;
        }
        if expression.kind() != "assignment_expression" {
            return None;
        }
        let (object, property) = member(expression.child_by_field_name("left")?, source)?;
        if text(object, source) != name {
            return None;
        }
        let value = expression.child_by_field_name("right")?;
        match property {
            "src" => url = Some(value),
            "async" | "defer" if matches!(value.kind(), "true" | "false") => {}
            _ => return None,
        }
    }
    None
}

fn document_container(node: Node<'_>, source: &str) -> bool {
    let node = if node.kind() == "parenthesized_expression" {
        let Some(inner) = node.named_child(0) else {
            return false;
        };
        inner
    } else {
        node
    };
    let is_container = |node| {
        member(node, source).is_some_and(|(object, property)| {
            text(object, source) == "document"
                && matches!(property, "head" | "body" | "documentElement")
        })
    };
    is_container(node)
        || node.kind() == "binary_expression"
            && node.child_by_field_name("operator").map(|op| op.kind()) == Some("||")
            && node.child_by_field_name("left").is_some_and(is_container)
            && node.child_by_field_name("right").is_some_and(is_container)
}

fn first_argument(call: Node<'_>) -> Option<Node<'_>> {
    call.child_by_field_name("arguments")?.named_child(0)
}

fn member<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> Option<(Node<'tree>, &'source str)> {
    let object = node.child_by_field_name("object")?;
    let property = match node.kind() {
        "member_expression" => text(node.child_by_field_name("property")?, source),
        "subscript_expression" => literal(node.child_by_field_name("index")?, source)?,
        _ => return None,
    };
    Some((object, property))
}

fn literal<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "string").then_some(())?;
    let raw = text(node, source);
    let value = raw.get(1..raw.len().checked_sub(1)?)?;
    (!value.contains('\\') && !node.has_error()).then_some(value)
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

fn is_http_url(value: &str) -> bool {
    let Some(authority) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .and_then(|rest| rest.split(['/', '?', '#']).next())
    else {
        return false;
    };
    !authority.is_empty()
        && !authority.contains('@')
        && value.len() <= 4096
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn executable_references_have_offsets_and_ignore_other_urls() {
        let source = br#"
            (function(){try{var s=document.createElement('script');
              s.src='https://example.invalid/a'; s.async=true;
              (document.head||document.documentElement).appendChild(s);
            }catch(e){}})();
            const other = document['createElement']('script');
            other['src'] = 'https://example.invalid/b';
            document['body']['insertBefore'](other, null);
            import('https://example.invalid/c');
            export { d } from 'https://example.invalid/d';
            // import('https://example.invalid/comment')
            const text = "import('https://example.invalid/string')";
            const img = document.createElement('img');
            img.src = 'https://example.invalid/image';
            document.head.appendChild(img);
            const unused = document.createElement('script');
            unused.src = 'https://example.invalid/unused';
        "#;
        let parsed = crate::OpenOptions::new()
            .path(Path::new("bundle.js"))
            .open(source);
        let urls: Vec<_> = parsed
            .references()
            .iter()
            .filter(|r| r.kind == RefKind::UrlFetch)
            .map(|r| {
                let RefLocator::Url(url) = &r.locator else {
                    panic!("expected URL")
                };
                let offset = r.offset.unwrap() as usize;
                assert_eq!(&source[offset..offset + url.len()], url.as_bytes());
                url.as_str()
            })
            .collect();
        assert_eq!(
            urls,
            [
                "https://example.invalid/a",
                "https://example.invalid/b",
                "https://example.invalid/c",
                "https://example.invalid/d",
            ]
        );
    }

    #[test]
    fn stops_at_object_replacement_and_rejects_non_http_imports() {
        let source = br#"
            let script = document.createElement('script');
            script.src = 'https://example.invalid/unused';
            script = anotherElement;
            document.head.appendChild(script);
            import('data:text/javascript,0');
            import('https://name@example.invalid/confusing');
            import type { T } from 'https://example.invalid/types';
            export type { T } from 'https://example.invalid/re-export';
        "#;
        let parsed = crate::OpenOptions::new()
            .path(Path::new("bundle.ts"))
            .open(source);
        assert!(parsed.references().is_empty());
    }
}
