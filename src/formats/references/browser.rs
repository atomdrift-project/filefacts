//! Statically known executable references in browser JavaScript.
use tree_sitter::Node;

use crate::formats::source::TreeCache;
use crate::output::{RefKind, RefLocator, Reference};

const MAX_REFERENCES: usize = 128;
const MAX_AST_NODES: usize = 250_000;
const MAX_SIBLINGS: usize = 8;
const MAX_VALUE_DEPTH: usize = 8;
const MAX_URL_BYTES: usize = 4096;

pub(crate) fn extend(cache: &TreeCache<'_>, references: &mut Vec<Reference>) {
    let source = cache.source();
    if !["createElement", "import", "export", "Worker"]
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
            "new_expression" => worker_target(node, source).map(|url| (url, "browser.worker")),
            "import_statement" | "export_statement" => {
                module_source(node).map(|url| (url, "javascript.module-source"))
            }
            _ => None,
        };
        if let Some((url, origin)) = target
            && let Some(value) = constant_string(url, source, 0)
        {
            let offset = url.start_byte() + usize::from(url.kind() == "string");
            push_reference(references, value, origin, offset);
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

fn worker_target<'tree>(expression: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let constructor = expression.child_by_field_name("constructor")?;
    let name = if constructor.kind() == "identifier" {
        text(constructor, source)
    } else {
        let (object, name) = member(constructor, source)?;
        if !matches!(text(object, source), "window" | "self" | "globalThis") {
            return None;
        }
        name
    };
    matches!(name, "Worker" | "SharedWorker").then(|| first_argument(expression))?
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
            if method == "setAttribute"
                && text(parent, source) == name
                && literal(first_argument(expression)?, source)?.eq_ignore_ascii_case("src")
            {
                url = expression.child_by_field_name("arguments")?.named_child(1);
                continue;
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

fn constant_string(node: Node<'_>, source: &str, depth: usize) -> Option<String> {
    if depth >= MAX_VALUE_DEPTH {
        return None;
    }
    let value = match node.kind() {
        "string" => literal(node, source)?.to_owned(),
        "parenthesized_expression" => constant_string(node.named_child(0)?, source, depth + 1)?,
        "binary_expression" if node.child_by_field_name("operator")?.kind() == "+" => {
            let mut value = constant_string(node.child_by_field_name("left")?, source, depth + 1)?;
            let right = constant_string(node.child_by_field_name("right")?, source, depth + 1)?;
            value.push_str(&right);
            value
        }
        "identifier" => constant_string(local_const(node, source)?, source, depth + 1)?,
        _ => return None,
    };
    (value.len() <= MAX_URL_BYTES).then_some(value)
}

fn local_const<'tree>(use_site: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let name = text(use_site, source);
    let mut statement = use_site;
    // Resolve only preceding, immutable bindings in the same statement list.
    // A separate function or block can shadow the name.
    for _ in 0..MAX_VALUE_DEPTH {
        let scope = statement.parent()?;
        if matches!(scope.kind(), "statement_block" | "program") {
            for _ in 0..MAX_SIBLINGS {
                statement = statement.prev_named_sibling()?;
                if statement.kind() != "lexical_declaration" {
                    continue;
                }
                let mut cursor = statement.walk();
                for declaration in statement.named_children(&mut cursor) {
                    let Some(binding) = declaration.child_by_field_name("name") else {
                        continue;
                    };
                    if text(binding, source) == name {
                        return (binding.kind() == "identifier"
                            && statement.child_by_field_name("kind")?.kind() == "const")
                            .then(|| declaration.child_by_field_name("value"))?;
                    }
                }
            }
            return None;
        }
        if matches!(
            scope.kind(),
            "arrow_function" | "function_expression" | "function_declaration"
        ) {
            return None;
        }
        statement = scope;
    }
    None
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
        && value.len() <= MAX_URL_BYTES
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

pub(crate) fn push_reference(
    references: &mut Vec<Reference>,
    value: String,
    source: &str,
    offset: usize,
) {
    let (locator, kind) = if is_http_url(&value) {
        (RefLocator::Url(value.clone()), RefKind::UrlFetch)
    } else if (source == "browser.html-script"
        || matches!(
            source,
            "javascript.dynamic-import" | "javascript.module-source"
        ) && (value.starts_with("./") || value.starts_with("../") || value.starts_with('/')))
        && !value.is_empty()
        && !value.starts_with("//")
        && !value.starts_with(['?', '#'])
        && !value.contains(':')
        && value.len() <= MAX_URL_BYTES
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        // A consuming URL scan can resolve these against the fetched module
        // or document. Loose files keep them inside their local artifact.
        (RefLocator::Path(value.clone()), RefKind::Local)
    } else {
        return;
    };
    let mut reference = Reference::new(locator, kind, source, value);
    reference.offset = Some(offset as u64);
    if let Some(existing) = references
        .iter_mut()
        .find(|r| r.locator == reference.locator)
    {
        if kind == RefKind::Local && existing.source == "import" {
            *existing = reference;
        }
        return;
    }
    references.push(reference);
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn resolves_simple_constants_and_worker_targets_without_crossing_scope() {
        let source = br#"
            function page() {
                const base = 'https://example.invalid/';
                const src = base + 'bound';
                const script = document.createElement('script');
                script.setAttribute('src', src);
                document.head.appendChild(script);
                import(base + 'module');
                import('./relative.js');
                new Worker(base + 'worker');
                function unknown(src) { import(src); }
                if (other) { import(src); }
                let mutable = 'https://example.invalid/mutable';
                import(mutable);
            }
        "#;
        let parsed = crate::OpenOptions::new()
            .path(Path::new("bundle.js"))
            .open(source);
        let refs: Vec<_> = parsed
            .references()
            .iter()
            .map(|r| (r.source.as_str(), &r.locator))
            .collect();
        assert_eq!(
            refs,
            [
                (
                    "javascript.dynamic-import",
                    &RefLocator::Path("./relative.js".into())
                ),
                (
                    "browser.script.src",
                    &RefLocator::Url("https://example.invalid/bound".into())
                ),
                (
                    "javascript.dynamic-import",
                    &RefLocator::Url("https://example.invalid/module".into())
                ),
                (
                    "browser.worker",
                    &RefLocator::Url("https://example.invalid/worker".into())
                ),
            ]
        );
    }

    #[test]
    fn html_references_skip_templates_data_blocks_and_comments() {
        let source = br#"<!doctype html>
            <script type="module" src="./run.js"></script>
            <script src="https://example.invalid/direct"></script>
            <script type="application/json" src="./data"></script>
            <template><script src="./inert"></script></template>
            <!-- <script src="./comment"></script> -->
            <script src=after-template.js></script>
            <textarea><script src="./quoted"></script></textarea>
        "#;
        let parsed = crate::OpenOptions::new()
            .path(Path::new("page.html"))
            .open(source);
        let refs: Vec<_> = parsed
            .references()
            .iter()
            .map(|r| r.evidence.as_str())
            .collect();
        assert_eq!(
            refs,
            [
                "./run.js",
                "https://example.invalid/direct",
                "after-template.js"
            ]
        );
    }

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
