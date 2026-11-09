//! Source in another language that a file carries verbatim, located for the
//! caller to analyze as that language: `embedded.sources`, a list of
//! `{language, offset, size}` with byte offsets into the file. An anonymous
//! range of the file's own bytes; a source a format names (a VBA module, an
//! archive member) is not listed here.
//!
//! For a JavaScript or TypeScript file:
//!
//! - `php`: every `<?php … ?>` block. PHP's `include` runs each block in
//!   the raw bytes of the file it includes, whatever the host language makes
//!   of them: OpenX 2.8.10 hid `eval($_POST[…])` in a string literal of its
//!   bundled flowplayer and had PHP `require_once` it. Found in the bytes,
//!   so a file too large to parse is still searched. An escaped tag, as in
//!   `/<\?php/`, is not a tag to PHP.
//! - `csharp`: the body of the documented Edge.js comment convention. Read
//!   from the syntax tree, and only when the parsed text is the file's bytes.

use serde_json::{Value as JsonValue, json};
use tree_sitter::Node;

use super::TreeCache;
use crate::output::Values;
use crate::value_key;

/// Record `sources` (language, byte offset, byte size) as `embedded.sources`,
/// in offset order. Records nothing when there are none.
pub(crate) fn record(values: &mut Values, mut sources: Vec<(&'static str, usize, usize)>) {
    if sources.is_empty() {
        return;
    }
    sources.sort_by_key(|&(_, offset, _)| offset);
    let list = sources
        .into_iter()
        .map(|(language, offset, size)| json!({"language": language, "offset": offset, "size": size}))
        .collect();
    values.insert_key(value_key!("embedded.sources"), JsonValue::Array(list));
}

/// The most PHP blocks located in one file.
const MAX_PHP_BLOCKS: usize = 8;

/// Each PHP block in `bytes`, as `(offset, size)`: from its open tag through
/// its close tag, or to the end of the file when it has none, as PHP reads it.
fn php_blocks(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while out.len() < MAX_PHP_BLOCKS {
        let Some(start) = bytes.get(from..).and_then(php_open_tag).map(|i| from + i) else {
            break;
        };
        let body = start + 2;
        let end = bytes
            .get(body..)
            .and_then(|rest| memchr::memmem::find(rest, b"?>"))
            .map_or(bytes.len(), |i| body + i + 2);
        out.push((start, end - start));
        from = end;
    }
    out
}

/// The offset of the first tag PHP opens a block at: `<?php` in any case
/// followed by whitespace, or the echo tag `<?=`.
fn php_open_tag(bytes: &[u8]) -> Option<usize> {
    memchr::memmem::find_iter(bytes, b"<?").find(|&i| {
        let rest = bytes.get(i + 2..).unwrap_or_default();
        match rest {
            [b'=', ..] => true,
            [p, h, q, space, ..] => {
                [*p, *h, *q].eq_ignore_ascii_case(b"php") && space.is_ascii_whitespace()
            }
            _ => false,
        }
    })
}

fn text<'a>(n: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(n.byte_range())
}

fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = n.walk();
    n.named_children(&mut cursor).collect()
}

fn literal<'a>(n: Node<'_>, source: &'a str) -> Option<&'a str> {
    if n.kind() != "string" {
        return None;
    }
    let raw = text(n, source)?;
    let body = raw.get(1..raw.len().checked_sub(1)?)?;
    (!body.contains('\\')).then_some(body)
}

/// The C# bodies an Edge.js (`edge-js`, `electron-edge-js`) module passes as
/// `edge.func(function(){/* … */})`, as `(offset, size)` in `source`: the
/// documented comment convention, bound to the module's own `require`.
fn edge_csharp(root: Node<'_>, source: &str) -> Vec<(usize, usize)> {
    if source.len() > 4 * 1024 * 1024 || !source.contains("edge-js") || !source.contains("func") {
        return vec![];
    }
    let mut all = Vec::new();
    let mut cursor = root.walk();
    loop {
        all.push(cursor.node());
        if all.len() > 1_000_000 {
            return vec![];
        }
        if cursor.goto_first_child() || cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                break;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
        if cursor.node() == root {
            break;
        }
    }
    // A lexically shadowed or escaped require is outside this recognizer.
    if all.iter().any(|n| {
        n.kind() == "identifier"
            && text(*n, source) == Some("require")
            && !n.parent().is_some_and(|p| {
                p.kind() == "call_expression" && p.child_by_field_name("function") == Some(*n)
            })
    }) {
        return vec![];
    }
    let mut out = Vec::new();
    for declaration in all
        .iter()
        .copied()
        .filter(|n| n.kind() == "variable_declarator")
    {
        let Some(binding) = declaration
            .child_by_field_name("name")
            .filter(|n| n.kind() == "identifier")
        else {
            continue;
        };
        let Some(name) = text(binding, source) else {
            continue;
        };
        let Some(value) = declaration
            .child_by_field_name("value")
            .filter(|n| n.kind() == "call_expression")
        else {
            continue;
        };
        if value
            .child_by_field_name("function")
            .and_then(|n| text(n, source))
            != Some("require")
        {
            continue;
        }
        let Some(args) = value.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(args);
        if args.len() != 1
            || !args
                .first()
                .and_then(|n| literal(*n, source))
                .is_some_and(|s| matches!(s, "edge-js" | "electron-edge-js"))
        {
            continue;
        }
        let refs: Vec<_> = all
            .iter()
            .copied()
            .filter(|n| {
                matches!(
                    n.kind(),
                    "identifier"
                        | "shorthand_property_identifier"
                        | "shorthand_property_identifier_pattern"
                ) && text(*n, source) == Some(name)
            })
            .collect();
        if refs.len() != 2 {
            continue;
        }
        let Some(receiver) = refs.iter().copied().find(|n| n.id() != binding.id()) else {
            continue;
        };
        let Some(member) = receiver.parent().filter(|n| {
            matches!(n.kind(), "member_expression" | "subscript_expression")
                && n.child_by_field_name("object") == Some(receiver)
        }) else {
            continue;
        };
        let key = member
            .child_by_field_name("property")
            .and_then(|n| text(n, source))
            .or_else(|| {
                member
                    .child_by_field_name("index")
                    .and_then(|n| literal(n, source))
            });
        if key != Some("func") {
            continue;
        }
        let Some(call) = member.parent().filter(|n| {
            n.kind() == "call_expression" && n.child_by_field_name("function") == Some(member)
        }) else {
            continue;
        };
        let Some(scope) = declaration.parent().and_then(|n| n.parent()) else {
            continue;
        };
        if receiver.start_byte() < declaration.end_byte()
            || receiver.end_byte() > scope.end_byte()
            || receiver.start_byte() < scope.start_byte()
        {
            continue;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(args);
        let &[function] = args.as_slice() else {
            continue;
        };
        if function.kind() != "function_expression" {
            continue;
        }
        if !function
            .child_by_field_name("parameters")
            .is_some_and(|n| children(n).is_empty())
        {
            continue;
        }
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let &[comment_node] = children(body).as_slice() else {
            continue;
        };
        if comment_node.kind() != "comment" {
            continue;
        }
        let Some(comment) = text(comment_node, source)
            .and_then(|s| s.strip_prefix("/*"))
            .and_then(|s| s.strip_suffix("*/"))
        else {
            continue;
        };
        if comment.len() < 64 || comment.len() > 1024 * 1024 {
            continue;
        }
        out.push((comment_node.start_byte() + 2, comment.len()));
        if out.len() >= 8 {
            break;
        }
    }
    out
}

/// Write `embedded.sources` for a JavaScript or TypeScript file.
pub(crate) fn emit(bytes: &[u8], tree_cache: Option<&TreeCache<'_>>, values: &mut Values) {
    let mut found: Vec<(&str, usize, usize)> = php_blocks(bytes)
        .into_iter()
        .map(|(offset, size)| ("php", offset, size))
        .collect();
    if let Some(cache) = tree_cache
        && cache.source().as_bytes() == bytes
    {
        found.extend(
            edge_csharp(cache.tree().root_node(), cache.source())
                .into_iter()
                .map(|(offset, size)| ("csharp", offset, size)),
        );
    }
    record(values, found);
}

#[cfg(test)]
mod tests;
