//! Parsed PHP calls inside passive media. No sample code is executed.
use crate::fileid::FileType;
use crate::formats::source::TreeCache;
use crate::{output::Values, value_key};
use serde_json::Value;
use std::collections::BTreeSet;
use tree_sitter::Node;

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 100_000;
/// Bytes after a tag's `<?` that must be text for it to count as a tag.
const CODE_PROBE: usize = 8;

pub(crate) fn extract(bytes: &[u8], values: &mut Values) {
    // The full PHP grammar treats bytes outside PHP tags as inline text.
    // Gate the uncommon parse cheaply, including uppercase and short-echo tags.
    if !bytes
        .windows(3)
        .any(|w| w == b"<?=" || w.eq_ignore_ascii_case(b"<?p"))
    {
        return;
    }
    if bytes.len() > MAX_BYTES {
        values.insert_key(value_key!("media.php.analysis_limited"), Value::Bool(true));
        return;
    }
    // The PHP grammar also accepts configuration-dependent bare <? tags.
    // Normalize those away: these facts require a valid long or echo tag.
    let mut normalized = bytes.to_vec();
    let mut first_tag = None;
    for (offset, pair) in bytes.windows(2).enumerate() {
        if pair != b"<?" {
            continue;
        }
        let Some(tag) = bytes.get(offset + 2..) else {
            continue;
        };
        // A tag the interpreter could run is followed by code. In compressed
        // media `<?=` turns up by chance, followed by binary bytes the PHP
        // lexer rejects; parsing from there costs a full error-recovery pass.
        let code_follows = tag
            .iter()
            .skip(1)
            .take(CODE_PROBE)
            .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (b' '..=b'~').contains(&b));
        if code_follows
            && (tag.starts_with(b"=")
                || (tag.get(..3).is_some_and(|p| p.eq_ignore_ascii_case(b"php"))
                    && tag.get(3).is_some_and(u8::is_ascii_whitespace)))
        {
            first_tag.get_or_insert(offset);
        } else if let Some(byte) = normalized.get_mut(offset + 1) {
            *byte = b' ';
        }
    }
    let Some(first_tag) = first_tag else {
        return;
    };
    // Binary prefixes can place arbitrary comment/string delimiters before
    // the opening PHP tag. They are inline output, not PHP lexer context.
    let Some(source) = normalized.get(first_tag..) else {
        return;
    };
    // The shared source parser counts work, not time, so the outcome (and
    // what the content-keyed cache keeps) never depends on load.
    let parsed = TreeCache::parse(source, FileType::Php, None);
    let Some(cache) = parsed.cache() else {
        tracing::debug!(
            target: "filefacts::embedded_php",
            len = source.len(),
            error = parsed.diagnostic().map_or("", |d| d.message.as_str()),
            "embedded PHP did not parse within its budget"
        );
        values.insert_key(value_key!("media.php.analysis_limited"), Value::Bool(true));
        return;
    };
    let root = cache.tree().root_node();
    let text = cache.source().as_bytes();
    let mut root_cursor = root.walk();
    let has_namespace = root
        .named_children(&mut root_cursor)
        .any(|node| node.kind() == "namespace_definition");
    let mut calls = BTreeSet::new();
    let mut pending = vec![root];
    let mut visited = 0;
    while let Some(node) = pending.pop() {
        visited += 1;
        if visited > MAX_NODES || node.named_child_count() > MAX_NODES - visited {
            tracing::debug!(
                target: "filefacts::embedded_php",
                budget = MAX_NODES,
                "embedded PHP node budget spent"
            );
            values.insert_key(value_key!("media.php.analysis_limited"), Value::Bool(true));
            return; // Never emit relationships from an incomplete walk.
        }
        if node.is_error() || node.is_missing() {
            continue;
        }
        if node.kind() == "function_call_expression"
            && !node.has_error()
            && let Some(name) = request_call(node, text, has_namespace)
        {
            calls.insert(name);
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    if !calls.is_empty() {
        values.insert_key(
            value_key!("media.php.request_calls"),
            Value::Array(calls.into_iter().map(Value::String).collect()),
        );
    }
}

fn request_call(node: Node<'_>, bytes: &[u8], has_namespace: bool) -> Option<String> {
    let function = node.child_by_field_name("function")?;
    if !matches!(function.kind(), "name" | "qualified_name") {
        return None;
    }
    let name = function.utf8_text(bytes).ok()?;
    let canonical = name.strip_prefix('\\').unwrap_or(name);
    if canonical.contains('\\') {
        return None;
    }
    // An unqualified call in a namespace may resolve to a local function.
    if !name.starts_with('\\') && has_namespace {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let argument = args
        .named_children(&mut cursor)
        .find(|n| n.kind() != "comment")?;
    if argument.kind() != "argument" {
        return None;
    }
    let mut first = argument.named_child(0)?;
    while first.kind() == "parenthesized_expression" {
        first = first.named_child(0)?;
    }
    if first.kind() != "subscript_expression" {
        return None;
    }
    while first.kind() == "subscript_expression" {
        first = first.named_child(0)?;
    }
    if first.kind() != "variable_name" {
        return None;
    }
    if !matches!(
        first.utf8_text(bytes).ok()?,
        "$_GET" | "$_POST" | "$_REQUEST" | "$_COOKIE" | "$_FILES"
    ) {
        return None;
    }
    Some(canonical.to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
