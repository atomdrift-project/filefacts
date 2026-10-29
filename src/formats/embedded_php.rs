//! Parsed PHP calls inside passive media. No sample code is executed.
use crate::{output::Values, value_key};
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};
use tree_sitter::Node;

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 100_000;

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
        if tag.starts_with(b"=")
            || (tag.get(..3).is_some_and(|p| p.eq_ignore_ascii_case(b"php"))
                && tag.get(3).is_some_and(u8::is_ascii_whitespace))
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
    // Begin at the first supported tag, keeping the original suffix for
    // node text and the normalized suffix for parsing.
    let (Some(original), Some(source)) = (bytes.get(first_tag..), normalized.get(first_tag..))
    else {
        return;
    };
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .is_err()
    {
        return;
    }
    // Count parser work rather than charging scheduler delays as CPU work.
    // Keep a wall backstop for a pathological external scanner as well.
    let deadline = Instant::now() + Duration::from_secs(2);
    let polls = Cell::new(0usize);
    let fetched = Cell::new(0usize);
    let fetch_budget = bytes.len().saturating_mul(16).saturating_add(4096);
    let mut progress = |_: &tree_sitter::ParseState| {
        polls.set(polls.get() + 1);
        if polls.get() > 10_000 || Instant::now() >= deadline || fetched.get() > fetch_budget {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let mut read = |offset: usize, _: tree_sitter::Point| -> &[u8] {
        if fetched.get() > fetch_budget {
            return &[];
        }
        let chunk = source
            .get(offset..offset.saturating_add(4096).min(source.len()))
            .unwrap_or_default();
        fetched.set(fetched.get().saturating_add(chunk.len()));
        chunk
    };
    let Some(tree) = parser.parse_with_options(
        &mut read,
        None,
        Some(tree_sitter::ParseOptions::default().progress_callback(&mut progress)),
    ) else {
        values.insert_key(value_key!("media.php.analysis_limited"), Value::Bool(true));
        return;
    };
    if fetched.get() > fetch_budget {
        values.insert_key(value_key!("media.php.analysis_limited"), Value::Bool(true));
        return;
    }
    let mut root_cursor = tree.root_node().walk();
    let has_namespace = tree
        .root_node()
        .named_children(&mut root_cursor)
        .any(|node| node.kind() == "namespace_definition");
    let mut calls = BTreeSet::new();
    let mut pending = vec![tree.root_node()];
    let mut visited = 0;
    while let Some(node) = pending.pop() {
        visited += 1;
        if visited > MAX_NODES
            || node.named_child_count() > MAX_NODES - visited
            || Instant::now() >= deadline
        {
            values.insert_key(value_key!("media.php.analysis_limited"), Value::Bool(true));
            return; // Never emit relationships from an incomplete walk.
        }
        if node.is_error() || node.is_missing() {
            continue;
        }
        if node.kind() == "function_call_expression"
            && !node.has_error()
            && let Some(name) = request_call(node, original, has_namespace)
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
mod tests {
    use super::*;
    fn calls(source: &[u8]) -> Vec<String> {
        let mut values = Values::default();
        extract(source, &mut values);
        values
            .get("media.php.request_calls")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
    #[test]
    fn embedded_php_request_calls_bind_the_first_argument() {
        for source in [
            &b"GIF89a\x00\xff<?php system($_GET['cmd']); ?>"[..],
            b"GIF89a<?= system($_REQUEST['cmd']); ?>",
            b"GIF89a<?PHP /* note */ $label='status'; SyStEm(($_COOKIE['cmd'])); ?>",
            b"GIF89a<?php \\system($_POST['cmd']); ?>",
        ] {
            assert_eq!(calls(source), ["system"], "{source:?}");
        }
        assert_eq!(calls(b"GIF89a<?php eval($_POST['code']); ?>"), ["eval"]);
    }
    #[test]
    fn embedded_php_request_calls_ignore_non_calls_and_other_arguments() {
        for source in [
            &b"GIF89a<?php echo 'system($_GET[\"cmd\"]);'; ?>"[..],
            b"GIF89a<?php /* system($_GET['cmd']); */ echo 1; ?>",
            b"GIF89a<?php $mode=$_GET['mode']; system('date'); ?>",
            b"GIF89a<?php system('date', $_GET['cmd']); ?>",
            b"GIF89a<?php $object->system($_GET['cmd']); ?>",
            b"GIF89a<?php Type::system($_GET['cmd']); ?>",
            b"GIF89a<?php system($_get['cmd']); ?>",
            b"GIF89a<?php echo 1; ?> system($_GET['cmd']);",
            b"GIF89a<?phpNotCode system($_GET['cmd']); ?>",
            b"GIF89a<?php namespace Local { system($_GET['cmd']); } ?>",
            b"GIF89a<?php namespace Local; system($_GET['cmd']); ?>",
        ] {
            assert!(calls(source).is_empty(), "{source:?}");
        }
    }
    #[test]
    fn embedded_php_gif_comment_request_command() {
        for tag in ["<?php ", "<?PHP\n", "<?="] {
            let payload = format!("{tag}system($_REQUEST[\"task\"]); ?>");
            let mut source = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff\x21\xfe".to_vec();
            source.push(payload.len() as u8);
            source.extend_from_slice(payload.as_bytes());
            source.extend_from_slice(b"\0\x2c\0\0\0\0\x01\0\x01\0\0\x02\x02\x44\x01\0\x3b");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert_eq!(calls(&source), ["system"], "{}", tree.root_node().to_sexp());
        }
    }

    #[test]
    fn embedded_php_byte_budget_is_explicit() {
        let mut source = vec![b' '; MAX_BYTES + 1];
        source[..3].copy_from_slice(b"<?=");
        let mut values = Values::default();
        extract(&source, &mut values);
        assert_eq!(
            values.get("media.php.analysis_limited"),
            Some(&Value::Bool(true))
        );
        assert!(values.get("media.php.request_calls").is_none());
    }
}
