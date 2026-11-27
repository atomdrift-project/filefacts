//! Element trees for the XML documents Windows acts on when they are opened:
//! an MSBuild project, a Task Scheduler task, a Settings shortcut
//! (`.SettingContent-ms`), a library (`.library-ms`), a search connector
//! (`.searchConnector-ms`) and a Contacts card (`.contact`). Rules address
//! them by path (`PCSettings.SearchableContent.ApplicationInformation.DeepLink`,
//! `Task.Actions.Exec.Command`). Other XML is not parsed here: a tree of an
//! arbitrary document costs more than it tells.
use std::borrow::Cow;

use serde_json::{Map, Value as JsonValue};

use crate::output::{Errors, Values};

/// Local names of the root elements whose documents get a tree.
const TREE_ROOTS: &[&str] = &[
    "Project",
    "Task",
    "PCSettings",
    "libraryDescription",
    "searchConnectorDescription",
    "contact",
];

/// Elements nested deeper than this become `null`: the tree is built and
/// dropped recursively, and real documents sit far below it.
const MAX_TREE_DEPTH: usize = 256;

pub(super) fn extract(bytes: &[u8], values: &mut Values, errors: &mut Errors) {
    if bytes.len() > 8 * 1024 * 1024 {
        return;
    }
    let Some(text) = decode(bytes) else {
        return;
    };
    // Look at the root's name before building a tree of the whole document.
    if !root_name(&text).is_some_and(|name| TREE_ROOTS.contains(&name)) {
        return;
    }
    let options = roxmltree::ParsingOptions {
        nodes_limit: 100_000,
        ..Default::default()
    };
    let doc = match roxmltree::Document::parse_with_options(&text, options) {
        Ok(doc) => doc,
        Err(err) => {
            tracing::debug!(target: "filefacts::xml", error = %err, "document not parsed");
            return;
        }
    };
    let root = doc.root_element();
    if root.has_tag_name("Project") {
        super::msbuild::extract(root, values);
    }
    let mut tree = Map::new();
    tree.insert(root.tag_name().name().to_string(), element_tree(root, 0));
    super::structured::merge_document(JsonValue::Object(tree), values, errors);
}

/// The document as text: UTF-8, or UTF-16 behind its byte-order mark, the
/// encoding `schtasks /xml` and Notepad write. Any BOM is dropped.
fn decode(bytes: &[u8]) -> Option<Cow<'_, str>> {
    let utf16 = |rest: &[u8], unit: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| unit(pair))
            .collect();
        String::from_utf16(&units).ok().map(Cow::Owned)
    };
    if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        return utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        return utf16(rest, u16::from_be_bytes);
    }
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    std::str::from_utf8(bytes).ok().map(Cow::Borrowed)
}

/// The local name of the document element, read from the prolog without
/// parsing the document: the declaration, comments, processing
/// instructions and a DOCTYPE are stepped over to the first start tag.
fn root_name(text: &str) -> Option<&str> {
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        let close = if rest.starts_with("<?") {
            "?>"
        } else if rest.starts_with("<!--") {
            "-->"
        } else if rest.starts_with("<!") {
            ">"
        } else {
            let name = rest
                .strip_prefix('<')?
                .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .next()?;
            return name.rsplit(':').next();
        };
        rest = rest.get(rest.find(close)? + close.len()..)?;
    }
}

/// An element as a value tree:
///
/// - attributes are `@`-prefixed keys, and a namespace declaration appears
///   as `@xmlns` / `@xmlns:<prefix>` only on the element that declares it;
/// - a child element is a key named for its local name, and siblings that
///   share a name become an array in document order;
/// - text (CDATA included) is the element's value when it has no attributes
///   or children, else its `_text` key. Comments and processing
///   instructions do not break it: `r<!-- -->un` reads `run`, as the
///   consumer that skips them reads it. Each run between child elements is
///   trimmed, and the runs are joined with spaces.
fn element_tree(node: roxmltree::Node<'_, '_>, depth: usize) -> JsonValue {
    if depth >= MAX_TREE_DEPTH {
        return JsonValue::Null;
    }
    let mut map = Map::new();
    for attr in node.attributes() {
        map.insert(
            format!("@{}", attr.name()),
            JsonValue::String(attr.value().to_string()),
        );
    }
    let parent = node.parent();
    for ns in node.namespaces() {
        let inherited = parent
            .and_then(|p| p.lookup_namespace_uri(ns.name()))
            .is_some_and(|uri| uri == ns.uri());
        if inherited {
            continue;
        }
        let key = ns
            .name()
            .map_or_else(|| "@xmlns".to_string(), |prefix| format!("@xmlns:{prefix}"));
        map.entry(key)
            .or_insert_with(|| JsonValue::String(ns.uri().to_string()));
    }
    let mut runs: Vec<String> = Vec::new();
    let mut run = String::new();
    for child in node.children() {
        if child.is_element() {
            end_run(&mut run, &mut runs);
            let value = element_tree(child, depth + 1);
            match map.get_mut(child.tag_name().name()) {
                None => {
                    map.insert(child.tag_name().name().to_string(), value);
                }
                Some(JsonValue::Array(siblings)) => siblings.push(value),
                Some(existing) => {
                    let first = std::mem::replace(existing, JsonValue::Null);
                    *existing = JsonValue::Array(vec![first, value]);
                }
            }
        } else if child.is_text()
            && let Some(text) = child.text()
        {
            run.push_str(text);
        }
    }
    end_run(&mut run, &mut runs);
    if runs.is_empty() {
        return JsonValue::Object(map);
    }
    let text = JsonValue::String(runs.join(" "));
    if map.is_empty() {
        return text;
    }
    map.insert("_text".to_string(), text);
    JsonValue::Object(map)
}

/// Close the text run at a child element: keep it trimmed unless blank.
fn end_run(run: &mut String, runs: &mut Vec<String>) {
    let text = run.trim();
    if !text.is_empty() {
        runs.push(text.to_owned());
    }
    run.clear();
}

#[cfg(test)]
mod tests;
