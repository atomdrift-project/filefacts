//! MSBuild projects: the project's element tree, and bounded, non-executing
//! property provenance for DownloadFile tasks. Only known literal/property
//! values and the MachineName property function are expanded. Unknown inputs
//! stay opaque; no environment is read.
use std::collections::HashMap;

use serde_json::{Map, Value as JsonValue};

use crate::output::{Errors, Values};
use crate::value_key;

#[derive(Clone, Debug)]
enum Part {
    Text(String),
    Hostname,
    Unknown,
}
type Properties = HashMap<String, Vec<Part>>;

fn expand(input: &str, properties: &Properties) -> Vec<Part> {
    if input.len() > 8192 {
        return vec![Part::Unknown];
    }
    let mut result = Vec::new();
    let mut remaining = input;
    while let Some(start) = remaining.find("$(") {
        result.push(Part::Text(remaining[..start].to_owned()));
        remaining = &remaining[start..];
        let Some(end) = remaining.find(')') else {
            result.push(Part::Unknown);
            remaining = "";
            break;
        };
        let expression: String = remaining[..=end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if expression == "$([System.Environment]::MachineName)" {
            result.push(Part::Hostname);
        } else {
            let name = remaining[2..end].to_ascii_lowercase();
            result.extend(
                properties
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| vec![Part::Unknown]),
            );
        }
        remaining = &remaining[end + 1..];
        if result.len() > 64
            || result
                .iter()
                .map(|p| if let Part::Text(t) = p { t.len() } else { 0 })
                .sum::<usize>()
                > 8192
        {
            return vec![Part::Unknown];
        }
    }
    result.push(Part::Text(remaining.to_owned()));
    result
}

fn properties(group: roxmltree::Node<'_, '_>, map: &mut Properties) {
    let nodes: Vec<_> = group
        .children()
        .filter(roxmltree::Node::is_element)
        .take(129)
        .collect();
    if nodes.len() > 128 {
        // An unvisited later assignment could overwrite a proven input.
        map.clear();
        return;
    }
    for node in nodes {
        let value =
            if node.attribute("Condition").is_some() || group.attribute("Condition").is_some() {
                vec![Part::Unknown]
            } else {
                expand(node.text().unwrap_or(""), map)
            };
        let name = node.tag_name().name().to_ascii_lowercase();
        if map.len() < 128 || map.contains_key(&name) {
            map.insert(name, value);
        }
    }
}

fn hostname_query_authority(parts: &[Part]) -> Option<String> {
    let mut prefix = String::new();
    for part in parts {
        match part {
            Part::Text(text) => prefix.push_str(text),
            Part::Unknown => return None,
            Part::Hostname => {
                let (scheme, rest) = prefix.split_once("://")?;
                if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                    return None;
                }
                let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                if authority_end == 0 {
                    return None;
                }
                let query = rest.find('?')?;
                if rest.contains('#') {
                    return None;
                }
                let field = rest[query + 1..].rsplit('&').next().unwrap_or("");
                return field
                    .contains('=')
                    .then(|| rest[..authority_end].to_ascii_lowercase());
            }
        }
        if prefix.len() > 8192 {
            return None;
        }
    }
    None
}

/// Whether the document element of the XML `text` is named `Project` (in
/// any namespace), read from the prolog without parsing the document: the
/// declaration, comments, processing instructions and a DOCTYPE are
/// stepped over to the first start tag.
fn root_is_project(text: &str) -> bool {
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        let skip_to = |close: &str, rest: &str| rest.find(close).map(|at| at + close.len());
        let step = if rest.starts_with("<?") {
            skip_to("?>", rest)
        } else if rest.starts_with("<!--") {
            skip_to("-->", rest)
        } else if rest.starts_with("<!") {
            skip_to(">", rest)
        } else if let Some(tag) = rest.strip_prefix('<') {
            let name = tag
                .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .next()
                .unwrap_or_default();
            return name.rsplit(':').next() == Some("Project");
        } else {
            return false;
        };
        let Some(step) = step else {
            return false;
        };
        rest = rest.get(step..).unwrap_or_default();
    }
}

/// Elements nested deeper than this become `null`: the tree is built and
/// dropped recursively, and real project files sit far below it.
const MAX_TREE_DEPTH: usize = 256;

/// An element as a value tree, so a rule addresses a project by path
/// (`Project.UsingTask.@TaskFactory`, `Project.Target[*].Exec.@Command`):
///
/// - attributes are `@`-prefixed keys, and a namespace declaration appears
///   as `@xmlns` / `@xmlns:<prefix>` only on the element that declares it;
/// - a child element is a key named for its local name, and siblings that
///   share a name become an array in document order;
/// - text (CDATA included) is trimmed, joined with spaces, and becomes the
///   element's value when it has no attributes or children, else its
///   `_text` key.
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
    let mut text: Vec<&str> = Vec::new();
    for child in node.children() {
        if child.is_element() {
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
            && let Some(t) = child.text().map(str::trim).filter(|t| !t.is_empty())
        {
            text.push(t);
        }
    }
    if text.is_empty() {
        return JsonValue::Object(map);
    }
    let text = JsonValue::String(text.join(" "));
    if map.is_empty() {
        return text;
    }
    map.insert("_text".to_string(), text);
    JsonValue::Object(map)
}

pub(super) fn extract(bytes: &[u8], values: &mut Values, errors: &mut Errors) {
    if bytes.len() > 8 * 1024 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let text = text.trim_start_matches('\u{feff}');
    // Most XML is not an MSBuild project: look at the root's name before
    // building a tree of the whole document.
    if !root_is_project(text) {
        return;
    }
    let options = roxmltree::ParsingOptions {
        nodes_limit: 100_000,
        ..Default::default()
    };
    let Ok(doc) = roxmltree::Document::parse_with_options(text, options) else {
        return;
    };
    let project = doc.root_element();
    if !project.has_tag_name("Project") {
        return;
    }
    let mut globals = Properties::new();
    for group in project
        .children()
        .filter(|n| n.has_tag_name("PropertyGroup"))
    {
        properties(group, &mut globals);
    }
    let mut downloads = Vec::new();
    for target in project
        .children()
        .filter(|n| n.has_tag_name("Target"))
        .take(256)
    {
        if target
            .attribute("Condition")
            .is_some_and(|c| c.trim().eq_ignore_ascii_case("false"))
        {
            continue;
        }
        let before: Vec<_> = target
            .attribute("BeforeTargets")
            .unwrap_or("")
            .split(';')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect();
        let precompile = before.iter().any(|v| {
            ["Build", "CoreCompile", "ResolveAssemblyReferences"]
                .iter()
                .any(|phase| v.eq_ignore_ascii_case(phase))
        });
        let mut local = globals.clone();
        for node in target.children().filter(roxmltree::Node::is_element) {
            if node.has_tag_name("PropertyGroup") {
                properties(node, &mut local);
            } else if node.has_tag_name("DownloadFile") && downloads.len() < 256 {
                if node
                    .attribute("Condition")
                    .is_some_and(|c| c.trim().eq_ignore_ascii_case("false"))
                {
                    continue;
                }
                let source = node.attribute("SourceUrl").unwrap_or("");
                let authority = precompile
                    .then(|| hostname_query_authority(&expand(source, &local)))
                    .flatten();
                downloads.push(serde_json::json!({
                    "target": target.attribute("Name").unwrap_or(""),
                    "before_targets": before,
                    "source_url": source,
                    "precompile_hostname_query": authority.is_some(),
                    "precompile_hostname_query_authority": authority,
                }));
            }
        }
    }
    if !downloads.is_empty() {
        values.insert_key(
            value_key!("msbuild.downloads"),
            serde_json::json!(downloads),
        );
    }
    let mut tree = Map::new();
    tree.insert(
        project.tag_name().name().to_string(),
        element_tree(project, 0),
    );
    super::structured::merge_document(JsonValue::Object(tree), values, errors);
}

#[cfg(test)]
mod tests;
