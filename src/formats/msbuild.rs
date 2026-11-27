//! MSBuild projects: bounded, non-executing property provenance for
//! DownloadFile tasks. Only known literal/property values and the
//! MachineName property function are expanded. Unknown inputs stay opaque;
//! no environment is read. The project's element tree is built in `xml`.
use std::collections::HashMap;

use crate::output::Values;
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

/// The DownloadFile tasks of an MSBuild `project` element, as
/// `msbuild.downloads`.
pub(super) fn extract(project: roxmltree::Node<'_, '_>, values: &mut Values) {
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
}

#[cfg(test)]
mod tests;
