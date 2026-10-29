//! Bounded, offline POM declarations, not an effective Maven build model.
//! Parent/BOM/profile/settings resolution never runs Maven or guesses a version.

use std::collections::BTreeMap;

use roxmltree::Node;
use serde_json::{Value, json};

const MAX_DEPENDENCIES: usize = 4096;

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|n| {
        n.is_element()
            && n.tag_name().name() == name
            && n.tag_name().namespace() == node.tag_name().namespace()
    })
}

fn text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name)?
        .text()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn expand(raw: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let mut value = raw.to_owned();
    for _ in 0..16 {
        let Some(start) = value.find("${") else {
            return Some(value);
        };
        let end = start + value[start..].find('}')?;
        let replacement = properties.get(&value[start + 2..end])?;
        // Bound expansion as well as its recursion (cycles stay unresolved).
        if value.len().saturating_add(replacement.len()) > 16_384 {
            return None;
        }
        value.replace_range(start..=end, replacement);
    }
    None
}

fn coordinate(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|part| !part.is_empty())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Append direct dependency rows and explicit unsupported-resolution gaps.
/// Rows from separate embedded POMs retain their own property/model scope.
pub(super) fn dependencies(xml: &str, member: &str, rows: &mut Vec<Value>, gaps: &mut Vec<Value>) {
    let gap = |gaps: &mut Vec<Value>, reason: String| {
        gaps.push(json!({"member": member, "reason": reason}));
    };
    let doc = match roxmltree::Document::parse(xml) {
        Ok(doc) => doc,
        Err(error) => {
            gap(gaps, format!("POM XML unavailable: {error}"));
            return;
        }
    };
    let root = doc.root_element();
    if root.tag_name().name() != "project"
        || !matches!(
            root.tag_name().namespace(),
            None | Some("http://maven.apache.org/POM/4.0.0")
        )
    {
        gap(gaps, "Unsupported POM root or namespace".into());
        return;
    }
    if child(root, "parent").is_some() {
        gap(
            gaps,
            "Parent POM dependencies/properties/repositories are not resolved".into(),
        );
    }
    if child(root, "profiles").is_some() {
        gap(
            gaps,
            "Profile-dependent POM declarations are not activated".into(),
        );
    }
    let mut properties = BTreeMap::new();
    if child(root, "dependencyManagement").is_some() {
        gap(gaps, "DependencyManagement/BOM inherited defaults are not resolved; emitted rows describe explicit base-POM declarations".into());
    }
    if let Some(props) = child(root, "properties") {
        for prop in props
            .children()
            .filter(|n| n.is_element() && n.tag_name().namespace() == props.tag_name().namespace())
        {
            if let Some(value) = prop.text() {
                properties.insert(prop.tag_name().name().to_owned(), value.trim().to_owned());
            }
        }
    }
    for name in ["groupId", "artifactId", "version"] {
        let value = text(root, name).or_else(|| {
            (name != "artifactId")
                .then(|| child(root, "parent").and_then(|p| text(p, name)))
                .flatten()
        });
        if let Some(value) = value {
            properties.insert(format!("project.{name}"), value.clone());
            properties.insert(format!("pom.{name}"), value);
        }
    }
    let Some(deps) = child(root, "dependencies") else {
        return;
    };
    let repositories = child(root, "repositories").is_some();
    for (index, dep) in deps
        .children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "dependency"
                && n.tag_name().namespace() == deps.tag_name().namespace()
        })
        .enumerate()
    {
        if index >= MAX_DEPENDENCIES || rows.len() >= MAX_DEPENDENCIES {
            gap(gaps, "POM dependency limit reached".into());
            break;
        }
        let mut fields = BTreeMap::new();
        let mut unresolved = false;
        for name in [
            "groupId",
            "artifactId",
            "version",
            "scope",
            "optional",
            "type",
            "classifier",
        ] {
            if let Some(raw) = text(dep, name) {
                if let Some(value) = expand(&raw, &properties) {
                    fields.insert(name, value);
                } else {
                    gap(
                        gaps,
                        format!("Dependency {index}: unresolved {name}: {raw}"),
                    );
                    unresolved = true;
                }
            }
        }
        if unresolved {
            continue;
        }
        let field = |name| fields.get(name).cloned();
        let (Some(group), Some(artifact)) = (field("groupId"), field("artifactId")) else {
            gap(
                gaps,
                format!("Dependency {index}: unresolved groupId/artifactId"),
            );
            continue;
        };
        if !coordinate(&group) || !coordinate(&artifact) {
            gap(
                gaps,
                format!("Dependency {index}: invalid groupId/artifactId"),
            );
            continue;
        }
        let label = format!("{group}:{artifact}");
        let scope = field("scope").unwrap_or_else(|| "compile".into());
        if !matches!(scope.as_str(), "compile" | "runtime" | "provided" | "test") {
            gap(
                gaps,
                format!("{label}: unresolved or unsupported scope {scope}"),
            );
            continue;
        }
        if repositories {
            gap(
                gaps,
                format!("{label}: custom POM repositories require effective-model resolution"),
            );
            continue;
        }
        let Some(version) = field("version") else {
            gap(
                gaps,
                format!(
                    "{label}: version requires unresolved property/parent/dependencyManagement/BOM"
                ),
            );
            continue;
        };
        if version.is_empty()
            || version.contains(['[', ']', '(', ')', ',', '$'])
            || matches!(version.as_str(), "LATEST" | "RELEASE")
        {
            gap(
                gaps,
                format!("{label}: Maven version requirement unresolved: {version}"),
            );
            continue;
        }
        let kind = field("type").unwrap_or_else(|| "jar".into());
        if !matches!(kind.as_str(), "jar" | "pom" | "war" | "ear" | "zip") {
            gap(gaps, format!("{label}: unsupported artifact type {kind}"));
            continue;
        }
        if field("optional").is_some_and(|s| !matches!(s.as_str(), "true" | "false")) {
            gap(gaps, format!("{label}: unsupported optional flag"));
            continue;
        }
        let mut qualifiers = Vec::new();
        if let Some(classifier) = field("classifier") {
            qualifiers.push(format!("classifier={}", encode(&classifier)));
        }
        if kind != "jar" {
            qualifiers.push(format!("type={}", encode(&kind)));
        }
        let mut purl = format!(
            "pkg:maven/{}/{artifact}@{}",
            encode(&group),
            encode(&version)
        );
        if !qualifiers.is_empty() {
            purl.push('?');
            purl.push_str(&qualifiers.join("&"));
        }
        rows.push(json!({"purl": purl, "member": member, "scope": scope,
            "optional": field("optional").is_some_and(|s| s == "true"),
            "evidence": format!("{label}:{version}")}));
    }
}

#[cfg(test)]
mod tests;
