//! Declarative dependency and local-entry references. No package code runs.
use super::{
    JsonValue, RefKind, RefLocator, Refs, Values, is_exact_npm_version, locator_from_repo,
    push_local_ref, pypi_purl,
};

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

pub(super) fn cargo(values: &Values, out: &mut Refs<'_>) {
    let root = values.as_json();
    let workspace = root.get("workspace").and_then(|v| v.get("dependencies"));
    for table in ["dependencies", "build-dependencies", "dev-dependencies"] {
        cargo_table(root.get(table), workspace, table, out);
    }
    if let Some(targets) = root.get("target").and_then(JsonValue::as_object) {
        for (target, body) in targets {
            for table in ["dependencies", "build-dependencies", "dev-dependencies"] {
                cargo_table(
                    body.get(table),
                    workspace,
                    &format!("target.{target}.{table}"),
                    out,
                );
            }
        }
    }
    cargo_table(workspace, None, "workspace.dependencies", out);
    if let Some(package) = root.get("package") {
        match package.get("build") {
            Some(JsonValue::Bool(false)) => {}
            Some(JsonValue::String(path)) => push_local_ref(out, path, "Cargo.toml:package.build"),
            _ => push_local_ref(out, "build.rs", "Cargo.toml:package.build:implicit"),
        }
        let lib = root.get("lib");
        let libpath = lib
            .and_then(|v| v.get("path"))
            .and_then(JsonValue::as_str)
            .unwrap_or("src/lib.rs");
        let role = if lib
            .and_then(|v| v.get("proc-macro"))
            .and_then(JsonValue::as_bool)
            == Some(true)
        {
            "Cargo.toml:lib:proc-macro"
        } else {
            "Cargo.toml:lib"
        };
        push_local_ref(out, libpath, role);
    }
}

fn cargo_table(
    table: Option<&JsonValue>,
    workspace: Option<&JsonValue>,
    source: &str,
    out: &mut Refs<'_>,
) {
    let Some(table) = table.and_then(JsonValue::as_object) else {
        return;
    };
    for (alias, declared) in table {
        let inherited = declared.get("workspace").and_then(JsonValue::as_bool) == Some(true);
        let Some(spec) = (if inherited {
            workspace.and_then(|w| w.get(alias))
        } else {
            Some(declared)
        }) else {
            out.push(
                RefLocator::Purl(format!("pkg:cargo/{alias}")),
                RefKind::Undefined,
                format!("Cargo.toml:{source}:workspace-unresolved"),
                alias,
                None,
            );
            continue;
        };
        let field = format!("Cargo.toml:{source}.{alias}");
        if let Some(path) = spec.get("path").and_then(JsonValue::as_str) {
            push_local_ref(
                out,
                &format!("{}/Cargo.toml", path.trim_end_matches('/')),
                &field,
            );
            continue;
        }
        let name = spec
            .get("package")
            .and_then(JsonValue::as_str)
            .unwrap_or(alias);
        let kind = if source.contains("dev-dependencies") {
            RefKind::Undefined
        } else {
            RefKind::Dependency
        };
        if let Some(git) = spec.get("git").and_then(JsonValue::as_str) {
            let mut locator = locator_from_repo(git);
            let mut kind = kind;
            if let RefLocator::Purl(purl) = &mut locator {
                if let Some(rev) = ["rev", "tag", "branch"]
                    .iter()
                    .find_map(|k| spec.get(k).and_then(JsonValue::as_str))
                {
                    purl.push('@');
                    purl.push_str(&encode(rev));
                }
            } else {
                kind = RefKind::Undefined;
            }
            out.push(locator, kind, &field, spec.to_string(), None);
            continue;
        }
        let requirement = spec
            .as_str()
            .or_else(|| spec.get("version").and_then(JsonValue::as_str))
            .unwrap_or("*");
        let mut purl = format!("pkg:cargo/{name}");
        if let Some(exact) = requirement
            .strip_prefix('=')
            .map(str::trim)
            .filter(|s| is_exact_npm_version(s))
        {
            purl.push('@');
            purl.push_str(exact);
        } else {
            purl.push_str(&format!("?version_requirement={}", encode(requirement)));
        }
        let kind = if let Some(registry) = spec.get("registry").and_then(JsonValue::as_str) {
            purl.push_str(if purl.contains('?') { "&" } else { "?" });
            purl.push_str(&format!("registry={}", encode(registry)));
            RefKind::Undefined // named private registry requires configuration resolution
        } else {
            kind
        };
        out.push(
            RefLocator::Purl(purl),
            kind,
            &field,
            format!("{alias}: {spec}"),
            None,
        );
    }
}

pub(super) fn pyproject(values: &Values, out: &mut Refs<'_>) {
    let root = values.as_json();
    for (parent, field, source) in [
        (
            "build-system",
            "requires",
            "pyproject.toml:build-system.requires",
        ),
        (
            "project",
            "dependencies",
            "pyproject.toml:project.dependencies",
        ),
    ] {
        if let Some(deps) = root
            .get(parent)
            .and_then(|v| v.get(field))
            .and_then(JsonValue::as_array)
        {
            for spec in deps.iter().filter_map(JsonValue::as_str) {
                python_requirement(spec, source, out);
            }
        }
    }
    if let Some(groups) = root
        .get("project")
        .and_then(|v| v.get("optional-dependencies"))
        .and_then(JsonValue::as_object)
    {
        for (group, deps) in groups {
            for spec in deps
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(JsonValue::as_str)
            {
                python_requirement(
                    spec,
                    &format!("pyproject.toml:project.optional-dependencies.{group}"),
                    out,
                );
            }
        }
    }
    if let Some(backend) = root
        .get("build-system")
        .and_then(|v| v.get("build-backend"))
        .and_then(JsonValue::as_str)
    {
        if let Some(paths) = root
            .get("build-system")
            .and_then(|v| v.get("backend-path"))
            .and_then(JsonValue::as_array)
        {
            let module = backend
                .split(':')
                .next()
                .unwrap_or(backend)
                .replace('.', "/");
            for path in paths.iter().filter_map(JsonValue::as_str) {
                push_local_ref(
                    out,
                    &format!("{path}/{module}.py"),
                    "pyproject.toml:build-system.build-backend",
                );
                push_local_ref(
                    out,
                    &format!("{path}/{module}/__init__.py"),
                    "pyproject.toml:build-system.build-backend",
                );
            }
        }
    }
}

fn python_requirement(spec: &str, source: &str, out: &mut Refs<'_>) {
    let (requirement, marker) = spec
        .split_once(';')
        .map_or((spec, None), |(a, b)| (a, Some(b.trim())));
    let requirement = requirement.trim();
    let end = requirement
        .find(|c: char| !c.is_ascii_alphanumeric() && !"-_.".contains(c))
        .unwrap_or(requirement.len());
    let name = &requirement[..end];
    if name.is_empty() {
        return;
    }
    let mut rest = requirement[end..].trim();
    if rest.starts_with('[') {
        let Some((_, after)) = rest.split_once(']') else {
            return;
        };
        rest = after.trim();
    }
    if let Some(url) = rest.strip_prefix('@') {
        let url = url.trim();
        let locator = if let Some(git) = url.strip_prefix("git+") {
            locator_from_repo(git)
        } else {
            RefLocator::Url(url.to_string())
        };
        out.push(locator, RefKind::Dependency, source, spec, None);
        return;
    }
    rest = rest.trim_matches(['(', ')']).trim();
    let base = pypi_purl(name, "").trim_end_matches('@').to_string();
    let mut purl = if let Some(exact) = rest
        .strip_prefix("==")
        .filter(|v| !v.contains([',', '*', ' ']))
    {
        format!("{base}@{}", encode(exact))
    } else if rest.is_empty() {
        base
    } else {
        format!("{base}?version_requirement={}", encode(rest))
    };
    if let Some(marker) = marker {
        purl.push_str(if purl.contains('?') { "&" } else { "?" });
        purl.push_str(&format!("environment_marker={}", encode(marker)));
    }
    out.push(
        RefLocator::Purl(purl),
        RefKind::Dependency,
        source,
        spec,
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileType;
    use crate::formats::references::derive;
    #[test]
    fn cargo_roles_aliases_ranges_workspace_and_disabled_build() {
        let values = Values::from_json(
            serde_json::json!({"package":{"name":"x","build":false},"dependencies":{"json":{"package":"serde_json","version":"=1.0.1"},"serde":"1.0"},"build-dependencies":{"cc":{"workspace":true}},"workspace":{"dependencies":{"cc":"=1.0.99"}},"target":{"cfg(unix)":{"build-dependencies":{"bindgen":"0.69"}}},"dev-dependencies":{"tempfile":"3"}}),
        );
        let refs = derive(FileType::CargoToml, &[], &values);
        assert!(
            refs.iter()
                .any(|r| r.locator == RefLocator::Purl("pkg:cargo/serde_json@1.0.1".into()))
        );
        assert!(
            refs.iter()
                .any(|r| r.source.contains("build-dependencies.cc")
                    && r.locator == RefLocator::Purl("pkg:cargo/cc@1.0.99".into()))
        );
        assert!(
            refs.iter()
                .any(|r| r.source.contains("cfg(unix)") && r.is_fetch_target())
        );
        assert!(
            refs.iter()
                .any(|r| r.source.contains("dev-dependencies") && !r.is_fetch_target())
        );
        assert!(!refs.iter().any(|r| r.source.contains("package.build")));
    }
    #[test]
    fn python_backend_and_runtime_requirements() {
        let values = Values::from_json(
            serde_json::json!({"build-system":{"requires":["setuptools>=70","wheel"],"build-backend":"backend","backend-path":["."]},"project":{"dependencies":["Requests==2.32.3","httpx>=0.27; python_version >= '3.9'"]}}),
        );
        let refs = derive(FileType::PyProjectToml, &[], &values);
        assert!(
            refs.iter()
                .any(|r| r.locator == RefLocator::Purl("pkg:pypi/requests@2.32.3".into()))
        );
        assert!(
            refs.iter()
                .any(|r| r.source.ends_with("build-system.requires") && r.is_fetch_target())
        );
        assert!(
            refs.iter()
                .any(|r| r.locator == RefLocator::Path("./backend.py".into()))
        );
    }
}
