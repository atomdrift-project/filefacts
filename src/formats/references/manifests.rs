//! Declarative dependency and local-entry references. No package code runs.
use super::{
    JsonValue, RefKind, RefLocator, Refs, Values, is_exact_npm_version, locator_from_repo,
    purl_encode as encode, push_local_ref, push_version_requirement, pypi_purl,
};

/// Read the installed package's own manifest. The container type has already
/// identified this as Arch, avoiding the ambiguous Alpine `.PKGINFO` name.
pub(super) fn arch_package(bytes: &[u8], out: &mut Refs<'_>) {
    use std::io::{Cursor, Read};
    let input = Cursor::new(bytes);
    let reader: Box<dyn Read> = if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let Ok(decoder) = zstd::stream::read::Decoder::new(input) else {
            return;
        };
        Box::new(decoder)
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(input))
    } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Box::new(xz2::read::XzDecoder::new(input))
    } else {
        Box::new(input)
    };
    let mut archive = tar::Archive::new(reader.take(128 * 1024 * 1024));
    let Ok(entries) = archive.entries() else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(path) = entry.path() else { continue };
        if path.as_ref() != std::path::Path::new(".PKGINFO") {
            continue;
        }
        if entry.size() > 1024 * 1024 {
            return;
        }
        let mut text = String::new();
        if entry
            .take(1024 * 1024 + 1)
            .read_to_string(&mut text)
            .is_err()
        {
            return;
        }
        for line in text.lines() {
            let Some((key, raw)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let (scope, optional) = match key {
                "depend" => (crate::DependencyScope::Runtime, false),
                "optdepend" => (crate::DependencyScope::Runtime, true),
                "makedepend" | "checkdepend" => (crate::DependencyScope::Build, false),
                _ => continue,
            };
            let spec = raw.trim().split_once(": ").map_or(raw.trim(), |(s, _)| s);
            let end = spec.find(['<', '>', '=']).unwrap_or(spec.len());
            let name = spec[..end].trim();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"@._+-".contains(&c))
            {
                continue;
            }
            let mut purl = format!("pkg:alpm/arch/{name}");
            push_version_requirement(&mut purl, spec[end..].trim());
            let before = out.refs.len();
            out.push(
                RefLocator::Purl(purl),
                RefKind::Dependency,
                format!("arch-pkginfo:{key}"),
                line.trim(),
                None,
            );
            if let Some(r) = out.refs.get_mut(before) {
                r.offset = None; // the manifest is inside a compressed archive
                r.context = Some(crate::DependencyContext {
                    scope,
                    optional,
                    has_install_script: false,
                    installed_path: None,
                });
            }
        }
        break;
    }
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
            push_version_requirement(&mut purl, requirement);
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

/// Repeated Requires-Dist headers from wheel or source distribution metadata.
/// Keep marker expressions in the locator: they describe a candidate, not a
/// guarantee that the requirement applies to the current environment.
pub(super) fn pkginfo(values: &Values, out: &mut Refs<'_>) {
    let Some(field) = values.as_json().get("requires-dist") else {
        return;
    };
    let specs: Vec<&str> = match field {
        JsonValue::String(s) => vec![s],
        JsonValue::Array(a) => a.iter().filter_map(JsonValue::as_str).collect(),
        _ => return,
    };
    for spec in specs {
        let start = out.refs.len();
        python_requirement(spec, "pkg-info:Requires-Dist", out);
        if let Some(r) = out.refs.get_mut(start) {
            let marker = spec.split_once(';').map(|(_, marker)| marker);
            r.context = Some(crate::DependencyContext {
                scope: crate::DependencyScope::Runtime,
                optional: marker.is_some(),
                has_install_script: false,
                installed_path: None,
            });
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
    } else {
        let mut purl = base;
        push_version_requirement(&mut purl, rest);
        purl
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
    fn arch_package_declares_runtime_optional_and_build_dependencies() {
        use std::io::Write;
        let mut tar = tar::Builder::new(Vec::new());
        let data = b"pkgname = demo\ndepend = bash>=5\noptdepend = electron: graphical interface\nmakedepend = nodejs\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, ".PKGINFO", &data[..]).unwrap();
        let plain = tar.into_inner().unwrap();
        let zstd = zstd::stream::encode_all(&plain[..], 1).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let gz = gz.finish().unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(&plain).unwrap();
        let xz = xz.finish().unwrap();
        for bytes in [&plain, &zstd, &gz, &xz] {
            let mut out = super::super::Refs {
                refs: Vec::new(),
                text: None,
                cursor: 0,
                budget: 0,
            };
            arch_package(bytes, &mut out);
            assert_eq!(out.refs.len(), 3);
            assert!(
                matches!(&out.refs[0].locator, RefLocator::Purl(p) if p.starts_with("pkg:alpm/arch/bash?") && p.contains("version_requirement="))
            );
            assert!(!out.refs[0].context.as_ref().unwrap().optional);
            assert!(out.refs[1].context.as_ref().unwrap().optional);
            assert_eq!(
                out.refs[2].context.as_ref().unwrap().scope,
                crate::DependencyScope::Build
            );
            assert!(out.refs.iter().all(|r| r.offset.is_none()));
        }
    }

    #[test]
    fn pkginfo_requires_dist_preserves_pins_ranges_and_markers() {
        let bytes = b"Metadata-Version: 2.4\nName: demo\nRequires-Dist: Requests==2.32.3\nRequires-Dist: boto3<2,>=1.0\nRequires-Dist: pytest>=9; extra == \"dev\"\n\nRequires-Dist: body-example==1.0\n";
        let facts = crate::OpenOptions::new()
            .path(std::path::Path::new("METADATA"))
            .open(bytes);
        let refs = facts.references();
        assert_eq!(refs.len(), 3);
        let pinned = refs
            .iter()
            .find(|r| r.evidence.starts_with("Requests"))
            .unwrap();
        assert_eq!(
            pinned.locator,
            RefLocator::Purl("pkg:pypi/requests@2.32.3".into())
        );
        assert!(!pinned.context.as_ref().unwrap().optional);
        let range = refs
            .iter()
            .find(|r| r.evidence.starts_with("boto3"))
            .unwrap();
        assert!(
            matches!(&range.locator, RefLocator::Purl(p) if p.contains("version_requirement="))
        );
        let extra = refs
            .iter()
            .find(|r| r.evidence.starts_with("pytest"))
            .unwrap();
        assert!(extra.context.as_ref().unwrap().optional);
        assert!(matches!(&extra.locator, RefLocator::Purl(p) if p.contains("environment_marker=")));
        assert!(refs.iter().all(|r| r.offset.is_some()));
    }
    #[test]
    fn cargo_roles_aliases_ranges_workspace_and_disabled_build() {
        let values = Values::from_json(
            serde_json::json!({"package":{"name":"x","build":false},"dependencies":{"json":{"package":"serde_json","version":"=1.0.1"},"serde":"1.0","anyhow":"*","log":{"optional":true}},"build-dependencies":{"cc":{"workspace":true}},"workspace":{"dependencies":{"cc":"=1.0.99"}},"target":{"cfg(unix)":{"build-dependencies":{"bindgen":"0.69"}}},"dev-dependencies":{"tempfile":"3"}}),
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
        // A range rides along as a qualifier; a wildcard or missing
        // requirement is the bare coordinate.
        let purls: Vec<&str> = refs
            .iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Purl(p) => Some(p.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            purls.contains(&"pkg:cargo/serde?version_requirement=1.0"),
            "{purls:?}"
        );
        assert!(purls.contains(&"pkg:cargo/anyhow"), "{purls:?}");
        assert!(purls.contains(&"pkg:cargo/log"), "{purls:?}");
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
