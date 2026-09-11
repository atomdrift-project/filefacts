//! Go dependency ownership over supplied members, without filesystem access.
//! This reconciles declarations, replacements and exact checksums. It does not
//! compute MVS or assert that a declared minimum is the version actually built.
use crate::{RefKind, RefLocator, Reference};
use std::collections::BTreeMap;

/// An artifact member's already-extracted reference facts.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceMember<'a> {
    /// Logical path, including archive ownership delimiters.
    pub path: &'a str,
    /// References produced by the member parser.
    pub references: &'a [Reference],
}

fn named(path: &str, name: &str) -> bool {
    path == name || path.ends_with(&format!("/{name}")) || path.ends_with(&format!("!!{name}"))
}

fn directory(path: &str) -> &str {
    let slash = path.rfind('/').map_or(0, |i| i + 1);
    let archive = path.rfind("!!").map_or(0, |i| i + 2);
    &path[..slash.max(archive)]
}

fn boundary(path: &str) -> &str {
    &path[..path.rfind("!!").map_or(0, |i| i + 2)]
}

fn local(base: &str, spec: &str) -> Option<String> {
    if spec.starts_with('/') || spec.contains(['\\', ':', '!', '#']) {
        return None;
    }
    let boundary = boundary(base);
    let relative = directory(base).strip_prefix(boundary)?;
    let absolute = relative.starts_with('/');
    let mut parts: Vec<_> = relative.split('/').filter(|p| !p.is_empty()).collect();
    for part in spec.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    Some(format!(
        "{boundary}{}{}",
        if absolute { "/" } else { "" },
        parts.join("/")
    ))
}

fn coordinate(reference: &Reference) -> Option<(&str, &str)> {
    let RefLocator::Purl(purl) = &reference.locator else {
        return None;
    };
    purl.strip_prefix("pkg:golang/")?.rsplit_once('@')
}

fn unresolved(reference: &Reference, reason: &str) -> Reference {
    let mut result = reference.clone();
    result.kind = RefKind::Undefined;
    result.source = format!("go.mod.unresolved-{reason}");
    result
}

fn owns(work: ReferenceMember<'_>, main: &str) -> bool {
    boundary(work.path) == boundary(main)
        && work.references.iter().any(|r| {
            r.source == "go.work.use" && matches!(&r.locator,
                RefLocator::Path(path) if local(work.path, path).is_some_and(|p| format!("{p}/go.mod") == main))
        })
}

fn reconcile(
    reference: &Reference,
    context: &[(ReferenceMember<'_>, bool)],
    sums: &[&Reference],
    members: &[ReferenceMember<'_>],
) -> Reference {
    if reference.source != "go.mod" || reference.kind != RefKind::Dependency {
        return reference.clone();
    }
    let Some((module, version)) = coordinate(reference) else {
        return reference.clone();
    };
    if context.iter().any(|(m, _)| {
        m.references
            .iter()
            .any(|r| r.source == "go.manifest.incomplete")
    }) {
        return unresolved(reference, "manifest");
    }
    if context.iter().any(|(m, _)| {
        m.references
            .iter()
            .any(|r| r.source == "go.mod.exclude" && r.locator == reference.locator)
    }) {
        return unresolved(reference, "excluded-minimum");
    }
    let mut matches = Vec::new();
    for (owner, workspace) in context {
        for r in owner
            .references
            .iter()
            .filter(|r| r.source.ends_with(".replace"))
        {
            let Some(words) = crate::formats::references::go::words(&r.evidence) else {
                return unresolved(reference, "replacement");
            };
            let Some(split) = words.iter().position(|w| w == "=>") else {
                return unresolved(reference, "replacement");
            };
            if words.first().map(String::as_str) != Some(module)
                || split == 2 && words[1] != version
            {
                continue;
            }
            matches.push(((*workspace, split == 2), owner.path, r));
        }
    }
    matches.sort_by_key(|(priority, _, _)| *priority);
    let mut result = reference.clone();
    result.source = "go.mod.declared-minimum".into();
    if let Some((priority, owner, replacement)) = matches.last() {
        let peers: Vec<_> = matches.iter().filter(|(p, _, _)| p == priority).collect();
        if peers.iter().any(|(_, path, r)| {
            r.locator != replacement.locator
                || matches!(r.locator, RefLocator::Path(_)) && path != owner
        }) {
            return unresolved(reference, "replacement-conflict");
        }
        result.locator = replacement.locator.clone();
        result.pinned_hash = None;
        result.content_sha256 = None;
        result.source = replacement.source.clone();
        result.evidence = format!(
            "{}; {}: {}",
            reference.evidence, owner, replacement.evidence
        );
        if let RefLocator::Path(path) = &replacement.locator {
            let Some(path) = local(owner, path) else {
                return unresolved(reference, "local-boundary");
            };
            if !members.iter().any(|m| m.path == format!("{path}/go.mod")) {
                return unresolved(reference, "local-missing");
            }
            result.kind = RefKind::Local;
            return result;
        }
    }
    let pins: Vec<_> = sums
        .iter()
        .filter(|r| r.source == "go.sum" && r.locator == result.locator)
        .collect();
    if let Some(pin) = pins.first() {
        if pins.iter().any(|r| r.pinned_hash != pin.pinned_hash) {
            return unresolved(reference, "checksum-conflict");
        }
        result.pinned_hash = pin.pinned_hash.clone();
    }
    result
}

/// Reconcile each module with its own manifest and owning workspace only.
/// Returned keys are logical member paths. Checksum-only/vendor records never
/// become fetch candidates. The caller passes artifact members, not host paths.
#[must_use]
pub fn go_dependency_context(members: &[ReferenceMember<'_>]) -> BTreeMap<String, Vec<Reference>> {
    let mut result = BTreeMap::new();
    let reference_count = members.iter().map(|m| m.references.len()).sum::<usize>();
    let over_budget = members.len() > 4096 || reference_count > 50_000;
    // Charge the conservative upper bound of nested reference/member scans,
    // not just the outer loop. A large workspace cannot hide quadratic work.
    let mut remaining = 2_000_000usize;
    for main in members.iter().filter(|m| named(m.path, "go.mod")) {
        let lookup_cost = members.len().saturating_add(reference_count);
        if over_budget || remaining < lookup_cost {
            result.insert(
                main.path.into(),
                main.references
                    .iter()
                    .map(|r| unresolved(r, "context-budget"))
                    .collect(),
            );
            continue;
        }
        remaining -= lookup_cost;
        let workspace = members
            .iter()
            .filter(|m| named(m.path, "go.work") && owns(**m, main.path))
            .max_by_key(|m| directory(m.path).len());
        let mut context = vec![(*main, false)];
        if let Some(work) = workspace {
            let work_cost = members.len().saturating_mul(work.references.len());
            if remaining < work_cost {
                result.insert(
                    main.path.into(),
                    main.references
                        .iter()
                        .map(|r| unresolved(r, "context-budget"))
                        .collect(),
                );
                continue;
            }
            remaining -= work_cost;
            context.extend(
                members
                    .iter()
                    .filter(|m| {
                        m.path != main.path && named(m.path, "go.mod") && owns(*work, m.path)
                    })
                    .map(|m| (*m, false)),
            );
            context.push((*work, true));
        }
        let mut sums = Vec::new();
        for (owner, work) in &context {
            let path = format!(
                "{}{}",
                directory(owner.path),
                if *work { "go.work.sum" } else { "go.sum" }
            );
            if let Some(sum) = members.iter().find(|m| m.path == path) {
                sums.extend(sum.references);
            }
        }
        let vendor_path = format!("{}vendor/modules.txt", directory(main.path));
        let vendor = members.iter().find(|m| m.path == vendor_path);
        let per_reference = context
            .iter()
            .map(|(m, _)| m.references.len())
            .sum::<usize>()
            .saturating_mul(4)
            .saturating_add(sums.len())
            .saturating_add(members.len());
        let resolve_cost = main.references.len().saturating_mul(per_reference);
        if remaining < resolve_cost {
            result.insert(
                main.path.into(),
                main.references
                    .iter()
                    .map(|r| unresolved(r, "context-budget"))
                    .collect(),
            );
            continue;
        }
        remaining -= resolve_cost;
        let resolved = main
            .references
            .iter()
            .map(|r| {
                let mut value = reconcile(r, &context, &sums, members);
                if value.kind == RefKind::Dependency {
                    if let Some(vendor) = vendor {
                        if vendor
                            .references
                            .iter()
                            .any(|r| r.source == "go.manifest.incomplete")
                        {
                            return unresolved(r, "vendor-metadata");
                        }
                        let original_module = coordinate(r).map(|(m, _)| m);
                        let selected = vendor.references.iter().find(|v| {
                            v.source == "go.vendor.module"
                                && coordinate(v).map(|(m, _)| m) == original_module
                        });
                        if let Some(selected) = selected {
                            let Some((module, _)) = coordinate(selected) else {
                                return unresolved(r, "vendor-metadata");
                            };
                            let path = format!("{}vendor/{module}/", directory(main.path));
                            if !members.iter().any(|m| m.path.starts_with(&path)) {
                                return unresolved(r, "vendor-missing");
                            }
                            value.kind = RefKind::Local;
                            value.locator = RefLocator::Path(format!("vendor/{module}"));
                            value.source = "go.vendor.bundled".into();
                            value.evidence = format!("{}; {}", r.evidence, selected.evidence);
                        } else {
                            return unresolved(r, "vendor-unlisted");
                        }
                    }
                }
                value
            })
            .collect();
        result.insert(main.path.into(), resolved);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(files: &[(&str, &str)]) -> BTreeMap<String, Vec<Reference>> {
        let owned: Vec<_> = files
            .iter()
            .map(|(path, content)| {
                let member_path = path.rsplit("!!").next().unwrap();
                let parsed =
                    crate::open_with_path(std::path::Path::new(member_path), content.as_bytes())
                        .unwrap();
                ((*path).to_string(), parsed.references().to_vec())
            })
            .collect();
        go_dependency_context(
            &owned
                .iter()
                .map(|(path, refs)| ReferenceMember {
                    path,
                    references: refs,
                })
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn replacement_uses_exact_checksum_not_history_or_nested_directives() {
        let facts = run(&[
            (
                "p.zip!!app/go.mod",
                "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => example.test/fork v2.0.0\n",
            ),
            (
                "p.zip!!app/go.sum",
                "example.test/fork v2.0.0 h1:EXACT\nexample.test/fork v2.0.0/go.mod h1:METADATA\nexample.test/lib v9.0.0 h1:HISTORY\n",
            ),
            (
                "p.zip!!app/nested/go.mod",
                "module nested\nreplace example.test/lib => example.test/unrelated v3.0.0\n",
            ),
        ]);
        let dependency = facts["p.zip!!app/go.mod"]
            .iter()
            .find(|r| r.kind == RefKind::Dependency)
            .unwrap();
        assert_eq!(
            dependency.locator,
            RefLocator::Purl("pkg:golang/example.test/fork@v2.0.0".into())
        );
        assert_eq!(dependency.pinned_hash.as_ref().unwrap().value, "EXACT");
        assert_eq!(
            facts["p.zip!!app/go.mod"]
                .iter()
                .filter(|r| r.kind == RefKind::Dependency)
                .count(),
            1
        );
    }

    #[test]
    fn workspace_override_requires_explicit_ownership() {
        let facts = run(&[
            (
                "p.zip!!go.work",
                "go 1.25\nuse ./app\nreplace example.test/lib => example.test/work v3.0.0\n",
            ),
            (
                "p.zip!!app/go.mod",
                "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => example.test/local v2.0.0\n",
            ),
            (
                "p.zip!!other/go.mod",
                "module other\nrequire example.test/lib v1.0.0\n",
            ),
            (
                "unrelated.zip!!go.work",
                "use ./app\nreplace example.test/lib => example.test/unrelated v4.0.0\n",
            ),
        ]);
        assert_eq!(
            facts["p.zip!!app/go.mod"][0].locator,
            RefLocator::Purl("pkg:golang/example.test/work@v3.0.0".into())
        );
        assert_eq!(
            facts["p.zip!!other/go.mod"][0].locator,
            RefLocator::Purl("pkg:golang/example.test/lib@v1.0.0".into())
        );
    }

    #[test]
    fn quoted_local_replacement_stays_inside_supplied_artifact() {
        let facts = run(&[
            (
                "p.zip!!app/go.mod",
                "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => \"../replacement folder\"\n",
            ),
            (
                "p.zip!!replacement folder/go.mod",
                "module example.test/lib\n",
            ),
        ]);
        assert_eq!(facts["p.zip!!app/go.mod"][0].kind, RefKind::Local);
        for path in ["../../escape", "/etc", "other.zip!!root"] {
            let source = format!(
                "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => {path}\n"
            );
            let facts = run(&[("p.zip!!app/go.mod", &source)]);
            assert!(
                facts["p.zip!!app/go.mod"][0]
                    .source
                    .contains("unresolved-local")
            );
        }
    }

    #[test]
    fn conflicts_exclusions_and_missing_local_modules_are_explicit() {
        for extra in [
            "exclude example.test/lib v1.0.0\n",
            "replace example.test/lib => ../missing\n",
            "replace example.test/lib => example.test/a v2.0.0\nreplace example.test/lib => example.test/b v3.0.0\n",
        ] {
            let source = format!("module app\nrequire example.test/lib v1.0.0\n{extra}");
            let facts = run(&[("p.zip!!app/go.mod", &source)]);
            assert_eq!(
                facts["p.zip!!app/go.mod"][0].kind,
                RefKind::Undefined,
                "{extra}"
            );
        }
        let facts = run(&[
            (
                "p.zip!!go.mod",
                "module app\nrequire example.test/lib v1.0.0\n",
            ),
            (
                "p.zip!!go.sum",
                "example.test/lib v1.0.0 h1:ONE\nexample.test/lib v1.0.0 h1:TWO\n",
            ),
        ]);
        assert_eq!(
            facts["p.zip!!go.mod"][0].source,
            "go.mod.unresolved-checksum-conflict"
        );
    }

    #[test]
    fn vendored_sources_are_not_refetched_from_the_registry() {
        let facts = run(&[
            (
                "p.zip!!go.mod",
                "module app\nrequire example.test/lib v1.0.0\n",
            ),
            (
                "p.zip!!vendor/modules.txt",
                "# example.test/lib v1.0.0\n## explicit\nexample.test/lib\n",
            ),
            ("p.zip!!vendor/example.test/lib/lib.go", "package lib\n"),
        ]);
        assert_eq!(facts["p.zip!!go.mod"][0].kind, RefKind::Local);
        assert_eq!(facts["p.zip!!go.mod"][0].source, "go.vendor.bundled");
    }
}
