//! Go dependency ownership over supplied members, without filesystem access.
//! This reconciles declarations, replacements and exact checksums. It does not
//! compute MVS or assert that a declared minimum is the version actually built.
use crate::formats::references::go::{source, words};
use crate::package_context::{ContextLimits, join_relative, member_directory};
use crate::{RefKind, RefLocator, Reference, Resolution, UnresolvedReason};
use std::collections::BTreeMap;

/// An artifact member's already-extracted reference facts.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceMember<'a> {
    /// Logical member path; see [the path contract](crate::package_context#paths).
    pub path: &'a str,
    /// References produced by the member parser ([`crate::ParsedFile::references`]).
    pub references: &'a [Reference],
}

/// Whether `path`'s final component is `name`.
fn named(path: &str, name: &str) -> bool {
    path.strip_suffix(name)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('/'))
}

/// The module directory a local `replace`/`use` path names, relative to the
/// member `base` that declares it; `None` when it leaves the artifact.
fn local(base: &str, spec: &str) -> Option<String> {
    join_relative(member_directory(base), spec)
}

/// Whether `path` is the `go.mod` of the module directory `module`.
fn is_module_manifest(path: &str, module: &str) -> bool {
    path.strip_suffix("go.mod")
        .and_then(|dir| dir.strip_suffix('/'))
        .map_or(path == "go.mod" && module.is_empty(), |dir| dir == module)
}

fn coordinate(reference: &Reference) -> Option<(&str, &str)> {
    let RefLocator::Purl(purl) = &reference.locator else {
        return None;
    };
    purl.strip_prefix("pkg:golang/")?.rsplit_once('@')
}

fn unresolved(reference: &Reference, reason: UnresolvedReason) -> Reference {
    let mut result = reference.clone();
    result.resolution = Some(Resolution::Unresolved(reason));
    result
}

/// Whether the workspace `work` lists the module whose manifest is `main`.
fn owns(work: ReferenceMember<'_>, main: &str) -> bool {
    work.references.iter().any(|r| {
        r.source == source::WORK_USE
            && matches!(&r.locator, RefLocator::Path(path)
                if local(work.path, path).is_some_and(|module| is_module_manifest(main, &module)))
    })
}

fn reconcile(
    reference: &Reference,
    context: &[(ReferenceMember<'_>, bool)],
    sums: &[&Reference],
    members: &[ReferenceMember<'_>],
) -> Reference {
    if reference.source != source::MOD || reference.kind != RefKind::Dependency {
        return reference.clone();
    }
    let Some((module, version)) = coordinate(reference) else {
        return reference.clone();
    };
    if context
        .iter()
        .any(|(m, _)| m.references.iter().any(|r| r.source == source::INCOMPLETE))
    {
        return unresolved(reference, UnresolvedReason::Manifest);
    }
    if context.iter().any(|(m, _)| {
        m.references
            .iter()
            .any(|r| r.source == source::MOD_EXCLUDE && r.locator == reference.locator)
    }) {
        return unresolved(reference, UnresolvedReason::ExcludedMinimum);
    }
    let mut matches = Vec::new();
    for (owner, workspace) in context {
        for r in owner
            .references
            .iter()
            .filter(|r| r.source == source::MOD_REPLACE || r.source == source::WORK_REPLACE)
        {
            let Some(words) = words(&r.evidence) else {
                return unresolved(reference, UnresolvedReason::Replacement);
            };
            let Some(split) = words.iter().position(|w| w == "=>") else {
                return unresolved(reference, UnresolvedReason::Replacement);
            };
            if words.first().map(String::as_str) != Some(module)
                || split == 2 && words.get(1).map(String::as_str) != Some(version)
            {
                continue;
            }
            matches.push(((*workspace, split == 2), owner.path, r));
        }
    }
    matches.sort_by_key(|(priority, _, _)| *priority);
    let mut result = reference.clone();
    result.resolution = Some(Resolution::DeclaredMinimum);
    if let Some((priority, owner, replacement)) = matches.last() {
        let peers: Vec<_> = matches.iter().filter(|(p, _, _)| p == priority).collect();
        if peers.iter().any(|(_, path, r)| {
            r.locator != replacement.locator
                || matches!(r.locator, RefLocator::Path(_)) && path != owner
        }) {
            return unresolved(reference, UnresolvedReason::ReplacementConflict);
        }
        result.resolution = Some(Resolution::Replaced);
        result.locator = replacement.locator.clone();
        result.pinned_hash = None;
        result.content_sha256 = None;
        result.source.clone_from(&replacement.source);
        result.evidence = format!(
            "{}; {}: {}",
            reference.evidence, owner, replacement.evidence
        );
        if let RefLocator::Path(path) = &replacement.locator {
            let Some(module) = local(owner, path) else {
                return unresolved(reference, UnresolvedReason::LocalBoundary);
            };
            if !members.iter().any(|m| is_module_manifest(m.path, &module)) {
                return unresolved(reference, UnresolvedReason::LocalMissing);
            }
            result.kind = RefKind::Local;
            return result;
        }
    }
    let pins: Vec<_> = sums
        .iter()
        .filter(|r| r.source == source::SUM && r.locator == result.locator)
        .collect();
    if let Some(pin) = pins.first() {
        if pins.iter().any(|r| r.pinned_hash != pin.pinned_hash) {
            return unresolved(reference, UnresolvedReason::ChecksumConflict);
        }
        result.pinned_hash.clone_from(&pin.pinned_hash);
    }
    result
}

/// Reconcile each module with its own manifest and owning workspace only.
/// Returned keys are logical member paths. Checksum-only/vendor records never
/// become fetch candidates. The caller passes one artifact's members, not
/// host paths; see [the path contract](crate::package_context#paths).
/// Budgets come from `limits`; a module they cannot cover keeps its
/// references with [`UnresolvedReason::ContextBudget`].
#[must_use]
pub fn go_dependency_context(
    members: &[ReferenceMember<'_>],
    limits: &ContextLimits,
) -> BTreeMap<String, Vec<Reference>> {
    let mut result = BTreeMap::new();
    let reference_count = members.iter().map(|m| m.references.len()).sum::<usize>();
    let over_budget =
        members.len() > limits.max_reference_members || reference_count > limits.max_references;
    // Charge the conservative upper bound of nested reference/member scans,
    // not just the outer loop. A large workspace cannot hide quadratic work.
    let mut remaining = limits.max_reference_work;
    let out_of_budget = |main: &ReferenceMember<'_>, stage: &str| {
        tracing::debug!(
            target: "filefacts::go_dependency_context",
            stage,
            manifest = main.path,
            members = members.len(),
            references = reference_count,
            "context budget spent; module references left unresolved"
        );
        main.references
            .iter()
            .map(|r| unresolved(r, UnresolvedReason::ContextBudget))
            .collect::<Vec<_>>()
    };
    for main in members.iter().filter(|m| named(m.path, "go.mod")) {
        let lookup_cost = members.len().saturating_add(reference_count);
        if over_budget || remaining < lookup_cost {
            result.insert(main.path.into(), out_of_budget(main, "lookup"));
            continue;
        }
        remaining -= lookup_cost;
        let workspace = members
            .iter()
            .filter(|m| named(m.path, "go.work") && owns(**m, main.path))
            .max_by_key(|m| member_directory(m.path).len());
        let mut context = vec![(*main, false)];
        if let Some(work) = workspace {
            let work_cost = members.len().saturating_mul(work.references.len());
            if remaining < work_cost {
                result.insert(main.path.into(), out_of_budget(main, "workspace"));
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
            let directory = member_directory(owner.path);
            let name = if *work { "go.work.sum" } else { "go.sum" };
            if let Some(sum) = members.iter().find(|m| {
                m.path
                    .strip_prefix(directory)
                    .is_some_and(|rest| rest == name)
            }) {
                sums.extend(sum.references);
            }
        }
        let vendor_directory = format!("{}vendor/", member_directory(main.path));
        let vendor = members
            .iter()
            .find(|m| m.path.strip_prefix(vendor_directory.as_str()) == Some("modules.txt"));
        let per_reference = context
            .iter()
            .map(|(m, _)| m.references.len())
            .sum::<usize>()
            .saturating_mul(4)
            .saturating_add(sums.len())
            .saturating_add(members.len());
        let resolve_cost = main.references.len().saturating_mul(per_reference);
        if remaining < resolve_cost {
            result.insert(main.path.into(), out_of_budget(main, "resolve"));
            continue;
        }
        remaining -= resolve_cost;
        let resolved = main
            .references
            .iter()
            .map(|r| {
                let mut value = reconcile(r, &context, &sums, members);
                if value.kind != RefKind::Dependency {
                    return value;
                }
                let Some(vendor) = vendor else {
                    return value;
                };
                if vendor
                    .references
                    .iter()
                    .any(|r| r.source == source::INCOMPLETE)
                {
                    return unresolved(r, UnresolvedReason::VendorMetadata);
                }
                let original_module = coordinate(r).map(|(m, _)| m);
                let Some(selected) = vendor.references.iter().find(|v| {
                    v.source == source::VENDOR_MODULE
                        && coordinate(v).map(|(m, _)| m) == original_module
                }) else {
                    return unresolved(r, UnresolvedReason::VendorUnlisted);
                };
                let Some((module, _)) = coordinate(selected) else {
                    return unresolved(r, UnresolvedReason::VendorMetadata);
                };
                let vendored = members.iter().any(|m| {
                    m.path
                        .strip_prefix(vendor_directory.as_str())
                        .and_then(|rest| rest.strip_prefix(module))
                        .is_some_and(|rest| rest.starts_with('/'))
                });
                if !vendored {
                    return unresolved(r, UnresolvedReason::VendorMissing);
                }
                value.kind = RefKind::Local;
                value.locator = RefLocator::Path(format!("vendor/{module}"));
                value.source.clone_from(&selected.source);
                value.resolution = Some(Resolution::Vendored);
                value.evidence = format!("{}; {}", r.evidence, selected.evidence);
                value
            })
            .collect();
        result.insert(main.path.into(), resolved);
    }
    result
}

#[cfg(test)]
mod tests;
