//! Package-consistency judgements over a package's own manifest: identity
//! fields that agree on another package's name, and a manifest that depends
//! on itself. Comparisons against named popular packages -- a name one edit
//! away, a summary copied verbatim -- are traits, so no package names live
//! here.
//!
//! Each compares claims one manifest makes (plus, for an sdist, the
//! `requires.txt` setuptools writes beside its `PKG-INFO`), so each is a
//! measurement of the package's own bytes and sits beside the parse that
//! reads it, as `npm.rs`'s `consistency.*` judgements do.

use serde_json::Value as JsonValue;

use super::core_metadata::CoreMetadata;
use crate::metric;
use crate::output::Metrics;

/// Emit the `consistency.*` judgements over a Python Core Metadata block,
/// counting an sdist's `requires.txt` toward the self-dependency.
///
/// - `consistency.metadata_identity_mismatch` — how many advertised identity
///   fields (a `name:`-prefixed summary, a GitHub homepage's repository)
///   agree on one name other than `Name`, when at least two do; else 0.
/// - `consistency.self_dependency` — unconditional requirements naming the
///   package itself, when it declares any requirements.
pub(super) fn core_metadata(
    headers: &CoreMetadata,
    requires_txt: Option<&str>,
    metrics: &mut Metrics,
) {
    let Some(name) = headers
        .first("name")
        .map(normalize_name)
        .filter(|name| !name.is_empty())
    else {
        return;
    };
    metrics.insert(
        metric!("consistency.metadata_identity_mismatch"),
        f64::from(advertised_identity_mismatch(headers, &name)),
    );
    if let Some(count) = python_self_dependencies(headers, requires_txt, &name) {
        metrics.insert(metric!("consistency.self_dependency"), f64::from(count));
    }
}

/// `dependencies` entries of an npm `package.json` naming the package itself;
/// `None` when it has no name or no runtime dependencies.
pub(super) fn npm_self_dependencies(manifest: &serde_json::Map<String, JsonValue>) -> Option<u32> {
    let name = manifest.get("name")?.as_str()?.trim().to_ascii_lowercase();
    let dependencies = manifest.get("dependencies")?.as_object()?;
    if name.is_empty() || dependencies.is_empty() {
        return None;
    }
    let count = dependencies
        .keys()
        .filter(|dependency| dependency.trim().eq_ignore_ascii_case(&name))
        .count();
    u32::try_from(count).ok()
}

/// PEP 503 normalisation: case folded, runs of `-`, `_` and `.` the same.
fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

/// How many advertised identity fields agree on one name that is not the
/// declared one, when at least two do (else 0).
///
/// A typosquat shipping its target verbatim keeps the target's metadata and
/// edits only `Name`. One mismatch is ordinary -- a distribution's module and
/// repository often differ from its name -- but the summary prefix and the
/// homepage repository both naming the same other package is copied metadata
/// with the label swapped.
fn advertised_identity_mismatch(headers: &CoreMetadata, name: &str) -> u32 {
    let mut advertised: Vec<String> = Vec::new();
    // The ecosystem convention of opening the summary with `name:`.
    if let Some((prefix, _)) = headers.first("summary").and_then(|s| s.split_once(':')) {
        let prefix = prefix.trim();
        if !prefix.is_empty()
            && prefix.len() <= 60
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            advertised.push(normalize_name(prefix));
        }
    }
    // A homepage on GitHub names its repository.
    if let Some(repo) = headers
        .first("home-page")
        .and_then(|url| url.split("github.com/").nth(1))
        .and_then(|rest| rest.split('/').nth(1))
        .map(|repo| repo.trim_end_matches(['/', ' ']))
        .filter(|repo| !repo.is_empty())
    {
        advertised.push(normalize_name(repo));
    }
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for other in advertised.iter().filter(|a| a.as_str() != name) {
        *counts.entry(other).or_default() += 1;
    }
    counts.into_values().max().filter(|&n| n >= 2).unwrap_or(0)
}

/// Unconditional requirements naming the package itself, from its
/// `Requires-Dist` headers and an sdist's `requires.txt`; `None` when it
/// declares no requirements at all.
///
/// A requirement guarded by an `extra` marker is optional, and an extra that
/// pulls in the package's own other extras (`foo[all]` requiring `foo[a,b]`)
/// is the ordinary way to aggregate them, so only unconditional requirements
/// count: `Requires-Dist` without an `extra` marker, and the leading,
/// unsectioned block of `requires.txt` (each `[extra]` header begins an
/// optional group).
fn python_self_dependencies(
    headers: &CoreMetadata,
    requires_txt: Option<&str>,
    name: &str,
) -> Option<u32> {
    let mut declared = false;
    let mut count = 0_u32;
    let mut check = |spec: &str| {
        if normalize_name(requirement_name(spec)) == name {
            count += 1;
        }
    };
    // One requirement per header: commas belong to it (`foo[a,b]`,
    // `>=1,<2`), and only a folded continuation line starts another.
    for (field, value) in &headers.fields {
        if field != "requires-dist" {
            continue;
        }
        declared = true;
        for spec in value.lines() {
            let conditional_on_extra = spec
                .split_once(';')
                .is_some_and(|(_, marker)| marker.contains("extra"));
            if !spec.trim().is_empty() && !conditional_on_extra {
                check(spec);
            }
        }
    }
    if let Some(text) = requires_txt {
        declared = true;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                break;
            }
            if !line.is_empty() && !line.starts_with('#') {
                check(line);
            }
        }
    }
    declared.then_some(count)
}

/// The distribution a requirement names: its leading run of PEP 508 name
/// characters, so `foo[extra]>=1.0 ; marker`, `foo (>=1.0)` and `foo==1` all
/// name `foo`.
fn requirement_name(spec: &str) -> &str {
    let spec = spec.trim();
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(spec.len());
    &spec[..end]
}

#[cfg(test)]
mod tests;
