//! Same-package Go context, independent of scanners and archive extractors.
use crate::Values;
use crate::package_context::{ContextLimits, Coverage, Phase, SourceFile, member_directory};
use constraint::PLATFORMS;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

mod constraint;

/// What [`crate::go_package_payload_flow`] found for one package variant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GoPackageFlow {
    /// One entry per member that parsed, in input order.
    pub files: Vec<GoFileFlow>,
    /// A budget was exhausted, a member failed to parse, or helper summaries
    /// did not settle, so coverage is incomplete — not clean.
    pub truncated: bool,
}

/// Payload-flow facts for one Go member.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GoFileFlow {
    /// The member's logical path.
    pub path: String,
    /// Its `source.payload_flow.*` and `source.go.*` values.
    pub facts: Values,
}

/// What [`go_source_context`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GoSourceContext {
    /// One entry per package directory, build variant and phase.
    pub packages: Vec<GoPackage>,
    /// Members no known platform builds: excluded by a custom build tag
    /// (`//go:build ignore`, `integration`), or carrying a constraint
    /// `go/build` rejects. Their own facts still come from extraction.
    pub unselected: Vec<String>,
    /// The input was incomplete, a member did not parse, analysis was
    /// cancelled, or a budget was exhausted, so coverage is incomplete — not
    /// clean.
    pub truncated: bool,
}

/// One Go package variant: the members compiled together for one set of
/// platforms, in one phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GoPackage {
    /// The package directory, as a logical member path.
    pub directory: String,
    /// The package clause's name.
    pub package: String,
    /// [`Phase::Runtime`], or [`Phase::Test`] when `_test.go` members join.
    pub phase: Phase,
    /// The `GOOS/GOARCH` ports (`linux/amd64`) whose default build selects
    /// exactly these members, judged by file-name suffixes and build
    /// constraints as `go/build` judges them. A port's default build sets
    /// its GOOS and GOARCH, the GOOS it implies (`android` → `linux`),
    /// `unix`, `cgo` where the port enables it, the `gc` compiler and every
    /// `go1.N` release tag; no custom tag. Empty when every port builds the
    /// same members.
    pub platforms: Vec<String>,
    /// The members compiled together, in input order.
    pub members: Vec<String>,
    /// The payload-flow analysis of this variant hit a budget.
    pub truncated: bool,
}

/// Analyze supplied Go members without filesystem access or execution.
/// Package directories, test variants, and build constraints bound helper
/// resolution. `sources` are one artifact's members; see [the path
/// contract](crate::package_context#paths). Raising `cancel` stops parsing
/// and analysis early and marks the result truncated. An incomplete input
/// or analysis budget remains explicit in the result.
#[must_use]
pub fn go_source_context(
    sources: &[SourceFile<'_>],
    coverage: Coverage,
    limits: &ContextLimits,
    cancel: Option<&AtomicBool>,
) -> GoSourceContext {
    let total_bytes = sources.iter().map(|s| s.source.len()).sum::<usize>();
    if sources.len() > limits.max_go_members || total_bytes > limits.max_go_bytes {
        tracing::debug!(
            target: "filefacts::go_package_context",
            stage = "input",
            members = sources.len(),
            len = total_bytes,
            "Go source context over its input budget; not analysed"
        );
        return GoSourceContext {
            packages: Vec::new(),
            unselected: Vec::new(),
            truncated: true,
        };
    }
    let mut groups: BTreeMap<(&str, String), Vec<Member<'_>>> = BTreeMap::new();
    let mut unselected = Vec::new();
    let mut truncated = coverage == Coverage::Incomplete;
    for &SourceFile { path, source } in sources {
        let directory = member_directory(path);
        let name = &path[directory.len()..];
        // `go/build` reads only `.go` files, matched case-sensitively, and
        // skips `_`- and `.`-prefixed ones.
        if std::path::Path::new(name)
            .extension()
            .is_none_or(|extension| extension != "go")
            || name.starts_with(['_', '.'])
        {
            continue;
        }
        if source.len() > limits.max_go_member_bytes {
            tracing::debug!(
                target: "filefacts::go_package_context",
                stage = "member",
                path,
                len = source.len(),
                "Go member over its size budget; skipped"
            );
            truncated = true;
            continue;
        }
        let constraint = match constraint::file_constraint(source) {
            Ok(constraint) => constraint,
            Err(error) => {
                tracing::debug!(
                    target: "filefacts::go_package_context",
                    stage = "constraint",
                    path,
                    %error,
                    "Go member build constraint rejected; no platform builds it"
                );
                unselected.push(path.to_string());
                continue;
            }
        };
        let builds: Vec<bool> = PLATFORMS
            .iter()
            .map(|platform| {
                let tag = |name: &str| platform.has_tag(name);
                constraint::file_name_matches(name, &tag)
                    && constraint.as_ref().is_none_or(|expr| expr.eval(&tag))
            })
            .collect();
        if !builds.contains(&true) {
            unselected.push(path.to_string());
            continue;
        }
        let Some(package) = crate::formats::source::go_package_clause(source, cancel) else {
            tracing::debug!(
                target: "filefacts::go_package_context",
                stage = "parse",
                path,
                len = source.len(),
                "Go member did not parse; left out of its package"
            );
            truncated = true;
            continue;
        };
        groups
            .entry((directory.strip_suffix('/').unwrap_or(directory), package))
            .or_default()
            .push(Member {
                path,
                source,
                builds,
                test: name.ends_with("_test.go"),
            });
    }
    let mut packages = Vec::new();
    'packages: for ((directory, package), members) in &groups {
        for phase in [Phase::Runtime, Phase::Test] {
            let test = phase == Phase::Test;
            if test && !members.iter().any(|m| m.test) {
                continue;
            }
            // Ports that build the same members share one variant, listed in
            // [`PLATFORMS`] order.
            // Each variant holds indices into `members`.
            let mut variants: Vec<(Vec<usize>, Vec<String>)> = Vec::new();
            for (index, platform) in PLATFORMS.iter().enumerate() {
                let selected: Vec<usize> = members
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| (!m.test || test) && m.builds.get(index) == Some(&true))
                    .map(|(i, _)| i)
                    .collect();
                let has_test = selected
                    .iter()
                    .any(|&i| members.get(i).is_some_and(|m| m.test));
                if selected.is_empty() || test && !has_test {
                    continue;
                }
                let platform = format!("{}/{}", platform.goos, platform.goarch);
                match variants.iter_mut().find(|(s, _)| *s == selected) {
                    Some((_, platforms)) => platforms.push(platform),
                    None => variants.push((selected, vec![platform])),
                }
            }
            let everywhere = matches!(variants.as_slice(), [(_, platforms)] if platforms.len() == PLATFORMS.len());
            for (selected, platforms) in variants {
                if packages.len() >= limits.max_go_packages {
                    tracing::debug!(
                        target: "filefacts::go_package_context",
                        stage = "variants",
                        budget = limits.max_go_packages,
                        "Go package variant budget spent; later variants left out"
                    );
                    truncated = true;
                    break 'packages;
                }
                let inputs: Vec<_> = selected
                    .iter()
                    .filter_map(|&i| members.get(i))
                    .map(|m| SourceFile {
                        path: m.path,
                        source: m.source,
                    })
                    .collect();
                let flow = crate::go_package_payload_flow(&inputs, limits, cancel);
                truncated |= flow.truncated;
                packages.push(GoPackage {
                    directory: (*directory).to_string(),
                    package: package.clone(),
                    phase,
                    platforms: if everywhere { Vec::new() } else { platforms },
                    members: inputs.iter().map(|f| f.path.to_string()).collect(),
                    truncated: flow.truncated,
                });
            }
        }
    }
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        truncated = true;
    }
    GoSourceContext {
        packages,
        unselected,
        truncated,
    }
}

/// One Go member grouped under its package.
struct Member<'a> {
    path: &'a str,
    source: &'a str,
    /// Whether each of [`PLATFORMS`] builds this member.
    builds: Vec<bool>,
    test: bool,
}

#[cfg(test)]
mod tests;
