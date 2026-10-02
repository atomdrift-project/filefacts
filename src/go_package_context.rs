//! Same-package Go context, independent of scanners and archive extractors.
use crate::Values;
use crate::package_context::{ContextLimits, Coverage, Phase, SourceFile, member_directory};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

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
    /// The input was incomplete or a budget was exhausted, so coverage is
    /// incomplete — not clean.
    pub truncated: bool,
}

/// One Go package variant: the members compiled together under one set of
/// build constraints, for one phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GoPackage {
    /// The package directory, as a logical member path.
    pub directory: String,
    /// The package clause's name.
    pub package: String,
    /// [`Phase::Runtime`], or [`Phase::Test`] when `_test.go` members join.
    pub phase: Phase,
    /// The build constraints that select this variant: `//go:build`
    /// expressions joined with ` && `, then `;<os-or-arch>` filename tags.
    /// Empty for unconstrained members.
    pub variant: String,
    /// The members compiled together.
    pub members: Vec<String>,
    /// `<initialization|runtime>-<event>` payload-flow labels.
    pub behaviors: BTreeSet<String>,
    /// The payload-flow analysis of this variant hit a budget.
    pub truncated: bool,
}

/// Package directory of a logical member path: its [`member_directory`]
/// without the trailing `/`. An archive delimiter stays (`x/a.zip!!`), so
/// members of sibling archives never share a package.
fn package_directory(path: &str) -> &str {
    let directory = member_directory(path);
    directory.strip_suffix('/').unwrap_or(directory)
}

/// Analyze supplied Go members without filesystem access or execution. Package
/// directories, test variants, and build constraints bound helper resolution.
/// An incomplete input or analysis budget remains explicit in the result.
#[must_use]
pub fn go_source_context(
    sources: &[SourceFile<'_>],
    coverage: Coverage,
    limits: &ContextLimits,
) -> GoSourceContext {
    if sources.len() > limits.max_go_members
        || sources.iter().map(|s| s.source.len()).sum::<usize>() > limits.max_go_bytes
    {
        return GoSourceContext {
            packages: Vec::new(),
            truncated: true,
        };
    }
    let mut groups: BTreeMap<(String, String), Vec<Member<'_>>> = BTreeMap::new();
    let mut truncated = coverage == Coverage::Incomplete;
    for &SourceFile { path, source } in sources {
        if source.len() > limits.max_go_member_bytes {
            truncated = true;
            continue;
        }
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(source.as_bytes());
        // The package clause needs only the syntax tree, not the extraction
        // pipeline behind `values()`.
        let Some(package) = parsed
            .source_ast()
            .and_then(|ast| crate::formats::source::go_package_name(&ast))
        else {
            continue;
        };
        let directory = package_directory(path);
        let mut variant = source
            .lines()
            .filter_map(|l| l.strip_prefix("//go:build "))
            .collect::<Vec<_>>()
            .join(" && ");
        let stem = path[member_directory(path).len()..]
            .trim_end_matches(".go")
            .trim_end_matches("_test");
        for part in stem.split('_').skip(1) {
            if matches!(
                part,
                "linux"
                    | "windows"
                    | "darwin"
                    | "freebsd"
                    | "openbsd"
                    | "netbsd"
                    | "android"
                    | "ios"
                    | "aix"
                    | "solaris"
                    | "illumos"
                    | "plan9"
                    | "js"
                    | "wasip1"
                    | "amd64"
                    | "386"
                    | "arm"
                    | "arm64"
                    | "riscv64"
                    | "ppc64"
                    | "ppc64le"
                    | "s390x"
                    | "wasm"
                    | "mips"
                    | "mipsle"
                    | "mips64"
                    | "mips64le"
                    | "loong64"
            ) {
                let _ = write!(variant, ";{part}");
            }
        }
        groups
            .entry((directory.to_string(), package.to_string()))
            .or_default()
            .push(Member {
                path,
                source,
                variant,
                test: path.ends_with("_test.go"),
            });
    }
    let mut packages = Vec::new();
    for ((directory, package), files) in groups {
        let variants: BTreeSet<_> = files.iter().map(|m| m.variant.clone()).collect();
        for variant in variants {
            for test in [false, true] {
                if packages.len() >= limits.max_go_packages {
                    truncated = true;
                    break;
                }
                let selected: Vec<_> = files
                    .iter()
                    .filter(|m| (!m.test || test) && (m.variant.is_empty() || m.variant == variant))
                    .collect();
                if selected.is_empty() || test && !selected.iter().any(|m| m.test) {
                    continue;
                }
                let inputs: Vec<_> = selected
                    .iter()
                    .map(|m| SourceFile {
                        path: m.path,
                        source: m.source,
                    })
                    .collect();
                let flow = crate::go_package_payload_flow(&inputs, limits);
                let mut behaviors = BTreeSet::new();
                for file in &flow.files {
                    for (key, prefix) in [
                        (
                            crate::value_key!("source.go.initialization_events"),
                            "initialization",
                        ),
                        (crate::value_key!("source.payload_flow.events"), "runtime"),
                    ] {
                        for event in file
                            .facts
                            .get_key(key)
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            if let Some(kind) = event.get("kind").and_then(Value::as_str) {
                                behaviors.insert(format!("{prefix}-{kind}"));
                            }
                        }
                    }
                }
                truncated |= flow.truncated;
                packages.push(GoPackage {
                    directory: directory.clone(),
                    package: package.clone(),
                    phase: if test { Phase::Test } else { Phase::Runtime },
                    variant: variant.clone(),
                    members: inputs.iter().map(|f| f.path.to_string()).collect(),
                    behaviors,
                    truncated: flow.truncated,
                });
            }
        }
    }
    GoSourceContext {
        packages,
        truncated,
    }
}

/// One Go member grouped under its package.
struct Member<'a> {
    path: &'a str,
    source: &'a str,
    /// Build constraints: see [`GoPackage::variant`].
    variant: String,
    test: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_directory_keeps_sibling_archives_apart() {
        assert_eq!(package_directory("pkg/a.go"), "pkg");
        assert_eq!(package_directory("main.go"), "");
        assert_eq!(package_directory("x/a.zip!!main.go"), "x/a.zip!!");
        assert_eq!(package_directory("x/a.zip!!sub/main.go"), "x/a.zip!!sub");

        let source = "package main\nfunc main(){}\n";
        let context = go_source_context(
            &[
                file("x/a.zip!!main.go", source),
                file("x/b.zip!!main.go", source),
            ],
            Coverage::Complete,
            &ContextLimits::default(),
        );
        let directories: BTreeSet<_> = context
            .packages
            .iter()
            .map(|p| p.directory.as_str())
            .collect();
        assert_eq!(directories, BTreeSet::from(["x/a.zip!!", "x/b.zip!!"]));
        assert!(!context.truncated);
    }

    fn file<'a>(path: &'a str, source: &'a str) -> SourceFile<'a> {
        SourceFile { path, source }
    }

    /// Incomplete input and exhausted budgets both mark the result truncated.
    #[test]
    fn incomplete_input_and_budgets_truncate() {
        let members = [file("p/a.go", "package one\nfunc A(){}\n")];
        let limits = ContextLimits::default();
        assert!(!go_source_context(&members, Coverage::Complete, &limits).truncated);
        assert!(go_source_context(&members, Coverage::Incomplete, &limits).truncated);
        let mut tight = limits;
        tight.max_go_members = 0;
        let context = go_source_context(&members, Coverage::Complete, &tight);
        assert!(context.truncated && context.packages.is_empty());
        let mut tight = limits;
        tight.max_go_packages = 0;
        assert!(go_source_context(&members, Coverage::Complete, &tight).truncated);
    }

    /// Members are grouped by the package clause read from each file's syntax
    /// tree; a non-Go member is not grouped at all.
    #[test]
    fn members_group_by_package_clause() {
        let context = go_source_context(
            &[
                file("p/a.go", "package one\nfunc A(){}\n"),
                file("p/b.go", "package two\nfunc B(){}\n"),
                file("p/c_linux.go", "package one\nfunc C(){}\n"),
                file("p/README.md", "package one\n"),
            ],
            Coverage::Complete,
            &ContextLimits::default(),
        );
        let packages: BTreeSet<_> = context
            .packages
            .iter()
            .map(|p| {
                assert_eq!(p.phase, Phase::Runtime);
                (p.package.as_str(), p.variant.as_str(), p.members.join(","))
            })
            .collect();
        assert_eq!(
            packages,
            BTreeSet::from([
                ("one", "", "p/a.go".to_string()),
                ("one", ";linux", "p/a.go,p/c_linux.go".to_string()),
                ("two", "", "p/b.go".to_string()),
            ])
        );
        let json = serde_json::to_value(&context).unwrap();
        assert_eq!(json["packages"][0]["phase"], "runtime");
        assert_eq!(
            json["packages"][0]["members"],
            serde_json::json!(["p/a.go"])
        );
    }
}
