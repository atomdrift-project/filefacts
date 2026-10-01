//! Same-package Go context, independent of scanners and archive extractors.
use crate::package_context::member_directory;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

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
pub fn go_source_context(sources: &[(String, String)], incomplete: bool) -> Value {
    if sources.len() > 512 || sources.iter().map(|(_, s)| s.len()).sum::<usize>() > 8 * 1024 * 1024
    {
        return json!({"packages":[],"truncated":true});
    }
    let mut groups: BTreeMap<(String, String), Vec<(&str, &str, String, bool)>> = BTreeMap::new();
    let mut truncated = incomplete;
    for (path, source) in sources {
        if source.len() > 2 * 1024 * 1024 {
            truncated = true;
            continue;
        }
        let Ok(parsed) = crate::open_with_path(std::path::Path::new(path), source.as_bytes())
        else {
            truncated = true;
            continue;
        };
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
            .push((path, source, variant, path.ends_with("_test.go")));
    }
    let mut packages = Vec::new();
    for ((directory, package), files) in groups {
        let variants: BTreeSet<_> = files.iter().map(|(_, _, v, _)| v.clone()).collect();
        for variant in variants {
            for test in [false, true] {
                if packages.len() >= 128 {
                    truncated = true;
                    break;
                }
                let selected: Vec<_> = files
                    .iter()
                    .filter(|(_, _, v, t)| (!*t || test) && (v.is_empty() || *v == variant))
                    .collect();
                if selected.is_empty() || test && !selected.iter().any(|(_, _, _, t)| *t) {
                    continue;
                }
                let inputs: Vec<_> = selected.iter().map(|(p, s, _, _)| (*p, *s)).collect();
                let facts = crate::go_package_payload_flow(&inputs);
                let mut behaviors = BTreeSet::new();
                let files = facts.get("files").and_then(Value::as_array);
                for file in files.into_iter().flatten() {
                    for (key, prefix) in [
                        (
                            crate::value_key!("source.go.initialization_events"),
                            "initialization",
                        ),
                        (crate::value_key!("source.payload_flow.events"), "runtime"),
                    ] {
                        for event in file
                            .get("facts")
                            .and_then(|facts| key.get_in(facts))
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
                let facts_truncated = facts.get("truncated");
                truncated |= facts_truncated.and_then(Value::as_bool) == Some(true);
                packages.push(json!({"directory":directory,"package":package,"phase":if test {"test"} else {"runtime"},"variant":variant,"members":inputs.iter().map(|(p,_)|p).collect::<Vec<_>>(),"behaviors":behaviors,"truncated":facts_truncated}));
            }
        }
    }
    json!({"packages":packages,"truncated":truncated})
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

        let source = "package main\nfunc main(){}\n".to_string();
        let context = go_source_context(
            &[
                ("x/a.zip!!main.go".into(), source.clone()),
                ("x/b.zip!!main.go".into(), source),
            ],
            false,
        );
        let directories: BTreeSet<_> = context["packages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["directory"].as_str())
            .collect();
        assert_eq!(directories, BTreeSet::from(["x/a.zip!!", "x/b.zip!!"]));
    }

    /// Members are grouped by the package clause read from each file's syntax
    /// tree; a non-Go member is not grouped at all.
    #[test]
    fn members_group_by_package_clause() {
        let context = go_source_context(
            &[
                ("p/a.go".into(), "package one\nfunc A(){}\n".into()),
                ("p/b.go".into(), "package two\nfunc B(){}\n".into()),
                ("p/c_linux.go".into(), "package one\nfunc C(){}\n".into()),
                ("p/README.md".into(), "package one\n".into()),
            ],
            false,
        );
        let packages: BTreeSet<_> = context["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["package"].as_str().unwrap(),
                    p["variant"].as_str().unwrap(),
                    p["members"].to_string(),
                )
            })
            .collect();
        assert_eq!(
            packages,
            BTreeSet::from([
                ("one", "", r#"["p/a.go"]"#.to_string()),
                ("one", ";linux", r#"["p/a.go","p/c_linux.go"]"#.to_string()),
                ("two", "", r#"["p/b.go"]"#.to_string()),
            ])
        );
    }
}
