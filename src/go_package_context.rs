//! Same-package Go context, independent of scanners and archive extractors.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

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
        let Some(package) = parsed
            .values()
            .get("source.go.package")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let directory = path
            .rsplit_once('/')
            .map_or_else(|| path.rsplit_once('!').map_or("", |(p, _)| p), |(p, _)| p);
        let mut variant = source
            .lines()
            .filter_map(|l| l.strip_prefix("//go:build "))
            .collect::<Vec<_>>()
            .join(" && ");
        let stem = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
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
                variant.push_str(&format!(";{part}"));
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
                for file in facts["files"].as_array().into_iter().flatten() {
                    for (pointer, prefix) in [
                        ("/facts/source/go/initialization_events", "initialization"),
                        ("/facts/source/payload_flow/events", "runtime"),
                    ] {
                        for event in file
                            .pointer(pointer)
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            if let Some(kind) = event["kind"].as_str() {
                                behaviors.insert(format!("{prefix}-{kind}"));
                            }
                        }
                    }
                }
                truncated |= facts["truncated"] == true;
                packages.push(json!({"directory":directory,"package":package,"phase":if test {"test"} else {"runtime"},"variant":variant,"members":inputs.iter().map(|(p,_)|p).collect::<Vec<_>>(),"behaviors":behaviors,"truncated":facts["truncated"]}));
            }
        }
    }
    json!({"packages":packages,"truncated":truncated})
}
