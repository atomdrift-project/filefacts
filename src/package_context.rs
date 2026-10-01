//! Bounded, filesystem-independent package relationships. The caller owns
//! archive traversal; filefacts owns language and manifest semantics.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// One analyzed member, with flattened parser values. Paths are logical archive
/// paths, not paths that this module may read from the host filesystem.
#[derive(Debug, Clone, Copy)]
pub struct SourceMember<'a> {
    /// Logical member path, including its archive ownership boundary.
    pub path: &'a str,
    /// Parsed, flattened facts from this member.
    pub values: &'a BTreeMap<String, Value>,
}

fn text<'a>(member: &'a SourceMember<'_>, key: &str) -> Option<&'a str> {
    member.values.get(key).and_then(Value::as_str)
}

/// Whether the flattened path `path` is `<array>[<i>].<field>`: one field of
/// an element of the array at `array`.
fn element_field(path: &str, array: crate::ValueKey, field: &str) -> bool {
    path.strip_prefix(array.as_str())
        .and_then(|rest| rest.strip_suffix(field))
        .and_then(|rest| rest.strip_suffix("]."))
        .is_some_and(|rest| rest.starts_with('['))
}

/// Directory of a logical member path, separator included: through its last
/// `/`, or through its last `!!` archive delimiter when that comes later, so
/// members of sibling archives (`x/a.zip!!main.go`, `x/b.zip!!main.go`) never
/// share a directory.
pub(crate) fn member_directory(path: &str) -> &str {
    let slash = path.rfind('/').map_or(0, |i| i + 1);
    let archive = path.rfind("!!").map_or(0, |i| i + 2);
    &path[..slash.max(archive)]
}

/// The archive that owns a logical member path: everything through its last
/// `!!` delimiter, or `""` outside any archive.
pub(crate) fn archive_boundary(path: &str) -> &str {
    &path[..path.rfind("!!").map_or(0, |i| i + 2)]
}

/// Apply the relative member reference `spec` to the `/`-separated directory
/// `dir`, returning the normalized segments joined by `/`. `None` for a spec
/// that is absolute, carries `\`, `:`, `!` or `#`, or climbs above `dir`'s
/// root, so a reference can never leave the tree it was resolved in.
pub(crate) fn join_relative(dir: &str, spec: &str) -> Option<String> {
    if spec.starts_with('/') || spec.contains(['\\', ':', '!', '#']) {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    for part in spec.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

fn resolve(base_file: &str, spec: &str, boundary: &str) -> Option<String> {
    let base = base_file
        .strip_prefix(boundary)?
        .rsplit_once('/')
        .map_or("", |(dir, _)| dir);
    Some(format!("{boundary}{}", join_relative(base, spec)?))
}

/// Resolve Cargo entry points and declared modules inside the supplied members.
/// Missing/ambiguous modules and exhausted budgets remain explicit. No globbed
/// source pooling and no filesystem access outside the supplied artifact.
#[must_use]
pub fn cargo_source_context(members: &[SourceMember<'_>]) -> Value {
    let files: BTreeMap<_, _> = members.iter().map(|m| (m.path, m)).collect();
    let mut targets = Vec::new();
    let mut truncated = false;
    let mut remaining = 20_000usize;
    for manifest in members
        .iter()
        .filter(|m| m.path.ends_with("/Cargo.toml") || m.path.ends_with("!!Cargo.toml"))
    {
        let boundary = &manifest.path[..manifest.path.len() - "Cargo.toml".len()];
        let mut entries = Vec::new();
        if text(manifest, crate::value_key!("cargo.build_mode").as_str()) != Some("disabled") {
            entries.push((
                text(manifest, "package.build").unwrap_or("build.rs"),
                "build",
            ));
        }
        let phase = if manifest
            .values
            .get("lib.proc-macro")
            .and_then(Value::as_bool)
            == Some(true)
        {
            "proc-macro"
        } else {
            "runtime"
        };
        entries.push((text(manifest, "lib.path").unwrap_or("src/lib.rs"), phase));
        entries.push(("src/main.rs", "runtime"));
        for (entry, phase) in entries {
            let Some(entry) =
                resolve(manifest.path, entry, boundary).filter(|p| files.contains_key(p.as_str()))
            else {
                continue;
            };
            let mut pending = vec![entry.clone()];
            let mut visited = BTreeSet::new();
            let mut kinds = BTreeSet::new();
            let mut missing = BTreeSet::new();
            while let Some(path) = pending.pop() {
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                remaining -= 1;
                if !visited.insert(path.clone()) {
                    continue;
                }
                let Some(file) = files.get(path.as_str()) else {
                    continue;
                };
                for (key, value) in file.values {
                    if element_field(key, crate::value_key!("source.payload_flow.events"), "kind") {
                        if let Some(kind) = value.as_str() {
                            kinds.insert(kind.to_string());
                        }
                    }
                    if !element_field(key, crate::value_key!("source.rust.modules"), "name") {
                        continue;
                    }
                    let Some(name) = value.as_str() else { continue };
                    let prefix = key.trim_end_matches("name");
                    let inline = text(file, &format!("{prefix}prefix")).unwrap_or("");
                    let stem = path
                        .rsplit('/')
                        .next()
                        .unwrap_or(&path)
                        .trim_end_matches(".rs");
                    let module_dir = if path == entry || matches!(stem, "lib" | "main" | "mod") {
                        String::new()
                    } else {
                        format!("{stem}/")
                    };
                    let candidates = match text(file, &format!("{prefix}path")) {
                        Some(spec) => vec![format!("{inline}{spec}")],
                        None => vec![
                            format!("{module_dir}{inline}{name}.rs"),
                            format!("{module_dir}{inline}{name}/mod.rs"),
                        ],
                    };
                    let found: Vec<_> = candidates
                        .iter()
                        .filter_map(|s| resolve(&path, s, boundary))
                        .filter(|p| files.contains_key(p.as_str()))
                        .collect();
                    if found.len() == 1 {
                        pending.extend(found);
                    } else {
                        missing.insert(format!("{path}:mod {name}"));
                    }
                }
            }
            // Compatibility projection for existing rules. New callers should
            // consume phase/members/events rather than a policy-bearing label.
            let mut behaviors: Vec<_> = kinds.iter().map(|k| format!("{phase}-{k}")).collect();
            if kinds.contains("file-http-body") && kinds.contains("ssh-authorized-keys-write") {
                behaviors.push("connected-file-upload-and-ssh-write".into());
            }
            targets.push(json!({"manifest":manifest.path,"entry":entry,"phase":phase,"members":visited,"events":kinds,"behaviors":behaviors,"unresolved_modules":missing}));
        }
    }
    json!({"targets":targets,"truncated":truncated})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cargo_context_respects_declared_graph_and_disabled_build() {
        let mut manifest = BTreeMap::from([("package.build".into(), json!("bootstrap.rs"))]);
        let root = BTreeMap::from([("source.rust.modules[0].name".into(), json!("helper"))]);
        let helper = BTreeMap::from([(
            "source.payload_flow.events[0].kind".into(),
            json!("file-http-body"),
        )]);
        let unrelated = BTreeMap::from([(
            "source.payload_flow.events[0].kind".into(),
            json!("ssh-authorized-keys-write"),
        )]);
        let run = |manifest: &BTreeMap<String, Value>| {
            cargo_source_context(&[
                SourceMember {
                    path: "p.zip!!pkg/Cargo.toml",
                    values: manifest,
                },
                SourceMember {
                    path: "p.zip!!pkg/bootstrap.rs",
                    values: &root,
                },
                SourceMember {
                    path: "p.zip!!pkg/helper.rs",
                    values: &helper,
                },
                SourceMember {
                    path: "p.zip!!pkg/unrelated.rs",
                    values: &unrelated,
                },
            ])
        };
        let facts = run(&manifest).to_string();
        assert!(facts.contains("build-file-http-body"));
        assert!(!facts.contains("ssh-authorized-keys-write"));
        manifest.insert("cargo.build_mode".into(), json!("disabled"));
        assert_eq!(run(&manifest)["targets"], json!([]));
    }
    #[test]
    fn element_field_matches_only_array_element_fields() {
        let events = crate::value_key!("source.payload_flow.events");
        for (path, expected) in [
            ("source.payload_flow.events[0].kind", true),
            ("source.payload_flow.events[12].kind", true),
            ("source.payload_flow.events[0].kinds", false),
            ("source.payload_flow.events.kind", false),
            ("source.payload_flow.events_extra[0].kind", false),
            ("source.payload_flow.events[0]", false),
            ("source.payload_flow.events].kind", false),
        ] {
            assert_eq!(element_field(path, events, "kind"), expected, "{path}");
        }
    }

    #[test]
    fn paths_do_not_escape_archive_or_package() {
        for path in [
            "../../outside.rs",
            "/etc/passwd",
            "x!!other.rs",
            "C:/other.rs",
        ] {
            assert!(resolve("a.zip!!pkg/src/lib.rs", path, "a.zip!!pkg/").is_none());
        }
        assert_eq!(
            resolve("a.zip!!pkg/src/lib.rs", "../helper.rs", "a.zip!!pkg/"),
            Some("a.zip!!pkg/helper.rs".into())
        );
    }

    #[test]
    fn member_path_helpers_respect_archive_boundaries() {
        assert_eq!(member_directory("pkg/a.go"), "pkg/");
        assert_eq!(member_directory("main.go"), "");
        assert_eq!(member_directory("x/a.zip!!main.go"), "x/a.zip!!");
        assert_eq!(member_directory("x/a.zip!!sub/main.go"), "x/a.zip!!sub/");
        assert_eq!(archive_boundary("x/a.zip!!sub/main.go"), "x/a.zip!!");
        assert_eq!(archive_boundary("x/main.go"), "");
        assert_eq!(join_relative("a/b", "../c/./d"), Some("a/c/d".into()));
        assert_eq!(join_relative("", "c"), Some("c".into()));
        for escaping in ["../../c", "/abs", "x!!y", "c:/d", "a\\b", "#frag"] {
            assert_eq!(join_relative("a", escaping), None, "{escaping}");
        }
    }
}
