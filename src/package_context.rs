//! Bounded, filesystem-independent package relationships. The caller owns
//! archive traversal; filefacts owns language and manifest semantics.
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

/// One source member's text. Paths are logical archive paths, never read
/// from the host filesystem.
#[derive(Debug, Clone, Copy)]
pub struct SourceFile<'a> {
    /// Logical member path, including its archive ownership boundary.
    pub path: &'a str,
    /// The member's source text.
    pub source: &'a str,
}

/// Whether the caller supplied every member of the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Every member the artifact holds was supplied.
    Complete,
    /// Some members were left out (an archive walk stopped at a limit, a
    /// member could not be read), so the result is marked truncated.
    Incomplete,
}

/// When code in a package context runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Phase {
    /// At build time: a Cargo build script.
    Build,
    /// Inside the compiler: a Cargo proc-macro crate.
    ProcMacro,
    /// When the program runs.
    Runtime,
    /// When the package's tests run (a Go `_test.go` variant).
    Test,
}

/// Budgets for [`cargo_source_context`] and [`crate::go_source_context`].
/// A result that hits one is marked `truncated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContextLimits {
    /// Most Go members analysed at all; more leaves the result empty.
    pub max_go_members: usize,
    /// Most Go source bytes, summed over members; more leaves the result
    /// empty.
    pub max_go_bytes: usize,
    /// Largest single Go member analysed; a larger one is skipped.
    pub max_go_member_bytes: usize,
    /// Most Go package variants reported.
    pub max_go_packages: usize,
    /// Most Rust module files visited across every Cargo target.
    pub max_cargo_visits: usize,
    /// Most members one Go package variant's payload flow analyses; more
    /// leaves that variant empty and truncated.
    pub max_flow_members: usize,
    /// Most Go source bytes, summed, one package variant's payload flow
    /// analyses; more leaves that variant empty and truncated.
    pub max_flow_bytes: usize,
}

impl Default for ContextLimits {
    fn default() -> Self {
        Self {
            max_go_members: 512,
            max_go_bytes: 8 * 1024 * 1024,
            max_go_member_bytes: 2 * 1024 * 1024,
            max_go_packages: 128,
            max_cargo_visits: 20_000,
            max_flow_members: 128,
            max_flow_bytes: 2 * 1024 * 1024,
        }
    }
}

/// What [`cargo_source_context`] resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CargoSourceContext {
    /// One entry per resolved target entry point.
    pub targets: Vec<CargoTarget>,
    /// A budget was exhausted, so coverage is incomplete — not clean.
    pub truncated: bool,
}

/// One Cargo target entry point and the module files it reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CargoTarget {
    /// The `Cargo.toml` member that declares the target.
    pub manifest: String,
    /// The entry-point member (`build.rs`, `src/lib.rs`, `src/main.rs`, or
    /// the manifest's override).
    pub entry: String,
    /// When the target's code runs.
    pub phase: Phase,
    /// Members reached from the entry point through declared modules.
    pub members: BTreeSet<String>,
    /// Payload-flow event kinds found in those members.
    pub events: BTreeSet<String>,
    /// `<phase>-<event>` labels, kept for existing rules; prefer `phase`
    /// and `events`.
    pub behaviors: Vec<String>,
    /// `<member>:mod <name>` declarations that matched no member, or more
    /// than one.
    pub unresolved_modules: BTreeSet<String>,
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
pub fn cargo_source_context(
    members: &[SourceMember<'_>],
    limits: &ContextLimits,
) -> CargoSourceContext {
    let files: BTreeMap<_, _> = members.iter().map(|m| (m.path, m)).collect();
    let mut targets = Vec::new();
    let mut truncated = false;
    let mut remaining = limits.max_cargo_visits;
    for manifest in members
        .iter()
        .filter(|m| m.path.ends_with("/Cargo.toml") || m.path.ends_with("!!Cargo.toml"))
    {
        let boundary = &manifest.path[..manifest.path.len() - "Cargo.toml".len()];
        let mut entries = Vec::new();
        if text(manifest, crate::value_key!("cargo.build_mode").as_str()) != Some("disabled") {
            entries.push((
                text(manifest, "package.build").unwrap_or("build.rs"),
                Phase::Build,
            ));
        }
        let phase = if manifest
            .values
            .get("lib.proc-macro")
            .and_then(Value::as_bool)
            == Some(true)
        {
            Phase::ProcMacro
        } else {
            Phase::Runtime
        };
        entries.push((text(manifest, "lib.path").unwrap_or("src/lib.rs"), phase));
        entries.push(("src/main.rs", Phase::Runtime));
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
            let label = phase.as_str();
            let mut behaviors: Vec<_> = kinds.iter().map(|k| format!("{label}-{k}")).collect();
            if kinds.contains("file-http-body") && kinds.contains("ssh-authorized-keys-write") {
                behaviors.push("connected-file-upload-and-ssh-write".into());
            }
            targets.push(CargoTarget {
                manifest: manifest.path.to_string(),
                entry,
                phase,
                members: visited,
                events: kinds,
                behaviors,
                unresolved_modules: missing,
            });
        }
    }
    CargoSourceContext { targets, truncated }
}

impl Phase {
    /// The serialized label, e.g. `"proc-macro"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::ProcMacro => "proc-macro",
            Self::Runtime => "runtime",
            Self::Test => "test",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
            cargo_source_context(
                &[
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
                ],
                &ContextLimits::default(),
            )
        };
        let facts = run(&manifest);
        assert!(!facts.truncated);
        let [target] = facts.targets.as_slice() else {
            panic!("one target: {facts:?}");
        };
        assert_eq!(target.phase, Phase::Build);
        assert_eq!(target.behaviors, ["build-file-http-body"]);
        assert!(!target.events.contains("ssh-authorized-keys-write"));
        let json = serde_json::to_value(&facts).unwrap();
        assert_eq!(json["targets"][0]["phase"], "build");
        assert_eq!(json["targets"][0]["entry"], "p.zip!!pkg/bootstrap.rs");
        manifest.insert("cargo.build_mode".into(), json!("disabled"));
        assert!(run(&manifest).targets.is_empty());
    }

    /// An exhausted visit budget is reported, not silently clean.
    #[test]
    fn cargo_context_reports_an_exhausted_budget() {
        let manifest = BTreeMap::new();
        let lib = BTreeMap::new();
        let members = [
            SourceMember {
                path: "pkg/Cargo.toml",
                values: &manifest,
            },
            SourceMember {
                path: "pkg/src/lib.rs",
                values: &lib,
            },
        ];
        let mut limits = ContextLimits::default();
        assert!(!cargo_source_context(&members, &limits).truncated);
        limits.max_cargo_visits = 0;
        assert!(cargo_source_context(&members, &limits).truncated);
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
