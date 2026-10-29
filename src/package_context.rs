//! Bounded, filesystem-independent package relationships. The caller owns
//! archive traversal; filefacts owns language and manifest semantics.
//!
//! # Paths
//!
//! Every function here takes the members of **one artifact** — one archive,
//! package or source tree — per call. Member paths are logical, relative to
//! that artifact's root and `/`-separated, and are never read from the host
//! filesystem. Every path character other than `/` is ordinary, so a
//! caller's own notation for nesting means nothing here. A reference that
//! climbs above the root, or is absolute, resolves to nothing, so a result
//! never reaches outside the members the caller grouped together: call once
//! per nested archive to keep its members apart from its parent's.
use crate::Values;
use crate::formats::references::document;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// One analyzed member and the values filefacts extracted from it.
#[derive(Debug, Clone, Copy)]
pub struct SourceMember<'a> {
    /// Logical member path; see [Paths](self#paths).
    pub path: &'a str,
    /// The member's extracted values ([`crate::ParsedFile::values`]).
    pub values: &'a Values,
}

/// One source member's text.
#[derive(Debug, Clone, Copy)]
pub struct SourceFile<'a> {
    /// Logical member path; see [Paths](self#paths).
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

/// Budgets for [`cargo_source_context`], [`crate::go_source_context`] and
/// [`crate::go_dependency_context`]. A result that hits one is marked
/// `truncated`, or its references unresolved.
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
    /// Most members a Go dependency context considers; more leaves every
    /// module's references unresolved.
    pub max_reference_members: usize,
    /// Most references, summed over members, a Go dependency context
    /// considers; more leaves every module's references unresolved.
    pub max_references: usize,
    /// Work units (member and reference comparisons) a Go dependency
    /// context spends across all modules; a module it cannot afford keeps
    /// its references unresolved.
    pub max_reference_work: usize,
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
            max_reference_members: 4096,
            max_references: 50_000,
            max_reference_work: 2_000_000,
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
    /// `<member>:mod <name>` declarations that matched no member, or more
    /// than one.
    pub unresolved_modules: BTreeSet<String>,
}

/// Directory of a logical member path, through its last `/`; `""` at the
/// artifact root.
pub(crate) fn member_directory(path: &str) -> &str {
    &path[..path.rfind('/').map_or(0, |i| i + 1)]
}

/// Apply the relative member reference `spec` to the `/`-separated directory
/// `dir`, returning the normalized segments joined by `/`. `None` for a spec
/// that is absolute (`/x`, `C:/x`, `\\x`) or climbs above `dir`'s root, so a
/// reference can never leave the artifact it was resolved in.
pub(crate) fn join_relative(dir: &str, spec: &str) -> Option<String> {
    if spec.starts_with('/') || spec.contains(['\\', ':']) {
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

/// `spec` resolved against the directory of `base_file`, kept within
/// `boundary`, the directory of the manifest that owns both.
fn resolve(base_file: &str, spec: &str, boundary: &str) -> Option<String> {
    let base = member_directory(base_file.strip_prefix(boundary)?);
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
        .filter(|m| m.path == "Cargo.toml" || m.path.ends_with("/Cargo.toml"))
    {
        let boundary = member_directory(manifest.path);
        let field = |path| document(manifest.values, path);
        let mut entries = Vec::new();
        if manifest
            .values
            .get_key(crate::value_key!("cargo.build_mode"))
            .and_then(Value::as_str)
            != Some("disabled")
        {
            entries.push((
                field("package.build")
                    .and_then(Value::as_str)
                    .unwrap_or("build.rs"),
                Phase::Build,
            ));
        }
        let phase = if field("lib.proc-macro").and_then(Value::as_bool) == Some(true) {
            Phase::ProcMacro
        } else {
            Phase::Runtime
        };
        entries.push((
            field("lib.path")
                .and_then(Value::as_str)
                .unwrap_or("src/lib.rs"),
            phase,
        ));
        entries.push(("src/main.rs", Phase::Runtime));
        for (entry, phase) in entries {
            let Some(entry) =
                resolve(manifest.path, entry, boundary).filter(|p| files.contains_key(p.as_str()))
            else {
                continue;
            };
            let mut pending = vec![entry.clone()];
            let mut visited = BTreeSet::new();
            let mut events = BTreeSet::new();
            let mut missing = BTreeSet::new();
            while let Some(path) = pending.pop() {
                if remaining == 0 {
                    tracing::debug!(
                        target: "filefacts::package_context",
                        stage = "cargo-modules",
                        budget = limits.max_cargo_visits,
                        manifest = manifest.path,
                        "module visit budget spent; target coverage incomplete"
                    );
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
                let array = |key| {
                    file.values
                        .get_key(key)
                        .and_then(Value::as_array)
                        .map_or(&[][..], Vec::as_slice)
                };
                events.extend(
                    array(crate::value_key!("source.payload_flow.events"))
                        .iter()
                        .filter_map(|event| event.get("kind")?.as_str())
                        .map(str::to_string),
                );
                let stem = path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&path)
                    .trim_end_matches(".rs");
                // A non-root module file's children live in its own
                // directory (`a.rs` declares `a/b.rs`).
                let module_dir = if path == entry || matches!(stem, "lib" | "main" | "mod") {
                    String::new()
                } else {
                    format!("{stem}/")
                };
                for module in array(crate::value_key!("source.rust.modules")) {
                    let Some(name) = module.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    let inline = module.get("prefix").and_then(Value::as_str).unwrap_or("");
                    let candidates = match module.get("path").and_then(Value::as_str) {
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
            targets.push(CargoTarget {
                manifest: manifest.path.to_string(),
                entry,
                phase,
                members: visited,
                events,
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
mod tests;
