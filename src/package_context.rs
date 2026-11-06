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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound;

pub use crate::formats::source::go_package_payload_flow;
pub use crate::go_dependency_context::{ReferenceMember, go_dependency_context};
pub use crate::go_package_context::{
    GoFileFlow, GoPackage, GoPackageFlow, GoSourceContext, go_source_context,
};

/// Whether `path` names reference metadata that matters whatever its detected
/// type (`go.work`, `go.work.sum`, `modules.txt`). An archive walker keeps
/// these members even when detection calls them non-program data; manifests
/// identified by type need no such exception.
#[must_use]
pub fn has_named_reference_metadata(path: &std::path::Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("go.work" | "go.work.sum" | "modules.txt")
    )
}

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

/// Budgets for [`cargo_source_context`], [`go_source_context`] and
/// [`go_dependency_context`]. A result that hits one is marked
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
    /// Evaluation steps one call's payload flow spends across every package
    /// variant, member and round; once spent, the remaining analyses are
    /// truncated.
    pub max_flow_steps: usize,
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
            max_flow_steps: 10_000_000,
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
    /// The entry-point member: `build.rs`, `src/lib.rs`, `src/main.rs`, a
    /// binary, example, test or bench target, or the manifest's override.
    pub entry: String,
    /// When the target's code runs: examples are [`Phase::Runtime`],
    /// tests and benches [`Phase::Test`].
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

#[cfg(test)]
thread_local! {
    /// Payload-flow events [`cargo_source_context`] has read on this thread.
    pub(crate) static EVENT_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The array at `key` in `values`, or an empty one.
fn array(values: &Values, key: crate::ValueKey) -> &[Value] {
    values
        .lookup(key)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// One kind of Cargo target beyond the library and build script.
struct TargetKind {
    /// The manifest's array of tables declaring them (`[[bin]]`).
    table: &'static str,
    /// The `package` key that turns their discovery off.
    discovery: &'static str,
    /// The directory Cargo discovers them in.
    directory: &'static str,
    phase: Phase,
}

const TARGET_KINDS: [TargetKind; 4] = [
    TargetKind {
        table: "bin",
        discovery: "package.autobins",
        directory: "src/bin",
        phase: Phase::Runtime,
    },
    TargetKind {
        table: "example",
        discovery: "package.autoexamples",
        directory: "examples",
        phase: Phase::Runtime,
    },
    TargetKind {
        table: "test",
        discovery: "package.autotests",
        directory: "tests",
        phase: Phase::Test,
    },
    TargetKind {
        table: "bench",
        discovery: "package.autobenches",
        directory: "benches",
        phase: Phase::Test,
    },
];

/// The entry points of `declared`, a manifest's `[[bin]]`-style array: each
/// target's `path`, or where Cargo looks for its `name` without one. Both
/// conventional places are returned; the caller keeps the one that exists.
fn declared_targets<'v>(
    declared: Option<&'v Value>,
    kind: &'v TargetKind,
    package: Option<&'v str>,
) -> impl Iterator<Item = String> + 'v {
    declared
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(move |target| {
            if let Some(path) = target.get("path").and_then(Value::as_str) {
                return vec![path.to_string()];
            }
            let Some(name) = target.get("name").and_then(Value::as_str) else {
                return Vec::new();
            };
            if kind.table == "bin" && Some(name) == package {
                return vec!["src/main.rs".to_string()];
            }
            vec![
                format!("{}/{name}.rs", kind.directory),
                format!("{}/{name}/main.rs", kind.directory),
            ]
        })
}

/// The entry points Cargo discovers for `kind` among `files`: every
/// `<directory>/<name>.rs` and `<directory>/<name>/main.rs` of the package
/// at `boundary`.
fn discovered_targets<'f>(
    files: &'f BTreeMap<&str, &SourceMember<'_>>,
    boundary: &'f str,
    kind: &'f TargetKind,
) -> impl Iterator<Item = String> + 'f {
    let prefix = format!("{boundary}{}/", kind.directory);
    // The keys under `prefix` are contiguous from it, so one manifest's
    // discovery costs its own targets, not every member of the artifact.
    let from = (Bound::Included(prefix.as_str()), Bound::Unbounded);
    let under = files.range::<str, _>(from);
    under
        .map_while(move |(path, _)| path.strip_prefix(prefix.as_str()))
        .filter_map(move |rest| {
            let entry = match rest.split_once('/') {
                // Cargo matches the extension case-sensitively.
                None => std::path::Path::new(rest)
                    .extension()
                    .is_some_and(|extension| extension == "rs"),
                Some((_, file)) => file == "main.rs",
            };
            entry.then(|| format!("{}/{rest}", kind.directory))
        })
}

/// Resolve Cargo entry points and declared modules inside the supplied members.
/// Entry points are the build script, the library, `src/main.rs`, and every
/// binary, example, test and bench target, declared or discovered as Cargo
/// discovers them. Missing/ambiguous modules and exhausted budgets remain
/// explicit. No globbed source pooling and no filesystem access outside the
/// supplied artifact.
#[must_use]
pub fn cargo_source_context(
    members: &[SourceMember<'_>],
    limits: &ContextLimits,
) -> CargoSourceContext {
    let files: BTreeMap<_, _> = members.iter().map(|m| (m.path, m)).collect();
    let mut targets = Vec::new();
    let mut truncated = false;
    let mut remaining = limits.max_cargo_visits;
    let mut event_kinds: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for manifest in members
        .iter()
        .filter(|m| m.path == "Cargo.toml" || m.path.ends_with("/Cargo.toml"))
    {
        let boundary = member_directory(manifest.path);
        let field = |path| document(manifest.values, path);
        let mut entries: Vec<(String, Phase)> = Vec::new();
        let build = match field("package.build") {
            Some(Value::Bool(false)) => None,
            Some(Value::String(path)) => Some(path.as_str()),
            _ => Some("build.rs"),
        };
        if let Some(build) = build
            && manifest
                .values
                .lookup(crate::value_key!("cargo.build_mode"))
                .and_then(Value::as_str)
                != Some("disabled")
        {
            entries.push((build.to_string(), Phase::Build));
        }
        let phase = if field("lib.proc-macro").and_then(Value::as_bool) == Some(true) {
            Phase::ProcMacro
        } else {
            Phase::Runtime
        };
        entries.push((
            field("lib.path")
                .and_then(Value::as_str)
                .unwrap_or("src/lib.rs")
                .to_string(),
            phase,
        ));
        entries.push(("src/main.rs".to_string(), Phase::Runtime));
        let package = field("package.name").and_then(Value::as_str);
        for kind in &TARGET_KINDS {
            let discovered = (field(kind.discovery).and_then(Value::as_bool) != Some(false))
                .then(|| discovered_targets(&files, boundary, kind));
            entries.extend(
                declared_targets(field(kind.table), kind, package)
                    .chain(discovered.into_iter().flatten())
                    .map(|entry| (entry, kind.phase)),
            );
        }
        let mut seen = BTreeSet::new();
        for (entry, phase) in entries {
            let Some(entry) = resolve(manifest.path, &entry, boundary)
                .filter(|p| files.contains_key(p.as_str()) && seen.insert(p.clone()))
            else {
                continue;
            };
            let mut pending = vec![entry.clone()];
            let mut visited = BTreeSet::new();
            let mut events = BTreeSet::new();
            let mut missing = BTreeSet::new();
            let mut spent = false;
            'visit: while let Some(path) = pending.pop() {
                if remaining == 0 {
                    spent = true;
                    break;
                }
                remaining -= 1;
                if !visited.insert(path.clone()) {
                    continue;
                }
                let Some((&member, file)) = files.get_key_value(path.as_str()) else {
                    continue;
                };
                // Read once per call: every target reaching a file shares it.
                let kinds = event_kinds.entry(member).or_insert_with(|| {
                    let events =
                        array(file.values, crate::value_key!("source.payload_flow.events"));
                    #[cfg(test)]
                    EVENT_READS.set(EVENT_READS.get() + events.len());
                    events
                        .iter()
                        .filter_map(|event| event.get("kind")?.as_str())
                        .collect()
                });
                events.extend(kinds.iter().map(|kind| (*kind).to_string()));
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
                for module in array(file.values, crate::value_key!("source.rust.modules")) {
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
                        // Spent when popped.
                        pending.extend(found);
                    } else if remaining == 0 {
                        spent = true;
                        break 'visit;
                    } else {
                        // Every target reaching this file lists it again, so
                        // an unresolved declaration costs a visit too.
                        remaining -= 1;
                        missing.insert(format!("{path}:mod {name}"));
                    }
                }
            }
            if spent {
                tracing::debug!(
                    target: "filefacts::package_context",
                    stage = "cargo-modules",
                    budget = limits.max_cargo_visits,
                    manifest = manifest.path,
                    "module visit budget spent; target coverage incomplete"
                );
                truncated = true;
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

#[cfg(test)]
mod tests;
