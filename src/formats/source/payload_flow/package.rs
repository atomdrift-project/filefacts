//! One Go package's members analysed together: helper summaries and package
//! globals flow between members until they settle.

use super::{Budget, Collected, Imports, Prepared, Summary, analyse, collect, prepare};
use crate::Values;
use crate::fileid::FileType;
use crate::formats::source::{TreeCache, go_syntax};
use crate::go_package_context::{GoFileFlow, GoPackageFlow};
use crate::package_context::{ContextLimits, SourceFile};
use crate::value_key;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

/// Rounds of package-wide refinement before the analysis gives up on a fixed
/// point and is reported truncated. Each round evaluates every member once,
/// with the summaries the previous round produced.
const MAX_PACKAGE_ROUNDS: usize = 16;

/// One Go member, parsed and indexed once for every package variant that
/// includes it.
pub(crate) struct GoMember<'t> {
    path: &'t str,
    prepared: Prepared<'t>,
    /// Its `source.go.*` execution facts.
    facts: Values,
}

impl<'t> GoMember<'t> {
    pub(crate) fn new(path: &'t str, tree: &'t TreeCache<'_>) -> Self {
        let root = tree.tree().root_node();
        let source = tree.source();
        let config = tree.config();
        let mut facts = Values::new();
        go_syntax::execution_facts(root, source, &mut facts);
        let imports = go_syntax::imports(root, source);
        let collected: Collected<'t> = collect(root, source, config);
        Self {
            path,
            prepared: prepare(root, source, config, collected, &Imports::Go(&imports)),
            facts,
        }
    }
}

/// Analyse one package variant's members together within `budget`. A variant
/// over [`ContextLimits::max_flow_members`] or
/// [`ContextLimits::max_flow_bytes`] is left empty and truncated.
pub(crate) fn package_flow(
    members: &[&GoMember<'_>],
    limits: &ContextLimits,
    budget: &mut Budget<'_>,
) -> GoPackageFlow {
    let total: usize = members.iter().map(|m| m.prepared.source.len()).sum();
    if members.len() > limits.max_flow_members || total > limits.max_flow_bytes {
        tracing::debug!(
            target: "filefacts::source",
            format = "go",
            members = members.len(),
            len = total,
            "package payload flow: package exceeds the flow budget"
        );
        return GoPackageFlow {
            files: Vec::new(),
            truncated: true,
        };
    }
    let mut seeds: BTreeMap<String, Summary> = BTreeMap::new();
    let mut globals = BTreeMap::new();
    let mut files = Vec::new();
    let mut truncated = false;
    let mut settled = false;
    for _ in 0..MAX_PACKAGE_ROUNDS {
        if budget.spent() {
            tracing::debug!(
                target: "filefacts::source",
                format = "go",
                members = members.len(),
                "package payload flow: step budget spent or cancelled"
            );
            truncated = true;
            break;
        }
        let mut next = BTreeMap::new();
        let mut next_globals = globals.clone();
        let mut duplicates = Vec::new();
        files.clear();
        for member in members {
            let mut values = member.facts.clone();
            let outcome = analyse(&member.prepared, &mut values, &seeds, &globals, budget, 1);
            truncated |= outcome.truncated;
            for (name, summary) in outcome.summaries {
                if next.insert(name.clone(), summary).is_some() {
                    duplicates.push(name);
                }
            }
            next_globals.extend(outcome.globals);
            files.push(GoFileFlow {
                path: member.path.to_string(),
                facts: values,
            });
        }
        for name in duplicates {
            tracing::debug!(
                target: "filefacts::source",
                format = "go",
                helper = %name,
                "package payload flow: helper defined in more than one member"
            );
            next.remove(&name);
            truncated = true;
        }
        if seeds == next && globals == next_globals {
            settled = true;
            break;
        }
        seeds = next;
        globals = next_globals;
    }
    if !settled && !truncated {
        tracing::debug!(
            target: "filefacts::source",
            format = "go",
            rounds = MAX_PACKAGE_ROUNDS,
            "package payload flow: helper summaries did not settle"
        );
    }
    truncated |= !settled;
    for file in &mut files {
        file.facts.insert_key(
            value_key!("source.payload_flow.truncated"),
            json!(truncated),
        );
    }
    GoPackageFlow { files, truncated }
}

/// Reanalyze same-package Go files with source-local import scopes and shared
/// package function/global summaries. The caller supplies only one directory
/// and package variant. No imports are fetched and no source is executed.
/// Results are bounded by [`ContextLimits::max_flow_members`],
/// [`ContextLimits::max_flow_bytes`] and [`ContextLimits::max_flow_steps`];
/// `truncated` means coverage is incomplete, not clean. Raising `cancel`
/// stops parsing and analysis early, as [`crate::OpenOptions::cancellation`]
/// does.
#[must_use]
pub fn go_package_payload_flow(
    sources: &[SourceFile<'_>],
    limits: &ContextLimits,
    cancel: Option<&AtomicBool>,
) -> GoPackageFlow {
    let total: usize = sources.iter().map(|f| f.source.len()).sum();
    if sources.len() > limits.max_flow_members || total > limits.max_flow_bytes {
        tracing::debug!(
            target: "filefacts::source",
            format = "go",
            members = sources.len(),
            len = total,
            "package payload flow: package exceeds the flow budget"
        );
        return GoPackageFlow {
            files: Vec::new(),
            truncated: true,
        };
    }
    // The shared parser applies the work budget, wall-clock backstop and
    // scanner guards that every other source parse gets.
    let trees: Vec<_> = sources
        .iter()
        .map(|f| TreeCache::parse(f.source.as_bytes(), FileType::Go, cancel))
        .collect();
    let mut parse_failed = false;
    let members: Vec<GoMember<'_>> = sources
        .iter()
        .zip(&trees)
        .filter_map(|(file, tree)| {
            let cache = tree.cache();
            if cache.is_none() {
                tracing::debug!(
                    target: "filefacts::source",
                    format = "go",
                    path = file.path,
                    error = tree.diagnostic().map_or("", |d| d.message.as_str()),
                    "package payload flow: member did not parse"
                );
                parse_failed = true;
            }
            Some(GoMember::new(file.path, cache?))
        })
        .collect();
    let members: Vec<&GoMember<'_>> = members.iter().collect();
    let mut budget = Budget::new(limits.max_flow_steps, cancel);
    let mut flow = package_flow(&members, limits, &mut budget);
    flow.truncated |= parse_failed;
    flow
}
