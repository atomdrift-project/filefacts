//! Bounded, source-local payload provenance. These are capabilities, not
//! reachability proofs or malware verdicts. No package code is executed.
//!
//! Track assignments and local helper summaries, keeping HTTP authentication
//! separate from request bodies. Unknown code is not assumed to be an HTTP
//! client. Analysis limits are surfaced rather than reported as clean scans.
//!
//! What counts as a payload source, an HTTP send or a file operation is data:
//! one [`model::Model`] per language ([`mod@model`]). The evaluator ([`eval`])
//! only follows values through syntax; [`package`] shares helper summaries
//! across the members of one Go package.
use super::langs::{Lang, LangConfig};
use super::scope::Scope;
use super::visit::{self, NodeIds, Visit};
use super::{named_children, text};
use crate::Values;
use crate::value_key;
use model::{Model, model};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use tree_sitter::Node;

mod eval;
mod model;
mod package;

pub use package::go_package_payload_flow;
pub(crate) use package::{GoMember, package_flow};

type Bits = u64;
const ENV: Bits = 1;
const SECRET: Bits = 2;
const CARGO: Bits = 4;
const FILE: Bits = 8;
const CREDFILE: Bits = 16;
const CARGOPATH: Bits = 32;
const SECRETPATH: Bits = 64;
const AUTHPATH: Bits = 128;
const CLIENT: Bits = 256;
const REQUEST: Bits = 512;
const CARGOHOME: Bits = 1024;
const CREDFILENAME: Bits = 2048;
const CURL_COMMAND: Bits = 4096;
const CURL_DATA_NEXT: Bits = 8192;
// A JavaScript process.env reference is a collection until code selects a
// property. Keep that state separate from a bulk environment read so aliases
// such as `const env = process.env` can refine non-secret configuration keys.
const ENV_OBJECT: Bits = 16384;
// One environment variable read by a call, as opposed to a bulk environment
// dump. A separate bit keeps provider/configuration values from looking like
// a complete dump.
const ENV_VALUE: Bits = 32768;
const PARAM_START: usize = 24;
const PARAM_COUNT: usize = 16;
const PARAM_BITS: Bits = ((1 << PARAM_COUNT) - 1) << PARAM_START;
/// Evaluation steps one file's analysis may take, past which it stops and is
/// reported truncated.
const STEP_LIMIT: usize = 200_000;
/// Rounds of helper-summary refinement before the analysis gives up on a
/// fixed point and is reported truncated.
const MAX_ROUNDS: usize = 8;
/// Largest source analysed at all.
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Summary {
    returns: Bits,
    body: Bits,
    write_path: Bits,
    http: bool,
    reads: Bits,
}

type Bindings<'g> = Scope<'g, Bits>;

/// One parsed file and its index, built once however many rounds analyse it.
struct Prepared<'t> {
    root: Node<'t>,
    source: &'t str,
    config: &'static LangConfig,
    /// Unambiguous helpers by name. A Go `init` is keyed `init@<offset>`,
    /// since a package may declare several.
    functions: BTreeMap<String, Node<'t>>,
    aliases: HashMap<String, String>,
    /// Node ids of test-only code, which is never evaluated.
    test_only: HashSet<usize>,
}

struct Analysis<'s> {
    source: &'s str,
    language: Lang,
    config: &'static LangConfig,
    model: &'static Model,
    aliases: HashMap<String, String>,
    test_only: &'s HashSet<usize>,
    summaries: BTreeMap<String, Summary>,
    budget: usize,
    truncated: bool,
}

/// What the analysis needs from the shared walk ([`super::visit`]): the
/// named helper functions and the Python imports, in source order.
/// Definitions are not descended into, since nested definitions have
/// separate lexical scopes rather than global names, and test-only items are
/// skipped.
pub(super) struct Collector<'t> {
    source: &'t str,
    language: Lang,
    /// One per open node: whether its named children are index candidates.
    expanded: Vec<bool>,
    events: Vec<Event<'t>>,
}

enum Event<'t> {
    /// A named definition: the index key and the function node.
    Function(String, Node<'t>),
    PythonImport(Node<'t>),
}

/// A finished [`Collector`], with the test-only nodes the walk found.
pub(super) struct Collected<'t> {
    events: Vec<Event<'t>>,
    test_only: HashSet<usize>,
}

impl<'t> Collector<'t> {
    /// A collector for `source`, or `None` when the language has no
    /// [`Model`] to analyse it with.
    pub(super) fn new(source: &'t str, language: Lang) -> Option<Self> {
        model(language).is_some().then(|| Self {
            source,
            language,
            expanded: Vec::new(),
            events: Vec::new(),
        })
    }

    /// Record `visit`'s node; `test_only` holds the test-only nodes the walk
    /// has found so far, which include this one when it is.
    pub(super) fn enter(
        &mut self,
        visit: &Visit<'t>,
        ids: &NodeIds,
        test_only: Option<&HashSet<usize>>,
    ) {
        let node = visit.node;
        let reached = visit.named && self.expanded.last().is_none_or(|&expanded| expanded);
        let mut expanded = false;
        if reached && !test_only.is_some_and(|ids| ids.contains(&node.id())) {
            if ids.function.contains(visit.kind_id) {
                if let Some(name) = node.child_by_field_name("name") {
                    let name = text(name, self.source);
                    let key = if self.language == Lang::Go && name == "init" {
                        format!("init@{}", node.start_byte())
                    } else {
                        name.to_string()
                    };
                    self.events.push(Event::Function(key, node));
                }
            } else if let Some((name, value)) = ids
                .variable_declarator
                .contains(visit.kind_id)
                .then(|| {
                    node.child_by_field_name("name")
                        .zip(node.child_by_field_name("value"))
                })
                .flatten()
                .filter(|(_, value)| ids.function.contains(value.kind_id()))
            {
                self.events
                    .push(Event::Function(text(name, self.source).to_string(), value));
            } else {
                expanded = true;
                if self.language == Lang::Python && ids.python_import.contains(visit.kind_id) {
                    self.events.push(Event::PythonImport(node));
                }
            }
        }
        self.expanded.push(expanded);
    }

    pub(super) fn exit(&mut self) {
        self.expanded.pop();
    }

    pub(super) fn into_collected(self, test_only: HashSet<usize>) -> Collected<'t> {
        Collected {
            events: self.events,
            test_only,
        }
    }
}

/// Walk `root` for the analysis alone, when no shared walk collected for it.
fn collect<'t>(root: Node<'t>, source: &'t str, config: &'static LangConfig) -> Collected<'t> {
    let mut collectors = visit::Collectors {
        payload: Collector::new(source, config.lang),
        ..visit::Collectors::default()
    };
    visit::walk(root, source, config, &mut collectors);
    Collected {
        events: collectors
            .payload
            .map(|collector| collector.events)
            .unwrap_or_default(),
        test_only: HashSet::new(),
    }
}

/// The import aliases [`emit`] resolves names through, computed once by the
/// caller.
pub(super) enum Imports<'a> {
    None,
    /// Rust `use` paths, `path as alias` when renamed.
    Rust(&'a [(String, u64)]),
    Go(&'a [super::go_syntax::Import<'a>]),
}

/// Index `collected` once: helpers by name, dropping ambiguous names, and
/// import aliases from `imports` and the Python imports.
fn prepare<'t>(
    root: Node<'t>,
    source: &'t str,
    config: &'static LangConfig,
    collected: Collected<'t>,
    imports: &Imports<'_>,
) -> Prepared<'t> {
    let mut aliases = HashMap::new();
    match imports {
        Imports::Go(imports) => {
            for import in *imports {
                let local = import
                    .name
                    .unwrap_or_else(|| import.path.rsplit('/').next().unwrap_or(import.path));
                if !matches!(local, "." | "_") {
                    aliases.insert(local.to_string(), import.path.to_string());
                }
            }
        }
        Imports::Rust(imports) => {
            for (import, _) in *imports {
                let (name, local) = import
                    .split_once(" as ")
                    .unwrap_or_else(|| (import, import.rsplit("::").next().unwrap_or("")));
                // Conflicting aliases are deliberately not canonicalized.
                aliases
                    .entry(local.to_string())
                    .and_modify(|old: &mut String| {
                        if old != name {
                            old.clear();
                        }
                    })
                    .or_insert_with(|| name.to_string());
            }
        }
        Imports::None => {}
    }
    let mut functions = BTreeMap::new();
    let mut ambiguous = Vec::new();
    for event in collected.events {
        match event {
            Event::Function(key, node) => {
                if functions.insert(key.clone(), node).is_some() {
                    ambiguous.push(key);
                }
            }
            Event::PythonImport(node) => python_imports(node, source, &mut aliases),
        }
    }
    for name in ambiguous {
        tracing::debug!(
            target: "filefacts::source",
            language = config.name(),
            helper = %name,
            "payload flow: helper defined more than once, left unresolved"
        );
        functions.remove(&name);
    }
    Prepared {
        root,
        source,
        config,
        functions,
        aliases,
        test_only: collected.test_only,
    }
}

/// The evaluation steps an analysis may still take and the flag that
/// cancels it, shared by every file and round of one analysis.
pub(crate) struct Budget<'c> {
    steps: usize,
    cancel: Option<&'c AtomicBool>,
}

impl<'c> Budget<'c> {
    pub(crate) fn new(steps: usize, cancel: Option<&'c AtomicBool>) -> Self {
        Self { steps, cancel }
    }

    /// No step is left, or the caller cancelled.
    fn spent(&self) -> bool {
        self.steps == 0 || self.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed))
    }
}

/// Analyse the file `collected` came from, as the shared walk collected it.
pub(super) fn emit<'t>(
    root: Node<'t>,
    source: &'t str,
    config: &'static LangConfig,
    values: &mut Values,
    collected: Collected<'t>,
    imports: &Imports<'_>,
) {
    if source.len() > MAX_SOURCE_BYTES {
        tracing::debug!(
            target: "filefacts::source",
            language = config.name(),
            len = source.len(),
            max = MAX_SOURCE_BYTES,
            "payload flow: source too large to analyse"
        );
        values.insert_key(value_key!("source.payload_flow.truncated"), json!(true));
        return;
    }
    let prepared = prepare(root, source, config, collected, imports);
    let mut budget = Budget::new(STEP_LIMIT, None);
    let outcome = analyse(
        &prepared,
        values,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &mut budget,
        MAX_ROUNDS,
    );
    if !outcome.settled {
        tracing::debug!(
            target: "filefacts::source",
            language = config.name(),
            rounds = MAX_ROUNDS,
            "payload flow: helper summaries did not settle"
        );
    }
    let truncated = outcome.truncated || !outcome.settled;
    if truncated {
        tracing::debug!(
            target: "filefacts::source",
            language = config.name(),
            len = source.len(),
            "payload flow: analysis truncated; events may be incomplete"
        );
    }
    values.insert_key(
        value_key!("source.payload_flow.truncated"),
        json!(truncated),
    );
}

/// What one [`analyse`] call leaves for a package-level caller's next round.
struct Outcome {
    /// Helper summaries, without Go `init`s, which nothing calls.
    summaries: BTreeMap<String, Summary>,
    /// The module-level bindings.
    globals: BTreeMap<String, Bits>,
    /// The helper summaries reached a fixed point within the rounds.
    settled: bool,
    /// The step budget, depth limit or cancellation cut evaluation short.
    truncated: bool,
}

/// Summarise every helper for up to `rounds` rounds or until the summaries
/// settle, then the module, and write the events. Every step comes out of
/// `budget`. `seeds` and `global_seeds` are what other package members
/// summarised in the previous round.
fn analyse(
    prepared: &Prepared<'_>,
    values: &mut Values,
    seeds: &BTreeMap<String, Summary>,
    global_seeds: &BTreeMap<String, Bits>,
    budget: &mut Budget<'_>,
    rounds: usize,
) -> Outcome {
    let config = prepared.config;
    let language = config.lang;
    let source = prepared.source;
    let root = prepared.root;
    let Some(model) = model(language) else {
        return Outcome {
            summaries: BTreeMap::new(),
            globals: BTreeMap::new(),
            settled: true,
            truncated: false,
        };
    };
    let mut a = Analysis {
        source,
        language,
        config,
        model,
        aliases: prepared.aliases.clone(),
        test_only: &prepared.test_only,
        summaries: seeds.clone(),
        budget: budget.steps,
        truncated: false,
    };
    let functions = &prepared.functions;
    let mut settled = false;
    // Rounds settle helper declaration order and bounded recursion.
    for _ in 0..rounds {
        if budget
            .cancel
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            a.truncated = true;
            break;
        }
        let before = a.summaries.clone();
        let mut globals = Bindings::over(global_seeds);
        if language == Lang::Go {
            a.eval(root, &mut globals, &mut Summary::default(), 0);
        }
        for (name, node) in functions {
            let mut bindings = Bindings::under(&globals);
            if let Some(params) = node.child_by_field_name("parameters") {
                for (index, param) in named_children(params).enumerate().take(PARAM_COUNT) {
                    let pat = param
                        .child_by_field_name("pattern")
                        .or_else(|| param.child_by_field_name("name"))
                        .unwrap_or(param);
                    let mut bits = 1 << (PARAM_START + index);
                    if let Some(mut ty) = param.child_by_field_name("type") {
                        while let Some(inner) = ty.child_by_field_name("type") {
                            ty = inner;
                        }
                        if model
                            .client_types
                            .contains(&a.canonical(text(ty, source)).as_str())
                        {
                            bits |= CLIENT;
                        }
                    }
                    a.bind(pat, bits, &mut bindings);
                }
            }
            let mut summary = Summary::default();
            if let Some(body) = node.child_by_field_name("body") {
                let tail = a.eval(body, &mut bindings, &mut summary, 0);
                if config.tail_returns {
                    summary.returns |= tail;
                }
            }
            a.summaries.insert(name.clone(), summary);
        }
        if a.summaries == before {
            settled = true;
            break;
        }
    }
    let mut events = Vec::new();
    for (name, node) in functions {
        if let Some(summary) = a.summaries.get(name) {
            events.extend(events_for(summary, name, node.start_byte()));
        }
    }
    let mut top = Summary::default();
    let mut globals = Bindings::over(global_seeds);
    a.eval(root, &mut globals, &mut top, 0);
    events.extend(events_for(&top, "<module>", 0));
    if language == Lang::Go {
        let mut startup = top.clone();
        for (name, summary) in &a.summaries {
            if name.starts_with("init@") && functions.contains_key(name) {
                startup.body |= summary.body;
                startup.http |= summary.http;
                startup.write_path |= summary.write_path;
            }
        }
        values.insert_key(
            value_key!("source.go.initialization_http"),
            json!(startup.http),
        );
        values.insert_key(
            value_key!("source.go.initialization_events"),
            json!(events_for(&startup, "<initialization>", 0)),
        );
    }
    events.sort_by_cached_key(serde_json::Value::to_string);
    events.dedup();
    values.insert_key(value_key!("source.payload_flow.events"), json!(events));
    // Top-level facts include direct calls and calls to resolved local helpers,
    // but not merely exported/uninvoked functions or constant-false branches.
    if language.is_ecmascript() {
        values.insert_key(value_key!("source.execution.module_http"), json!(top.http));
    }
    budget.steps = a.budget;
    Outcome {
        summaries: a
            .summaries
            .into_iter()
            .filter(|(name, _)| functions.contains_key(name) && !name.starts_with("init@"))
            .collect(),
        globals: globals.into_map(),
        settled,
        truncated: a.truncated,
    }
}

fn events_for(summary: &Summary, name: &str, offset: usize) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    let body = summary.body
        | if summary.body & ENV_OBJECT != 0 {
            ENV | SECRET
        } else {
            0
        };
    for (bit, kind) in [
        (ENV, "environment-http-body"),
        (ENV_VALUE, "environment-value-http-body"),
        (SECRET, "secret-http-body"),
        (CARGO, "cargo-credential-http-body"),
        (FILE, "file-http-body"),
        (CREDFILE, "credential-file-http-body"),
    ] {
        if body & bit != 0 {
            events.push(json!({"kind":kind,"function":name,"offset":offset}));
        }
    }
    if summary.write_path & AUTHPATH != 0 {
        events.push(json!({"kind":"ssh-authorized-keys-write","function":name,"offset":offset}));
    }
    if summary.reads & CARGO != 0 {
        events.push(json!({"kind":"cargo-credential-read","function":name,"offset":offset}));
    }
    events
}

/// Bind the names a Python `import` or `from … import` statement declares
/// to their dotted targets.
fn python_imports(node: Node<'_>, source: &str, aliases: &mut HashMap<String, String>) {
    let module = node.child_by_field_name("module_name");
    for child in named_children(node) {
        if Some(child) == module {
            continue;
        }
        let (name, alias) = if child.kind() == "aliased_import" {
            let (Some(name), Some(alias)) = (
                child.child_by_field_name("name"),
                child.child_by_field_name("alias"),
            ) else {
                continue;
            };
            (text(name, source), text(alias, source))
        } else if child.kind() == "dotted_name" {
            (text(child, source), text(child, source))
        } else {
            continue;
        };
        let target = match module {
            Some(module) => format!("{}.{name}", text(module, source)),
            None => name.to_string(),
        };
        aliases.insert(alias.to_string(), target);
    }
}

/// Union `bits` into `name`'s binding, binding it if it is unbound.
fn add_bits(bindings: &mut Bindings<'_>, name: &str, bits: Bits) {
    let bits = bindings.get(name).unwrap_or(0) | bits;
    bindings.insert(name.to_string(), bits);
}

#[cfg(test)]
mod tests;
