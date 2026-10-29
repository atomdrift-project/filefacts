//! Bounded, source-local payload provenance. These are capabilities, not
//! reachability proofs or malware verdicts. No package code is executed.
//!
//! Track assignments and local helper summaries, keeping HTTP authentication
//! separate from request bodies. Unknown code is not assumed to be an HTTP
//! client. Analysis limits are surfaced rather than reported as clean scans.
//!
//! What counts as a payload source, an HTTP send or a file operation is data:
//! one [`Model`] per language. The evaluator only follows values through
//! syntax.
use super::langs::{self, Lang, LangConfig};
use super::scope::Scope;
use super::visit::{self, NodeIds, Visit};
use super::{MAX_FLOW_DEPTH, TreeCache, named_children, text};
use crate::fileid::FileType;
use crate::package_context::{ContextLimits, SourceFile};
use crate::value_key;
use crate::{GoFileFlow, GoPackageFlow, Values};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use tree_sitter::Node;

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
/// Evaluation steps per analysis, past which it stops and is reported
/// truncated.
const LIMIT: usize = 200_000;
/// Rounds of helper-summary refinement before the analysis gives up on a
/// fixed point and is reported truncated.
const MAX_ROUNDS: usize = 8;
/// Largest source analysed at all.
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;

/// Path fragments of credential files.
const SECRET_PATHS: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    "id_rsa",
    "id_ed25519",
    ".env",
    ".kube/config",
    "application_default_credentials.json",
    ".terraform.d/credentials",
    "credentials.tfrc.json",
];
/// Path fragments of Cargo's credential file.
const CARGO_CREDENTIAL_PATHS: &[&str] = &[".cargo/credentials", ".cargo\\\\credentials"];
/// File names that are Cargo's credential file once joined to `CARGO_HOME`.
const CARGO_CREDENTIAL_NAMES: &[&str] = &["credentials", "credentials.toml"];
/// Environment variable name fragments that hold secrets.
const SECRET_VARIABLES: &[&str] = &[
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
];

/// How an HTTP send carries its body.
#[derive(Clone, Copy)]
enum Body {
    /// Not in this call; a request builder may add it later.
    None,
    /// The argument at this index.
    Arg(usize),
    /// The first argument, a request built with its body.
    Request,
    /// The [`Model::keyword_bodies`] keyword arguments, or the second
    /// positional one.
    Keywords,
    /// The `body` field of the second argument, an options object.
    Options,
}

/// An HTTP send: a free function, or a method of an HTTP client.
struct Send {
    name: &'static str,
    on_client: bool,
    body: Body,
}

const fn send(name: &'static str, body: Body) -> Send {
    Send {
        name,
        on_client: false,
        body,
    }
}

const fn client_send(name: &'static str, body: Body) -> Send {
    Send {
        name,
        on_client: true,
        body,
    }
}

/// One language's library knowledge. Names are canonical: import aliases
/// are already resolved (`h.Post` with `h "net/http"` is `net/http.Post`).
struct Model {
    /// Calls returning the whole environment.
    environ_calls: &'static [&'static str],
    /// Member reads that are the whole environment.
    environ_members: &'static [&'static str],
    /// Calls returning the one variable their first argument names.
    env_var_calls: &'static [&'static str],
    /// Prefixes of member reads that select one variable (`os.environ[`).
    env_var_members: &'static [&'static str],
    /// Calls constructing an HTTP client.
    client_calls: &'static [&'static str],
    /// Member reads that are an HTTP client.
    client_members: &'static [&'static str],
    /// Types whose parameters and composite literals are HTTP clients.
    client_types: &'static [&'static str],
    /// Calls building a request whose body is their last argument.
    request_calls: &'static [&'static str],
    sends: &'static [Send],
    /// Modules whose functions are matched as client methods
    /// (`requests.post` as `post` on a client).
    client_modules: &'static [&'static str],
    /// Whether a send without its body returns a request builder.
    sends_return_builders: bool,
    /// Methods of a request builder whose arguments are the body.
    body_methods: &'static [&'static str],
    /// Methods of a client whose arguments are the body.
    client_body_methods: &'static [&'static str],
    /// Keyword arguments that carry a [`Body::Keywords`] body.
    keyword_bodies: &'static [&'static str],
    /// Calls reading a file named by their arguments.
    file_read_calls: &'static [&'static str],
    /// Methods reading a file; called on a reader, they fill the buffer
    /// passed as their first argument.
    file_read_methods: &'static [&'static str],
    /// Calls writing a file whose path is their first argument.
    file_write_calls: &'static [&'static str],
    /// Methods whose arguments join their receiver's contents.
    append_methods: &'static [&'static str],
    /// Methods that read only metadata, none of their receiver's bytes.
    metadata_methods: &'static [&'static str],
    /// Methods that set authentication, never body.
    auth_methods: &'static [&'static str],
    /// Callee spellings whose calls set request headers, never body.
    header_selectors: &'static [&'static str],
    /// Calls starting a process whose first argument is the program.
    process_calls: &'static [&'static str],
}

const EMPTY: Model = Model {
    environ_calls: &[],
    environ_members: &[],
    env_var_calls: &[],
    env_var_members: &[],
    client_calls: &[],
    client_members: &[],
    client_types: &[],
    request_calls: &[],
    sends: &[],
    client_modules: &[],
    sends_return_builders: false,
    body_methods: &[],
    client_body_methods: &[],
    keyword_bodies: &[],
    file_read_calls: &[],
    file_read_methods: &[],
    file_write_calls: &[],
    append_methods: &["push", "append", "extend", "insert"],
    metadata_methods: &[],
    auth_methods: &[],
    header_selectors: &[],
    process_calls: &[],
};

const RUST: Model = Model {
    environ_calls: &[
        "std::env::vars",
        "std::env::vars_os",
        "env::vars",
        "env::vars_os",
    ],
    env_var_calls: &[
        "std::env::var",
        "std::env::var_os",
        "env::var",
        "env::var_os",
    ],
    client_calls: &[
        "reqwest::Client::new",
        "reqwest::Client::builder",
        "reqwest::blocking::Client::new",
        "reqwest::blocking::Client::builder",
        "curl::easy::Easy::new",
    ],
    client_types: &[
        "reqwest::Client",
        "reqwest::blocking::Client",
        "curl::easy::Easy",
    ],
    sends: &[
        client_send("post", Body::None),
        client_send("put", Body::None),
        client_send("patch", Body::None),
        client_send("get", Body::None),
        client_send("request", Body::None),
        send("ureq::post", Body::None),
        send("ureq::put", Body::None),
        send("ureq::patch", Body::None),
        send("ureq::get", Body::None),
    ],
    sends_return_builders: true,
    body_methods: &[
        "body",
        "json",
        "form",
        "multipart",
        "send_json",
        "send_form",
        "send_bytes",
        "send_string",
        "send",
    ],
    client_body_methods: &["post_fields_copy"],
    file_read_calls: &[
        "std::fs::read",
        "std::fs::read_to_string",
        "fs::read",
        "fs::read_to_string",
    ],
    file_read_methods: &["read_to_end", "read_to_string"],
    file_write_calls: &["std::fs::write", "fs::write"],
    metadata_methods: &["len", "is_empty", "is_ok", "is_err", "is_some", "is_none"],
    process_calls: &["std::process::Command::new", "Command::new"],
    ..EMPTY
};

const PYTHON: Model = Model {
    environ_members: &["os.environ"],
    env_var_calls: &["os.getenv", "os.environ.get"],
    env_var_members: &["os.environ["],
    client_calls: &["requests.Session", "httpx.Client", "httpx.AsyncClient"],
    sends: &[
        client_send("get", Body::None),
        client_send("head", Body::None),
        client_send("delete", Body::None),
        client_send("options", Body::None),
        client_send("post", Body::Keywords),
        client_send("put", Body::Keywords),
        client_send("patch", Body::Keywords),
        client_send("request", Body::Keywords),
    ],
    client_modules: &["requests.", "httpx."],
    keyword_bodies: &["data", "json", "files"],
    file_read_calls: &["open"],
    file_read_methods: &["read_text", "read_bytes"],
    ..EMPTY
};

const ECMASCRIPT: Model = Model {
    environ_members: &["process.env"],
    env_var_members: &["process.env.", "process.env["],
    sends: &[send("fetch", Body::Options)],
    file_read_calls: &["fs.readFileSync", "fs.readFile"],
    ..EMPTY
};

const GO: Model = Model {
    environ_calls: &["os.Environ"],
    env_var_calls: &["os.Getenv", "os.LookupEnv"],
    client_members: &["net/http.DefaultClient"],
    client_types: &["net/http.Client"],
    request_calls: &["net/http.NewRequest", "net/http.NewRequestWithContext"],
    sends: &[
        send("net/http.Post", Body::Arg(2)),
        send("net/http.PostForm", Body::Arg(1)),
        client_send("Post", Body::Arg(2)),
        client_send("PostForm", Body::Arg(1)),
        client_send("Do", Body::Request),
    ],
    file_read_calls: &[
        "os.ReadFile",
        "io/ioutil.ReadFile",
        "os.Open",
        "io.ReadAll",
        "io/ioutil.ReadAll",
    ],
    file_write_calls: &["os.WriteFile", "io/ioutil.WriteFile"],
    // Form and body builders; headers and authentication are not body.
    append_methods: &["Set", "Add", "Write", "WriteString"],
    auth_methods: &["SetBasicAuth", "AddCookie"],
    header_selectors: &[".Header."],
    ..EMPTY
};

/// The [`Model`] of an analysed language.
fn model(language: Lang) -> Option<&'static Model> {
    match language {
        Lang::Rust => Some(&RUST),
        Lang::Python => Some(&PYTHON),
        Lang::JavaScript | Lang::TypeScript => Some(&ECMASCRIPT),
        Lang::Go => Some(&GO),
        _ => None,
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Summary {
    returns: Bits,
    body: Bits,
    write_path: Bits,
    http: bool,
    reads: Bits,
}

type Bindings<'g> = Scope<'g, Bits>;

/// The index of one file, built once however many rounds analyse it.
struct Prepared<'t> {
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
    /// A collector for `source`, or `None` when [`emit`] will not analyse it.
    pub(super) fn new(source: &'t str, language: Lang) -> Option<Self> {
        (model(language).is_some() && source.len() <= MAX_SOURCE_BYTES).then(|| Self {
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
    source: &'t str,
    language: Lang,
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
            language = language.name(),
            helper = %name,
            "payload flow: helper defined more than once, left unresolved"
        );
        functions.remove(&name);
    }
    Prepared {
        functions,
        aliases,
        test_only: collected.test_only,
    }
}

/// Analyse `root`, using what the shared walk collected when it ran a
/// [`Collector`].
pub(super) fn emit<'t>(
    root: Node<'t>,
    source: &'t str,
    config: &'static LangConfig,
    values: &mut Values,
    collected: Option<Collected<'t>>,
    imports: &Imports<'_>,
) {
    if model(config.lang).is_none() {
        return;
    }
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
    let collected = collected.unwrap_or_else(|| collect(root, source, config));
    let prepared = prepare(source, config.lang, collected, imports);
    analyse(
        root,
        source,
        config,
        &prepared,
        values,
        &BTreeMap::new(),
        &BTreeMap::new(),
    );
}

/// Summarise every helper to a fixed point, then the module, and write the
/// events. Returns the helper summaries and module bindings a package-level
/// caller seeds the next round with.
fn analyse<'t>(
    root: Node<'t>,
    source: &'t str,
    config: &'static LangConfig,
    prepared: &'t Prepared<'t>,
    values: &mut Values,
    seeds: &BTreeMap<String, Summary>,
    global_seeds: &BTreeMap<String, Bits>,
) -> (BTreeMap<String, Summary>, BTreeMap<String, Bits>) {
    let language = config.lang;
    let Some(model) = model(language) else {
        return (BTreeMap::new(), BTreeMap::new());
    };
    let mut a = Analysis {
        source,
        language,
        config,
        model,
        aliases: prepared.aliases.clone(),
        test_only: &prepared.test_only,
        summaries: seeds.clone(),
        budget: LIMIT,
        truncated: false,
    };
    let functions = &prepared.functions;
    // Rounds settle helper declaration order and bounded recursion.
    for round in 0..MAX_ROUNDS {
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
                if language == Lang::Rust {
                    summary.returns |= tail;
                }
            }
            a.summaries.insert(name.clone(), summary);
        }
        if a.summaries == before {
            break;
        }
        if round == MAX_ROUNDS - 1 {
            tracing::debug!(
                target: "filefacts::source",
                language = language.name(),
                rounds = MAX_ROUNDS,
                "payload flow: helper summaries did not settle"
            );
            a.truncated = true;
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
    if a.truncated {
        tracing::debug!(
            target: "filefacts::source",
            language = language.name(),
            len = source.len(),
            "payload flow: analysis truncated; events may be incomplete"
        );
    }
    values.insert_key(value_key!("source.payload_flow.events"), json!(events));
    values.insert_key(
        value_key!("source.payload_flow.truncated"),
        json!(a.truncated),
    );
    // Top-level facts include direct calls and calls to resolved local helpers,
    // but not merely exported/uninvoked functions or constant-false branches.
    if language.is_ecmascript() {
        values.insert_key(value_key!("source.execution.module_http"), json!(top.http));
    }
    (
        a.summaries
            .into_iter()
            .filter(|(name, _)| functions.contains_key(name) && !name.starts_with("init@"))
            .collect(),
        globals.into_map(),
    )
}

/// Reanalyze same-package Go files with source-local import scopes and shared
/// package function/global summaries. The caller supplies only one directory
/// and package variant. No imports are fetched and no source is executed.
/// Results are bounded by [`ContextLimits::max_flow_members`] and
/// [`ContextLimits::max_flow_bytes`]; `truncated` means coverage is
/// incomplete, not clean. `cancel` stops the parses early, as
/// [`crate::OpenOptions::cancellation`] does.
#[must_use]
pub fn go_package_payload_flow(
    sources: &[SourceFile<'_>],
    limits: &ContextLimits,
    cancel: Option<&AtomicBool>,
) -> GoPackageFlow {
    let total: usize = sources.iter().map(|f| f.source.len()).sum();
    let Some(config) = langs::config_for(FileType::Go) else {
        return GoPackageFlow {
            files: Vec::new(),
            truncated: true,
        };
    };
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
    let mut truncated = false;
    let mut members = Vec::new();
    for (file, tree) in sources.iter().zip(&trees) {
        let Some(tree) = tree.cache() else {
            tracing::debug!(
                target: "filefacts::source",
                format = "go",
                path = file.path,
                error = tree.diagnostic().map_or("", |d| d.message.as_str()),
                "package payload flow: member did not parse"
            );
            truncated = true;
            continue;
        };
        let root = tree.tree().root_node();
        let source = tree.source();
        let mut facts = Values::new();
        super::go_syntax::execution_facts(root, source, &mut facts);
        let imports = super::go_syntax::imports(root, source);
        let prepared = prepare(
            source,
            Lang::Go,
            collect(root, source, config),
            &Imports::Go(&imports),
        );
        members.push((file.path, root, source, prepared, facts));
    }
    let mut seeds = BTreeMap::new();
    let mut globals = BTreeMap::new();
    let mut result = Vec::new();
    for round in 0..MAX_ROUNDS {
        let mut next = BTreeMap::new();
        let mut next_globals = globals.clone();
        let mut duplicates = Vec::new();
        result.clear();
        for (path, root, source, prepared, facts) in &members {
            let mut values = facts.clone();
            let (summaries, bindings) = analyse(
                *root,
                source,
                config,
                prepared,
                &mut values,
                &seeds,
                &globals,
            );
            truncated |= values
                .get("source.payload_flow.truncated")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
            for (name, summary) in summaries {
                if next.insert(name.clone(), summary).is_some() {
                    duplicates.push(name);
                }
            }
            next_globals.extend(bindings);
            result.push(GoFileFlow {
                path: (*path).to_string(),
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
            break;
        }
        seeds = next;
        globals = next_globals;
        if round == MAX_ROUNDS - 1 {
            truncated = true;
        }
    }
    GoPackageFlow {
        files: result,
        truncated,
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

impl<'s> Analysis<'s> {
    fn text(&self, node: Node<'_>) -> &'s str {
        text(node, self.source)
    }

    fn canonical(&self, name: &str) -> String {
        let end = name.find([':', '.']).unwrap_or(name.len());
        match self.aliases.get(&name[..end]).filter(|s| !s.is_empty()) {
            Some(prefix) => format!("{prefix}{}", &name[end..]),
            None => name.to_string(),
        }
    }

    fn bind(&self, pattern: Node<'_>, bits: Bits, bindings: &mut Bindings<'_>) {
        let mut stack = vec![pattern];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                bindings.insert(self.text(node).to_string(), bits);
            } else if !matches!(node.kind(), "type_identifier" | "scoped_identifier") {
                stack.extend(named_children(node));
            }
        }
    }

    /// Whether `node` starts `x.len()` or another
    /// [`Model::metadata_methods`] call written as tokens, inside a macro's
    /// token tree.
    fn metadata_tokens(&self, node: Node<'_>) -> bool {
        node.kind() == "identifier"
            && node.next_sibling().is_some_and(|dot| {
                self.text(dot) == "."
                    && dot.next_sibling().is_some_and(|method| {
                        self.model.metadata_methods.contains(&self.text(method))
                            && method
                                .next_sibling()
                                .is_some_and(|args| self.text(args) == "()")
                    })
            })
    }

    fn eval(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        if self.budget == 0 || depth > MAX_FLOW_DEPTH {
            self.truncated = true;
            return 0;
        }
        self.budget -= 1;
        // Measured once: `Node::kind` measures and validates a C string.
        let kind = node.kind();
        if self.test_only.contains(&node.id())
            || self.config.is_function(node)
            || matches!(
                kind,
                "macro_definition" | "comment" | "line_comment" | "block_comment"
            )
        {
            return 0;
        }
        let text = self.text(node);
        if matches!(
            kind,
            "identifier" | "shorthand_field_identifier" | "shorthand_property_identifier"
        ) {
            return bindings.get(text).unwrap_or(0);
        }
        // Rust format! arguments are token trees rather than expression ASTs.
        // A metadata-only query consumes the source without returning its bytes.
        if self.language == Lang::Rust && kind == "token_tree" {
            let mut result = 0;
            for child in named_children(node) {
                if !self.metadata_tokens(child) {
                    result |= self.eval(child, bindings, out, depth + 1);
                }
            }
            return result;
        }
        if self.language == Lang::Rust && kind == "match_expression" {
            return self.match_expression(node, bindings, out, depth);
        }
        if kind == "macro_invocation"
            && node
                .child_by_field_name("macro")
                .is_some_and(|n| matches!(self.text(n), "format" | "format_args" | "std::format"))
        {
            return self.format_macro(node, bindings, out, depth);
        }
        if matches!(
            kind,
            "string"
                | "string_literal"
                | "raw_string_literal"
                | "interpreted_string_literal"
                | "string_fragment"
        ) {
            return path_bits(text);
        }
        if matches!(kind, "import_statement" | "import_from_statement") {
            if self.language == Lang::Python {
                python_imports(node, self.source, &mut self.aliases);
            }
            return 0;
        }
        if matches!(
            kind,
            "let_declaration"
                | "let_condition"
                | "assignment"
                | "assignment_expression"
                | "variable_declarator"
                | "const_item"
                | "static_item"
                | "short_var_declaration"
                | "assignment_statement"
                | "var_spec"
        ) {
            let value = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("right"));
            let target = node
                .child_by_field_name("pattern")
                .or_else(|| node.child_by_field_name("left"))
                .or_else(|| node.child_by_field_name("name"));
            if let (Some(target), Some(value)) = (target, value) {
                if self.language == Lang::Go && target.kind() == "selector_expression" {
                    // `req.Body = …` replaces a request's body.
                    if target
                        .child_by_field_name("field")
                        .is_some_and(|n| self.text(n) == "Body")
                    {
                        if let Some(receiver) = target.child_by_field_name("operand") {
                            let bits = self.eval(value, bindings, out, depth + 1);
                            let receiver = self.text(receiver);
                            if bindings
                                .get(receiver)
                                .is_some_and(|state| state & REQUEST != 0)
                            {
                                bindings.insert(receiver.to_string(), REQUEST | bits);
                            }
                        }
                    }
                    return 0;
                }
                let bits = self.eval(value, bindings, out, depth + 1);
                self.bind(target, bits, bindings);
                return 0;
            }
        }
        if matches!(
            kind,
            "for_expression" | "for_statement" | "for_in_statement" | "range_clause"
        ) {
            let iterable = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("right"));
            let pat = node
                .child_by_field_name("pattern")
                .or_else(|| node.child_by_field_name("left"));
            if let (Some(value), Some(pattern)) = (iterable, pat) {
                let bits = self.eval(value, bindings, out, depth + 1);
                self.bind(pattern, bits, bindings);
                if let Some(body) = node.child_by_field_name("body") {
                    self.eval(body, bindings, out, depth + 1);
                }
                return 0;
            }
        }
        if matches!(kind, "if_statement" | "if_expression") {
            return self.if_statement(node, bindings, out, depth);
        }
        if matches!(kind, "call_expression" | "call") {
            return self.call(node, bindings, out, depth + 1);
        }
        if kind == "return_statement" || kind == "return_expression" {
            let bits = self.all(node, bindings, out, depth + 1);
            out.returns |= bits;
            return bits;
        }
        if matches!(
            kind,
            "attribute"
                | "member_expression"
                | "subscript"
                | "subscript_expression"
                | "selector_expression"
        ) {
            if let Some(bits) = self.member(node, bindings, out, depth) {
                return bits;
            }
        }
        if self.language == Lang::Go
            && kind == "composite_literal"
            && node.child_by_field_name("type").is_some_and(|n| {
                self.model
                    .client_types
                    .contains(&self.canonical(self.text(n)).as_str())
            })
        {
            return CLIENT;
        }
        if matches!(
            kind,
            "block" | "statement_block" | "source_file" | "module" | "program"
        ) {
            return self.block(node, bindings, out, depth);
        }
        self.all(node, bindings, out, depth + 1)
    }

    fn match_expression(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let input = node
            .child_by_field_name("value")
            .map_or(0, |value| self.eval(value, bindings, out, depth + 1));
        let mut result = 0;
        let mut merged: BTreeMap<String, Bits> = BTreeMap::new();
        if let Some(body) = node.child_by_field_name("body") {
            for arm in named_children(body).filter(|n| n.kind() == "match_arm") {
                let mut branch = Bindings::under(bindings);
                let mut pattern_names = Bindings::default();
                if let Some(pattern) = arm.child_by_field_name("pattern") {
                    self.bind(pattern, input, &mut branch);
                    self.bind(pattern, 0, &mut pattern_names);
                }
                if let Some(value) = arm.child_by_field_name("value") {
                    result |= self.eval(value, &mut branch, out, depth + 1);
                }
                // Arm-local pattern bindings never escape the match.
                for (name, bits) in branch.bound() {
                    if pattern_names.get(name).is_none() {
                        *merged.entry(name.clone()).or_default() |= bits;
                    }
                }
            }
        }
        for (name, bits) in merged {
            add_bits(bindings, &name, bits);
        }
        result
    }

    /// `format!` and friends: the arguments, plus every binding named inline
    /// in a format string (`"{token}"`).
    fn format_macro(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let mut bits = self.all(node, bindings, out, depth + 1);
        let mut stack: Vec<_> = named_children(node).collect();
        while let Some(child) = stack.pop() {
            if child.kind() != "string_literal" {
                stack.extend(named_children(child));
                continue;
            }
            let literal = self.text(child);
            let bytes = literal.as_bytes();
            let mut index = 0;
            while let Some(&byte) = bytes.get(index) {
                if byte == b'{' {
                    if bytes.get(index + 1) == Some(&b'{') {
                        index += 2;
                        continue;
                    }
                    let start = index + 1;
                    let mut end = start;
                    while bytes
                        .get(end)
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    {
                        end += 1;
                    }
                    if end > start && matches!(bytes.get(end), Some(b'}' | b':')) {
                        bits |= literal
                            .get(start..end)
                            .and_then(|name| bindings.get(name))
                            .unwrap_or(0);
                    }
                }
                index += 1;
            }
        }
        bits
    }

    fn if_statement(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let condition = node.child_by_field_name("condition");
        // Reachability is enforced only for the module-execution fact.
        if self.language.is_ecmascript()
            && condition.is_some_and(|n| self.text(n).trim_matches(['(', ')', ' ']) == "false")
        {
            return 0;
        }
        if let Some(condition) = condition {
            self.eval(condition, bindings, out, depth + 1);
        }
        // What the branches bind, unioned into the bindings before the `if`.
        // A name a branch leaves alone keeps its bits there, so only the
        // branch's own layer can add any.
        let mut merged: BTreeMap<String, Bits> = BTreeMap::new();
        let mut result = 0;
        for field in ["consequence", "alternative"] {
            if let Some(branch) = node.child_by_field_name(field) {
                let mut branch_bindings = Bindings::under(bindings);
                result |= self.eval(branch, &mut branch_bindings, out, depth + 1);
                for (name, bits) in branch_bindings.bound() {
                    *merged.entry(name.clone()).or_default() |= bits;
                }
            }
        }
        for (name, bits) in merged {
            add_bits(bindings, &name, bits);
        }
        result
    }

    /// A member or subscript read, or `None` to evaluate it as an ordinary
    /// expression.
    fn member(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Option<Bits> {
        let text = self.text(node);
        let canonical = self.canonical(text);
        if self.model.client_members.contains(&canonical.as_str()) {
            return Some(CLIENT);
        }
        if self.model.environ_members.contains(&canonical.as_str()) {
            return Some(if self.language.is_ecmascript() {
                ENV_OBJECT
            } else {
                ENV | SECRET
            });
        }
        let selects_variable = self
            .model
            .env_var_members
            .iter()
            .any(|prefix| canonical.starts_with(prefix));
        if !self.language.is_ecmascript() {
            return selects_variable.then(|| env_bits(text));
        }
        let object = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("value"));
        let property = node
            .child_by_field_name("property")
            .or_else(|| node.child_by_field_name("field"));
        let object_bits = object.map(|object| self.eval(object, bindings, out, depth + 1));
        if object_bits.is_some_and(|bits| bits & ENV_OBJECT != 0) {
            if let Some(property) = property {
                return Some(env_bits(self.text(property)));
            }
            let index = node
                .child_by_field_name("index")
                .or_else(|| node.child_by_field_name("subscript"));
            if let Some(index) = index {
                let key = self.text(index).trim_matches(['\'', '"', '`']);
                if key != self.text(index) {
                    return Some(env_bits(key));
                }
            }
            // A dynamic key may select a credential, so retain the
            // conservative source classification.
            return Some(ENV | SECRET);
        }
        if selects_variable {
            return Some(env_bits(text));
        }
        // `object` is already evaluated; letting the fallback `all` evaluate
        // it again would double the work at every link of a member chain.
        Some(
            named_children(node)
                .filter(|child| Some(*child) != object)
                .fold(object_bits.unwrap_or(0), |bits, child| {
                    bits | self.eval(child, bindings, out, depth + 1)
                }),
        )
    }

    fn block(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let mut tail = 0;
        let scoped = matches!(
            self.language,
            Lang::Rust | Lang::JavaScript | Lang::TypeScript
        ) && matches!(node.kind(), "block" | "statement_block");
        // The names the block declares are restored after it. Only theirs
        // are saved: copying every binding per block is quadratic.
        let mut declared = Bindings::default();
        if scoped {
            for child in named_children(node) {
                if child.kind() == "let_declaration" {
                    if let Some(pattern) = child.child_by_field_name("pattern") {
                        self.bind(pattern, 0, &mut declared);
                    }
                }
                if child.kind() == "lexical_declaration" {
                    for declaration in named_children(child) {
                        if let Some(name) = declaration.child_by_field_name("name") {
                            self.bind(name, 0, &mut declared);
                        }
                    }
                }
            }
        }
        let before: Vec<(String, Option<Bits>)> = declared
            .into_names()
            .map(|name| {
                let old = bindings.get(&name);
                (name, old)
            })
            .collect();
        for child in named_children(node) {
            tail = self.eval(child, bindings, out, depth + 1);
        }
        for (name, old) in before {
            if let Some(old) = old {
                bindings.insert(name, old);
            } else {
                bindings.remove(&name);
            }
        }
        tail
    }

    fn all(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        named_children(node).fold(0, |bits, n| bits | self.eval(n, bindings, out, depth + 1))
    }

    fn call(
        &mut self,
        node: Node<'_>,
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let model = self.model;
        let Some(mut callee) = node.child_by_field_name("function") else {
            return 0;
        };
        while callee.kind() == "generic_function" {
            let Some(function) = callee.child_by_field_name("function") else {
                break;
            };
            callee = function;
        }
        let raw = self.text(callee);
        let prefix = raw.split([':', '.']).next().unwrap_or(raw);
        let name = if bindings.get(prefix).is_some() {
            raw.to_string()
        } else {
            self.canonical(raw)
        };
        let receiver = callee
            .child_by_field_name("value")
            .or_else(|| callee.child_by_field_name("object"))
            .or_else(|| callee.child_by_field_name("operand"));
        let recv = receiver.map_or(0, |n| self.eval(n, bindings, out, depth + 1));
        let method = callee
            .child_by_field_name("field")
            .or_else(|| callee.child_by_field_name("attribute"))
            .or_else(|| callee.child_by_field_name("property"))
            .map(|n| self.text(n))
            .unwrap_or_else(|| name.rsplit("::").next().unwrap_or(&name));
        let args = node
            .child_by_field_name("arguments")
            .map(|args| named_children(args).collect::<Vec<_>>())
            .unwrap_or_default();
        let bits: Vec<Bits> = args
            .iter()
            .map(|&n| self.eval(n, bindings, out, depth + 1))
            .collect();
        let all = bits.iter().fold(0, |a, b| a | b);
        let is = |names: &[&str]| names.contains(&name.as_str());
        if receiver.is_some() && args.is_empty() && model.metadata_methods.contains(&method) {
            return 0;
        }
        if is(model.process_calls)
            && args
                .first()
                .is_some_and(|n| self.text(*n).trim_matches('"') == "curl")
        {
            return CURL_COMMAND;
        }
        if recv & CURL_COMMAND != 0 {
            return self.curl_arguments(recv, method, &args, bindings, out, depth);
        }
        if is(model.environ_calls) {
            return ENV | SECRET;
        }
        if is(model.env_var_calls) {
            let bits = args.first().map_or(0, |n| env_bits(self.text(*n))) | ENV_VALUE;
            out.reads |= bits;
            return bits;
        }
        if is(model.request_calls) {
            return REQUEST | bits.last().copied().unwrap_or(0);
        }
        if is(model.client_calls) {
            return CLIENT;
        }
        let on_client = recv & CLIENT != 0
            || model
                .client_modules
                .iter()
                .any(|module| name.starts_with(module));
        let sent = model.sends.iter().find(|send| {
            if send.on_client {
                on_client && method == send.name
            } else {
                name == send.name
            }
        });
        if let Some(send) = sent {
            out.http = true;
            match send.body {
                Body::None => {}
                Body::Arg(index) => {
                    out.body |= bits.get(index).copied().unwrap_or(0);
                    return 0;
                }
                Body::Request => {
                    out.body |= bits.first().copied().unwrap_or(0) & !REQUEST;
                    return 0;
                }
                Body::Keywords => {
                    for (index, (arg, arg_bits)) in args.iter().zip(&bits).enumerate() {
                        let body = if arg.kind() == "keyword_argument" {
                            arg.child_by_field_name("name")
                                .is_some_and(|n| model.keyword_bodies.contains(&self.text(n)))
                        } else {
                            index == 1
                        };
                        if body {
                            out.body |= arg_bits;
                        }
                    }
                }
                Body::Options => {
                    if let Some(options) = args.get(1) {
                        for pair in named_children(*options) {
                            if pair
                                .child_by_field_name("key")
                                .is_some_and(|n| self.text(n).trim_matches(['\'', '"']) == "body")
                            {
                                if let Some(value) = pair.child_by_field_name("value") {
                                    out.body |= self.eval(value, bindings, out, depth + 1);
                                }
                            }
                        }
                    }
                }
            }
        }
        if model.auth_methods.contains(&method)
            || model
                .header_selectors
                .iter()
                .any(|selector| raw.contains(selector))
        {
            return 0;
        }
        if (recv & REQUEST != 0 && model.body_methods.contains(&method))
            || (recv & CLIENT != 0 && model.client_body_methods.contains(&method))
        {
            out.body |= all;
        }
        let read_method = model.file_read_methods.contains(&method);
        if is(model.file_read_calls) || read_method {
            let path = all | recv;
            let bits = (path & PARAM_BITS) | FILE | credential_bits(path);
            out.reads |= bits;
            if receiver.is_some() && read_method {
                if let Some(buffer) = args.first() {
                    self.bind(*buffer, bits, bindings);
                }
            }
            return bits;
        }
        if is(model.file_write_calls) {
            out.write_path |= bits.first().copied().unwrap_or(0);
            return 0;
        }
        if model.append_methods.contains(&method) {
            if let Some(receiver) = receiver {
                add_bits(bindings, self.text(receiver), all);
                return 0;
            }
        }
        if let Some(summary) = self.summaries.get(&name).cloned() {
            out.body |= substitute(summary.body, &bits);
            out.write_path |= substitute(summary.write_path, &bits);
            out.http |= summary.http;
            out.reads |= substitute(summary.reads, &bits);
            return substitute(summary.returns, &bits);
        }
        if sent.is_some() && model.sends_return_builders {
            return REQUEST;
        }
        // An immediately invoked closure executes its body; an uncalled or
        // exported closure was skipped by eval above.
        let mut closure = callee;
        while closure.kind() == "parenthesized_expression" {
            let Some(child) = closure.named_child(0) else {
                break;
            };
            closure = child;
        }
        if self.config.is_function(closure) {
            if let Some(body) = closure.child_by_field_name("body") {
                return self.eval(body, bindings, out, depth + 1);
            }
        }
        // Authentication never taints a builder's body. A body operation also
        // does not turn response bytes into the originally submitted secret.
        if recv & (CLIENT | REQUEST) != 0 {
            return recv & (CLIENT | REQUEST);
        }
        let mut result = recv | all;
        if result & CARGOHOME != 0 && result & CREDFILENAME != 0 {
            result |= CARGOPATH | SECRETPATH;
        }
        result
    }

    /// `.arg(…)`/`.args(…)` on a `curl` command: the value after a data flag
    /// is the request body.
    fn curl_arguments(
        &mut self,
        recv: Bits,
        method: &str,
        args: &[Node<'_>],
        bindings: &mut Bindings<'_>,
        out: &mut Summary,
        depth: usize,
    ) -> Bits {
        let mut state = recv;
        let command_args = if method == "args" {
            args.first()
                .map(|n| {
                    let mut n = *n;
                    while n.kind() == "reference_expression" {
                        let Some(child) = n.named_child(0) else { break };
                        n = child;
                    }
                    named_children(n).collect()
                })
                .unwrap_or_default()
        } else {
            args.to_vec()
        };
        if matches!(method, "arg" | "args") {
            for arg in command_args {
                if state & CURL_DATA_NEXT != 0 {
                    out.body |= self.eval(arg, bindings, out, depth + 1);
                    out.http = true;
                    state &= !CURL_DATA_NEXT;
                } else if matches!(
                    self.text(arg).trim_matches('"'),
                    "-d" | "--data" | "--data-raw" | "--data-binary" | "--json" | "-F" | "--form"
                ) {
                    state |= CURL_DATA_NEXT;
                }
            }
        }
        state
    }
}

/// The credential bits a file read of `path` adds.
fn credential_bits(path: Bits) -> Bits {
    let mut bits = 0;
    if path & SECRETPATH != 0 {
        bits |= CREDFILE | SECRET;
    }
    if path & CARGOPATH != 0 {
        bits |= CARGO | CREDFILE | SECRET;
    }
    bits
}

/// The path bits a string literal's text carries.
fn path_bits(text: &str) -> Bits {
    let mut bits = 0;
    if CARGO_CREDENTIAL_PATHS.iter().any(|p| text.contains(p)) {
        bits |= CARGOPATH | SECRETPATH;
    }
    if SECRET_PATHS.iter().any(|p| text.contains(p)) {
        bits |= SECRETPATH;
    }
    if text.contains("authorized_keys") {
        bits |= AUTHPATH;
    }
    if CARGO_CREDENTIAL_NAMES.contains(&text.trim_matches(['\'', '"'])) {
        bits |= CREDFILENAME;
    }
    bits
}

fn substitute(value: Bits, args: &[Bits]) -> Bits {
    let mut result = value & !PARAM_BITS;
    for index in 0..PARAM_COUNT {
        if value & (1 << (PARAM_START + index)) != 0 {
            result |= args.get(index).copied().unwrap_or(0);
        }
    }
    if result & FILE != 0 {
        result |= credential_bits(result);
    }
    result
}

fn env_bits(name: &str) -> Bits {
    if name.contains("CARGO_REGISTRY_TOKEN")
        || name.contains("CARGO_REGISTRIES_") && name.contains("_TOKEN")
    {
        CARGO | SECRET
    } else if name.contains("CARGO_HOME") {
        CARGOHOME
    } else if SECRET_VARIABLES.iter().any(|s| name.contains(s)) {
        SECRET
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
