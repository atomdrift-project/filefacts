//! Each analysed language's library knowledge: what reads the environment
//! or a file, what builds and sends an HTTP request, and where its body goes.

use crate::formats::source::langs::Lang;

/// How an HTTP send carries its body.
#[derive(Clone, Copy)]
pub(super) enum Body {
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
pub(super) struct Send {
    pub(super) name: &'static str,
    pub(super) on_client: bool,
    pub(super) body: Body,
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
pub(super) struct Model {
    /// Calls returning the whole environment.
    pub(super) environ_calls: &'static [&'static str],
    /// Member reads that are the whole environment.
    pub(super) environ_members: &'static [&'static str],
    /// Calls returning the one variable their first argument names.
    pub(super) env_var_calls: &'static [&'static str],
    /// Prefixes of member reads that select one variable (`os.environ[`).
    pub(super) env_var_members: &'static [&'static str],
    /// Calls constructing an HTTP client.
    pub(super) client_calls: &'static [&'static str],
    /// Member reads that are an HTTP client.
    pub(super) client_members: &'static [&'static str],
    /// Types whose parameters and composite literals are HTTP clients.
    pub(super) client_types: &'static [&'static str],
    /// Calls building a request whose body is their last argument.
    pub(super) request_calls: &'static [&'static str],
    pub(super) sends: &'static [Send],
    /// Modules whose functions are matched as client methods
    /// (`requests.post` as `post` on a client).
    pub(super) client_modules: &'static [&'static str],
    /// Whether a send without its body returns a request builder.
    pub(super) sends_return_builders: bool,
    /// Methods of a request builder whose arguments are the body.
    pub(super) body_methods: &'static [&'static str],
    /// Methods of a client whose arguments are the body.
    pub(super) client_body_methods: &'static [&'static str],
    /// Keyword arguments that carry a [`Body::Keywords`] body.
    pub(super) keyword_bodies: &'static [&'static str],
    /// Calls reading a file named by their arguments.
    pub(super) file_read_calls: &'static [&'static str],
    /// Methods reading a file; called on a reader, they fill the buffer
    /// passed as their first argument.
    pub(super) file_read_methods: &'static [&'static str],
    /// Calls writing a file whose path is their first argument.
    pub(super) file_write_calls: &'static [&'static str],
    /// Methods whose arguments join their receiver's contents.
    pub(super) append_methods: &'static [&'static str],
    /// Methods that read only metadata, none of their receiver's bytes.
    pub(super) metadata_methods: &'static [&'static str],
    /// Methods that set authentication, never body.
    pub(super) auth_methods: &'static [&'static str],
    /// Callee spellings whose calls set request headers, never body.
    pub(super) header_selectors: &'static [&'static str],
    /// Calls starting a process whose first argument is the program.
    pub(super) process_calls: &'static [&'static str],
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
pub(super) fn model(language: Lang) -> Option<&'static Model> {
    match language {
        Lang::Rust => Some(&RUST),
        Lang::Python => Some(&PYTHON),
        Lang::JavaScript | Lang::TypeScript => Some(&ECMASCRIPT),
        Lang::Go => Some(&GO),
        _ => None,
    }
}
