use super::*;
use serde_json::json;

fn values(json: Value) -> Values {
    Values::from_json(json)
}

#[test]
fn cargo_context_respects_declared_graph_and_disabled_build() {
    let mut manifest = json!({"package": {"build": "bootstrap.rs"}});
    let root = values(json!({"source": {"rust": {"modules": [{"name": "helper"}]}}}));
    let helper = values(json!({
        "source": {"payload_flow": {"events": [{"kind": "file-http-body"}]}}
    }));
    let unrelated = values(json!({
        "source": {"payload_flow": {"events": [{"kind": "ssh-authorized-keys-write"}]}}
    }));
    let run = |manifest: &Values| {
        cargo_source_context(
            &[
                SourceMember {
                    path: "pkg/Cargo.toml",
                    values: manifest,
                },
                SourceMember {
                    path: "pkg/bootstrap.rs",
                    values: &root,
                },
                SourceMember {
                    path: "pkg/helper.rs",
                    values: &helper,
                },
                SourceMember {
                    path: "pkg/unrelated.rs",
                    values: &unrelated,
                },
            ],
            &ContextLimits::default(),
        )
    };
    let facts = run(&values(manifest.clone()));
    assert!(!facts.truncated);
    let [target] = facts.targets.as_slice() else {
        panic!("one target: {facts:?}");
    };
    assert_eq!(target.phase, Phase::Build);
    assert_eq!(
        target.events,
        BTreeSet::from(["file-http-body".to_string()])
    );
    let json = serde_json::to_value(&facts).unwrap();
    assert_eq!(json["targets"][0]["phase"], "build");
    assert_eq!(json["targets"][0]["entry"], "pkg/bootstrap.rs");
    assert!(json["targets"][0].get("behaviors").is_none());
    manifest["cargo"] = json!({"build_mode": "disabled"});
    assert!(run(&values(manifest)).targets.is_empty());
}

/// Modules resolve through inline module prefixes, `#[path]` overrides and
/// the non-root module directory rule; a proc-macro library is its own phase.
#[test]
fn cargo_context_follows_module_declarations() {
    let manifest = values(json!({"lib": {"proc-macro": true}}));
    let lib = values(json!({"source": {"rust": {"modules": [
        {"name": "a"},
        {"name": "b", "prefix": "inner/"},
        {"name": "c", "path": "elsewhere/c.rs"},
        {"name": "absent"}
    ]}}}));
    let a = values(json!({"source": {"rust": {"modules": [{"name": "nested"}]}}}));
    let empty = Values::new();
    let members = [
        ("Cargo.toml", &manifest),
        ("src/lib.rs", &lib),
        ("src/a.rs", &a),
        ("src/a/nested.rs", &empty),
        ("src/inner/b/mod.rs", &empty),
        ("src/elsewhere/c.rs", &empty),
    ]
    .map(|(path, values)| SourceMember { path, values });
    let facts = cargo_source_context(&members, &ContextLimits::default());
    let lib = facts
        .targets
        .iter()
        .find(|t| t.entry == "src/lib.rs")
        .expect("lib target");
    assert_eq!(lib.phase, Phase::ProcMacro);
    assert_eq!(
        lib.members,
        BTreeSet::from(
            [
                "src/lib.rs",
                "src/a.rs",
                "src/a/nested.rs",
                "src/inner/b/mod.rs",
                "src/elsewhere/c.rs"
            ]
            .map(String::from)
        )
    );
    assert_eq!(
        lib.unresolved_modules,
        BTreeSet::from(["src/lib.rs:mod absent".to_string()])
    );
}

/// An exhausted visit budget is reported, not silently clean.
#[test]
fn cargo_context_reports_an_exhausted_budget() {
    let manifest = Values::new();
    let lib = Values::new();
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
fn paths_do_not_escape_the_manifest_directory() {
    for path in ["../../outside.rs", "/etc/passwd", "C:/other.rs", "a\\b.rs"] {
        assert!(resolve("pkg/src/lib.rs", path, "pkg/").is_none(), "{path}");
    }
    assert_eq!(
        resolve("pkg/src/lib.rs", "../helper.rs", "pkg/"),
        Some("pkg/helper.rs".into())
    );
    // A file outside the boundary resolves nothing.
    assert!(resolve("other/src/lib.rs", "helper.rs", "pkg/").is_none());
}

/// Only `/` separates; every other character is part of a name.
#[test]
fn member_paths_split_only_on_slash() {
    assert_eq!(member_directory("pkg/a.go"), "pkg/");
    assert_eq!(member_directory("main.go"), "");
    assert_eq!(member_directory("x/a.zip!!main.go"), "x/");
    assert_eq!(join_relative("a/b", "../c/./d"), Some("a/c/d".into()));
    assert_eq!(join_relative("", "c"), Some("c".into()));
    assert_eq!(join_relative("a", "x!!y#z"), Some("a/x!!y#z".into()));
    for escaping in ["../../c", "/abs", "c:/d", "a\\b"] {
        assert_eq!(join_relative("a", escaping), None, "{escaping}");
    }
}
