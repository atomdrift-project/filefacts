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

/// Declared `[[bin]]`, `[[example]]`, `[[test]]` and `[[bench]]` targets
/// resolve, and so do the ones Cargo discovers in `src/bin`, `examples`,
/// `tests` and `benches` unless the manifest turns discovery off.
#[test]
fn cargo_binary_example_test_and_bench_targets_resolve() {
    let empty = values(json!({}));
    let manifest = values(json!({
        "package": {"name": "pkg", "build": false},
        "bin": [
            {"name": "tool", "path": "tools/tool.rs"},
            {"name": "pkg"},
            {"name": "named"},
        ],
        "test": [{"name": "custom", "path": "checks/custom.rs"}],
    }));
    let paths = [
        "pkg/Cargo.toml",
        "pkg/src/main.rs",
        "pkg/tools/tool.rs",
        "pkg/src/bin/named.rs",
        "pkg/src/bin/auto.rs",
        "pkg/src/bin/multi/main.rs",
        "pkg/src/bin/multi/helper.rs",
        "pkg/examples/demo.rs",
        "pkg/tests/it.rs",
        "pkg/checks/custom.rs",
        "pkg/benches/speed/main.rs",
        "pkg/src/bin/nested/deeper/x.rs",
    ];
    let members: Vec<_> = paths
        .iter()
        .map(|&path| SourceMember {
            path,
            values: if path.ends_with("Cargo.toml") {
                &manifest
            } else {
                &empty
            },
        })
        .collect();
    let facts = cargo_source_context(&members, &ContextLimits::default());
    let targets: BTreeSet<_> = facts
        .targets
        .iter()
        .map(|t| (t.entry.as_str(), t.phase))
        .collect();
    assert_eq!(
        targets,
        BTreeSet::from([
            ("pkg/src/main.rs", Phase::Runtime),
            ("pkg/tools/tool.rs", Phase::Runtime),
            ("pkg/src/bin/named.rs", Phase::Runtime),
            ("pkg/src/bin/auto.rs", Phase::Runtime),
            ("pkg/src/bin/multi/main.rs", Phase::Runtime),
            ("pkg/examples/demo.rs", Phase::Runtime),
            ("pkg/tests/it.rs", Phase::Test),
            ("pkg/checks/custom.rs", Phase::Test),
            ("pkg/benches/speed/main.rs", Phase::Test),
        ])
    );

    let off = values(json!({
        "package": {"autobins": false, "autoexamples": false, "autotests": false, "autobenches": false},
    }));
    let members: Vec<_> = paths
        .iter()
        .map(|&path| SourceMember {
            path,
            values: if path.ends_with("Cargo.toml") {
                &off
            } else {
                &empty
            },
        })
        .collect();
    let entries: Vec<_> = cargo_source_context(&members, &ContextLimits::default())
        .targets
        .into_iter()
        .map(|t| t.entry)
        .collect();
    assert_eq!(entries, ["pkg/src/main.rs"]);
}

/// Members for `targets` binaries that all include one shared module file,
/// which declares `missing` modules no member provides and carries `events`
/// payload-flow events.
fn shared_module_crate(targets: usize, missing: usize, events: usize) -> Vec<(String, Values)> {
    let shared = values(json!({"source": {
        "rust": {"modules": (0..missing).map(|i| json!({"name": format!("m{i}")})).collect::<Vec<_>>()},
        "payload_flow": {"events": (0..events)
            .map(|i| json!({"kind": "file-http-body", "function": format!("f{i}")}))
            .collect::<Vec<_>>()},
    }}));
    let bin = values(
        json!({"source": {"rust": {"modules": [{"name": "shared", "path": "../shared.rs"}]}}}),
    );
    let mut members = vec![
        ("Cargo.toml".to_string(), values(json!({}))),
        ("src/shared.rs".to_string(), shared),
    ];
    members.extend((0..targets).map(|i| (format!("src/bin/b{i}.rs"), bin.clone())));
    members
}

fn cargo_context(members: &[(String, Values)], limits: &ContextLimits) -> CargoSourceContext {
    let members: Vec<_> = members
        .iter()
        .map(|(path, values)| SourceMember { path, values })
        .collect();
    cargo_source_context(&members, limits)
}

/// Every target that reaches a module file reports that file's unresolved
/// declarations, so they count against the visit budget like the files
/// themselves: otherwise a few hundred small members could each list every
/// declaration of one large file.
#[test]
fn unresolved_modules_count_against_the_visit_budget() {
    let mut limits = ContextLimits::default();
    limits.max_cargo_visits = 1_000;
    let context = cargo_context(&shared_module_crate(200, 1_000, 0), &limits);
    assert!(context.truncated);
    let listed: usize = context
        .targets
        .iter()
        .map(|t| t.unresolved_modules.len())
        .sum();
    assert!(
        listed <= limits.max_cargo_visits,
        "{listed} unresolved modules listed"
    );

    // Within the budget every declaration is still listed.
    let context = cargo_context(&shared_module_crate(2, 10, 0), &limits);
    assert!(!context.truncated);
    for target in &context.targets {
        assert_eq!(target.unresolved_modules.len(), 10, "{}", target.entry);
    }
}

/// A module file's payload-flow events are read once per call, not once per
/// target that reaches it.
#[test]
fn shared_module_events_are_read_once() {
    let members = shared_module_crate(200, 0, 1_000);
    EVENT_READS.set(0);
    let context = cargo_context(&members, &ContextLimits::default());
    assert!(!context.truncated);
    assert_eq!(context.targets.len(), 200);
    for target in &context.targets {
        assert_eq!(
            target.events,
            BTreeSet::from(["file-http-body".to_string()])
        );
    }
    assert!(
        EVENT_READS.get() <= 2_000,
        "{} events read",
        EVENT_READS.get()
    );
}

/// Each manifest discovers its targets among the members under its own
/// directory, so an artifact of many small packages costs time linear in
/// its members, not their square.
#[test]
#[ignore = "wall-clock bound; run with --ignored"]
fn target_discovery_is_linear_in_members() {
    let empty = values(json!({}));
    let paths: Vec<String> = (0..30_000)
        .flat_map(|i| [format!("p{i}/Cargo.toml"), format!("p{i}/src/bin/b.rs")])
        .collect();
    let members: Vec<_> = paths
        .iter()
        .map(|path| SourceMember {
            path,
            values: &empty,
        })
        .collect();
    let started = std::time::Instant::now();
    let context = cargo_source_context(&members, &ContextLimits::default());
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(context.targets.len(), 30_000);
}

#[test]
fn unused_runtime_dependencies_counts_phantoms() {
    // An injected dependency the code never references.
    assert_eq!(
        unused_runtime_dependencies(["dayjs", "easy-day-js"], ["dayjs/plugin/utc", "./util"]),
        Some(1)
    );
    // Scoped and dotted names are whole names; a subpath counts as a use.
    assert_eq!(
        unused_runtime_dependencies(
            ["@scope/pkg", "lodash.merge"],
            ["@scope/pkg/sub", "lodash.merge"]
        ),
        Some(0)
    );
    // A prefix is not a use: `react-dom` does not use `react`.
    assert_eq!(
        unused_runtime_dependencies(["react"], ["react-dom"]),
        Some(1)
    );
}

#[test]
fn unused_runtime_dependencies_abstains_without_both_sides() {
    assert_eq!(unused_runtime_dependencies([], ["x"]), None);
    // No imports observed: unused cannot be told from unparsed.
    assert_eq!(unused_runtime_dependencies(["x"], []), None);
}
