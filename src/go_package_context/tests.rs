use super::*;
use std::collections::BTreeSet;

fn file<'a>(path: &'a str, source: &'a str) -> SourceFile<'a> {
    SourceFile { path, source }
}

fn context(members: &[SourceFile<'_>]) -> GoSourceContext {
    go_source_context(members, Coverage::Complete, &ContextLimits::default(), None)
}

/// Every port of `goos`, as [`GoPackage::platforms`] spells them.
fn ports(goos: &[&str]) -> Vec<String> {
    PLATFORMS
        .iter()
        .filter(|p| goos.contains(&p.goos))
        .map(|p| format!("{}/{}", p.goos, p.goarch))
        .collect()
}

#[test]
fn members_of_different_directories_never_share_a_package() {
    let source = "package main\nfunc main(){}\n";
    let context = context(&[file("x/a/main.go", source), file("x/b/main.go", source)]);
    let directories: BTreeSet<_> = context
        .packages
        .iter()
        .map(|p| p.directory.as_str())
        .collect();
    assert_eq!(directories, BTreeSet::from(["x/a", "x/b"]));
    assert!(!context.truncated);
}

/// Incomplete input, exhausted budgets and cancellation all mark the result
/// truncated.
#[test]
fn incomplete_input_budgets_and_cancellation_truncate() {
    let members = [file("p/a.go", "package one\nfunc A(){}\n")];
    let limits = ContextLimits::default();
    assert!(!go_source_context(&members, Coverage::Complete, &limits, None).truncated);
    assert!(go_source_context(&members, Coverage::Incomplete, &limits, None).truncated);
    let mut tight = limits;
    tight.max_go_members = 0;
    let result = go_source_context(&members, Coverage::Complete, &tight, None);
    assert!(result.truncated && result.packages.is_empty());
    let mut tight = limits;
    tight.max_go_packages = 0;
    assert!(go_source_context(&members, Coverage::Complete, &tight, None).truncated);
    let cancelled = AtomicBool::new(true);
    let result = go_source_context(&members, Coverage::Complete, &limits, Some(&cancelled));
    assert!(result.truncated);
}

/// Members are grouped by the package clause read from each file's syntax
/// tree, then split by the platforms that build them; a non-Go member is
/// not grouped at all.
#[test]
fn members_group_by_package_clause_and_platform() {
    let context = context(&[
        file("p/a.go", "package one\nfunc A(){}\n"),
        file("p/b.go", "package two\nfunc B(){}\n"),
        file("p/c_linux.go", "package one\nfunc C(){}\n"),
        file("p/README.md", "package one\n"),
    ]);
    let packages: BTreeSet<_> = context
        .packages
        .iter()
        .map(|p| {
            assert_eq!(p.phase, Phase::Runtime);
            (p.package.as_str(), p.platforms.clone(), p.members.join(","))
        })
        .collect();
    let linux = ports(&["android", "linux"]);
    let others: Vec<String> = PLATFORMS
        .iter()
        .map(|p| format!("{}/{}", p.goos, p.goarch))
        .filter(|p| !linux.contains(p))
        .collect();
    assert_eq!(
        packages,
        BTreeSet::from([
            ("one", others, "p/a.go".to_string()),
            ("one", linux, "p/a.go,p/c_linux.go".to_string()),
            ("two", Vec::new(), "p/b.go".to_string()),
        ])
    );
    let json = serde_json::to_value(&context).unwrap();
    assert_eq!(json["packages"][0]["phase"], "runtime");
    assert!(json["packages"][0].get("behaviors").is_none());
}

/// A `//go:build` line selects platforms only in the leading comment block,
/// a custom tag leaves a member unselected, and `_test.go` members form the
/// test phase.
#[test]
fn build_constraints_select_members_as_go_build_does() {
    let context = context(&[
        file("p/a.go", "package p\n"),
        file("p/unix.go", "//go:build unix && !cgo\n\npackage p\n"),
        file("p/late.go", "package p\n\n//go:build ignore\n"),
        file("p/gen.go", "//go:build ignore\n\npackage main\n"),
        file("p/bad.go", "//go:build (linux\n\npackage p\n"),
        file("p/a_test.go", "package p\n"),
        file("p/_skip.go", "package p\n"),
    ]);
    assert_eq!(context.unselected, ["p/gen.go", "p/bad.go"]);
    let runtime: Vec<_> = context
        .packages
        .iter()
        .filter(|p| p.phase == Phase::Runtime)
        .collect();
    // Only unix ports without cgo by default build `unix.go`.
    let unix_no_cgo: Vec<String> = PLATFORMS
        .iter()
        .filter(|p| !p.cgo && constraint::Platform::has_tag(p, "unix"))
        .map(|p| format!("{}/{}", p.goos, p.goarch))
        .collect();
    assert_eq!(unix_no_cgo, ["linux/ppc64", "openbsd/ppc64"]);
    let with_unix = runtime
        .iter()
        .find(|p| p.members.iter().any(|m| m == "p/unix.go"))
        .expect("unix variant");
    assert_eq!(with_unix.platforms, unix_no_cgo);
    assert_eq!(with_unix.members, ["p/a.go", "p/unix.go", "p/late.go"]);
    let test = context
        .packages
        .iter()
        .filter(|p| p.phase == Phase::Test)
        .count();
    assert_eq!(test, 2, "{context:?}");
    assert!(
        context
            .packages
            .iter()
            .all(|p| !p.members.iter().any(|m| m == "p/_skip.go"))
    );
}

/// Each member is parsed once however many variants include it, every
/// variant's payload flow is reported, and all of them share one step
/// budget.
#[test]
fn members_are_parsed_once_and_flow_shares_one_budget() {
    let members = [
        file(
            "p/a.go",
            "package p\nimport \"net/http\"\nfunc send(d string){http.Post(u,\"t\",d)}\n",
        ),
        file(
            "p/b.go",
            "package p\nimport \"os\"\nfunc init(){send(os.Getenv(\"GITHUB_TOKEN\"))}\n",
        ),
        file("p/c_linux.go", "package p\nfunc L(){}\n"),
        file("p/c_windows.go", "package p\nfunc W(){}\n"),
        file("p/c_darwin.go", "package p\nfunc D(){}\n"),
        file("p/a_test.go", "package p\nfunc T(){}\n"),
    ];
    let parses = crate::formats::source::parse::PARSES.get();
    let result = context(&members);
    assert_eq!(
        crate::formats::source::parse::PARSES.get() - parses,
        members.len()
    );
    assert!(result.packages.len() > 4, "{:?}", result.packages);
    assert!(!result.truncated);
    for package in &result.packages {
        assert_eq!(
            package
                .files
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            package.members
        );
        let b = package.files.iter().find(|f| f.path == "p/b.go").unwrap();
        assert_eq!(
            b.facts.get("source.go.initialization_http"),
            Some(&serde_json::json!(true)),
            "{package:?}"
        );
    }
    let mut tight = ContextLimits::default();
    tight.max_flow_steps = 50;
    let result = go_source_context(&members, Coverage::Complete, &tight, None);
    assert!(result.truncated);
    assert!(result.packages.iter().all(|p| p.truncated));
}

/// Each `// +build` line is one more condition the file must meet, and a
/// member under the size budget can hold a couple of hundred thousand of
/// them. Evaluating and dropping the combined constraint must not recurse
/// once per line.
#[test]
fn many_plus_build_lines_do_not_overflow_the_stack() {
    let lines = 130_000;
    let source = format!(
        "{}\npackage p\nfunc F(){{}}\n",
        "//+build linux\n".repeat(lines)
    );
    assert!(source.len() <= ContextLimits::default().max_go_member_bytes);
    let context = context(&[file("p/a.go", &source)]);
    assert!(context.unselected.is_empty());
    let [package] = context.packages.as_slice() else {
        panic!("one package variant expected: {:?}", context.packages);
    };
    assert_eq!(package.members, ["p/a.go"]);
    assert_eq!(package.platforms, ports(&["linux", "android"]));
}
