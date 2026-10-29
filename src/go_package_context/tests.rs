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
