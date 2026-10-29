use super::*;

fn run_with(files: &[(&str, &str)], limits: &ContextLimits) -> BTreeMap<String, Vec<Reference>> {
    let owned: Vec<_> = files
        .iter()
        .map(|(path, content)| {
            let parsed = crate::OpenOptions::new()
                .path(std::path::Path::new(path))
                .open(content.as_bytes());
            ((*path).to_string(), parsed.references().to_vec())
        })
        .collect();
    go_dependency_context(
        &owned
            .iter()
            .map(|(path, refs)| ReferenceMember {
                path,
                references: refs,
            })
            .collect::<Vec<_>>(),
        limits,
    )
}

fn run(files: &[(&str, &str)]) -> BTreeMap<String, Vec<Reference>> {
    run_with(files, &ContextLimits::default())
}

fn unresolved_reason(reference: &Reference) -> Option<UnresolvedReason> {
    match reference.resolution {
        Some(Resolution::Unresolved(reason)) => Some(reason),
        _ => None,
    }
}

#[test]
fn named_matches_only_the_final_component() {
    for (path, expected) in [
        ("go.mod", true),
        ("pkg/go.mod", true),
        ("pkg/notgo.mod", false),
        ("go.mod.bak", false),
        ("x/a.zip!go.mod", false),
    ] {
        assert_eq!(named(path, "go.mod"), expected, "{path}");
    }
}

#[test]
fn replacement_uses_exact_checksum_not_history_or_nested_directives() {
    let facts = run(&[
        (
            "app/go.mod",
            "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => example.test/fork v2.0.0\n",
        ),
        (
            "app/go.sum",
            "example.test/fork v2.0.0 h1:EXACT\nexample.test/fork v2.0.0/go.mod h1:METADATA\nexample.test/lib v9.0.0 h1:HISTORY\n",
        ),
        (
            "app/nested/go.mod",
            "module nested\nreplace example.test/lib => example.test/unrelated v3.0.0\n",
        ),
    ]);
    let dependency = facts["app/go.mod"]
        .iter()
        .find(|r| r.kind == RefKind::Dependency)
        .unwrap();
    assert_eq!(
        dependency.locator,
        RefLocator::Purl("pkg:golang/example.test/fork@v2.0.0".into())
    );
    assert_eq!(dependency.pinned_hash.as_ref().unwrap().value, "EXACT");
    assert_eq!(dependency.resolution, Some(Resolution::Replaced));
    assert_eq!(dependency.source, source::MOD_REPLACE);
    assert_eq!(
        facts["app/go.mod"]
            .iter()
            .filter(|r| r.kind == RefKind::Dependency)
            .count(),
        1
    );
}

#[test]
fn an_unreplaced_requirement_is_the_declared_minimum() {
    let facts = run(&[("go.mod", "module app\nrequire example.test/lib v1.0.0\n")]);
    let [dependency] = facts["go.mod"].as_slice() else {
        panic!("{facts:?}");
    };
    assert_eq!(dependency.resolution, Some(Resolution::DeclaredMinimum));
    assert_eq!(dependency.source, source::MOD);
    assert!(dependency.is_fetch_target());
}

#[test]
fn workspace_override_requires_explicit_ownership() {
    let facts = run(&[
        (
            "go.work",
            "go 1.25\nuse ./app\nreplace example.test/lib => example.test/work v3.0.0\n",
        ),
        (
            "app/go.mod",
            "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => example.test/local v2.0.0\n",
        ),
        (
            "other/go.mod",
            "module other\nrequire example.test/lib v1.0.0\n",
        ),
        (
            "unrelated/go.work",
            "use ./app\nreplace example.test/lib => example.test/unrelated v4.0.0\n",
        ),
    ]);
    assert_eq!(
        facts["app/go.mod"][0].locator,
        RefLocator::Purl("pkg:golang/example.test/work@v3.0.0".into())
    );
    assert_eq!(
        facts["other/go.mod"][0].locator,
        RefLocator::Purl("pkg:golang/example.test/lib@v1.0.0".into())
    );
}

#[test]
fn quoted_local_replacement_stays_inside_supplied_artifact() {
    let facts = run(&[
        (
            "app/go.mod",
            "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => \"../replacement folder\"\n",
        ),
        ("replacement folder/go.mod", "module example.test/lib\n"),
    ]);
    assert_eq!(facts["app/go.mod"][0].kind, RefKind::Local);
    assert_eq!(
        facts["app/go.mod"][0].resolution,
        Some(Resolution::Replaced)
    );
    for (path, reason) in [
        ("../../escape", UnresolvedReason::LocalBoundary),
        ("/etc", UnresolvedReason::LocalBoundary),
        ("../sibling", UnresolvedReason::LocalMissing),
    ] {
        let source = format!(
            "module app\nrequire example.test/lib v1.0.0\nreplace example.test/lib => {path}\n"
        );
        let facts = run(&[("app/go.mod", &source)]);
        let reference = &facts["app/go.mod"][0];
        assert_eq!(unresolved_reason(reference), Some(reason), "{path}");
        assert_eq!(reference.kind, RefKind::Dependency, "{path}");
        assert!(!reference.is_fetch_target(), "{path}");
    }
}

#[test]
fn conflicts_exclusions_and_missing_local_modules_are_explicit() {
    for (extra, reason) in [
        (
            "exclude example.test/lib v1.0.0\n",
            UnresolvedReason::ExcludedMinimum,
        ),
        (
            "replace example.test/lib => ../missing\n",
            UnresolvedReason::LocalMissing,
        ),
        (
            "replace example.test/lib => example.test/a v2.0.0\nreplace example.test/lib => example.test/b v3.0.0\n",
            UnresolvedReason::ReplacementConflict,
        ),
    ] {
        let source = format!("module app\nrequire example.test/lib v1.0.0\n{extra}");
        let facts = run(&[("app/go.mod", &source)]);
        assert_eq!(
            unresolved_reason(&facts["app/go.mod"][0]),
            Some(reason),
            "{extra}"
        );
    }
    let facts = run(&[
        ("go.mod", "module app\nrequire example.test/lib v1.0.0\n"),
        (
            "go.sum",
            "example.test/lib v1.0.0 h1:ONE\nexample.test/lib v1.0.0 h1:TWO\n",
        ),
    ]);
    assert_eq!(
        unresolved_reason(&facts["go.mod"][0]),
        Some(UnresolvedReason::ChecksumConflict)
    );
    assert_eq!(facts["go.mod"][0].source, source::MOD);
}

#[test]
fn vendored_sources_are_not_refetched_from_the_registry() {
    let files = [
        ("go.mod", "module app\nrequire example.test/lib v1.0.0\n"),
        (
            "vendor/modules.txt",
            "# example.test/lib v1.0.0\n## explicit\nexample.test/lib\n",
        ),
        ("vendor/example.test/lib/lib.go", "package lib\n"),
    ];
    let facts = run(&files);
    let vendored = &facts["go.mod"][0];
    assert_eq!(vendored.kind, RefKind::Local);
    assert_eq!(vendored.resolution, Some(Resolution::Vendored));
    assert_eq!(vendored.source, source::VENDOR_MODULE);
    assert_eq!(
        vendored.locator,
        RefLocator::Path("vendor/example.test/lib".into())
    );
    // A listed module whose directory is absent is not silently local.
    let facts = run(&files[..2]);
    assert_eq!(
        unresolved_reason(&facts["go.mod"][0]),
        Some(UnresolvedReason::VendorMissing)
    );
}

/// Every budget lives in [`ContextLimits`]; exhausting one leaves the
/// module's references unresolved rather than silently resolved.
#[test]
fn budgets_come_from_context_limits() {
    let files = [("go.mod", "module app\nrequire example.test/lib v1.0.0\n")];
    let defaults = ContextLimits::default();
    assert_eq!(
        run_with(&files, &defaults)["go.mod"][0].resolution,
        Some(Resolution::DeclaredMinimum)
    );
    for limits in [
        ContextLimits {
            max_reference_members: 0,
            ..defaults
        },
        ContextLimits {
            max_references: 0,
            ..defaults
        },
        ContextLimits {
            max_reference_work: 0,
            ..defaults
        },
    ] {
        assert_eq!(
            unresolved_reason(&run_with(&files, &limits)["go.mod"][0]),
            Some(UnresolvedReason::ContextBudget),
            "{limits:?}"
        );
    }
}
