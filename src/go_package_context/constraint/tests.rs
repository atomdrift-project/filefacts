use super::*;

/// `shouldBuild` under a context whose only set tag is `yes`.
fn should_build(content: &str) -> Result<bool, ConstraintError> {
    Ok(file_constraint(content)?.is_none_or(|expr| expr.eval(&|tag: &str| tag == "yes")))
}

/// The cases of `TestShouldBuild` in `go/build/build_test.go`, under its
/// `BuildTags: ["yes"]` context.
#[test]
fn go_build_should_build_cases() {
    for (name, content, expected) in [
        ("Yes", "// +build yes\n\npackage main\n", true),
        ("Yes2", "//go:build yes\npackage main\n", true),
        ("Or", "// +build no yes\n\npackage main\n", true),
        ("Or2", "//go:build no || yes\npackage main\n", true),
        ("And", "// +build no,yes\n\npackage main\n", false),
        ("And2", "//go:build no && yes\npackage main\n", false),
        (
            "Cgo",
            "// +build cgo\n\n// Copyright The Go Authors.\n\n// This package implements parsing of tags like\n// +build tag1\npackage build",
            false,
        ),
        (
            "Cgo2",
            "//go:build cgo\n// Copyright The Go Authors.\n\n// This package implements parsing of tags like\n// +build tag1\npackage build",
            false,
        ),
        (
            "AfterPackage",
            "// Copyright The Go Authors.\n\npackage build\n\n// shouldBuild checks tags given by lines of the form\n// +build tag\n//go:build tag\nfunc shouldBuild(content []byte)\n",
            true,
        ),
        ("TooClose", "// +build yes\npackage main\n", true),
        ("TooClose2", "//go:build no\npackage main\n", false),
        ("TooCloseNo", "// +build no\npackage main\n", true),
        ("TooCloseNo2", "//go:build no\npackage main\n", false),
        (
            "BinaryOnly",
            "//go:binary-only-package\n// +build yes\n\npackage main\n",
            true,
        ),
        (
            "BinaryOnly2",
            "//go:binary-only-package\n//go:build no\npackage main\n",
            false,
        ),
        (
            "ValidGoBuild",
            "// +build yes\n\n//go:build no\npackage main\n",
            false,
        ),
        (
            "MissingBuild2",
            "/* */\n// +build yes\n\n//go:build no\npackage main\n",
            false,
        ),
        ("Comment1", "/*\n//go:build no\n*/\n\npackage main\n", true),
        (
            "Comment2",
            "/*\ntext\n*/\n\n//go:build no\npackage main\n",
            false,
        ),
        (
            "Comment3",
            "/*/*/ /* hi *//* \ntext\n*/\n\n//go:build no\npackage main\n",
            false,
        ),
        ("Comment4", "/**///go:build no\npackage main\n", true),
        ("Comment5", "/**/\n//go:build no\npackage main\n", false),
    ] {
        assert_eq!(should_build(content), Ok(expected), "{name}");
    }
}

/// A `//go:build` line only counts before the package clause, so one in a
/// function's doc comment constrains nothing.
#[test]
fn go_build_after_the_package_clause_is_ignored() {
    assert_eq!(
        file_constraint("package p\n\n//go:build ignore\nfunc f() {}\n"),
        Ok(None)
    );
}

#[test]
fn invalid_go_build_lines_are_errors() {
    for (content, expected) in [
        (
            "//go:build a\n//go:build b\npackage p\n",
            ConstraintError::MultipleGoBuild,
        ),
        (
            "//go:build\npackage p\n",
            ConstraintError::Syntax("unexpected end of expression"),
        ),
        (
            "//go:build !!a\npackage p\n",
            ConstraintError::Syntax("double negation not allowed"),
        ),
        (
            "//go:build (a\npackage p\n",
            ConstraintError::Syntax("missing close paren"),
        ),
        (
            "//go:build a & b\npackage p\n",
            ConstraintError::Syntax("invalid syntax"),
        ),
        (
            "//go:build a b\npackage p\n",
            ConstraintError::Syntax("unexpected token"),
        ),
    ] {
        assert_eq!(file_constraint(content), Err(expected), "{content}");
    }
    let deep = format!(
        "//go:build {}a{}\npackage p\n",
        "(".repeat(2000),
        ")".repeat(2000)
    );
    assert_eq!(
        file_constraint(&deep),
        Err(ConstraintError::Syntax("build expression too large"))
    );
}

/// `&&` binds tighter than `||`, parentheses regroup, and `!` applies to
/// one atom: the expression cases of `go/build/constraint`'s tests.
#[test]
fn go_build_expressions_follow_go_precedence() {
    let eval = |text: &str, set: &[&str]| {
        parse_expr(text)
            .unwrap()
            .eval(&|tag: &str| set.contains(&tag))
    };
    assert!(eval("x || y && z", &["x"]));
    assert!(!eval("(x || y) && z", &["x"]));
    assert!(eval("!x && y", &["y"]));
    assert!(!eval("!(x || y)", &["y"]));
    assert!(eval("go1.21 && linux.v2", &["go1.21", "linux.v2"]));
    assert_eq!(
        parse_expr("x || y && z"),
        Ok(Expr::or(
            Expr::Tag("x".into()),
            Expr::and(Expr::Tag("y".into()), Expr::Tag("z".into()))
        ))
    );
}

/// `+build` lines: spaces are OR, commas AND; every line must hold; an
/// invalid tag never holds; an over-long line is ignored.
#[test]
fn plus_build_lines_combine_like_go() {
    let tags = |set: &'static [&'static str]| move |tag: &str| set.contains(&tag);
    let built = |content: &str, set: &'static [&'static str]| {
        file_constraint(content)
            .unwrap()
            .is_none_or(|expr| expr.eval(&tags(set)))
    };
    assert!(built("// +build a,!b c\n\npackage p\n", &["a"]));
    assert!(!built("// +build a,!b c\n\npackage p\n", &["a", "b"]));
    assert!(!built("// +build a\n// +build b\n\npackage p\n", &["a"]));
    assert!(built(
        "// +build a\n// +build b\n\npackage p\n",
        &["a", "b"]
    ));
    assert!(!built("// +build a-b\n\npackage p\n", &["a-b"]));
    assert!(!built("// +build !!a\n\npackage p\n", &[]));
    assert!(built("//+build a\n\npackage p\n", &["a"]));
    assert!(built("// +buildx\n\npackage p\n", &[]));
    let long = format!("// +build {}\n\npackage p\n", "a,".repeat(200));
    assert_eq!(file_constraint(&long), Ok(None));
}

/// The cases of `TestGoodOSArchFile` in `go/build/build_test.go`, on
/// linux/amd64 with `darwin`/`arm64` as the other OS and architecture.
#[test]
fn go_build_good_os_arch_file_cases() {
    let here = Platform {
        goos: "linux",
        goarch: "amd64",
        cgo: true,
    };
    let tag = |name: &str| here.has_tag(name);
    for (name, expected) in [
        ("file.go", true),
        ("file_foo.go", true),
        ("file_amd64.go", true),
        ("file_arm64.go", false),
        ("file_linux.go", true),
        ("file_darwin.go", false),
        ("file_linux_amd64.go", true),
        ("file_darwin_amd64.go", false),
        ("file_linux_arm64.go", false),
        ("file_darwin_arm64.go", false),
        ("file_foo_amd64.go", true),
        ("file_foo_arm64.go", false),
        ("file_linux.c", true),
        ("file_darwin.c", false),
        ("file_darwin_test.go", false),
        ("file_linux_test.go", true),
        ("linux.go", true),
        ("file_linux.pb.go", true),
        ("file_darwin.pb.go", false),
        ("file_arm_extra.go", true),
        ("file_zos.go", false),
    ] {
        assert_eq!(file_name_matches(name, &tag), expected, "{name}");
    }
}

/// The GOOS a port implies, `unix`, `cgo` and release tags hold where
/// `go/build` sets them.
#[test]
fn platform_tags_follow_go_build_match_tag() {
    let find = |goos: &str, goarch: &str| {
        *PLATFORMS
            .iter()
            .find(|p| p.goos == goos && p.goarch == goarch)
            .unwrap()
    };
    let android = find("android", "arm64");
    assert!(android.has_tag("linux") && android.has_tag("unix") && android.has_tag("cgo"));
    assert!(file_name_matches("x_linux.go", &|t: &str| android.has_tag(t)));
    assert!(find("illumos", "amd64").has_tag("solaris"));
    assert!(find("ios", "arm64").has_tag("darwin"));
    let windows = find("windows", "amd64");
    assert!(!windows.has_tag("unix") && windows.has_tag("gc") && windows.has_tag("go1.21"));
    assert!(!windows.has_tag("go1.") && !windows.has_tag("gccgo"));
    assert!(!find("js", "wasm").has_tag("cgo"));
    assert!(!find("linux", "ppc64").has_tag("cgo"));
    for platform in PLATFORMS {
        assert!(KNOWN_OS.contains(&platform.goos), "{platform:?}");
        assert!(KNOWN_ARCH.contains(&platform.goarch), "{platform:?}");
    }
}
