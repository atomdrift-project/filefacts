use super::*;

fn npm_values(repo: Option<&str>) -> Values {
    let mut v = Values::new();
    if let Some(r) = repo {
        v.insert("npm.repository.url", JsonValue::String(r.into()));
    }
    v
}

#[test]
fn npm_repository_is_a_forge_purl() {
    let refs = derive(
        FileType::Npm,
        &[],
        &npm_values(Some("git+https://github.com/wacrot/infra-data-kit.git")),
    );
    assert_eq!(refs.len(), 1);
    assert_eq!(
        refs[0].locator,
        RefLocator::Purl("pkg:github/wacrot/infra-data-kit".into())
    );
    assert_eq!(refs[0].kind, RefKind::Repository);
}

#[test]
fn non_forge_repo_stays_url() {
    let refs = derive(
        FileType::Npm,
        &[],
        &npm_values(Some("https://example.com/x/y.git")),
    );
    assert_eq!(
        refs[0].locator,
        RefLocator::Url("https://example.com/x/y.git".into())
    );
}

#[test]
fn package_json_deps_pin_exact_and_unversion_ranges() {
    // A manifest declares an exact pin, a caret range, a scoped range, and
    // an optional dep; dev deps are ignored. Exact → versioned PURL;
    // non-exact specs retain their constraint on an unversioned PURL.
    let manifest = br#"{
            "name": "app",
            "dependencies": {
                "left-pad": "1.3.0",
                "easy-day-js": "^1.11.21",
                "@scope/util": "~2.0.0"
            },
            "optionalDependencies": { "fsevents": "*" },
            "devDependencies": { "typescript": "^6.0.3" }
        }"#;
    let refs = derive(FileType::PackageJson, manifest, &Values::new());
    let purls: Vec<&str> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Purl(p) => Some(p.as_str()),
            RefLocator::Url(_) | RefLocator::Path(_) => None,
        })
        .collect();
    assert!(purls.contains(&"pkg:npm/left-pad@1.3.0"), "{purls:?}");
    assert!(
        purls.contains(&"pkg:npm/easy-day-js?version_requirement=%5E1.11.21"),
        "{purls:?}"
    );
    assert!(
        purls.contains(&"pkg:npm/%40scope/util?version_requirement=~2.0.0"),
        "{purls:?}"
    );
    assert!(
        purls.contains(&"pkg:npm/fsevents"),
        "a wildcard adds nothing to the coordinate: {purls:?}"
    );
    assert!(
        !purls.iter().any(|p| p.contains("typescript")),
        "devDependencies must not be fetched: {purls:?}"
    );
    // The declared range is preserved as evidence for the report.
    let easy = refs
        .iter()
        .find(|r| matches!(&r.locator, RefLocator::Purl(p) if p == "pkg:npm/easy-day-js?version_requirement=%5E1.11.21"))
        .expect("easy-day-js ref");
    assert_eq!(easy.evidence, "easy-day-js@^1.11.21");
    assert_eq!(easy.kind, RefKind::Dependency);
}

#[test]
fn vscode_extension_manifest_deps_become_dependencies() {
    let manifest = br#"{
            "name": "krabt-extension-pack",
            "publisher": "krabt",
            "extensionDependencies": ["Dart-Code.dart-code"],
            "extensionPack": ["krabt.krabt-proto", "eamodio.gitlens", "not-an-id", "a.b.c"]
        }"#;
    let refs = derive(FileType::PackageJson, manifest, &Values::new());
    let purls: Vec<&str> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Purl(p) => Some(p.as_str()),
            RefLocator::Url(_) | RefLocator::Path(_) => None,
        })
        .collect();
    assert!(
        purls.contains(&"pkg:vscode/Dart-Code/dart-code"),
        "{purls:?}"
    );
    assert!(purls.contains(&"pkg:vscode/krabt/krabt-proto"), "{purls:?}");
    assert!(purls.contains(&"pkg:vscode/eamodio/gitlens"), "{purls:?}");
    // Not marketplace coordinates: no publisher half, and a three-part id.
    assert!(!purls.iter().any(|p| p.contains("not-an-id")), "{purls:?}");
    assert!(!purls.iter().any(|p| p.contains("a.b.c")), "{purls:?}");
    let pack = refs
        .iter()
        .find(|r| matches!(&r.locator, RefLocator::Purl(p) if p == "pkg:vscode/krabt/krabt-proto"))
        .expect("pack ref");
    assert_eq!(pack.kind, RefKind::Dependency);
    assert_eq!(pack.source, "extensionPack");
}

#[test]
fn package_json_deps_follow_the_spec_protocol_not_the_key() {
    // Only a registry range is a coordinate under the map's own key. A
    // local protocol delivers nothing external; an alias delivers the
    // aliased package; a forge or URL spec is fetched from there. Reading
    // the key regardless would both invent coordinates and miss the ones
    // actually delivered.
    let manifest = br#"{
            "name": "app",
            "dependencies": {
                "@scope/shared": "workspace:*",
                "cat-dep": "catalog:",
                "file-dep": "file:../local-thing",
                "link-dep": "link:../other",
                "portal-dep": "portal:../p",
                "bare-path-dep": "../sibling",
                "helper": "npm:left-pad@1.3.0",
                "loose-alias": "npm:@scope/util",
                "git-dep": "git+https://github.com/foo/bar.git#v1.2.3",
                "gh-dep": "github:foo/baz",
                "bare-forge-dep": "foo/qux",
                "ranged-forge-dep": "foo/quux#semver:^1.0.0",
                "url-dep": "https://example.com/foo.tgz",
                "range-dep": "^1.6.0"
            }
        }"#;
    let refs = derive(FileType::PackageJson, manifest, &Values::new());
    let locators: Vec<&RefLocator> = refs.iter().map(|r| &r.locator).collect();
    let has = |want: &str| {
        locators.iter().any(|l| match l {
            RefLocator::Purl(v) | RefLocator::Url(v) => v == want,
            RefLocator::Path(_) => false,
        })
    };

    // Local protocols and paths are inside the artifact: no reference.
    for key in [
        "shared",
        "cat-dep",
        "file-dep",
        "link-dep",
        "portal-dep",
        "bare-path-dep",
    ] {
        assert!(
            !locators
                .iter()
                .any(|l| matches!(l, RefLocator::Purl(p) if p.contains(key))),
            "local spec must emit no reference: {key} in {locators:?}"
        );
    }
    // An alias names the aliased package, never the local import name.
    assert!(has("pkg:npm/left-pad@1.3.0"), "{locators:?}");
    assert!(
        has("pkg:npm/%40scope/util"),
        "a rangeless alias is the bare coordinate: {locators:?}"
    );
    assert!(
        !locators
            .iter()
            .any(|l| matches!(l, RefLocator::Purl(p) if p.contains("helper"))),
        "alias key is not a package: {locators:?}"
    );
    // Forge specs normalize to a forge PURL, bare commit-ish as version.
    assert!(has("pkg:github/foo/bar@v1.2.3"), "{locators:?}");
    assert!(has("pkg:github/foo/baz"), "{locators:?}");
    assert!(has("pkg:github/foo/qux"), "{locators:?}");
    assert!(
        has("pkg:github/foo/quux"),
        "a `semver:` fragment is a range, not a pin: {locators:?}"
    );
    // A plain URL is fetched verbatim.
    assert!(has("https://example.com/foo.tgz"), "{locators:?}");
    // The ordinary registry range remains a registry dependency with its
    // install constraint retained.
    assert!(
        has("pkg:npm/range-dep?version_requirement=%5E1.6.0"),
        "{locators:?}"
    );
    assert_eq!(refs.len(), 8, "one ref per non-local spec: {locators:?}");
}

#[test]
fn npm_alias_splits_scoped_and_unversioned_forms() {
    assert_eq!(split_npm_alias("left-pad@1.3.0"), ("left-pad", "1.3.0"));
    assert_eq!(split_npm_alias("@scope/util@^2"), ("@scope/util", "^2"));
    assert_eq!(split_npm_alias("@scope/util"), ("@scope/util", ""));
    assert_eq!(split_npm_alias("left-pad"), ("left-pad", ""));
}

#[test]
fn package_json_entry_points_are_local_file_refs() {
    // `main`/`module`/`bin` point at sibling files in the same package, so
    // each is a Local reference with a Path locator — resolved against the
    // bundle, never fetched. A string `bin` and a `bin` map both work.
    let manifest = br#"{
            "name": "app",
            "main": "./lib/index.js",
            "module": "lib/index.mjs",
            "bin": { "app": "bin/cli.js", "app-dev": "bin/dev.js" },
            "dependencies": { "left-pad": "1.3.0" }
        }"#;
    let refs = derive(FileType::PackageJson, manifest, &Values::new());
    let paths: Vec<(&str, &str)> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Path(p) => Some((p.as_str(), r.source.as_str())),
            _ => None,
        })
        .collect();
    assert!(
        paths.contains(&("./lib/index.js", "package.json:main")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&("lib/index.mjs", "package.json:module")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&("bin/cli.js", "package.json:bin")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&("bin/dev.js", "package.json:bin")),
        "{paths:?}"
    );
    // Every Path locator is a Local kind, and Local is never a fetch target.
    for r in refs
        .iter()
        .filter(|r| matches!(r.locator, RefLocator::Path(_)))
    {
        assert_eq!(r.kind, RefKind::Local);
        assert!(!r.is_fetch_target());
    }
    // The byte offset points at the path's first occurrence in the manifest.
    let main = refs
        .iter()
        .find(|r| matches!(&r.locator, RefLocator::Path(p) if p == "./lib/index.js"))
        .expect("main ref");
    let text = std::str::from_utf8(manifest).unwrap();
    assert_eq!(
        main.offset.unwrap() as usize,
        text.find("./lib/index.js").unwrap()
    );
}

#[test]
fn package_json_exports_map_yields_local_refs_deduped() {
    // The modern `exports` map carries explicit file targets under
    // conditions; subpath patterns (`./*`) are skipped and a target shared
    // with `main` is emitted once.
    let manifest = br#"{
            "name": "chai-plugin-helper",
            "main": "./index.js",
            "exports": {
                ".": { "require": "./index.js", "import": "./index.mjs" },
                "./util": { "default": "./lib/util.js" },
                "./*": "./*"
            }
        }"#;
    let refs = derive(FileType::PackageJson, manifest, &Values::new());
    let paths: Vec<&str> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Path(p) => Some(p.as_str()),
            _ => None,
        })
        .collect();
    assert!(paths.contains(&"./index.js"), "{paths:?}");
    assert!(paths.contains(&"./index.mjs"), "{paths:?}");
    assert!(paths.contains(&"./lib/util.js"), "{paths:?}");
    // `./index.js` is in both `main` and `exports` — emitted once.
    assert_eq!(
        paths.iter().filter(|p| **p == "./index.js").count(),
        1,
        "{paths:?}"
    );
    // The `./*` subpath pattern names no single file.
    assert!(!paths.iter().any(|p| p.contains('*')), "{paths:?}");
}

#[test]
fn js_relative_imports_become_local_refs() {
    // require / import-from / export-from / side-effect / dynamic import,
    // in their common spacings. Bare packages and `import.meta` are not
    // intra-artifact references; an identical specifier is emitted once.
    let src = br#"
            const a = require('./util');
            import b from "../lib/helper.js";
            export { c } from './sub/mod';
            import "./side-effect";
            const d = await import("./dynamic.js");
            const ext = require('lodash');
            const meta = import.meta.url;
            const dup = require('./util');
        "#;
    let refs = derive(FileType::JavaScript, src, &Values::new());
    let paths: Vec<&str> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Path(p) => Some(p.as_str()),
            _ => None,
        })
        .collect();
    for want in [
        "./util",
        "../lib/helper.js",
        "./sub/mod",
        "./side-effect",
        "./dynamic.js",
    ] {
        assert!(paths.contains(&want), "missing {want}: {paths:?}");
    }
    assert!(
        !paths.iter().any(|p| p.contains("lodash")),
        "a bare package is an external dependency, not a local ref: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("meta")),
        "import.meta is not an import string: {paths:?}"
    );
    assert_eq!(
        paths.iter().filter(|p| **p == "./util").count(),
        1,
        "identical specifier emitted once: {paths:?}"
    );
    // Every JS path reference is a Local kind.
    for r in refs
        .iter()
        .filter(|r| matches!(r.locator, RefLocator::Path(_)))
    {
        assert_eq!(r.kind, RefKind::Local);
    }
}

#[test]
fn package_json_string_bin_is_a_local_ref() {
    // `bin` as a bare string (the package's single executable) resolves too.
    let manifest = br#"{ "name": "app", "bin": "cli.js" }"#;
    let refs = derive(FileType::PackageJson, manifest, &Values::new());
    assert!(
        refs.iter().any(
            |r| matches!(&r.locator, RefLocator::Path(p) if p == "cli.js")
                && r.kind == RefKind::Local
        ),
        "{refs:?}"
    );
}

#[test]
fn is_exact_npm_version_classifies_specs() {
    assert!(is_exact_npm_version("1.3.0"));
    assert!(is_exact_npm_version("2.0.0-beta.1"));
    assert!(!is_exact_npm_version("^1.11.21"));
    assert!(!is_exact_npm_version("~2.0.0"));
    assert!(!is_exact_npm_version(">=1.0.0"));
    assert!(!is_exact_npm_version("1.x"));
    assert!(!is_exact_npm_version("*"));
    assert!(!is_exact_npm_version("latest"));
    assert!(!is_exact_npm_version("1.2")); // partial → resolve to current
    assert!(!is_exact_npm_version("1.0.0 || 2.0.0"));
}

#[test]
fn npm_lock_v3_pins_dependencies() {
    // npm v2/v3 lockfile: `packages` keyed by install path, each with
    // a version and an `integrity` pin. The "" root is not a dep.
    let lock = serde_json::json!({
        "lockfileVersion": 3,
        "packages": {
            "": { "name": "app", "version": "1.0.0" },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "integrity": "sha512-AAAA"
            },
            "node_modules/@scope/util": {
                "version": "2.1.0",
                "integrity": "sha512-BBBB"
            }
        }
    });
    let values = Values::from_json(lock);
    let refs = derive(FileType::PackageLockJson, &[], &values);

    assert_eq!(refs.len(), 2);
    assert!(refs.iter().all(|r| r.kind == RefKind::Dependency));

    let left = refs
        .iter()
        .find(|r| r.locator == RefLocator::Purl("pkg:npm/left-pad@1.3.0".into()))
        .expect("left-pad");
    assert_eq!(
        left.pinned_hash,
        Some(PinnedHash {
            algo: HashAlgo::Sha512,
            value: "AAAA".into()
        })
    );
    assert!(left.is_fetch_target());

    // Scoped package: `@scope/util` → PURL namespace `%40scope`.
    assert!(
        refs.iter()
            .any(|r| r.locator == RefLocator::Purl("pkg:npm/%40scope/util@2.1.0".into()))
    );
}

#[test]
fn srcinfo_aur_foreign_bootstrap() {
    // Modeled on the pacman-foreign-bootstrap sample: a `bun` dep (the
    // foreign-bootstrap vector), a constrained dep, a tarball source
    // pinned by sha256, and a tag-pinned git source left as SKIP.
    let sum = "6b824bfd5a9f2c1cd8d6a30f858a7bdc7813a448f4894a151da035dac5af2f91";
    let pkg = serde_json::json!({
        "pkg": {
            "depends": ["bun", "boost>=1.69.0"],
            "source": [
                "https://example.com/extra.tar.gz",
                "git+https://github.com/nanocurrency/nano-node.git#tag=V22.1"
            ],
            "sha256sums": [sum, "SKIP"]
        }
    });
    let refs = derive(FileType::SrcInfo, &[], &Values::from_json(pkg));

    // Foreign dependency surfaced as an alpm PURL, fetch target.
    let bun = refs
        .iter()
        .find(|r| r.locator == RefLocator::Purl("pkg:alpm/arch/bun".into()))
        .expect("bun dep");
    assert_eq!(bun.kind, RefKind::Dependency);
    assert!(bun.is_fetch_target());
    // Version constraint stripped from the name.
    assert!(
        refs.iter()
            .any(|r| r.locator == RefLocator::Purl("pkg:alpm/arch/boost".into()))
    );

    // Tarball source: sha256 pin doubles as the hopper content key.
    let tar = refs
        .iter()
        .find(|r| r.locator == RefLocator::Url("https://example.com/extra.tar.gz".into()))
        .expect("tarball source");
    assert_eq!(
        tar.pinned_hash,
        Some(PinnedHash {
            algo: HashAlgo::Sha256,
            value: sum.into()
        })
    );
    assert_eq!(tar.content_sha256.as_deref(), Some(sum));

    // Git source: forge PURL with the tag as version, SKIP → no pin.
    let git = refs
        .iter()
        .find(|r| r.locator == RefLocator::Purl("pkg:github/nanocurrency/nano-node@V22.1".into()))
        .expect("git source");
    assert!(git.pinned_hash.is_none());
    assert!(git.content_sha256.is_none());
}

#[test]
fn srcinfo_release_asset_url_stays_url_with_pin() {
    // A GitHub *release asset* download URL (not the repo) must be fetched
    // verbatim so its sha256sums pin applies. Collapsing it to
    // `pkg:github/owner/repo` would resolve to the source tree at HEAD —
    // different bytes, a hash mismatch. Modeled on ttf-iosevka-curly-slab.
    let sum = "97d10cd3052cf30a3bc5bac4434d2937220e3343c4304eca9bd5c2259b10f5bc";
    let asset = "https://github.com/be5invis/Iosevka/releases/download/v34.7.0/PkgTTF-Iosevka.zip";
    let pkg = serde_json::json!({
        "pkg": {
            "source": [asset],
            "sha256sums": [sum]
        }
    });
    let refs = derive(FileType::SrcInfo, &[], &Values::from_json(pkg));
    let r = refs
        .iter()
        .find(|r| r.locator == RefLocator::Url(asset.into()))
        .expect("release asset stays a verbatim URL");
    assert_eq!(r.content_sha256.as_deref(), Some(sum));
    // No forge PURL was minted from the release-download path.
    assert!(
        !refs
            .iter()
            .any(|r| matches!(&r.locator, RefLocator::Purl(p) if p.starts_with("pkg:github/")))
    );
}

#[test]
fn go_mod_extracts_single_line_and_block_requires() {
    let gomod = b"module example.com/app\n\ngo 1.25\n\n\
            require github.com/foo/Bar v1.2.3\n\n\
            require (\n\
            \tgolang.org/x/net v0.1.0\n\
            \tcodeberg.org/a/b v0.0.0-20260507212222-cbe932efc123 // indirect\n\
            )\n";
    let refs = derive(FileType::GoMod, gomod, &Values::new());
    let purls: Vec<&str> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Purl(p) => Some(p.as_str()),
            RefLocator::Url(_) | RefLocator::Path(_) => None,
        })
        .collect();
    assert!(purls.contains(&"pkg:golang/github.com/foo/Bar@v1.2.3"));
    assert!(purls.contains(&"pkg:golang/golang.org/x/net@v0.1.0"));
    assert!(
        purls.contains(&"pkg:golang/codeberg.org/a/b@v0.0.0-20260507212222-cbe932efc123"),
        "indirect deps are kept: {purls:?}"
    );
    // go.mod has no hashes — those live in go.sum.
    assert!(
        refs.iter()
            .all(|r| r.kind == RefKind::Dependency && r.pinned_hash.is_none())
    );
}

#[test]
fn go_sum_preserves_both_hash_kinds_without_selecting_dependencies() {
    let gosum = b"github.com/foo/bar v1.2.3 h1:AAAA=\n\
            github.com/foo/bar v1.2.3/go.mod h1:BBBB=\n";
    let refs = derive(FileType::GoSum, gosum, &Values::new());
    assert_eq!(
        refs.len(),
        2,
        "preserve module and metadata checksums independently"
    );
    assert!(refs.iter().all(|r| r.kind == RefKind::Undefined));
    assert_eq!(refs[1].source, "go.sum.go.mod");
    let r = &refs[0];
    assert_eq!(
        r.locator,
        RefLocator::Purl("pkg:golang/github.com/foo/bar@v1.2.3".into())
    );
    assert_eq!(
        r.pinned_hash,
        Some(PinnedHash {
            algo: HashAlgo::GoModH1,
            value: "AAAA=".into()
        })
    );
    // h1: is a file-tree digest, not the zip's content hash.
    assert!(r.content_sha256.is_none());
}

#[test]
fn cargo_lock_pins_registry_crates_and_skips_path_deps() {
    // `package` array as `extract_toml` would promote a Cargo.lock's
    // `[[package]]` tables. The path/workspace crate (no checksum) is skipped.
    let values = Values::from_json(serde_json::json!({
        "package": [
            {
                "name": "serde", "version": "1.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "checksum": "1b5d307320b3181d6d7954e663bd7c774a838b8220fe0593c86d9fb09f498b4b"
            },
            { "name": "my-workspace-crate", "version": "0.1.0" }
        ]
    }));
    let refs = derive(FileType::CargoLock, &[], &values);
    assert_eq!(refs.len(), 1, "only the registry crate, not the path dep");
    let r = &refs[0];
    assert_eq!(r.locator, RefLocator::Purl("pkg:cargo/serde@1.0.0".into()));
    let sum = "1b5d307320b3181d6d7954e663bd7c774a838b8220fe0593c86d9fb09f498b4b";
    assert_eq!(
        r.pinned_hash,
        Some(PinnedHash {
            algo: HashAlgo::Sha256,
            value: sum.into()
        })
    );
    // A SHA-256 pin *is* the .crate's content hash — doubles as the hopper key.
    assert_eq!(r.content_sha256.as_deref(), Some(sum));
}

#[test]
fn cargo_toml_emits_repository_as_forge_purl() {
    let values = Values::from_json(serde_json::json!({
        "package": {
            "name": "app", "version": "0.1.0",
            "repository": "https://github.com/foo/bar"
        }
    }));
    let refs = derive(FileType::CargoToml, &[], &values);
    let repo = refs
        .iter()
        .find(|r| r.kind == RefKind::Repository)
        .expect("repository ref");
    assert_eq!(repo.locator, RefLocator::Purl("pkg:github/foo/bar".into()));
}

fn purls(refs: &[Reference]) -> Vec<&str> {
    refs.iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Purl(p) => Some(p.as_str()),
            RefLocator::Url(_) | RefLocator::Path(_) => None,
        })
        .collect()
}

#[test]
fn requirements_txt_keeps_exact_pins_only() {
    let req = b"# comment\n\
            requests==2.28.1\n\
            Flask==2.0.0  # web\n\
            numpy>=1.0\n\
            -r other.txt\n\
            Django[argon2]==4.1.0 ; python_version >= '3.8'\n\
            unpinned\n";
    let refs = derive(FileType::RequirementsTxt, req, &Values::new());
    let purls = purls(&refs);
    assert!(purls.contains(&"pkg:pypi/requests@2.28.1"));
    assert!(
        purls.contains(&"pkg:pypi/flask@2.0.0"),
        "normalized: {purls:?}"
    );
    assert!(
        purls.contains(&"pkg:pypi/django@4.1.0"),
        "extras + marker stripped: {purls:?}"
    );
    assert_eq!(refs.len(), 3, "ranges/options/unpinned skipped: {purls:?}");
}

#[test]
fn poetry_lock_extracts_resolved_packages() {
    let values = Values::from_json(serde_json::json!({
        "package": [
            {"name": "requests", "version": "2.28.1"},
            {"name": "PyYAML", "version": "6.0"}
        ]
    }));
    let refs = derive(FileType::PoetryLock, &[], &values);
    let purls = purls(&refs);
    assert!(purls.contains(&"pkg:pypi/requests@2.28.1"));
    assert!(
        purls.contains(&"pkg:pypi/pyyaml@6.0"),
        "normalized: {purls:?}"
    );
}

#[test]
fn yarn_lock_extracts_npm_deps_with_integrity() {
    let lock = b"# THIS IS AN AUTOGENERATED FILE\n\n\
            \"@babel/code-frame@^7.0.0\":\n  version \"7.12.11\"\n  \
            resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.11.tgz\"\n  \
            integrity sha512-AAAA\n  dependencies:\n    \"@babel/highlight\" \"^7.10.4\"\n\n\
            lodash@^4.17.15:\n  version \"4.17.21\"\n  integrity sha512-BBBB\n";
    let refs = derive(FileType::YarnLock, lock, &Values::new());
    assert_eq!(refs.len(), 2);
    let babel = refs
        .iter()
        .find(|r| r.locator == RefLocator::Purl("pkg:npm/%40babel/code-frame@7.12.11".into()))
        .expect("babel");
    assert_eq!(
        babel.pinned_hash,
        Some(PinnedHash {
            algo: HashAlgo::Sha512,
            value: "AAAA".into()
        })
    );
    assert!(
        refs.iter()
            .any(|r| r.locator == RefLocator::Purl("pkg:npm/lodash@4.17.21".into()))
    );
}

#[test]
fn npm_lock_aliases_resolve_to_the_real_package() {
    // An alias installs one package under another name. Only the aliased-to
    // package is on the registry — `string-width-cjs` was never published.
    let v3 = serde_json::json!({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/string-width-cjs": {
                "name": "string-width",
                "version": "4.2.3",
                "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"
            }
        }
    });
    let refs = derive(FileType::PackageLockJson, &[], &Values::from_json(v3));
    assert_eq!(purls(&refs), vec!["pkg:npm/string-width@4.2.3"]);

    // v1 folds the alias into the version.
    let v1 = serde_json::json!({
        "lockfileVersion": 1,
        "dependencies": {
            "strip-ansi-cjs": { "version": "npm:strip-ansi@6.0.1" },
            "left-pad": { "version": "1.3.0" }
        }
    });
    let refs = derive(FileType::PackageLockJson, &[], &Values::from_json(v1));
    let p = purls(&refs);
    assert!(p.contains(&"pkg:npm/strip-ansi@6.0.1"), "{p:?}");
    assert!(p.contains(&"pkg:npm/left-pad@1.3.0"), "{p:?}");
}

#[test]
fn yarn_lock_alias_resolves_to_the_real_package() {
    let lock = b"\"wrap-ansi-cjs@npm:wrap-ansi@^7.0.0\":\n  version \"7.0.0\"\n\n\
            lodash@npm:^4.17.15:\n  version \"4.17.21\"\n";
    let refs = derive(FileType::YarnLock, lock, &Values::new());
    let p = purls(&refs);
    assert!(p.contains(&"pkg:npm/wrap-ansi@7.0.0"), "{p:?}");
    // Berry writes the protocol on every entry; that is a range, not an alias.
    assert!(p.contains(&"pkg:npm/lodash@4.17.21"), "{p:?}");
}

#[test]
fn pnpm_lock_alias_resolves_to_the_real_package() {
    let values = Values::from_json(serde_json::json!({
        "packages": {
            "string-width-cjs@npm:string-width@4.2.3": {
                "resolution": { "integrity": "sha512-EEEE" }
            }
        }
    }));
    let refs = derive(FileType::PnpmLock, &[], &values);
    assert_eq!(purls(&refs), vec!["pkg:npm/string-width@4.2.3"]);
}

#[test]
fn pnpm_lock_extracts_packages_with_integrity() {
    // The `packages` map as extract_yaml promotes it (v6 `/name@ver` keys).
    let values = Values::from_json(serde_json::json!({
        "packages": {
            "/lodash@4.17.21": { "resolution": { "integrity": "sha512-CCCC" } },
            "/@babel/code-frame@7.12.11(react@18.0.0)": {
                "resolution": { "integrity": "sha512-DDDD" }
            }
        }
    }));
    let refs = derive(FileType::PnpmLock, &[], &values);
    let p = purls(&refs);
    assert!(p.contains(&"pkg:npm/lodash@4.17.21"), "{p:?}");
    // Scoped name encoded, peer-suffix stripped.
    assert!(p.contains(&"pkg:npm/%40babel/code-frame@7.12.11"), "{p:?}");
    assert!(refs.iter().all(|r| r.pinned_hash.is_some()));
}

#[test]
fn gemfile_lock_extracts_gem_specs_only() {
    let lock = b"GEM\n  remote: https://rubygems.org/\n  specs:\n    \
            rake (13.0.6)\n    rspec (3.12.0)\n      rspec-core (~> 3.12.0)\n\n\
            GIT\n  remote: https://github.com/foo/bar.git\n  specs:\n    \
            bar (1.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n";
    let refs = derive(FileType::GemfileLock, lock, &Values::new());
    let purls = purls(&refs); // reused helper: just collects PURL strings
    assert!(purls.contains(&"pkg:gem/rake@13.0.6"), "{purls:?}");
    assert!(purls.contains(&"pkg:gem/rspec@3.12.0"), "{purls:?}");
    // The sub-dependency constraint (indent 6) is not a resolved gem.
    assert!(!purls.iter().any(|p| p.contains("rspec-core")), "{purls:?}");
    // The GIT gem isn't on rubygems.org, so it's skipped.
    assert!(!purls.iter().any(|p| p.contains("/bar@")), "{purls:?}");
}

#[test]
fn gem_archive_resolves_runtime_deps_to_rubygems() {
    // A .gem's declared runtime deps (lifted from metadata.gz by the gem
    // extractor) resolve as unversioned gem PURLs — the gemspec declares
    // ranges, not pins. This is the manifest path; it must NOT depend on
    // `require` statements (which are load paths, not gem names, and are not
    // npm — the bug that motivated this arm).
    let mut values = Values::new();
    values.insert(
        "gem.runtime_dependencies",
        serde_json::json!(["faraday", "faraday-multipart", "mime-types"]),
    );
    let refs = derive(FileType::Gem, &[], &values);
    let p = purls(&refs);
    assert!(p.contains(&"pkg:gem/faraday"), "{p:?}");
    assert!(p.contains(&"pkg:gem/faraday-multipart"), "{p:?}");
    assert!(p.contains(&"pkg:gem/mime-types"), "{p:?}");
    // Every dep is a rubygems PURL — nothing leaked to npm.
    assert!(
        refs.iter().all(|r| matches!(
            &r.locator,
            RefLocator::Purl(pu) if pu.starts_with("pkg:gem/")
        )),
        "{refs:?}"
    );
    assert!(refs.iter().all(|r| r.kind == RefKind::Dependency));
}

#[test]
fn gem_archive_without_deps_yields_nothing() {
    // A dependency-free gem (or one whose metadata.gz had no runtime deps)
    // must not fabricate references.
    let refs = derive(FileType::Gem, &[], &Values::new());
    assert!(refs.is_empty(), "{refs:?}");
}

#[test]
fn vsix_dependencies_resolve_to_the_marketplace() {
    // A VSIX's `<Dependency>` extension ids resolve as VS Code Marketplace
    // PURLs (publisher/name), not npm — even though the VSIX is Node code.
    let mut values = Values::new();
    values.insert(
        "vsix.dependencies",
        serde_json::json!([
            { "id": "ms-python.python", "version": "2024.0.0" },
            { "id": "dbaeumer.vscode-eslint" },
            { "id": "no-dot-here" },     // not a publisher.name → skipped
            { "version": "1.0.0" }       // no id → skipped
        ]),
    );
    let refs = derive(FileType::Vsix, &[], &values);
    let p = purls(&refs);
    assert!(p.contains(&"pkg:vscode/ms-python/python"), "{p:?}");
    assert!(p.contains(&"pkg:vscode/dbaeumer/vscode-eslint"), "{p:?}");
    assert_eq!(p.len(), 2, "malformed ids must be skipped: {p:?}");
    assert!(
        refs.iter().all(|r| r.kind == RefKind::Dependency),
        "{refs:?}"
    );
}

#[test]
fn composer_lock_extracts_packages_and_dev() {
    let values = Values::from_json(serde_json::json!({
        "packages": [
            {"name": "monolog/monolog", "version": "3.0.0",
             "dist": {"type": "zip", "url": "https://api.github.com/x"}}
        ],
        "packages-dev": [
            {"name": "phpunit/phpunit", "version": "10.1.0"}
        ]
    }));
    let refs = derive(FileType::ComposerLock, &[], &values);
    let purls = purls(&refs);
    assert!(
        purls.contains(&"pkg:composer/monolog/monolog@3.0.0"),
        "{purls:?}"
    );
    assert!(
        purls.contains(&"pkg:composer/phpunit/phpunit@10.1.0"),
        "{purls:?}"
    );
    assert!(refs.iter().all(|r| r.kind == RefKind::Dependency));
}

#[test]
fn pipfile_lock_extracts_default_and_develop() {
    let values = Values::from_json(serde_json::json!({
        "default": { "requests": { "version": "==2.28.1" } },
        "develop": { "pytest": { "version": "==7.0.0" } }
    }));
    let refs = derive(FileType::PipfileLock, &[], &values);
    let purls = purls(&refs);
    assert!(purls.contains(&"pkg:pypi/requests@2.28.1"));
    assert!(purls.contains(&"pkg:pypi/pytest@7.0.0"));
}

#[test]
fn github_actions_maps_uses_to_repo_and_container_purls() {
    let values = Values::from_json(serde_json::json!({
        "jobs": { "build": { "steps": [
            { "uses": "actions/checkout@v4" },
            { "uses": "docker://ghcr.io/owner/tool:1.2" },
            { "uses": "docker://alpine:3.19" },
            { "uses": "docker://localhost:5000/tool" },
            { "uses": "docker://alpine" },
            { "uses": "./.github/actions/local" },
            { "run": "echo hi" }
        ] } }
    }));
    let refs = derive(FileType::GithubActions, &[], &values);
    let purls = purls(&refs);
    // Repo action → pkg:github; container action → pkg:oci. The `oci` type
    // reserves the version for a digest, so registry and tag are
    // qualifiers. A local action ships in the repo, so it is not a ref.
    assert!(purls.contains(&"pkg:github/actions/checkout@v4"));
    assert!(purls.contains(&"pkg:oci/tool?repository_url=ghcr.io%2Fowner&tag=1.2"));
    assert!(purls.contains(&"pkg:oci/alpine?tag=3.19"));
    // A registry port is not a tag, and the `:` it keeps needs no encoding.
    assert!(purls.contains(&"pkg:oci/tool?repository_url=localhost:5000"));
    // An untagged reference stays untagged — an unpinned action reads as
    // unpinned rather than being silently resolved to `latest`.
    assert!(purls.contains(&"pkg:oci/alpine"), "{purls:?}");
    assert_eq!(
        refs.len(),
        5,
        "local action and run step are not references"
    );
    // Every action reference is a declared dependency (kind); its CI-only
    // context comes from the workflow file, not the reference.
    assert!(refs.iter().all(|r| r.kind == RefKind::Dependency));
}

#[test]
fn locate_cites_a_real_occurrence_of_every_evidence() {
    // The resume-from-cursor search keeps locating N references linear.
    // The invariant it must hold is that every offset still *cites* its
    // evidence — the byte there really begins that string.
    let mut yaml = String::from("name: w\non: push\njobs:\n  build:\n    steps:\n");
    let mut steps = Vec::new();
    for i in 0..64 {
        yaml.push_str(&format!("      - uses: actions/step{i}@v{i}\n"));
        steps.push(serde_json::json!({ "uses": format!("actions/step{i}@v{i}") }));
    }
    // A repeat of an earlier step: it is a distinct step at a distinct
    // byte, so it must cite its own line, not the first one's.
    yaml.push_str("      - uses: actions/step0@v0\n");
    steps.push(serde_json::json!({ "uses": "actions/step0@v0" }));

    let values = Values::from_json(serde_json::json!({
        "jobs": { "build": { "steps": steps } }
    }));
    let refs = derive(FileType::GithubActions, yaml.as_bytes(), &values);
    assert_eq!(refs.len(), 65);

    for r in &refs {
        assert!(
            yaml[r.offset.unwrap() as usize..].starts_with(&r.evidence),
            "offset {:?} must cite {:?}",
            r.offset,
            r.evidence
        );
    }
    // Distinct evidence in document order lands exactly where a whole-file
    // search would.
    for r in &refs[..64] {
        assert_eq!(r.offset.unwrap() as usize, yaml.find(&r.evidence).unwrap());
    }
    // The duplicate cites its own later line, which a whole-file search
    // could not distinguish from the first.
    assert_eq!(refs[64].evidence, refs[0].evidence);
    assert!(refs[64].offset > refs[63].offset);
}

#[test]
fn github_action_rejects_purl_injection() {
    // A crafted `uses:` whose ref carries a purl qualifier would, if
    // interpolated, redirect the fetch to an attacker host. Each of these
    // must produce no locator rather than a poisoned one.
    for hostile in [
        "actions/checkout@v4?repository_url=http://evil.example/x",
        "actions/checkout@v4&repository_url=evil",
        "actions/checkout@v4#frag",
        "actions/checkout@v4%2e%2e",
        "actions/checkout@../../../../etc/passwd",
        "docker://ghcr.io/owner/tool:1.2?repository_url=http://evil",
        "docker://evil\u{0000}/tool:1",
        // A protocol-relative registry: percent-encoded into
        // `repository_url`, a consumer resolving it as a URL would fetch
        // from evil.example over its own scheme.
        "docker:////evil.example/tool",
        "docker://evil.example//tool:1",
        "docker://-evil.example/tool:1",
        "actions/checkout@v4 --extra",
    ] {
        assert_eq!(
            github_action_locator(hostile),
            None,
            "must reject injection-shaped uses: {hostile:?}"
        );
    }
    // A pinned SHA and a slashed ref are legitimate and still resolve.
    assert_eq!(
        github_action_locator("actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        Some(RefLocator::Purl(
            "pkg:github/actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into()
        ))
    );
    assert_eq!(
        github_action_locator("owner/repo@refs/tags/v1"),
        Some(RefLocator::Purl(
            "pkg:github/owner/repo@refs/tags/v1".into()
        ))
    );
}
