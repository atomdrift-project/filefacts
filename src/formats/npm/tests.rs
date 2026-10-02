use super::*;
use std::io::Write;

/// A gzipped tar holding the given members.
fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, body) in members {
        let mut h = tar::Header::new_ustar();
        h.set_path(path).unwrap();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append(&h, *body).unwrap();
    }
    let tar = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

fn run_tgz(bytes: &[u8]) -> (Values, Errors) {
    let mut v = Values::new();
    let mut e = Errors::new();
    extract(
        bytes,
        FileType::Npm,
        &mut v,
        &mut Metrics::new(),
        &mut Vec::new(),
        &mut e,
    )
    .unwrap();
    (v, e)
}

/// The one recorded error's stage and kind.
fn only_error(errors: &Errors) -> (Stage, crate::ErrorKind) {
    assert_eq!(errors.len(), 1, "{errors:?}");
    (errors.as_slice()[0].stage, errors.as_slice()[0].kind)
}

#[test]
fn tarball_manifest_is_read_and_records_nothing() {
    let (v, e) = run_tgz(&tgz(&[(MANIFEST, br#"{"name": "demo"}"#)]));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(v.get("npm.name").and_then(JsonValue::as_str), Some("demo"));
    // A tarball without the manifest is not a failure.
    let (_, e) = run_tgz(&tgz(&[("package/index.js", b"//")]));
    assert!(e.is_empty(), "{e:?}");
}

#[test]
fn manifest_that_is_not_json_records_one_error() {
    let (v, e) = run_tgz(&tgz(&[(MANIFEST, b"{\"name\": ")]));
    assert_eq!(
        only_error(&e),
        (Stage::FormatExtract, crate::ErrorKind::Malformed)
    );
    assert!(v.get("npm.name").is_none());
}

#[test]
fn corrupt_gzip_stream_records_one_tar_parse_error() {
    let mut bytes = tgz(&[(MANIFEST, br#"{"name": "demo"}"#)]);
    for b in &mut bytes[10..] {
        *b ^= 0x5a;
    }
    let (v, e) = run_tgz(&bytes);
    assert_eq!(
        only_error(&e),
        (Stage::TarParse, crate::ErrorKind::Malformed)
    );
    assert!(v.get("npm.name").is_none());
}

#[test]
fn oversized_manifest_is_a_limit_not_an_error() {
    let big = vec![b' '; MAX_MANIFEST as usize + 1];
    let (v, e) = run_tgz(&tgz(&[(MANIFEST, &big)]));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("npm.limits").and_then(JsonValue::as_array).unwrap();
    assert_eq!(limits[0]["stage"], "manifest");
}

#[test]
fn emits_name_version_and_author_email() {
    let manifest = serde_json::json!({
        "name": "left-pad",
        "version": "1.3.0",
        "description": "String left pad",
        "author": "Azer Koculu <azer@example.com> (http://azer.bike)",
        "repository": { "url": "git+https://github.com/azer/left-pad.git" }
    });
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    emit(&manifest, &mut values, &mut metrics);
    assert_eq!(
        values.get("npm.name").and_then(JsonValue::as_str),
        Some("left-pad")
    );
    assert_eq!(
        values.get("npm.description").and_then(JsonValue::as_str),
        Some("String left pad")
    );
    assert_eq!(
        values.get("npm.author.email").and_then(JsonValue::as_str),
        Some("azer@example.com")
    );
    assert_eq!(
        values.get("npm.repository.url").and_then(JsonValue::as_str),
        Some("git+https://github.com/azer/left-pad.git")
    );
}

#[test]
fn maintainers_become_structured_array() {
    let manifest = serde_json::json!({
        "name": "x",
        "maintainers": [{ "name": "a", "email": "a@x.io" }, "b <b@x.io>"]
    });
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    emit(&manifest, &mut values, &mut metrics);
    let m = values
        .get("npm.maintainers")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(
        m[1].get("email").and_then(JsonValue::as_str),
        Some("b@x.io")
    );
}

/// Run `emit` and return only the metrics, for the consistency judgements.
fn consistency(manifest: &JsonValue) -> Metrics {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    emit(manifest, &mut values, &mut metrics);
    metrics
}

fn name_repo(name: &str, repository: &JsonValue) -> Option<f64> {
    consistency(&serde_json::json!({ "name": name, "repository": repository }))
        .get("consistency.name_repo_mismatch")
}

fn publisher_repo(publisher: &str, repository: &str) -> Option<f64> {
    consistency(&serde_json::json!({
        "publisher": publisher,
        "repository": { "url": repository },
    }))
    .get("consistency.publisher_repo_owner_mismatch")
}

#[test]
fn name_repo_mismatch_spots_a_clone_and_rename() {
    // Both gauntlet samples: the manifest names one package and claims
    // another project's repository.
    assert_eq!(
        name_repo(
            "tailwindcss-form-styles",
            &serde_json::json!("https://github.com/tailwindlabs/tailwindcss-forms"),
        ),
        Some(1.0),
    );
    assert_eq!(
        name_repo(
            "tailwindcss-3d-animate",
            &serde_json::json!({ "url": "git://github.com/sambauers/tailwindcss-3d.git" }),
        ),
        Some(1.0),
    );
}

#[test]
fn name_repo_mismatch_folds_the_noise() {
    // A scope, a `.git` suffix and `-`/`_`/case spelling differ without
    // disagreeing.
    for (name, repo) in [
        (
            "@tailwindcss/forms",
            "https://github.com/tailwindlabs/tailwindcss-forms",
        ),
        (
            "@h3nr1-d14z/nat-gate",
            "git+https://github.com/h3nr1-d14z/nat-gate.git",
        ),
        ("Lodash", "https://github.com/lodash/lodash.git"),
        (
            "mini_svg_data_uri",
            "https://github.com/tigt/mini-svg-data-uri/",
        ),
    ] {
        assert_eq!(
            name_repo(name, &serde_json::json!(repo)),
            Some(0.0),
            "{name} vs {repo}",
        );
    }
}

#[test]
fn name_repo_mismatch_abstains_for_a_monorepo() {
    // `@react-pdf/png-js` ships from `diegomura/react-pdf` and says so.
    assert_eq!(
        name_repo(
            "@react-pdf/png-js",
            &serde_json::json!({
                "url": "https://github.com/diegomura/react-pdf.git",
                "directory": "packages/png-js",
            }),
        ),
        None,
    );
}

#[test]
fn name_repo_mismatch_abstains_without_a_claim() {
    // No repository is no claim to contradict, and neither is no manifest.
    assert_eq!(
        consistency(&serde_json::json!({ "name": "solo" })).get("consistency.name_repo_mismatch"),
        None,
    );
    assert_eq!(
        consistency(&serde_json::json!({})).get("consistency.name_repo_mismatch"),
        None,
    );
}

#[test]
fn self_reference_needs_the_dependency_to_name_this_repository() {
    // opensearch-js 3.8.0: a lone optional dependency, renamed into a
    // scope the project does not own, pinned to a commit in the project's
    // own repository. The tarball it ships is otherwise unchanged.
    let manifest = serde_json::json!({
        "name": "@opensearch-project/opensearch",
        "repository": { "url": "https://github.com/opensearch-project/opensearch-js.git" },
        "optionalDependencies": {
            "@opensearch/setup":
                "github:opensearch-project/opensearch-js#d446803f4c3bc116263faa3499a1d3f95b2825de"
        },
    });
    assert_eq!(
        consistency(&manifest).get("consistency.self_referential_git_dependency"),
        Some(1.0)
    );
}

#[test]
fn a_git_dependency_on_another_project_is_not_a_self_reference() {
    let manifest = serde_json::json!({
        "name": "left-pad",
        "repository": { "url": "git+https://github.com/azer/left-pad.git" },
        "dependencies": { "patched-dep": "github:someone/other-project#main" },
    });
    assert_eq!(
        consistency(&manifest).get("consistency.self_referential_git_dependency"),
        Some(0.0)
    );
}

#[test]
fn registry_aliases_and_ranges_are_not_repository_references() {
    // `npm:@ai-sdk/provider@3.0.10` carries a slash but names no forge, so
    // a manifest full of aliases declares no git dependency and the metric
    // abstains rather than reading them as a disagreement.
    let manifest = serde_json::json!({
        "name": "@mastra/core",
        "repository": { "url": "https://github.com/mastra-ai/mastra.git" },
        "dependencies": {
            "@ai-sdk/provider-v6": "npm:@ai-sdk/provider@3.0.10",
            "easy-day-js": "^1.11.21",
        },
    });
    assert_eq!(
        consistency(&manifest).get("consistency.self_referential_git_dependency"),
        None
    );
}

#[test]
fn publisher_repo_owner_mismatch_separates_a_fork_from_a_republication() {
    // Republication: the upstream repository kept, the listing renamed.
    assert_eq!(
        publisher_repo("krabt", "https://github.com/zxh0/vscode-proto3"),
        Some(1.0),
    );
    // Honest fork: the author publishes their own repository, even though
    // the package name and the repository name differ.
    assert_eq!(
        publisher_repo(
            "Bobronium",
            "https://github.com/Bobronium/vscode-pycharm-darcula-theme",
        ),
        Some(0.0),
    );
    // Case and separators are noise, not disagreement.
    assert_eq!(
        publisher_repo("Dart-Code", "https://github.com/dartcode/Flutter.git"),
        Some(0.0),
    );
}

#[test]
fn publisher_repo_owner_mismatch_abstains_without_both_sides() {
    // No publisher: an ordinary npm manifest, not a marketplace listing.
    assert_eq!(publisher_repo("", "https://github.com/a/b"), None);
    // A URL that names no owner.
    assert_eq!(publisher_repo("krabt", "https://example.com/thing"), None);
}
