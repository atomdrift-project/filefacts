use super::*;
use crate::output::{Metrics, Values};

fn run(input: &str) -> Values {
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    extract(input.as_bytes(), &mut values, &mut metrics);
    values
}

fn get_str(values: &Values, path: &str) -> Option<String> {
    values
        .get(path)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn get_arr(values: &Values, path: &str) -> Vec<String> {
    values
        .get(path)
        .and_then(JsonValue::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn first_heading_simple() {
    let v = run("# Hello\n\nbody text\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("Hello")
    );
}

#[test]
fn first_heading_with_leading_blank_lines() {
    let v = run("\n\n   # Hello   \nrest\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("Hello")
    );
}

#[test]
fn first_heading_h2_counts() {
    let v = run("## Subhead\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("Subhead")
    );
}

#[test]
fn first_heading_wins_over_later_ones() {
    let v = run("# First\n\n## Second\n\n### Third\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("First")
    );
}

#[test]
fn first_heading_strips_trailing_hashes() {
    let v = run("# Hello ###\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("Hello")
    );
}

#[test]
fn first_heading_strips_inline_emphasis() {
    let v = run("# **Bold** *and* `code`\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("Bold and code")
    );
}

#[test]
fn first_heading_clob_case() {
    let v = run("# `@img/sharp-win32-x64`\n\nLong description.\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("@img/sharp-win32-x64")
    );
}

#[test]
fn no_heading_no_value() {
    let v = run("Just a paragraph.\n");
    assert_eq!(get_str(&v, "markdown.first_heading"), None);
}

#[test]
fn empty_heading_no_value() {
    let v = run("# \n# Real heading\n");
    // The empty `# ` is rejected; the real heading wins.
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("Real heading")
    );
}

#[test]
fn heading_inside_fence_is_skipped() {
    let v = run("```\n# not a heading\n```\n\n# real heading\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("real heading")
    );
}

#[test]
fn heading_inside_tilde_fence_is_skipped() {
    let v = run("~~~\n# not a heading\n~~~\n\n# real heading\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("real heading")
    );
}

#[test]
fn rejects_more_than_six_hashes() {
    let v = run("####### too deep\n# real heading\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("real heading")
    );
}

#[test]
fn requires_space_after_hashes() {
    let v = run("#noSpace\n# real heading\n");
    assert_eq!(
        get_str(&v, "markdown.first_heading").as_deref(),
        Some("real heading")
    );
}

#[test]
fn github_repos_basic() {
    let v = run("See https://github.com/lovell/sharp for details.\n");
    assert_eq!(
        get_arr(&v, "markdown.github_repos"),
        vec!["github.com/lovell/sharp"]
    );
}

#[test]
fn github_repos_strips_subpaths() {
    let v = run(
        "See https://github.com/lovell/sharp/issues/123 and https://github.com/lovell/sharp/blob/main/README.md\n",
    );
    // Two refs, but both collapse to the same owner/repo and dedup.
    assert_eq!(
        get_arr(&v, "markdown.github_repos"),
        vec!["github.com/lovell/sharp"]
    );
}

#[test]
fn github_repos_strips_dotgit_suffix() {
    let v = run("git clone https://github.com/foo/bar.git\nWebsite https://github.com/foo/bar\n");
    assert_eq!(
        get_arr(&v, "markdown.github_repos"),
        vec!["github.com/foo/bar"]
    );
}

#[test]
fn github_repos_deduped_preserves_first_seen_order() {
    let v =
        run("https://github.com/aaa/one https://github.com/bbb/two https://github.com/aaa/one\n");
    assert_eq!(
        get_arr(&v, "markdown.github_repos"),
        vec!["github.com/aaa/one", "github.com/bbb/two"]
    );
}

#[test]
fn github_repos_handles_no_repo() {
    let v = run("https://github.com/orgonly\nhttps://github.com/\n");
    assert!(get_arr(&v, "markdown.github_repos").is_empty());
}

#[test]
fn github_repos_none_no_value() {
    let v = run("# No links here\n");
    assert!(v.get("markdown.github_repos").is_none());
}

#[test]
fn npm_packages_registry_link() {
    let v = run("Install from https://www.npmjs.com/package/tailwindcss-3d today.\n");
    assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["tailwindcss-3d"]);
}

#[test]
fn npm_packages_shields_badge_and_dedup() {
    let v = run(
        "![v](https://img.shields.io/npm/v/tailwindcss-3d?style=flat) \
             see https://www.npmjs.com/package/tailwindcss-3d\n",
    );
    assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["tailwindcss-3d"]);
}

#[test]
fn npm_packages_strips_shields_badge_extension() {
    // `img.shields.io/npm/v/etag.svg` names `etag`, not `etag.svg`.
    let v = run("![v](https://img.shields.io/npm/v/etag.svg)\n");
    assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["etag"]);
    let v = run("![v](https://img.shields.io/npm/v/js-yaml.png)\n");
    assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["js-yaml"]);
}

#[test]
fn npm_packages_keeps_a_real_dotted_name() {
    // `punycode.js` is a real package name; only image suffixes are stripped.
    let v = run("https://www.npmjs.com/package/punycode.js\n");
    assert_eq!(get_arr(&v, "markdown.npm_packages"), vec!["punycode.js"]);
}

#[test]
fn npm_packages_scoped_name() {
    let v = run("https://www.npmjs.com/package/@scope/pkg-name\n");
    assert_eq!(
        get_arr(&v, "markdown.npm_packages"),
        vec!["@scope/pkg-name"]
    );
}

#[test]
fn npm_packages_none_no_value() {
    let v = run("# A README with no npm references\n");
    assert!(v.get("markdown.npm_packages").is_none());
}

#[test]
fn install_packages_npm_install() {
    let v = run("Install it:\n\n```\nnpm install theta-registry\n```\n");
    assert_eq!(
        get_arr(&v, "markdown.install_packages"),
        vec!["theta-registry"]
    );
}

#[test]
fn install_packages_skips_flags_and_handles_managers() {
    let v =
        run("npm i --save-dev eslint\nyarn add react\npnpm add -D vitest\npip install requests\n");
    assert_eq!(
        get_arr(&v, "markdown.install_packages"),
        vec!["eslint", "react", "vitest", "requests"]
    );
}

#[test]
fn install_packages_vscode_marketplace_id() {
    let v = run("```\ncode --install-extension publisher.my-extension\n```\n");
    assert_eq!(
        get_arr(&v, "markdown.install_extensions"),
        vec!["my-extension"],
        "only the extension half of a marketplace id names the package"
    );
    assert!(get_arr(&v, "markdown.install_packages").is_empty());
}

#[test]
fn install_packages_vsix_file_strips_version() {
    // The `x.x.x` placeholder is what vsce's own docs print, and what a
    // cloned README carries over verbatim.
    let v = run("code --install-extension sugar-extension-pack-x.x.x.vsix\n\
             cursor --install-extension ./dist/my-ext-1.2.3.vsix\n");
    assert_eq!(
        get_arr(&v, "markdown.install_extensions"),
        vec!["sugar-extension-pack", "my-ext"]
    );
}

#[test]
fn install_packages_vscode_forks_and_non_version_tail() {
    let v = run(
        "codium --install-extension vscode-icons-team.vscode-icons\n\
             windsurf --install-extension vscode-icons-2.vsix\n",
    );
    assert_eq!(
        get_arr(&v, "markdown.install_extensions"),
        vec!["vscode-icons", "vscode-icons-2"],
        "a numeric trailing segment with no dot is part of the name"
    );
}

#[test]
fn install_packages_ignores_other_code_invocations() {
    let v = run("code .\ncode --list-extensions\ncode --help\n");
    assert!(get_arr(&v, "markdown.install_extensions").is_empty());
}

#[test]
fn install_extensions_kept_apart_from_companion_packages() {
    // An extension's README routinely documents installing the backend it
    // drives. That names a companion program, not the extension, so it must
    // not land in the list the manifest is checked against.
    let v = run("```bash\npip install --upgrade zenzic\n```\n\n\
             ```bash\ncode --install-extension pythonwoods.zenzic-vscode\n```\n");
    assert_eq!(get_arr(&v, "markdown.install_packages"), vec!["zenzic"]);
    assert_eq!(
        get_arr(&v, "markdown.install_extensions"),
        vec!["zenzic-vscode"]
    );
}

#[test]
fn install_packages_scoped_name_and_version_pin() {
    let v = run("npm install @scope/pkg-name@1.2.3\n");
    assert_eq!(
        get_arr(&v, "markdown.install_packages"),
        vec!["@scope/pkg-name"]
    );
}

#[test]
fn install_packages_strips_prompt_and_list_marker() {
    let v = run("$ npm install alpha\n- yarn add beta\n");
    assert_eq!(
        get_arr(&v, "markdown.install_packages"),
        vec!["alpha", "beta"]
    );
}

#[test]
fn install_packages_rejects_paths_urls_and_shell() {
    // Local paths, tarball URLs and piped commands are not registry names.
    let v = run("npm install ./local\nnpm install https://x.test/a.tgz\nnpm install foo | sh\n");
    assert!(v.get("markdown.install_packages").is_none());
}

#[test]
fn install_packages_dedupes_preserving_order() {
    let v = run("npm install foo\nyarn add foo\nnpm install bar\n");
    assert_eq!(get_arr(&v, "markdown.install_packages"), vec!["foo", "bar"]);
}

#[test]
fn install_packages_none_no_value() {
    let v = run("# A README that never says how to install\n");
    assert!(v.get("markdown.install_packages").is_none());
}

#[test]
fn handles_invalid_utf8_gracefully() {
    // Stray byte should not panic.
    let mut bytes = b"# Heading\n".to_vec();
    bytes.push(0xff);
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    extract(&bytes, &mut values, &mut metrics);
    assert_eq!(
        get_str(&values, "markdown.first_heading").as_deref(),
        Some("Heading")
    );
}
