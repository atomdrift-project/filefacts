//! Reference extraction — the external packages and URLs an artifact points
//! at, plus the intra-artifact files it names (a manifest entry point), folded
//! across formats into [`Reference`] rows.
//!
//! Mirrors [`super::identity`]: format parsers write `values`, and
//! [`derive()`] reads them back into one typed view. PURL is preferred over
//! a raw URL wherever the ecosystem is identifiable, for disambiguation; an
//! intra-artifact target is a [`RefLocator::Path`].

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value as JsonValue;

use crate::fileid::FileType;
use crate::output::{HashAlgo, PinnedHash, RefKind, RefLocator, Reference, Values};
use crate::value_key;
pub(crate) mod go;
mod manifests;

/// Derive external references from a parsed file's `values`. `bytes` is the
/// raw file, used to locate each reference's `evidence` for its byte offset.
pub(crate) fn derive(file_type: FileType, bytes: &[u8], values: &Values) -> Vec<Reference> {
    let mut out = Refs {
        refs: Vec::new(),
        // UTF-8 text manifests can be searched for offsets; binary or
        // compressed sources (an npm `.tgz`) cannot.
        text: std::str::from_utf8(bytes).ok(),
        cursor: 0,
        budget: MAX_LOCATE_SCAN,
    };
    match values
        .get_key(value_key!("go_manifest.kind"))
        .and_then(JsonValue::as_str)
    {
        Some("go.work") => {
            go::manifest(&mut out, "go.work");
            return out.refs;
        }
        Some("go.work.sum") => {
            go::sums(&mut out);
            return out.refs;
        }
        Some("modules.txt") => {
            go::vendor(&mut out);
            return out.refs;
        }
        _ => {}
    }
    // Only declared, structured dependencies live here. Imperative/undeclared
    // recognition (install-hook commands, shell/Dockerfile `npm install`,
    // `curl | sh`, URLs in variables) is fletch's `find`, which consumes these
    // facts and adds the hunted refs.
    match file_type {
        FileType::Npm | FileType::PackageJson => npm(values, &mut out),
        FileType::PackageLockJson => npm_lock(values, &mut out),
        FileType::SrcInfo => srcinfo(values, &mut out),
        FileType::GoMod => go::manifest(&mut out, "go.mod"),
        FileType::GoSum => go::sums(&mut out),
        FileType::CargoToml => cargo_toml(values, &mut out),
        FileType::CargoLock => cargo_lock(values, &mut out),
        FileType::PyProjectToml => manifests::pyproject(values, &mut out),
        FileType::RequirementsTxt => requirements_txt(&mut out),
        FileType::PoetryLock => poetry_lock(values, &mut out),
        FileType::PipfileLock => pipfile_lock(values, &mut out),
        FileType::GemfileLock => gemfile_lock(&mut out),
        FileType::Gem => gem_runtime_deps(values, &mut out),
        FileType::Vsix => vsix_deps(values, &mut out),
        FileType::ComposerLock => composer_lock(values, &mut out),
        FileType::YarnLock => yarn_lock(&mut out),
        FileType::PnpmLock => pnpm_lock(values, &mut out),
        FileType::JavaScript | FileType::TypeScript => js_local_refs(&mut out),
        FileType::GithubActions => github_actions(values, &mut out),
        _ => {}
    }
    out.refs
}

/// GitHub Actions `uses:` steps — third-party code a workflow (or composite
/// `action.yml`) runs. Each `owner/repo@ref` is a GitHub repository action
/// (`pkg:github`), each `docker://…` a container action (`pkg:oci`); local
/// `./…` actions ship in the repo and are not external. Every match is a
/// declared [`RefKind::Dependency`] — its CI-only *context* is the workflow
/// file's, not the reference's, so a consumer gates fetching on the file type
/// rather than a per-reference mark.
fn github_actions(values: &Values, out: &mut Refs<'_>) {
    let root = values.as_json();
    // Workflow steps: `jobs.<job>.steps[].uses`, plus a job-level `uses:` that
    // calls a reusable workflow. Composite actions: `runs.steps[].uses`.
    if let Some(jobs) = root.get("jobs").and_then(JsonValue::as_object) {
        for job in jobs.values() {
            emit_uses(out, job.get("uses"), "github-actions.jobs.uses");
            emit_step_uses(out, job.get("steps"));
        }
    }
    emit_step_uses(out, root.get("runs").and_then(|runs| runs.get("steps")));
}

/// Emit `uses:` for every step in a `steps:` array.
fn emit_step_uses(out: &mut Refs<'_>, steps: Option<&JsonValue>) {
    let Some(steps) = steps.and_then(JsonValue::as_array) else {
        return;
    };
    for step in steps {
        emit_uses(out, step.get("uses"), "github-actions.steps.uses");
    }
}

/// Emit one `uses:` value as a reference, if it names remote third-party code.
fn emit_uses(out: &mut Refs<'_>, uses: Option<&JsonValue>, source: &str) {
    let Some(raw) = uses.and_then(JsonValue::as_str) else {
        return;
    };
    if let Some(locator) = github_action_locator(raw) {
        out.push(locator, RefKind::Dependency, source, raw, None);
    }
}

/// A fetchable locator for a GitHub Actions `uses:` value.
/// `owner/repo[/subpath]@ref` → `pkg:github/owner/repo@ref`;
/// `docker://[registry/]image[:tag]` → `pkg:oci/image?repository_url=…&tag=…`,
/// the name lowercased as the `oci` purl type requires. Local (`./…`) uses ship
/// in the repo and return `None`.
fn github_action_locator(uses: &str) -> Option<RefLocator> {
    let uses = uses.trim();
    if let Some(image) = uses.strip_prefix("docker://") {
        // A `:` opens the tag only after the last `/` — otherwise it is a
        // registry port (`localhost:5000/tool`), not a tag.
        let (path, tag) = match image.rsplit_once(':') {
            Some((path, tag)) if !tag.contains('/') => (path, Some(tag)),
            _ => (image, None),
        };
        let (registry, name) = match path.rsplit_once('/') {
            Some((registry, leaf)) => (Some(registry), leaf),
            None => (None, path),
        };
        // The registry keeps `/` for a namespace and `:` for a port; the image
        // leaf and the tag are bare names. Anything else must never reach a
        // fetchable locator.
        if !purl_safe(name, b"")
            || !registry.is_none_or(registry_safe)
            || !tag.is_none_or(|t| purl_safe(t, b""))
        {
            return None;
        }
        // The `oci` type reserves the version for the sha256 digest, which a
        // workflow reference never carries — registry and tag are qualifiers.
        // A registry's slashes are percent-encoded: purl exempts a separator
        // character from encoding only in separator position, and inside a
        // qualifier value `/` is ordinary text (only `&` ends a value). An
        // absent tag stays absent, so an unpinned action reads as unpinned.
        // Canonical form sorts qualifiers by key — keep any addition here in
        // alphabetical order.
        let quals: Vec<String> = [
            registry.map(|r| format!("repository_url={}", r.replace('/', "%2F"))),
            tag.map(|t| format!("tag={t}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        let purl = format!("pkg:oci/{}", name.to_ascii_lowercase());
        return Some(RefLocator::Purl(if quals.is_empty() {
            purl
        } else {
            format!("{purl}?{}", quals.join("&"))
        }));
    }
    if uses.starts_with('.') {
        return None; // local action, ships in the repo
    }
    let (repo, git_ref) = uses.split_once('@')?;
    let mut segs = repo.split('/');
    let (owner, name) = (segs.next()?, segs.next()?);
    // Validate every component before it reaches the purl: a `uses:` value is
    // attacker-controlled (it comes from a scanned repo's workflow), and an
    // unescaped `?`/`&`/`@` in the ref would inject a purl qualifier — e.g.
    // `owner/repo@v1?repository_url=http://evil` redirects the fetch to an
    // attacker host. The ref keeps `/` (`refs/tags/x`); owner and name are bare
    // slugs. `purl_safe` also rejects `..`, so no ref walks the archive URL.
    if !purl_safe(owner, b"") || !purl_safe(name, b"") || !purl_safe(git_ref, b"/") {
        return None;
    }
    Some(RefLocator::Purl(format!(
        "pkg:github/{owner}/{name}@{git_ref}"
    )))
}

/// Whether a `uses:` component is safe to interpolate into a PURL: non-empty,
/// free of path traversal (`..`), and limited to identifier characters plus the
/// `extra` punctuation legal for its position (`/` in a ref path, `:` for a
/// registry port). Every PURL-syntax character (`?`, `#`, `&`, `@`, `%`),
/// whitespace, and control byte is rejected, so a component can neither open a
/// qualifier nor redirect the fetch.
/// Whether a container registry is well-formed enough to hand to a fetcher:
/// `host[:port]` plus optional namespace segments, each a real label.
///
/// Beyond [`purl_safe`] this requires every `/`-separated segment to be
/// non-empty and alphanumeric-led. `purl_safe` alone admits `//evil.example`,
/// which survives into `repository_url` and which a consumer resolving it as a
/// URL reads as protocol-relative — pointing the fetch at an attacker's host.
fn registry_safe(registry: &str) -> bool {
    purl_safe(registry, b"/:")
        && registry
            .split('/')
            .all(|seg| seg.starts_with(|c: char| c.is_ascii_alphanumeric()))
}

fn purl_safe(s: &str, extra: &[u8]) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') || extra.contains(&b)
        })
}

/// Relative `require`/`import`/`export … from`/dynamic `import()` targets in a
/// JS/TS source — the intra-package module graph the entry points alone don't
/// reveal (an npm trojan reaches its payload through `require('./util')`, not a
/// manifest field). Only relative specifiers (`./`, `../`) are intra-artifact
/// references; a bare package name is an external dependency, recorded
/// elsewhere. A consumer resolves each against the bundle's other files, so an
/// over-broad match that names no real file simply draws no edge.
fn js_local_refs(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let mut seen: Vec<&str> = Vec::new();
    for caps in js_relative_import_re().captures_iter(text) {
        let Some(spec) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if spec.is_empty() || seen.contains(&spec) {
            continue;
        }
        seen.push(spec);
        push_local_ref(out, spec, "import");
    }
}

/// Matches a relative module specifier in `require("./x")`, `import … from
/// "./x"`, `export … from "./x"`, side-effect `import "./x"`, and dynamic
/// `import("./x")`. The keyword gate plus a specifier that must start with `.`
/// keeps bare-package and non-import strings out; the closing quote keeps
/// `import.meta` / `fromCharCode` out.
fn js_relative_import_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"\b(?:require|import|from)\b\s*\(?\s*["'](\.[^"'\n]*)["']"#)
            .expect("js_relative_import_re compiles")
    })
}

/// `yarn.lock` (Yarn classic): one block per resolved package, headed by its
/// `"name@range":` spec key, with `version "x"` and `integrity "sha…"` lines.
/// The block's name + resolved version become an npm dependency; the integrity
/// is a verifiable pin. Registry is npm regardless of the `resolved` mirror URL.
fn yarn_lock(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let mut name: Option<&str> = None;
    let mut version: Option<&str> = None;
    let mut integrity: Option<&str> = None;
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("version ") {
                version = Some(v.trim_matches('"'));
            } else if let Some(i) = t.strip_prefix("integrity ") {
                integrity = Some(i.trim_matches('"'));
            }
        } else {
            // A new block header (or blank separator) flushes the previous block.
            flush_yarn(out, name, version, integrity);
            (name, version, integrity) = (yarn_key_name(line), None, None);
        }
    }
    flush_yarn(out, name, version, integrity);
}

/// Emit one yarn.lock block as an npm dependency, if it named a package and a
/// resolved version.
fn flush_yarn(out: &mut Refs<'_>, name: Option<&str>, version: Option<&str>, integ: Option<&str>) {
    let (Some(name), Some(version)) = (name, version) else {
        return;
    };
    out.push(
        RefLocator::Purl(npm_purl(name, version)),
        RefKind::Dependency,
        "yarn.lock",
        format!("{name}@{version}"),
        integ.and_then(parse_integrity),
    );
}

/// The package name from a yarn.lock block header — the first `name@range` of a
/// (possibly comma-separated, possibly quoted) spec key, with the range dropped.
fn yarn_key_name(line: &str) -> Option<&str> {
    // The header ends in `:`; splitting on the first one instead would cut an
    // alias spec (`"a@npm:b@^1":`) in half.
    let key = line
        .trim_end()
        .strip_suffix(':')?
        .split(',')
        .next()?
        .trim()
        .trim_matches('"');
    npm_alias_target(key).or_else(|| npm_spec(key).map(|(name, _)| name))
}

/// The package an npm alias points at, for a spec key spelled
/// `<local name>@npm:<real name>@<range>` — the form npm, Yarn and pnpm all
/// use. Only the aliased-to package exists upstream, so `string-width-cjs@npm:
/// string-width@^4.2.0` is a reference to `string-width`; taking the key at
/// face value asks the registry for a package that was never published.
///
/// `None` for Yarn Berry's per-entry protocol (`lodash@npm:^4.17.21`), where
/// what follows the protocol is a range rather than a package: a range holds no
/// `@` of its own, so requiring a `name@range` split there is enough to tell
/// the two apart.
fn npm_alias_target(spec: &str) -> Option<&str> {
    let (_, target) = spec.split_once("@npm:")?;
    let (name, _range) = npm_spec(target)?;
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '@' || c == '_')
        .then_some(name)
}

/// `pnpm-lock.yaml`: the `packages` map is keyed by `/name@version` (v6) or
/// `name@version` (v9), each with `resolution.integrity`. Peer-dependency
/// suffixes (`(react@18)`) and the leading `/` are stripped; the integrity is a
/// verifiable pin.
fn pnpm_lock(values: &Values, out: &mut Refs<'_>) {
    let Some(packages) = values
        .as_json()
        .get("packages")
        .and_then(JsonValue::as_object)
    else {
        return;
    };
    for (key, entry) in packages {
        let spec = key.trim_start_matches('/');
        let spec = spec.split('(').next().unwrap_or(spec);
        let Some((name, version)) = npm_spec(spec) else {
            continue;
        };
        // `alias@npm:real@1.2.3` — the version is the alias key's own, but the
        // package to fetch is the one aliased to.
        let name = npm_alias_target(spec).unwrap_or(name);
        let pin = entry
            .get("resolution")
            .and_then(|r| r.get("integrity"))
            .and_then(JsonValue::as_str)
            .and_then(parse_integrity);
        out.push(
            RefLocator::Purl(npm_purl(name, version)),
            RefKind::Dependency,
            "pnpm-lock.yaml",
            key.as_str(),
            pin,
        );
    }
}

/// Split a `name@version` spec into its parts, handling scoped names whose own
/// leading `@` is not the version separator. `None` if either part is empty.
fn npm_spec(spec: &str) -> Option<(&str, &str)> {
    match spec.rfind('@') {
        Some(0) | None => None,
        Some(i) => {
            let (name, version) = (&spec[..i], &spec[i + 1..]);
            (!name.is_empty() && !version.is_empty()).then_some((name, version))
        }
    }
}

/// `requirements.txt`: `name==version` exact pins. Version ranges (`>=`, `~=`),
/// unpinned names, `-r`/`-e`/`--option` lines, and comments are skipped — only
/// an exact pin names a fetchable artifact. Extras (`pkg[extra]`) and trailing
/// environment markers / `--hash` are stripped.
fn requirements_txt(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('-') {
            continue; // blank, comment, or an option / `-r include`
        }
        let Some((name_part, rest)) = line.split_once("==") else {
            continue; // not an exact pin
        };
        let name = name_part.split('[').next().unwrap_or(name_part).trim();
        // The version runs until whitespace, a `;` marker, or a `,` specifier.
        let version = rest
            .split([' ', '\t', ';', ','])
            .next()
            .unwrap_or(rest)
            .trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(
            RefLocator::Purl(pypi_purl(name, version)),
            RefKind::Dependency,
            "requirements.txt",
            line,
            None,
        );
    }
}

/// `poetry.lock`: every resolved `[[package]]` at its exact version. File hashes
/// live under `[package.files]` as a per-distribution list that doesn't map to a
/// single content pin, so these carry none.
fn poetry_lock(values: &Values, out: &mut Refs<'_>) {
    let Some(pkgs) = values
        .as_json()
        .get("package")
        .and_then(JsonValue::as_array)
    else {
        return;
    };
    for pkg in pkgs {
        let (Some(name), Some(version)) = (
            pkg.get("name").and_then(JsonValue::as_str),
            pkg.get("version").and_then(JsonValue::as_str),
        ) else {
            continue;
        };
        out.push(
            RefLocator::Purl(pypi_purl(name, version)),
            RefKind::Dependency,
            "poetry.lock",
            name,
            None,
        );
    }
}

/// `Pipfile.lock`: the `default` and `develop` sections, each mapping a package
/// name to a `{ "version": "==x.y.z" }` entry. Git/path entries without a pinned
/// version are skipped.
fn pipfile_lock(values: &Values, out: &mut Refs<'_>) {
    let root = values.as_json();
    for section in ["default", "develop"] {
        let Some(deps) = root.get(section).and_then(JsonValue::as_object) else {
            continue;
        };
        for (name, entry) in deps {
            let version = entry
                .get("version")
                .and_then(JsonValue::as_str)
                .map(|v| v.trim_start_matches("=="))
                .filter(|v| !v.is_empty());
            let Some(version) = version else { continue };
            out.push(
                RefLocator::Purl(pypi_purl(name, version)),
                RefKind::Dependency,
                format!("{section}.{name}"),
                name,
                None,
            );
        }
    }
}

/// `Gemfile.lock`: the resolved gems in the `GEM` section's `specs:` block, each
/// at indent 4 as `name (version)`. Only `GEM` (rubygems.org) sections are
/// fetchable — `GIT`/`PATH` gems resolve elsewhere and are skipped; sub-
/// dependency constraints (indent 6) are skipped too.
fn gemfile_lock(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let mut section = "";
    let mut in_specs = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            section = line.trim(); // GEM / GIT / PATH / PLATFORMS / …
            in_specs = false;
            continue;
        }
        if line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if !in_specs || section != "GEM" || indent != 4 {
            continue;
        }
        // A resolved gem line: `name (version)`.
        let Some((name, rest)) = line.trim().split_once(" (") else {
            continue;
        };
        let Some(version) = rest.strip_suffix(')') else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(
            RefLocator::Purl(format!("pkg:gem/{name}@{version}")),
            RefKind::Dependency,
            "Gemfile.lock",
            line.trim(),
            None,
        );
    }
}

/// A `.gem` archive's declared runtime dependencies, read from the
/// `gem.runtime_dependencies` names the gem extractor lifts out of `metadata.gz`.
/// A gemspec declares version *ranges* (`>= 0`, `~> 1.0`), not pins, so these are
/// unversioned `pkg:gem/<name>` PURLs that resolve to the current release through
/// rubygems.org at fetch time. Development dependencies are intentionally excluded
/// (the extractor already split them out). This is the gem counterpart to npm's
/// manifest-declared deps: without it a scanned gem would resolve no dependencies
/// at all, and a Ruby `require` is *not* a substitute — it is not npm, and its
/// specifier is a load path, not a gem name (`require "faraday/multipart"` loads
/// the `faraday-multipart` gem).
fn gem_runtime_deps(values: &Values, out: &mut Refs<'_>) {
    let Some(deps) = values
        .get_key(value_key!("gem.runtime_dependencies"))
        .and_then(JsonValue::as_array)
    else {
        return;
    };
    for dep in deps {
        let Some(name) = dep.as_str() else { continue };
        if name.is_empty() {
            continue;
        }
        out.push(
            RefLocator::Purl(format!("pkg:gem/{name}")),
            RefKind::Dependency,
            "gem.runtime_dependencies",
            name,
            None,
        );
    }
}

/// A VSIX extension's declared `<Dependency Id="publisher.name">` elements — the
/// other marketplace extensions it activates. Each resolves as a VS Code
/// Marketplace PURL (`pkg:vscode/<publisher>/<name>`), the same ecosystem the
/// extension itself belongs to — *not* npm, even though a VSIX is a zip of Node
/// code. The declared version is a range the marketplace resolver ignores, so
/// these are unversioned. An `Id` without the `publisher.name` shape isn't a
/// resolvable extension identity and is skipped rather than turned into a bad ref.
fn vsix_deps(values: &Values, out: &mut Refs<'_>) {
    let Some(deps) = values
        .get_key(value_key!("vsix.dependencies"))
        .and_then(JsonValue::as_array)
    else {
        return;
    };
    for dep in deps {
        let Some(id) = dep.get("id").and_then(JsonValue::as_str) else {
            continue;
        };
        let Some((publisher, name)) = id.split_once('.') else {
            continue;
        };
        if publisher.is_empty() || name.is_empty() {
            continue;
        }
        out.push(
            RefLocator::Purl(format!("pkg:vscode/{publisher}/{name}")),
            RefKind::Dependency,
            "vsix.dependencies",
            id,
            None,
        );
    }
}

/// `composer.lock`: the resolved `packages` and `packages-dev`, each at an exact
/// version. The download URL is not derivable from name+version, so these stay
/// PURLs and resolve through Packagist at fetch time; no pin (the lockfile's
/// `dist.shasum` is sha1 and frequently empty for VCS dists).
fn composer_lock(values: &Values, out: &mut Refs<'_>) {
    let root = values.as_json();
    for section in ["packages", "packages-dev"] {
        let Some(pkgs) = root.get(section).and_then(JsonValue::as_array) else {
            continue;
        };
        for pkg in pkgs {
            let (Some(name), Some(version)) = (
                pkg.get("name").and_then(JsonValue::as_str),
                pkg.get("version").and_then(JsonValue::as_str),
            ) else {
                continue;
            };
            out.push(
                RefLocator::Purl(format!("pkg:composer/{name}@{version}")),
                RefKind::Dependency,
                section,
                name,
                None,
            );
        }
    }
}

/// `pkg:pypi/<name>@<version>` with the name PEP 503-normalized (lowercase, runs
/// of `-_.` collapsed to one `-`) — the form PyPI's API and PURL both expect.
fn pypi_purl(name: &str, version: &str) -> String {
    let mut norm = String::with_capacity(name.len());
    let mut last_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_sep {
                norm.push('-');
                last_sep = true;
            }
        } else {
            norm.push(c.to_ascii_lowercase());
            last_sep = false;
        }
    }
    format!("pkg:pypi/{norm}@{version}")
}

/// `Cargo.toml`: the declared source repository (identity). The `[dependencies]`
/// are version *requirements* (ranges), not fetchable pins — those resolve in
/// `Cargo.lock`, mirroring npm's manifest/lockfile split.
fn cargo_toml(values: &Values, out: &mut Refs<'_>) {
    manifests::cargo(values, out);
    if let Some(repo) = document_str(values, "package.repository") {
        out.push(
            locator_from_repo(repo),
            RefKind::Repository,
            "package.repository",
            repo,
            None,
        );
    }
}

/// `Cargo.lock`: every `[[package]]` resolved to an exact version. Registry
/// crates carry a `checksum` (raw-content SHA-256, so it doubles as the hopper
/// content key); path/workspace/git entries have none and aren't fetchable from
/// crates.io, so they're skipped.
fn cargo_lock(values: &Values, out: &mut Refs<'_>) {
    let Some(pkgs) = values
        .as_json()
        .get("package")
        .and_then(JsonValue::as_array)
    else {
        return;
    };
    for pkg in pkgs {
        let (Some(name), Some(version), Some(checksum)) = (
            pkg.get("name").and_then(JsonValue::as_str),
            pkg.get("version").and_then(JsonValue::as_str),
            pkg.get("checksum").and_then(JsonValue::as_str),
        ) else {
            continue;
        };
        let pin = PinnedHash {
            algo: HashAlgo::Sha256,
            value: checksum.to_string(),
        };
        out.push(
            RefLocator::Purl(format!("pkg:cargo/{name}@{version}")),
            RefKind::Dependency,
            "Cargo.lock",
            checksum, // unique per entry → exact byte offset
            Some(pin),
        );
    }
}

/// Budget for whole-file evidence searches, in bytes scanned.
///
/// [`Refs::locate`] resumes from the previous match, which is linear while a
/// producer emits in document order. A producer that doesn't falls back to
/// searching the whole file per reference — O(N × file), quadratic in a
/// manifest that declares thousands. Measured before this budget existed: 40k
/// `uses:` steps in 1.5 MB cost 10.5 s, rising 4× per doubling, so a crafted
/// input scales to hours of CPU on one file. Once the budget is spent the
/// remaining offsets report 0, already the value for evidence we can't locate.
const MAX_LOCATE_SCAN: usize = 64 << 20;

/// Reference accumulator that also carries the raw file text for offsets.
struct Refs<'a> {
    refs: Vec<Reference>,
    text: Option<&'a str>,
    /// Where the last evidence was found; the next search resumes here.
    cursor: usize,
    /// Remaining whole-file search budget; see [`MAX_LOCATE_SCAN`].
    budget: usize,
}

impl Refs<'_> {
    /// Byte offset of `evidence`: its first occurrence at or after the previous
    /// match, else its first occurrence anywhere, else the package name / URL
    /// anchor, else 0.
    ///
    /// Resuming at the previous match is what keeps this linear, and it also
    /// sharpens repeated evidence: two steps that name the same action cite
    /// their own lines instead of both citing the first. The cursor never
    /// advances *past* a match, so a producer emitting two references for one
    /// span still gets that span twice.
    fn locate(&mut self, evidence: &str, locator: &RefLocator) -> u64 {
        let Some(text) = self.text else { return 0 };
        if let Some(at) = text.get(self.cursor..).and_then(|tail| tail.find(evidence)) {
            self.cursor += at;
            return self.cursor as u64;
        }
        if self.budget == 0 {
            return 0;
        }
        // A miss already cost a scan to end-of-file, and the fallback costs up
        // to two more; charge the pair.
        self.budget = self.budget.saturating_sub(text.len().saturating_mul(2));
        let found = text
            .find(evidence)
            .or_else(|| text.find(&anchor_from_locator(locator)));
        if let Some(at) = found {
            self.cursor = at;
        }
        found.unwrap_or(0) as u64
    }

    /// Push one reference, deriving its `offset`, and `content_sha256` from a
    /// SHA-256 pin (a sha256 pin *is* the content hash, so it doubles as the
    /// hopper key). Every producer goes through here so these rules live in
    /// one place.
    ///
    /// The offset always resolves to something citable: the start of
    /// `evidence`, else the start of the package name / URL (so a joined
    /// multi-line command still points at its package), else `0`.
    fn push(
        &mut self,
        locator: RefLocator,
        kind: RefKind,
        source: impl Into<String>,
        evidence: impl Into<String>,
        pinned_hash: Option<PinnedHash>,
    ) {
        let evidence = evidence.into();
        let offset = self.locate(&evidence, &locator);
        let content_sha256 = pinned_hash
            .as_ref()
            .filter(|p| p.algo == HashAlgo::Sha256)
            .map(|p| p.value.clone());
        self.refs.push(Reference {
            locator,
            kind,
            source: source.into(),
            evidence,
            offset,
            pinned_hash,
            content_sha256,
        });
    }
}

/// A findable substring for locating a reference when its full `evidence`
/// isn't verbatim in the file — the URL, or a PURL's package name with the
/// `%40` scope decoded back to `@` and the version stripped.
fn anchor_from_locator(loc: &RefLocator) -> String {
    match loc {
        RefLocator::Url(u) => u.clone(),
        RefLocator::Path(p) => p.clone(),
        RefLocator::Purl(p) => {
            let body = p.strip_prefix("pkg:").unwrap_or(p);
            let body = body.split_once('/').map_or(body, |(_, rest)| rest); // drop type
            let name = body.split('@').next().unwrap_or(body); // drop @version
            name.replace("%40", "@")
        }
    }
}

/// npm: the declared source repository (identity). Install-hook command/URL
/// hunting lives in `fletch::find`.
fn npm(values: &Values, out: &mut Refs<'_>) {
    if let Some(repo) = values
        .get_key(value_key!("npm.repository.url"))
        .and_then(JsonValue::as_str)
    {
        out.push(
            locator_from_repo(repo),
            RefKind::Repository,
            "npm.repository.url",
            repo,
            None,
        );
    }
    npm_manifest_deps(out);
    npm_local_refs(out);
    vscode_extension_deps(out);
}

/// `extensionDependencies` and `extensionPack` from a VS Code extension
/// manifest, as `pkg:vscode/<publisher>/<name>` dependencies.
///
/// These are declared install-time dependencies in the strongest sense the
/// editor has: it refuses to install the extension without what
/// `extensionDependencies` names, and installs everything in `extensionPack`
/// alongside it. They belong here with the other manifest-declared coordinates
/// rather than in a consumer's value-driven hunt, because only references
/// emitted at parse time survive into an archive member's retained facts — and
/// a VSIX is an archive, so a hunt that reads the values tree never sees them.
///
/// Following them is what makes the interesting artifact reachable: an
/// extension pack contributes no code of its own and exists to bring its
/// entries along. It also makes the *failure* observable — an entry the
/// marketplace no longer serves was pulled, and extensions get pulled for
/// reasons.
///
/// Unversioned: a manifest names the extension, never a version.
fn vscode_extension_deps(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let Ok(manifest) = serde_json::from_str::<JsonValue>(text) else {
        return;
    };
    for field in ["extensionDependencies", "extensionPack"] {
        let Some(entries) = manifest.get(field).and_then(JsonValue::as_array) else {
            continue;
        };
        for id in entries.iter().filter_map(JsonValue::as_str) {
            // A marketplace id is `publisher.name`; neither half may itself
            // contain a dot, so anything else is not an extension coordinate.
            let Some((publisher, name)) = id.split_once('.') else {
                continue;
            };
            if !is_marketplace_segment(publisher) || !is_marketplace_segment(name) {
                continue;
            }
            out.push(
                RefLocator::Purl(format!("pkg:vscode/{publisher}/{name}")),
                RefKind::Dependency,
                field,
                id,
                None,
            );
        }
    }
}

/// Marketplace publisher and extension names are ASCII alphanumerics with
/// hyphens or underscores. Rejecting anything else keeps paths, versions and
/// free text out of the dependency list.
fn is_marketplace_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Intra-artifact file references a `package.json` names: the entry module
/// (`main`/`module`), the `exports` map's targets, and the executables (`bin`).
/// Each points at a sibling file in the same package, so a consumer resolves it
/// against the bundle's other members rather than fetching it. A no-op for a
/// binary `.tgz` (no text). The initial, deliberately small set of inter-file
/// producers — relative `import`/`require` targets and HTML `src` can follow.
fn npm_local_refs(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let Ok(manifest) = serde_json::from_str::<JsonValue>(text) else {
        return;
    };
    // Dedup identical targets — `exports` routinely repeats `main` and lists one
    // file under several conditions (`require`/`import`/`default`).
    let mut seen: Vec<String> = Vec::new();
    let mut emit = |out: &mut Refs<'_>, path: &str, source: &str| {
        if path.is_empty() || path.contains('*') {
            return; // empty, or a subpath pattern (`./*`) that names no one file
        }
        if seen.iter().any(|p| p == path) {
            return;
        }
        seen.push(path.to_string());
        push_local_ref(out, path, source);
    };

    // Single-string entry-point fields.
    for (field, source) in [
        ("main", "package.json:main"),
        ("module", "package.json:module"),
    ] {
        if let Some(path) = manifest.get(field).and_then(JsonValue::as_str) {
            emit(out, path, source);
        }
    }
    // `exports`: the modern entry map. Its leaf string values are file targets
    // (`{".": {"require": "./index.js", "import": "./index.mjs"}}`); subpath
    // patterns (`"./*"`) are skipped above.
    if let Some(exports) = manifest.get("exports") {
        let mut paths = Vec::new();
        collect_export_paths(exports, &mut paths);
        for path in paths {
            emit(out, &path, "package.json:exports");
        }
    }
    // `bin`: either a single path (the package's lone binary) or a name→path map.
    match manifest.get("bin") {
        Some(JsonValue::String(path)) => emit(out, path, "package.json:bin"),
        Some(JsonValue::Object(map)) => {
            for path in map.values().filter_map(JsonValue::as_str) {
                emit(out, path, "package.json:bin");
            }
        }
        _ => {}
    }
}

/// Collect every relative-path string leaf (`./…`) from an `exports` value,
/// which nests arbitrarily: a string, a conditions object, a subpath map, or an
/// array of fallbacks. Non-relative entries (bare package names in a fallback
/// array) are not intra-artifact references and are left out.
fn collect_export_paths(value: &JsonValue, out: &mut Vec<String>) {
    match value {
        JsonValue::String(s) if s.starts_with("./") => out.push(s.clone()),
        JsonValue::Object(map) => {
            for v in map.values() {
                collect_export_paths(v, out);
            }
        }
        JsonValue::Array(arr) => {
            for v in arr {
                collect_export_paths(v, out);
            }
        }
        _ => {}
    }
}

/// Emit one intra-artifact file reference, skipping an empty target.
fn push_local_ref(out: &mut Refs<'_>, path: &str, source: &str) {
    if path.is_empty() {
        return;
    }
    out.push(
        RefLocator::Path(path.to_string()),
        RefKind::Local,
        source,
        path,
        None,
    );
}

/// Declared runtime dependencies of a `package.json`, read from the manifest
/// text — the dependency map is not mirrored into `values`. Each becomes a
/// fetchable npm reference: an exact pin (`1.2.3`) resolves straight to its
/// tarball like a lockfile entry, while a range, dist-tag, or wildcard is
/// emitted as an unversioned coordinate with its spec preserved for the
/// fetcher to resolve against the registry. Only `dependencies` and
/// `optionalDependencies` are followed — `devDependencies` and
/// `peerDependencies` are not installed for a consumed package, so they are not
/// part of the delivered supply chain. A no-op for a binary `.tgz` (no text).
fn npm_manifest_deps(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let Ok(manifest) = serde_json::from_str::<JsonValue>(text) else {
        return;
    };
    for field in ["dependencies", "optionalDependencies"] {
        let Some(deps) = manifest.get(field).and_then(JsonValue::as_object) else {
            continue;
        };
        for (name, spec) in deps {
            let Some(spec) = spec.as_str() else { continue };
            let Some(locator) = npm_dep_locator(name, spec) else {
                continue;
            };
            out.push(
                locator,
                RefKind::Dependency,
                "package.json",
                format!("{name}@{spec}"),
                None,
            );
        }
    }
}

/// Where an npm dependency spec actually points. A spec is not always a
/// registry range: npm and its alternatives accept several protocols, and only
/// the registry ones name a package *on the registry* under the map's key.
/// Deriving the PURL from the key regardless is wrong in both directions — it
/// invents a coordinate that either does not exist (`"@scope/shared":
/// "workspace:*"`) or, worse, names an unrelated published package that happens
/// to share the key (`"link-dep": "link:../other"` resolving to the real
/// `link-dep` on npm) — while the dependency that is actually delivered goes
/// unrecorded.
///
/// - `workspace:` / `catalog:` / `file:` / `link:` / `portal:`, and a bare
///   relative path: the code is inside the artifact or its workspace, so
///   nothing external is delivered and there is no reference to record.
/// - `npm:name[@range]`: an alias. The delivered package is the *aliased* one;
///   the key is only the name it is imported under locally.
/// - `git+…`, `git://`, `http(s)://`, and the `github:`/`gitlab:`/`bitbucket:`
///   and bare `owner/repo` shorthands: fetched from a forge or URL, never from
///   the registry.
/// - anything else: a range, dist-tag, or exact version of the key's own
///   package — the one case where the key *is* the coordinate.
fn npm_dep_locator(name: &str, spec: &str) -> Option<RefLocator> {
    if is_local_npm_spec(spec) {
        return None;
    }
    if let Some(alias) = spec.strip_prefix("npm:") {
        let (aliased, range) = split_npm_alias(alias);
        return npm_registry_locator(aliased, range);
    }
    if let Some(locator) = npm_remote_locator(spec) {
        return Some(locator);
    }
    npm_registry_locator(name, spec)
}

/// A registry coordinate: versioned when the spec pins one exact version,
/// versionless otherwise for the fetcher to resolve.
fn npm_registry_locator(name: &str, spec: &str) -> Option<RefLocator> {
    (!name.is_empty()).then(|| {
        RefLocator::Purl(if is_exact_npm_version(spec) {
            npm_purl(name, spec)
        } else {
            npm_purl_unversioned(name, spec)
        })
    })
}

/// Whether a spec resolves to code already on disk — a workspace sibling, a
/// pnpm catalog entry (itself declared in the workspace manifest), or a plain
/// path. None of these is fetchable, and all of them are inside the artifact
/// already, where they are scanned in place.
fn is_local_npm_spec(spec: &str) -> bool {
    const LOCAL_PROTOCOLS: [&str; 5] = ["workspace:", "catalog:", "file:", "link:", "portal:"];
    const LOCAL_PATHS: [&str; 4] = ["./", "../", "/", "~/"];
    LOCAL_PROTOCOLS.iter().any(|p| spec.starts_with(p))
        || LOCAL_PATHS.iter().any(|p| spec.starts_with(p))
}

/// Split an `npm:` alias body into the aliased package and its range. The name
/// may be scoped, so the separating `@` is the one after position 0; with no
/// range the requirement is empty and the alias tracks the registry's current
/// release.
fn split_npm_alias(alias: &str) -> (&str, &str) {
    let at = match alias.strip_prefix('@') {
        Some(scoped) => scoped.find('@').map(|i| i + 1),
        None => alias.find('@'),
    };
    at.map_or((alias, ""), |i| (&alias[..i], &alias[i + 1..]))
}

/// A spec fetched from a forge or a URL rather than the registry, as its
/// locator — a forge PURL where the host is one, else the URL verbatim.
/// `None` when the spec is not remote.
///
/// npm's commit-ish fragment is bare (`#v1.2.3`, `#main`) rather than the
/// `#tag=`/`#commit=` form [`source_locator`] parses, so it is applied here;
/// a `#semver:` fragment is a range, not a pin, and contributes no version.
fn npm_remote_locator(spec: &str) -> Option<RefLocator> {
    let (base, fragment) = spec
        .split_once('#')
        .map_or((spec, None), |(b, f)| (b, Some(f)));
    let url = npm_forge_shorthand(base).unwrap_or_else(|| base.to_string());
    let locator = source_locator(&url)?;
    let version = fragment.filter(|f| !f.is_empty() && !f.starts_with("semver:"));
    match (locator, version) {
        (RefLocator::Purl(purl), Some(version)) => {
            Some(RefLocator::Purl(format!("{purl}@{version}")))
        }
        (locator, _) => Some(locator),
    }
}

/// The forge URL an npm shorthand abbreviates: `github:owner/repo` and its
/// `gitlab:`/`bitbucket:` siblings, plus the bare `owner/repo` form npm reads
/// as GitHub. `None` for anything else, including a spec carrying some other
/// protocol — a local one is already gone by here, and a real URL needs no
/// expansion.
fn npm_forge_shorthand(spec: &str) -> Option<String> {
    let (host, path) = match spec.split_once(':') {
        Some(("github", path)) => ("github.com", path),
        Some(("gitlab", path)) => ("gitlab.com", path),
        Some(("bitbucket", path)) => ("bitbucket.org", path),
        Some(_) => return None,
        // A range never contains `/`, so an unprefixed `owner/repo` is GitHub.
        None => ("github.com", spec),
    };
    let (owner, repo) = path.split_once('/')?;
    (!owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
        .then(|| format!("https://{host}/{owner}/{repo}"))
}

/// An npm PURL with no pinned version, retaining the declared range or tag as
/// a qualifier so the fetcher can resolve exactly what the package manager
/// would install. A rangeless or wildcard spec is the bare coordinate.
fn npm_purl_unversioned(name: &str, spec: &str) -> String {
    let mut purl = match name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Some((scope, pkg)) => format!("pkg:npm/%40{scope}/{pkg}"),
        None => format!("pkg:npm/{name}"),
    };
    push_version_requirement(&mut purl, spec);
    purl
}

/// Append a declared install constraint to an unversioned PURL as a
/// `version_requirement` qualifier. PURL itself has no range syntax, so this
/// is a house convention for the fetcher; an empty or `*` requirement carries
/// no information and is omitted, leaving the plain coordinate.
fn push_version_requirement(purl: &mut String, requirement: &str) {
    let requirement = requirement.trim();
    if requirement.is_empty() || requirement == "*" {
        return;
    }
    purl.push_str("?version_requirement=");
    purl.push_str(&purl_encode(requirement));
}

/// Percent-encode a PURL component, keeping only the unreserved characters.
fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Whether an npm dependency spec is a single concrete version
/// (`MAJOR.MINOR.PATCH[-prerelease]`) rather than a range, comparator, union,
/// dist-tag, or partial/wildcard. Errs toward "not exact": a misjudged exact
/// would build a bogus tarball URL, whereas a non-exact keeps its install
/// requirement or dist-tag for the fetcher.
fn is_exact_npm_version(spec: &str) -> bool {
    spec.starts_with(|c: char| c.is_ascii_digit())
        && spec.split('.').count() >= 3
        && !spec.contains(['^', '~', '>', '<', '=', '|', '*', 'x', 'X', ' '])
}

/// npm `package-lock.json`: every locked dependency, with the `integrity`
/// pin the lockfile commits to. The whole lockfile is already parsed into
/// `values` verbatim, so this walks the JSON tree directly.
///
/// Lockfile v2/v3 keys deps by install path under `packages`; v1 keys them
/// by name under `dependencies`. Both carry `version` and `integrity`.
fn npm_lock(values: &Values, out: &mut Refs<'_>) {
    let root = values.as_json();
    if let Some(pkgs) = root.get("packages").and_then(JsonValue::as_object) {
        for (path, entry) in pkgs {
            // "" is the root project, not a dependency.
            let Some(name) = dep_name_from_path(path) else {
                continue;
            };
            // `path` is the lockfile's own key — findable in the bytes, so
            // it doubles as the entry's evidence.
            push_locked_dep(out, name, entry, &format!("packages.{path}"), path);
        }
    }
    if let Some(deps) = root.get("dependencies").and_then(JsonValue::as_object) {
        for (name, entry) in deps {
            push_locked_dep(out, name, entry, &format!("dependencies.{name}"), name);
        }
    }
}

/// The package name from a v2/v3 `packages` key, which is an install path
/// like `node_modules/foo` or `node_modules/a/node_modules/@scope/bar`.
/// The dependency is whatever follows the last `node_modules/`.
fn dep_name_from_path(path: &str) -> Option<&str> {
    let name = path.rsplit("node_modules/").next()?;
    (!name.is_empty() && name != path).then_some(name)
}

/// Push one locked dependency: `pkg:npm/...@version` with its `integrity`
/// pin. Skipped if it has no version (a bare reference, not a resolved
/// package).
fn push_locked_dep(
    out: &mut Refs<'_>,
    name: &str,
    entry: &JsonValue,
    source: &str,
    evidence: &str,
) {
    let Some(version) = entry.get("version").and_then(JsonValue::as_str) else {
        return;
    };
    // An alias installs one package under another name, and only the real
    // package exists on the registry: `node_modules/string-width-cjs` fetches
    // `string-width`. v2/v3 record the real package in `name`; v1 folds it into
    // the version as `npm:<name>@<version>`.
    let (name, version) = match version.strip_prefix("npm:").and_then(npm_spec) {
        Some(aliased) => aliased,
        None => (
            entry
                .get("name")
                .and_then(JsonValue::as_str)
                .filter(|aliased| !aliased.is_empty())
                .unwrap_or(name),
            version,
        ),
    };
    let pinned_hash = entry
        .get("integrity")
        .and_then(JsonValue::as_str)
        .and_then(parse_integrity);
    out.push(
        RefLocator::Purl(npm_purl(name, version)),
        RefKind::Dependency,
        source,
        evidence,
        pinned_hash,
    );
}

/// `pkg:npm/name@version`, scope `@s/n` encoded as the PURL namespace
/// `%40s/n`.
fn npm_purl(name: &str, version: &str) -> String {
    match name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Some((scope, pkg)) => format!("pkg:npm/%40{scope}/{pkg}@{version}"),
        None => format!("pkg:npm/{name}@{version}"),
    }
}

/// Parse an npm Subresource Integrity string (`sha512-<base64>`, possibly
/// space-separated alternatives — take the first).
fn parse_integrity(s: &str) -> Option<PinnedHash> {
    let first = s.split_whitespace().next()?;
    let (algo, value) = first.split_once('-')?;
    let algo = match algo {
        "sha512" => HashAlgo::Sha512,
        "sha256" => HashAlgo::Sha256,
        "sha1" => HashAlgo::Sha1,
        _ => return None,
    };
    (!value.is_empty()).then(|| PinnedHash {
        algo,
        value: value.to_string(),
    })
}

/// Arch / AUR `.SRCINFO`: declared package dependencies and build sources.
/// This is the PKGBUILD's machine-readable metadata, already parsed under
/// `pkg.*` by `pkgmeta::extract_srcinfo`, so no bash is parsed here.
fn srcinfo(values: &Values, out: &mut Refs<'_>) {
    let Some(pkg) = values
        .get_key(value_key!("pkg"))
        .and_then(JsonValue::as_object)
    else {
        return;
    };

    // Declared pacman dependencies. A *foreign* one — not in the official
    // repos — is the AUR bootstrap vector (`depends = bun` pulls an npm
    // runtime); whether it is foreign is a downstream resolution question,
    // so every declared dep is recorded.
    for field in ["depends", "makedepends"] {
        for dep in str_array(pkg.get(field)) {
            let name = alpm_pkg_name(dep);
            if name.is_empty() {
                continue;
            }
            out.push(
                RefLocator::Purl(format!("pkg:alpm/arch/{name}")),
                RefKind::Dependency,
                format!("pkg.{field}"),
                dep,
                None,
            );
        }
    }

    // Build sources, each paired positionally with its `sha256sums` pin.
    // URL sources become refs; bare filenames are in-archive members, not
    // external, so they are skipped. A real `sha256sums` entry is the
    // source's SHA-256 — `Refs::push` lifts it into `content_sha256`.
    let sources = str_array(pkg.get("source"));
    let sums = str_array(pkg.get("sha256sums"));
    for (i, src) in sources.iter().enumerate() {
        let Some(locator) = source_locator(src) else {
            continue;
        };
        let pin = sums.get(i).copied().and_then(sha256_pin);
        out.push(locator, RefKind::Dependency, "pkg.source", *src, pin);
    }
}

/// A pacman dependency name with its version constraint stripped:
/// `boost>=1.69.0` → `boost`.
fn alpm_pkg_name(dep: &str) -> &str {
    dep.split(['>', '<', '=']).next().unwrap_or(dep).trim()
}

/// A `source=()` entry's locator, or `None` if it is a bare local filename.
/// Handles the `name::url` rename form and a `#tag=`/`#commit=` fragment;
/// a git forge URL normalizes to a PURL (with the tag/commit as version).
fn source_locator(src: &str) -> Option<RefLocator> {
    let url = src.rsplit("::").next().unwrap_or(src); // drop `name::` rename
    let (base, frag) = url
        .split_once('#')
        .map_or((url, None), |(b, f)| (b, Some(f)));
    let scheme_part = base
        .trim_start_matches("git+")
        .trim_start_matches("hg+")
        .trim_start_matches("svn+")
        .trim_start_matches("bzr+");
    let is_remote = ["https://", "http://", "ftp://", "git://"]
        .iter()
        .any(|s| scheme_part.starts_with(s));
    if !is_remote {
        return None; // local filename
    }
    if let Some(purl) = purl_from_forge(base) {
        let version = frag.and_then(frag_version);
        return Some(RefLocator::Purl(
            version.map_or(purl.clone(), |v| format!("{purl}@{v}")),
        ));
    }
    Some(RefLocator::Url(scheme_part.to_string()))
}

/// The pinned ref from a VCS fragment: `tag=V1.2` / `commit=abc` → the value.
fn frag_version(frag: &str) -> Option<String> {
    frag.split('&')
        .find_map(|p| p.strip_prefix("tag=").or_else(|| p.strip_prefix("commit=")))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// A `sha256sums` entry as a pin, if it is a real 64-hex digest. `SKIP`
/// and non-hex values are verification opt-outs, not digests.
fn sha256_pin(s: &str) -> Option<PinnedHash> {
    let s = s.trim();
    let is_hex = s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    is_hex.then(|| PinnedHash {
        algo: HashAlgo::Sha256,
        value: s.to_ascii_lowercase(),
    })
}

/// Collect a `values` field that is an array of strings (or a lone string).
fn str_array(v: Option<&JsonValue>) -> Vec<&str> {
    match v {
        Some(JsonValue::Array(a)) => a.iter().filter_map(JsonValue::as_str).collect(),
        Some(JsonValue::String(s)) => vec![s.as_str()],
        _ => Vec::new(),
    }
}

/// Normalize a repository URL to a PURL when the host is a known forge,
/// else keep it as a raw URL. PURL is canonical, so
/// `git+https://github.com/a/b.git` and `https://github.com/a/b` both
/// collapse to `pkg:github/a/b`.
fn locator_from_repo(repo: &str) -> RefLocator {
    purl_from_forge(repo).map_or_else(|| RefLocator::Url(repo.to_string()), RefLocator::Purl)
}

/// `pkg:github/owner/repo` (or gitlab/bitbucket) from a forge URL, if it
/// is one. Namespace and name are lowercased for canonical form.
///
/// Only a *bare* `owner/repo` path (optionally `.git`) is a whole-repo
/// reference. A deeper path — `owner/repo/releases/download/v1/asset.zip`,
/// `owner/repo/archive/v1.tar.gz` — points at one specific artifact, not the
/// repo, so it is declined; the caller keeps the URL and fetches it verbatim
/// (matching its `sha256sums` pin). Collapsing such a URL to `pkg:github/
/// owner/repo` would resolve to the source tree at HEAD — the wrong bytes.
fn purl_from_forge(repo: &str) -> Option<String> {
    let s = repo.trim_start_matches("git+");
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))?;
    let rest = rest.strip_prefix("www.").unwrap_or(rest);
    let (host, path) = rest.split_once('/')?;
    let ty = match host {
        "github.com" => "github",
        "gitlab.com" => "gitlab",
        "bitbucket.org" => "bitbucket",
        _ => return None,
    };
    let path = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/');
    let mut parts = path.split('/');
    let owner = parts.next().filter(|s| !s.is_empty())?;
    let name = parts.next().filter(|s| !s.is_empty())?;
    if parts.next().is_some() {
        return None; // deeper than owner/repo: a specific artifact, not the repo
    }
    Some(format!(
        "pkg:{ty}/{}/{}",
        owner.to_ascii_lowercase(),
        name.to_ascii_lowercase()
    ))
}

/// A string at `path` in a manifest's verbatim document tree, such as
/// `package.repository` in a `Cargo.toml`. The path comes from the manifest
/// format, not from an extractor, so it is not a cataloged value key.
fn document_str<'a>(values: &'a Values, path: &str) -> Option<&'a str> {
    values.get(path).and_then(JsonValue::as_str)
}

#[cfg(test)]
mod tests;
