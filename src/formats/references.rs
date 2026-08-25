//! Reference extraction — the external packages and URLs an artifact points
//! at, plus the intra-artifact files it names (a manifest entry point), folded
//! across formats into [`Reference`] rows.
//!
//! Mirrors [`super::identity`]: format parsers write `values`, and
//! [`derive`] reads them back into one typed view. PURL is preferred over
//! a raw URL wherever the ecosystem is identifiable, for disambiguation; an
//! intra-artifact target is a [`RefLocator::Path`].

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value as JsonValue;

use crate::fileid::FileType;
use crate::output::{HashAlgo, PinnedHash, RefKind, RefLocator, Reference, Values};

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
    // Only declared, structured dependencies live here. Imperative/undeclared
    // recognition (install-hook commands, shell/Dockerfile `npm install`,
    // `curl | sh`, URLs in variables) is fletch's `find`, which consumes these
    // facts and adds the hunted refs.
    match file_type {
        FileType::Npm | FileType::PackageJson => npm(values, &mut out),
        FileType::PackageLockJson => npm_lock(values, &mut out),
        FileType::SrcInfo => srcinfo(values, &mut out),
        FileType::GoMod => go_mod(&mut out),
        FileType::GoSum => go_sum(&mut out),
        FileType::CargoToml => cargo_toml(values, &mut out),
        FileType::CargoLock => cargo_lock(values, &mut out),
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
    let key = line
        .split(':')
        .next()?
        .split(',')
        .next()?
        .trim()
        .trim_matches('"');
    npm_spec(key).map(|(name, _)| name)
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
        .get("gem.runtime_dependencies")
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
        .get("vsix.dependencies")
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
    if let Some(repo) = get_str(values, "package.repository") {
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

/// `require` directives in a `go.mod` — the module's declared dependencies, each
/// pinned to an exact version (Go has no version ranges). Handles both the
/// single-line (`require mod v1.2.3`) and block (`require (\n  mod v1.2.3\n)`)
/// forms; an `// indirect` trailer is informational and dropped. Hashes live in
/// `go.sum`, so these carry no pin.
fn go_mod(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    let mut in_block = false;
    for line in text.lines() {
        let line = strip_line_comment(line).trim();
        // The `require` directive is the word followed by whitespace or `(` —
        // not merely a prefix of a module path like `require.dev/x`.
        let directive = line
            .strip_prefix("require")
            .filter(|rest| rest.is_empty() || rest.starts_with(['(', ' ', '\t']));
        if let Some(rest) = directive {
            let rest = rest.trim_start();
            if rest == "(" {
                in_block = true;
            } else if !rest.is_empty() {
                push_go_dep(out, rest, "go.mod"); // single-line require
            }
        } else if in_block {
            if line == ")" {
                in_block = false;
            } else if !line.is_empty() {
                push_go_dep(out, line, "go.mod");
            }
        }
    }
}

/// `go.sum` lines: `<module> <version> h1:<base64>` pins the module zip;
/// `<module> <version>/go.mod h1:<base64>` pins only its go.mod. Emit a pinned
/// reference for the former (the fetchable artifact); skip the `/go.mod` lines.
fn go_sum(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(module), Some(version), Some(hash)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(h1) = hash.strip_prefix("h1:") else {
            continue;
        };
        if version.ends_with("/go.mod") {
            continue;
        }
        let pin = PinnedHash {
            algo: HashAlgo::GoModH1,
            value: h1.to_string(),
        };
        out.push(
            RefLocator::Purl(go_purl(module, version)),
            RefKind::Dependency,
            "go.sum",
            line.trim(),
            Some(pin),
        );
    }
}

/// Push a `module version` pair (a `go.mod` require line or block entry) as a
/// Go dependency. Ignores malformed lines that aren't `path version`.
fn push_go_dep(out: &mut Refs<'_>, entry: &str, source: &str) {
    let mut fields = entry.split_whitespace();
    let (Some(module), Some(version)) = (fields.next(), fields.next()) else {
        return;
    };
    out.push(
        RefLocator::Purl(go_purl(module, version)),
        RefKind::Dependency,
        source,
        entry,
        None,
    );
}

/// `pkg:golang/<module>@<version>`. The module path keeps its real case (the
/// case-folding GOPROXY needs is a transport concern, applied at fetch time).
fn go_purl(module: &str, version: &str) -> String {
    format!("pkg:golang/{module}@{version}")
}

/// Drop a `//` line comment (e.g. `go.mod`'s `// indirect`), leaving the rest.
fn strip_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(code, _)| code)
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
    if let Some(repo) = get_str(values, "npm.repository.url") {
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
/// emitted versionless for the fetcher to resolve against the registry. Only
/// `dependencies`/`optionalDependencies` are followed — `devDependencies` and
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
            npm_purl_unversioned(name)
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
/// range the alias tracks whatever the registry serves (`*`).
fn split_npm_alias(alias: &str) -> (&str, &str) {
    let at = match alias.strip_prefix('@') {
        Some(scoped) => scoped.find('@').map(|i| i + 1),
        None => alias.find('@'),
    };
    at.map_or((alias, "*"), |i| (&alias[..i], &alias[i + 1..]))
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

/// An npm PURL with no version — a manifest dependency whose declared spec is a
/// range/tag/wildcard rather than a single version. The fetcher resolves it to
/// the registry's current release.
fn npm_purl_unversioned(name: &str) -> String {
    match name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Some((scope, pkg)) => format!("pkg:npm/%40{scope}/{pkg}"),
        None => format!("pkg:npm/{name}"),
    }
}

/// Whether an npm dependency spec is a single concrete version
/// (`MAJOR.MINOR.PATCH[-prerelease]`) rather than a range, comparator, union,
/// dist-tag, or partial/wildcard. Errs toward "not exact": a misjudged exact
/// would build a bogus tarball URL, whereas a non-exact simply resolves to the
/// registry's current version.
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
    let Some(pkg) = values.as_json().get("pkg").and_then(JsonValue::as_object) else {
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

fn get_str<'a>(values: &'a Values, key: &str) -> Option<&'a str> {
    values.get(key).and_then(JsonValue::as_str)
}

#[cfg(test)]
mod tests {
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
        // anything else → versionless PURL for the fetcher to resolve.
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
        assert!(purls.contains(&"pkg:npm/easy-day-js"), "{purls:?}");
        assert!(purls.contains(&"pkg:npm/%40scope/util"), "{purls:?}");
        assert!(purls.contains(&"pkg:npm/fsevents"), "{purls:?}");
        assert!(
            !purls.iter().any(|p| p.contains("typescript")),
            "devDependencies must not be fetched: {purls:?}"
        );
        // The declared range is preserved as evidence for the report.
        let easy = refs
            .iter()
            .find(|r| matches!(&r.locator, RefLocator::Purl(p) if p == "pkg:npm/easy-day-js"))
            .expect("easy-day-js ref");
        assert_eq!(easy.evidence, "easy-day-js@^1.11.21");
        assert_eq!(easy.kind, RefKind::Dependency);
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
        assert!(has("pkg:npm/%40scope/util"), "{locators:?}");
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
        // The ordinary registry range is untouched.
        assert!(has("pkg:npm/range-dep"), "{locators:?}");
        assert_eq!(refs.len(), 8, "one ref per non-local spec: {locators:?}");
    }

    #[test]
    fn npm_alias_splits_scoped_and_unversioned_forms() {
        assert_eq!(split_npm_alias("left-pad@1.3.0"), ("left-pad", "1.3.0"));
        assert_eq!(split_npm_alias("@scope/util@^2"), ("@scope/util", "^2"));
        assert_eq!(split_npm_alias("@scope/util"), ("@scope/util", "*"));
        assert_eq!(split_npm_alias("left-pad"), ("left-pad", "*"));
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
        assert_eq!(main.offset as usize, text.find("./lib/index.js").unwrap());
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
            .find(|r| {
                r.locator == RefLocator::Purl("pkg:github/nanocurrency/nano-node@V22.1".into())
            })
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
        let asset =
            "https://github.com/be5invis/Iosevka/releases/download/v34.7.0/PkgTTF-Iosevka.zip";
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
    fn go_sum_pins_module_zips_and_skips_go_mod_lines() {
        let gosum = b"github.com/foo/bar v1.2.3 h1:AAAA=\n\
            github.com/foo/bar v1.2.3/go.mod h1:BBBB=\n";
        let refs = derive(FileType::GoSum, gosum, &Values::new());
        assert_eq!(
            refs.len(),
            1,
            "only the module-zip line, not the /go.mod line"
        );
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
                yaml[r.offset as usize..].starts_with(&r.evidence),
                "offset {} must cite {:?}",
                r.offset,
                r.evidence
            );
        }
        // Distinct evidence in document order lands exactly where a whole-file
        // search would.
        for r in &refs[..64] {
            assert_eq!(r.offset as usize, yaml.find(&r.evidence).unwrap());
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
}
