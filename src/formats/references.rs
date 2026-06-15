//! External-reference extraction — the packages and URLs an artifact
//! points at, folded across formats into [`ExternalRef`] rows.
//!
//! Mirrors [`super::identity`]: format parsers write `values`, and
//! [`derive`] reads them back into one typed view. PURL is preferred over
//! a raw URL wherever the ecosystem is identifiable, for disambiguation.

use serde_json::Value as JsonValue;

use crate::fileid::FileType;
use crate::output::{ExternalRef, HashAlgo, PinnedHash, RefKind, RefLocator, Values};

/// Derive external references from a parsed file's `values`. `bytes` is the
/// raw file, used to locate each reference's `evidence` for its byte offset.
pub(crate) fn derive(file_type: FileType, bytes: &[u8], values: &Values) -> Vec<ExternalRef> {
    let mut out = Refs {
        refs: Vec::new(),
        // UTF-8 text manifests can be searched for offsets; binary or
        // compressed sources (an npm `.tgz`) cannot.
        text: std::str::from_utf8(bytes).ok(),
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
        FileType::ComposerLock => composer_lock(values, &mut out),
        FileType::YarnLock => yarn_lock(&mut out),
        FileType::PnpmLock => pnpm_lock(values, &mut out),
        _ => {}
    }
    out.refs
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

/// Reference accumulator that also carries the raw file text for offsets.
struct Refs<'a> {
    refs: Vec<ExternalRef>,
    text: Option<&'a str>,
}

impl Refs<'_> {
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
        let offset = self
            .text
            .and_then(|t| {
                t.find(&evidence)
                    .or_else(|| t.find(&anchor_from_locator(&locator)))
            })
            .unwrap_or(0) as u64;
        let content_sha256 = pinned_hash
            .as_ref()
            .filter(|p| p.algo == HashAlgo::Sha256)
            .map(|p| p.value.clone());
        self.refs.push(ExternalRef {
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
                RefLocator::Url(_) => None,
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

    fn purls(refs: &[ExternalRef]) -> Vec<&str> {
        refs.iter()
            .filter_map(|r| match &r.locator {
                RefLocator::Purl(p) => Some(p.as_str()),
                RefLocator::Url(_) => None,
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
}
