//! npm package (`.tgz`) and bare `package.json` identity extractor.
//!
//! The member listing comes from the generic [`super::tar`] walker; this
//! module adds the publisher identity that lives inside the manifest:
//! the package name, version, description, author and maintainer names/emails, and
//! the repository/homepage URLs. Emails are the strongest cross-package
//! identifier npm carries, so they are surfaced as structured fields the
//! identity normalizer rolls up.
//!
//! npm extracts every member, so a later `package.json` replaces an
//! earlier one: the manifest is the last one in the tarball, and the
//! whole tarball is inflated to find it.
//!
//! Two of the emitted facts are cross-field judgements over the manifest
//! rather than fields lifted out of it: `consistency.name_repo_mismatch`
//! and `consistency.publisher_repo_owner_mismatch`. Both compare two
//! claims the same manifest makes, so they are measurements of one file's
//! bytes and belong here beside the parse that reads them.

use crate::formats::ExtractCtx;
use serde_json::Value as JsonValue;

use super::bounded::{
    Limits, MAX_MANIFEST_BYTES, MAX_TARGZ_SEARCH, TarGzSearch, find_targz_member,
};
use super::people::{self, Person};
use crate::error::Error;
use crate::fileid::FileType;
use crate::metric;
use crate::output::{Errors, Metrics, Stage, Values};
use crate::value_key;

/// Where npm puts the manifest inside the tarball.
const MANIFEST: &str = "package/package.json";

pub(super) fn extract(bytes: &[u8], ctx: ExtractCtx<'_>) -> Result<(), Error> {
    let ExtractCtx {
        values,
        metrics,
        archive_members,
        errors,
        ..
    } = ctx;
    if let Some(manifest) = package_json(bytes, values, errors) {
        emit(&manifest, values, metrics);
    }
    super::tar::extract(bytes, FileType::Npm, values, metrics, archive_members)
}

/// Read and parse `package/package.json` from a gzipped npm tarball.
/// `None` when the tarball has none (silently), when it is over the size
/// cap or past the inflate budget (an `npm.limits` entry), or when the
/// tarball or manifest is unreadable or not JSON (an error). The last
/// manifest in the tarball is the one read.
fn package_json(bytes: &[u8], values: &mut Values, errors: &mut Errors) -> Option<JsonValue> {
    // npm unpacks a tarball with its first path component stripped, whatever
    // it is called, so `<any>/package.json` lands as the package's own
    // manifest; `package/` is only the name `npm pack` writes.
    let is_manifest = |path: &str| {
        path.split_once('/')
            .is_some_and(|(_, rest)| rest == "package.json")
    };
    let (path, prefix) = match find_targz_member(bytes, is_manifest, MAX_MANIFEST_BYTES) {
        Ok(TarGzSearch::Found { path, prefix }) => (path, prefix),
        Ok(TarGzSearch::Absent) => return None,
        Ok(TarGzSearch::InflateCapped) => {
            let mut limits = Limits::default();
            limits.push(
                "manifest-search",
                format!(
                    "tarball inflates past {MAX_TARGZ_SEARCH} bytes before its end; {MANIFEST} not read"
                ),
            );
            limits.emit(values, value_key!("npm.limits"));
            return None;
        }
        Err(e) => {
            e.into_failure(Stage::TarParse, MANIFEST).record(errors);
            return None;
        }
    };
    if prefix.truncated {
        let mut limits = Limits::default();
        limits.push(
            "manifest",
            format!("{path} over the {MAX_MANIFEST_BYTES}-byte cap; not parsed"),
        );
        limits.emit(values, value_key!("npm.limits"));
        return None;
    }
    serde_json::from_slice(&prefix.bytes)
        .map_err(|e| errors.record_malformed(Stage::FormatExtract, format!("{path}: {e}")))
        .ok()
}

/// Emit `npm.*` identity values from a parsed `package.json`, plus the
/// `consistency.*` judgements over them. Shared by the tarball path and the
/// bare-`package.json` file type.
pub(super) fn emit(manifest: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    let Some(obj) = manifest.as_object() else {
        return;
    };
    super::npm_facts::emit(obj, values, metrics);
    for (field, key) in [
        ("name", value_key!("npm.name")),
        ("version", value_key!("npm.version")),
        ("description", value_key!("npm.description")),
        ("homepage", value_key!("npm.homepage")),
    ] {
        if let Some(s) = obj.get(field).and_then(JsonValue::as_str) {
            values.insert_key(key, JsonValue::String(s.to_string()));
        }
    }
    if let Some(url) = repository_url(obj.get("repository")) {
        values.insert_key(
            value_key!("npm.repository.url"),
            JsonValue::String(url.to_string()),
        );
    }
    // npm names one `author` and any number of `maintainers`, each a person
    // object or a `"Name <email> (url)"` string.
    people::put(
        values,
        value_key!("npm.authors"),
        obj.get("author").map(Person::from_json),
    );
    people::put_list(
        values,
        value_key!("npm.maintainers"),
        obj.get("maintainers")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .map(Person::from_json),
        value_key!("npm.limits"),
    );
    // Install-time lifecycle hooks: the command string is the reference
    // source — a `postinstall` that fetches a remote stage is the classic
    // npm supply-chain vector.
    if let Some(scripts) = obj.get("scripts").and_then(JsonValue::as_object) {
        for (hook, key) in crate::values::NPM_INSTALL_HOOKS {
            if let Some(cmd) = scripts.get(hook).and_then(JsonValue::as_str) {
                values.insert_key(key, JsonValue::String(cmd.to_string()));
            }
        }
        // Every script npm runs on its own during install or publish -- the
        // ones a package author does not have to be asked to run.
        let lifecycle: Vec<JsonValue> = LIFECYCLE_HOOKS
            .iter()
            .filter_map(|hook| {
                let command = scripts.get(*hook)?.as_str()?;
                Some(serde_json::json!({"hook": hook, "command": command}))
            })
            .collect();
        if !lifecycle.is_empty() {
            values.insert_key(
                value_key!("npm.lifecycle_scripts"),
                JsonValue::Array(lifecycle),
            );
        }
    }
    if let Some(mismatch) = name_repo_mismatch(obj) {
        metrics.insert(
            metric!("consistency.name_repo_mismatch"),
            f64::from(u8::from(mismatch)),
        );
    }
    if let Some(mismatch) = publisher_repo_owner_mismatch(obj) {
        metrics.insert(
            metric!("consistency.publisher_repo_owner_mismatch"),
            f64::from(u8::from(mismatch)),
        );
    }
    if let Some(self_ref) = self_referential_git_dependency(obj) {
        metrics.insert(
            metric!("consistency.self_referential_git_dependency"),
            f64::from(u8::from(self_ref)),
        );
    }
    if let Some(count) = super::package_consistency::npm_self_dependencies(obj) {
        metrics.insert(metric!("consistency.self_dependency"), f64::from(count));
    }
}

/// The scripts npm runs by itself around install and publish.
pub(super) const LIFECYCLE_HOOKS: [&str; 9] = [
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepare",
    "prepack",
    "postpack",
    "publish",
    "postpublish",
];

/// The dependency sections whose entries a package resolves at install time.
pub(super) const DEPENDENCY_SECTIONS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

/// Each declared dependency as an import symbol: the package name, its
/// version spec in `library`, anchored at the entry's key in `bytes`.
pub(super) fn dependency_imports(manifest: &JsonValue, bytes: &[u8], symbols: &mut crate::Symbols) {
    let text = String::from_utf8_lossy(bytes);
    for section in DEPENDENCY_SECTIONS {
        let Some(entries) = manifest.get(section).and_then(JsonValue::as_object) else {
            continue;
        };
        let section_start = text.find(&format!("\"{section}\"")).unwrap_or(0);
        for (name, spec) in entries {
            let offset = text
                .get(section_start..)
                .and_then(|rest| rest.find(&format!("\"{name}\"")))
                .map(|rel| (section_start + rel) as u64);
            let spec = spec.as_str();
            // `"axois": "npm:axios@1"` installs axios under another name:
            // the package is axios, and `axois` is only what it is called.
            let (name, alias) = match spec.and_then(alias_target) {
                Some(target) => (target.to_string(), Some(name.clone())),
                None => (name.clone(), None),
            };
            symbols.push(crate::Symbol::Import {
                name,
                alias,
                library: spec.map(str::to_string),
                offset,
                ordinal: None,
            });
        }
    }
}

/// The package an `npm:` alias spec installs (`npm:@scope/pkg@1` →
/// `@scope/pkg`).
fn alias_target(spec: &str) -> Option<&str> {
    let alias = spec.strip_prefix("npm:")?;
    let name_end = if alias.starts_with('@') {
        let package_start = alias.find('/')? + 1;
        alias
            .get(package_start..)?
            .find('@')
            .map_or(alias.len(), |at| package_start + at)
    } else {
        alias.find('@').unwrap_or(alias.len())
    };
    alias.get(..name_end).filter(|name| !name.is_empty())
}

/// Fold a string to its comparable core: no separators, no case.
fn slug(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

/// The same fold applied to the last path segment of a repository URL, with
/// a trailing `.git` dropped first.
fn repo_slug(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    slug(
        trimmed
            .rsplit('/')
            .next()
            .unwrap_or(trimmed)
            .trim_end_matches(".git"),
    )
}

/// Whether the manifest names one package and claims another project's
/// repository — the clone-and-rename shape, where there is no hostile code
/// to find because the payload is a later version.
///
/// Compared on folded slugs, because the noise is predictable: a `.git`
/// suffix and `-`/`_`/case spelling all differ without disagreeing. For a
/// scoped package, accept either the full scope-plus-name slug or the package
/// name alone: both `@tailwindcss/forms` in `tailwindcss-forms` and
/// `@alice/tool` in `tool` are ordinary same-project naming shapes.
///
/// Deliberately literal beyond that. A package legitimately named `foo` in a
/// repo called `foo-js` will read as a mismatch — which is why this is one
/// weak signal and never a verdict on its own.
///
/// `None` when either field is missing: a package that claims no repository
/// has made no claim to contradict. Also `None` for a monorepo package, which
/// declares the subdirectory it ships from and thereby makes no claim that the
/// repository shares its name (`@react-pdf/png-js` ships from
/// `diegomura/react-pdf` with `directory: packages/png-js`).
fn name_repo_mismatch(obj: &serde_json::Map<String, JsonValue>) -> Option<bool> {
    // Only the object form of `repository` can name a subdirectory.
    let directory = obj
        .get("repository")
        .and_then(JsonValue::as_object)
        .and_then(|repository| repository.get("directory"));
    if directory.and_then(JsonValue::as_str).is_some() {
        return None;
    }
    let raw_name = obj.get("name")?.as_str()?;
    let name = slug(raw_name);
    let unscoped_name = slug(raw_name.rsplit('/').next().unwrap_or(raw_name));
    let repo = repo_slug(repository_url(obj.get("repository"))?);
    if name.is_empty() || unscoped_name.is_empty() || repo.is_empty() {
        return None;
    }
    Some(name != repo && unscoped_name != repo)
}

/// Whether a marketplace extension's publisher disagrees with the owner of
/// the repository it claims.
///
/// This is the discriminator a bare name-vs-repository mismatch lacks. An
/// honest fork renames the package and keeps its own repository, so publisher
/// and owner still agree (`alice/theme` published by `alice`). A
/// republication keeps the *upstream's* repository URL — it was never part of
/// the branding the repackager set out to change — so the listing is
/// published by one identity while pointing at another's code (publisher
/// `mallory`, repository `alice/theme`).
///
/// `None` whenever either side is missing — a `package.json` with no
/// `publisher` is not a marketplace extension and has made no claim to
/// contradict.
fn publisher_repo_owner_mismatch(obj: &serde_json::Map<String, JsonValue>) -> Option<bool> {
    let publisher = slug(obj.get("publisher")?.as_str()?);
    let repo = repository_url(obj.get("repository"))?;

    // The owner is the path segment before the repository name, on any forge
    // that uses the `host/owner/repo` shape. Anything shorter names no owner.
    let path = repo
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .rsplit("://")
        .next()
        .unwrap_or(repo);
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .skip(1) // host
        .collect();
    let owner = slug(segments.first()?);
    if publisher.is_empty() || owner.is_empty() || segments.len() < 2 {
        return None;
    }
    Some(publisher != owner)
}

/// The `owner`/`repo` pair a forge reference points at, folded for
/// comparison. Accepts every shape npm and the forges use — `github:o/r`, a
/// `git+https://`, `git://` or plain `https://` URL, `git@host:o/r`, and the
/// bare `o/r` shorthand — because the caller has already decided the string
/// is meant to name a repository.
fn forge_parts(spec: &str) -> Option<(String, String)> {
    let path = spec.trim().split('#').next()?;
    let path = path
        .trim_start_matches("git+")
        .trim_start_matches("github:")
        .trim_start_matches("gitlab:")
        .trim_start_matches("bitbucket:");
    // Drop scheme and host when the reference is a URL; `git@host:owner/repo`
    // and the bare shorthand are already rooted at the owner.
    let path = match path.split_once("://") {
        Some((_, rest)) => rest.split_once('/').map_or(rest, |(_, tail)| tail),
        None => path.rsplit(':').next().unwrap_or(path),
    };
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let repo = slug(segments.last()?.trim_end_matches(".git"));
    let owner = slug(segments.get(segments.len().checked_sub(2)?)?);
    (!owner.is_empty() && !repo.is_empty()).then_some((owner, repo))
}

/// Whether a dependency specifier resolves through git rather than through
/// the registry.
///
/// A registry alias such as `npm:@ai-sdk/provider@3.0.10` also carries a
/// slash, so requiring a git marker rather than merely a slash is what keeps
/// ordinary aliases from reading as repository references.
fn is_git_specifier(spec: &str) -> bool {
    let spec = spec.trim();
    spec.starts_with("github:")
        || spec.starts_with("gitlab:")
        || spec.starts_with("bitbucket:")
        || spec.starts_with("git+")
        || spec.starts_with("git://")
        || spec.starts_with("git@")
        || (spec.contains('#') && !spec.contains(':'))
}

/// Whether the manifest declares a git-resolved dependency on the very
/// repository it says it ships from.
///
/// A package has no reason to depend on itself. What the shape buys an
/// attacker is that the published tarball stays clean: the code that runs at
/// install time lives at a commit in the repository, which npm fetches
/// separately and which no registry audit of the tarball ever sees. Pinning
/// it to a commit rather than a tag keeps it off every branch listing too.
///
/// `None` when the manifest claims no repository, or declares no git
/// dependency — there is nothing to agree or disagree about.
fn self_referential_git_dependency(obj: &serde_json::Map<String, JsonValue>) -> Option<bool> {
    let own = forge_parts(repository_url(obj.get("repository"))?)?;
    let mut saw_git_dependency = false;
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(deps) = obj.get(field).and_then(JsonValue::as_object) else {
            continue;
        };
        for spec in deps.values().filter_map(JsonValue::as_str) {
            if !is_git_specifier(spec) {
                continue;
            }
            saw_git_dependency = true;
            let Some(target) = forge_parts(spec) else {
                continue;
            };
            if target == own {
                return Some(true);
            }
        }
    }
    saw_git_dependency.then_some(false)
}

/// A `repository` is either a string (`"github:user/repo"` or a URL) or
/// an object `{ "url": "…" }`.
fn repository_url(value: Option<&JsonValue>) -> Option<&str> {
    match value? {
        JsonValue::String(s) => Some(s),
        JsonValue::Object(o) => o.get("url").and_then(JsonValue::as_str),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
