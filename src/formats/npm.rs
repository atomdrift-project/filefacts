//! npm package (`.tgz`) and bare `package.json` identity extractor.
//!
//! The member listing comes from the generic [`super::tar`] walker; this
//! module adds the publisher identity that lives inside the manifest:
//! the package name, version, description, author and maintainer names/emails, and
//! the repository/homepage URLs. Emails are the strongest cross-package
//! identifier npm carries, so they are surfaced as structured fields the
//! identity normalizer rolls up.
//!
//! Decompression stops as soon as `package/package.json` is reached —
//! usually near the front, so a multi-megabyte tarball is rarely fully
//! inflated just to read one manifest.
//!
//! Two of the emitted facts are cross-field judgements over the manifest
//! rather than fields lifted out of it: `consistency.name_repo_mismatch`
//! and `consistency.publisher_repo_owner_mismatch`. Both compare two
//! claims the same manifest makes, so they are measurements of one file's
//! bytes and belong here beside the parse that reads them.

use serde_json::Value as JsonValue;

use super::bounded::{MAX_TARGZ_SEARCH, TarGzSearch, find_targz_member, push_limit};
use crate::error::Error;
use crate::fileid::FileType;
use crate::metric;
use crate::output::{ArchiveMember, Errors, Metrics, Stage, Values};
use crate::value_key;

/// Manifests larger than this are almost certainly hostile padding; we
/// stop reading rather than buffer them.
const MAX_MANIFEST: u64 = 1 << 20;

/// Where npm puts the manifest inside the tarball.
const MANIFEST: &str = "package/package.json";

pub(super) fn extract(
    bytes: &[u8],
    file_type: FileType,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<(), Error> {
    if let Some(manifest) = package_json(bytes, values, errors) {
        emit(&manifest, values, metrics);
    }
    super::tar::extract(bytes, file_type, values, metrics, archive_members)
}

/// Read and parse `package/package.json` from a gzipped npm tarball.
/// `None` when the tarball has none (silently), when it is over the size
/// cap or past the inflate budget (an `npm.limits` entry), or when the
/// tarball or manifest is unreadable or not JSON (an error). Decompression
/// stops at the manifest.
fn package_json(bytes: &[u8], values: &mut Values, errors: &mut Errors) -> Option<JsonValue> {
    let prefix = match find_targz_member(bytes, |p| p == MANIFEST, MAX_MANIFEST) {
        Ok(TarGzSearch::Found { prefix, .. }) => prefix,
        Ok(TarGzSearch::Absent) => return None,
        Ok(TarGzSearch::InflateCapped) => {
            push_limit(
                values,
                value_key!("npm.limits"),
                "manifest-search",
                format!("no {MANIFEST} in the first {MAX_TARGZ_SEARCH} inflated bytes"),
            );
            return None;
        }
        Err(e) => {
            e.into_failure(Stage::TarParse, MANIFEST).record(errors);
            return None;
        }
    };
    if prefix.truncated {
        push_limit(
            values,
            value_key!("npm.limits"),
            "manifest",
            format!("{MANIFEST} over the {MAX_MANIFEST}-byte cap; not parsed"),
        );
        return None;
    }
    serde_json::from_slice(&prefix.bytes)
        .map_err(|e| errors.record_malformed(Stage::FormatExtract, format!("{MANIFEST}: {e}")))
        .ok()
}

/// Emit `npm.*` identity values from a parsed `package.json`, plus the
/// `consistency.*` judgements over them. Shared by the tarball path and the
/// bare-`package.json` file type.
pub(super) fn emit(manifest: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    let Some(obj) = manifest.as_object() else {
        return;
    };
    if let Some(name) = obj.get("name").and_then(JsonValue::as_str) {
        values.insert_key(value_key!("npm.name"), JsonValue::String(name.to_string()));
    }
    if let Some(version) = obj.get("version").and_then(JsonValue::as_str) {
        values.insert_key(
            value_key!("npm.version"),
            JsonValue::String(version.to_string()),
        );
    }
    if let Some(description) = obj.get("description").and_then(JsonValue::as_str) {
        values.insert_key(
            value_key!("npm.description"),
            JsonValue::String(description.to_string()),
        );
    }
    if let Some(homepage) = obj.get("homepage").and_then(JsonValue::as_str) {
        values.insert_key(
            value_key!("npm.homepage"),
            JsonValue::String(homepage.to_string()),
        );
    }
    if let Some(url) = repository_url(obj.get("repository")) {
        values.insert_key(value_key!("npm.repository.url"), JsonValue::String(url));
    }
    if let Some(author) = person(obj.get("author")) {
        for (field, value) in author.named_fields() {
            values.insert_key_at(value_key!("npm.author"), field, JsonValue::String(value));
        }
    }
    let maintainers = people(obj.get("maintainers"));
    if !maintainers.is_empty() {
        values.insert_key(value_key!("npm.maintainers"), JsonValue::Array(maintainers));
    }
    // Install-time lifecycle hooks: the command string is the reference
    // source — a `postinstall` that fetches a remote stage is the classic
    // npm supply-chain vector.
    if let Some(scripts) = obj.get("scripts").and_then(JsonValue::as_object) {
        for (hook, key) in [
            ("preinstall", value_key!("npm.scripts.preinstall")),
            ("install", value_key!("npm.scripts.install")),
            ("postinstall", value_key!("npm.scripts.postinstall")),
        ] {
            if let Some(cmd) = scripts.get(hook).and_then(JsonValue::as_str) {
                values.insert_key(key, JsonValue::String(cmd.to_string()));
            }
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

/// A `repository` object may declare the subdirectory a monorepo package
/// ships from. Only the object form can carry it.
fn repository_directory(value: Option<&JsonValue>) -> Option<&str> {
    value?.as_object()?.get("directory")?.as_str()
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
    if repository_directory(obj.get("repository")).is_some() {
        return None;
    }
    let raw_name = obj.get("name")?.as_str()?;
    let name = slug(raw_name);
    let unscoped_name = slug(raw_name.rsplit('/').next().unwrap_or(raw_name));
    let repo = repo_slug(&repository_url(obj.get("repository"))?);
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
/// and owner still agree (`Bobronium/vscode-pycharm-darcula-theme` published
/// by `Bobronium`). A republication keeps the *upstream's* repository URL — it
/// was never part of the branding the repackager set out to change — so the
/// listing is published by one identity while pointing at another's code
/// (`krabt-proto`, publisher `krabt`, repository `zxh0/vscode-proto3`).
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
        .unwrap_or(&repo);
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
    let own = forge_parts(&repository_url(obj.get("repository"))?)?;
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
fn repository_url(value: Option<&JsonValue>) -> Option<String> {
    match value? {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Object(o) => o.get("url").and_then(JsonValue::as_str).map(str::to_string),
        _ => None,
    }
}

/// A parsed npm "person" — name, email, url — from either the object
/// form or the `"Name <email> (url)"` string form.
struct Person {
    name: Option<String>,
    email: Option<String>,
    url: Option<String>,
}

impl Person {
    fn named_fields(&self) -> impl Iterator<Item = (&'static str, String)> {
        [
            ("name", self.name.clone()),
            ("email", self.email.clone()),
            ("url", self.url.clone()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
    }

    fn into_json(self) -> Option<JsonValue> {
        let mut obj = serde_json::Map::new();
        for (k, v) in self.named_fields() {
            obj.insert(k.to_string(), JsonValue::String(v));
        }
        (!obj.is_empty()).then_some(JsonValue::Object(obj))
    }
}

fn person(value: Option<&JsonValue>) -> Option<Person> {
    match value? {
        JsonValue::String(s) => Some(parse_person_string(s)),
        JsonValue::Object(o) => {
            let p = Person {
                name: o
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                email: o
                    .get("email")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                url: o.get("url").and_then(JsonValue::as_str).map(str::to_string),
            };
            (p.name.is_some() || p.email.is_some()).then_some(p)
        }
        _ => None,
    }
}

fn people(value: Option<&JsonValue>) -> Vec<JsonValue> {
    value
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| person(Some(v)))
        .filter_map(Person::into_json)
        .collect()
}

/// Split `"Name <email> (url)"` into its parts.
fn parse_person_string(s: &str) -> Person {
    let email = between(s, '<', '>');
    let url = between(s, '(', ')');
    let name_end = s.find('<').or_else(|| s.find('(')).unwrap_or(s.len());
    let name = s[..name_end].trim();
    Person {
        name: (!name.is_empty()).then(|| name.to_string()),
        email,
        url,
    }
}

fn between(s: &str, open: char, close: char) -> Option<String> {
    let start = s.find(open)?;
    let end = s[start + 1..].find(close)? + start + 1;
    let inner = s[start + 1..end].trim();
    (!inner.is_empty()).then(|| inner.to_string())
}

#[cfg(test)]
mod tests;
