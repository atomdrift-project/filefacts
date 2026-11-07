//! Package-consistency judgements over a package's own manifest: a name one
//! edit from a popular package, identity fields that agree on another
//! package's name, a summary copied from one, and a manifest that depends on
//! itself.
//!
//! Each compares claims one manifest makes (plus, for an sdist, the
//! `requires.txt` setuptools writes beside its `PKG-INFO`), so each is a
//! measurement of the package's own bytes and sits beside the parse that
//! reads it, as `npm.rs`'s `consistency.*` judgements do.

use serde_json::Value as JsonValue;

use super::core_metadata::CoreMetadata;
use crate::metric;
use crate::output::Metrics;

/// Popular and high-value PyPI distribution names, one edit away from which
/// a distribution name is almost certainly a typosquat.
///
/// Public knowledge -- top-download and documented impersonation targets --
/// not derived from any sample set. `boto` is absent although real: it is one
/// edit from `boto3`, and the legitimate legacy package would flag itself.
const POPULAR_PACKAGES: &[&str] = &[
    "requests",
    "urllib3",
    "boto3",
    "botocore",
    "setuptools",
    "numpy",
    "pandas",
    "python-dateutil",
    "six",
    "certifi",
    "idna",
    "charset-normalizer",
    "wheel",
    "pip",
    "typing-extensions",
    "packaging",
    "pyyaml",
    "cryptography",
    "click",
    "jinja2",
    "flask",
    "django",
    "fastapi",
    "aiohttp",
    "httpx",
    "starlette",
    "pydantic",
    "sqlalchemy",
    "scipy",
    "scikit-learn",
    "matplotlib",
    "pillow",
    "torch",
    "tensorflow",
    "keras",
    "transformers",
    "openai",
    "langchain",
    "langchain-openai",
    "discord",
    "discord-py",
    "colorama",
    "rich",
    "tqdm",
    "beautifulsoup4",
    "lxml",
    "selenium",
    "pytest",
    "attrs",
    "markupsafe",
    "werkzeug",
    "itsdangerous",
    "redis",
    "pymongo",
    "psycopg2",
    "protobuf",
    "grpcio",
    "pycryptodome",
    "paramiko",
    "web3",
    "eth-account",
    "eth-utils",
    "eth-abi",
    "solana",
    "pyfiglet",
    "s3transfer",
    "crytic-compile",
    "psutil",
    "pyjwt",
    "oauthlib",
    "pytz",
    "babel",
    "sphinx",
    "tornado",
    "gunicorn",
    "uvicorn",
    "celery",
    "dnspython",
    "figlet",
];

/// Popular packages' own distinctive one-line summaries, with the
/// distribution that owns each. A rename-clone copies its target's metadata
/// verbatim, so one of these under another `Name` is copied identity with the
/// label swapped (`fluxhttp` shipping aiohttp's tagline). Exact normalised
/// match only, so a generic tagline never earns a place here, and the owner
/// itself is exempt by construction. Public knowledge, not sample-derived.
const POPULAR_SUMMARIES: &[(&str, &str)] = &[
    ("async http client/server framework (asyncio)", "aiohttp"),
    ("python http for humans.", "requests"),
    ("cross-platform colored terminal text.", "colorama"),
    ("composable command line interface toolkit", "click"),
    ("the uncompromising code formatter.", "black"),
    ("fast, extensible progress meter", "tqdm"),
    ("screen-scraping library", "beautifulsoup4"),
    ("data validation using python type hints", "pydantic"),
    ("the little asgi library that shines.", "starlette"),
];

/// Emit the `consistency.*` judgements over a Python Core Metadata block,
/// counting an sdist's `requires.txt` toward the self-dependency.
///
/// - `consistency.name_typosquat` — 1 when `Name` is one edit from a popular
///   package without being it.
/// - `consistency.metadata_identity_mismatch` — how many advertised identity
///   fields (a `name:`-prefixed summary, a GitHub homepage's repository)
///   agree on one name other than `Name`, when at least two do; else 0.
/// - `consistency.cloned_summary` — 1 when the summary is a popular package's
///   own tagline and `Name` is not that package.
/// - `consistency.self_dependency` — unconditional requirements naming the
///   package itself, when it declares any requirements.
pub(super) fn core_metadata(
    headers: &CoreMetadata,
    requires_txt: Option<&str>,
    metrics: &mut Metrics,
) {
    let Some(name) = headers
        .first("name")
        .map(normalize_name)
        .filter(|name| !name.is_empty())
    else {
        return;
    };
    let squat = !POPULAR_PACKAGES.contains(&name.as_str())
        && POPULAR_PACKAGES
            .iter()
            .any(|popular| within_one_edit(&name, popular));
    metrics.insert(
        metric!("consistency.name_typosquat"),
        f64::from(u8::from(squat)),
    );
    metrics.insert(
        metric!("consistency.metadata_identity_mismatch"),
        f64::from(advertised_identity_mismatch(headers, &name)),
    );
    if let Some(summary) = headers.first("summary") {
        metrics.insert(
            metric!("consistency.cloned_summary"),
            f64::from(u8::from(cloned_summary(&name, summary))),
        );
    }
    if let Some(count) = python_self_dependencies(headers, requires_txt, &name) {
        metrics.insert(metric!("consistency.self_dependency"), f64::from(count));
    }
}

/// `dependencies` entries of an npm `package.json` naming the package itself;
/// `None` when it has no name or no runtime dependencies.
pub(super) fn npm_self_dependencies(manifest: &serde_json::Map<String, JsonValue>) -> Option<u32> {
    let name = manifest.get("name")?.as_str()?.trim().to_ascii_lowercase();
    let dependencies = manifest.get("dependencies")?.as_object()?;
    if name.is_empty() || dependencies.is_empty() {
        return None;
    }
    let count = dependencies
        .keys()
        .filter(|dependency| dependency.trim().eq_ignore_ascii_case(&name))
        .count();
    u32::try_from(count).ok()
}

/// PEP 503 normalisation: case folded, runs of `-`, `_` and `.` the same.
fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

/// Whether `a` and `b` differ by at most one character edit (substitution,
/// insertion, or deletion): Levenshtein distance at most 1.
fn within_one_edit(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    if a.len() == b.len() {
        return a.iter().zip(b).filter(|(x, y)| x != y).count() <= 1;
    }
    // The shorter must be the longer with one character removed.
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let split = short.iter().zip(long).take_while(|(x, y)| x == y).count();
    short.get(split..) == long.get(split + 1..)
}

/// How many advertised identity fields agree on one name that is not the
/// declared one, when at least two do (else 0).
///
/// A typosquat shipping its target verbatim keeps the target's metadata and
/// edits only `Name`. One mismatch is ordinary -- a distribution's module and
/// repository often differ from its name -- but the summary prefix and the
/// homepage repository both naming the same other package is copied metadata
/// with the label swapped.
fn advertised_identity_mismatch(headers: &CoreMetadata, name: &str) -> u32 {
    let mut advertised: Vec<String> = Vec::new();
    // The ecosystem convention of opening the summary with `name:`.
    if let Some((prefix, _)) = headers.first("summary").and_then(|s| s.split_once(':')) {
        let prefix = prefix.trim();
        if !prefix.is_empty()
            && prefix.len() <= 60
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            advertised.push(normalize_name(prefix));
        }
    }
    // A homepage on GitHub names its repository.
    if let Some(repo) = headers
        .first("home-page")
        .and_then(|url| url.split("github.com/").nth(1))
        .and_then(|rest| rest.split('/').nth(1))
        .map(|repo| repo.trim_end_matches(['/', ' ']))
        .filter(|repo| !repo.is_empty())
    {
        advertised.push(normalize_name(repo));
    }
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for other in advertised.iter().filter(|a| a.as_str() != name) {
        *counts.entry(other).or_default() += 1;
    }
    counts.into_values().max().filter(|&n| n >= 2).unwrap_or(0)
}

/// Whether `summary` is a popular package's own tagline under another name.
fn cloned_summary(name: &str, summary: &str) -> bool {
    let summary = summary
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    POPULAR_SUMMARIES
        .iter()
        .any(|(tagline, owner)| summary == *tagline && name != normalize_name(owner))
}

/// Unconditional requirements naming the package itself, from its
/// `Requires-Dist` headers and an sdist's `requires.txt`; `None` when it
/// declares no requirements at all.
///
/// A requirement guarded by an `extra` marker is optional, and an extra that
/// pulls in the package's own other extras (`foo[all]` requiring `foo[a,b]`)
/// is the ordinary way to aggregate them, so only unconditional requirements
/// count: `Requires-Dist` without an `extra` marker, and the leading,
/// unsectioned block of `requires.txt` (each `[extra]` header begins an
/// optional group).
fn python_self_dependencies(
    headers: &CoreMetadata,
    requires_txt: Option<&str>,
    name: &str,
) -> Option<u32> {
    let mut declared = false;
    let mut count = 0_u32;
    let mut check = |spec: &str| {
        if normalize_name(requirement_name(spec)) == name {
            count += 1;
        }
    };
    // One requirement per header: commas belong to it (`foo[a,b]`,
    // `>=1,<2`), and only a folded continuation line starts another.
    for (field, value) in &headers.fields {
        if field != "requires-dist" {
            continue;
        }
        declared = true;
        for spec in value.lines() {
            let conditional_on_extra = spec
                .split_once(';')
                .is_some_and(|(_, marker)| marker.contains("extra"));
            if !spec.trim().is_empty() && !conditional_on_extra {
                check(spec);
            }
        }
    }
    if let Some(text) = requires_txt {
        declared = true;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                break;
            }
            if !line.is_empty() && !line.starts_with('#') {
                check(line);
            }
        }
    }
    declared.then_some(count)
}

/// The distribution a requirement names: its leading run of PEP 508 name
/// characters, so `foo[extra]>=1.0 ; marker`, `foo (>=1.0)` and `foo==1` all
/// name `foo`.
fn requirement_name(spec: &str) -> &str {
    let spec = spec.trim();
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(spec.len());
    &spec[..end]
}

#[cfg(test)]
mod tests;
