//! Facts read out of an npm manifest's scripts and authorship, for traits to
//! judge. Nothing here knows a package or host by name: which hosts are
//! trusted, which names are popular and which dot paths are conventional is
//! policy, and lives in traits and cleave's named datasets.
//!
//! - `consistency.missing_author` — 1 for a named, versioned, public package
//!   with no author, no publisher and no workspace-local dependencies.
//! - `npm.script_hosts[]` — the host of every `http(s)` URL in `scripts`.
//! - `npm.lifecycle_dot_paths[]` — every whitespace-separated token in an
//!   install or publish lifecycle command that names a dot path (`/.`).

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value as JsonValue};

use super::npm::{DEPENDENCY_SECTIONS, LIFECYCLE_HOOKS};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Emit the script and authorship facts for a parsed `package.json` object.
pub(super) fn emit(manifest: &Map<String, JsonValue>, values: &mut Values, metrics: &mut Metrics) {
    if missing_author(manifest) {
        metrics.insert(metric!("consistency.missing_author"), 1.0);
    }
    let Some(scripts) = manifest.get("scripts").and_then(JsonValue::as_object) else {
        return;
    };
    let mut hosts: Vec<&str> = scripts
        .values()
        .filter_map(JsonValue::as_str)
        .flat_map(url_hosts)
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    insert_list(values, value_key!("npm.script_hosts"), hosts);

    let dot_paths = LIFECYCLE_HOOKS
        .iter()
        .filter_map(|hook| scripts.get(*hook)?.as_str())
        .flat_map(str::split_whitespace)
        .filter(|token| token.contains("/."))
        .collect();
    insert_list(values, value_key!("npm.lifecycle_dot_paths"), dot_paths);
}

fn insert_list(values: &mut Values, key: crate::output::ValueKey, list: Vec<&str>) {
    if !list.is_empty() {
        values.insert_key(
            key,
            JsonValue::Array(list.into_iter().map(JsonValue::from).collect()),
        );
    }
}

/// The host of every `http(s)` URL in `text`: no userinfo, no port.
fn url_hosts(text: &str) -> Vec<&str> {
    static URL: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(url) = URL
        .get_or_init(|| Regex::new(r#"https?://([^\s"'<>()/?#]+)"#).ok())
        .as_ref()
    else {
        return Vec::new();
    };
    url.captures_iter(text)
        .filter_map(|c| c.get(1))
        .map(|authority| {
            let host = authority.as_str().rsplit('@').next().unwrap_or_default();
            host.split(':').next().unwrap_or_default()
        })
        .filter(|host| !host.is_empty())
        .collect()
}

/// A named, versioned, public package that names no author or publisher and
/// is not a workspace member (whose authorship lives at the root).
fn missing_author(manifest: &Map<String, JsonValue>) -> bool {
    let author_empty = match manifest.get("author") {
        None => true,
        Some(JsonValue::String(s)) => s.trim().is_empty(),
        Some(JsonValue::Object(person)) => person
            .get("name")
            .and_then(JsonValue::as_str)
            .is_none_or(|s| s.trim().is_empty()),
        Some(_) => false,
    };
    let is_private = match manifest.get("private") {
        Some(JsonValue::Bool(b)) => *b,
        Some(JsonValue::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    let workspace_local = DEPENDENCY_SECTIONS
        .iter()
        .filter_map(|section| manifest.get(*section).and_then(JsonValue::as_object))
        .flat_map(Map::values)
        .filter_map(JsonValue::as_str)
        .any(|spec| spec.starts_with("workspace:") || spec.starts_with("catalog:"));
    author_empty
        && manifest.get("name").is_some_and(|v| !v.is_null())
        && manifest.get("version").is_some_and(|v| !v.is_null())
        && !is_private
        && !workspace_local
        && manifest.get("publisher").is_none_or(JsonValue::is_null)
}

#[cfg(test)]
mod tests;
