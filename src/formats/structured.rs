//! Extractors for structured-document formats.
//!
//! For these formats the file's content *is* the metadata. The parsed tree
//! lands in [`Values`] with no synthetic key-namespace prefix — `fileid`
//! already tells consumers which structured format they're looking at — but
//! beside, never over, what filefacts itself writes: see [`merge_document`].

use std::collections::BTreeSet;

use serde_json::{Map, Value as JsonValue};

use crate::error::Error;
use crate::metric;
use crate::output::{Errors, Metrics, Stage, Values};
use crate::value_key;

mod json;
mod plist;
mod toml;
mod yaml;

#[cfg(test)]
use plist::{PLIST_MAX_DEPTH, base64_encode};
pub(super) use yaml::parse_yaml;

/// Generic JSON payloads are common, sometimes huge, and not always worth
/// deserializing. Named JSON formats use `extract_json` directly and are not
/// subject to this limit.
pub(crate) const GENERIC_JSON_PARSE_LIMIT_BYTES: usize = 75 * 1024;

/// Parse the bytes as JSON and merge the document into `values` (see
/// [`merge_document`]).
pub(super) fn extract_json(
    bytes: &[u8],
    values: &mut Values,
    errors: &mut Errors,
) -> Result<(), Error> {
    let parsed: JsonValue =
        serde_json::from_slice(bytes).map_err(|e| Error::malformed_caused_by("json", e))?;
    merge_document(parsed, values, errors);
    Ok(())
}

/// Composer shell bodies are executable script fields, unlike descriptive
/// JSON text or setuptools class-import declarations. Keep flows within one
/// command string; do not correlate independent handlers or events.
pub(super) fn extract_composer_json(
    bytes: &[u8],
    values: &mut Values,
    errors: &mut Errors,
) -> Result<(), Error> {
    extract_json(bytes, values, errors)?;
    let mut flows = Vec::new();
    let scripts = values.get("scripts").cloned();
    if let Some(JsonValue::Object(scripts)) = scripts {
        for (event, handlers) in scripts {
            // Lifecycle hooks applicable to install/update/autoload/create-project.
            if !matches!(
                event.as_str(),
                "pre-install-cmd"
                    | "post-install-cmd"
                    | "pre-update-cmd"
                    | "post-update-cmd"
                    | "pre-autoload-dump"
                    | "post-autoload-dump"
                    | "post-root-package-install"
                    | "post-create-project-cmd"
            ) {
                continue;
            }
            let handlers = match handlers {
                JsonValue::String(s) => vec![JsonValue::String(s)],
                JsonValue::Array(a) => a,
                _ => continue,
            };
            for (index, handler) in handlers.iter().enumerate() {
                let Some(body) = handler.as_str() else {
                    continue;
                };
                for mut flow in super::systemd::literal_shell_body_flows(body) {
                    if let Some(fields) = flow.as_object_mut() {
                        fields.insert("event".to_owned(), JsonValue::String(event.clone()));
                        fields.insert("handler_index".to_owned(), JsonValue::from(index));
                    }
                    flows.push(flow);
                }
            }
        }
    }
    values.insert_key(
        value_key!("composer.install_hook_flows"),
        JsonValue::Array(flows),
    );
    Ok(())
}

/// Parse a generic `.json` document if it is below the default parse cap.
/// Oversized files stay analyzable as text/raw content, but we avoid building
/// a potentially huge `serde_json::Value` tree.
pub(super) fn extract_generic_json(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    metrics.insert(
        metric!("json.parse_limit_bytes"),
        GENERIC_JSON_PARSE_LIMIT_BYTES as f64,
    );
    if bytes.len() > GENERIC_JSON_PARSE_LIMIT_BYTES {
        values.insert_key(value_key!("json.parse.skipped"), JsonValue::Bool(true));
        values.insert_key(
            value_key!("json.parse.reason"),
            JsonValue::String("size_limit".to_string()),
        );
        values.insert_key(
            value_key!("json.parse.limit_bytes"),
            JsonValue::Number((GENERIC_JSON_PARSE_LIMIT_BYTES as u64).into()),
        );
        values.insert_key(
            value_key!("json.parse.size"),
            JsonValue::Number((bytes.len() as u64).into()),
        );
        return Ok(());
    }

    metrics.insert(metric!("json.parsed_bytes"), bytes.len() as f64);
    if let Ok(parsed) = serde_json::from_slice::<JsonValue>(bytes) {
        merge_document(parsed, values, errors);
        return Ok(());
    }
    // JSON with comments. VS Code's own workspace files (`.vscode/tasks.json`,
    // `settings.json`, `launch.json`), `tsconfig.json` and most `.eslintrc`
    // variants are JSONC by specification: `//` and `/* */` comments and
    // trailing commas are legal there, and their consumers parse them fine.
    // A strict-only parse dropped the whole value tree for every such file,
    // so a folder-open task with a trailing comma had no `tasks[*].command`
    // for any value path to read -- a gap one campaign relied on to slip a
    // hidden autorun past scanners that parse strictly. Fall back to the same
    // tolerant parser gyp uses, with JSONC comment syntax, and record that
    // the fallback was needed: a document that is not strict JSON is a fact
    // worth keeping, without losing the tree.
    match json::parse_jsonc(bytes) {
        Some(parsed) => {
            metrics.insert(metric!("json.parse_lenient"), 1.0);
            merge_document(parsed, values, errors);
            Ok(())
        }
        None => Err(Error::malformed(
            "json",
            "not valid JSON or JSONC".to_string(),
        )),
    }
}

/// Parse a node-gyp build manifest (`binding.gyp`, `.gyp`, `.gypi`).
///
/// gyp is Python-literal syntax, JSON only in the common case. Real manifests
/// use trailing commas, `#` comments, and single quotes; hostile ones add
/// Python string escapes (`\xNN`, `\uNNNN`, `\U00NNNNNN`) so a byte-escaped
/// keyword like `"\x6e\x6f\x6e\x65"` reads as `"none"` only after decoding.
/// Parse as strict JSON first (fast, exact, unchanged behavior for the common
/// case), then fall back to a tolerant Python-literal parse so value paths like
/// `targets[*].sources[*]` and a concealed target `type` still resolve instead
/// of vanishing into a text/raw scan. `gyp.parse_lenient=1` marks a manifest
/// that needed the fallback — a diffable signal, since a build manifest that is
/// not even valid JSON is itself worth a second look.
pub(super) fn extract_gyp(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    metrics.insert(
        metric!("json.parse_limit_bytes"),
        GENERIC_JSON_PARSE_LIMIT_BYTES as f64,
    );
    if bytes.len() > GENERIC_JSON_PARSE_LIMIT_BYTES {
        values.insert_key(value_key!("json.parse.skipped"), JsonValue::Bool(true));
        values.insert_key(
            value_key!("json.parse.reason"),
            JsonValue::String("size_limit".to_string()),
        );
        values.insert_key(
            value_key!("json.parse.limit_bytes"),
            JsonValue::Number((GENERIC_JSON_PARSE_LIMIT_BYTES as u64).into()),
        );
        values.insert_key(
            value_key!("json.parse.size"),
            JsonValue::Number((bytes.len() as u64).into()),
        );
        return Ok(());
    }
    metrics.insert(metric!("json.parsed_bytes"), bytes.len() as f64);
    if let Ok(parsed) = serde_json::from_slice::<JsonValue>(bytes) {
        merge_document(parsed, values, errors);
        return Ok(());
    }
    match json::parse_gyp(bytes) {
        Some(parsed) => {
            metrics.insert(metric!("gyp.parse_lenient"), 1.0);
            merge_document(parsed, values, errors);
            Ok(())
        }
        None => Err(Error::malformed(
            "gyp",
            "not valid JSON or gyp Python-literal syntax".to_string(),
        )),
    }
}

/// Parse the bytes as one YAML document; see [`parse_yaml`]. A stream of
/// several documents is malformed here, since the single-tree `Values` view
/// has no place for the others.
pub(super) fn extract_yaml(
    bytes: &[u8],
    values: &mut Values,
    errors: &mut Errors,
) -> Result<(), Error> {
    let json = parse_yaml(bytes)?;
    merge_document(json, values, errors);
    Ok(())
}

/// Parse the bytes as one TOML document.
pub(super) fn extract_toml(
    bytes: &[u8],
    values: &mut Values,
    errors: &mut Errors,
) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed_with_source("toml", "input is not utf-8", e))?;
    let parsed: ::toml::Table =
        ::toml::from_str(text).map_err(|e| Error::malformed_caused_by("toml", e))?;
    merge_document(
        toml::toml_to_json(::toml::Value::Table(parsed)),
        values,
        errors,
    );
    Ok(())
}

/// Parse the bytes as an Apple Property List (XML, binary or ASCII form).
pub(super) fn extract_plist(
    bytes: &[u8],
    values: &mut Values,
    errors: &mut Errors,
) -> Result<(), Error> {
    merge_document(plist::parse_plist(bytes)?, values, errors);
    Ok(())
}

/// Typed native entitlement requests. A declaration is not proof of a valid
/// signature, permission grant, bundle identity or an executed memory action.
pub(super) fn plist_entitlement_metrics(values: &Values, metrics: &mut Metrics) {
    for (key, field) in [
        (
            "com.apple.security.cs.allow-jit",
            metric!("plist.jit_entitlement_requested"),
        ),
        (
            "com.apple.security.cs.allow-unsigned-executable-memory",
            metric!("plist.unsigned_executable_memory_entitlement_requested"),
        ),
    ] {
        let requested = values.as_json().get(key).and_then(JsonValue::as_bool) == Some(true);
        metrics.insert(field, f64::from(u8::from(requested)));
    }
}

/// Parse a bare Python Core Metadata file (`PKG-INFO`, `METADATA`) with the
/// one Core Metadata parser. Every header lands under its lowercased name; a
/// header that repeats becomes an array of its values in file order.
pub(super) fn extract_pkginfo(
    bytes: &[u8],
    values: &mut Values,
    errors: &mut Errors,
) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed_with_source("pkginfo", "input is not utf-8", e))?;
    let mut root: Map<String, JsonValue> = Map::new();
    for (key, value) in super::python_sdist::CoreMetadata::parse(text).fields {
        let value = JsonValue::String(value);
        match root.get_mut(&key) {
            None => {
                root.insert(key, value);
            }
            Some(JsonValue::Array(arr)) => arr.push(value),
            Some(existing) => {
                let prior = std::mem::replace(existing, JsonValue::Null);
                *existing = JsonValue::Array(vec![prior, value]);
            }
        }
    }
    merge_document(JsonValue::Object(root), values, errors);
    Ok(())
}

/// Roots filefacts writes for a structured document after its tree is
/// merged: the `npm.*` identity of a package.json, `cargo.build_mode`,
/// `composer.*` and the `json.parse.*` skip record. A document key naming one
/// would blend into those facts, so it is refused, as is a key naming a root
/// already written before the merge (`file.basename`).
///
/// Every other catalog root stays open to documents on purpose. Many are
/// ordinary words real manifests use at their top level: conda's `source`
/// and `build`, electron-builder's `build`, vercel's `pkg`, a JSON-RPC
/// `method`. Refusing them would discard facts to protect namespaces no
/// structured-document extractor writes.
const DERIVED_ROOTS: &[&str] = &["file", "npm", "cargo", "composer", "json"];

/// Merge a parsed document into `values`, beside whatever filefacts has
/// already written: an object's entries become root keys, and any other
/// document lands under `root`. A document key that names a reserved root
/// (one already present, or one of [`DERIVED_ROOTS`]) is dropped, and the
/// drop recorded in `errors`, so a document can neither erase nor forge
/// filefacts' own facts. A dotted key is judged by its first segment, since a
/// consumer that flattens the tree reads it as the path it spells.
pub(super) fn merge_document(doc: JsonValue, values: &mut Values, errors: &mut Errors) {
    let doc = match doc {
        JsonValue::Object(doc) => doc,
        other => {
            values.insert_key(value_key!("root"), other);
            return;
        }
    };
    let mut root = match std::mem::take(values).into_json() {
        JsonValue::Object(root) => root,
        _ => Map::new(),
    };
    let written: BTreeSet<String> = root.keys().cloned().collect();
    let reserved = |key: &str| {
        let first = key.split(['.', '[']).next().unwrap_or(key);
        DERIVED_ROOTS.contains(&first) || written.contains(first)
    };
    let mut dropped = Vec::new();
    for (key, value) in doc {
        if reserved(&key) {
            dropped.push(key);
        } else {
            root.insert(key, value);
        }
    }
    *values = Values::from_json(JsonValue::Object(root));
    if !dropped.is_empty() {
        tracing::debug!(
            target: "filefacts::structured",
            stage = "merge",
            keys = ?dropped,
            "document keys collide with filefacts-owned roots"
        );
        errors.record_fallback(
            Stage::FormatExtract,
            format!(
                "document keys {} name filefacts-owned roots; dropped",
                dropped.join(", ")
            ),
        );
    }
}

#[cfg(test)]
mod tests;
