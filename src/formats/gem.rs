//! RubyGems package (`.gem`) metadata extractor.
//!
//! A gem is an uncompressed `ustar` tar holding three members:
//! `metadata.gz` (a gzipped `Gem::Specification` YAML), `data.tar.gz` (the
//! installed files), and `checksums.yaml.gz`. The package's *identity* —
//! name, version, dependencies, authors — lives only in `metadata.gz`; it
//! never appears in the installed file tree. This extractor reads that one
//! member (gunzipping just it, no other decompression) and surfaces the
//! identity as `gem.*` facts.
//!
//! Emitted keys:
//!
//! - `gem.name`, `gem.version`, `gem.platform` — core identity. `platform`
//!   is `"ruby"` for pure-Ruby gems, otherwise a native target triple.
//! - `gem.summary`, `gem.homepage` — provenance / impersonation signals.
//! - `gem.licenses[]`, `gem.authors[]` — SPDX licenses and author names.
//! - `gem.runtime_dependencies[]` — runtime dependency names (bounded).
//! - `gem.dependency_count`, `gem.runtime_dependency_count`,
//!   `gem.development_dependency_count` — dependency-shape metrics.

use crate::metric;
use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::output::{Metrics, Values};
use crate::value_key;

use super::structured::parse_yaml;

/// Cap on the compressed `metadata.gz` we read from the outer tar. Real gem
/// specifications are a few KiB; anything larger is malformed or hostile.
const MAX_METADATA_GZ: u64 = 1 << 20; // 1 MiB
/// Cap on the decompressed YAML, guarding against a gzip bomb in `metadata.gz`.
const MAX_METADATA_YAML: u64 = 8 << 20; // 8 MiB
/// Cap on the number of list entries (authors, licenses, dependency names)
/// retained — a gem with tens of thousands of deps shouldn't bloat the facts.
const MAX_LIST: usize = 256;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    // A gem whose `metadata.gz` is absent or unparseable still gets the generic
    // archive.* surface from the tar walker — just no gem.* identity. Degrade
    // quietly rather than failing the whole extraction.
    let Some(spec) = read_metadata(bytes) else {
        return Ok(());
    };

    if let Some(name) = field_str(&spec, "name") {
        values.insert_key(value_key!("gem.name"), JsonValue::String(name.to_string()));
    }
    // `version` is a nested `!ruby/object:Gem::Version` mapping: { version: x }.
    if let Some(version) = spec.get("version").and_then(|v| field_str(v, "version")) {
        values.insert_key(
            value_key!("gem.version"),
            JsonValue::String(version.to_string()),
        );
    }
    if let Some(platform) = field_str(&spec, "platform") {
        values.insert("gem.platform", JsonValue::String(platform.to_string()));
    }
    if let Some(summary) = field_str(&spec, "summary") {
        values.insert_key(
            value_key!("gem.summary"),
            JsonValue::String(summary.to_string()),
        );
    }
    if let Some(homepage) = field_str(&spec, "homepage") {
        values.insert_key(
            value_key!("gem.homepage"),
            JsonValue::String(homepage.to_string()),
        );
    }

    // `licenses` (plural, a sequence) is current; `license` (singular) is the
    // legacy single-value form. Prefer the sequence, fall back to the scalar.
    let mut licenses = collect_strings(spec.get("licenses"));
    if licenses.is_empty() {
        if let Some(l) = field_str(&spec, "license") {
            licenses.push(l.to_string());
        }
    }
    if !licenses.is_empty() {
        values.insert("gem.licenses", string_array(&licenses));
    }

    // Same plural/singular split for authors (`authors` seq vs `author` scalar).
    let mut authors = collect_strings(spec.get("authors"));
    if authors.is_empty() {
        if let Some(a) = field_str(&spec, "author") {
            authors.push(a.to_string());
        }
    }
    if !authors.is_empty() {
        values.insert_key(value_key!("gem.authors"), string_array(&authors));
    }

    extract_dependencies(&spec, values, metrics);
    Ok(())
}

/// Walk the outer (uncompressed) tar, read `metadata.gz`, gunzip it, and parse
/// the `Gem::Specification` YAML. Its Ruby tags are dropped, leaving plain
/// mappings. Returns `None` on any malformed step — the caller treats that as
/// "no gem identity available".
fn read_metadata(bytes: &[u8]) -> Option<JsonValue> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    for entry in archive.entries().ok()? {
        let Ok(mut entry) = entry else { break };
        // Take an owned copy of the member name so the immutable borrow of
        // `entry` ends before we read its body.
        let name = entry.path().ok().map(|p| p.to_string_lossy().into_owned());
        if name.as_deref() != Some("metadata.gz") {
            continue;
        }
        let mut gz = Vec::new();
        entry
            .by_ref()
            .take(MAX_METADATA_GZ)
            .read_to_end(&mut gz)
            .ok()?;
        let mut yaml = String::new();
        flate2::read::GzDecoder::new(&gz[..])
            .take(MAX_METADATA_YAML)
            .read_to_string(&mut yaml)
            .ok()?;
        return parse_yaml(yaml.as_bytes()).ok();
    }
    None
}

/// Surface the dependency shape. Each dependency is a
/// `!ruby/object:Gem::Dependency` mapping with a `name` and a `type` symbol
/// (`:runtime` or `:development`).
fn extract_dependencies(spec: &JsonValue, values: &mut Values, metrics: &mut Metrics) {
    let Some(deps) = spec.get("dependencies").and_then(JsonValue::as_array) else {
        return;
    };
    let mut runtime: Vec<String> = Vec::new();
    let mut runtime_count: u64 = 0;
    let mut development_count: u64 = 0;
    for dep in deps {
        let Some(name) = field_str(dep, "name") else {
            continue;
        };
        // YAML symbols (`:runtime`) parse as the string `":runtime"`; tolerate
        // both the symbol and bare forms.
        let is_dev =
            field_str(dep, "type").is_some_and(|t| t == ":development" || t == "development");
        if is_dev {
            development_count += 1;
        } else {
            runtime_count += 1;
            if runtime.len() < MAX_LIST {
                runtime.push(name.to_string());
            }
        }
    }
    metrics.insert(metric!("gem.dependency_count"), deps.len() as f64);
    metrics.insert(
        metric!("gem.runtime_dependency_count"),
        runtime_count as f64,
    );
    metrics.insert(
        metric!("gem.development_dependency_count"),
        development_count as f64,
    );
    if !runtime.is_empty() {
        values.insert_key(
            value_key!("gem.runtime_dependencies"),
            string_array(&runtime),
        );
    }
}

/// Convenience: the string value of `key` within a mapping.
fn field_str<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    v.get(key).and_then(JsonValue::as_str)
}

/// Collect the string entries of a sequence, bounded.
fn collect_strings(v: Option<&JsonValue>) -> Vec<String> {
    v.and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .take(MAX_LIST)
        .filter_map(JsonValue::as_str)
        .map(str::to_string)
        .collect()
}

fn string_array(items: &[String]) -> JsonValue {
    JsonValue::Array(items.iter().cloned().map(JsonValue::String).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal `.gem`: an uncompressed tar whose `metadata.gz` member
    /// is the gzipped `spec_yaml`.
    fn build_gem(spec_yaml: &str) -> Vec<u8> {
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(spec_yaml.as_bytes()).unwrap();
            enc.finish().unwrap();
        }
        let mut out = Vec::new();
        {
            let mut b = tar::Builder::new(&mut out);
            let mut h = tar::Header::new_ustar();
            h.set_path("metadata.gz").unwrap();
            h.set_size(gz.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, &gz[..]).unwrap();
            b.finish().unwrap();
        }
        out
    }

    const RAILS_SPEC: &str = r#"--- !ruby/object:Gem::Specification
name: rails
version: !ruby/object:Gem::Version
  version: 7.0.4
platform: ruby
authors:
- David Heinemeier Hansson
homepage: https://rubyonrails.org
licenses:
- MIT
dependencies:
- !ruby/object:Gem::Dependency
  name: activesupport
  type: :runtime
- !ruby/object:Gem::Dependency
  name: rake
  type: :development
summary: Full-stack web application framework.
"#;

    #[test]
    fn extracts_core_identity() {
        let gem = build_gem(RAILS_SPEC);
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract(&gem, &mut v, &mut m).unwrap();

        assert_eq!(v.get("gem.name").and_then(|x| x.as_str()), Some("rails"));
        assert_eq!(v.get("gem.version").and_then(|x| x.as_str()), Some("7.0.4"));
        assert_eq!(v.get("gem.platform").and_then(|x| x.as_str()), Some("ruby"));
        assert_eq!(
            v.get("gem.homepage").and_then(|x| x.as_str()),
            Some("https://rubyonrails.org")
        );
    }

    #[test]
    fn splits_runtime_and_development_dependencies() {
        let gem = build_gem(RAILS_SPEC);
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract(&gem, &mut v, &mut m).unwrap();

        assert_eq!(m.get("gem.dependency_count"), Some(2.0));
        assert_eq!(m.get("gem.runtime_dependency_count"), Some(1.0));
        assert_eq!(m.get("gem.development_dependency_count"), Some(1.0));
        let runtime = v
            .get("gem.runtime_dependencies")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(runtime.len(), 1);
        assert_eq!(runtime[0].as_str(), Some("activesupport"));
    }

    #[test]
    fn collects_licenses_and_authors() {
        let gem = build_gem(RAILS_SPEC);
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract(&gem, &mut v, &mut m).unwrap();

        let licenses = v.get("gem.licenses").and_then(|x| x.as_array()).unwrap();
        assert_eq!(licenses[0].as_str(), Some("MIT"));
        let authors = v.get("gem.authors").and_then(|x| x.as_array()).unwrap();
        assert_eq!(authors[0].as_str(), Some("David Heinemeier Hansson"));
    }

    /// RubyGems writes a requirement shared by two fields as an anchor and an
    /// alias, and quotes nothing that YAML 1.2 reads as a string: `yes` and
    /// `on` stay names here.
    #[test]
    fn aliased_requirements_and_yaml_1_1_words_parse() {
        let spec = r#"--- !ruby/object:Gem::Specification
name: yes
version: !ruby/object:Gem::Version
  version: '1.0'
platform: ruby
authors: [on, off]
dependencies:
- !ruby/object:Gem::Dependency
  name: rake
  requirement: &1 !ruby/object:Gem::Requirement
    requirements:
    - - ">="
      - !ruby/object:Gem::Version
        version: '0'
  type: :development
  version_requirements: *1
- !ruby/object:Gem::Dependency
  name: no
  type: :runtime
"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract(&build_gem(spec), &mut v, &mut m).unwrap();
        assert_eq!(v.get("gem.name").and_then(|x| x.as_str()), Some("yes"));
        assert_eq!(v.get("gem.version").and_then(|x| x.as_str()), Some("1.0"));
        assert_eq!(
            v.get("gem.authors"),
            Some(&serde_json::json!(["on", "off"]))
        );
        assert_eq!(m.get("gem.development_dependency_count"), Some(1.0));
        assert_eq!(
            v.get("gem.runtime_dependencies"),
            Some(&serde_json::json!(["no"]))
        );
    }

    #[test]
    fn missing_metadata_degrades_quietly() {
        // A tar with no metadata.gz member: extract succeeds, emits no gem.*.
        let mut out = Vec::new();
        {
            let mut b = tar::Builder::new(&mut out);
            let mut h = tar::Header::new_ustar();
            h.set_path("data.tar.gz").unwrap();
            h.set_size(0);
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract(&out, &mut v, &mut m).unwrap();
        assert!(v.get("gem.name").is_none());
    }
}
