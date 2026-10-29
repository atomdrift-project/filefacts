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
    extract(&gem, &mut v, &mut m, &mut Errors::new());

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
    extract(&gem, &mut v, &mut m, &mut Errors::new());

    assert_eq!(m.get("gem.dependency_count"), Some(2.0));
    assert_eq!(m.get("gem.runtime_dependency_count"), Some(1.0));
    assert_eq!(m.get("gem.development_dependency_count"), Some(1.0));
    let runtime = v
        .get("gem.dependencies")
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
    extract(&gem, &mut v, &mut m, &mut Errors::new());

    assert_eq!(v.get("gem.license").and_then(|x| x.as_str()), Some("MIT"));
    let authors = v.get("gem.authors").and_then(|x| x.as_array()).unwrap();
    assert_eq!(
        authors[0]["name"].as_str(),
        Some("David Heinemeier Hansson")
    );
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
    extract(&build_gem(spec), &mut v, &mut m, &mut Errors::new());
    assert_eq!(v.get("gem.name").and_then(|x| x.as_str()), Some("yes"));
    assert_eq!(v.get("gem.version").and_then(|x| x.as_str()), Some("1.0"));
    assert_eq!(
        v.get("gem.authors"),
        Some(&serde_json::json!([{"name": "on"}, {"name": "off"}]))
    );
    assert_eq!(m.get("gem.development_dependency_count"), Some(1.0));
    assert_eq!(v.get("gem.dependencies"), Some(&serde_json::json!(["no"])));
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
    let mut errors = Errors::new();
    extract(&out, &mut v, &mut m, &mut errors);
    assert!(v.get("gem.name").is_none());
    assert!(errors.is_empty(), "{errors:?}");
}

/// A gem with the metadata member but no gzip stream inside it, or with
/// a spec that is not YAML, degrades to no gem.* facts with the failed
/// step recorded rather than silently swallowed.
#[test]
fn unreadable_metadata_is_recorded() {
    let mut not_gzip = Vec::new();
    {
        let mut b = tar::Builder::new(&mut not_gzip);
        let mut h = tar::Header::new_ustar();
        h.set_path("metadata.gz").unwrap();
        h.set_size(8);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, &b"not gzip"[..]).unwrap();
        b.finish().unwrap();
    }
    for (gem, step) in [
        (not_gzip, "gunzip failed"),
        (build_gem("name: [unclosed"), "metadata.gz: "),
    ] {
        let mut v = Values::new();
        let mut errors = Errors::new();
        extract(&gem, &mut v, &mut Metrics::new(), &mut errors);
        assert!(v.get("gem.name").is_none());
        assert!(
            errors
                .iter()
                .any(|e| e.stage == Stage::FormatExtract && e.message.contains(step)),
            "{step}: {errors:?}"
        );
    }
}
