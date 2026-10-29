use super::*;

fn open<'a>(path: &str, source: &'a str) -> crate::ParsedFile<'a> {
    crate::OpenOptions::new()
        .path(std::path::Path::new(path))
        .open(source.as_bytes())
}

/// A kind name used for both a named and an anonymous node matches both,
/// as comparing `Node::kind` does.
#[test]
fn kind_sets_match_every_symbol_with_the_name() {
    let language: Language = tree_sitter_python::LANGUAGE.into();
    let set = KindSet::new(&language, &["lambda"]);
    let named = language.id_for_node_kind("lambda", true);
    let anonymous = language.id_for_node_kind("lambda", false);
    assert_ne!(named, anonymous);
    assert!(set.contains(named) && set.contains(anonymous));
    assert!(!set.contains(language.id_for_node_kind("identifier", true)));
    assert!(!set.contains(u16::MAX), "ERROR is in no set");
}

/// Literals are in source order, as every other walk output is.
#[test]
fn literals_are_in_source_order() {
    let parsed = open("a.py", "x = 'a'\ny = ['b', 'c']\n");
    let texts: Vec<&str> = parsed.literals().iter().map(|l| l.value.as_str()).collect();
    assert_eq!(texts, ["a", "b", "c"]);
}

/// A function counts as nested-containing when any function lies
/// anywhere inside it, found in the same walk rather than by re-walking
/// each function's subtree.
#[test]
fn nested_functions_are_found_during_the_walk() {
    let parsed = open(
        "a.js",
        "function a() { if (x) { while (y) { function b() {} } } }\nfunction c() { return 1; }\n",
    );
    let metrics = parsed.metrics();
    assert_eq!(metrics.get("functions.nested"), Some(1.0));
    assert_eq!(metrics.get("functions.max_nesting_depth"), Some(1.0));
}

/// The payload-flow index has no size limit of its own: a module of many
/// statements is analysed within the evaluation step budget.
#[test]
fn payload_index_covers_every_statement() {
    let source = format!(
        "{}import os, requests\nrequests.post(url, data=dict(os.environ))\n",
        "x = 1\n".repeat(20_000)
    );
    let parsed = open("a.py", &source);
    let values = parsed.values();
    assert_eq!(
        values
            .get("source.payload_flow.truncated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(
        values
            .get("source.payload_flow.events")
            .is_some_and(|events| events.to_string().contains("environment-http-body"))
    );
}

/// Identifier metrics read leaf identifiers only, so nested identifier
/// kinds cannot make them read more text than the source holds: each `"$(`
/// level is a `command_name` spanning every level inside it.
#[test]
fn nested_identifier_kinds_count_their_leaves_once() {
    let depth = 4_000;
    let source = format!("x={}echo{}\n", "\"$(".repeat(depth), ")\"".repeat(depth));
    let parsed = open("a.sh", &source);
    let metrics = parsed.metrics();
    let count = metrics.get("identifiers.count").expect("identifiers");
    let avg = metrics.get("identifiers.avg_length").expect("identifiers");
    assert!(count * avg <= source.len() as f64, "{count} × {avg}");

    // `echo hi\nls -l\n`: the words, not the `command_name`s around two of
    // them.
    let parsed = open("a.sh", "echo hi\nls -l\n");
    assert_eq!(parsed.metrics().get("identifiers.count"), Some(4.0));
}
