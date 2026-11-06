use super::{Values, split_index};
use serde_json::json;

#[test]
fn insert_and_get_top_level() {
    let mut v = Values::new();
    v.insert("name", json!("filefacts"));
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("filefacts"));
}

#[test]
fn insert_creates_nested_objects() {
    let mut v = Values::new();
    v.insert("pe.coff.machine", json!("x86_64"));
    assert_eq!(
        v.get("pe.coff.machine").and_then(|x| x.as_str()),
        Some("x86_64")
    );
    assert!(v.get("pe.coff").unwrap().is_object());
}

#[test]
fn insert_overwrites_non_object_intermediate() {
    // Setting a leaf, then nesting under the same key, should not
    // panic — the leaf is overwritten with an object.
    let mut v = Values::new();
    v.insert("pe", json!("leaf"));
    v.insert("pe.coff.machine", json!("x86_64"));
    assert_eq!(
        v.get("pe.coff.machine").and_then(|x| x.as_str()),
        Some("x86_64")
    );
}

#[test]
fn get_missing_returns_none() {
    let v = Values::new();
    assert!(v.get("nope").is_none());
    assert!(v.get("a.b.c").is_none());
}

#[test]
fn iter_yields_top_level() {
    let mut v = Values::new();
    v.insert("a", json!(1));
    v.insert("b", json!(2));
    let keys: Vec<&str> = v.iter().map(|(k, _)| k).collect();
    assert!(keys.contains(&"a"));
    assert!(keys.contains(&"b"));
}

#[test]
fn is_empty_works() {
    let v = Values::new();
    assert!(v.is_empty());
    let mut v = Values::new();
    v.insert("x", json!(1));
    assert!(!v.is_empty());
}

/// The checked accessors read and write exactly what the string
/// accessors do at the joined path, so converting a call site cannot
/// change output.
#[test]
fn checked_accessors_match_string_paths() {
    let mut v = Values::new();
    v.insert_key(
        crate::value_key!("pe.signatures"),
        json!([{"subject": "CN=a", "thumbprint_sha256": "ab"}]),
    );
    v.insert_key_at(
        crate::value_key!("office.compobj"),
        "prog_id",
        json!("Word.Document.8"),
    );
    v.insert("office.compobj.user_type", json!("Microsoft Word"));

    let sigs = crate::value_key!("pe.signatures");
    assert_eq!(v.lookup(sigs), v.get("pe.signatures"));
    for rest in ["[0]", "[0].thumbprint_sha256", "[1]", "[0].missing", ""] {
        let joined = if rest.is_empty() || rest.starts_with('[') {
            format!("pe.signatures{rest}")
        } else {
            format!("pe.signatures.{rest}")
        };
        assert_eq!(v.lookup_at(sigs, rest), v.get(&joined), "{rest:?}");
    }
    let compobj = crate::value_key!("office.compobj");
    assert_eq!(
        v.lookup_at(compobj, "prog_id"),
        Some(&json!("Word.Document.8"))
    );
    assert_eq!(
        v.lookup_at(compobj, "user_type"),
        v.get("office.compobj.user_type")
    );
    assert!(v.lookup(crate::value_key!("pe.go")).is_none());
}

#[test]
fn serializes_as_json_object() {
    let mut v = Values::new();
    v.insert("pe.coff.machine", json!("x86_64"));
    let s = serde_json::to_string(&v).unwrap();
    assert_eq!(s, r#"{"pe":{"coff":{"machine":"x86_64"}}}"#);
}

#[test]
fn a_path_from_data_cannot_nest_the_tree_without_bound() {
    // A data tail of dots must not become a million nested objects: the
    // tree is dropped and serialized recursively.
    let mut v = Values::new();
    let tail = ".".repeat(1_000_000);
    v.insert(&format!("wasm.producers.{tail}"), json!("x"));
    assert!(serde_json::to_string(&v).is_ok());
    assert!(v.get("wasm.producers").unwrap().is_object());
    drop(v);
}

#[test]
fn split_index_plain_key() {
    assert_eq!(split_index("plain"), ("plain", None));
}

#[test]
fn split_index_indexed_key() {
    assert_eq!(split_index("members[0]"), ("members", Some(0)));
    assert_eq!(split_index("a[42]"), ("a", Some(42)));
}

#[test]
fn split_index_malformed_falls_through() {
    // Strict parsing here would force every caller to handle the
    // "malformed input" case. Returning the segment unchanged lets
    // `navigate` fail naturally on the subsequent object lookup.
    assert_eq!(split_index("members["), ("members[", None));
    assert_eq!(split_index("members[a]"), ("members[a]", None));
}
