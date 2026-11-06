use super::*;
use std::collections::BTreeSet;

#[test]
fn every_view_has_a_unique_name_that_round_trips() {
    let mut names = BTreeSet::new();
    for &view in View::ALL {
        assert!(names.insert(view.name()), "{} is listed twice", view.name());
        assert_eq!(View::from_name(view.name()), Some(view));
        assert!(!view.description().is_empty());
    }
    assert_eq!(View::from_name("strings"), None);
}

#[test]
fn bundle_carries_every_bundled_view_and_nothing_else() {
    let parsed = hermetic(
        "example.py",
        b"import os  # fetch\nos.system('curl http://example.invalid/x')\n",
    );
    let bundle = serde_json::to_value(parsed.bundle()).unwrap();
    let keys: BTreeSet<&str> = bundle
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = std::iter::once("schema_version")
        .chain(
            View::ALL
                .iter()
                .copied()
                .filter(|v| v.bundled())
                .map(View::name),
        )
        .collect();
    assert_eq!(keys, expected);
    for &view in View::ALL {
        let alone = serde_json::to_value(parsed.view(view)).unwrap();
        match view {
            _ if view.bundled() => assert_eq!(bundle[view.name()], alone, "{view:?}"),
            // A kind's rows are the matching rows of `symbols`.
            View::Kind(_) => {
                let symbols = bundle["symbols"].as_array().unwrap();
                assert!(
                    alone
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|r| symbols.contains(r))
                );
            }
            View::Flow => assert!(alone.is_object()),
            _ => panic!("{view:?} is neither bundled nor covered"),
        }
    }
    assert_eq!(parsed.parse_count(), 1);
}

fn hermetic<'a>(path: &str, bytes: &'a [u8]) -> ParsedFile<'a> {
    crate::OpenOptions::new()
        .cache(false)
        .path(std::path::Path::new(path))
        .open(bytes)
}

#[test]
fn flow_is_a_format_neutral_view() {
    let parsed = hermetic("example.py", b"send(acquire())\n");
    let value = serde_json::to_value(parsed.view(View::Flow)).unwrap();
    assert_eq!(value["producer"], "tree-sitter");
    assert_eq!(value["language"], "python");
    assert!(value["values"].as_array().is_some());
    assert_eq!(parsed.parse_count(), 1);
}

#[test]
fn unavailable_binary_flow_is_null_not_an_empty_graph() {
    let parsed = hermetic(
        "example.elf",
        include_bytes!("../../tests/fixtures/test.elf"),
    );
    assert!(parsed.flow().is_none());
    let value = serde_json::to_value(parsed.view(View::Flow)).unwrap();
    assert!(value.is_null());
}
