use super::*;
use crate::formats::marshal::Version;
use crate::output::{Errors, Metrics, Symbol, Symbols, Values};

fn build_pyc(magic_word: u16, flags: u32, ts: u32, sz: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&magic_word.to_le_bytes());
    out.extend_from_slice(&[0x0D, 0x0A]);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&ts.to_le_bytes());
    out.extend_from_slice(&sz.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut sinks = crate::formats::Sinks::default();
    extract(bytes, sinks.ctx());
    (sinks.values, sinks.metrics)
}

fn literals(bytes: &[u8]) -> Vec<(String, u64)> {
    let mut sinks = crate::formats::Sinks::default();
    extract(bytes, sinks.ctx());
    sinks
        .strings
        .literals
        .iter()
        .map(|l| (l.value.clone(), l.offset))
        .collect()
}

fn identifiers(bytes: &[u8]) -> (Symbols, Errors) {
    let mut sinks = crate::formats::Sinks::default();
    extract(bytes, sinks.ctx());
    (sinks.symbols, sinks.errors)
}

#[test]
fn python_314_names_are_identifiers_but_catalog_constants_are_not() {
    let code = include_bytes!("../../../testdata/pyc/names-314.pyc");
    let (symbols, errors) = identifiers(code);
    assert!(errors.is_empty(), "{errors:?}");
    for name in ["keyboard", "on_press", "slice", "frozenset"] {
        assert!(symbols.iter().any(|s| s.name() == Some(name)), "{name}");
    }
    let (symbols, errors) = identifiers(include_bytes!("../../../testdata/pyc/strings-314.pyc"));
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(symbols.len(), 1);
    assert_eq!(
        symbols.iter().next().and_then(Symbol::name),
        Some("CATALOG")
    );
    let (values, _) = run(code);
    assert_eq!(
        values.get("pyc.python_version").and_then(|v| v.as_str()),
        Some("3.14")
    );
}

#[test]
fn python_311_code_layout_keeps_offsets_into_original_bytes() {
    let code = include_bytes!("../../../testdata/pyc/names-311.pyc");
    let (symbols, errors) = identifiers(code);
    assert!(errors.is_empty(), "{errors:?}");
    for name in ["strip", "replace", "startswith", "lstrip"] {
        let symbol = symbols.iter().find(|s| s.name() == Some(name)).unwrap();
        let Symbol::Identifier {
            offset: Some(offset),
            ..
        } = symbol
        else {
            panic!("identifier offset missing")
        };
        assert_eq!(
            &code[*offset as usize..*offset as usize + name.len()],
            name.as_bytes()
        );
    }
}

#[test]
fn truncated_nested_code_never_leaks_partial_identifier_facts() {
    let code = include_bytes!("../../../testdata/pyc/names-314.pyc");
    for end in 16..code.len() {
        let (symbols, errors) = identifiers(&code[..end]);
        assert!(
            symbols.is_empty(),
            "partial identifiers at truncation {end}"
        );
        assert!(!errors.is_empty(), "missing diagnostic at {end}");
    }
}

#[test]
fn malformed_or_excessive_marshal_inputs_are_recoverable() {
    for body in [
        b"c\0\0".as_slice(),
        b"r\xff\xff\xff\x7f".as_slice(),
        b"c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0(\xff\xff\xff\x7f".as_slice(),
    ] {
        let bytes = build_pyc(3627, 0, 0, 0, body);
        let (symbols, errors) = identifiers(&bytes);
        assert!(symbols.is_empty());
        assert!(!errors.is_empty());
    }
    let mut body = b"c".to_vec();
    body.extend_from_slice(&[0; 20]);
    for _ in 0..100 {
        body.extend_from_slice(b")\x01");
    }
    body.push(b'N');
    let (symbols, errors) = identifiers(&build_pyc(3627, 0, 0, 0, &body));
    assert!(symbols.is_empty());
    assert!(!errors.is_empty());
}

#[test]
fn surfaces_header_and_filenames() {
    let mut body = vec![0x10];
    body.extend_from_slice(b"/build/foo/bar.py");
    body.push(0);
    let pyc = build_pyc(3413, 0, 1_700_000_000, 1234, &body);
    let (v, m) = run(&pyc);
    assert_eq!(
        v.get("pyc.python_version").and_then(|x| x.as_str()),
        Some("3.8")
    );
    assert_eq!(m.get("pyc.timestamp"), Some(1_700_000_000.0));
    assert_eq!(m.get("pyc.source_size"), Some(1234.0));
    let files = v
        .get("pyc.source_files")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(files[0].as_str(), Some("/build/foo/bar.py"));
}

#[test]
fn hash_based_emits_hash_key_not_timestamp() {
    let body = b"\x10/build/foo.py\x00".to_vec();
    let pyc = build_pyc(3439, 0x01, 0, 0, &body);
    let (v, m) = run(&pyc);
    assert!(v.get("pyc.hash").is_some());
    assert!(m.get("pyc.timestamp").is_none());
}

#[test]
fn rejects_too_short() {
    let (v, _) = run(b"short");
    assert!(v.get("pyc.magic").is_none());
}

#[test]
fn rejects_bad_signature() {
    let (v, _) = run(&[0u8; 32]);
    assert!(v.get("pyc.magic").is_none());
}

#[test]
fn dedupes_filenames() {
    let mut body = Vec::new();
    for _ in 0..40 {
        body.push(0x10);
        body.extend_from_slice(b"/tmp/file.py");
        body.push(0);
    }
    let pyc = build_pyc(3413, 0, 1, 1, &body);
    let (v, _) = run(&pyc);
    let files = v
        .get("pyc.source_files")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(files.len(), 1);
}

#[test]
fn unknown_magic_omits_version() {
    // Magic word not in the version table — header still parses,
    // but `pyc.python_version` is omitted rather than mis-labelled.
    let pyc = build_pyc(9999, 0, 0, 0, b"");
    let (v, _) = run(&pyc);
    assert!(v.get("pyc.magic").is_some());
    assert!(v.get("pyc.python_version").is_none());
}

#[test]
fn recognizes_pyx_pyw_pyi_extensions() {
    let mut body = Vec::new();
    for path in [b"a/b.pyx" as &[u8], b"c/d.pyw", b"e/f.pyi", b"g.py"] {
        body.push(0x10);
        body.extend_from_slice(path);
        body.push(0);
    }
    let pyc = build_pyc(3413, 0, 1, 1, &body);
    let (v, m) = run(&pyc);
    let files = v
        .get("pyc.source_files")
        .and_then(|x| x.as_array())
        .unwrap();
    let paths: Vec<&str> = files.iter().filter_map(|x| x.as_str()).collect();
    assert!(paths.contains(&"a/b.pyx"));
    assert!(paths.contains(&"c/d.pyw"));
    assert!(paths.contains(&"e/f.pyi"));
    assert!(paths.contains(&"g.py"));
    assert_eq!(m.get("pyc.source_file_count"), Some(4.0));
}

#[test]
fn rejects_signature_with_wrong_second_pair() {
    // First two bytes look like a magic word but the next two are
    // not `\r\n` — must reject.
    let mut bytes = vec![0x55, 0x0D, 0x00, 0x00];
    bytes.extend_from_slice(&[0u8; 12]);
    let (v, _) = run(&bytes);
    assert!(v.get("pyc.magic").is_none());
}

#[test]
fn body_scan_caps_filename_count() {
    // Build 40 distinct filenames; should cap at MAX_SOURCE_FILES (32).
    let mut body = Vec::new();
    for i in 0..40 {
        body.push(0x10);
        body.extend_from_slice(format!("/tmp/file{i}.py").as_bytes());
        body.push(0);
    }
    let pyc = build_pyc(3413, 0, 1, 1, &body);
    let (v, _) = run(&pyc);
    let files = v
        .get("pyc.source_files")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(files.len(), MAX_SOURCE_FILES);
}

#[test]
fn empty_input_is_silent() {
    let (v, _) = run(&[]);
    assert!(v.get("pyc.magic").is_none());
}

/// A module's `str` constants are its string literals, each at the offset of
/// its bytes in the file; they never become identifiers, and names never
/// become literals.
#[test]
fn string_constants_are_literals_at_their_offsets() {
    let code = include_bytes!("../../../testdata/pyc/strings-314.pyc");
    let found = literals(code);
    for want in [
        "create_text_channel",
        "This channel will receive keystroke logs every 5 seconds.",
        "Starting key logging with 5-second batching",
        "Execute shell command",
    ] {
        let (value, offset) = found
            .iter()
            .find(|(v, _)| v == want)
            .unwrap_or_else(|| panic!("{want} missing from {found:?}"));
        let at = usize::try_from(*offset).unwrap();
        assert_eq!(&code[at..at + value.len()], value.as_bytes());
    }
    assert!(
        !found.iter().any(|(v, _)| v == "CATALOG"),
        "a name is not a literal"
    );
    let (symbols, _) = identifiers(code);
    assert!(
        !symbols
            .iter()
            .any(|s| s.name() == Some("create_text_channel"))
    );
    // Older layouts carry their constants too.
    let found = literals(include_bytes!("../../../testdata/pyc/names-311.pyc"));
    assert!(found.iter().any(|(v, _)| v == "Bearer "), "{found:?}");
}

#[test]
fn truncated_streams_never_leak_partial_literals() {
    let code = include_bytes!("../../../testdata/pyc/strings-314.pyc");
    for end in 16..code.len() {
        assert!(
            literals(&code[..end]).is_empty(),
            "partial literals at truncation {end}"
        );
    }
}

/// The string literals every `literals-*.pyc` module spells (see the README).
const MODULE_LITERALS: &[&str] = &[
    "Module docstring for the literal fixture.",
    "1234567890:AAEhBP0av18o8wSxQkJt-2A_bCdEfGhIjKl",
    "bytes-constant-value",
    "first-mode",
    "second-mode",
    "Handle one event.",
    "open",
    "close",
    "nested-function-literal",
    "lambda-literal",
    "class-body-literal",
];

/// One module compiled by every CPython from 3.8 to 3.16a2: each release's
/// code-object layout and marshal dialect yields every literal, at its
/// offset, with no diagnostic, and the release is named.
#[test]
fn every_release_from_38_to_316_yields_its_literals() {
    let modules: [(&str, &[u8]); 9] = [
        (
            "3.8",
            include_bytes!("../../../testdata/pyc/literals-38.pyc"),
        ),
        (
            "3.9",
            include_bytes!("../../../testdata/pyc/literals-39.pyc"),
        ),
        (
            "3.10",
            include_bytes!("../../../testdata/pyc/literals-310.pyc"),
        ),
        (
            "3.11",
            include_bytes!("../../../testdata/pyc/literals-311.pyc"),
        ),
        (
            "3.12",
            include_bytes!("../../../testdata/pyc/literals-312.pyc"),
        ),
        (
            "3.13",
            include_bytes!("../../../testdata/pyc/literals-313.pyc"),
        ),
        (
            "3.14",
            include_bytes!("../../../testdata/pyc/literals-314.pyc"),
        ),
        (
            "3.15",
            include_bytes!("../../../testdata/pyc/literals-315.pyc"),
        ),
        (
            "3.16",
            include_bytes!("../../../testdata/pyc/literals-316.pyc"),
        ),
    ];
    for (release, code) in modules {
        let (symbols, errors) = identifiers(code);
        assert!(errors.is_empty(), "{release}: {errors:?}");
        assert!(
            symbols.iter().any(|s| s.name() == Some("handler")),
            "{release}"
        );
        let found = literals(code);
        for want in MODULE_LITERALS {
            let (value, offset) = found
                .iter()
                .find(|(v, _)| v == want)
                .unwrap_or_else(|| panic!("{release}: {want} missing from {found:?}"));
            let at = usize::try_from(*offset).unwrap();
            assert_eq!(&code[at..at + value.len()], value.as_bytes(), "{release}");
        }
        let (values, _) = run(code);
        assert_eq!(
            values.get("pyc.python_version").and_then(|v| v.as_str()),
            Some(release)
        );
    }
}

/// A marshal code object in `release`'s layout, its constants `consts`
/// (each already marshalled) and its one name `name` (marshalled).
fn code_object(release: Version, consts: &[Vec<u8>], name: &[u8]) -> Vec<u8> {
    let int = |out: &mut Vec<u8>, n: u32| out.extend_from_slice(&n.to_le_bytes());
    let bytes = |out: &mut Vec<u8>, b: &[u8]| {
        out.push(b's');
        out.extend_from_slice(&u32::try_from(b.len()).unwrap().to_le_bytes());
        out.extend_from_slice(b);
    };
    let tuple = |out: &mut Vec<u8>, items: &[&[u8]]| {
        out.push(b'(');
        out.extend_from_slice(&u32::try_from(items.len()).unwrap().to_le_bytes());
        for item in items {
            out.extend_from_slice(item);
        }
    };
    let counts = if release.major == 2 {
        3
    } else if release >= Version::three(8) {
        5
    } else {
        4
    };
    let mut out = vec![b'c'];
    for _ in 0..counts {
        int(&mut out, 0);
    }
    int(&mut out, 0x40); // co_flags
    bytes(&mut out, b"d\x00S\x00"); // co_code
    tuple(
        &mut out,
        &consts.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    tuple(&mut out, &[name]);
    for _ in 0..3 {
        tuple(&mut out, &[]); // co_varnames, co_freevars, co_cellvars
    }
    bytes(&mut out, b"old.py"); // co_filename
    bytes(&mut out, b"<module>"); // co_name
    int(&mut out, 1); // co_firstlineno
    bytes(&mut out, b""); // co_lnotab
    out
}

/// A marshal string object of type `tag`.
fn string(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// Releases no current interpreter writes, assembled to their documented
/// layouts: 2.7 (byte-string `str`, 16 bytes of counts, an 8-byte header),
/// 3.0-3.2 (8-byte header), 3.3-3.6 (12-byte header) and 3.7 (16), with
/// the interned-string back-references (`R`) used before 3.4.
#[test]
fn older_releases_yield_their_literals() {
    let reference = |index: u32| {
        let mut out = vec![b'R'];
        out.extend_from_slice(&index.to_le_bytes());
        out
    };
    let cases: [(u16, Version, usize, Vec<Vec<u8>>, &[&str]); 5] = [
        (
            62211,
            Version { major: 2, minor: 7 },
            8,
            vec![
                string(b't', b"py2-interned"),
                string(b's', b"py2-plain"),
                string(b'u', b"py2-unicode"),
                reference(0),
            ],
            &["py2-interned", "py2-plain", "py2-unicode"],
        ),
        (
            3131,
            Version::three(0),
            8,
            vec![
                string(b't', b"py30-interned"),
                reference(0),
                string(b'u', b"py30-text"),
            ],
            &["py30-interned", "py30-text"],
        ),
        (
            3230,
            Version::three(3),
            12,
            vec![string(b'u', b"py33-text"), string(b's', b"py33-bytes")],
            &["py33-text", "py33-bytes"],
        ),
        (
            3379,
            Version::three(6),
            12,
            vec![string(b'a', b"py36-ascii"), string(b'u', b"py36-text")],
            &["py36-ascii", "py36-text"],
        ),
        (
            3394,
            Version::three(7),
            16,
            vec![string(b'u', b"py37-text")],
            &["py37-text"],
        ),
    ];
    for (magic, release, header_len, consts, want) in cases {
        let name = if release.major == 2 {
            string(b't', b"handler")
        } else {
            string(b'u', b"handler")
        };
        let mut pyc = magic.to_le_bytes().to_vec();
        pyc.extend_from_slice(&[0x0D, 0x0A]);
        pyc.resize(header_len, 0);
        pyc.extend_from_slice(&code_object(release, &consts, &name));
        let (symbols, errors) = identifiers(&pyc);
        assert!(errors.is_empty(), "{release:?}: {errors:?}");
        assert!(
            symbols.iter().any(|s| s.name() == Some("handler")),
            "{release:?}"
        );
        let found = literals(&pyc);
        for w in want {
            let (value, offset) = found
                .iter()
                .find(|(v, _)| v == w)
                .unwrap_or_else(|| panic!("{release:?}: {w} missing from {found:?}"));
            let at = usize::try_from(*offset).unwrap();
            assert_eq!(&pyc[at..at + value.len()], value.as_bytes(), "{release:?}");
        }
        let (values, _) = run(&pyc);
        assert_eq!(
            values.get("pyc.python_version").and_then(|v| v.as_str()),
            Some(format!("{}.{}", release.major, release.minor).as_str())
        );
    }
}

/// Every release's block of magic words maps to it, and words outside every
/// block map to nothing.
#[test]
fn magic_words_name_their_release() {
    for (word, release) in [
        (62211, Some(Version { major: 2, minor: 7 })),
        (3131, Some(Version::three(0))),
        (3310, Some(Version::three(4))),
        (3394, Some(Version::three(7))),
        (3413, Some(Version::three(8))),
        (3495, Some(Version::three(11))),
        (3600, Some(Version::three(14))),
        (3627, Some(Version::three(14))),
        (3666, Some(Version::three(15))),
        (3706, Some(Version::three(16))),
        (3750, None),
        (20121, None),
    ] {
        assert_eq!(python_version_for_magic(word), release, "{word}");
    }
}
