use super::*;

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
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    extract(bytes, &mut v, &mut s, &mut m);
    (v, m)
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
