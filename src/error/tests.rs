use super::*;

#[test]
fn malformed_keeps_its_display_and_exposes_the_cause() {
    let plain = Error::malformed("cab", "not a cabinet (bad CFHEADER magic)");
    assert_eq!(
        plain.to_string(),
        "malformed cab: not a cabinet (bad CFHEADER magic)"
    );
    assert!(plain.source().is_none());

    let cause = io::Error::other("unexpected end of file");
    let caused = Error::malformed_caused_by("tar", cause);
    assert_eq!(caused.to_string(), "malformed tar");
    let source = caused.source().expect("source");
    assert_eq!(source.to_string(), "unexpected end of file");
    assert!(source.downcast_ref::<io::Error>().is_some());
    assert_eq!(
        display_chain(&caused),
        "malformed tar: unexpected end of file"
    );

    let in_context = Error::malformed_with_source("zip", "entry 3", io::Error::other("bad crc"));
    assert_eq!(in_context.to_string(), "malformed zip: entry 3");
    assert_eq!(
        display_chain(&in_context),
        "malformed zip: entry 3: bad crc"
    );
}

#[test]
fn a_chain_reporter_prints_each_cause_once() {
    let errors = [
        Error::malformed_caused_by("tar", io::Error::other("unexpected end of file")),
        Error::io("/tmp/x", io::Error::other("permission denied")),
    ];
    for err in &errors {
        let chain = display_chain(err);
        let cause = err.source().expect("source").to_string();
        assert_eq!(chain.matches(&cause).count(), 1, "{chain}");
    }
}

#[test]
fn io_names_the_path_and_keeps_the_kind() {
    let err = Error::io(
        "/samples/a.bin",
        io::Error::new(io::ErrorKind::NotFound, "gone"),
    );
    assert_eq!(err.to_string(), "cannot read /samples/a.bin");
    let Error::Io { path, source } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(
        path.as_deref(),
        Some(std::path::Path::new("/samples/a.bin"))
    );
    assert_eq!(source.kind(), io::ErrorKind::NotFound);
    let bare: Error = io::Error::other("disk on fire").into();
    assert_eq!(bare.to_string(), "i/o error");
}

#[test]
fn error_is_send_and_sync() {
    fn assert_bounds<T: Send + Sync + 'static>() {}
    assert_bounds::<Error>();
}
