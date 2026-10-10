use super::*;

#[test]
fn deep_nesting_is_refused_without_overflowing() {
    let (deep, at_cap, past_cap) = on_small_stack(|| {
        (
            parse(&nested_xml(20_000)).map(drop),
            parse(&nested_xml(MAX_DEPTH)).map(drop),
            parse(&nested_xml(MAX_DEPTH + 1)).map(drop),
        )
    });
    assert!(matches!(deep, Err(PlistError::TooDeep)));
    assert!(at_cap.is_ok());
    assert!(matches!(past_cap, Err(PlistError::TooDeep)));
}

#[test]
fn reference_expansion_is_refused_up_front() {
    let bytes = reference_dag(8);
    let start = std::time::Instant::now();
    let err = parse(&bytes).unwrap_err();
    assert!(matches!(err, PlistError::Expansion { .. }), "{err}");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn modest_reference_reuse_still_parses() {
    // Two levels of 14 references expand to 1 + 14 + 196 values, well
    // inside the size-derived cap.
    let value = parse(&reference_dag(2)).unwrap();
    assert_eq!(value.as_array().map(Vec::len), Some(14));
}

#[test]
fn reader_errors_keep_their_source() {
    let err = parse(b"<plist><array><string>v</string></plist>").unwrap_err();
    assert!(matches!(err, PlistError::Parse(_)));
    assert!(std::error::Error::source(&err).is_some());
    let err = err.into_error("plist");
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn refusals_map_to_malformed_errors() {
    let err = PlistError::TooDeep.into_error("nib");
    assert_eq!(
        err.to_string(),
        format!("malformed nib: plist nests deeper than {MAX_DEPTH} levels")
    );
}

/// Objects sharing one collection's bytes are each walked for their own
/// references: tens of thousands of them over one array of tens of
/// thousands of references was a quadratic walk before any size passed the
/// cap. The references read now count toward it.
#[test]
fn shared_collection_walk_is_bounded() {
    let bytes = shared_collection(20_000);
    let start = std::time::Instant::now();
    let err = parse(&bytes).unwrap_err();
    assert!(matches!(err, PlistError::Expansion { .. }), "{err}");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    // A handful of them is ordinary reuse.
    let value = parse(&shared_collection(4)).unwrap();
    assert_eq!(value.as_array().map(Vec::len), Some(4));
}
