use super::*;

/// The catalog is the contract downstream reads; an unsorted or
/// duplicated entry means a merge went wrong.
#[test]
fn catalog_is_sorted_and_unique() {
    for pair in CATALOG.windows(2) {
        assert!(
            pair[0] < pair[1],
            "CATALOG must be sorted and free of duplicates: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

/// Every declared key is a dotted lowercase path. Catches a stray
/// description or a copy-paste of a `Values` path.
#[test]
fn catalog_entries_are_dotted_paths() {
    for key in CATALOG {
        assert!(
            key.contains('.')
                && key.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'_'),
            "not a metric path: {key}"
        );
    }
}

#[test]
fn declared_resolves_to_the_literal() {
    assert_eq!(metric!("file.entropy").as_str(), "file.entropy");
}

#[test]
fn families_build_the_documented_shape() {
    assert_eq!(
        archive_method_count("deflate").as_str(),
        "archive.compression.method_counts.deflate"
    );
    assert_eq!(
        source_query_limited("identifiers", QueryLimit::Output).as_str(),
        "source.query_limited.identifiers.output_limit"
    );
}
