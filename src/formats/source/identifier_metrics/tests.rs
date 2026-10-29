use super::*;

#[test]
fn empty_identifiers_emit_nothing() {
    let mut m = Metrics::new();
    emit(&[], &mut m);
    assert!(m.is_empty());
}

#[test]
fn basic_counts() {
    let mut m = Metrics::new();
    emit(&["foo", "bar", "baz", "foo"], &mut m);
    assert_eq!(m.get("identifiers.count"), Some(4.0));
    assert_eq!(m.get("identifiers.unique"), Some(3.0));
}

#[test]
fn single_char_detection() {
    let mut m = Metrics::new();
    emit(&["a", "b", "c", "x", "y", "longName"], &mut m);
    assert_eq!(m.get("identifiers.single_char_count"), Some(5.0));
}

#[test]
fn hex_like_detection() {
    let mut m = Metrics::new();
    emit(&["deadbeef", "cafebabe", "normalName"], &mut m);
    assert_eq!(m.get("identifiers.hex_like_names"), Some(2.0));
}

/// Float sums must not follow hash iteration order: the disk cache and
/// output diffs rely on identical input giving bit-identical metrics.
#[test]
fn float_metrics_are_bit_for_bit_reproducible() {
    let names: Vec<String> = (0..600u32)
        .map(|i| {
            format!(
                "{}_{:x}{}",
                ["v", "tmpName", "Q9z"][(i % 3) as usize],
                i * 7919,
                "k".repeat((i % 7) as usize)
            )
        })
        .collect();
    let identifiers: Vec<&str> = names.iter().map(String::as_str).collect();
    let bits = || {
        let mut m = Metrics::new();
        emit(&identifiers, &mut m);
        [
            "identifiers.avg_entropy",
            "identifiers.length_stddev",
            "identifiers.avg_length",
        ]
        .map(|key| m.get(key).expect(key).to_bits())
    };
    let first = bits();
    for _ in 0..32 {
        assert_eq!(bits(), first);
    }
}
