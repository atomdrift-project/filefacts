use super::{Fact, MetricKey, Metrics, Span};

#[test]
fn insert_and_get() {
    let mut m = Metrics::new();
    m.insert(MetricKey::unchecked("file.size"), 1024.0);
    m.insert(MetricKey::unchecked("file.entropy"), 7.21);
    assert_eq!(m.get("file.size"), Some(1024.0));
    assert_eq!(m.get("file.entropy"), Some(7.21));
    assert_eq!(m.get("missing"), None);
    assert_eq!(m.len(), 2);
}

#[test]
fn located_metric_carries_spans() {
    let mut m = Metrics::new();
    m.insert_located(
        MetricKey::unchecked("binary.peak_region_entropy"),
        8.0,
        [Span::new(4096, 2048)],
    );
    assert_eq!(m.get("binary.peak_region_entropy"), Some(8.0));
    let f = m.fact("binary.peak_region_entropy").unwrap();
    assert_eq!(f.spans, vec![Span::new(4096, 2048)]);
}

#[test]
fn iter_is_sorted() {
    let mut m = Metrics::new();
    m.insert(MetricKey::unchecked("z"), 1.0);
    m.insert(MetricKey::unchecked("a"), 2.0);
    m.insert(MetricKey::unchecked("m"), 3.0);
    let keys: Vec<&str> = m.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, vec!["a", "m", "z"]);
}

#[test]
fn unlocated_fact_serializes_as_bare_number() {
    let mut m = Metrics::new();
    m.insert(MetricKey::unchecked("a"), 1.0);
    m.insert(MetricKey::unchecked("b"), 2.0);
    let s = serde_json::to_string(&m).unwrap();
    assert_eq!(s, r#"{"a":1.0,"b":2.0}"#);
}

#[test]
fn located_fact_serializes_as_object() {
    let mut m = Metrics::new();
    m.insert_located(MetricKey::unchecked("p"), 8.0, [Span::new(16, 32)]);
    let s = serde_json::to_string(&m).unwrap();
    assert_eq!(s, r#"{"p":{"value":8.0,"spans":[{"offset":16,"len":32}]}}"#);
}

#[test]
fn round_trips_both_forms() {
    let mut m = Metrics::new();
    m.insert(MetricKey::unchecked("plain"), 3.5);
    m.insert_located(
        MetricKey::unchecked("located"),
        8.0,
        [Span::new(1, 2), Span::new(9, 4)],
    );
    let s = serde_json::to_string(&m).unwrap();
    let back: Metrics = serde_json::from_str(&s).unwrap();
    assert_eq!(back.get("plain"), Some(3.5));
    assert_eq!(
        back.fact("located").unwrap().spans,
        vec![Span::new(1, 2), Span::new(9, 4)]
    );
}

#[test]
fn deserializes_bare_number() {
    // An unlocated fact is written as a bare number and reads back as one.
    let m: Metrics = serde_json::from_str(r#"{"file.entropy":7.0}"#).unwrap();
    assert_eq!(m.get("file.entropy"), Some(7.0));
    assert!(m.fact("file.entropy").unwrap().spans.is_empty());
}

/// A catalog key is stored without copying its text.
#[test]
fn static_keys_are_stored_borrowed() {
    let name: &'static str = "file.size";
    let mut m = Metrics::new();
    m.insert(MetricKey::unchecked(name), 1.0);
    let (key, _) = m.0.first_key_value().unwrap();
    assert!(std::ptr::eq(key.as_str(), name));
}

#[test]
fn fact_default_is_unlocated_zero() {
    let f = Fact::default();
    assert_eq!(f.value, 0.0);
    assert!(f.spans.is_empty());
}
