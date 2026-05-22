//! Derived numeric features.

use std::collections::BTreeMap;

use serde::Serialize;

/// Derived numeric features of a file.
///
/// Anything that answers "how much / how many / how spread" lives here.
/// Anything that's a verbatim structural fact lives in [`crate::Values`]
/// instead.
///
/// `Metrics` is intentionally a flat key→number map rather than a typed
/// struct: format-specific metrics names follow each format's own
/// conventions, and filefacts prefers a uniform interface over a typed
/// surface that would have to grow a field for every metric every
/// extractor invents.
///
/// Numbers are stored as `f64` so a single representation handles
/// integer counts, ratios in `[0.0, 1.0]`, and entropies in `[0.0, 8.0]`.
/// Callers that need integer precision can round at the boundary.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Metrics(BTreeMap<String, f64>);

impl Metrics {
    /// Empty metrics map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a metric. Overwrites any existing value for the same key.
    pub fn insert(&mut self, key: impl Into<String>, value: f64) {
        self.0.insert(key.into(), value);
    }

    /// Look up a metric.
    pub fn get(&self, key: &str) -> Option<f64> {
        self.0.get(key).copied()
    }

    /// Iterate (key, value) pairs in lexicographic key order. The
    /// `BTreeMap` backing this view gives stable iteration order, which
    /// makes the JSON output diff-friendly across runs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, f64)> {
        self.0.iter().map(|(k, &v)| (k.as_str(), v))
    }

    /// Number of metrics recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no metrics have been recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the underlying `BTreeMap`.
    ///
    /// Useful for downstream consumers (e.g. cleave's `FilefactsView`)
    /// that want to attach the metric map to their own report shape
    /// without re-walking `iter()` and copying key by key.
    pub fn as_map(&self) -> &BTreeMap<String, f64> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn insert_and_get() {
        let mut m = Metrics::new();
        m.insert("file.size_bytes", 1024.0);
        m.insert("file.entropy", 7.21);
        assert_eq!(m.get("file.size_bytes"), Some(1024.0));
        assert_eq!(m.get("file.entropy"), Some(7.21));
        assert_eq!(m.get("missing"), None);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn iter_is_sorted() {
        let mut m = Metrics::new();
        m.insert("z", 1.0);
        m.insert("a", 2.0);
        m.insert("m", 3.0);
        let keys: Vec<&str> = m.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }

    #[test]
    fn serializes_as_object() {
        let mut m = Metrics::new();
        m.insert("a", 1.0);
        m.insert("b", 2.0);
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, r#"{"a":1.0,"b":2.0}"#);
    }
}
