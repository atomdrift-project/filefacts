//! Derived numeric features.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Span;

/// A named observation about the file: a value plus, optionally, the byte
/// spans where the evidence for it lives.
///
/// Most metrics are file-global and carry no spans (`overall_entropy`, a
/// count, a ratio). A *located* metric — a concealed high-entropy region, an
/// invisible-character run, an over-long line — carries the spans it was
/// measured from, so downstream consumers can point at the bytes without a
/// parallel map keyed by metric name. The value and its provenance are one
/// fact, not two facts joined by a string.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Fact {
    /// The measured value (count, ratio, entropy, …).
    pub value: f64,
    /// Byte spans the value was measured from; empty for a file-global fact.
    pub spans: Vec<Span>,
}

impl Fact {
    /// A file-global fact with no associated location.
    fn unlocated(value: f64) -> Self {
        Self {
            value,
            spans: Vec::new(),
        }
    }
}

// A fact serializes transparently as a bare number when it has no spans, so
// the overwhelmingly common file-global metric keeps the historical
// `{name: number}` JSON shape. A located fact serializes as
// `{"value": n, "spans": [...]}`. Deserialization accepts either form.
impl Serialize for Fact {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.spans.is_empty() {
            self.value.serialize(s)
        } else {
            let mut st = s.serialize_struct("Fact", 2)?;
            st.serialize_field("value", &self.value)?;
            st.serialize_field("spans", &self.spans)?;
            st.end()
        }
    }
}

impl<'de> Deserialize<'de> for Fact {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct FactVisitor;

        impl<'de> Visitor<'de> for FactVisitor {
            type Value = Fact;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a number or a {value, spans} object")
            }

            fn visit_f64<E>(self, v: f64) -> Result<Fact, E> {
                Ok(Fact::unlocated(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Fact, E> {
                Ok(Fact::unlocated(v as f64))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Fact, E> {
                Ok(Fact::unlocated(v as f64))
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Fact, M::Error> {
                let mut value = None;
                let mut spans = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "value" => value = Some(map.next_value()?),
                        "spans" => spans = Some(map.next_value()?),
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(Fact {
                    value: value.ok_or_else(|| de::Error::missing_field("value"))?,
                    spans: spans.unwrap_or_default(),
                })
            }
        }

        d.deserialize_any(FactVisitor)
    }
}

/// Derived numeric features of a file.
///
/// Anything that answers "how much / how many / how spread" lives here.
/// Anything that's a verbatim structural fact lives in [`crate::Values`]
/// instead.
///
/// `Metrics` is intentionally a flat key→[`Fact`] map rather than a typed
/// struct: format-specific metric names follow each format's own
/// conventions, and filefacts prefers a uniform interface over a typed
/// surface that would have to grow a field for every metric every extractor
/// invents.
///
/// Values are stored as `f64` so a single representation handles integer
/// counts, ratios in `[0.0, 1.0]`, and entropies in `[0.0, 8.0]`. Callers
/// that need integer precision can round at the boundary. Byte offsets are
/// never the value — they live in a fact's [`Fact::spans`], which are `u64`
/// and so exact for large files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Metrics(BTreeMap<String, Fact>);

impl Metrics {
    /// Empty metrics map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a file-global metric. Overwrites any existing entry.
    pub fn insert(&mut self, key: impl Into<String>, value: f64) {
        self.0.insert(key.into(), Fact::unlocated(value));
    }

    /// Record a *located* metric: a value plus the byte spans it was measured
    /// from. The spans travel with the value through every downstream
    /// consumer (facts JSON, disk cache, the trait engine, prism).
    pub fn insert_located(
        &mut self,
        key: impl Into<String>,
        value: f64,
        spans: impl IntoIterator<Item = Span>,
    ) {
        self.0.insert(
            key.into(),
            Fact {
                value,
                spans: spans.into_iter().collect(),
            },
        );
    }

    /// Look up a metric's value.
    pub fn get(&self, key: &str) -> Option<f64> {
        self.0.get(key).map(|f| f.value)
    }

    /// Look up a metric's full fact, including any spans.
    pub fn fact(&self, key: &str) -> Option<&Fact> {
        self.0.get(key)
    }

    /// Iterate (key, value) pairs in lexicographic key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, f64)> {
        self.0.iter().map(|(k, f)| (k.as_str(), f.value))
    }

    /// Iterate (key, fact) pairs in lexicographic key order — use when the
    /// caller needs the spans, not just the value.
    pub fn iter_facts(&self) -> impl Iterator<Item = (&str, &Fact)> {
        self.0.iter().map(|(k, f)| (k.as_str(), f))
    }

    /// Number of metrics recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no metrics have been recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the underlying `BTreeMap` of facts.
    pub fn as_map(&self) -> &BTreeMap<String, Fact> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Fact, Metrics, Span};

    #[test]
    fn insert_and_get() {
        let mut m = Metrics::new();
        m.insert("file.size", 1024.0);
        m.insert("file.entropy", 7.21);
        assert_eq!(m.get("file.size"), Some(1024.0));
        assert_eq!(m.get("file.entropy"), Some(7.21));
        assert_eq!(m.get("missing"), None);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn located_metric_carries_spans() {
        let mut m = Metrics::new();
        m.insert_located("binary.peak_region_entropy", 8.0, [Span::new(4096, 2048)]);
        assert_eq!(m.get("binary.peak_region_entropy"), Some(8.0));
        let f = m.fact("binary.peak_region_entropy").unwrap();
        assert_eq!(f.spans, vec![Span::new(4096, 2048)]);
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
    fn unlocated_fact_serializes_as_bare_number() {
        let mut m = Metrics::new();
        m.insert("a", 1.0);
        m.insert("b", 2.0);
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, r#"{"a":1.0,"b":2.0}"#);
    }

    #[test]
    fn located_fact_serializes_as_object() {
        let mut m = Metrics::new();
        m.insert_located("p", 8.0, [Span::new(16, 32)]);
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, r#"{"p":{"value":8.0,"spans":[{"offset":16,"len":32}]}}"#);
    }

    #[test]
    fn round_trips_both_forms() {
        let mut m = Metrics::new();
        m.insert("plain", 3.5);
        m.insert_located("located", 8.0, [Span::new(1, 2), Span::new(9, 4)]);
        let s = serde_json::to_string(&m).unwrap();
        let back: Metrics = serde_json::from_str(&s).unwrap();
        assert_eq!(back.get("plain"), Some(3.5));
        assert_eq!(
            back.fact("located").unwrap().spans,
            vec![Span::new(1, 2), Span::new(9, 4)]
        );
    }

    #[test]
    fn deserializes_legacy_bare_number() {
        // Caches/inputs written before spans existed are still readable.
        let m: Metrics = serde_json::from_str(r#"{"file.entropy":7.0}"#).unwrap();
        assert_eq!(m.get("file.entropy"), Some(7.0));
        assert!(m.fact("file.entropy").unwrap().spans.is_empty());
    }

    #[test]
    fn fact_default_is_unlocated_zero() {
        let f = Fact::default();
        assert_eq!(f.value, 0.0);
        assert!(f.spans.is_empty());
    }
}
