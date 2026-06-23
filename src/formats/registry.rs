//! `*.registry.json`: a normalized package-registry metadata document.
//!
//! The whole file is a serialized [`crate::Registry`]; parsing it means
//! deserializing and projecting onto the `registry.*` `values`/`metrics`
//! surface. fletch produces these from a registry round-trip; scan writes one
//! beside each fetched dependency so the registry's account of a package is
//! analyzed with the same trait engine as the package's own bytes.

use crate::Registry;
use crate::error::Error;
use crate::output::{Metrics, Values};

/// Parse a registry-metadata document into `registry.*` facts. A document that
/// doesn't deserialize is a structural parse error, surfaced like any other
/// malformed manifest.
pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let record: Registry =
        serde_json::from_slice(bytes).map_err(|e| Error::malformed("registry", e.to_string()))?;
    record.write_facts(values, metrics);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_splits_into_values_and_metrics() {
        let doc = serde_json::json!({
            "ecosystem": "npm",
            "name": "left-pad",
            "version": "1.3.0",
            "published_at": 1_619_172_000u64,
            "age_days": 100,
            "author": "azer",
            "license": "WTFPL",
            "downloads_recent": 5_441_645u64,
            "deprecated": "use String.prototype.padStart()",
            "maintainers": 2
        })
        .to_string();
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        extract(doc.as_bytes(), &mut values, &mut metrics).expect("parse");

        // Verbatim identity/text → values.
        assert_eq!(
            values.get("registry.ecosystem").and_then(|v| v.as_str()),
            Some("npm")
        );
        assert_eq!(
            values.get("registry.license").and_then(|v| v.as_str()),
            Some("WTFPL")
        );
        assert_eq!(
            values.get("registry.deprecated").and_then(|v| v.as_str()),
            Some("use String.prototype.padStart()")
        );
        // Counted/measured → metrics, thresholdable by trait `min`/`max`.
        assert_eq!(metrics.get("registry.age_days"), Some(100.0));
        assert_eq!(metrics.get("registry.downloads_recent"), Some(5_441_645.0));
        assert_eq!(metrics.get("registry.maintainers"), Some(2.0));
        assert_eq!(metrics.get("registry.is_deprecated"), Some(1.0));
        // Absent optionals are skipped, not zero-filled.
        assert_eq!(metrics.get("registry.rating"), None);
        assert!(values.get("registry.homepage").is_none());
    }

    #[test]
    fn malformed_document_is_a_parse_error() {
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        assert!(extract(b"not json", &mut values, &mut metrics).is_err());
    }
}
