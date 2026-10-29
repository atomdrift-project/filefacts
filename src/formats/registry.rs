//! `*.registry.json`: a normalized package-registry metadata document.
//!
//! The whole file is a serialized [`crate::Registry`]; parsing it means
//! deserializing and projecting onto the `registry.*` `values`/`metrics`
//! surface. A caller that fetches a package's registry record writes one
//! beside the package, so the registry's account of it is analyzed by the
//! same rules as the package's own bytes.

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
        serde_json::from_slice(bytes).map_err(|e| Error::malformed_caused_by("registry", e))?;
    record.write_facts(values, metrics);
    Ok(())
}

#[cfg(test)]
mod tests;
