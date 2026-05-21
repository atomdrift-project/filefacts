//! Format-agnostic extractor.
//!
//! Records facts that hold for any blob of bytes: total size and
//! Shannon entropy. Runs before every format-specific extractor so the
//! metric exists even for unrecognised inputs.

use crate::output::{Metrics, Strings, Values};
use crate::scan::entropy;

/// Run the generic byte-level pass. Always succeeds.
pub(super) fn extract(
    bytes: &[u8],
    _values: &mut Values,
    _strings: &mut Strings,
    metrics: &mut Metrics,
) {
    metrics.insert("file.size_bytes", bytes.len() as f64);
    metrics.insert("file.entropy", entropy::shannon(bytes));
}
