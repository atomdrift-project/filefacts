//! Format-agnostic extractor.
//!
//! Records facts that hold for any blob of bytes: total size and
//! Shannon entropy. Runs before every format-specific extractor so the
//! metric exists even for unrecognised inputs.

use crate::metric;
use crate::output::{Metrics, Span, Values};
use crate::scan::entropy;
use crate::value_key;

/// Run the generic byte-level pass. Always succeeds.
pub(super) fn extract(bytes: &[u8], metrics: &mut Metrics) {
    // One windowed pass yields both the whole-file entropy and the
    // concealed-region signals below, so the file is read only once.
    let scan = entropy::windowed(bytes);
    metrics.insert(metric!("file.size"), bytes.len() as f64);
    // Whole-file Shannon entropy: the unqualified default, which the
    // specializations qualify (`binary.code_entropy`, `binary.data_entropy`,
    // `sections.entropy_*`).
    metrics.insert(metric!("file.entropy"), scan.overall);

    // Peak concentrated region. Whole-file and section entropy both average a
    // small encrypted stage into its surroundings; this surfaces and locates
    // the single most concentrated region for any file type. Pure measurement
    // — the detection policy ("how high, how big, against what baseline") lives
    // in the rules. The canonical tell is `peak_region_entropy` high while
    // `overall_entropy` stays low (a blob concealed in low-entropy padding, or
    // a base64 region inside readable source). The high-entropy runs travel
    // with `peak_region_entropy` as its spans, so a finding can point an
    // analyst straight at the bytes — no offset scalar to join against.
    if scan.peak_bytes > 0 {
        let spans = scan.spans.iter().map(|&(offset, len)| Span { offset, len });
        metrics.insert_located(
            metric!("binary.peak_region_entropy"),
            scan.peak_entropy,
            spans,
        );
        metrics.insert(metric!("binary.peak_region_bytes"), scan.peak_bytes as f64);
    }
}

/// Record the key of a PE hidden under a repeating XOR key, which
/// identification recovered (see [`crate::FileId::xor_pe_key`]).
///
/// - `xor.has_embedded_pe` — 1 when the whole file decodes to a PE.
/// - `xor.pe_key_length` — the key's period in bytes (smallest that decodes).
/// - value `xor.pe_key` — the key as lowercase hex, aligned to offset 0
///   (`plain[i] = bytes[i] ^ key[i % len]`), for consumers that decode it.
pub(super) fn extract_xor_pe(
    key: stng::RepeatingXorKey,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    metrics.insert(metric!("xor.has_embedded_pe"), 1.0);
    metrics.insert(metric!("xor.pe_key_length"), key.period() as f64);
    values.insert_key(
        value_key!("xor.pe_key"),
        serde_json::Value::String(super::common::hex_encode(key.bytes())),
    );
}

#[cfg(test)]
mod tests;
