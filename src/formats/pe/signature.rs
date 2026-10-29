//! Authenticode: the signatures in the Certificate Table, the image hash
//! they commit to, and the judgement of one against the other.
//!
//! The presence of `pe.signatures` is the "is the binary signed?" answer.
//! `pe.cert_table_size` is emitted whenever the directory names a non-empty
//! table, so a size with no parsed signature reads as a claimed but
//! unparseable (tampered) signature.

mod image_hash;
mod trust;

use goblin::pe::PE;
use goblin::pe::optional_header::OptionalHeader;
use serde_json::Value as JsonValue;

use crate::formats::cms;
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Emit `pe.signatures`, `pe.image_hash.*` and `pe.signature_integrity`.
///
/// `pe` is the full parse, without which no image hash can be computed: the
/// signatures are still reported, and a signature that commits to an image
/// digest is then judged `unverifiable`.
pub(super) fn extract(
    pe: Option<&PE<'_>>,
    opt: &OptionalHeader,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let mut signatures = certificate_table(opt, bytes, metrics)
        .map(cms::certificate_table)
        .unwrap_or_default();
    let hashes = pe
        .map(|pe| image_hash::extract(pe, bytes, &signatures, values, metrics))
        .unwrap_or_default();
    let Some(integrity) = trust::judge(&mut signatures, &hashes) else {
        return;
    };
    values.insert_key(
        value_key!("pe.signatures"),
        JsonValue::Array(signatures.iter().map(cms::Signature::to_json).collect()),
    );
    values.insert_key(
        value_key!("pe.signature_integrity"),
        JsonValue::String(integrity.label().into()),
    );
}

/// The Certificate Table's bytes, recording its size as
/// `pe.cert_table_size`. For this directory alone the `virtual_address` is a
/// file offset (a PE/COFF spec carve-out), so the bytes are read directly; a
/// table outside the file means the header was tampered with, flagged as
/// `pe.security_directory_out_of_bounds`.
fn certificate_table<'a>(
    opt: &OptionalHeader,
    bytes: &'a [u8],
    metrics: &mut Metrics,
) -> Option<&'a [u8]> {
    let dir = opt.data_directories.get_certificate_table()?;
    if dir.size == 0 {
        return None;
    }
    metrics.insert(metric!("pe.cert_table_size"), f64::from(dir.size));
    let offset = dir.virtual_address as usize;
    let table = offset
        .checked_add(dir.size as usize)
        .and_then(|end| bytes.get(offset..end));
    if table.is_none() {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "certificate-table",
            offset,
            len = dir.size,
            "certificate table lies outside the file"
        );
        if offset > 0 {
            metrics.insert(metric!("pe.security_directory_out_of_bounds"), 1.0);
        }
    }
    table
}
