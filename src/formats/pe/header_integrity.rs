//! The DOS and NT headers as the loader meets them, read before any parse so
//! they are reported even when the parse fails: bytes prepended before `MZ`,
//! an `e_lfanew` that does not lead to `PE\0\0`, and a header area padded
//! with one repeated byte. Each is how a sample defeats a parser while the
//! image stays loadable (or carvable).
//!
//! - `pe.header.mz_offset` — where `MZ` begins, when not at offset 0 (it is
//!   looked for in the first 64 bytes, as file identification does).
//! - `pe.header.nt_signature` — the four bytes at `e_lfanew`, hex, when they
//!   are not `PE\0\0`.
//! - `pe.header.dominant_byte` / `pe.header.dominant_byte_ratio` — the most
//!   frequent non-zero byte in the first 512 bytes of the image, and its
//!   share of them.

use serde_json::Value as JsonValue;

use crate::bytes::u32_le;
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Header bytes the dominant-byte share is measured over.
const HEADER_AREA: usize = 512;

pub(super) fn emit(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(mz) = bytes
        .get(..64)
        .unwrap_or(bytes)
        .windows(2)
        .position(|pair| pair == b"MZ")
    else {
        return;
    };
    if mz > 0 {
        values.insert_key(value_key!("pe.header.mz_offset"), JsonValue::from(mz));
    }
    let image = bytes.get(mz..).unwrap_or_default();

    let signature = u32_le(image, 0x3c)
        .and_then(|at| usize::try_from(at).ok())
        .and_then(|at| image.get(at..at.checked_add(4)?));
    if let Some(signature) = signature.filter(|s| *s != b"PE\0\0") {
        let hex: Vec<String> = signature.iter().map(|b| format!("{b:02x}")).collect();
        values.insert_key(
            value_key!("pe.header.nt_signature"),
            JsonValue::String(hex.join(" ")),
        );
    }

    let head = image.get(..HEADER_AREA).unwrap_or(image);
    if head.len() < 64 {
        return;
    }
    let mut counts = [0u32; 256];
    for &b in head {
        if let Some(count) = counts.get_mut(usize::from(b)) {
            *count = count.saturating_add(1);
        }
    }
    let Some((byte, &count)) = counts
        .iter()
        .enumerate()
        .skip(1)
        .max_by_key(|&(_, count)| *count)
        .filter(|&(_, &count)| count > 0)
    else {
        return;
    };
    values.insert_key(
        value_key!("pe.header.dominant_byte"),
        JsonValue::String(format!("0x{byte:02x}")),
    );
    metrics.insert(
        metric!("pe.header.dominant_byte_ratio"),
        f64::from(count) / head.len() as f64,
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn image(prefix: &[u8], signature: [u8; 4], fill: u8) -> Vec<u8> {
        let mut pe = vec![fill; 0x200];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(&signature);
        [prefix, &pe].concat()
    }

    fn facts(bytes: &[u8]) -> (Values, Metrics) {
        let (mut values, mut metrics) = (Values::new(), Metrics::new());
        emit(bytes, &mut values, &mut metrics);
        (values, metrics)
    }

    #[test]
    fn a_clean_header_reports_only_its_byte_profile() {
        let (v, m) = facts(&image(b"", *b"PE\0\0", 0));
        assert!(v.get("pe.header.mz_offset").is_none());
        assert!(v.get("pe.header.nt_signature").is_none());
        assert!(m.get("pe.header.dominant_byte_ratio").unwrap() < 0.1);
    }

    #[test]
    fn prefix_signature_and_padding() {
        let (v, m) = facts(&image(b"junk!", *b"XX\0\0", 0x20));
        assert_eq!(v.get("pe.header.mz_offset"), Some(&JsonValue::from(5)));
        assert_eq!(
            v.get("pe.header.nt_signature"),
            Some(&JsonValue::from("58 58 00 00"))
        );
        assert_eq!(
            v.get("pe.header.dominant_byte"),
            Some(&JsonValue::from("0x20"))
        );
        assert!(m.get("pe.header.dominant_byte_ratio").unwrap() > 0.9);
    }
}
