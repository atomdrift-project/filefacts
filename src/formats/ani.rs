//! Animated cursor header facts from actual top-level RIFF chunk boundaries.
use crate::bytes::{sat_usize, u32_le};
use crate::output::{Metrics, Values};
use crate::{metric, value_key};
use serde_json::json;

pub(crate) fn extract(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    if bytes.get(..4) != Some(b"RIFF") || bytes.get(8..12) != Some(b"ACON") {
        return;
    }
    let Some(declared) = u32_le(bytes, 4) else {
        return;
    };
    let limit = sat_usize(u64::from(declared) + 8).min(bytes.len());
    let mut at = 12usize;
    let mut headers = Vec::new();
    let mut oversized = 0u64;
    let mut oversized_after_fixed = 0u64;
    let mut fixed_seen = false;
    for _ in 0..4096 {
        let Some(chunk) = bytes.get(at..limit) else {
            break;
        };
        let (Some(id), Some(size)) = (chunk.first_chunk::<4>(), u32_le(chunk, 4)) else {
            break;
        };
        let size = size as usize;
        if id == b"anih" {
            let cb_size = bytes.get(..limit).and_then(|b| u32_le(b, at + 8));
            headers.push(json!({"offset": at, "declared_size": size, "structure_size": cb_size}));
            if size > 36 {
                oversized += 1;
                if fixed_seen {
                    oversized_after_fixed += 1;
                }
            }
            if size == 36 && cb_size == Some(36) {
                fixed_seen = true;
            }
        }
        let Some(end) = at.checked_add(8).and_then(|b| b.checked_add(size)) else {
            break;
        };
        if end > limit {
            break;
        }
        at = end + (size & 1);
    }
    values.insert_key(value_key!("ani.headers"), json!(headers));
    metrics.insert(metric!("ani.oversized_header_count"), oversized as f64);
    metrics.insert(
        metric!("ani.oversized_after_fixed_header_count"),
        oversized_after_fixed as f64,
    );
}

#[cfg(test)]
mod tests;
