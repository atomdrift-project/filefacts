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
            let cb_size = bytes
                .get(at + 8..limit)
                .and_then(|b| b.get(..4))
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
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
mod tests {
    use super::*;
    fn facts(chunks: &[u8]) -> (Values, Metrics) {
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&((chunks.len() + 4) as u32).to_le_bytes());
        bytes.extend_from_slice(b"ACON");
        bytes.extend_from_slice(chunks);
        let (mut values, mut metrics) = (Values::default(), Metrics::default());
        extract(&bytes, &mut values, &mut metrics);
        (values, metrics)
    }
    #[test]
    fn only_chunk_boundaries_count_as_headers() {
        let mut normal = b"anih\x24\0\0\0\x24\0\0\0".to_vec();
        normal.resize(44, 0);
        let mut body = b"anih\x64\0\0\0".to_vec();
        body.resize(100, 0);
        let mut chunks = normal.clone();
        chunks.extend_from_slice(b"JUNK");
        chunks.extend_from_slice(&(body.len() as u32).to_le_bytes());
        chunks.extend_from_slice(&body);
        let (_, m) = facts(&chunks);
        assert_eq!(m.get("ani.oversized_header_count"), Some(0.0));
        normal.extend_from_slice(&body);
        let (v, m) = facts(&normal);
        assert_eq!(m.get("ani.oversized_header_count"), Some(1.0));
        assert_eq!(m.get("ani.oversized_after_fixed_header_count"), Some(1.0));
        assert_eq!(v.get("ani.headers").unwrap().as_array().unwrap().len(), 2);
        for n in 0..normal.len() {
            let _ = facts(&normal[..n]);
        }
    }
}
