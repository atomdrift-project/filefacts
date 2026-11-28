//! GGUF model files (llama.cpp's `gguf`, versions 1 through 3).
//!
//! A GGUF file is a key/value metadata table, a tensor index, alignment
//! padding and the tensor data. Runtimes read exactly the byte ranges the
//! index names, so bytes past the last tensor are never loaded: a place to
//! carry a payload. The `tokenizer.chat_template` string is a Jinja program
//! rendered before every model turn: a place to plant instructions the user
//! never sees.
//!
//! Only the header is walked. Tensor data is never read, so a multi-gigabyte
//! model costs one pass over its metadata plus two bounded windows. Every
//! count and length is untrusted and is checked against the input and a
//! fixed budget before it is used; arithmetic is checked throughout.
//!
//! Facts:
//! - `gguf.version`, `gguf.tensor_count`, `gguf.metadata_count`,
//!   `gguf.alignment` (metrics)
//! - `gguf.architecture`: the `general.architecture` string
//! - `gguf.chat_templates[]`: `{key, offset, length}` of each chat-template
//!   string, so a consumer can read the template without a second parser
//! - `gguf.duplicate_keys[]`: metadata keys stored more than once, which
//!   loaders resolve differently
//! - `gguf.data_offset` and `gguf.data_end`: where tensor data starts and
//!   where the last tensor ends, when every tensor type is known
//! - `gguf.truncated`: the input ends before `gguf.data_end` (a header-only
//!   carve, or a partial download)
//! - `gguf.trailing_bytes` and `gguf.trailing_nonzero_bytes` (metrics): the
//!   bytes past `gguf.data_end`, and how many of the first
//!   [`NONZERO_WINDOW`] of them are not zero
//! - `gguf.padding_nonzero_bytes` (metric): non-zero bytes in the alignment
//!   padding before the tensor data, which a writer always zeroes

use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;
use serde_json::{Value as JsonValue, json};
use std::collections::HashSet;

#[cfg(test)]
mod tests;

/// Metadata entries walked; real models carry a few dozen.
const MAX_METADATA: u64 = 1 << 16;
/// Tensors indexed; the largest mixture-of-experts models stay far below.
const MAX_TENSORS: u64 = 1 << 20;
/// Array elements and tensors visited in total. A vocabulary is ~260k
/// strings and its merges ~500k; past this the walk stops rather than spin
/// on a crafted count.
const MAX_ITEMS: u64 = 1 << 24;
/// Bytes of a metadata key, a tensor name, or `general.architecture`.
const MAX_NAME: u64 = 1 << 16;
/// Nesting of array-of-array values.
const MAX_ARRAY_DEPTH: u8 = 3;
/// Dimensions of one tensor; ggml uses at most four.
const MAX_DIMS: u32 = 8;
/// Largest `general.alignment` honored; llama.cpp requires a power of two.
const MAX_ALIGNMENT: u64 = 1 << 30;
/// Bytes inspected when counting non-zero padding or trailing bytes.
const NONZERO_WINDOW: usize = 1 << 20;

const KEY_ALIGNMENT: &[u8] = b"general.alignment";
const KEY_ARCHITECTURE: &[u8] = b"general.architecture";
const KEY_CHAT_TEMPLATE: &[u8] = b"tokenizer.chat_template";

/// GGUF metadata value types.
const T_U8: u32 = 0;
const T_I8: u32 = 1;
const T_U16: u32 = 2;
const T_I16: u32 = 3;
const T_U32: u32 = 4;
const T_I32: u32 = 5;
const T_F32: u32 = 6;
const T_BOOL: u32 = 7;
const T_STRING: u32 = 8;
const T_ARRAY: u32 = 9;
const T_U64: u32 = 10;
const T_I64: u32 = 11;
const T_F64: u32 = 12;

/// Width in bytes of a scalar metadata type.
fn scalar_width(kind: u32) -> Option<u64> {
    match kind {
        T_U8 | T_I8 | T_BOOL => Some(1),
        T_U16 | T_I16 => Some(2),
        T_U32 | T_I32 | T_F32 => Some(4),
        T_U64 | T_I64 | T_F64 => Some(8),
        _ => None,
    }
}

/// `(elements per block, bytes per block)` of a ggml tensor type, from
/// ggml's type traits. `None` for a type this table does not know, which
/// leaves the end of the tensor data unknown rather than guessed.
fn block_layout(ggml_type: u32) -> Option<(u64, u64)> {
    Some(match ggml_type {
        0 => (1, 4),      // F32
        1 => (1, 2),      // F16
        2 => (32, 18),    // Q4_0
        3 => (32, 20),    // Q4_1
        6 => (32, 22),    // Q5_0
        7 => (32, 24),    // Q5_1
        8 => (32, 34),    // Q8_0
        9 => (32, 36),    // Q8_1
        10 => (256, 84),  // Q2_K
        11 => (256, 110), // Q3_K
        12 => (256, 144), // Q4_K
        13 => (256, 176), // Q5_K
        14 => (256, 210), // Q6_K
        15 => (256, 292), // Q8_K
        16 => (256, 66),  // IQ2_XXS
        17 => (256, 74),  // IQ2_XS
        18 => (256, 98),  // IQ3_XXS
        19 => (256, 50),  // IQ1_S
        20 => (32, 18),   // IQ4_NL
        21 => (256, 110), // IQ3_S
        22 => (256, 82),  // IQ2_S
        23 => (256, 136), // IQ4_XS
        24 => (1, 1),     // I8
        25 => (1, 2),     // I16
        26 => (1, 4),     // I32
        27 => (1, 8),     // I64
        28 => (1, 8),     // F64
        29 => (256, 56),  // IQ1_M
        30 => (1, 2),     // BF16
        34 => (256, 54),  // TQ1_0
        35 => (256, 66),  // TQ2_0
        39 => (32, 17),   // MXFP4
        _ => return None,
    })
}

/// A bounded little-endian reader over the input.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Version 1 stores counts and string lengths as u32; later versions
    /// as u64.
    wide: bool,
    /// Items left in [`MAX_ITEMS`].
    budget: u64,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: u64) -> Option<&'a [u8]> {
        let n = usize::try_from(n).ok()?;
        let end = self.pos.checked_add(n)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(*self.take(4)?.first_chunk()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(*self.take(8)?.first_chunk()?))
    }

    /// A count or string length: u32 in version 1, u64 after.
    fn len(&mut self) -> Option<u64> {
        if self.wide {
            self.u64()
        } else {
            self.u32().map(u64::from)
        }
    }

    /// Charge `n` items against the walk budget.
    fn spend(&mut self, n: u64) -> Option<()> {
        self.budget = self.budget.checked_sub(n)?;
        Some(())
    }

    /// A length-prefixed string: its offset and bytes.
    fn string(&mut self) -> Option<(usize, &'a [u8])> {
        let len = self.len()?;
        let at = self.pos;
        Some((at, self.take(len)?))
    }

    /// Step over one value of `kind` without keeping it.
    fn skip_value(&mut self, kind: u32, depth: u8) -> Option<()> {
        if let Some(width) = scalar_width(kind) {
            return self.take(width).map(drop);
        }
        match kind {
            T_STRING => self.string().map(drop),
            T_ARRAY if depth < MAX_ARRAY_DEPTH => {
                let elem = self.u32()?;
                let count = self.len()?;
                self.spend(count)?;
                if let Some(width) = scalar_width(elem) {
                    return self.take(count.checked_mul(width)?).map(drop);
                }
                // Each string or array element consumes at least a length
                // prefix, so a count larger than the input fails on read.
                for _ in 0..count {
                    self.skip_value(elem, depth + 1)?;
                }
                Some(())
            }
            _ => None,
        }
    }
}

/// One chat-template string inside the metadata.
struct Template<'a> {
    key: &'a [u8],
    offset: usize,
    length: usize,
}

/// What the header walk recovered. Fields stay `None` where the walk ended
/// before reaching them.
#[derive(Default)]
struct Header<'a> {
    version: u32,
    tensor_count: u64,
    metadata_count: u64,
    alignment: u64,
    architecture: Option<&'a [u8]>,
    templates: Vec<Template<'a>>,
    duplicate_keys: Vec<&'a [u8]>,
    /// Where the tensor index ends.
    index_end: Option<usize>,
    /// Where the tensor data begins.
    data_offset: Option<u64>,
    /// Where the last tensor ends.
    data_end: Option<u64>,
    unknown_types: Vec<u32>,
}

/// Whether `data` opens with a GGUF header this extractor reads: the magic
/// and a little-endian version 1 to 3. A byte-swapped (big-endian) file has
/// the same magic and a version this test rejects.
#[must_use]
pub(crate) fn is_gguf(data: &[u8]) -> bool {
    data.starts_with(b"GGUF")
        && data
            .get(4..8)
            .and_then(|v| v.first_chunk::<4>())
            .is_some_and(|v| matches!(u32::from_le_bytes(*v), 1..=3))
}

/// Walk the header. Returns what was read before the walk ended; a header
/// cut off mid-table still yields the facts that precede the cut.
fn walk(data: &[u8]) -> Option<Header<'_>> {
    if !is_gguf(data) {
        return None;
    }
    let mut r = Reader {
        data,
        pos: 4,
        wide: true,
        budget: MAX_ITEMS,
    };
    let mut h = Header {
        alignment: 32,
        ..Header::default()
    };
    h.version = r.u32()?;
    r.wide = h.version >= 2;
    h.tensor_count = r.len()?;
    h.metadata_count = r.len()?;
    if h.metadata_count > MAX_METADATA || h.tensor_count > MAX_TENSORS {
        return Some(h);
    }
    let mut seen: HashSet<&[u8]> = HashSet::new();
    for _ in 0..h.metadata_count {
        if read_entry(&mut r, &mut h, &mut seen).is_none() {
            return Some(h);
        }
    }
    let mut data_size: Option<u64> = Some(0);
    for _ in 0..h.tensor_count {
        match read_tensor(&mut r) {
            Some(Ok(end)) => data_size = data_size.and_then(|max| Some(max.max(end?))),
            Some(Err(ggml_type)) => {
                data_size = None;
                if h.unknown_types.len() < 16 && !h.unknown_types.contains(&ggml_type) {
                    h.unknown_types.push(ggml_type);
                }
            }
            None => return Some(h),
        }
    }
    h.index_end = Some(r.pos);
    let index_end = u64::try_from(r.pos).ok()?;
    h.data_offset = index_end.checked_next_multiple_of(h.alignment);
    h.data_end = h
        .data_offset
        .zip(data_size)
        .and_then(|(o, s)| o.checked_add(s));
    Some(h)
}

/// Read one metadata entry, recording the keys this extractor reports.
fn read_entry<'a>(
    r: &mut Reader<'a>,
    h: &mut Header<'a>,
    seen: &mut HashSet<&'a [u8]>,
) -> Option<()> {
    r.spend(1)?;
    let key_len = r.len()?;
    if key_len > MAX_NAME {
        return None;
    }
    let key = r.take(key_len)?;
    if !seen.insert(key) && h.duplicate_keys.len() < 16 {
        h.duplicate_keys.push(key);
    }
    let kind = r.u32()?;
    let is_template = key == KEY_CHAT_TEMPLATE
        || key
            .strip_prefix(KEY_CHAT_TEMPLATE)
            .is_some_and(|rest| rest.first() == Some(&b'.'));
    match kind {
        T_STRING if is_template => {
            let (offset, text) = r.string()?;
            h.templates.push(Template {
                key,
                offset,
                length: text.len(),
            });
        }
        T_STRING if key == KEY_ARCHITECTURE => {
            let (_, text) = r.string()?;
            if u64::try_from(text.len()).is_ok_and(|n| n <= MAX_NAME) {
                h.architecture = Some(text);
            }
        }
        T_U32 if key == KEY_ALIGNMENT => {
            let alignment = u64::from(r.u32()?);
            if alignment.is_power_of_two() && alignment <= MAX_ALIGNMENT {
                h.alignment = alignment;
            }
        }
        _ => r.skip_value(kind, 0)?,
    }
    Some(())
}

/// Read one tensor index entry: `Ok(end)` with its end relative to the data
/// section (`None` on overflow), `Err(type)` for a ggml type with no known
/// block layout, or `None` when the index is cut off or malformed.
fn read_tensor(r: &mut Reader<'_>) -> Option<Result<Option<u64>, u32>> {
    r.spend(1)?;
    let name_len = r.len()?;
    if name_len > MAX_NAME {
        return None;
    }
    r.take(name_len)?;
    let dims = r.u32()?;
    if dims > MAX_DIMS {
        return None;
    }
    let mut elements: Option<u64> = Some(1);
    for _ in 0..dims {
        let dim = r.u64()?;
        elements = elements.and_then(|e| e.checked_mul(dim));
    }
    let ggml_type = r.u32()?;
    let offset = r.u64()?;
    let Some((per_block, block_bytes)) = block_layout(ggml_type) else {
        return Some(Err(ggml_type));
    };
    let end = elements
        .filter(|e| e % per_block == 0)
        .and_then(|e| (e / per_block).checked_mul(block_bytes))
        .and_then(|size| offset.checked_add(size));
    Some(Ok(end))
}

/// Non-zero bytes in the first [`NONZERO_WINDOW`] bytes of `region`.
fn nonzero_prefix(region: &[u8]) -> usize {
    region
        .iter()
        .take(NONZERO_WINDOW)
        .filter(|&&b| b != 0)
        .count()
}

fn lossy(bytes: &[u8]) -> JsonValue {
    JsonValue::String(String::from_utf8_lossy(bytes).into_owned())
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and sizes reported as f64 metrics"
)]
pub(crate) fn extract(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(h) = walk(bytes) else {
        return;
    };
    metrics.insert(metric!("gguf.version"), f64::from(h.version));
    metrics.insert(metric!("gguf.tensor_count"), h.tensor_count as f64);
    metrics.insert(metric!("gguf.metadata_count"), h.metadata_count as f64);
    metrics.insert(metric!("gguf.alignment"), h.alignment as f64);
    if let Some(architecture) = h.architecture {
        values.insert_key(value_key!("gguf.architecture"), lossy(architecture));
    }
    if !h.templates.is_empty() {
        let templates = h
            .templates
            .iter()
            .map(|t| json!({"key": lossy(t.key), "offset": t.offset, "length": t.length}))
            .collect();
        values.insert_key(
            value_key!("gguf.chat_templates"),
            JsonValue::Array(templates),
        );
    }
    if !h.duplicate_keys.is_empty() {
        let keys = h.duplicate_keys.iter().map(|k| lossy(k)).collect();
        values.insert_key(value_key!("gguf.duplicate_keys"), JsonValue::Array(keys));
    }
    if !h.unknown_types.is_empty() {
        let types = h
            .unknown_types
            .iter()
            .map(|&t| JsonValue::from(t))
            .collect();
        values.insert_key(
            value_key!("gguf.unknown_tensor_types"),
            JsonValue::Array(types),
        );
    }
    if let (Some(index_end), Some(data_offset)) = (h.index_end, h.data_offset) {
        values.insert_key(value_key!("gguf.data_offset"), JsonValue::from(data_offset));
        let padding_end = usize::try_from(data_offset).unwrap_or(usize::MAX);
        if let Some(padding) = bytes.get(index_end..padding_end.min(bytes.len())) {
            let nonzero = nonzero_prefix(padding);
            if nonzero > 0 {
                metrics.insert(metric!("gguf.padding_nonzero_bytes"), nonzero as f64);
            }
        }
    }
    let Some(data_end) = h.data_end else {
        return;
    };
    values.insert_key(value_key!("gguf.data_end"), JsonValue::from(data_end));
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if data_end > len {
        values.insert_key(value_key!("gguf.truncated"), JsonValue::Bool(true));
        return;
    }
    let trailing = len - data_end;
    if trailing == 0 {
        return;
    }
    metrics.insert(metric!("gguf.trailing_bytes"), trailing as f64);
    let start = usize::try_from(data_end).unwrap_or(usize::MAX);
    if let Some(region) = bytes.get(start..) {
        let nonzero = nonzero_prefix(region);
        if nonzero > 0 {
            metrics.insert(metric!("gguf.trailing_nonzero_bytes"), nonzero as f64);
        }
    }
}
