//! Android binary XML (AXML) reader.
//!
//! `AndroidManifest.xml` inside an APK is not text: it is the compiled chunk
//! format `aapt` emits — a string pool followed by element chunks holding
//! string-pool indices. Without a reader for it an APK has no package name, no
//! version, no SDK levels and no permission list, which is the whole of an
//! Android app's declared identity.
//!
//! This walks chunks and returns elements with their attributes resolved to
//! strings. It is deliberately tolerant: a manifest that has been mangled to
//! defeat parsers is a fact worth reporting, not a reason to return nothing,
//! so a bad chunk stops the walk and keeps what came before it.

use super::common::bytes_at::{u16_le, u32_le};
use crate::value_key;

/// One parsed element: its tag name and resolved attributes.
pub(super) struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
}

const TYPE_STRING_POOL: u16 = 0x0001;
const TYPE_START_ELEMENT: u16 = 0x0102;
const UTF8_FLAG: u32 = 1 << 8;

/// Chunks to walk before giving up. A manifest has a few hundred elements;
/// this bounds a crafted file without truncating a real one.
const MAX_ELEMENTS: usize = 4096;

/// Decoded string-pool text kept across the document. Pool offsets are not
/// required to be distinct, so every one of 65,536 entries can name the same
/// multi-MiB string; real manifests decode a few tens of KiB. Entries past
/// the budget are dropped and resolve as empty.
const MAX_POOL_TEXT: usize = 16 << 20;

/// Element and attribute text resolved out of the pool. Every name and value
/// is a copy of a pool entry, and `MAX_ELEMENTS` elements of 512 attributes
/// can each name the largest one. The walk stops when this is spent.
const MAX_ELEMENT_TEXT: usize = 16 << 20;

/// Take `len` bytes from `budget`, or spend it entirely and fail.
fn charge(budget: &mut usize, len: usize) -> Option<()> {
    let Some(left) = budget.checked_sub(len) else {
        *budget = 0;
        return None;
    };
    *budget = left;
    Some(())
}

/// Identify a compiled Android XML document before passing arbitrary XML or
/// binary data through the tolerant chunk walker.
pub(super) fn looks_like_axml(data: &[u8]) -> bool {
    if data.len() < 12 || data.len() > 16 * 1024 * 1024 {
        return false;
    }
    u16_le(data, 0) == Some(0x0003)
        && u16_le(data, 2) == Some(8)
        && u32_le(data, 4).map(|n| n as usize) == Some(data.len())
        && u16_le(data, 8) == Some(TYPE_STRING_POOL)
}

/// Decode the string pool. Entries are UTF-16LE by default, UTF-8 when the
/// pool sets `UTF8_FLAG`; both use a length prefix that extends to two units
/// when the high bit is set. Decoding stops once `budget` is spent.
fn parse_string_pool(chunk: &[u8], budget: &mut usize) -> Vec<String> {
    let Some(count) = u32_le(chunk, 8).map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(flags) = u32_le(chunk, 16) else {
        return Vec::new();
    };
    let Some(strings_start) = u32_le(chunk, 20).map(|v| v as usize) else {
        return Vec::new();
    };
    let utf8 = flags & UTF8_FLAG != 0;
    let mut out = Vec::with_capacity(count.min(4096));
    for i in 0..count.min(65_536) {
        let Some(offset) = u32_le(chunk, 28 + i * 4).map(|v| v as usize) else {
            break;
        };
        let Some(at) = strings_start.checked_add(offset) else {
            break;
        };
        let text = decode_string(chunk, at, utf8).unwrap_or_default();
        if charge(budget, text.len()).is_none() {
            break;
        }
        out.push(text);
    }
    out
}

fn decode_string(chunk: &[u8], at: usize, utf8: bool) -> Option<String> {
    if utf8 {
        // Two varint lengths: UTF-16 length, then byte length.
        let (_, after_u16) = varint8(chunk, at)?;
        let (len, after) = varint8(chunk, after_u16)?;
        let end = after.checked_add(len)?;
        Some(String::from_utf8_lossy(chunk.get(after..end)?).into_owned())
    } else {
        let first = u16_le(chunk, at)? as usize;
        let (len, start) = if first & 0x8000 != 0 {
            // High bit set: the length spans two units.
            let low = u16_le(chunk, at.checked_add(2)?)? as usize;
            ((((first & 0x7fff) << 16) | low), at.checked_add(4)?)
        } else {
            (first, at.checked_add(2)?)
        };
        // A length running past the chunk is truncated, as in the UTF-8 arm.
        // The declared length (up to 2^31 units) must not size an allocation
        // the chunk cannot back.
        let end = start.checked_add(len.checked_mul(2)?)?;
        let units = chunk.get(start..end)?;
        Some(crate::bytes::utf16_lossy(
            units,
            crate::bytes::Endian::Little,
        ))
    }
}

/// One- or two-byte varint used by the UTF-8 pool encoding.
fn varint8(chunk: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *chunk.get(at)? as usize;
    if first & 0x80 != 0 {
        let second = *chunk.get(at + 1)? as usize;
        Some((((first & 0x7f) << 8) | second, at + 2))
    } else {
        Some((first, at + 1))
    }
}

/// A copy of pool entry `index`, charged to `budget`; `None` once the budget
/// is spent.
fn pool_str(pool: &[String], index: u32, budget: &mut usize) -> Option<String> {
    // 0xFFFFFFFF is the "no string" sentinel.
    if index == u32::MAX {
        return Some(String::new());
    }
    let text = pool.get(index as usize).map_or("", String::as_str);
    charge(budget, text.len())?;
    Some(text.to_owned())
}

/// Render a typed attribute value. Only the types a manifest actually uses are
/// spelled out; anything else is reported as its raw integer rather than
/// guessed at, so a reader can tell a real value from an unrecognized one.
fn typed_value(pool: &[String], data_type: u8, data: u32, budget: &mut usize) -> Option<String> {
    Some(match data_type {
        // TYPE_STRING
        0x03 => pool_str(pool, data, budget)?,
        // TYPE_INT_BOOLEAN
        0x12 => (data != 0).to_string(),
        // TYPE_INT_HEX
        0x11 => format!("0x{data:x}"),
        // TYPE_REFERENCE / TYPE_ATTRIBUTE — a resource id, not a value.
        0x01 | 0x02 => format!("@0x{data:x}"),
        // TYPE_INT_DEC and the remaining integer types.
        _ => data.cast_signed().to_string(),
    })
}

/// Walk the document and return its start elements in order.
pub(super) fn parse(bytes: &[u8]) -> Vec<Element> {
    let mut pool: Vec<String> = Vec::new();
    let mut elements = Vec::new();
    let mut pool_budget = MAX_POOL_TEXT;
    let mut text_budget = MAX_ELEMENT_TEXT;

    // Skip the 8-byte document header, then walk sibling chunks.
    let mut off = 8usize;
    while off + 8 <= bytes.len() && elements.len() < MAX_ELEMENTS && text_budget > 0 {
        let Some(chunk_type) = u16_le(bytes, off) else {
            break;
        };
        let Some(size) = u32_le(bytes, off + 4).map(|v| v as usize) else {
            break;
        };
        // A zero or out-of-range size would loop forever or read past the end.
        let Some(chunk) = off
            .checked_add(size)
            .filter(|_| size >= 8)
            .and_then(|end| bytes.get(off..end))
        else {
            break;
        };
        match chunk_type {
            TYPE_STRING_POOL => pool = parse_string_pool(chunk, &mut pool_budget),
            TYPE_START_ELEMENT => {
                if let Some(el) = parse_start_element(chunk, &pool, &mut text_budget) {
                    elements.push(el);
                }
            }
            _ => {}
        }
        off += size;
    }
    elements
}

/// Publish decoded string-valued Android XML attributes. The ordinary byte
/// string scanner cannot see strings in AXML's indexed UTF-8/UTF-16 pool, but
/// those values include the visible copy, button labels, and input hints in
/// lock screens and overlays.
pub(super) fn extract_values(bytes: &[u8], values: &mut crate::output::Values) {
    let elements = parse(bytes);
    if elements.is_empty() {
        return;
    }
    let flattened: Vec<_> = elements
        .iter()
        .flat_map(|element| {
            element.attrs.iter().map(|(attribute, value)| {
                serde_json::json!({
                    "element": element.name,
                    "attribute": attribute,
                    "value": value,
                })
            })
        })
        .collect();
    if !flattened.is_empty() {
        values.insert_key(
            value_key!("android_xml.values"),
            serde_json::Value::Array(flattened),
        );
    }
}

/// Resolve one start element, charging its names and values to `budget`.
/// An element the budget cannot cover is dropped whole.
fn parse_start_element(chunk: &[u8], pool: &[String], budget: &mut usize) -> Option<Element> {
    // header: type/headerSize/size (8) + lineNumber (4) + comment (4)
    // body:   ns (4) + name (4) + attrStart (2) + attrSize (2) + attrCount (2)
    let name = pool_str(pool, u32_le(chunk, 20)?, budget)?;
    let attr_start = u16_le(chunk, 24)? as usize;
    let attr_size = u16_le(chunk, 26)? as usize;
    let attr_count = u16_le(chunk, 28)? as usize;
    let mut attrs = Vec::new();
    // 20 bytes is the documented per-attribute record: ns(4) name(4)
    // rawValue(4) size(2) res0(1) dataType(1) data(4). Any other stride means
    // a layout this reader does not understand, so the attributes are left out
    // rather than misread into plausible-looking nonsense.
    if attr_size != 20 {
        return Some(Element { name, attrs });
    }
    for i in 0..attr_count.min(512) {
        let at = 16 + attr_start + i * attr_size;
        let Some(name_idx) = u32_le(chunk, at + 4) else {
            break;
        };
        let Some(raw_idx) = u32_le(chunk, at + 8) else {
            break;
        };
        let Some(data_type) = chunk.get(at + 15).copied() else {
            break;
        };
        let Some(data) = u32_le(chunk, at + 16) else {
            break;
        };
        let attr_name = pool_str(pool, name_idx, budget)?;
        // The raw string is authoritative when present; otherwise fall back to
        // the typed value.
        let value = if raw_idx == u32::MAX {
            typed_value(pool, data_type, data, budget)?
        } else {
            pool_str(pool, raw_idx, budget)?
        };
        attrs.push((attr_name, value));
    }
    Some(Element { name, attrs })
}

#[cfg(test)]
mod tests;
