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

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

/// Decode the string pool. Entries are UTF-16LE by default, UTF-8 when the
/// pool sets `UTF8_FLAG`; both use a length prefix that extends to two units
/// when the high bit is set.
fn parse_string_pool(chunk: &[u8]) -> Vec<String> {
    let Some(count) = u32_at(chunk, 8).map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(flags) = u32_at(chunk, 16) else {
        return Vec::new();
    };
    let Some(strings_start) = u32_at(chunk, 20).map(|v| v as usize) else {
        return Vec::new();
    };
    let utf8 = flags & UTF8_FLAG != 0;
    let mut out = Vec::with_capacity(count.min(4096));
    for i in 0..count.min(65_536) {
        let Some(offset) = u32_at(chunk, 28 + i * 4).map(|v| v as usize) else {
            break;
        };
        let Some(at) = strings_start.checked_add(offset) else {
            break;
        };
        out.push(decode_string(chunk, at, utf8).unwrap_or_default());
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
        let first = u16_at(chunk, at)? as usize;
        let (len, start) = if first & 0x8000 != 0 {
            // High bit set: the length spans two units.
            let low = u16_at(chunk, at + 2)? as usize;
            ((((first & 0x7fff) << 16) | low), at + 4)
        } else {
            (first, at + 2)
        };
        let units: Vec<u16> = (0..len)
            .map(|i| u16_at(chunk, start + i * 2).unwrap_or(0))
            .collect();
        Some(String::from_utf16_lossy(&units))
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

fn pool_str(pool: &[String], index: u32) -> String {
    // 0xFFFFFFFF is the "no string" sentinel.
    if index == u32::MAX {
        return String::new();
    }
    pool.get(index as usize).cloned().unwrap_or_default()
}

/// Render a typed attribute value. Only the types a manifest actually uses are
/// spelled out; anything else is reported as its raw integer rather than
/// guessed at, so a reader can tell a real value from an unrecognized one.
fn typed_value(pool: &[String], data_type: u8, data: u32) -> String {
    match data_type {
        // TYPE_STRING
        0x03 => pool_str(pool, data),
        // TYPE_INT_BOOLEAN
        0x12 => (data != 0).to_string(),
        // TYPE_INT_HEX
        0x11 => format!("0x{data:x}"),
        // TYPE_REFERENCE / TYPE_ATTRIBUTE — a resource id, not a value.
        0x01 | 0x02 => format!("@0x{data:x}"),
        // TYPE_INT_DEC and the remaining integer types.
        _ => (data as i32).to_string(),
    }
}

/// Walk the document and return its start elements in order.
pub(super) fn parse(bytes: &[u8]) -> Vec<Element> {
    let mut pool: Vec<String> = Vec::new();
    let mut elements = Vec::new();

    // Skip the 8-byte document header, then walk sibling chunks.
    let mut off = 8usize;
    while off + 8 <= bytes.len() && elements.len() < MAX_ELEMENTS {
        let Some(chunk_type) = u16_at(bytes, off) else {
            break;
        };
        let Some(size) = u32_at(bytes, off + 4).map(|v| v as usize) else {
            break;
        };
        // A zero or out-of-range size would loop forever or read past the end.
        if size < 8 || off + size > bytes.len() {
            break;
        }
        let chunk = &bytes[off..off + size];
        match chunk_type {
            TYPE_STRING_POOL => pool = parse_string_pool(chunk),
            TYPE_START_ELEMENT => {
                if let Some(el) = parse_start_element(chunk, &pool) {
                    elements.push(el);
                }
            }
            _ => {}
        }
        off += size;
    }
    elements
}

fn parse_start_element(chunk: &[u8], pool: &[String]) -> Option<Element> {
    // header: type/headerSize/size (8) + lineNumber (4) + comment (4)
    // body:   ns (4) + name (4) + attrStart (2) + attrSize (2) + attrCount (2)
    let name = pool_str(pool, u32_at(chunk, 20)?);
    let attr_start = u16_at(chunk, 24)? as usize;
    let attr_size = u16_at(chunk, 26)? as usize;
    let attr_count = u16_at(chunk, 28)? as usize;
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
        let Some(name_idx) = u32_at(chunk, at + 4) else {
            break;
        };
        let Some(raw_idx) = u32_at(chunk, at + 8) else {
            break;
        };
        let Some(data_type) = chunk.get(at + 15).copied() else {
            break;
        };
        let Some(data) = u32_at(chunk, at + 16) else {
            break;
        };
        let attr_name = pool_str(pool, name_idx);
        // The raw string is authoritative when present; otherwise fall back to
        // the typed value.
        let value = if raw_idx == u32::MAX {
            typed_value(pool, data_type, data)
        } else {
            pool_str(pool, raw_idx)
        };
        attrs.push((attr_name, value));
    }
    Some(Element { name, attrs })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a minimal AXML document: header, UTF-8 string pool, and one
    /// start element carrying a single string attribute.
    fn doc() -> Vec<u8> {
        let strings = ["manifest", "package", "com.example.app"];
        // --- string pool ---
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(data.len() as u32);
            data.push(s.len() as u8); // utf16 len
            data.push(s.len() as u8); // utf8 len
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let header = 28 + offsets.len() * 4;
        let pool_size = header + data.len();
        let mut pool = Vec::new();
        pool.extend_from_slice(&TYPE_STRING_POOL.to_le_bytes());
        pool.extend_from_slice(&28u16.to_le_bytes());
        pool.extend_from_slice(&(pool_size as u32).to_le_bytes());
        pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes()); // style count
        pool.extend_from_slice(&UTF8_FLAG.to_le_bytes());
        pool.extend_from_slice(&(header as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes()); // styles start
        for o in &offsets {
            pool.extend_from_slice(&o.to_le_bytes());
        }
        pool.extend_from_slice(&data);

        // --- start element: <manifest package="com.example.app"> ---
        let mut el = Vec::new();
        el.extend_from_slice(&TYPE_START_ELEMENT.to_le_bytes());
        el.extend_from_slice(&16u16.to_le_bytes());
        el.extend_from_slice(&(36u32 + 20).to_le_bytes());
        el.extend_from_slice(&1u32.to_le_bytes()); // line
        el.extend_from_slice(&u32::MAX.to_le_bytes()); // comment
        el.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
        el.extend_from_slice(&0u32.to_le_bytes()); // name -> "manifest"
        el.extend_from_slice(&20u16.to_le_bytes()); // attrStart
        el.extend_from_slice(&20u16.to_le_bytes()); // attrSize
        el.extend_from_slice(&1u16.to_le_bytes()); // attrCount
        el.extend_from_slice(&0u16.to_le_bytes()); // id
        el.extend_from_slice(&0u16.to_le_bytes()); // class
        el.extend_from_slice(&0u16.to_le_bytes()); // style
        el.extend_from_slice(&u32::MAX.to_le_bytes()); // attr ns
        el.extend_from_slice(&1u32.to_le_bytes()); // attr name -> "package"
        el.extend_from_slice(&2u32.to_le_bytes()); // raw -> "com.example.app"
        el.extend_from_slice(&8u16.to_le_bytes()); // size
        el.push(0); // res0
        el.push(0x03); // TYPE_STRING
        el.extend_from_slice(&2u32.to_le_bytes()); // data

        let mut out = Vec::new();
        out.extend_from_slice(&0x0003u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&((8 + pool.len() + el.len()) as u32).to_le_bytes());
        out.extend_from_slice(&pool);
        out.extend_from_slice(&el);
        out
    }

    #[test]
    fn reads_element_and_attribute_from_a_utf8_pool() {
        let els = parse(&doc());
        assert_eq!(els.len(), 1);
        assert_eq!(els[0].name, "manifest");
        assert_eq!(
            els[0].attrs,
            vec![("package".to_string(), "com.example.app".to_string())]
        );
    }

    #[test]
    fn a_zero_sized_chunk_does_not_hang_the_walk() {
        // A chunk claiming size 0 would loop forever if the walk trusted it.
        let mut b = vec![0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0];
        b.extend_from_slice(&[0x02, 0x01, 0x10, 0x00, 0, 0, 0, 0]);
        assert!(parse(&b).is_empty());
    }

    #[test]
    fn truncated_input_yields_what_was_read() {
        let full = doc();
        for cut in [8, 20, 40, full.len() / 2] {
            // Must not panic on any prefix.
            let _ = parse(&full[..cut.min(full.len())]);
        }
    }
}
