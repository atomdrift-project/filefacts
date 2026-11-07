//! Embedded objects in a compound file: streams that are themselves an
//! executable or container, and OLE1 `\x01Ole10Native` packages -- the
//! Packager shape that wraps an arbitrary file (classically an `.exe`) in a
//! document.
//!
//! Each object becomes one `office.embedded[]` entry with the keys the OOXML
//! view uses (`filename`, `kind`, `size_bytes`) plus where its bytes sit:
//! `stream`, and for a package `data_offset`, the payload's offset within
//! that stream. A caller that analyzes payloads carves them from there.

use std::io::{Read, Seek};

use serde_json::{Map, Value as JsonValue};

use crate::bytes::u32_le;
use crate::formats::common::embedded_kind;

/// Objects listed per document. Real documents embed a handful.
pub(super) const MAX_EMBEDDED: usize = 64;

/// How much of a package is read to find its payload: the header (label,
/// source path, temp path) and the payload's first bytes. Paths are
/// `MAX_PATH`-bounded in practice; a header longer than this is not one.
const PACKAGE_HEADER_BYTES: usize = 8 << 10;

/// A stream worth classifying: its path and length.
pub(super) struct StreamEntry {
    pub(super) path: String,
    pub(super) len: u64,
}

/// The embedded objects among `streams`, at most [`MAX_EMBEDDED`].
pub(super) fn scan<R: Read + Seek>(
    comp: &mut cfb::CompoundFile<R>,
    streams: &[StreamEntry],
) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for entry in streams {
        if out.len() >= MAX_EMBEDDED {
            break;
        }
        let Ok(mut stream) = comp.open_stream(&entry.path) else {
            continue;
        };
        let want = usize::try_from(entry.len)
            .map_or(PACKAGE_HEADER_BYTES, |len| len.min(PACKAGE_HEADER_BYTES));
        let mut head = vec![0; want];
        let Ok(()) = stream.read_exact(&mut head) else {
            continue;
        };
        let object = if entry.path.ends_with("\u{1}Ole10Native") {
            package(&head, entry)
        } else {
            embedded_kind(&head).map(|kind| {
                let mut obj = Map::new();
                obj.insert("filename".into(), entry.path.clone().into());
                obj.insert("kind".into(), kind.into());
                obj.insert("size_bytes".into(), entry.len.into());
                obj.insert("stream".into(), entry.path.clone().into());
                obj
            })
        };
        if let Some(obj) = object {
            out.push(JsonValue::Object(obj));
        }
    }
    out
}

/// An OLE1 Packager object (MS-OLEDS §2.3.6's native data as Packager
/// writes it): total size, a type word, the label and the source path as
/// NUL-terminated strings, a reserved word pair, the temp path with its
/// length, then the payload with its length.
fn package(head: &[u8], entry: &StreamEntry) -> Option<Map<String, JsonValue>> {
    // Total size (u32) and a type word (u16) whose value writers vary on.
    let mut at = 6;
    let label = cstr(head, &mut at)?;
    let source_path = cstr(head, &mut at)?;
    at += 4; // reserved
    let temp_len = usize::try_from(u32_le(head, at)?).ok()?;
    at = at.checked_add(4)?.checked_add(temp_len)?;
    let size = u32_le(head, at)?;
    let data_offset = at.checked_add(4)?;
    // The payload must fit in the stream it claims to be in.
    if u64::from(size) > entry.len.saturating_sub(data_offset as u64) {
        return None;
    }
    let mut obj = Map::new();
    let name = if label.is_empty() {
        &source_path
    } else {
        &label
    };
    obj.insert("filename".into(), name.clone().into());
    if !source_path.is_empty() {
        obj.insert("source_path".into(), source_path.into());
    }
    if let Some(kind) = head.get(data_offset..).and_then(embedded_kind) {
        obj.insert("kind".into(), kind.into());
    }
    obj.insert("size_bytes".into(), size.into());
    obj.insert("stream".into(), entry.path.clone().into());
    obj.insert("data_offset".into(), data_offset.into());
    obj.insert("relationship_type".into(), "package".into());
    Some(obj)
}

/// The NUL-terminated string at `*at`, advancing past its terminator.
fn cstr(bytes: &[u8], at: &mut usize) -> Option<String> {
    let rest = bytes.get(*at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    *at += end + 1;
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}
