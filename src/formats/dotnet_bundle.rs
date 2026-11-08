//! The manifest of a .NET single-file bundle: the managed assemblies and
//! files an apphost (PE, ELF or Mach-O) carries after its own image.
//! Layouts follow dotnet/runtime's bundle/header.h and file_entry.h
//! (versions 1, 2 and 6). The native host's fixed marker is preceded by the
//! manifest offset; an unpatched apphost leaves it zero. Nothing is loaded,
//! decompressed or executed: members are reported where they lie, and v6's
//! raw-DEFLATE members carry their compressed size.
//!
//! `binary.dotnet_bundle` — `{version, header_offset, members[{path, offset,
//! size, compressed_size}], notes[], error}`; `notes` say where a damaged
//! manifest stopped, `error` why no manifest could be read at all.

use serde_json::{Map, Value as JsonValue, json};

use crate::output::Values;
use crate::value_key;

/// The fixed marker the bundler patches into the apphost.
const SIGNATURE: &[u8; 32] = &[
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
];
/// Longest member path read.
const MAX_STRING: usize = 4096;
/// Most markers examined: an earlier decoy must not hide a later manifest,
/// but the search is bounded.
const MAX_MARKERS: usize = 32;
/// Most members listed.
const MAX_MEMBERS: usize = 65_536;
/// Manifest bytes read before the walk stops.
const MANIFEST_BUDGET: usize = 8 * 1024 * 1024;

/// A cursor over the manifest that fails rather than reading past the end.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.at.checked_add(n).ok_or("manifest offset overflow")?;
        let bytes = self.data.get(self.at..end).ok_or("manifest truncated")?;
        self.at = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| "manifest truncated")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().map_err(|_| "manifest truncated")?,
        ))
    }

    /// A .NET `BinaryWriter` string: 7-bit encoded length, then UTF-8.
    fn string(&mut self) -> Result<String, String> {
        let mut len = 0usize;
        for shift in (0..35).step_by(7) {
            let byte = *self.take(1)?.first().ok_or("manifest truncated")?;
            if shift == 28 && byte > 7 {
                return Err("invalid string length".into());
            }
            len |= usize::from(byte & 127) << shift;
            if byte < 128 {
                if len > MAX_STRING {
                    return Err("bundle string exceeds limit".into());
                }
                return String::from_utf8(self.take(len)?.to_vec())
                    .map_err(|_| "invalid UTF-8 bundle path".into());
            }
        }
        Err("invalid string length".into())
    }
}

/// The manifest at `header`.
fn manifest(data: &[u8], header: usize) -> Result<Map<String, JsonValue>, String> {
    let mut reader = Reader {
        data: data.get(header..).ok_or("bundle header outside file")?,
        at: 0,
    };
    let (major, minor) = (reader.u32()?, reader.u32()?);
    if !matches!(major, 1 | 2 | 6) || minor != 0 {
        return Err(format!("unsupported bundle version {major}.{minor}"));
    }
    let count = usize::try_from(reader.u32()?).map_err(|_| "invalid bundle member count")?;
    if count == 0 || count > MAX_MEMBERS {
        return Err("invalid bundle member count".into());
    }
    let _bundle_id = reader.string()?;
    if major >= 2 {
        // Deps/runtimeconfig locations and flags.
        reader.take(40)?;
    }
    let mut members = Vec::new();
    let mut notes = Vec::new();
    for index in 0..count {
        if reader.at > MANIFEST_BUDGET {
            notes.push(JsonValue::from(
                "bundle manifest exceeded 8 MiB parsing budget",
            ));
            break;
        }
        let entry = (|| -> Result<JsonValue, String> {
            let offset = reader.u64()?;
            let size = reader.u64()?;
            let compressed = if major >= 6 { reader.u64()? } else { 0 };
            reader.take(1)?; // file type
            let path = reader.string()?;
            Ok(json!({"path": path, "offset": offset, "size": size, "compressed_size": compressed}))
        })();
        match entry {
            Ok(entry) => members.push(entry),
            Err(error) => {
                notes.push(JsonValue::from(format!(
                    "bundle manifest stopped at member {index}/{count}: {error}"
                )));
                break;
            }
        }
    }
    let mut out = Map::new();
    out.insert("version".into(), JsonValue::from(major));
    out.insert("header_offset".into(), JsonValue::from(header));
    out.insert("members".into(), JsonValue::Array(members));
    if !notes.is_empty() {
        out.insert("notes".into(), JsonValue::Array(notes));
    }
    Ok(out)
}

/// Read the bundle manifest a host carries, if it carries one.
fn parse(data: &[u8]) -> Option<Map<String, JsonValue>> {
    let mut error = None;
    for (index, marker) in memchr::memmem::find_iter(data, SIGNATURE).enumerate() {
        if index >= MAX_MARKERS {
            error = Some("too many .NET bundle markers".to_string());
            break;
        }
        let Some(header) = marker
            .checked_sub(8)
            .and_then(|start| data.get(start..marker))
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            continue;
        };
        if header == 0 {
            continue; // an unpatched apphost
        }
        match usize::try_from(header)
            .map_err(|_| "bundle offset overflow".to_string())
            .and_then(|header| manifest(data, header))
        {
            Ok(bundle) => return Some(bundle),
            Err(problem) => error = Some(problem),
        }
    }
    error.map(|error| {
        let mut out = Map::new();
        out.insert("error".into(), JsonValue::from(error));
        out
    })
}

pub(super) fn emit(data: &[u8], values: &mut Values) {
    if let Some(bundle) = parse(data) {
        values.insert_key(
            value_key!("binary.dotnet_bundle"),
            JsonValue::Object(bundle),
        );
    }
}

#[cfg(test)]
mod tests;
