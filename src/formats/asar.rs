//! Electron ASAR archive-index extractor.
//!
//! ASAR stores a Chromium-pickle header followed by raw, uncompressed member
//! bytes. This extractor reads only the header table and byte ranges; callers
//! that need recursive analysis should slice members and dispatch them by their
//! own detected file types.

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::error::Error;
use crate::output::{ArchiveMember, Metrics, Values};

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let chunk = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::malformed("asar", "truncated header"))?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn parse_offset(value: &JsonValue) -> Option<u64> {
    match value {
        JsonValue::String(s) => s.parse::<u64>().ok(),
        JsonValue::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn path_join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

fn looks_nested_archive(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".zip")
        || lower.ends_with(".jar")
        || lower.ends_with(".asar")
        || lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".7z")
        || lower.ends_with(".rar")
}

fn looks_script(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".ts")
        || lower.ends_with(".sh")
        || lower.ends_with(".ps1")
        || lower.ends_with(".py")
}

struct AsarIndex {
    data_offset: u64,
    header_size: u64,
    files: JsonMap<String, JsonValue>,
}

fn parse_index(bytes: &[u8]) -> Result<AsarIndex, Error> {
    if bytes.len() < 16 {
        return Err(Error::malformed("asar", "truncated header"));
    }

    let pickle_field_size = read_u32_le(bytes, 0)?;
    let header_size = read_u32_le(bytes, 4)? as usize;
    let json_size = read_u32_le(bytes, 12)? as usize;
    if pickle_field_size != 4 {
        return Err(Error::malformed("asar", "unexpected pickle header"));
    }

    let header_end = 16usize
        .checked_add(json_size)
        .ok_or_else(|| Error::malformed("asar", "header size overflow"))?;
    let data_offset = 8usize
        .checked_add(header_size)
        .ok_or_else(|| Error::malformed("asar", "data offset overflow"))?;
    if header_end > bytes.len() || data_offset > bytes.len() || data_offset < header_end {
        return Err(Error::malformed("asar", "header extends past end of file"));
    }

    let header: JsonValue = serde_json::from_slice(&bytes[16..header_end])
        .map_err(|e| Error::malformed("asar", format!("invalid header json: {e}")))?;
    let files = header
        .get("files")
        .and_then(JsonValue::as_object)
        .cloned()
        .ok_or_else(|| Error::malformed("asar", "missing files table"))?;

    Ok(AsarIndex {
        data_offset: data_offset as u64,
        header_size: header_size as u64,
        files,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_files(
    prefix: &str,
    files: &JsonMap<String, JsonValue>,
    data_offset: u64,
    members: &mut Vec<JsonValue>,
    archive_members: &mut Vec<ArchiveMember>,
    file_count: &mut u64,
    directory_count: &mut u64,
    total_uncompressed: &mut u64,
    max_filename_length: &mut u64,
    script_count: &mut u64,
    nested_archive_count: &mut u64,
) -> Result<(), Error> {
    for (name, node) in files {
        let path = path_join(prefix, name);
        let Some(obj) = node.as_object() else {
            continue;
        };

        if let Some(children) = obj.get("files").and_then(JsonValue::as_object) {
            *directory_count += 1;
            walk_files(
                &path,
                children,
                data_offset,
                members,
                archive_members,
                file_count,
                directory_count,
                total_uncompressed,
                max_filename_length,
                script_count,
                nested_archive_count,
            )?;
            continue;
        }

        let Some(size) = obj.get("size").and_then(JsonValue::as_u64) else {
            continue;
        };
        let unpacked = obj
            .get("unpacked")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        let offset = obj.get("offset").and_then(parse_offset);
        let data_start = offset.and_then(|o| data_offset.checked_add(o));

        *file_count += 1;
        *total_uncompressed = total_uncompressed.saturating_add(size);
        *max_filename_length = (*max_filename_length).max(path.len() as u64);
        if looks_script(&path) {
            *script_count += 1;
        }
        if looks_nested_archive(&path) {
            *nested_archive_count += 1;
        }

        let mut member = JsonMap::new();
        member.insert("path".into(), JsonValue::String(path.clone()));
        member.insert("size_bytes".into(), JsonValue::Number(size.into()));
        member.insert("entry_type".into(), JsonValue::String("regular".into()));
        if unpacked {
            member.insert("unpacked".into(), JsonValue::Bool(true));
        }
        if let Some(start) = data_start {
            member.insert("data_offset".into(), JsonValue::Number(start.into()));
        }
        members.push(JsonValue::Object(member));

        if unpacked {
            continue;
        }
        if let Some(start) = data_start {
            archive_members.push(ArchiveMember {
                path,
                size_bytes: size,
                entry_type: Some("regular".to_string()),
                mtime_unix: None,
                linkname: None,
                host_os: None,
                crc32: None,
                encrypted: false,
                compression: Some(crate::output::ArchiveCompression {
                    compressed_size: Some(size),
                    method: Some("stored".to_string()),
                }),
                ownership: None,
                offsets: crate::output::ArchiveOffsets {
                    header: None,
                    data: Some(start),
                    central_header: None,
                },
            });
        }
    }
    Ok(())
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let index = parse_index(bytes)?;
    values.insert("archive.format.kind", JsonValue::String("asar".into()));
    metrics.insert("archive.header_size", index.header_size as f64);

    let mut members = Vec::new();
    let mut file_count = 0u64;
    let mut directory_count = 0u64;
    let mut total_uncompressed = 0u64;
    let mut max_filename_length = 0u64;
    let mut script_count = 0u64;
    let mut nested_archive_count = 0u64;

    walk_files(
        "",
        &index.files,
        index.data_offset,
        &mut members,
        archive_members,
        &mut file_count,
        &mut directory_count,
        &mut total_uncompressed,
        &mut max_filename_length,
        &mut script_count,
        &mut nested_archive_count,
    )?;

    values.insert("archive.members", JsonValue::Array(members));
    values.insert(
        "archive.format.entry_types",
        JsonValue::Array(vec![JsonValue::String("regular".into())]),
    );
    values.insert(
        "archive.compression.methods",
        JsonValue::Array(vec![JsonValue::String("stored".into())]),
    );

    metrics.insert("archive.member_count", file_count as f64);
    metrics.insert("archive.file_count", file_count as f64);
    metrics.insert("archive.directory_count", directory_count as f64);
    metrics.insert("archive.uncompressed_size", total_uncompressed as f64);
    metrics.insert("archive.compressed_size", total_uncompressed as f64);
    metrics.insert("archive.format.regular_count", file_count as f64);
    metrics.insert("archive.max_filename_length", max_filename_length as f64);
    metrics.insert("archive.script_count", script_count as f64);
    metrics.insert("archive.nested_archive_count", nested_archive_count as f64);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let header = br#"{"files":{"main.js":{"size":18,"offset":"0"},"package.json":{"size":2,"offset":"18"},"lib":{"files":{"inner.js":{"size":3,"offset":"20"}}}}}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&((header.len() + 8) as u32).to_le_bytes());
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(b"console.log('x');{}abc");
        bytes
    }

    #[test]
    fn extracts_asar_archive_members() {
        let mut values = Values::new();
        let mut metrics = Metrics::new();
        let mut members = Vec::new();
        extract(&fixture(), &mut values, &mut metrics, &mut members).unwrap();

        assert_eq!(
            values
                .get("archive.format.kind")
                .and_then(JsonValue::as_str),
            Some("asar")
        );
        assert_eq!(metrics.get("archive.member_count"), Some(3.0));
        assert_eq!(metrics.get("archive.directory_count"), Some(1.0));
        assert_eq!(metrics.get("archive.script_count"), Some(2.0));
        assert_eq!(members.len(), 3);
        let main = members.iter().find(|m| m.path == "main.js").unwrap();
        assert_eq!(main.offsets.data, Some(header_len_for_test()));
    }

    fn header_len_for_test() -> u64 {
        let header = br#"{"files":{"main.js":{"size":18,"offset":"0"},"package.json":{"size":2,"offset":"18"},"lib":{"files":{"inner.js":{"size":3,"offset":"20"}}}}}"#;
        (header.len() + 16) as u64
    }
}
