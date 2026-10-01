//! Electron ASAR archive-index extractor.
//!
//! ASAR stores a Chromium-pickle header followed by raw, uncompressed member
//! bytes. This extractor reads only the header table and byte ranges; callers
//! that need recursive analysis should slice members and dispatch them by their
//! own detected file types.

use crate::metric;
use serde_json::{Map as JsonMap, Value as JsonValue};

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use crate::bytes;
use crate::error::Error;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};

/// The shared aggregates an ASAR reports, over its file entries. Directories
/// are implicit nodes of the header tree rather than members, so their count
/// is kept by the walk.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::UncompressedSize(Scope::All),
    Agg::CompressedSize,
    Agg::MaxFilenameLength,
    Agg::Scripts,
    Agg::NestedArchives,
];

/// An ASAR member's published value has never carried the (always
/// `stored`) compression fields; they are on the typed member only.
const SHAPE: Shape = Shape {
    compression: false,
    ..Shape::FULL
};

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
    // Pickle size, header size, pickle payload size, JSON string length.
    let (Some(pickle_field_size), Some(header_size), Some(json_size)) = (
        bytes::u32_le(bytes, 0),
        bytes::u32_le(bytes, 4),
        bytes::u32_le(bytes, 12),
    ) else {
        return Err(Error::malformed("asar", "truncated header"));
    };
    let (header_size, json_size) = (header_size as usize, json_size as usize);
    if pickle_field_size != 4 {
        return Err(Error::malformed("asar", "unexpected pickle header"));
    }

    let header_end = 16usize
        .checked_add(json_size)
        .ok_or_else(|| Error::malformed("asar", "header size overflow"))?;
    let data_offset = 8usize
        .checked_add(header_size)
        .ok_or_else(|| Error::malformed("asar", "data offset overflow"))?;
    let json = bytes
        .get(16..header_end)
        .filter(|_| data_offset <= bytes.len() && data_offset >= header_end)
        .ok_or_else(|| Error::malformed("asar", "header extends past end of file"))?;

    let header: JsonValue = serde_json::from_slice(json)
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

/// What the header-tree walk accumulates.
struct Walk {
    data_offset: u64,
    members: Vec<JsonValue>,
    stats: ArchiveStats,
    directory_count: u64,
}

fn walk_files(
    prefix: &str,
    files: &JsonMap<String, JsonValue>,
    walk: &mut Walk,
    archive_members: &mut Vec<ArchiveMember>,
) {
    for (name, node) in files {
        let path = path_join(prefix, name);
        let Some(obj) = node.as_object() else {
            continue;
        };

        if let Some(children) = obj.get("files").and_then(JsonValue::as_object) {
            walk.directory_count += 1;
            walk_files(&path, children, walk, archive_members);
            continue;
        }

        let Some(size) = obj.get("size").and_then(JsonValue::as_u64) else {
            continue;
        };
        let unpacked = obj
            .get("unpacked")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        let data_start = obj
            .get("offset")
            .and_then(parse_offset)
            .and_then(|o| walk.data_offset.checked_add(o));

        let member = ArchiveMember {
            path,
            size_bytes: size,
            entry_type: Some("regular".to_string()),
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: Some(ArchiveCompression {
                compressed_size: Some(size),
                method: Some("stored".to_string()),
            }),
            ownership: None,
            offsets: ArchiveOffsets {
                header: None,
                data: data_start,
                central_header: None,
            },
        };
        // ASAR keeps its own Electron-oriented script and archive suffixes.
        let mut reading = Reading::of(&member);
        reading.class.is_script = looks_script(&member.path);
        reading.class.is_nested_archive = looks_nested_archive(&member.path);
        walk.stats.observe(&member, &reading);

        let mut value = member_value(&member, SHAPE);
        if unpacked {
            value.insert("unpacked".into(), JsonValue::Bool(true));
        }
        walk.members.push(JsonValue::Object(value));

        // An unpacked member lives beside the archive, and one without an
        // offset has no bytes here: neither is a slice of the input.
        if !unpacked && data_start.is_some() {
            archive_members.push(member);
        }
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let index = parse_index(bytes)?;
    values.insert("archive.format.kind", JsonValue::String("asar".into()));
    metrics.insert(metric!("archive.header_size"), index.header_size as f64);

    let mut walk = Walk {
        data_offset: index.data_offset,
        members: Vec::new(),
        stats: ArchiveStats::new(AGGS),
        directory_count: 0,
    };
    walk_files("", &index.files, &mut walk, archive_members);

    values.insert("archive.members", JsonValue::Array(walk.members));
    walk.stats.emit(values, metrics);
    // One entry type and one method by construction, declared even for an
    // archive with no files.
    values.insert(
        "archive.format.entry_types",
        JsonValue::Array(vec![JsonValue::String("regular".into())]),
    );
    values.insert(
        "archive.compression.methods",
        JsonValue::Array(vec![JsonValue::String("stored".into())]),
    );
    metrics.insert(
        metric!("archive.directory_count"),
        walk.directory_count as f64,
    );
    metrics.insert(
        metric!("archive.format.regular_count"),
        walk.stats.member_count() as f64,
    );

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
