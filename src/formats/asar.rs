//! Electron ASAR archive-index extractor.
//!
//! ASAR stores a Chromium-pickle header followed by raw, uncompressed member
//! bytes. This extractor reads only the header table and byte ranges; callers
//! that need recursive analysis should slice members and dispatch them by their
//! own detected file types.

use crate::metric;
use crate::value_key;
use serde_json::{Map as JsonMap, Value as JsonValue};

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, member_value};
use super::bounded::{Limits, MAX_ARCHIVE_MEMBERS, MAX_PATH_BYTES};
use crate::bytes;
use crate::error::Error;
use crate::output::{ArchiveCompression, ArchiveMember, EntryType, Metrics, Values};

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

fn parse_offset(value: &JsonValue) -> Option<u64> {
    match value {
        JsonValue::String(s) => s.parse::<u64>().ok(),
        JsonValue::Number(n) => n.as_u64(),
        _ => None,
    }
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

    let mut header: JsonValue = serde_json::from_slice(json)
        .map_err(|e| Error::malformed_with_source("asar", "invalid header json", e))?;
    // Moved out of the parsed header, not cloned: the table is the whole
    // header, and can run to megabytes.
    let files = match header.get_mut("files").map(JsonValue::take) {
        Some(JsonValue::Object(files)) => files,
        _ => return Err(Error::malformed("asar", "missing files table")),
    };

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
    /// File entries past [`MAX_ARCHIVE_MEMBERS`], counted but not listed.
    unlisted: u64,
    /// Path bytes the rest of the walk may still build. Every member's
    /// path repeats its ancestors' names, so a deep chain of long directory
    /// names multiplies into gigabytes of paths without it.
    path_budget: usize,
    /// The path budget ran out and the walk stopped.
    path_capped: bool,
}

impl Walk {
    /// `prefix/name`, charged against the path budget; `None` once it is
    /// spent.
    fn join(&mut self, prefix: &str, name: &str) -> Option<String> {
        let len = prefix.len() + usize::from(!prefix.is_empty()) + name.len();
        let Some(left) = self.path_budget.checked_sub(len) else {
            self.path_budget = 0;
            self.path_capped = true;
            return None;
        };
        self.path_budget = left;
        Some(if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        })
    }
}

fn walk_files(
    prefix: &str,
    files: &JsonMap<String, JsonValue>,
    walk: &mut Walk,
    archive_members: &mut Vec<ArchiveMember>,
) {
    for (name, node) in files {
        if walk.path_capped {
            return;
        }
        let Some(obj) = node.as_object() else {
            continue;
        };

        if let Some(children) = obj.get("files").and_then(JsonValue::as_object) {
            walk.directory_count += 1;
            let Some(path) = walk.join(prefix, name) else {
                return;
            };
            walk_files(&path, children, walk, archive_members);
            continue;
        }

        let Some(size) = obj.get("size").and_then(JsonValue::as_u64) else {
            continue;
        };
        if walk.members.len() >= MAX_ARCHIVE_MEMBERS {
            walk.unlisted += 1;
            continue;
        }
        let Some(path) = walk.join(prefix, name) else {
            return;
        };
        let unpacked = obj
            .get("unpacked")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        let data_start = obj
            .get("offset")
            .and_then(parse_offset)
            .and_then(|o| walk.data_offset.checked_add(o));

        let mut member = ArchiveMember::new(path, size, EntryType::Regular);
        member.compression = ArchiveCompression::new(Some(size), Some("stored".into()));
        member.offsets.data = data_start;
        walk.stats.observe(&member, &Reading::of(&member));

        let mut value = member_value(&member);
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
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("asar".into()),
    );
    metrics.insert(metric!("archive.header_size"), index.header_size as f64);

    let mut walk = Walk {
        data_offset: index.data_offset,
        members: Vec::new(),
        stats: ArchiveStats::new(AGGS),
        directory_count: 0,
        unlisted: 0,
        path_budget: MAX_PATH_BYTES,
        path_capped: false,
    };
    walk_files("", &index.files, &mut walk, archive_members);
    let mut limits = Limits::default();
    if walk.path_capped {
        limits.push(
            "path-budget",
            format!("member paths exceeded {MAX_PATH_BYTES} bytes"),
        );
    }
    if walk.unlisted > 0 {
        limits.push(
            "member-cap",
            format!(
                "listed {MAX_ARCHIVE_MEMBERS} of {} members",
                MAX_ARCHIVE_MEMBERS as u64 + walk.unlisted
            ),
        );
    }
    limits.emit(values, value_key!("asar.limits"));

    values.insert_key(
        value_key!("archive.members"),
        JsonValue::Array(walk.members),
    );
    walk.stats.emit(values, metrics);
    // One entry type and one method by construction, declared even for an
    // archive with no files.
    values.insert_key(
        value_key!("archive.format.entry_types"),
        JsonValue::Array(vec![JsonValue::String("regular".into())]),
    );
    values.insert_key(
        value_key!("archive.compression.methods"),
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
mod tests;
