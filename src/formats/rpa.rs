//! Ren'Py archive facts from a bounded, non-executing pickle index reader.

use serde_json::{Value as JsonValue, json};

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use crate::error::Error;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};
use crate::{metric, value_key};

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::UncompressedSize(Scope::Files),
    Agg::Methods { always: true },
    Agg::EntryTypes,
    Agg::MaxFilenameLength,
    Agg::HiddenFiles,
    Agg::PathTraversal(Scope::All),
    Agg::NameTricks,
    Agg::Executables,
    Agg::Scripts,
    Agg::NestedArchives,
    Agg::MisplacedExecutables,
    Agg::NoiseFiles,
    Agg::DuplicateMembers,
];

fn hex_preview(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().min(32) * 2);
    for &b in bytes.iter().take(32) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let header = crate::rpa::parse_header(bytes).map_err(|e| Error::malformed("rpa", e))?;
    let index = match crate::rpa::parse(bytes) {
        Ok(index) => index,
        Err(error) => {
            values.insert_key(
                value_key!("rpa"),
                json!({
                    "version": header.version,
                    "header_size": header.header_size,
                    "index_offset": header.index_offset,
                    "key_hex": format!("{:08x}", header.key),
                    "payload_region_bytes": header.index_offset - header.header_size as u64,
                    "complete": false,
                    "index_error": error,
                }),
            );
            return Err(Error::malformed("rpa", error));
        }
    };
    values.insert_key(value_key!("archive.format.kind"), json!("rpa"));

    let mut stats = ArchiveStats::new(AGGS);
    let mut listed = Vec::with_capacity(index.members.len());
    let mut detailed = Vec::with_capacity(index.members.len());
    let mut ranges = Vec::new();
    let mut chunk_count = 0u64;
    let mut multi_chunk_count = 0u64;
    let mut prefix_member_count = 0u64;
    let mut prefix_bytes = 0u64;
    let mut referenced_bytes = 0u64;
    let mut logical_bytes = 0u64;
    let mut non_monotonic_count = 0u64;
    let mut last_offset = 0u64;
    for entry in &index.members {
        if entry.chunks.len() > 1 {
            multi_chunk_count += 1;
        }
        let mut has_prefix = false;
        let mut member_prefix_bytes = 0u64;
        let mut member_physical_bytes = 0u64;
        let mut chunk_values = Vec::with_capacity(entry.chunks.len());
        for chunk in &entry.chunks {
            chunk_count += 1;
            prefix_bytes += chunk.prefix.len() as u64;
            member_prefix_bytes += chunk.prefix.len() as u64;
            referenced_bytes += chunk.length;
            member_physical_bytes += chunk.length;
            if !chunk.prefix.is_empty() {
                has_prefix = true;
            }
            if chunk.offset < last_offset {
                non_monotonic_count += 1;
            }
            last_offset = chunk.offset;
            if chunk.length > 0 {
                ranges.push((chunk.offset, chunk.offset + chunk.length));
            }
            let preview_start = usize::try_from(chunk.offset)
                .map_err(|_| Error::malformed("rpa", "chunk offset overflow"))?;
            let preview_end = usize::try_from(chunk.offset + chunk.length.min(32))
                .map_err(|_| Error::malformed("rpa", "chunk preview end overflow"))?;
            let preview = bytes
                .get(preview_start..preview_end)
                .ok_or_else(|| Error::malformed("rpa", "chunk preview outside archive"))?;
            chunk_values.push(json!({
                "offset": chunk.offset,
                "length": chunk.length,
                "payload_hex_preview": hex_preview(preview),
                "prefix_length": chunk.prefix.len(),
                "prefix_hex_preview": hex_preview(&chunk.prefix),
                "prefix_sha256": if chunk.prefix.is_empty() { None } else { Some(sha256(&chunk.prefix)) },
            }));
        }
        if has_prefix {
            prefix_member_count += 1;
        }
        logical_bytes += entry.size;
        let member = ArchiveMember {
            path: entry.path.clone(),
            size_bytes: entry.size,
            entry_type: Some("regular".into()),
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: Some(ArchiveCompression {
                compressed_size: None,
                method: Some("stored".into()),
            }),
            ownership: None,
            offsets: ArchiveOffsets {
                header: None,
                data: entry.chunks.first().map(|c| c.offset),
                central_header: None,
            },
        };
        stats.observe(&member, &Reading::of(&member));
        listed.push(JsonValue::Object(member_value(&member, Shape::FULL)));
        members.push(member);
        detailed.push(json!({
            "path": entry.path,
            "size_bytes": entry.size,
            "chunk_count": entry.chunks.len(),
            "prefix_bytes": member_prefix_bytes,
            "physical_bytes": member_physical_bytes,
            "chunks": chunk_values,
        }));
    }
    ranges.sort_unstable();
    let mut covered_bytes = 0u64;
    let mut end = header.header_size as u64;
    for (start, stop) in ranges {
        if stop > end {
            covered_bytes += stop - start.max(end);
            end = stop;
        }
    }
    let payload_region_bytes = header.index_offset - header.header_size as u64;
    let index_ratio = if index.compressed_index_size == 0 {
        0.0
    } else {
        index.uncompressed_index_size as f64 / index.compressed_index_size as f64
    };
    values.insert_key(value_key!("archive.members"), JsonValue::Array(listed));
    values.insert_key(
        value_key!("rpa"),
        json!({
            "version": header.version,
            "header_size": header.header_size,
            "index_offset": header.index_offset,
            "key_hex": format!("{:08x}", header.key),
            "key_is_default": header.version == 3 && header.key == 0x42424242,
            "complete": true,
            "index": {
                "compression": "zlib",
                "compressed_size": index.compressed_index_size,
                "uncompressed_size": index.uncompressed_index_size,
                "compression_ratio": index_ratio,
                "compressed_entropy": index.compressed_entropy,
                "pickle_entropy": index.index_entropy,
                "compressed_sha256": index.compressed_index_sha256,
                "sha256": index.index_sha256,
                "trailing_bytes": index.trailing_bytes,
                "trailing_sha256": index.trailing_sha256,
                "pickle_protocol": index.pickle_protocol,
                "pickle_opcode_count": index.pickle_opcode_count,
                "pickle_memo_count": index.pickle_memo_count,
                "pickle_frame_count": index.pickle_frame_count,
            },
            "member_count": index.members.len(),
            "duplicate_key_assignment_count": index.duplicate_key_assignment_count,
            "chunk_count": chunk_count,
            "multi_chunk_member_count": multi_chunk_count,
            "prefix_member_count": prefix_member_count,
            "prefix_bytes": prefix_bytes,
            "logical_member_bytes": logical_bytes,
            "physical_referenced_bytes": referenced_bytes,
            "physical_covered_bytes": covered_bytes,
            "overlapping_reference_bytes": referenced_bytes.saturating_sub(covered_bytes),
            "payload_region_bytes": payload_region_bytes,
            "unreferenced_payload_bytes": payload_region_bytes.saturating_sub(covered_bytes),
            "non_monotonic_chunk_count": non_monotonic_count,
            "members": detailed,
        }),
    );
    metrics.insert(metric!("rpa.chunk_count"), chunk_count as f64);
    metrics.insert(
        metric!("rpa.duplicate_key_assignment_count"),
        index.duplicate_key_assignment_count as f64,
    );
    metrics.insert(metric!("rpa.index_compression_ratio"), index_ratio);
    metrics.insert(
        metric!("rpa.index_compressed_entropy"),
        index.compressed_entropy,
    );
    metrics.insert(
        metric!("rpa.index_compressed_size"),
        index.compressed_index_size as f64,
    );
    metrics.insert(metric!("rpa.index_offset"), header.index_offset as f64);
    metrics.insert(metric!("rpa.index_pickle_entropy"), index.index_entropy);
    metrics.insert(
        metric!("rpa.index_size"),
        index.uncompressed_index_size as f64,
    );
    metrics.insert(
        metric!("rpa.index_trailing_bytes"),
        index.trailing_bytes as f64,
    );
    metrics.insert(metric!("rpa.member_count"), index.members.len() as f64);
    metrics.insert(metric!("rpa.logical_member_bytes"), logical_bytes as f64);
    metrics.insert(
        metric!("rpa.multi_chunk_member_count"),
        multi_chunk_count as f64,
    );
    metrics.insert(
        metric!("rpa.non_monotonic_chunk_count"),
        non_monotonic_count as f64,
    );
    metrics.insert(
        metric!("rpa.overlapping_reference_bytes"),
        referenced_bytes.saturating_sub(covered_bytes) as f64,
    );
    metrics.insert(
        metric!("rpa.payload_region_bytes"),
        payload_region_bytes as f64,
    );
    metrics.insert(metric!("rpa.physical_covered_bytes"), covered_bytes as f64);
    metrics.insert(
        metric!("rpa.physical_referenced_bytes"),
        referenced_bytes as f64,
    );
    metrics.insert(metric!("rpa.prefix_bytes"), prefix_bytes as f64);
    metrics.insert(
        metric!("rpa.prefix_member_count"),
        prefix_member_count as f64,
    );
    metrics.insert(
        metric!("rpa.unreferenced_payload_bytes"),
        payload_region_bytes.saturating_sub(covered_bytes) as f64,
    );
    metrics.insert(metric!("rpa.version"), f64::from(header.version));
    stats.emit(values, metrics);
    Ok(())
}
