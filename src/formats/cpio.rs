//! Bounded ASCII CPIO indexing. No files, links, or devices are created.
//! Layout reference: libarchive's cpio(5), portable/new ASCII sections.
//! The checksum variant is indexed, not authenticated; its additive checksum
//! is deliberately not exposed as a CRC-32. Binary and RPM stripped formats
//! require different metadata and are not interpreted as ASCII CPIO.

use serde_json::Value as JsonValue;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use crate::error::Error;
use crate::output::{ArchiveMember, ArchiveOffsets, ArchiveOwnership, Metrics, Values};
use crate::value_key;

const MAX_ENTRIES: usize = 65_536;
const MAX_NAME_BYTES: usize = 1024 * 1024;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// The shared aggregates a CPIO reports. Like tar, only regular entries are
/// files and only their sizes are summed.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::DirectoryCount,
    Agg::UncompressedSize(Scope::Files),
    Agg::EntryTypes,
    Agg::ModeBits,
    Agg::SymlinkCount,
    Agg::SymlinkEscapes,
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
    Agg::MtimeRange,
];

fn invalid(message: &str) -> Error {
    Error::malformed("cpio", message)
}

fn number(field: &[u8], radix: u32) -> Result<u64, Error> {
    if !field.iter().all(|b| match radix {
        8 => matches!(b, b'0'..=b'7'),
        _ => b.is_ascii_hexdigit(),
    }) {
        return Err(invalid("invalid numeric field"));
    }
    let text = std::str::from_utf8(field).map_err(|_| invalid("non-ASCII numeric field"))?;
    u64::from_str_radix(text, radix).map_err(|_| invalid("numeric field overflow"))
}

fn extent(bytes: &[u8], start: usize, len: usize) -> Result<&[u8], Error> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| invalid("extent overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| invalid("truncated entry"))
}

/// A fixed-size header at `start`, typed so its fields are read by constant
/// offsets.
fn header_at<const N: usize>(bytes: &[u8], start: usize) -> Result<&[u8; N], Error> {
    extent(bytes, start, N)?
        .first_chunk::<N>()
        .ok_or_else(|| invalid("truncated entry"))
}

fn aligned(offset: usize, alignment: usize) -> Result<usize, Error> {
    offset
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or_else(|| invalid("alignment overflow"))
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    values.insert_key(value_key!("cpio.complete"), serde_json::json!(false));
    let first = members.len();
    let result = index(bytes, values, members, MAX_ENTRIES, MAX_METADATA_BYTES);
    if result.is_ok() {
        values.insert_key(value_key!("cpio.complete"), serde_json::json!(true));
    }
    // An incomplete stream keeps the members indexed before the fault, so
    // the aggregates cover those too.
    let indexed = members.get(first..).unwrap_or_default();
    let mut stats = ArchiveStats::new(AGGS);
    for member in indexed {
        let mut reading = Reading::of(member);
        reading.file = member.entry_type.as_deref() == Some("regular");
        reading.exec_mode = member
            .ownership
            .as_ref()
            .and_then(|o| o.mode_octal)
            .is_some_and(|mode| mode & 0o111 != 0);
        stats.observe(member, &reading);
    }
    let list = indexed
        .iter()
        .map(|m| JsonValue::Object(member_value(m, Shape::FULL)))
        .collect();
    values.insert_key(value_key!("archive.members"), JsonValue::Array(list));
    stats.emit(values, metrics);
    result
}

/// One decoded fixed-size ASCII header. Named fields keep the two variant
/// layouts from being matched up positionally: `newc` reads its name and file
/// sizes out of order, from fields 11 and 6.
struct Header {
    size: usize,
    alignment: usize,
    mode: u64,
    uid: u64,
    gid: u64,
    mtime: u64,
    name_size: u64,
    file_size: u64,
    variant: &'static str,
}

fn index(
    bytes: &[u8],
    values: &mut Values,
    members: &mut Vec<ArchiveMember>,
    max_entries: usize,
    max_metadata: usize,
) -> Result<(), Error> {
    let mut offset = 0usize;
    let mut metadata_bytes = 0usize;
    loop {
        let magic = extent(bytes, offset, 6)?;
        let header = match magic {
            b"070707" => {
                let h = header_at::<76>(bytes, offset)?;
                // Validate even numeric fields not projected into ArchiveMember.
                for field in h[6..48].as_chunks::<6>().0 {
                    number(field, 8)?;
                }
                Header {
                    size: 76,
                    alignment: 1,
                    mode: number(&h[18..24], 8)?,
                    uid: number(&h[24..30], 8)?,
                    gid: number(&h[30..36], 8)?,
                    mtime: number(&h[48..59], 8)?,
                    name_size: number(&h[59..65], 8)?,
                    file_size: number(&h[65..76], 8)?,
                    variant: "odc",
                }
            }
            b"070701" | b"070702" => {
                let h = header_at::<110>(bytes, offset)?;
                let mut fields = [0u64; 13];
                for (value, field) in fields.iter_mut().zip(h[6..].as_chunks::<8>().0) {
                    *value = number(field, 16)?;
                }
                Header {
                    size: 110,
                    alignment: 4,
                    mode: fields[1],
                    uid: fields[2],
                    gid: fields[3],
                    mtime: fields[5],
                    name_size: fields[11],
                    file_size: fields[6],
                    variant: if magic == b"070702" { "crc" } else { "newc" },
                }
            }
            _ => return Err(invalid("unsupported or invalid CPIO header")),
        };
        if offset == 0 {
            values.insert_key(
                value_key!("cpio.variant"),
                serde_json::json!(header.variant),
            );
        }
        let name_size =
            usize::try_from(header.name_size).map_err(|_| invalid("name size overflow"))?;
        if name_size == 0 || name_size > MAX_NAME_BYTES {
            return Err(invalid("name size exceeds limit"));
        }
        metadata_bytes = metadata_bytes
            .checked_add(header.size + name_size)
            .ok_or_else(|| invalid("metadata size overflow"))?;
        if metadata_bytes > max_metadata {
            return Err(invalid("metadata budget exceeded"));
        }
        let name_offset = offset
            .checked_add(header.size)
            .ok_or_else(|| invalid("header overflow"))?;
        let name = extent(bytes, name_offset, name_size)?;
        let Some((&0, name)) = name.split_last() else {
            return Err(invalid("invalid NUL-terminated pathname"));
        };
        if name.contains(&0) {
            return Err(invalid("invalid NUL-terminated pathname"));
        }
        let data_offset = aligned(name_offset + name_size, header.alignment)?;
        let size = usize::try_from(header.file_size).map_err(|_| invalid("file size overflow"))?;
        let payload = extent(bytes, data_offset, size)?;
        let next = aligned(data_offset + size, header.alignment)?;
        if name == b"TRAILER!!!" {
            if size != 0 {
                return Err(invalid("trailer claims file data"));
            }
            // `next` is the already-aligned `data_offset`, inside the input.
            if bytes
                .get(next..)
                .is_some_and(|rest| rest.iter().any(|b| *b != 0))
            {
                return Err(invalid("non-padding bytes follow CPIO trailer"));
            }
            return Ok(());
        }
        if members.len() >= max_entries {
            return Err(invalid("member count exceeds limit"));
        }
        let kind = match header.mode & 0o170000 {
            0o100000 => "regular",
            0o040000 => "directory",
            0o120000 => "symlink",
            0o020000 => "character",
            0o060000 => "block",
            0o010000 => "fifo",
            0o140000 => "socket",
            _ => "unknown",
        };
        // Small link bodies are metadata; large ones stay bounded byte extents.
        let linkname = if kind == "symlink" && size <= 4096 {
            metadata_bytes += size;
            if metadata_bytes > max_metadata {
                return Err(invalid("metadata budget exceeded by link targets"));
            }
            Some(String::from_utf8_lossy(payload).into_owned())
        } else {
            None
        };
        members.push(ArchiveMember {
            path: String::from_utf8_lossy(name).into_owned(),
            size_bytes: header.file_size,
            entry_type: Some(kind.into()),
            mtime_unix: i64::try_from(header.mtime).ok(),
            linkname,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership: Some(ArchiveOwnership {
                mode_octal: u32::try_from(header.mode).ok(),
                uid: Some(header.uid),
                gid: Some(header.gid),
                uname: None,
                gname: None,
            }),
            offsets: ArchiveOffsets {
                header: Some(offset as u64),
                data: Some(data_offset as u64),
                central_header: None,
            },
        });
        // A missing alignment byte must not hide a fully present file body.
        // Retain its valid extent before reporting the incomplete stream.
        extent(bytes, data_offset + size, next - data_offset - size)?;
        offset = next;
    }
}

#[cfg(test)]
mod tests;
