//! Bounded ASCII CPIO indexing. No files, links, or devices are created.
//! Layout reference: libarchive's cpio(5), portable/new ASCII sections.
//! The checksum variant is indexed, not authenticated; its additive checksum
//! is deliberately not exposed as a CRC-32. Binary and RPM stripped formats
//! require different metadata and are not interpreted as ASCII CPIO.

use crate::error::Error;
use crate::output::{ArchiveMember, ArchiveOffsets, ArchiveOwnership, Values};

const MAX_ENTRIES: usize = 65_536;
const MAX_NAME_BYTES: usize = 1024 * 1024;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

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

fn aligned(offset: usize, alignment: usize) -> Result<usize, Error> {
    offset
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or_else(|| invalid("alignment overflow"))
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    values.insert("cpio.complete", serde_json::json!(false));
    let result = index(bytes, values, members, MAX_ENTRIES, MAX_METADATA_BYTES);
    if result.is_ok() {
        values.insert("cpio.complete", serde_json::json!(true));
    }
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
                let h = extent(bytes, offset, 76)?;
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
                let h = extent(bytes, offset, 110)?;
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
            values.insert("cpio.variant", serde_json::json!(header.variant));
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
        if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
            return Err(invalid("invalid NUL-terminated pathname"));
        }
        let data_offset = aligned(name_offset + name_size, header.alignment)?;
        let size = usize::try_from(header.file_size).map_err(|_| invalid("file size overflow"))?;
        let payload = extent(bytes, data_offset, size)?;
        let next = aligned(data_offset + size, header.alignment)?;
        if &name[..name.len() - 1] == b"TRAILER!!!" {
            if size != 0 {
                return Err(invalid("trailer claims file data"));
            }
            if bytes[next..].iter().any(|b| *b != 0) {
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
            path: String::from_utf8_lossy(&name[..name.len() - 1]).into_owned(),
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
mod tests {
    use super::*;

    fn entry(out: &mut Vec<u8>, magic: &str, name: &str, body: &[u8], mode: u32) {
        if magic == "070707" {
            out.extend_from_slice(
                format!(
                    "070707{:06o}{:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                    0,
                    1,
                    2,
                    3,
                    1,
                    0,
                    4,
                    name.len() + 1,
                    body.len()
                )
                .as_bytes(),
            );
        } else {
            out.extend_from_slice(magic.as_bytes());
            for value in [
                1,
                mode,
                2,
                3,
                1,
                4,
                body.len() as u32,
                0,
                0,
                0,
                0,
                name.len() as u32 + 1,
                0,
            ] {
                out.extend_from_slice(format!("{value:08x}").as_bytes());
            }
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        if magic != "070707" {
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }
        out.extend_from_slice(body);
        if magic != "070707" {
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }
    }

    fn fixture(magic: &str) -> Vec<u8> {
        let mut data = Vec::new();
        entry(&mut data, magic, "./padding", b"x", 0o100644);
        entry(
            &mut data,
            magic,
            "./postinstall",
            b"#!/bin/sh\necho ready\n",
            0o100755,
        );
        entry(&mut data, magic, "TRAILER!!!", b"", 0);
        data
    }

    #[test]
    fn ascii_variants_index_exact_extents_and_identity() {
        for magic in ["070707", "070701", "070702"] {
            let bytes = fixture(magic);
            let parsed =
                crate::FileId::from_path_and_bytes(std::path::Path::new("Scripts"), &bytes);
            assert_eq!(parsed.file_type(), crate::FileType::Cpio);
            assert!(parsed.file_type().is_archive());
            assert_eq!(
                parsed.file_type().archive_format(),
                Some(crate::ArchiveFormat::Cpio)
            );
            let mut values = Values::new();
            let mut members = Vec::new();
            extract(&bytes, &mut values, &mut members).unwrap();
            assert_eq!(members.len(), 2);
            assert_eq!(members[1].path, "./postinstall");
            assert_eq!(
                members[1].ownership.as_ref().unwrap().mode_octal,
                Some(0o100755)
            );
            let start = members[1].offsets.data.unwrap() as usize;
            assert_eq!(
                &bytes[start..start + members[1].size_bytes as usize],
                b"#!/bin/sh\necho ready\n"
            );
        }
    }

    #[test]
    fn digit_runs_that_are_not_cpio_headers_keep_their_own_identity() {
        // The six-digit magic is six ordinary characters, so content detection
        // must see a complete, well-formed first header before claiming CPIO.
        for text in [
            b"070701,cost,units\n070702,12,3\n".as_slice(),
            b"070707 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            b"070707",
        ] {
            let parsed =
                crate::FileId::from_path_and_bytes(std::path::Path::new("report.csv"), text);
            assert_ne!(parsed.file_type(), crate::FileType::Cpio, "{text:?}");
        }
        // A header whose fields are outside its radix is not claimed either.
        let mut bytes = fixture("070701");
        bytes[109] = b'g';
        assert_ne!(
            crate::FileId::from_path_and_bytes(std::path::Path::new("x"), &bytes).file_type(),
            crate::FileType::Cpio
        );
    }

    #[test]
    fn every_truncated_prefix_reports_incomplete() {
        for magic in ["070707", "070701", "070702"] {
            let bytes = fixture(magic);
            for end in 0..bytes.len() {
                assert!(
                    extract(&bytes[..end], &mut Values::new(), &mut Vec::new()).is_err(),
                    "{magic}, {end}"
                );
            }
        }
    }

    #[test]
    fn bounded_metadata_and_partial_results() {
        let bytes = fixture("070707");
        let mut members = Vec::new();
        assert!(
            index(
                &bytes,
                &mut Values::new(),
                &mut members,
                1,
                MAX_METADATA_BYTES
            )
            .is_err()
        );
        assert_eq!(members.len(), 1);
        assert!(index(&bytes, &mut Values::new(), &mut Vec::new(), MAX_ENTRIES, 80).is_err());
        let mut bytes = fixture("070701");
        bytes[94..102].copy_from_slice(b"ffffffff");
        assert!(extract(&bytes, &mut Values::new(), &mut Vec::new()).is_err());

        let mut bytes = Vec::new();
        entry(&mut bytes, "070707", "link", &[b'x'; 4096], 0o120777);
        entry(&mut bytes, "070707", "TRAILER!!!", b"", 0);
        let mut members = Vec::new();
        assert!(index(&bytes, &mut Values::new(), &mut members, MAX_ENTRIES, 500).is_err());
        assert!(
            members.is_empty(),
            "link allocation must obey metadata budget"
        );
    }

    #[test]
    fn public_api_retains_partial_members_and_completion_state() {
        let mut bytes = fixture("070707");
        let parsed = crate::open(&bytes).unwrap();
        assert_eq!(
            parsed.values().get("cpio.complete"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(parsed.archive_members().len(), 2);
        assert!(parsed.errors().is_empty());
        bytes.pop();
        let parsed = crate::open(&bytes).unwrap();
        assert_eq!(
            parsed.values().get("cpio.complete"),
            Some(&serde_json::json!(false))
        );
        assert_eq!(parsed.archive_members().len(), 2);
        assert!(!parsed.errors().is_empty());
        assert_eq!(
            crate::FileType::from_label("cpio"),
            Some(crate::FileType::Cpio)
        );
    }

    #[test]
    fn missing_body_padding_does_not_hide_the_complete_member() {
        let mut bytes = Vec::new();
        entry(&mut bytes, "070701", "postinstall", b"x", 0o100755);
        // Newc's one-byte body has three alignment bytes after it.
        bytes.truncate(bytes.len() - 3);
        let parsed = crate::open(&bytes).unwrap();
        assert_eq!(parsed.archive_members().len(), 1);
        let member = &parsed.archive_members()[0];
        assert_eq!(member.path, "postinstall");
        assert_eq!(bytes[member.offsets.data.unwrap() as usize], b'x');
        assert_eq!(
            parsed.values().get("cpio.complete"),
            Some(&serde_json::json!(false))
        );
        assert!(!parsed.errors().is_empty());
    }

    #[test]
    fn path_and_link_metadata_remain_unmodified() {
        let mut bytes = Vec::new();
        for name in ["../outside", "/absolute", "same", "same"] {
            entry(&mut bytes, "070707", name, b"../target", 0o120777);
        }
        entry(&mut bytes, "070707", "TRAILER!!!", b"", 0);
        let mut members = Vec::new();
        extract(&bytes, &mut Values::new(), &mut members).unwrap();
        assert_eq!(
            members.iter().map(|m| m.path.as_str()).collect::<Vec<_>>(),
            ["../outside", "/absolute", "same", "same"]
        );
        assert!(
            members
                .iter()
                .all(|m| m.linkname.as_deref() == Some("../target"))
        );
    }

    #[test]
    fn invalid_fields_names_and_trailers_are_errors() {
        let mut bytes = fixture("070707");
        bytes[18] = b'8';
        assert!(extract(&bytes, &mut Values::new(), &mut Vec::new()).is_err());
        let mut bytes = fixture("070707");
        bytes[76] = 0;
        assert!(extract(&bytes, &mut Values::new(), &mut Vec::new()).is_err());
        let mut bytes = Vec::new();
        entry(&mut bytes, "070701", "TRAILER!!!", b"x", 0);
        assert!(extract(&bytes, &mut Values::new(), &mut Vec::new()).is_err());
        let mut bytes = fixture("070707");
        bytes.extend_from_slice(b"extra");
        assert!(extract(&bytes, &mut Values::new(), &mut Vec::new()).is_err());
    }
}
