//! UDF (ISO/IEC 13346 + OSTA UDF) layer of an optical-disc image.
//!
//! Most `.iso` files carrying UDF are *bridge* discs: the same bytes are
//! described twice, once by an ISO 9660 tree and once by a UDF one. Windows
//! mounts the UDF view, older tooling mounts the ISO 9660 view, and nothing
//! requires the two to agree — so the UDF tree is walked independently here
//! and its file count is reported next to the ISO 9660 one. A disagreement
//! is the fact worth having; matching counts cost one cheap walk to prove.
//!
//! Large images (over 4 GiB of payload, or with files above the ISO 9660
//! 4 GiB extent ceiling) are frequently UDF-*only*. Without this walk they
//! would report an empty file list, which reads exactly like a benign empty
//! image.
//!
//! Emitted keys:
//!
//! - `iso.udf.revision` — OSTA revision from the domain identifier suffix,
//!   as a `"2.60"`-style string.
//! - `iso.udf.logical_volume_id`, `iso.udf.volume_set_id`
//! - `iso.udf.implementation_id` — the writing implementation's EntityID,
//!   the UDF equivalent of the ISO 9660 builder stamp.
//! - `iso.udf.partition_contents` — `+NSR02`/`+NSR03` (a real filesystem)
//!   vs `+CD001` (an ISO 9660 shadow partition).
//! - `iso.udf.file_count` / `iso.udf.dir_count` — from the tree walk.

use serde_json::Value as JsonValue;

use crate::formats::common::bytes_at::{u16_le, u32_le, u64_le};
use crate::output::{ArchiveMember, ArchiveOffsets, Metrics, Values};

use super::iso::SECTOR;

/// The Anchor Volume Descriptor Pointer sits at a fixed sector; ECMA-167
/// requires at least two of these three locations to hold one.
const ANCHOR_SECTORS: [usize; 1] = [256];
/// Cap on descriptors read from the main volume descriptor sequence.
const MAX_VDS_DESCRIPTORS: usize = 64;
/// Cap on directories visited during the file-tree walk.
const MAX_DIRS: usize = 8192;
/// Cap on file identifier descriptors read across the whole tree.
const MAX_ENTRIES: usize = 65_536;
/// Cap on tree depth.
const MAX_DEPTH: u32 = 32;
/// Cap on a single directory extent read.
const MAX_DIR_EXTENT: usize = 32 << 20;

/// Descriptor tag identifiers used here (ECMA-167 §3/4).
mod tag {
    pub(super) const PRIMARY_VOLUME: u16 = 1;
    pub(super) const ANCHOR: u16 = 2;
    pub(super) const IMPL_USE_VOLUME: u16 = 4;
    pub(super) const PARTITION: u16 = 5;
    pub(super) const LOGICAL_VOLUME: u16 = 6;
    pub(super) const TERMINATING: u16 = 8;
    pub(super) const FILE_SET: u16 = 256;
    pub(super) const FILE_IDENTIFIER: u16 = 257;
    pub(super) const FILE_ENTRY: u16 = 261;
    pub(super) const EXTENDED_FILE_ENTRY: u16 = 266;
}

/// What the UDF layer found, for the ISO 9660 side to reconcile against.
pub(super) struct UdfFacts {
    /// A UDF anchor and logical volume were found.
    pub(super) present: bool,
    /// Members recovered from the UDF file tree. Used when the ISO 9660
    /// tree produced none; otherwise only counted.
    pub(super) members: Vec<ArchiveMember>,
    pub(super) file_count: u64,
}

pub(super) fn extract(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) -> UdfFacts {
    let mut facts = UdfFacts {
        present: false,
        members: Vec::new(),
        file_count: 0,
    };

    let Some(anchor) = find_anchor(bytes) else {
        return facts;
    };
    facts.present = true;

    let mvds = ExtentAd::parse(anchor.get(16..24));
    let Some(mvds) = mvds else {
        return facts;
    };

    let mut lvd: Option<LogicalVolume> = None;
    let mut partition: Option<Partition> = None;
    let mut impl_id: Option<String> = None;
    let mut volume_set_id: Option<String> = None;

    // The volume descriptor sequence is a run of whole sectors, terminated
    // by a Terminating Descriptor or by the extent's declared length.
    let count = (mvds.length as usize / SECTOR).min(MAX_VDS_DESCRIPTORS);
    for i in 0..count {
        let Some(sector) = sector_at(bytes, mvds.location as usize + i) else {
            break;
        };
        let Some(id) = u16_le(sector, 0) else { break };
        match id {
            tag::TERMINATING => break,
            tag::PRIMARY_VOLUME => {
                volume_set_id = dstring(sector.get(72..200));
            }
            tag::IMPL_USE_VOLUME => {
                // The implementation-use VD names the writing tool.
                impl_id = entity_id(sector.get(52..84));
            }
            tag::PARTITION => {
                partition = Some(Partition {
                    number: u16_le(sector, 22).unwrap_or(0),
                    contents: entity_id(sector.get(24..56)).unwrap_or_default(),
                    start: u32_le(sector, 188).unwrap_or(0),
                    length: u32_le(sector, 192).unwrap_or(0),
                });
            }
            tag::LOGICAL_VOLUME => {
                lvd = Some(LogicalVolume {
                    identifier: dstring(sector.get(84..212)).unwrap_or_default(),
                    block_size: u32_le(sector, 212).unwrap_or(SECTOR as u32),
                    domain: entity_id(sector.get(216..248)).unwrap_or_default(),
                    revision: domain_revision(sector.get(216..248)),
                    // logical_volume_contents_use is a long_ad pointing at
                    // the File Set Descriptor.
                    file_set: LongAd::parse(sector.get(248..264)),
                });
            }
            _ => {}
        }
    }

    if let Some(lv) = &lvd {
        if !lv.identifier.is_empty() {
            values.insert(
                "iso.udf.logical_volume_id",
                JsonValue::String(lv.identifier.clone()),
            );
        }
        if !lv.domain.is_empty() {
            values.insert("iso.udf.domain", JsonValue::String(lv.domain.clone()));
        }
        if let Some(rev) = &lv.revision {
            values.insert("iso.udf.revision", JsonValue::String(rev.clone()));
        }
        metrics.insert("iso.udf.logical_block_size", f64::from(lv.block_size));
    }
    if let Some(id) = impl_id {
        values.insert("iso.udf.implementation_id", JsonValue::String(id));
    }
    if let Some(id) = volume_set_id {
        values.insert("iso.udf.volume_set_id", JsonValue::String(id));
    }
    if let Some(p) = &partition {
        values.insert(
            "iso.udf.partition_contents",
            JsonValue::String(p.contents.clone()),
        );
        metrics.insert("iso.udf.partition_start_lba", f64::from(p.start));
        metrics.insert("iso.udf.partition_sectors", f64::from(p.length));
    }

    let (Some(lv), Some(part)) = (lvd, partition) else {
        return facts;
    };
    let Some(fsd_ad) = lv.file_set else {
        return facts;
    };

    let vol = Volume {
        bytes,
        partition_start: part.start,
        block_size: if lv.block_size == 0 {
            SECTOR as u32
        } else {
            lv.block_size
        },
    };

    // File Set Descriptor → root directory ICB.
    let Some(fsd) = vol.block(fsd_ad.location) else {
        return facts;
    };
    if u16_le(fsd, 0) != Some(tag::FILE_SET) {
        return facts;
    }
    if let Some(id) = dstring(fsd.get(304..336)) {
        values.insert("iso.udf.file_set_id", JsonValue::String(id));
    }
    let Some(root) = LongAd::parse(fsd.get(400..416)) else {
        return facts;
    };

    let mut walk = TreeWalk::new(&vol);
    walk.run(root.location);
    facts.file_count = walk.file_count;
    facts.members = walk.members;

    metrics.insert("iso.udf.file_count", walk.file_count as f64);
    metrics.insert("iso.udf.dir_count", walk.dir_count as f64);
    if walk.truncated {
        values.insert("iso.udf.tree_truncated", JsonValue::Bool(true));
    }
    facts
}

fn find_anchor(bytes: &[u8]) -> Option<&[u8]> {
    let last = bytes.len() / SECTOR;
    // 256 is mandatory; the tail copies are the fallback for images whose
    // head was overwritten or that were cut from a larger volume.
    let candidates = ANCHOR_SECTORS
        .into_iter()
        .chain(last.checked_sub(1))
        .chain(last.checked_sub(257));
    for sector in candidates {
        let Some(block) = sector_at(bytes, sector) else {
            continue;
        };
        if u16_le(block, 0) == Some(tag::ANCHOR) && u32_le(block, 12) == Some(sector as u32) {
            return Some(block);
        }
    }
    None
}

#[inline]
fn sector_at(bytes: &[u8], sector: usize) -> Option<&[u8]> {
    let start = sector.checked_mul(SECTOR)?;
    bytes.get(start..start.checked_add(SECTOR)?)
}

struct Partition {
    #[allow(dead_code)]
    number: u16,
    contents: String,
    start: u32,
    length: u32,
}

struct LogicalVolume {
    identifier: String,
    block_size: u32,
    domain: String,
    revision: Option<String>,
    file_set: Option<LongAd>,
}

struct ExtentAd {
    length: u32,
    location: u32,
}

impl ExtentAd {
    fn parse(raw: Option<&[u8]>) -> Option<Self> {
        let raw = raw?;
        Some(Self {
            length: u32_le(raw, 0)?,
            location: u32_le(raw, 4)?,
        })
    }
}

struct LongAd {
    location: u32,
}

impl LongAd {
    fn parse(raw: Option<&[u8]>) -> Option<Self> {
        let raw = raw?;
        let length = u32_le(raw, 0)?;
        let location = u32_le(raw, 4)?;
        // A zero-length long_ad is the "no such extent" encoding.
        (length != 0 || location != 0).then_some(Self { location })
    }
}

/// A `dstring`: fixed-width field whose last byte is the used length and
/// whose first content byte is a charset marker (8 = Latin-1, 16 = UCS-2BE).
fn dstring(raw: Option<&[u8]>) -> Option<String> {
    let raw = raw?;
    let used = *raw.last()? as usize;
    if used < 2 {
        return None;
    }
    let body = raw.get(1..used)?;
    let text = match raw.first() {
        Some(16) => {
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => body.iter().map(|b| char::from(*b)).collect(),
    };
    let text = text.trim_end_matches('\u{0}').trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// An `EntityID`: a flags byte, a 23-byte identifier, and an 8-byte suffix.
fn entity_id(raw: Option<&[u8]>) -> Option<String> {
    let raw = raw?;
    let id = raw.get(1..24)?;
    let text: String = id
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| char::from(*b))
        .collect();
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The OSTA domain identifier's suffix carries the UDF revision as BCD in
/// its first two bytes: `0x0260` is UDF 2.60.
fn domain_revision(raw: Option<&[u8]>) -> Option<String> {
    let raw = raw?;
    let rev = u16_le(raw, 24)?;
    if rev == 0 {
        return None;
    }
    Some(format!("{}.{:02x}", rev >> 8, rev & 0xff))
}

/// Partition-relative addressing. UDF allocation descriptors are logical
/// block numbers within a partition, not absolute sectors.
struct Volume<'a> {
    bytes: &'a [u8],
    partition_start: u32,
    block_size: u32,
}

impl<'a> Volume<'a> {
    fn byte_offset(&self, block: u32) -> u64 {
        (u64::from(self.partition_start) + u64::from(block)) * u64::from(self.block_size)
    }

    fn block(&self, block: u32) -> Option<&'a [u8]> {
        let start = usize::try_from(self.byte_offset(block)).ok()?;
        let len = self.block_size as usize;
        self.bytes.get(start..start.checked_add(len)?)
    }

    fn range(&self, block: u32, len: usize) -> Option<&'a [u8]> {
        let start = usize::try_from(self.byte_offset(block)).ok()?;
        let end = start.checked_add(len.min(MAX_DIR_EXTENT))?;
        self.bytes.get(start..end.min(self.bytes.len()))
    }
}

/// A parsed File Entry / Extended File Entry.
struct FileEntry {
    file_type: u8,
    info_length: u64,
    permissions: u32,
    mtime_unix: Option<i64>,
    /// First data extent, when the file's bytes are one contiguous run
    /// outside the entry itself.
    first_extent: Option<(u32, u32)>,
    /// Data stored inline in the entry (AD type 3).
    embedded: bool,
}

fn parse_file_entry(block: &[u8]) -> Option<FileEntry> {
    let tag_id = u16_le(block, 0)?;
    let extended = match tag_id {
        tag::FILE_ENTRY => false,
        tag::EXTENDED_FILE_ENTRY => true,
        _ => return None,
    };
    // ICB tag sits at +16; its flags' low three bits select the
    // allocation-descriptor form used at the end of the entry.
    let icb_flags = u16_le(block, 16 + 18)?;
    let ad_type = icb_flags & 0x07;
    let file_type = *block.get(16 + 11)?;
    let permissions = u32_le(block, 40)?;
    // Extended File Entries insert creation time plus two reserved
    // 8-byte fields ahead of the tail, shifting everything after +176.
    let (info_off, ea_off) = if extended { (56, 208) } else { (56, 168) };
    let info_length = u64_le(block, info_off)?;
    let mtime_unix = timestamp(block.get(if extended { 96 } else { 84 }..));
    let l_ea = u32_le(block, ea_off)? as usize;
    let l_ad = u32_le(block, ea_off + 4)? as usize;
    let ad_start = ea_off + 8 + l_ea;

    let mut entry = FileEntry {
        file_type,
        info_length,
        permissions,
        mtime_unix,
        first_extent: None,
        embedded: ad_type == 3,
    };
    if ad_type == 3 {
        return Some(entry);
    }
    let ads = block.get(ad_start..ad_start.checked_add(l_ad)?)?;
    entry.first_extent = match ad_type {
        // short_ad: length u32 (high 2 bits are the extent type), position u32
        0 => Some((u32_le(ads, 4)?, u32_le(ads, 0)? & 0x3FFF_FFFF)),
        // long_ad: length u32, block u32, partition u16, impl [6]
        1 => Some((u32_le(ads, 4)?, u32_le(ads, 0)? & 0x3FFF_FFFF)),
        _ => None,
    };
    Some(entry)
}

/// ECMA-167 timestamp: type/timezone u16, year i16, then byte fields.
fn timestamp(raw: Option<&[u8]>) -> Option<i64> {
    let raw = raw?;
    let b = raw.get(..12)?;
    let year = i16::from_le_bytes([b[2], b[3]]);
    if !(1900..=2999).contains(&year) {
        return None;
    }
    let days = crate::scan::days_from_civil(i32::from(year), u32::from(b[4]), u32::from(b[5]))?;
    Some(days * 86_400 + i64::from(b[6]) * 3600 + i64::from(b[7]) * 60 + i64::from(b[8]))
}

struct TreeWalk<'a, 'v> {
    vol: &'v Volume<'a>,
    members: Vec<ArchiveMember>,
    visited: Vec<u32>,
    file_count: u64,
    dir_count: u64,
    truncated: bool,
}

impl<'a, 'v> TreeWalk<'a, 'v> {
    fn new(vol: &'v Volume<'a>) -> Self {
        Self {
            vol,
            members: Vec::new(),
            visited: Vec::new(),
            file_count: 0,
            dir_count: 0,
            truncated: false,
        }
    }

    fn run(&mut self, root_icb: u32) {
        let mut queue = vec![(root_icb, String::new(), 0_u32)];
        let mut head = 0;
        while head < queue.len() {
            let (icb, prefix, depth) = queue[head].clone();
            head += 1;
            if self.visited.len() >= MAX_DIRS || self.members.len() >= MAX_ENTRIES {
                self.truncated = true;
                return;
            }
            if depth > MAX_DEPTH || self.visited.contains(&icb) {
                continue;
            }
            self.visited.push(icb);
            self.dir_count += 1;

            let Some(block) = self.vol.block(icb) else {
                continue;
            };
            let Some(entry) = parse_file_entry(block) else {
                continue;
            };
            // Directory contents live either inline in the entry (AD type 3)
            // or in the entry's first extent.
            let data = if entry.embedded {
                let l_ea = u32_le(block, 168).unwrap_or(0) as usize;
                block.get(176 + l_ea..).map(<[u8]>::to_vec)
            } else {
                entry
                    .first_extent
                    .and_then(|(len, blk)| self.vol.range(blk, len as usize).map(<[u8]>::to_vec))
            };
            let Some(data) = data else { continue };
            for (name, child_icb, is_dir) in parse_fids(&data) {
                let path = format!("{prefix}/{name}");
                if is_dir {
                    queue.push((child_icb, path, depth + 1));
                    continue;
                }
                self.emit_file(&path, child_icb);
                if self.members.len() >= MAX_ENTRIES {
                    self.truncated = true;
                    return;
                }
            }
        }
    }

    fn emit_file(&mut self, path: &str, icb: u32) {
        let Some(block) = self.vol.block(icb) else {
            return;
        };
        let Some(entry) = parse_file_entry(block) else {
            return;
        };
        self.file_count += 1;
        let offset = entry
            .first_extent
            .filter(|_| !entry.embedded)
            .map(|(_, blk)| self.vol.byte_offset(blk));
        self.members.push(ArchiveMember {
            path: path.trim_start_matches('/').to_string(),
            size_bytes: entry.info_length,
            entry_type: Some(
                match entry.file_type {
                    4 => "directory",
                    12 => "symlink",
                    _ => "regular",
                }
                .into(),
            ),
            mtime_unix: entry.mtime_unix,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership: Some(crate::output::ArchiveOwnership {
                mode_octal: Some(udf_permissions_to_mode(entry.permissions)),
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            }),
            offsets: ArchiveOffsets {
                header: None,
                data: offset.filter(|_| entry.info_length > 0),
                central_header: None,
            },
        });
    }
}

/// UDF stores permissions in 5-bit groups (delete/attrib/execute/write/read)
/// for other/group/owner. Fold them into the POSIX bits a consumer expects.
fn udf_permissions_to_mode(perms: u32) -> u32 {
    let map = |bits: u32| {
        u32::from(bits & 0x04 != 0) << 2
            | u32::from(bits & 0x02 != 0) << 1
            | u32::from(bits & 0x01 != 0)
    };
    // other = bits 0..4, group = 5..9, owner = 10..14
    (map((perms >> 10) & 0x1F) << 6) | (map((perms >> 5) & 0x1F) << 3) | map(perms & 0x1F)
}

/// Parse a directory's File Identifier Descriptors.
fn parse_fids(data: &[u8]) -> Vec<(String, u32, bool)> {
    let mut out = Vec::new();
    let mut pos = 0_usize;
    while pos + 38 <= data.len() && out.len() < MAX_ENTRIES {
        let Some(rec) = data.get(pos..) else { break };
        if u16_le(rec, 0) != Some(tag::FILE_IDENTIFIER) {
            break;
        }
        let characteristics = rec.get(18).copied().unwrap_or(0);
        let l_fi = rec.get(19).copied().unwrap_or(0) as usize;
        let icb_block = u32_le(rec, 20).unwrap_or(0);
        let l_iu = u16_le(rec, 36).unwrap_or(0) as usize;
        let name_off = 38 + l_iu;
        let total = name_off + l_fi;
        // Records are padded to a 4-byte boundary.
        let padded = total.div_ceil(4) * 4;
        if padded == 0 || pos.checked_add(padded).is_none() {
            break;
        }
        // Bit 3 marks the parent ("..") entry, which has no name.
        if characteristics & 0x08 == 0 && l_fi > 0 {
            if let Some(raw) = rec.get(name_off..total) {
                let name = decode_d_characters(raw);
                // Bit 2 = deleted, bit 0 = hidden. Deleted entries still
                // point at live bytes; keep them, they are evidence.
                if !name.is_empty() {
                    out.push((name, icb_block, characteristics & 0x02 != 0));
                }
            }
        }
        pos += padded;
    }
    out
}

/// A UDF file identifier: first byte is the compression id (8 = Latin-1,
/// 16 = UCS-2BE), the rest is the name.
fn decode_d_characters(raw: &[u8]) -> String {
    match raw.first() {
        Some(16) => {
            let units: Vec<u16> = raw
                .get(1..)
                .unwrap_or_default()
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        Some(8) => raw
            .get(1..)
            .unwrap_or_default()
            .iter()
            .map(|b| char::from(*b))
            .collect(),
        _ => String::new(),
    }
    .replace(['/', '\u{0}'], "_")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn dstring_decodes_both_charsets() {
        // Latin-1: marker 8, "AB", used length 3.
        let mut latin = vec![0_u8; 8];
        latin[0] = 8;
        latin[1] = b'A';
        latin[2] = b'B';
        latin[7] = 3;
        assert_eq!(dstring(Some(&latin)).as_deref(), Some("AB"));

        // UCS-2BE: marker 16, "AB", used length 5.
        let mut ucs = vec![0_u8; 8];
        ucs[0] = 16;
        ucs[1..5].copy_from_slice(&[0, b'A', 0, b'B']);
        ucs[7] = 5;
        assert_eq!(dstring(Some(&ucs)).as_deref(), Some("AB"));
    }

    #[test]
    fn revision_reads_as_bcd() {
        let mut ent = vec![0_u8; 32];
        ent[24] = 0x60;
        ent[25] = 0x02;
        assert_eq!(domain_revision(Some(&ent)).as_deref(), Some("2.60"));
        assert_eq!(domain_revision(Some(&[0_u8; 32])), None);
    }

    #[test]
    fn permissions_fold_to_posix() {
        // owner rwx, group r-x, other r--
        let perms = (0b00111 << 10) | (0b00101 << 5) | 0b00100;
        assert_eq!(udf_permissions_to_mode(perms), 0o754);
    }

    #[test]
    fn file_identifiers_reject_a_non_fid_run() {
        assert!(parse_fids(&[0_u8; 64]).is_empty());
    }
}
