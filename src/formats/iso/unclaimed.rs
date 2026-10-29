//! Unclaimed space: the byte ranges of an image that neither the volume's
//! own structures nor a hybrid partition table account for.

use serde_json::{Value as JsonValue, json};

use super::{File, Pvd, SECTOR, SYSTEM_AREA_SECTORS};
use crate::formats::common::bytes_at::u32_le;
use crate::metric;
use crate::output::{ArchiveMember, EntryType, Metrics, Values};
use crate::value_key;

/// Cap on unclaimed regions reported. A fragmented image must not turn into
/// thousands of pseudo-members.
const MAX_UNCLAIMED_REGIONS: usize = 8;
/// Smallest unclaimed run worth reporting. Below a couple of sectors a gap
/// is ordinary alignment padding.
const MIN_UNCLAIMED_BYTES: u64 = 4096;

/// The byte ranges an MBR/GPT partition table in the system area claims.
///
/// A hybrid image (`xorriso -isohybrid-mbr`, and every Linux/BSD installer
/// built that way) carries a partition table in LBA 0 alongside the ISO 9660
/// descriptors. Its content lives in a partition, so the ISO volume can be a
/// few sectors while the file is gigabytes, with one 0xEE (GPT protective)
/// entry spanning the whole image.
///
/// Those bytes are accounted for — by the partition table — so they are not
/// "unclaimed". Without this, the entire filesystem is reported as one
/// `trailing` member and every data-file rule runs across a whole operating
/// system as an opaque blob.
///
/// Only entries that actually describe a range count. Bytes past the last
/// partition are still unaccounted for and are still reported, so a payload
/// appended after the partitioned area does not hide behind this.
pub(super) fn partition_claimed_ranges(bytes: &[u8]) -> Vec<(u64, u64)> {
    let area = bytes
        .get(..SYSTEM_AREA_SECTORS * SECTOR)
        .unwrap_or_default();
    if area.get(510..512) != Some(&[0x55, 0xAA]) {
        return Vec::new();
    }
    // LBA size is fixed at 512 for the MBR entry format regardless of the
    // ISO's own 2048-byte sectors.
    const LBA: u64 = 512;
    let total = bytes.len() as u64;
    let mut out = Vec::new();
    for i in 0..4 {
        let off = 446 + i * 16;
        let Some(e) = area.get(off..off + 16) else {
            break;
        };
        let ptype = e.get(4).copied().unwrap_or(0);
        let start = u64::from(u32_le(e, 8).unwrap_or(0));
        let count = u64::from(u32_le(e, 12).unwrap_or(0));
        if ptype == 0 || count == 0 {
            continue;
        }
        let begin = start.saturating_mul(LBA).min(total);
        let end = start.saturating_add(count).saturating_mul(LBA).min(total);
        if end > begin {
            out.push((begin, end));
        }
    }
    out
}

/// Byte ranges inside the image that nothing accounts for.
///
/// A walk of the directory tree only ever reads what the tree points at.
/// The descriptors, the path tables, and every directory and file extent
/// together cover the parts of an image that *mean* something; whatever is
/// left is addressable storage that a mounted image ignores. That is where
/// a payload goes when the goal is for a file listing to look clean, so the
/// regions are surfaced as members in their own right and analysed like any
/// other content.
///
/// All-zero runs are excluded: an image is padded to a sector, and empty
/// padding is not evidence of anything.
pub(super) fn unclaimed_regions(
    files: &[File],
    pvd: &Pvd,
    bytes: &[u8],
    mut claimed: Vec<(u64, u64)>,
) -> Vec<(EntryType, u64, u64)> {
    let sector = SECTOR as u64;
    let round_up = |n: u64| n.div_ceil(sector).saturating_mul(sector);
    claimed.reserve(files.len());
    for f in files {
        // Directories are metadata, and their extents are as much a claim on
        // the image as a file's bytes are.
        let len = round_up(u64::from(f.size));
        claimed.push((f.offset, f.offset.saturating_add(len.max(sector))));
    }
    claimed.sort_unstable();

    let declared = u64::from(pvd.volume_space_sectors).saturating_mul(sector);
    let mut out = Vec::new();
    let mut cursor = 0_u64;
    for (start, end) in claimed {
        if start > cursor && start - cursor >= MIN_UNCLAIMED_BYTES {
            out.push((EntryType::Slack, cursor, start - cursor));
        }
        cursor = cursor.max(end);
    }
    if declared > cursor && declared - cursor >= MIN_UNCLAIMED_BYTES {
        out.push((EntryType::Slack, cursor, declared - cursor));
    }
    // Bytes past the volume the descriptors declare. On a plain image no
    // mastering tool writes here and an appended payload does, so any
    // trailing byte is unaccounted for. On a hybrid image the partition
    // table claims them, and only what lies past the last partition is
    // genuinely unaccounted.
    let actual = bytes.len() as u64;
    if actual > declared {
        let partition_end = partition_claimed_ranges(bytes)
            .into_iter()
            .map(|(_, end)| end)
            .max()
            .unwrap_or(0);
        let trailing_from = declared.max(partition_end);
        if actual > trailing_from {
            out.push((EntryType::Trailing, trailing_from, actual - trailing_from));
        }
    }

    out.retain(|(kind, off, len)| {
        // Trailing data is reported even when zeroed: nothing should be
        // there at all. Interior padding is normally zeroed and says
        // nothing, so only a populated run counts.
        *kind == EntryType::Trailing
            || usize::try_from(*off)
                .ok()
                .zip(usize::try_from(*len).ok())
                .and_then(|(s, l)| bytes.get(s..s.saturating_add(l)))
                .is_some_and(|region| region.iter().any(|b| *b != 0))
    });
    out.sort_by_key(|(_, _, len)| std::cmp::Reverse(*len));
    out.truncate(MAX_UNCLAIMED_REGIONS);
    out
}

pub(super) fn emit_unclaimed(
    regions: &[(EntryType, u64, u64)],
    declared: u64,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    anomalies: &mut Vec<&'static str>,
) {
    let total: u64 = regions
        .iter()
        .filter(|(kind, _, _)| *kind == EntryType::Slack)
        .map(|(_, _, len)| *len)
        .sum();
    metrics.insert(metric!("iso.unallocated_bytes"), total as f64);
    metrics.insert(metric!("iso.unclaimed_region_count"), regions.len() as f64);
    if declared > 0 {
        metrics.insert(
            metric!("iso.unallocated_ratio"),
            total as f64 / declared as f64,
        );
    }
    if total > 0 {
        anomalies.push("populated-unallocated-space");
    }

    let mut list = Vec::with_capacity(regions.len());
    for (kind, offset, len) in regions {
        list.push(json!({ "kind": kind.as_str(), "offset": offset, "size_bytes": len }));
        let path = match kind {
            EntryType::Trailing => ".iso-unclaimed/trailing.bin".to_string(),
            _ => format!(".iso-unclaimed/slack-{offset:#x}.bin"),
        };
        // A distinct entry type, not `regular`: these are byte ranges the
        // filesystem does not name, and a consumer must be able to tell
        // them apart from files the image actually declares.
        let mut member = ArchiveMember::new(path, *len, *kind);
        member.offsets.data = Some(*offset);
        archive_members.push(member);
    }
    if !list.is_empty() {
        values.insert_key(value_key!("iso.unclaimed"), JsonValue::Array(list));
    }
}
