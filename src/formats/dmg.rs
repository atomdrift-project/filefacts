//! Apple Disk Image (`.dmg` / UDIF) container extractor.
//!
//! A UDIF image is a compressed *disk image*: a `koly` trailer (the last 512
//! bytes) points at an XML property list whose `resource-fork → blkx` array
//! describes each partition as a run-length table of compressed "chunks"
//! (the `mish` block table). The chunks decompress to the raw bytes of a
//! whole-disk image — a GPT (or Apple Partition Map) wrapping an HFS+ or
//! APFS filesystem.
//!
//! Like the other container extractors, this one describes what's *in* the
//! image without unpacking the filesystem. Two layers, both cheap:
//!
//! - **Container facts (no decompression):** UDIF version/variant, the
//!   partition table, the per-codec chunk histogram (a builder-tool
//!   fingerprint — UDZO/UDBZ/ULFO/ULMO), the compressed↔uncompressed ratio,
//!   and the inner filesystem type read straight from the partition names.
//! - **Volume facts (zlib only):** for `zlib`/`raw` images we decompress just
//!   the leading bytes of the filesystem partition and read the volume
//!   superblock — HFS+ create/modify dates + file/folder counts, or the APFS
//!   volume name, `newfs_apfs` formatter version, file/dir counts, and modify
//!   time. `bzip2`/`LZFSE`/`LZMA` images get container facts only; the full
//!   reconstruction is cleave's job (it shells the HFS+ walk to `7z` and
//!   reconstructs APFS via dmgwiz + a filesystem reader).
//!
//! Emitted keys (selected):
//!
//! - `dmg.format`, `dmg.udif_version`, `dmg.udif_format`, `dmg.image_variant`
//! - `dmg.filesystem` — `HFS+` / `HFSX` / `APFS`, from the partition name.
//! - `dmg.partitions[]` — per-partition name, size, dominant codec.
//! - `dmg.compression.codecs[]` + `dmg.compression.codec_counts.*` metrics.
//! - `dmg.volume.name`, `dmg.volume.created_unix`, `dmg.volume.modified_unix`,
//!   `dmg.volume.formatted_by`, and `dmg.volume.{file,folder,symlink}_count`.

use crate::metric;
use std::io::Read;

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use crate::bytes::{u32_be, u64_be, u64_le};
use crate::error::Error;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};
use crate::value_key;

/// The shared aggregates over a disk image's partitions. A partition name
/// (`disk image (Apple_HFS : 4)`) is a label, not a file name, so none of the
/// name-based counts apply.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::UncompressedSize(Scope::All),
    Agg::CompressedSize,
    Agg::CompressionRatio,
    Agg::Methods { always: true },
    Agg::EntryTypes,
];

/// The `koly` trailer is a fixed 512 bytes at the end of the file.
const KOLY_LEN: usize = 512;
/// Sectors are 512 bytes throughout the UDIF/partition/filesystem layers.
const SECTOR: u64 = 512;
/// Cap on the XML property list we hand to the plist parser. Real resource
/// forks are KBs–low MBs even for thousand-chunk images; this bounds a
/// hostile `xml_length`.
const MAX_XML: usize = 16 << 20;
/// Cap on partitions retained from the `blkx` array.
const MAX_PARTITIONS: usize = 4096;
/// Cap on the bytes we decompress from a partition to read its volume
/// superblock. The HFS+ header sits at +1024; an APFS volume superblock is
/// reachable within the first couple of MiB.
const MAX_VOL_PREFIX: usize = 4 << 20;
/// Seconds between the HFS+ epoch (1904-01-01) and the Unix epoch.
const MAC_EPOCH_OFFSET: i64 = 2_082_844_800;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let koly = Koly::parse(bytes).ok_or_else(|| Error::malformed("dmg", "missing koly trailer"))?;

    values.insert_key(value_key!("dmg.format"), JsonValue::String("UDIF".into()));
    values.insert_key(
        value_key!("dmg.udif_version"),
        JsonValue::Number(koly.version.into()),
    );
    values.insert_key(
        value_key!("dmg.image_variant"),
        JsonValue::Number(koly.image_variant.into()),
    );
    metrics.insert(metric!("dmg.sector_count"), koly.sector_count as f64);
    let uncompressed = koly.sector_count.saturating_mul(SECTOR);
    metrics.insert(metric!("dmg.uncompressed_size"), uncompressed as f64);
    metrics.insert(metric!("dmg.data_fork_bytes"), koly.data_fork_length as f64);
    if koly.data_fork_length > 0 {
        // >1 means the image expands on mount; the small hash-named samples in
        // the wild run 8–80×, a sparse-volume / hidden-payload signal.
        metrics.insert(
            metric!("dmg.compression.ratio"),
            uncompressed as f64 / koly.data_fork_length as f64,
        );
    }

    let partitions = parse_blkx(bytes, &koly);

    // Inner filesystem type, read straight from the partition names
    // (`disk image (Apple_HFS : 4)`) — no decompression required, so it
    // works for every codec including LZFSE.
    if let Some(fs) = partitions.iter().find_map(|p| fs_from_name(&p.name)) {
        values.insert_key(value_key!("dmg.filesystem"), JsonValue::String(fs.into()));
    }

    emit_partitions(&partitions, values, metrics, archive_members);

    // Volume superblock facts — best-effort, zlib/raw images only.
    volume_facts(bytes, &koly, &partitions, values, metrics);

    Ok(())
}

/// The fields of the `koly` (UDIFResourceFile) trailer we use.
struct Koly {
    version: u32,
    data_fork_offset: u64,
    data_fork_length: u64,
    xml_offset: u64,
    xml_length: u64,
    image_variant: u32,
    sector_count: u64,
}

impl Koly {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let t = bytes.get(bytes.len().checked_sub(KOLY_LEN)?..)?;
        if !t.starts_with(b"koly") {
            return None;
        }
        Some(Self {
            version: u32_be(t, 4)?,
            data_fork_offset: u64_be(t, 24)?,
            data_fork_length: u64_be(t, 32)?,
            xml_offset: u64_be(t, 216)?,
            xml_length: u64_be(t, 224)?,
            image_variant: u32_be(t, 488)?,
            sector_count: u64_be(t, 492)?,
        })
    }
}

/// One partition's run-length table, recovered from a `blkx` entry.
struct Partition {
    name: String,
    /// Output sectors this partition spans.
    sector_count: u64,
    /// Base offset of the partition's chunk data within the data fork.
    data_offset: u64,
    chunks: Vec<Chunk>,
}

/// One `BLKXChunkEntry`: a run of output sectors and the bytes they
/// decompress from. `sector_number` is relative to the partition start,
/// so it doubles as the partition-relative output offset.
struct Chunk {
    entry_type: u32,
    sector_number: u64,
    /// Output sectors this chunk decodes to.
    sector_count: u64,
    comp_offset: u64,
    comp_length: u64,
}

/// Parse the resource-fork plist and decode each `blkx` member's `mish`
/// block table. Returns the partitions in plist order; malformed entries
/// are skipped rather than failing the whole image.
fn parse_blkx(bytes: &[u8], koly: &Koly) -> Vec<Partition> {
    // Compare in u64 before narrowing: on a 32-bit target `as usize` would
    // wrap a hostile 64-bit offset into a valid one.
    let Ok(start) = usize::try_from(koly.xml_offset) else {
        return Vec::new();
    };
    let len = usize::try_from(koly.xml_length.min(MAX_XML as u64)).unwrap_or(MAX_XML);
    let Some(xml) = bytes.get(start..start.saturating_add(len)) else {
        return Vec::new();
    };
    let Ok(plist) = super::plist_guard::parse(xml) else {
        return Vec::new();
    };
    let Some(blkx) = plist
        .as_dictionary()
        .and_then(|d| d.get("resource-fork"))
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("blkx"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in blkx.iter().take(MAX_PARTITIONS) {
        let Some(dict) = entry.as_dictionary() else {
            continue;
        };
        let name = dict
            .get("Name")
            .or_else(|| dict.get("CFName"))
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let Some(data) = dict.get("Data").and_then(|v| v.as_data()) else {
            continue;
        };
        if let Some(part) = parse_mish(name, data) {
            out.push(part);
        }
    }
    out
}

/// Decode a `mish` (BLKXTable) blob: a fixed header followed by an array of
/// 40-byte chunk descriptors starting at offset 204.
fn parse_mish(name: String, data: &[u8]) -> Option<Partition> {
    if !data.starts_with(b"mish") {
        return None;
    }
    let sector_count = u64_be(data, 16)?;
    let data_offset = u64_be(data, 24)?;
    let declared = u32_be(data, 200)? as usize;
    // The chunk count is attacker-controlled; clamp to what the blob holds.
    let available = data.len().saturating_sub(204) / 40;
    let count = declared.min(available);

    let mut chunks = Vec::with_capacity(count);
    for i in 0..count {
        let off = 204 + i * 40;
        let entry_type = u32_be(data, off)?;
        chunks.push(Chunk {
            entry_type,
            sector_number: u64_be(data, off + 8)?,
            sector_count: u64_be(data, off + 16)?,
            comp_offset: u64_be(data, off + 24)?,
            comp_length: u64_be(data, off + 32)?,
        });
    }
    Some(Partition {
        name,
        sector_count,
        data_offset,
        chunks,
    })
}

/// Emit the partition table, the per-codec histogram, and one
/// [`ArchiveMember`] per partition.
fn emit_partitions(
    partitions: &[Partition],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) {
    metrics.insert(metric!("dmg.partition_count"), partitions.len() as f64);

    // Codec chunk counts across all partitions. BTreeMap → stable order.
    let mut codec_counts: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    let mut compressors: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();

    let mut members = Vec::with_capacity(partitions.len());
    let mut archive_values = Vec::with_capacity(partitions.len());
    let mut stats = ArchiveStats::new(AGGS);
    for p in partitions {
        let mut part_codecs: std::collections::BTreeMap<&'static str, u64> =
            std::collections::BTreeMap::new();
        let mut compressed: u64 = 0;
        for c in &p.chunks {
            let codec = codec_name(c.entry_type);
            // Terminator / comment chunks carry no payload.
            if matches!(codec, "last" | "comment") {
                continue;
            }
            *codec_counts.entry(codec).or_insert(0) += 1;
            *part_codecs.entry(codec).or_insert(0) += 1;
            compressed = compressed.saturating_add(c.comp_length);
            if is_compressor(codec) {
                compressors.insert(codec);
            }
        }

        let size_bytes = p.sector_count.saturating_mul(SECTOR);
        let method = dominant_codec(&part_codecs);

        let mut obj = JsonMap::new();
        obj.insert("name".into(), JsonValue::String(p.name.clone()));
        obj.insert("size_bytes".into(), JsonValue::Number(size_bytes.into()));
        obj.insert(
            "compressed_bytes".into(),
            JsonValue::Number(compressed.into()),
        );
        obj.insert(
            "compression_method".into(),
            JsonValue::String(method.into()),
        );
        if let Some(fs) = fs_from_name(&p.name) {
            obj.insert("filesystem".into(), JsonValue::String(fs.into()));
        }
        members.push(JsonValue::Object(obj));

        let member = ArchiveMember {
            path: p.name.clone(),
            size_bytes,
            entry_type: Some("partition".into()),
            mtime_unix: None,
            linkname: None,
            host_os: Some("macintosh".into()),
            crc32: None,
            encrypted: false,
            compression: Some(ArchiveCompression {
                compressed_size: Some(compressed),
                method: Some(method.into()),
            }),
            ownership: None,
            offsets: ArchiveOffsets::default(),
        };
        stats.observe(&member, &Reading::opaque());
        archive_values.push(JsonValue::Object(member_value(&member, Shape::FULL)));
        archive_members.push(member);
    }

    values.insert_key(value_key!("dmg.partitions"), JsonValue::Array(members));
    values.insert_key(
        value_key!("archive.members"),
        JsonValue::Array(archive_values),
    );
    stats.emit(values, metrics);

    let codecs: Vec<JsonValue> = codec_counts
        .keys()
        .map(|k| JsonValue::String((*k).into()))
        .collect();
    values.insert_key(
        value_key!("dmg.compression.codecs"),
        JsonValue::Array(codecs),
    );
    for (codec, count) in &codec_counts {
        metrics.insert(crate::dmg_codec_count(codec), *count as f64);
    }

    // The compressor set fingerprints the creating tool / `hdiutil -format`.
    let format = match compressors.iter().copied().collect::<Vec<_>>().as_slice() {
        [] => "UDRO", // uncompressed (raw/zero only)
        ["zlib"] => "UDZO",
        ["bzip2"] => "UDBZ",
        ["lzfse"] => "ULFO",
        ["lzma"] => "ULMO",
        ["adc"] => "UDCO",
        _ => "mixed",
    };
    values.insert_key(
        value_key!("dmg.udif_format"),
        JsonValue::String(format.into()),
    );
}

/// Read the filesystem partition's volume superblock. Best-effort: only
/// `zlib`/`raw` images are reachable here, and any structural surprise
/// leaves the volume facts unset rather than failing.
fn volume_facts(
    bytes: &[u8],
    koly: &Koly,
    partitions: &[Partition],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    // The filesystem partition is the one whose name records a filesystem;
    // failing that (Apple Partition Map images), the largest partition.
    let Some(part) = partitions
        .iter()
        .find(|p| fs_from_name(&p.name).is_some())
        .or_else(|| partitions.iter().max_by_key(|p| p.sector_count))
    else {
        return;
    };

    let Some(prefix) = reconstruct_prefix(bytes, koly, part, MAX_VOL_PREFIX) else {
        return; // compressed with a codec we don't carry (LZFSE/bzip2/LZMA).
    };

    if let Some(()) = hfs_volume_facts(&prefix, values, metrics) {
        return;
    }
    apfs_volume_facts(&prefix, values, metrics);
}

/// Inflated bytes [`reconstruct_prefix`] decodes across every chunk. The
/// window is [`MAX_VOL_PREFIX`]; a few times that allows for overlapping
/// chunks without letting 300,000 descriptors that all name one zlib blob
/// inflate it 300,000 times.
const MAX_PREFIX_INFLATE: usize = 4 * MAX_VOL_PREFIX;

/// Bytes [`reconstruct_prefix`] handles across every chunk: what `raw`
/// chunks copy, what `zero` chunks fill and what `zlib` chunks consume. The
/// inflate budget alone does not bound the work: a chunk whose stream
/// inflates to nothing (a run of empty deflate blocks) still consumes its
/// whole source, and chunks that rewrite the same sectors while one stays
/// unwritten each handle up to the window. Hundreds of thousands of such
/// descriptors multiplied the image size by the descriptor count.
const MAX_PREFIX_WORK: usize = 4 * MAX_VOL_PREFIX;

/// Decompress the leading `max` bytes of a partition using only the codecs
/// filefacts carries (`raw`, `zero`, `zlib`). Returns `None` the moment a
/// chunk inside the window needs a codec we don't have — the volume header
/// would be unreadable anyway.
///
/// Each chunk writes at most its own sector run, the walk stops once every
/// sector of the window has been written, and zlib output across all chunks
/// shares [`MAX_PREFIX_INFLATE`]. A chunk that points outside the image or
/// whose stream is damaged loses only its own sectors.
fn reconstruct_prefix(bytes: &[u8], koly: &Koly, part: &Partition, max: usize) -> Option<Vec<u8>> {
    reconstruct_prefix_counted(bytes, koly, part, max).map(|(buf, _)| buf)
}

/// [`reconstruct_prefix`], also returning how many bytes it inflated.
fn reconstruct_prefix_counted(
    bytes: &[u8],
    koly: &Koly,
    part: &Partition,
    max: usize,
) -> Option<(Vec<u8>, usize)> {
    let sector = crate::bytes::sat_usize(SECTOR);
    let mut buf = vec![0u8; max];
    let mut written = vec![false; max.div_ceil(sector)];
    let mut pending = written.len();
    let mut inflate_budget = MAX_PREFIX_INFLATE;
    let mut work_budget = MAX_PREFIX_WORK;
    let fork_base = koly.data_fork_offset.saturating_add(part.data_offset);
    for c in &part.chunks {
        if pending == 0 || work_budget == 0 {
            break;
        }
        let Some(out_off) = c
            .sector_number
            .checked_mul(SECTOR)
            .and_then(|off| usize::try_from(off).ok())
            .filter(|&off| off < max)
        else {
            continue; // beyond the window — irrelevant to the superblock.
        };
        let want = usize::try_from(c.sector_count.saturating_mul(SECTOR))
            .unwrap_or(usize::MAX)
            .min(max - out_off);
        let codec = codec_name(c.entry_type);
        let n = match codec {
            "zero" | "ignore" => {
                // Already zero-filled; only the sectors are marked.
                let n = want.min(work_budget);
                work_budget -= n;
                n
            }
            "comment" | "last" => continue,
            "raw" => {
                let Some(src) = chunk_source(bytes, fork_base, c) else {
                    continue;
                };
                let src = src.get(..want.min(work_budget)).unwrap_or(src);
                work_budget -= src.len();
                fill(&mut buf, out_off, src);
                src.len()
            }
            "zlib" => {
                if inflate_budget == 0 {
                    break;
                }
                let Some(src) = chunk_source(bytes, fork_base, c) else {
                    continue;
                };
                let src = src.get(..work_budget).unwrap_or(src);
                let mut out = Vec::new();
                // A truncated or corrupt stream keeps what decoded before
                // the damage; `read_to_end` leaves it in `out`.
                let mut zlib = flate2::read::ZlibDecoder::new(src);
                let _ = (&mut zlib)
                    .take(want.min(inflate_budget) as u64)
                    .read_to_end(&mut out);
                // Charged at least a sector: setting up an inflater costs
                // that much even for a stream that consumes nothing.
                let consumed = usize::try_from(zlib.total_in()).unwrap_or(usize::MAX);
                work_budget = work_budget.saturating_sub(consumed.max(sector));
                inflate_budget -= out.len();
                fill(&mut buf, out_off, &out);
                out.len()
            }
            _ => return None, // adc / bzip2 / lzfse / lzma
        };
        let first = out_off / sector;
        let last = out_off
            .saturating_add(n)
            .div_ceil(sector)
            .min(written.len());
        for done in written.get_mut(first..last).into_iter().flatten() {
            if !*done {
                *done = true;
                pending -= 1;
            }
        }
    }
    Some((buf, MAX_PREFIX_INFLATE - inflate_budget))
}

/// The compressed bytes chunk `c` decodes from, or `None` when they lie
/// outside the image.
fn chunk_source<'b>(bytes: &'b [u8], fork_base: u64, c: &Chunk) -> Option<&'b [u8]> {
    let start = usize::try_from(fork_base.checked_add(c.comp_offset)?).ok()?;
    let len = usize::try_from(c.comp_length).ok()?;
    bytes.get(start..start.checked_add(len)?)
}

/// Copy as much of `src` as fits into `buf` starting at `at`.
fn fill(buf: &mut [u8], at: usize, src: &[u8]) {
    let n = buf.len().saturating_sub(at).min(src.len());
    if let (Some(dst), Some(src)) = (buf.get_mut(at..at + n), src.get(..n)) {
        dst.copy_from_slice(src);
    }
}

/// Parse an HFS+/HFSX volume header (at partition offset 1024). Returns
/// `Some(())` when the signature matches so the caller stops.
fn hfs_volume_facts(prefix: &[u8], values: &mut Values, metrics: &mut Metrics) -> Option<()> {
    let vh = prefix.get(1024..)?.first_chunk::<64>()?;
    let fs = match &vh[0..2] {
        b"H+" => "HFS+",
        b"HX" => "HFSX",
        _ => return None,
    };
    values.insert_key(
        value_key!("dmg.volume.filesystem"),
        JsonValue::String(fs.into()),
    );

    // `lastMountedVersion` (e.g. `10.0`, `HFSJ`, `fsck`) fingerprints the
    // last writer — a coarse creating-tool signal.
    let lmv: String = vh[8..12]
        .iter()
        .filter(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    if !lmv.is_empty() {
        values.insert_key(
            value_key!("dmg.volume.last_mounted_version"),
            JsonValue::String(lmv),
        );
    }

    // Dates are seconds since 1904. Per the HFS+ spec `createDate` is local
    // time while `modifyDate` is GMT, so their delta is the build machine's
    // timezone offset — surfaced separately rather than normalized away.
    let create = u32_be(vh, 16)?;
    let modify = u32_be(vh, 20)?;
    if let Some(t) = hfs_to_unix(create) {
        values.insert_key(
            value_key!("dmg.volume.created_unix"),
            JsonValue::Number(t.into()),
        );
    }
    if let Some(t) = hfs_to_unix(modify) {
        values.insert_key(
            value_key!("dmg.volume.modified_unix"),
            JsonValue::Number(t.into()),
        );
    }
    if let (Some(c), Some(m)) = (hfs_to_unix(create), hfs_to_unix(modify)) {
        metrics.insert(metric!("dmg.volume.timezone_skew_seconds"), (c - m) as f64);
    }

    metrics.insert(metric!("dmg.volume.file_count"), f64::from(u32_be(vh, 32)?));
    metrics.insert(
        metric!("dmg.volume.folder_count"),
        f64::from(u32_be(vh, 36)?),
    );
    metrics.insert(metric!("dmg.volume.block_size"), f64::from(u32_be(vh, 40)?));
    Some(())
}

/// Locate an APFS volume superblock (`APSB`) within the reconstructed prefix
/// and lift its identity/provenance fields. Integers are little-endian;
/// timestamps are nanoseconds since the Unix epoch (UTC).
fn apfs_volume_facts(prefix: &[u8], values: &mut Values, metrics: &mut Metrics) -> Option<()> {
    // `apfs_magic` sits at offset +32 of the object block. Field offsets
    // below are into the `apfs_superblock_t`; note `apfs_meta_crypto` is 20
    // bytes, which shifts everything past offset 112 by 4 vs a naive layout.
    let magic = memchr::memmem::find(prefix, b"APSB")?;
    let block = magic.checked_sub(32)?;
    let sb = prefix.get(block..block.checked_add(704 + 256)?)?;

    values.insert_key(
        value_key!("dmg.volume.filesystem"),
        JsonValue::String("APFS".into()),
    );

    // The fs-object counters live in the volume's b-tree; sealed
    // distribution volumes leave the superblock copies zeroed. Emit only
    // when populated — the authoritative count is cleave's full-walk job.
    for (key, off) in [
        (metric!("dmg.volume.file_count"), 184),
        (metric!("dmg.volume.folder_count"), 192),
        (metric!("dmg.volume.symlink_count"), 200),
    ] {
        let n = u64_le(sb, off)?;
        if n > 0 {
            metrics.insert(key, n as f64);
        }
    }

    if let Some(t) = apfs_ns_to_unix(u64_le(sb, 256)?) {
        values.insert_key(
            value_key!("dmg.volume.modified_unix"),
            JsonValue::Number(t.into()),
        );
    }
    // `apfs_formatted_by`: a 32-byte id (`newfs_apfs (NNNN.NN.N)`) and the
    // nanosecond timestamp it was laid down — a precise build-environment
    // fingerprint and creation time.
    if let Some(id) = c_string(sb, 272, 32) {
        values.insert_key(value_key!("dmg.volume.formatted_by"), JsonValue::String(id));
    }
    if let Some(t) = apfs_ns_to_unix(u64_le(sb, 304)?) {
        values.insert_key(
            value_key!("dmg.volume.created_unix"),
            JsonValue::Number(t.into()),
        );
    }
    if let Some(name) = c_string(sb, 704, 256) {
        values.insert_key(value_key!("dmg.volume.name"), JsonValue::String(name));
    }
    Some(())
}

/// Map a `BLKXChunkEntry` type to filefacts' stable codec vocabulary.
fn codec_name(entry_type: u32) -> &'static str {
    match entry_type {
        0x0000_0000 => "zero",
        0x0000_0001 => "raw",
        0x0000_0002 => "ignore",
        0x8000_0004 => "adc",
        0x8000_0005 => "zlib",
        0x8000_0006 => "bzip2",
        0x8000_0007 => "lzfse",
        0x8000_0008 => "lzma",
        0x7fff_fffe => "comment",
        0xffff_ffff => "last",
        _ => "unknown",
    }
}

/// Whether a codec actually compresses (vs. raw/zero/structural markers).
fn is_compressor(codec: &str) -> bool {
    matches!(codec, "adc" | "zlib" | "bzip2" | "lzfse" | "lzma")
}

/// The codec backing the most chunks in a partition (`mixed` on a tie of
/// distinct compressors, `none` when empty).
fn dominant_codec(counts: &std::collections::BTreeMap<&'static str, u64>) -> &'static str {
    counts
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(k, _)| *k)
        .unwrap_or("none")
}

/// Inner filesystem named in a partition label (`disk image (Apple_HFS : 4)`).
fn fs_from_name(name: &str) -> Option<&'static str> {
    if name.contains("Apple_APFS") {
        Some("APFS")
    } else if name.contains("Apple_HFSX") {
        Some("HFSX")
    } else if name.contains("Apple_HFS") {
        Some("HFS+")
    } else {
        None
    }
}

fn hfs_to_unix(secs: u32) -> Option<i64> {
    (secs != 0).then(|| i64::from(secs) - MAC_EPOCH_OFFSET)
}

fn apfs_ns_to_unix(ns: u64) -> Option<i64> {
    (ns != 0).then(|| (ns / 1_000_000_000).cast_signed())
}

/// Read a NUL-terminated UTF-8 string from a fixed-width field, returning
/// `None` when empty or not valid UTF-8.
fn c_string(b: &[u8], off: usize, len: usize) -> Option<String> {
    let field = b.get(off..off.checked_add(len)?)?;
    let text = field.split(|&c| c == 0).next().unwrap_or(field);
    let s = std::str::from_utf8(text).ok()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a minimal single-partition UDIF image: `[data fork][xml][koly]`.
    /// `fork` is stored as one `raw` chunk; the plist names one `blkx` member.
    fn build_dmg(name: &str, fork: &[u8]) -> Vec<u8> {
        let sectors = fork.len().div_ceil(512) as u64;

        // mish: header + one raw chunk + a terminator chunk.
        let mut mish = vec![0u8; 204];
        mish[0..4].copy_from_slice(b"mish");
        mish[4..8].copy_from_slice(&1u32.to_be_bytes()); // version
        mish[8..16].copy_from_slice(&0u64.to_be_bytes()); // base sector
        mish[16..24].copy_from_slice(&sectors.to_be_bytes());
        mish[200..204].copy_from_slice(&2u32.to_be_bytes()); // chunk count
        let push_chunk = |m: &mut Vec<u8>, et: u32, sec: u64, cnt: u64, coff: u64, clen: u64| {
            let mut c = vec![0u8; 40];
            c[0..4].copy_from_slice(&et.to_be_bytes());
            c[8..16].copy_from_slice(&sec.to_be_bytes());
            c[16..24].copy_from_slice(&cnt.to_be_bytes());
            c[24..32].copy_from_slice(&coff.to_be_bytes());
            c[32..40].copy_from_slice(&clen.to_be_bytes());
            m.extend_from_slice(&c);
        };
        push_chunk(&mut mish, 0x0000_0001, 0, sectors, 0, fork.len() as u64);
        push_chunk(&mut mish, 0xffff_ffff, sectors, 0, fork.len() as u64, 0);

        // resource-fork → blkx → [ { Name, Data } ]
        let mut entry = plist::Dictionary::new();
        entry.insert("Name".into(), plist::Value::String(name.into()));
        entry.insert("Data".into(), plist::Value::Data(mish));
        let mut rf = plist::Dictionary::new();
        rf.insert(
            "blkx".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(entry)]),
        );
        let mut root = plist::Dictionary::new();
        root.insert("resource-fork".into(), plist::Value::Dictionary(rf));
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(root)).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(fork);
        let xml_offset = out.len() as u64;
        out.extend_from_slice(&xml);

        let mut koly = vec![0u8; KOLY_LEN];
        koly[0..4].copy_from_slice(b"koly");
        koly[4..8].copy_from_slice(&4u32.to_be_bytes()); // version
        koly[8..12].copy_from_slice(&512u32.to_be_bytes()); // header size
        koly[24..32].copy_from_slice(&0u64.to_be_bytes()); // data fork offset
        koly[32..40].copy_from_slice(&(fork.len() as u64).to_be_bytes());
        koly[216..224].copy_from_slice(&xml_offset.to_be_bytes());
        koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
        koly[488..492].copy_from_slice(&1u32.to_be_bytes()); // image variant
        koly[492..500].copy_from_slice(&sectors.to_be_bytes());
        out.extend_from_slice(&koly);
        out
    }

    /// A 2048-byte partition carrying an HFS+ volume header at +1024.
    fn hfs_fork(file_count: u32, folder_count: u32, create: u32, modify: u32) -> Vec<u8> {
        let mut fork = vec![0u8; 2048];
        let vh = &mut fork[1024..];
        vh[0..2].copy_from_slice(b"H+");
        vh[8..12].copy_from_slice(b"10.0"); // lastMountedVersion
        vh[16..20].copy_from_slice(&create.to_be_bytes());
        vh[20..24].copy_from_slice(&modify.to_be_bytes());
        vh[32..36].copy_from_slice(&file_count.to_be_bytes());
        vh[36..40].copy_from_slice(&folder_count.to_be_bytes());
        vh[40..44].copy_from_slice(&4096u32.to_be_bytes()); // block size
        fork
    }

    fn run(bytes: &[u8]) -> (Values, Metrics, Vec<ArchiveMember>) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut members = Vec::new();
        extract(bytes, &mut v, &mut m, &mut members).unwrap();
        (v, m, members)
    }

    #[test]
    fn container_facts_for_raw_hfs_image() {
        let dmg = build_dmg("disk image (Apple_HFS : 4)", &hfs_fork(42, 7, 0, 0));
        let (v, m, members) = run(&dmg);

        assert_eq!(v.get("dmg.format").and_then(|x| x.as_str()), Some("UDIF"));
        assert_eq!(v.get("dmg.udif_version").and_then(|x| x.as_u64()), Some(4));
        // No compressor used → uncompressed format label.
        assert_eq!(
            v.get("dmg.udif_format").and_then(|x| x.as_str()),
            Some("UDRO")
        );
        assert_eq!(
            v.get("dmg.filesystem").and_then(|x| x.as_str()),
            Some("HFS+")
        );
        assert_eq!(m.get("dmg.partition_count"), Some(1.0));
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].entry_type.as_deref(), Some("partition"));
    }

    #[test]
    fn hfs_volume_facts_from_raw_chunk() {
        // create 4h ahead of modify → +14400s timezone skew (local vs GMT).
        let create = MAC_EPOCH_OFFSET as u32 + 14_400;
        let modify = MAC_EPOCH_OFFSET as u32;
        let dmg = build_dmg(
            "disk image (Apple_HFS : 4)",
            &hfs_fork(42, 7, create, modify),
        );
        let (v, m, _) = run(&dmg);

        assert_eq!(m.get("dmg.volume.file_count"), Some(42.0));
        assert_eq!(m.get("dmg.volume.folder_count"), Some(7.0));
        assert_eq!(m.get("dmg.volume.block_size"), Some(4096.0));
        assert_eq!(m.get("dmg.volume.timezone_skew_seconds"), Some(14_400.0));
        assert_eq!(
            v.get("dmg.volume.modified_unix").and_then(|x| x.as_i64()),
            Some(0)
        );
        assert_eq!(
            v.get("dmg.volume.last_mounted_version")
                .and_then(|x| x.as_str()),
            Some("10.0")
        );
    }

    #[test]
    fn zlib_chunk_is_decompressed_for_volume_facts() {
        use std::io::Write;
        let fork = hfs_fork(3, 1, 0, 0);
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&fork).unwrap();
        let zlib = enc.finish().unwrap();

        // Build a DMG whose single chunk is zlib instead of raw.
        let sectors = (fork.len() / 512) as u64;
        let mut mish = vec![0u8; 204];
        mish[0..4].copy_from_slice(b"mish");
        mish[16..24].copy_from_slice(&sectors.to_be_bytes());
        mish[200..204].copy_from_slice(&1u32.to_be_bytes());
        let mut c = vec![0u8; 40];
        c[0..4].copy_from_slice(&0x8000_0005u32.to_be_bytes()); // zlib
        c[16..24].copy_from_slice(&sectors.to_be_bytes());
        c[32..40].copy_from_slice(&(zlib.len() as u64).to_be_bytes());
        mish.extend_from_slice(&c);

        let mut entry = plist::Dictionary::new();
        entry.insert(
            "Name".into(),
            plist::Value::String("disk image (Apple_HFS : 4)".into()),
        );
        entry.insert("Data".into(), plist::Value::Data(mish));
        let mut rf = plist::Dictionary::new();
        rf.insert(
            "blkx".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(entry)]),
        );
        let mut root = plist::Dictionary::new();
        root.insert("resource-fork".into(), plist::Value::Dictionary(rf));
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(root)).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&zlib);
        let xml_offset = out.len() as u64;
        out.extend_from_slice(&xml);
        let mut koly = vec![0u8; KOLY_LEN];
        koly[0..4].copy_from_slice(b"koly");
        koly[4..8].copy_from_slice(&4u32.to_be_bytes());
        koly[32..40].copy_from_slice(&(zlib.len() as u64).to_be_bytes());
        koly[216..224].copy_from_slice(&xml_offset.to_be_bytes());
        koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
        koly[492..500].copy_from_slice(&sectors.to_be_bytes());
        out.extend_from_slice(&koly);

        let (v, m, _) = run(&out);
        assert_eq!(
            v.get("dmg.udif_format").and_then(|x| x.as_str()),
            Some("UDZO")
        );
        assert_eq!(m.get("dmg.volume.file_count"), Some(3.0));
    }

    /// Partitions are archive members: listed under `archive.members` and
    /// summed by the shared aggregates.
    #[test]
    fn partitions_are_published_as_archive_members() {
        let dmg = build_dmg("disk image (Apple_HFS : 4)", &hfs_fork(1, 1, 0, 0));
        let (v, m, members) = run(&dmg);
        let listed = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert_eq!(listed.len(), members.len());
        assert_eq!(listed[0]["entry_type"], "partition");
        assert_eq!(listed[0]["compression_method"], "raw");
        assert_eq!(listed[0]["host_os"], "macintosh");
        assert_eq!(m.get("archive.member_count"), Some(1.0));
        assert_eq!(m.get("archive.uncompressed_size"), Some(2048.0));
        assert_eq!(m.get("archive.compression.method_counts.raw"), Some(1.0));
        // A partition label is not a file name.
        assert!(m.get("archive.executable_count").is_none());
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zlib_chunk(sector_number: u64, sector_count: u64, comp_length: u64) -> Chunk {
        Chunk {
            entry_type: 0x8000_0005,
            sector_number,
            sector_count,
            comp_offset: 0,
            comp_length,
        }
    }

    fn koly_at_zero() -> Koly {
        Koly {
            version: 4,
            data_fork_offset: 0,
            data_fork_length: 0,
            xml_offset: 0,
            xml_length: 0,
            image_variant: 1,
            sector_count: 0,
        }
    }

    /// Thousands of descriptors naming one zlib blob used to inflate it once
    /// each, up to the whole window every time. Overlapping chunks now share
    /// one inflate budget, and each decodes at most its own sector run.
    #[test]
    fn overlapping_zlib_chunks_share_one_inflate_budget() {
        let blob = zlib(&vec![0_u8; MAX_VOL_PREFIX]);
        let half = (MAX_VOL_PREFIX as u64 / SECTOR) / 2;
        let part = Partition {
            name: String::new(),
            sector_count: half * 2,
            data_offset: 0,
            chunks: (0..10_000)
                .map(|_| zlib_chunk(0, half, blob.len() as u64))
                .collect(),
        };
        let (_, inflated) =
            reconstruct_prefix_counted(&blob, &koly_at_zero(), &part, MAX_VOL_PREFIX).unwrap();
        assert_eq!(inflated, MAX_PREFIX_INFLATE);
    }

    /// A chunk writes no more than its declared sector run.
    #[test]
    fn zlib_chunk_output_is_capped_at_its_sector_count() {
        let blob = zlib(&vec![0xAB_u8; 8 * SECTOR as usize]);
        let part = Partition {
            name: String::new(),
            sector_count: 8,
            data_offset: 0,
            chunks: vec![zlib_chunk(0, 1, blob.len() as u64)],
        };
        let (buf, inflated) =
            reconstruct_prefix_counted(&blob, &koly_at_zero(), &part, 8 * SECTOR as usize).unwrap();
        assert_eq!(inflated, SECTOR as usize);
        assert!(buf[..SECTOR as usize].iter().all(|&b| b == 0xAB));
        assert!(buf[SECTOR as usize..].iter().all(|&b| b == 0));
    }

    /// One chunk pointing outside the image no longer discards the others.
    #[test]
    fn bad_chunk_loses_only_its_own_sectors() {
        let blob = zlib(&[0xCD_u8; SECTOR as usize]);
        let mut bad = zlib_chunk(1, 1, 64);
        bad.comp_offset = u64::MAX - 8;
        let part = Partition {
            name: String::new(),
            sector_count: 2,
            data_offset: 0,
            chunks: vec![zlib_chunk(0, 1, blob.len() as u64), bad],
        };
        let (buf, _) =
            reconstruct_prefix_counted(&blob, &koly_at_zero(), &part, 2 * SECTOR as usize).unwrap();
        assert!(buf[..SECTOR as usize].iter().all(|&b| b == 0xCD));
    }

    /// Descriptors that each re-handle the window while one sector stays
    /// unwritten no longer multiply the work by the descriptor count: zlib
    /// streams that inflate to nothing still consume their source, and raw
    /// or zero runs rewrite sectors already written. The walk stops at the
    /// work budget, before a last chunk that would finish the window.
    #[test]
    fn chunks_that_never_finish_the_window_share_one_work_budget() {
        // A zlib stream of empty stored blocks: 64 KiB consumed, nothing out.
        let mut bytes = vec![0x78, 0x01];
        for _ in 0..(64 << 10) / 5 {
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        let stalled = bytes.len() as u64;
        let finisher = zlib(&[0xAB; SECTOR as usize]);
        let finisher_at = bytes.len() as u64;
        bytes.extend_from_slice(&finisher);
        let raw_at = bytes.len() as u64;
        bytes.extend_from_slice(&[0xAB; SECTOR as usize]);

        let window = MAX_VOL_PREFIX as u64 / SECTOR;
        let rounds = MAX_PREFIX_WORK / (64 << 10) + 8;
        for (entry_type, finish_type, finish_at, finish_len) in [
            (0x8000_0005, 0x8000_0005, finisher_at, finisher.len() as u64),
            (0x0000_0001, 0x0000_0001, raw_at, SECTOR),
            (0x0000_0000, 0x0000_0001, raw_at, SECTOR),
        ] {
            let mut chunks: Vec<Chunk> = (0..rounds)
                .map(|_| Chunk {
                    entry_type,
                    sector_number: 0,
                    sector_count: window - 1,
                    comp_offset: 0,
                    comp_length: stalled,
                })
                .collect();
            chunks.push(Chunk {
                entry_type: finish_type,
                sector_number: window - 1,
                sector_count: 1,
                comp_offset: finish_at,
                comp_length: finish_len,
            });
            let part = Partition {
                name: String::new(),
                sector_count: window,
                data_offset: 0,
                chunks,
            };
            let buf = reconstruct_prefix(&bytes, &koly_at_zero(), &part, MAX_VOL_PREFIX).unwrap();
            let last = &buf[MAX_VOL_PREFIX - SECTOR as usize..];
            assert!(
                last.iter().all(|&b| b == 0),
                "entry type {entry_type:#x}: the walk ran past its work budget"
            );
        }
    }

    #[test]
    fn non_dmg_bytes_error() {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut members = Vec::new();
        assert!(extract(b"not a dmg at all", &mut v, &mut m, &mut members).is_err());
    }

    /// The resource-fork plist is attacker bytes: a binary plist whose shared
    /// references expand exponentially is refused instead of expanded.
    #[test]
    fn blkx_plist_reference_expansion_is_refused() {
        let xml = crate::formats::plist_guard::reference_dag(8);
        let koly = Koly {
            xml_length: xml.len() as u64,
            ..koly_at_zero()
        };
        let start = std::time::Instant::now();
        assert!(parse_blkx(&xml, &koly).is_empty());
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
}
