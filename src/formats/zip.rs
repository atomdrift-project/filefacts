//! ZIP archive-index extractor.
//!
//! Reads the central directory only — never decompresses entries. The
//! output is the full member listing, the archive comment, and a few
//! per-entry forensic fields drawn from the central-directory header.
//!
//! Decompression and recursion are the caller's responsibility:
//! `filefacts` describes what's *in* the archive, not what each member
//! *contains*.

// JAR signing manifests have format-defined uppercase names
// (`META-INF/*.SF`, `*.RSA`). The case-sensitive comparison is required.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use crate::metric;
use crate::value_key;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek};

use serde_json::Value as JsonValue;
use zip::{CompressionMethod, ZipArchive};

use super::archive_stats::{Agg, ArchiveStats, Dominance, Reading, Scope, Shape, member_value};
use super::common::bytes_at;
use crate::error::Error;
use crate::output::{
    ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership, Metrics, Values,
};

/// Cap on how many central-directory entries are walked into
/// `archive.members`. `ZipArchive::len()` counts the entries the `zip` crate
/// actually parsed (each at least 46 bytes of central directory, de-duplicated
/// by name), so it is bounded by the input size, not by the count the EOCD
/// declares. A large input can still hold millions, though, and each walked
/// entry costs a JSON member and an [`ArchiveMember`]. 65_536 fits a generous
/// real-world archive (the JDK ships a few thousand classes per jar).
pub(super) const MAX_ZIP_MEMBERS: usize = 65_536;

/// The shared aggregates over the walked entries. The member count, the
/// duplicate count and the sentinel-mtime count are ZIP's own: they also
/// cover what the `zip` crate de-duplicated or the walk cap left out.
///
/// The central-directory walk never reads a symlink's target (it lives in
/// the compressed body), so `archive.symlink_escape_count` is always 0 here.
const AGGS: &[Agg] = &[
    Agg::FileCount,
    Agg::DirectoryCount,
    Agg::UncompressedSize(Scope::All),
    Agg::CompressedSize,
    Agg::CompressionRatio,
    Agg::Methods { always: true },
    Agg::EntryTypes,
    Agg::ModeBits,
    Agg::SymlinkCount,
    Agg::EncryptedCount,
    Agg::MaxFilenameLength,
    Agg::HiddenFiles,
    Agg::PathTraversal(Scope::All),
    Agg::SymlinkEscapes,
    Agg::Executables,
    Agg::Scripts,
    Agg::NameTricks,
    Agg::NestedArchives,
    Agg::MisplacedExecutables,
    Agg::ZipBombRatio(Scope::Files),
    Agg::NoiseFiles,
    Agg::MtimeRange,
    Agg::MtimeAnomalies(Dominance::UntimedGroup),
];

pub(super) fn open_archive(bytes: &[u8]) -> Result<ZipArchive<Cursor<&[u8]>>, Error> {
    ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| Error::malformed_with_source("zip", e.to_string(), e))
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let mut archive = open_archive(bytes)?;
    extract_from_archive(&mut archive, bytes, values, metrics, archive_members)
}

pub(super) fn extract_from_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    walk_archive(
        archive,
        bytes,
        values,
        metrics,
        archive_members,
        MAX_ZIP_MEMBERS,
    )
}

/// [`extract_from_archive`] with the member cap as a parameter, so the cap
/// can be exercised without building a 65k-entry archive.
fn walk_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    max_members: usize,
) -> Result<(), Error> {
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("zip".into()),
    );

    let comment = archive.comment();
    let has_comment = !comment.is_empty();
    if has_comment {
        let comment_str = String::from_utf8_lossy(comment).into_owned();
        values.insert_key(
            value_key!("archive.comment"),
            JsonValue::String(comment_str),
        );
        metrics.insert(metric!("archive.comment_size"), comment.len() as f64);
    }

    // Entries past the cap are not walked, so every per-member list and
    // count below covers the first `walked` entries; `archive.member_count`
    // still reports the full parsed count.
    let walked = archive.len().min(max_members);
    if walked < archive.len() {
        values.insert_key(
            value_key!("zip.limits"),
            serde_json::json!([{
                "stage": "member-cap",
                "reason": format!("walked {walked} of {} members", archive.len()),
            }]),
        );
    }
    let mut members: Vec<JsonValue> = Vec::with_capacity(walked);
    let mut stats = ArchiveStats::new(AGGS);
    let mut extra_field_size: u64 = 0;
    let mut uses_zip64 = false;
    let mut entry_comment_count: u64 = 0;
    let mut entry_comment_size: u64 = 0;
    // Tag IDs encountered in any LFH/CDH extra field (union across members).
    let mut extra_field_tags: BTreeSet<u16> = BTreeSet::new();

    for i in 0..walked {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| Error::malformed_with_source("zip", format!("entry {i}: {e}"), e))?;

        let mode = entry.unix_mode();
        let is_symlink = |m: u32| m & 0o170_000 == 0o120_000;
        let entry_type = if entry.is_dir() {
            "directory"
        } else if mode.is_some_and(is_symlink) {
            "symlink"
        } else {
            "regular"
        };
        let compressed = entry.compressed_size();
        let member = ArchiveMember {
            path: entry.name().to_string(),
            size_bytes: entry.size(),
            entry_type: Some(entry_type.into()),
            // None means the MS-DOS date didn't parse — Mozilla's (1980, 0, 0)
            // "no recorded timestamp" sentinel is the common case, and
            // deterministic-build tooling (web-ext, bazel) produces it on
            // purpose.
            mtime_unix: entry
                .last_modified()
                .and_then(crate::scan::zip_datetime_to_unix),
            linkname: None,
            host_os: None,
            crc32: Some(entry.crc32()),
            encrypted: entry.encrypted(),
            compression: Some(ArchiveCompression {
                compressed_size: Some(compressed),
                method: Some(compression_method_name(entry.compression()).into()),
            }),
            ownership: mode.map(|mode| ArchiveOwnership {
                mode_octal: Some(mode),
                ..Default::default()
            }),
            offsets: ArchiveOffsets {
                header: Some(entry.header_start()),
                data: Some(entry.data_start()),
                central_header: Some(entry.central_header_start()),
            },
        };
        let mut reading = Reading::of(&member);
        // An exec bit on anything but a symlink makes it executable,
        // whatever its name.
        reading.exec_mode = mode.is_some_and(|m| !is_symlink(m) && m & 0o111 != 0);
        stats.observe(&member, &reading);

        let mut obj = member_value(&member, Shape::FULL);
        let mut entry_tags = BTreeSet::new();
        if let Some(extra) = entry.extra_data() {
            extra_field_size += extra.len() as u64;
            entry_tags = enumerate_extra_tags(extra);
            extra_field_tags.extend(&entry_tags);
            uses_zip64 |= entry_tags.contains(&0x0001);
        }
        // Sentinel sizes in the central directory also indicate Zip64 usage.
        uses_zip64 |= compressed == 0xFFFF_FFFF || member.size_bytes == 0xFFFF_FFFF;
        if !entry_tags.is_empty() {
            let tags = entry_tags.iter().map(|t| JsonValue::from(*t)).collect();
            obj.insert("extra_tags".into(), JsonValue::Array(tags));
        }

        // Per-entry comment (CDH `file_comment` field) — separate from
        // the archive-level EOCD comment. Used in some packaging tools
        // legitimately; abused for out-of-band config strings.
        let entry_comment = entry.comment();
        if !entry_comment.is_empty() {
            entry_comment_count += 1;
            entry_comment_size += entry_comment.len() as u64;
            obj.insert(
                "comment_size".into(),
                JsonValue::from(entry_comment.len() as u64),
            );
        }

        members.push(JsonValue::Object(obj));
        archive_members.push(member);
    }

    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    stats.emit(values, metrics);
    metrics.insert(metric!("archive.member_count"), archive.len() as f64);
    metrics.insert(metric!("archive.extra_field_size"), extra_field_size as f64);
    if !extra_field_tags.is_empty() {
        let tags = extra_field_tags
            .iter()
            .map(|t| JsonValue::from(*t))
            .collect();
        values.insert_key(
            value_key!("archive.extra_field_tags"),
            JsonValue::Array(tags),
        );
    }
    if uses_zip64 {
        metrics.insert(metric!("archive.uses_zip64"), 1.0);
    }
    if has_comment {
        metrics.insert(metric!("archive.has_comment"), 1.0);
    }
    metrics.insert(
        metric!("archive.entry_comment_count"),
        entry_comment_count as f64,
    );
    if entry_comment_size > 0 {
        metrics.insert(
            metric!("archive.entry_comment_size"),
            entry_comment_size as f64,
        );
    }

    // Duplicate-name and CRC-collision detection. The `zip` crate
    // deduplicates the central directory by name at parse time, so the
    // per-member loop above can't see shadowed entries — walk the raw
    // CDH bytes directly to catch the ZIP-confusion attack shape.
    let cd_start = archive.central_directory_start() as usize;
    let raw_entries = scan_central_directory(bytes, cd_start);

    let mut name_counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut crc_counts: BTreeMap<u32, u64> = BTreeMap::new();
    for e in &raw_entries {
        *name_counts.entry(e.name.as_str()).or_insert(0) += 1;
        if e.uncompressed_size > 0 {
            *crc_counts.entry(e.crc32).or_insert(0) += 1;
        }
    }

    let mut duplicate_member_count: u64 = 0;
    let mut duplicate_names: Vec<JsonValue> = Vec::new();
    for (name, count) in &name_counts {
        if *count > 1 {
            duplicate_member_count += count - 1;
            if duplicate_names.len() < 16 {
                duplicate_names.push(JsonValue::String((*name).to_string()));
            }
        }
    }
    metrics.insert(
        metric!("archive.duplicate_member_count"),
        duplicate_member_count as f64,
    );
    if !duplicate_names.is_empty() {
        values.insert_key(
            value_key!("archive.duplicate_member_names"),
            JsonValue::Array(duplicate_names),
        );
    }

    // CRC collisions: how many *extra* entries share a CRC32 with a
    // prior one (excluding zero-size entries, which all share CRC=0).
    let crc_collision_count: u64 = crc_counts.values().map(|c| c.saturating_sub(1)).sum();
    metrics.insert(
        metric!("archive.crc_collision_count"),
        crc_collision_count as f64,
    );

    // Sentinel mtime count derived from the raw CDH (the zip crate's
    // dedup keeps only one entry per name, hiding sentinel-mtime
    // duplicates from the per-member loop). Recompute from raw — the
    // value-add is that this also catches duplicates' sentinel state.
    let raw_sentinel_count = raw_entries
        .iter()
        .filter(|e| e.parsed_mtime.is_none())
        .count() as u64;
    metrics.insert(
        metric!("archive.timing.sentinel_mtime_count"),
        stats.untimed().max(raw_sentinel_count) as f64,
    );

    // Mozilla / JAR signing-pipeline detection: existence of the
    // signature-chain files in `META-INF/` is a benign-build attestation
    // (not a cryptographic verification). Emit the structural marker; the
    // consumer decides what to do with it.
    let signed_marker = members_includes(archive, "META-INF/cose.manifest")
        && members_includes(archive, "META-INF/cose.sig");
    if signed_marker {
        values.insert_key(
            value_key!("archive.signing.mozilla_extension_shape"),
            JsonValue::Bool(true),
        );
    }

    // Also report `archive.signing.jar_signed_shape` when META-INF/*.SF
    // and META-INF/*.RSA both exist.
    let jar_signed_shape = archive_names(archive)
        .any(|n| n.starts_with("META-INF/") && n.ends_with(".SF"))
        && archive_names(archive)
            .any(|n| n.starts_with("META-INF/") && (n.ends_with(".RSA") || n.ends_with(".DSA")));
    if jar_signed_shape {
        values.insert_key(
            value_key!("archive.signing.jar_signed_shape"),
            JsonValue::Bool(true),
        );
    }

    // Chrome Web Store signed-extension shape. The `_metadata/verified_contents.json`
    // entry is the canonical marker; it is unique to the Chrome web-store
    // signing pipeline and lets a CRX-renamed-to-.zip be told apart from
    // a generic ZIP without inspecting the CRX header.
    if members_includes(archive, "_metadata/verified_contents.json") {
        values.insert_key(
            value_key!("archive.signing.chrome_webstore_shape"),
            JsonValue::Bool(true),
        );
    }

    // Container-level structural facts derived from the raw byte stream:
    // prefix bytes before the first LFH (self-extracting stubs / polyglots)
    // and trailing bytes after the EOCD record (appended payloads).
    let prefix = scan_prefix_bytes(bytes);
    if prefix > 0 {
        metrics.insert(metric!("archive.leading_bytes"), prefix as f64);
    }
    let trailing = scan_trailing_bytes(bytes);
    if trailing > 0 {
        metrics.insert(metric!("archive.trailing_bytes"), trailing as f64);
    }

    Ok(())
}

/// One central-directory entry as recovered by the raw walker. The
/// fields are the subset filefacts needs for duplicate / CRC collision
/// / sentinel-mtime detection — *not* a full CDH model.
struct RawCdhEntry {
    name: String,
    crc32: u32,
    uncompressed_size: u64,
    parsed_mtime: Option<i64>,
}

/// Fixed part of a central-directory file header, before the name.
const CDH_FIXED_LEN: usize = 46;

/// Walk the raw central directory and return every entry — including
/// duplicates that the `zip` crate's name-keyed map collapses. Starts
/// at `cd_start` (the byte offset reported by `central_directory_start`)
/// and stops when it can no longer find a `PK\x01\x02` signature.
fn scan_central_directory(bytes: &[u8], cd_start: usize) -> Vec<RawCdhEntry> {
    let mut out = Vec::new();
    let mut i = cd_start;
    while let Some(header) = bytes
        .get(i..)
        .and_then(|rest| rest.first_chunk::<CDH_FIXED_LEN>())
    {
        if !header.starts_with(b"PK\x01\x02") {
            break;
        }
        // Every field sits inside the fixed header just read.
        let u16_at = |off| bytes_at::u16_le(header, off).unwrap_or(0);
        let u32_at = |off| bytes_at::u32_le(header, off).unwrap_or(0);
        let name_len = usize::from(u16_at(28));
        let extra_len = usize::from(u16_at(30));
        let comment_len = usize::from(u16_at(32));
        let name_start = i + CDH_FIXED_LEN;
        let name_end = name_start + name_len;
        let Some(name) = bytes.get(name_start..name_end) else {
            break;
        };
        let parsed_mtime = ::zip::DateTime::try_from_msdos(u16_at(14), u16_at(12))
            .ok()
            .and_then(crate::scan::zip_datetime_to_unix);
        out.push(RawCdhEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            crc32: u32_at(16),
            uncompressed_size: u64::from(u32_at(24)),
            parsed_mtime,
        });
        i = name_end + extra_len + comment_len;
    }
    out
}

/// Walk an extra-field TLV blob and return the set of tag IDs present.
/// Format: `[u16 tag][u16 size][size bytes]` repeating. Malformed input
/// (a length that would overrun the buffer) stops the walk silently.
pub(super) fn enumerate_extra_tags(extra: &[u8]) -> BTreeSet<u16> {
    let mut tags = BTreeSet::new();
    let mut i = 0usize;
    while let Some(&[t0, t1, s0, s1]) = extra.get(i..).and_then(|rest| rest.first_chunk::<4>()) {
        tags.insert(u16::from_le_bytes([t0, t1]));
        let size = usize::from(u16::from_le_bytes([s0, s1]));
        let Some(next) = i.checked_add(4).and_then(|n| n.checked_add(size)) else {
            break;
        };
        if next > extra.len() {
            break;
        }
        i = next;
    }
    tags
}

/// Offset of the first ZIP local-file-header signature `PK\x03\x04`.
/// Returning >0 means the archive carries a prefix (self-extracting
/// stub, polyglot, or appended-front payload). The `zip` crate parses
/// such archives correctly because EOCD offsets are relative to the
/// start of stream, but the prefix is still container-level data
/// outside any signed-content scheme.
fn scan_prefix_bytes(bytes: &[u8]) -> usize {
    memchr::memmem::find(bytes, b"PK\x03\x04").unwrap_or(0)
}

/// Bytes appended after the End-of-Central-Directory record's stated
/// end (EOCD offset + 22 + comment length). A non-zero value means an
/// attacker (or an aggressive concatenator) stuck data on the end of
/// the archive that the canonical EOCD doesn't account for.
fn scan_trailing_bytes(bytes: &[u8]) -> usize {
    let Some(eocd_offset) = find_eocd(bytes) else {
        return 0;
    };
    // The comment length is the record's last fixed field, at +20.
    let Some(comment_len) = bytes_at::u16_le(bytes, eocd_offset + 20) else {
        return 0;
    };
    let end = eocd_offset + 22 + usize::from(comment_len);
    bytes.len().saturating_sub(end)
}

/// Locate the End-of-Central-Directory signature `PK\x05\x06`. ZIP
/// readers scan backward from EOF over at most 64 KiB + 22 because the
/// EOCD itself is 22 bytes and the comment can be up to 65 535 bytes.
/// Returns the offset of the last EOCD signature in that window, or
/// `None` if not found.
fn find_eocd(bytes: &[u8]) -> Option<usize> {
    const MAX_COMMENT_LEN: usize = 65_535;
    const EOCD_LEN: usize = 22;
    if bytes.len() < EOCD_LEN {
        return None;
    }
    let scan_start = bytes.len().saturating_sub(MAX_COMMENT_LEN + EOCD_LEN);
    let window = bytes.get(scan_start..)?;
    memchr::memmem::rfind(window, b"PK\x05\x06").map(|i| scan_start + i)
}

fn archive_names<R: std::io::Read + std::io::Seek>(
    archive: &ZipArchive<R>,
) -> impl Iterator<Item = &str> {
    archive.file_names()
}

fn members_includes<R: std::io::Read + std::io::Seek>(
    archive: &ZipArchive<R>,
    needle: &str,
) -> bool {
    archive.file_names().any(|n| n == needle)
}

fn compression_method_name(method: CompressionMethod) -> &'static str {
    match method {
        CompressionMethod::Stored => "stored",
        CompressionMethod::Deflated => "deflate",
        CompressionMethod::Bzip2 => "bzip2",
        CompressionMethod::Zstd => "zstd",
        CompressionMethod::Lzma => "lzma",
        CompressionMethod::Xz => "xz",
        CompressionMethod::Aes => "aes",
        _ => "other",
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests;
