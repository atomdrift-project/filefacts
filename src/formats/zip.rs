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
    ZipArchive::new(Cursor::new(bytes)).map_err(|e| Error::malformed("zip", e.to_string()))
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
    values.insert("archive.format.kind", JsonValue::String("zip".into()));

    let comment = archive.comment();
    let has_comment = !comment.is_empty();
    if has_comment {
        let comment_str = String::from_utf8_lossy(comment).into_owned();
        values.insert("archive.comment", JsonValue::String(comment_str));
        metrics.insert(metric!("archive.comment_size"), comment.len() as f64);
    }

    // Entries past the cap are not walked, so every per-member list and
    // count below covers the first `walked` entries; `archive.member_count`
    // still reports the full parsed count.
    let walked = archive.len().min(max_members);
    if walked < archive.len() {
        values.insert(
            "zip.limits",
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
            .map_err(|e| Error::malformed("zip", format!("entry {i}: {e}")))?;

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

    values.insert("archive.members", JsonValue::Array(members));
    stats.emit(values, metrics);
    metrics.insert(metric!("archive.member_count"), archive.len() as f64);
    metrics.insert(metric!("archive.extra_field_size"), extra_field_size as f64);
    if !extra_field_tags.is_empty() {
        let tags = extra_field_tags
            .iter()
            .map(|t| JsonValue::from(*t))
            .collect();
        values.insert("archive.extra_field_tags", JsonValue::Array(tags));
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
        values.insert(
            "archive.duplicate_member_names",
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
        values.insert(
            "archive.signing.mozilla_extension_shape",
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
        values.insert("archive.signing.jar_signed_shape", JsonValue::Bool(true));
    }

    // Chrome Web Store signed-extension shape. The `_metadata/verified_contents.json`
    // entry is the canonical marker; it is unique to the Chrome web-store
    // signing pipeline and lets a CRX-renamed-to-.zip be told apart from
    // a generic ZIP without inspecting the CRX header.
    if members_includes(archive, "_metadata/verified_contents.json") {
        values.insert(
            "archive.signing.chrome_webstore_shape",
            JsonValue::Bool(true),
        );
    }

    // Container-level structural facts derived from the raw byte stream:
    // prefix bytes before the first LFH (self-extracting stubs / polyglots)
    // and trailing bytes after the EOCD record (appended payloads).
    let prefix = scan_prefix_bytes(bytes);
    if prefix > 0 {
        metrics.insert(metric!("archive.prefix_bytes"), prefix as f64);
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
mod tests {
    use super::*;
    use crate::output::{Metrics, Values};
    use std::io::Cursor;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut archive_members = Vec::new();
        let _ = extract(bytes, &mut v, &mut m, &mut archive_members);
        (v, m)
    }

    /// Build an in-memory zip with the given members. Each tuple:
    /// `(path, body, compression_method, last_modified_unix)`.
    fn build_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            for (path, body, method) in entries {
                let opts = SimpleFileOptions::default()
                    .compression_method(*method)
                    .unix_permissions(0o644);
                w.start_file(*path, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    /// The member walk stops at the cap and says so; the uncapped count stays
    /// in `archive.member_count`.
    #[test]
    fn member_walk_stops_at_cap_and_records_limit() {
        let z = build_zip(&[
            ("a.txt", b"a", CompressionMethod::Stored),
            ("b.txt", b"b", CompressionMethod::Stored),
            ("c.txt", b"c", CompressionMethod::Stored),
        ]);
        let mut archive = open_archive(&z).unwrap();
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut typed = Vec::new();
        walk_archive(&mut archive, &z, &mut v, &mut m, &mut typed, 2).unwrap();

        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(typed.len(), 2);
        assert_eq!(m.get("archive.file_count"), Some(2.0));
        assert_eq!(m.get("archive.member_count"), Some(3.0));
        let limits = v.get("zip.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits[0]["stage"].as_str(), Some("member-cap"));

        // Under the cap, nothing is recorded.
        let (v, _) = run(&z);
        assert!(v.get("zip.limits").is_none());
    }

    #[test]
    fn compression_names_are_stable() {
        assert_eq!(compression_method_name(CompressionMethod::Stored), "stored");
        assert_eq!(
            compression_method_name(CompressionMethod::Deflated),
            "deflate"
        );
    }

    #[test]
    fn surfaces_member_listing_and_per_member_fields() {
        let z = build_zip(&[
            ("file.txt", b"hello world", CompressionMethod::Stored),
            (
                "nested/file.bin",
                b"\x00\x01\x02\x03",
                CompressionMethod::Deflated,
            ),
        ]);
        let (v, m) = run(&z);
        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert_eq!(members.len(), 2);
        let m0 = members[0].as_object().unwrap();
        assert_eq!(m0["path"].as_str(), Some("file.txt"));
        assert_eq!(m0["compression_method"].as_str(), Some("stored"));
        assert_eq!(m0["entry_type"].as_str(), Some("regular"));
        assert_eq!(m.get("archive.member_count"), Some(2.0));
    }

    #[test]
    fn format_kind_set_to_zip() {
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.format.kind").and_then(|x| x.as_str()),
            Some("zip")
        );
    }

    #[test]
    fn compression_methods_array_unique() {
        let z = build_zip(&[
            ("a", b"x", CompressionMethod::Stored),
            ("b", b"y", CompressionMethod::Stored),
            ("c", b"z", CompressionMethod::Deflated),
        ]);
        let (v, _) = run(&z);
        let methods = v
            .get("archive.compression.methods")
            .and_then(|x| x.as_array())
            .unwrap();
        let names: Vec<&str> = methods.iter().filter_map(|x| x.as_str()).collect();
        // BTreeMap iteration order is alphabetical: deflate, stored.
        assert_eq!(names, vec!["deflate", "stored"]);
    }

    #[test]
    fn compression_ratio_present_when_uncompressed_nonzero() {
        let z = build_zip(&[(
            "big.txt",
            &b"abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij".repeat(20),
            CompressionMethod::Deflated,
        )]);
        let (_, m) = run(&z);
        let r = m.get("archive.compression.ratio").unwrap();
        assert!(r > 0.0 && r < 1.0, "expected ratio in (0,1), got {r}");
    }

    #[test]
    fn jar_signed_shape_detected() {
        let z = build_zip(&[
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\n",
                CompressionMethod::Stored,
            ),
            ("META-INF/CERT.SF", b"sigfile", CompressionMethod::Stored),
            ("META-INF/CERT.RSA", b"\x00\x01", CompressionMethod::Stored),
            ("Main.class", b"\xca\xfe\xba\xbe", CompressionMethod::Stored),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.signing.jar_signed_shape")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
        // mozilla-extension shape needs cose.manifest + cose.sig; not set here.
        assert!(v.get("archive.signing.mozilla_extension_shape").is_none());
    }

    #[test]
    fn mozilla_extension_shape_detected() {
        let z = build_zip(&[
            (
                "META-INF/cose.manifest",
                b"mozcose",
                CompressionMethod::Stored,
            ),
            ("META-INF/cose.sig", b"\xde\xad", CompressionMethod::Stored),
            ("manifest.json", b"{}", CompressionMethod::Stored),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.signing.mozilla_extension_shape")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn empty_zip_emits_empty_member_list() {
        let z = build_zip(&[]);
        let (v, m) = run(&z);
        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert!(members.is_empty());
        assert_eq!(m.get("archive.member_count"), Some(0.0));
    }

    #[test]
    fn non_zip_input_rejected_silently() {
        // Bytes that don't start with PK\x03\x04 — extract returns Err
        // (which filefacts' dispatcher swallows). Values left empty.
        let (v, _) = run(b"not a zip");
        assert!(v.get("archive.members").is_none());
    }

    #[test]
    fn aggregate_method_counts_per_compression() {
        let z = build_zip(&[
            ("a", b"x", CompressionMethod::Stored),
            ("b", b"y", CompressionMethod::Deflated),
            ("c", b"z", CompressionMethod::Deflated),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.compression.method_counts.stored"), Some(1.0));
        assert_eq!(
            m.get("archive.compression.method_counts.deflate"),
            Some(2.0)
        );
    }

    #[test]
    fn truncated_zip_doesnt_crash() {
        // Take a valid zip and chop most of it off.
        let z = build_zip(&[("a", b"hello", CompressionMethod::Stored)]);
        let truncated = &z[..z.len() / 2];
        let (_, _) = run(truncated);
        // No assertions — we only care that it didn't panic.
    }

    // ---- Ported `ArchiveMetrics` aggregates ----

    #[test]
    fn file_and_directory_counts_track_member_kinds() {
        // ZipWriter::add_directory creates a real directory entry.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(0o644);
            w.add_directory("dir/", opts).unwrap();
            w.start_file("dir/a", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("dir/b", opts).unwrap();
            w.write_all(b"y").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.file_count"), Some(2.0));
        assert_eq!(m.get("archive.directory_count"), Some(1.0));
    }

    #[test]
    fn totals_and_compression_ratio() {
        let z = build_zip(&[
            ("a", b"abcdefghij", CompressionMethod::Stored),
            ("b", b"klmnop", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.uncompressed_size"), Some(16.0));
        assert!(m.get("archive.compressed_size").unwrap() >= 16.0);
        // Canonical nested namespace only — flat `archive.compression_ratio`
        // alias retired.
        assert!(m.get("archive.compression.ratio").is_some());
    }

    #[test]
    fn hidden_file_count_includes_dotfiles_anywhere_in_path() {
        let z = build_zip(&[
            (".hidden", b"x", CompressionMethod::Stored),
            ("normal", b"x", CompressionMethod::Stored),
            ("nested/.dot/file", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.hidden_file_count"), Some(2.0));
    }

    #[test]
    fn path_traversal_count_flags_dotdot_components() {
        let z = build_zip(&[
            ("../escape", b"x", CompressionMethod::Stored),
            ("ok/file", b"x", CompressionMethod::Stored),
            ("/absolute", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.path_traversal_count"), Some(2.0));
    }

    #[test]
    fn script_and_executable_counts() {
        let z = build_zip(&[
            ("run.sh", b"#!/bin/sh\n", CompressionMethod::Stored),
            ("setup.py", b"x", CompressionMethod::Stored),
            ("payload.exe", b"x", CompressionMethod::Stored),
            ("readme.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.script_count"), Some(2.0));
        assert_eq!(m.get("archive.executable_count"), Some(1.0));
    }

    #[test]
    fn unicode_and_rtlo_filename_flags() {
        // U+202E is RIGHT-TO-LEFT OVERRIDE; payload.exe rendered as fxe.daolyap.
        let rtlo_name = "payload\u{202e}fdp.exe";
        let z = build_zip(&[
            ("résumé.pdf", b"x", CompressionMethod::Stored),
            (rtlo_name, b"x", CompressionMethod::Stored),
            ("ascii.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.unicode_filename_count"), Some(2.0));
        assert_eq!(m.get("archive.rtlo_filename_count"), Some(1.0));
    }

    #[test]
    fn double_extension_flag() {
        let z = build_zip(&[
            ("invoice.pdf.exe", b"x", CompressionMethod::Stored),
            ("photo.jpg.scr", b"x", CompressionMethod::Stored),
            ("ok.tar.gz", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        // pdf+exe and jpg+scr both match; tar+gz doesn't (gz isn't executable).
        assert_eq!(m.get("archive.double_extension_count"), Some(2.0));
    }

    #[test]
    fn nested_archive_count() {
        let z = build_zip(&[
            ("inner.zip", b"PK\x05\x06", CompressionMethod::Stored),
            ("payload.tar.gz", b"x", CompressionMethod::Stored),
            ("readme.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.nested_archive_count"), Some(2.0));
    }

    #[test]
    fn has_comment_flag_when_archive_has_global_comment() {
        // Build a zip with a comment.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.set_raw_comment(b"hello world".to_vec().into_boxed_slice());
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            w.start_file("a", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.has_comment"), Some(1.0));
    }

    /// Canonical key list emitted by the ZIP extractor. The test fails
    /// loudly when filefacts stops emitting any of these keys for a
    /// realistic archive — protects traits referencing them from
    /// silent disappearance.
    #[test]
    fn full_archive_key_set_emitted_for_realistic_zip() {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.set_raw_comment(b"build comment".to_vec().into_boxed_slice());
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644)
                .last_modified_time(zip::DateTime::default());
            w.add_directory("dir/", opts).unwrap();
            w.start_file("dir/a.txt", opts).unwrap();
            w.write_all(b"hello world").unwrap();
            w.start_file("dir/script.sh", opts.unix_permissions(0o755))
                .unwrap();
            w.write_all(b"#!/bin/sh\n").unwrap();
            w.start_file("payload.exe", opts).unwrap();
            w.write_all(b"\x4d\x5a").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());

        // Every key listed here must remain present — adding new keys is fine;
        // dropping one is a breaking change requiring a trait/comment update.
        for key in [
            "archive.member_count",
            "archive.file_count",
            "archive.directory_count",
            "archive.uncompressed_size",
            "archive.compressed_size",
            "archive.compression.ratio",
            "archive.max_filename_length",
            "archive.hidden_file_count",
            "archive.path_traversal_count",
            "archive.symlink_escape_count",
            "archive.executable_count",
            "archive.script_count",
            "archive.unicode_filename_count",
            "archive.homoglyph_filename_count",
            "archive.double_extension_count",
            "archive.rtlo_filename_count",
            "archive.nested_archive_count",
            "archive.misplaced_executable_count",
            "archive.extra_field_size",
            "archive.security.setuid_count",
            "archive.security.setgid_count",
            "archive.security.sticky_count",
            "archive.security.world_writable_count",
            "archive.security.symlink_count",
            "archive.security.encrypted_count",
            "archive.has_comment",
        ] {
            assert!(
                m.get(key).is_some(),
                "missing required archive metric key: {key}"
            );
        }
    }

    #[test]
    fn max_filename_length_tracks_longest_entry() {
        let long = "a".repeat(120);
        let z = build_zip(&[
            ("short", b"x", CompressionMethod::Stored),
            (long.as_str(), b"y", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.max_filename_length"), Some(120.0));
    }

    // ---- Extra-field tag enumeration (task 3) ----

    #[test]
    fn enumerate_extra_tags_handles_known_tlv_stream() {
        // Two well-formed TLVs back-to-back: Unicode Path (0x7075) with 3
        // bytes of body, followed by NTFS times (0x000a) with 4 bytes.
        let extra = &[
            0x75, 0x70, 0x03, 0x00, b'a', b'b', b'c', 0x0a, 0x00, 0x04, 0x00, 1, 2, 3, 4,
        ];
        let tags = enumerate_extra_tags(extra);
        assert!(tags.contains(&0x7075));
        assert!(tags.contains(&0x000a));
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn enumerate_extra_tags_stops_on_overrun() {
        // Header claims 100 bytes of body but only 2 are present —
        // walker must stop without panic and report the single tag it
        // managed to read (the tag header itself is intact).
        let extra = &[0x01, 0x00, 100, 0x00, 0xde, 0xad];
        let tags = enumerate_extra_tags(extra);
        assert!(tags.contains(&0x0001));
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn enumerate_extra_tags_empty_input_is_empty() {
        assert!(enumerate_extra_tags(&[]).is_empty());
    }

    // ---- Out-of-band smuggling detectors (task 4) ----

    #[test]
    fn comment_size_emitted_when_archive_has_comment() {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.set_raw_comment(b"hello".to_vec().into_boxed_slice());
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            w.start_file("a", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.comment_size"), Some(5.0));
    }

    #[test]
    fn prefix_bytes_detected_for_polyglot_with_leading_payload() {
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        // Prepend a 16-byte stub before the first local file header.
        let mut polyglot = b"\x00".repeat(16);
        polyglot.extend_from_slice(&z);
        let (_, m) = run(&polyglot);
        assert_eq!(m.get("archive.prefix_bytes"), Some(16.0));
    }

    #[test]
    fn trailing_bytes_detected_for_appended_payload() {
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        let mut tampered = z.clone();
        tampered.extend_from_slice(b"appended-data-here");
        let (_, m) = run(&tampered);
        assert_eq!(m.get("archive.trailing_bytes"), Some(18.0));
    }

    #[test]
    fn no_prefix_or_trailing_for_clean_archive() {
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        let (_, m) = run(&z);
        assert!(m.get("archive.prefix_bytes").is_none());
        assert!(m.get("archive.trailing_bytes").is_none());
    }

    /// Build a minimal hand-rolled ZIP with two CDH entries pointing at
    /// the *same* local-file body and the same on-disk name. ZipWriter
    /// rejects duplicate names, so this exercises the duplicate-name
    /// detector with raw bytes — exactly the ZIP-confusion attack
    /// shape (one CDH-only, one LFH+CDH, two paths winning).
    fn build_duplicate_name_zip() -> Vec<u8> {
        let mut out = Vec::new();
        let name = b"dup.txt";
        let body = b"hello";
        let crc = crc32fast::hash(body);

        // Single local file header + body.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method = stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes()); // crc
        out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // csize
        out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // usize
        out.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(body);

        let lfh_offset: u32 = 0;
        let cd_start = out.len() as u32;

        // Two central-directory entries pointing at the same LFH.
        for _ in 0..2 {
            out.extend_from_slice(b"PK\x01\x02");
            out.extend_from_slice(&0x031Eu16.to_le_bytes()); // version made by
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(&0u16.to_le_bytes()); // comment len
            out.extend_from_slice(&0u16.to_le_bytes()); // disk
            out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            out.extend_from_slice(&lfh_offset.to_le_bytes());
            out.extend_from_slice(name);
        }

        let cd_size = (out.len() as u32) - cd_start;

        // EOCD
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // disk start
        out.extend_from_slice(&2u16.to_le_bytes()); // entries on disk
        out.extend_from_slice(&2u16.to_le_bytes()); // total entries
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len

        out
    }

    #[test]
    fn duplicate_member_count_detects_zip_confusion() {
        let z = build_duplicate_name_zip();
        let (v, m) = run(&z);
        // Two CDH entries with the same name → one duplicate beyond the first.
        assert_eq!(m.get("archive.duplicate_member_count"), Some(1.0));
        let names = v
            .get("archive.duplicate_member_names")
            .and_then(|x| x.as_array())
            .expect("duplicate names emitted");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), Some("dup.txt"));
    }

    #[test]
    fn crc_collision_count_detects_identical_bodies() {
        // Two files with identical bodies → identical CRC32.
        let z = build_zip(&[
            ("one.txt", b"identical body", CompressionMethod::Stored),
            ("two.txt", b"identical body", CompressionMethod::Stored),
            ("three.txt", b"different", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.crc_collision_count"), Some(1.0));
    }

    /// A Zip64 archive whose entries declare `sizes` (both compressed and
    /// uncompressed). The sizes are never backed by data; the central
    /// directory is all the extractor reads.
    fn zip64_with_sizes(sizes: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (i, &size) in sizes.iter().enumerate() {
            let name = format!("f{i}.bin");
            let lfh = out.len() as u64;
            out.extend_from_slice(b"PK\x03\x04");
            for v in [45u16, 0, 0, 0, 0x21] {
                out.extend(v.to_le_bytes());
            }
            for v in [0u32, u32::MAX, u32::MAX] {
                out.extend(v.to_le_bytes());
            }
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(20u16.to_le_bytes());
            out.extend(name.as_bytes());
            for v in [1u16, 16] {
                out.extend(v.to_le_bytes());
            }
            out.extend(size.to_le_bytes());
            out.extend(size.to_le_bytes());

            cd.extend_from_slice(b"PK\x01\x02");
            for v in [0x032Du16, 45, 0, 0, 0, 0x21] {
                cd.extend(v.to_le_bytes());
            }
            for v in [0u32, u32::MAX, u32::MAX] {
                cd.extend(v.to_le_bytes());
            }
            for v in [name.len() as u16, 28, 0, 0, 0] {
                cd.extend(v.to_le_bytes());
            }
            for v in [0u32, u32::MAX] {
                cd.extend(v.to_le_bytes());
            }
            cd.extend(name.as_bytes());
            for v in [1u16, 24] {
                cd.extend(v.to_le_bytes());
            }
            for v in [size, size, lfh] {
                cd.extend(v.to_le_bytes());
            }
        }
        let cd_offset = out.len() as u64;
        out.extend(&cd);
        let eocd64 = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x06");
        out.extend(44u64.to_le_bytes());
        for v in [45u16, 45] {
            out.extend(v.to_le_bytes());
        }
        for v in [0u32, 0] {
            out.extend(v.to_le_bytes());
        }
        for v in [
            sizes.len() as u64,
            sizes.len() as u64,
            cd.len() as u64,
            cd_offset,
        ] {
            out.extend(v.to_le_bytes());
        }
        out.extend_from_slice(b"PK\x06\x07");
        out.extend(0u32.to_le_bytes());
        out.extend(eocd64.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        out.extend_from_slice(b"PK\x05\x06");
        for v in [0u16, 0, u16::MAX, u16::MAX] {
            out.extend(v.to_le_bytes());
        }
        for v in [u32::MAX, u32::MAX] {
            out.extend(v.to_le_bytes());
        }
        out.extend(0u16.to_le_bytes());
        out
    }

    /// Declared Zip64 sizes summing past `u64::MAX` overflowed the size
    /// totals: a panic in builds with overflow checks, a wrapped total
    /// otherwise.
    #[test]
    fn zip64_size_totals_saturate() {
        let z = zip64_with_sizes(&[1 << 63, 1 << 63]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.member_count"), Some(2.0));
        assert_eq!(m.get("archive.uncompressed_size"), Some(u64::MAX as f64));
        assert_eq!(m.get("archive.compressed_size"), Some(u64::MAX as f64));
    }

    #[test]
    fn crc_collision_ignores_zero_size_entries() {
        // Two empty files share CRC32=0 but aren't a real collision.
        let z = build_zip(&[
            ("empty1", b"", CompressionMethod::Stored),
            ("empty2", b"", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.crc_collision_count"), Some(0.0));
    }

    #[test]
    fn find_eocd_locates_signature_at_end_of_clean_zip() {
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        let offset = find_eocd(&z).unwrap();
        assert_eq!(&z[offset..offset + 4], b"PK\x05\x06");
        // Clean zip → EOCD sits exactly 22 bytes from the end.
        assert_eq!(offset, z.len() - 22);
    }

    #[test]
    fn find_eocd_returns_none_for_too_short_input() {
        assert!(find_eocd(b"PK").is_none());
    }

    // ---- Timestamp anomalies (task 5) ----

    #[test]
    fn sentinel_mtime_count_counts_unparseable_dates() {
        // ZipWriter always emits a valid DateTime, so we hand-roll a
        // zip with mod_date=0 mod_time=0 (day=0 month=0 → unparseable,
        // matching the Mozilla "(1980, 0, 0) no recorded timestamp"
        // shape that filefacts treats as a sentinel).
        let z = build_duplicate_name_zip();
        let (_, m) = run(&z);
        // The hand-rolled archive has 2 CDH entries both at the sentinel.
        assert_eq!(m.get("archive.timing.sentinel_mtime_count"), Some(2.0));
    }

    #[test]
    fn dominant_mtime_outlier_detected_for_supply_chain_drop() {
        // Three files at sentinel + one file with a real future mtime —
        // the classic "attacker dropped one extra entry" signal.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            w.start_file("a", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("b", opts).unwrap();
            w.write_all(b"y").unwrap();
            w.start_file("c", opts).unwrap();
            w.write_all(b"z").unwrap();
            let real = zip::DateTime::from_date_and_time(2025, 6, 15, 12, 0, 0).unwrap();
            w.start_file("payload.dropped", opts.last_modified_time(real))
                .unwrap();
            w.write_all(b"!").unwrap();
            w.finish().unwrap();
        }
        let (v, m) = run(&buf.into_inner());
        // Three of four entries share the sentinel bucket → fraction = 0.75.
        let fraction = m.get("archive.timing.mtime_dominant_fraction").unwrap();
        assert!(
            (fraction - 0.75).abs() < 1e-9,
            "expected ~0.75, got {fraction}"
        );
        assert_eq!(m.get("archive.timing.mtime_outlier_count"), Some(1.0));
        let outliers = v
            .get("archive.timing.mtime_outlier_members")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(outliers.len(), 1);
        assert_eq!(outliers[0].as_str(), Some("payload.dropped"));
    }

    #[test]
    fn no_outliers_emitted_when_no_dominant_majority() {
        // Two distinct buckets, 1 entry each — neither is a majority.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            let d1 = zip::DateTime::from_date_and_time(2020, 1, 1, 0, 0, 0).unwrap();
            let d2 = zip::DateTime::from_date_and_time(2025, 1, 1, 0, 0, 0).unwrap();
            w.start_file("a", opts.last_modified_time(d1)).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("b", opts.last_modified_time(d2)).unwrap();
            w.write_all(b"y").unwrap();
            w.finish().unwrap();
        }
        let (v, m) = run(&buf.into_inner());
        // Dominant fraction is 0.5, not strictly greater → no outliers.
        assert_eq!(m.get("archive.timing.mtime_dominant_fraction"), Some(0.5));
        assert!(m.get("archive.timing.mtime_outlier_count").is_none());
        assert!(v.get("archive.timing.mtime_outlier_members").is_none());
    }

    #[test]
    fn mtime_unique_ratio_one_when_all_distinct() {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            let d1 = zip::DateTime::from_date_and_time(2020, 1, 1, 0, 0, 0).unwrap();
            let d2 = zip::DateTime::from_date_and_time(2021, 1, 1, 0, 0, 0).unwrap();
            w.start_file("a", opts.last_modified_time(d1)).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("b", opts.last_modified_time(d2)).unwrap();
            w.write_all(b"y").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.timing.mtime_unique_ratio"), Some(1.0));
    }

    #[test]
    fn future_mtime_count_flags_year_2100_plus() {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            let future = zip::DateTime::from_date_and_time(2107, 12, 31, 23, 59, 58).unwrap();
            w.start_file("a", opts.last_modified_time(future)).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.timing.future_mtime_count"), Some(1.0));
    }

    // ---- Noise files + Chrome web-store shape (task 6) ----

    #[test]
    fn noise_file_count_tracks_developer_detritus() {
        let z = build_zip(&[
            ("__MACOSX/foo", b"x", CompressionMethod::Stored),
            ("subdir/.DS_Store", b"x", CompressionMethod::Stored),
            ("Thumbs.db", b"x", CompressionMethod::Stored),
            ("desktop.ini", b"x", CompressionMethod::Stored),
            ("clean.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.noise_file_count"), Some(4.0));
    }

    #[test]
    fn chrome_webstore_shape_detected() {
        let z = build_zip(&[
            (
                "_metadata/verified_contents.json",
                b"{}",
                CompressionMethod::Stored,
            ),
            ("manifest.json", b"{}", CompressionMethod::Stored),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.signing.chrome_webstore_shape")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
    }

    // ---- Per-entry extra_tags surface ----

    #[test]
    fn extra_field_tags_aggregated_at_archive_level() {
        // ZipWriter at default settings doesn't synthesize Unicode-path
        // extras, but Mach-O and NTFS-times extras are sometimes added
        // by Info-ZIP. Building a clean archive: extra_field_tags is
        // either absent or contains tags the writer chose to emit. The
        // important invariant is that *when* extras exist, they parse
        // to a deduped sorted u16 set — already covered by
        // enumerate_extra_tags_handles_known_tlv_stream.
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        let (v, _) = run(&z);
        // Either absent (no extras) or a JSON array of numbers.
        if let Some(arr) = v.get("archive.extra_field_tags").and_then(|x| x.as_array()) {
            for item in arr {
                assert!(item.as_u64().is_some());
            }
        }
    }
}
