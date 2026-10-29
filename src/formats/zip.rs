//! ZIP archive-index extractor.
//!
//! The walk reads the central directory only. The output is the full member
//! listing, the archive comment, and a few per-entry forensic fields drawn
//! from the central-directory header. Package layers built on a ZIP read a
//! few named members (manifests, signature blocks) through [`read_member`],
//! which caps what it inflates; everything else is the caller's to unpack:
//! `filefacts` describes what's *in* the archive, not what each member
//! *contains*.
//!
//! The `zip` crate checks every local file header while opening an archive,
//! but Android and Java read members through the central directory alone.
//! One corrupted local header therefore hides an APK from the crate while
//! the device installs it — a known anti-analysis shape. [`open`] restores
//! the local-header signatures the central directory points at and tries
//! again, and when even that fails, the member listing still comes from the
//! raw central directory.

use crate::metric;
use crate::value_key;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;

use serde_json::Value as JsonValue;
use zip::result::ZipError;
use zip::{CompressionMethod, ZipArchive};

use super::archive_stats::{Agg, ArchiveStats, Dominance, Reading, Scope, member_value};
use super::bounded::{Limits, MAX_ARCHIVE_MEMBERS, MemberPrefix, inflate_capped};
use super::common::{bytes_at, ends_with_ci};
use crate::error::Error;
use crate::output::{
    ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership, EntryType, Errors,
    Metrics, Stage, Values,
};

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

/// Bytes the `zip` crate may read while opening an archive, per input byte,
/// on top of [`OPEN_READ_SLACK`]. Opening a well-formed archive reads its
/// end-of-central-directory search window, the central directory, and a
/// local header per member (smaller than the member's directory record):
/// under two passes over the input. But the crate tries every `PK\x05\x06`
/// in the file as an end record and, for each one that fails, rescans the
/// directory it names, so an input packed with failing candidates took
/// quadratic time to refuse (24 s for 1 MiB, minutes for a few MiB). The
/// budget turns that into a prompt open failure.
const OPEN_READS_PER_BYTE: u64 = 4;

/// Fixed part of the open read budget, so a small archive's search window
/// never counts against it.
const OPEN_READ_SLACK: u64 = 1 << 20;

/// A ZIP the `zip` crate opened: over the input itself, or over a copy whose
/// local-header signatures [`open`] restored.
pub(super) type Archive<'a> = ZipArchive<Budgeted<Cursor<Cow<'a, [u8]>>>>;

/// A reader that fails once its shared byte budget is spent. [`open_crate`]
/// bounds the `zip` crate's open with it and then lifts the budget: member
/// reads after the open are bounded by their own caps.
pub(super) struct Budgeted<R> {
    inner: R,
    left: Rc<Cell<u64>>,
}

impl<R: Read> Read for Budgeted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.left.get();
        if left == 0 && !buf.is_empty() {
            return Err(io::Error::other("zip open read budget exhausted"));
        }
        let max = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = self.inner.read(buf.get_mut(..max).unwrap_or_default())?;
        self.left.set(left.saturating_sub(n as u64));
        Ok(n)
    }
}

impl<R: Seek> Seek for Budgeted<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Open `bytes` with the `zip` crate, its reads bounded by
/// [`OPEN_READS_PER_BYTE`] until the archive is open.
fn open_crate(bytes: Cow<'_, [u8]>) -> Result<Archive<'_>, ZipError> {
    let budget = (bytes.len() as u64)
        .saturating_mul(OPEN_READS_PER_BYTE)
        .saturating_add(OPEN_READ_SLACK);
    let left = Rc::new(Cell::new(budget));
    let archive = ZipArchive::new(Budgeted {
        inner: Cursor::new(bytes),
        left: Rc::clone(&left),
    })?;
    left.set(u64::MAX);
    Ok(archive)
}

/// What [`open`] could make of a ZIP.
enum Opened<'a> {
    /// The `zip` crate opened it, `repaired` local headers needing their
    /// signature restored first. `directory` is the raw central directory,
    /// when the EOCD locates one, kept so the walk does not search again.
    Archive {
        archive: Archive<'a>,
        repaired: usize,
        directory: Option<RawDirectory>,
    },
    /// Not even a repaired copy opens; only the raw central directory
    /// reads. `error` is why the crate refused the original.
    RawOnly {
        error: ZipError,
        directory: RawDirectory,
    },
}

/// Open `bytes` as a ZIP. `Err` only when there is no central directory to
/// read at all — the input is not a ZIP.
fn open(bytes: &[u8]) -> Result<Opened<'_>, Error> {
    let directory = read_raw_directory(bytes);
    let error = match open_crate(Cow::Borrowed(bytes)) {
        Ok(archive) => {
            // The `zip` crate defers local-header validation until a member
            // is read, so a damaged local signature would only surface when
            // a package layer reads one. Check the central directory's
            // targets here, and repair them up front.
            if let Some(dir) = &directory
                && dir
                    .entries
                    .iter()
                    .any(|entry| !local_header_intact(bytes, dir, entry))
                && let Some((repaired_bytes, repaired)) = repair_local_headers(bytes, dir)
                && let Ok(archive) = open_crate(Cow::Owned(repaired_bytes))
            {
                return Ok(Opened::Archive {
                    archive,
                    repaired,
                    directory,
                });
            }
            return Ok(Opened::Archive {
                archive,
                repaired: 0,
                directory,
            });
        }
        Err(error) => error,
    };
    let Some(directory) = directory else {
        return Err(Error::malformed_caused_by("zip", error));
    };
    if let Some((repaired_bytes, repaired)) = repair_local_headers(bytes, &directory)
        && let Ok(archive) = open_crate(Cow::Owned(repaired_bytes))
    {
        tracing::debug!(
            target: "filefacts::zip",
            repaired,
            error = %error,
            "zip opened after restoring local-header signatures"
        );
        return Ok(Opened::Archive {
            archive,
            repaired,
            directory: Some(directory),
        });
    }
    Ok(Opened::RawOnly { error, directory })
}

/// Open `bytes` and emit the ZIP member listing and archive facts. Returns
/// the open archive for a package layer to read members from, or `None`
/// when only the raw central directory was readable: the listing is still
/// emitted, but no member content can be.
pub(super) fn open_and_walk<'a>(
    bytes: &'a [u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<Option<Archive<'a>>, Error> {
    match open(bytes)? {
        Opened::Archive {
            mut archive,
            repaired,
            directory,
        } => {
            if repaired > 0 {
                metrics.insert(
                    metric!("archive.local_header_mismatch_count"),
                    repaired as f64,
                );
                errors.record_fallback(
                    Stage::ZipParse,
                    format!(
                        "{repaired} local file header(s) lack their signature; \
                         read through the central directory, as Android and Java do"
                    ),
                );
            } else if let Some(dir) = &directory {
                // Pointers no signature repair could fix: the listing stands,
                // but those members will not read.
                let mismatched = dir
                    .entries
                    .iter()
                    .filter(|e| !local_header_intact(bytes, dir, e))
                    .count();
                if mismatched > 0 {
                    metrics.insert(
                        metric!("archive.local_header_mismatch_count"),
                        mismatched as f64,
                    );
                    errors.record_fallback(
                        Stage::ZipParse,
                        format!(
                            "{mismatched} central-directory entries point at no local \
                             file header; their members will not read"
                        ),
                    );
                }
            }
            let walked = walk_archive(
                &mut archive,
                directory.as_ref(),
                bytes,
                values,
                metrics,
                archive_members,
                MAX_ARCHIVE_MEMBERS,
            );
            match (walked, &directory) {
                (Ok(()), _) => {}
                // An entry the crate parsed but cannot open its record for:
                // the raw central directory still lists every member.
                (Err(error), Some(dir)) => {
                    errors.record_fallback(
                        Stage::ZipParse,
                        format!("{error}; members listed from the raw central directory"),
                    );
                    walk_raw(
                        dir,
                        bytes,
                        values,
                        metrics,
                        archive_members,
                        MAX_ARCHIVE_MEMBERS,
                    );
                }
                (Err(error), None) => return Err(error),
            }
            Ok(Some(archive))
        }
        Opened::RawOnly { error, directory } => {
            let mismatched = directory
                .entries
                .iter()
                .filter(|e| !local_header_intact(bytes, &directory, e))
                .count();
            if mismatched > 0 {
                metrics.insert(
                    metric!("archive.local_header_mismatch_count"),
                    mismatched as f64,
                );
            }
            errors.record_fallback(
                Stage::ZipParse,
                format!("{error}; members listed from the raw central directory"),
            );
            walk_raw(
                &directory,
                bytes,
                values,
                metrics,
                archive_members,
                MAX_ARCHIVE_MEMBERS,
            );
            Ok(None)
        }
    }
}

/// Emit the ZIP member listing and archive facts for `bytes`.
pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
) -> Result<(), Error> {
    open_and_walk(bytes, values, metrics, archive_members, errors).map(drop)
}

/// One walked member, with the per-entry facts the walk aggregates.
struct EntryFacts {
    member: ArchiveMember,
    exec_mode: bool,
    extra_len: usize,
    extra_tags: BTreeSet<u16>,
    comment_len: usize,
}

impl EntryFacts {
    /// Facts for a member whose central-directory record gave `mode`,
    /// `extra` and `comment_len`.
    fn new(member: ArchiveMember, mode: Option<u32>, extra: &[u8], comment_len: usize) -> Self {
        // An exec bit on anything but a symlink makes it executable,
        // whatever its name.
        let exec_mode = mode.is_some_and(|m| !is_symlink_mode(m) && m & 0o111 != 0);
        Self {
            member,
            exec_mode,
            extra_len: extra.len(),
            extra_tags: enumerate_extra_tags(extra),
            comment_len,
        }
    }
}

fn is_symlink_mode(mode: u32) -> bool {
    mode & 0o170_000 == 0o120_000
}

fn entry_type(is_dir: bool, mode: Option<u32>) -> EntryType {
    if is_dir {
        EntryType::Directory
    } else if mode.is_some_and(is_symlink_mode) {
        EntryType::Symlink
    } else {
        EntryType::Regular
    }
}

/// Walk the members the `zip` crate parsed. `directory` is the raw central
/// directory [`open`] already read, if any. The member cap is a parameter so
/// it can be exercised without building a 65k-entry archive.
fn walk_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    directory: Option<&RawDirectory>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    max_members: usize,
) -> Result<(), Error> {
    // Entries past the cap are not walked, so every per-member list and
    // count covers the first `walked` entries; `archive.member_count`
    // still reports the full parsed count.
    let walked = archive.len().min(max_members);
    let mut facts = Vec::with_capacity(walked);
    for i in 0..walked {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| Error::malformed_with_source("zip", format!("entry {i}"), e))?;
        let mode = entry.unix_mode();
        // Names that are not UTF-8 are decoded as CP437, which maps every
        // byte, so this fallback never runs in practice.
        let path = entry.name().map_or_else(
            |_| String::from_utf8_lossy(entry.name_raw()).into_owned(),
            Cow::into_owned,
        );
        let member = ArchiveMember {
            // None means the MS-DOS date didn't parse — Mozilla's (1980, 0, 0)
            // "no recorded timestamp" sentinel is the common case, and
            // deterministic-build tooling (web-ext, bazel) produces it on
            // purpose.
            mtime_unix: entry
                .last_modified()
                .and_then(crate::scan::zip_datetime_to_unix),
            crc32: Some(entry.crc32()),
            encrypted: entry.encrypted(),
            compression: ArchiveCompression::new(
                Some(entry.compressed_size()),
                Some(method_name(entry.compression()).into()),
            ),
            ownership: mode.map(ArchiveOwnership::mode).unwrap_or_default(),
            offsets: ArchiveOffsets {
                header: Some(entry.header_start()),
                data: entry.data_start(),
                central_header: Some(entry.central_header_start()),
            },
            ..ArchiveMember::new(path, entry.size(), entry_type(entry.is_dir(), mode))
        };
        let extra = entry.extra_data().unwrap_or_default();
        facts.push(EntryFacts::new(member, mode, &extra, entry.comment().len()));
    }

    // The `zip` crate de-duplicates the central directory by name at parse
    // time, so the member loop above can't see shadowed entries. Walk the
    // raw CDH bytes as well to catch the ZIP-confusion attack shape: the
    // directory `open` read, when it starts where the crate's does.
    let cd_start = usize::try_from(archive.central_directory_start()).unwrap_or(usize::MAX);
    let scanned;
    let (raw_entries, eocd) = match directory {
        Some(d) if d.start == cd_start => (d.entries.as_slice(), Some(d.eocd)),
        _ => {
            scanned = scan_central_directory(bytes, cd_start);
            (scanned.as_slice(), find_eocd(bytes))
        }
    };
    let names: Vec<Cow<'_, str>> = archive.file_names().filter_map(Result::ok).collect();
    let names: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
    emit_walk(
        WalkInput {
            bytes,
            comment: archive.comment(),
            member_count: archive.len(),
            facts,
            raw_entries,
            names: &names,
            eocd,
        },
        values,
        metrics,
        archive_members,
    );
    Ok(())
}

/// The member listing from the raw central directory alone, for an archive
/// the `zip` crate will not open.
fn walk_raw(
    directory: &RawDirectory,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    max_members: usize,
) {
    let facts = directory
        .entries
        .iter()
        .take(max_members)
        .map(|e| {
            let header = e
                .header_offset
                .saturating_add(directory.archive_offset as u64);
            let member = ArchiveMember {
                mtime_unix: e.parsed_mtime,
                crc32: Some(e.crc32),
                encrypted: e.flags & 0x0001 != 0,
                compression: ArchiveCompression::new(
                    Some(e.compressed_size),
                    Some(method_name_from_id(e.method).into()),
                ),
                ownership: e
                    .unix_mode()
                    .map(ArchiveOwnership::mode)
                    .unwrap_or_default(),
                offsets: ArchiveOffsets {
                    header: Some(header),
                    data: None,
                    central_header: Some(e.central_header_offset as u64),
                },
                ..ArchiveMember::new(
                    e.name.clone(),
                    e.uncompressed_size,
                    entry_type(e.name.ends_with('/'), e.unix_mode()),
                )
            };
            EntryFacts::new(member, e.unix_mode(), e.extra(bytes), e.comment_len)
        })
        .collect();
    let names: Vec<&str> = directory.entries.iter().map(|e| e.name.as_str()).collect();
    emit_walk(
        WalkInput {
            bytes,
            comment: directory.comment(bytes),
            member_count: directory.entries.len(),
            facts,
            raw_entries: &directory.entries,
            names: &names,
            eocd: Some(directory.eocd),
        },
        values,
        metrics,
        archive_members,
    );
}

/// What [`emit_walk`] reports on.
struct WalkInput<'w> {
    bytes: &'w [u8],
    /// The archive (EOCD) comment.
    comment: &'w [u8],
    /// Every member, walked or not.
    member_count: usize,
    /// The walked members.
    facts: Vec<EntryFacts>,
    /// Every central-directory record, duplicates included.
    raw_entries: &'w [RawCdhEntry],
    /// Every member name.
    names: &'w [&'w str],
    /// Offset of the end-of-central-directory record, when found.
    eocd: Option<usize>,
}

/// Emit the member listing and the archive-level facts, however the members
/// were read.
fn emit_walk(
    input: WalkInput<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) {
    let WalkInput {
        bytes,
        comment,
        member_count,
        facts,
        raw_entries,
        names,
        eocd,
    } = input;
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("zip".into()),
    );

    let has_comment = !comment.is_empty();
    if has_comment {
        let comment_str = String::from_utf8_lossy(comment).into_owned();
        values.insert_key(
            value_key!("archive.comment"),
            JsonValue::String(comment_str),
        );
        metrics.insert(metric!("archive.comment_size"), comment.len() as f64);
    }

    let walked = facts.len();
    if walked < member_count {
        let mut limits = Limits::default();
        limits.push(
            "member-cap",
            format!("walked {walked} of {member_count} members"),
        );
        limits.emit(values, value_key!("zip.limits"));
    }
    let mut members: Vec<JsonValue> = Vec::with_capacity(walked);
    let mut stats = ArchiveStats::new(AGGS);
    let mut extra_field_size: u64 = 0;
    let mut uses_zip64 = false;
    let mut entry_comment_count: u64 = 0;
    let mut entry_comment_size: u64 = 0;
    // Tag IDs encountered in any LFH/CDH extra field (union across members).
    let mut extra_field_tags: BTreeSet<u16> = BTreeSet::new();

    for entry in facts {
        let EntryFacts {
            member,
            exec_mode,
            extra_len,
            extra_tags,
            comment_len,
        } = entry;
        let mut reading = Reading::of(&member);
        reading.exec_mode = exec_mode;
        stats.observe(&member, &reading);

        let mut obj = member_value(&member);
        extra_field_size += extra_len as u64;
        extra_field_tags.extend(&extra_tags);
        uses_zip64 |= extra_tags.contains(&0x0001);
        // Sentinel sizes in the central directory also indicate Zip64 usage.
        let compressed = member.compression.compressed_size.unwrap_or(0);
        uses_zip64 |= compressed == 0xFFFF_FFFF || member.size_bytes == 0xFFFF_FFFF;
        if !extra_tags.is_empty() {
            let tags = extra_tags.iter().map(|t| JsonValue::from(*t)).collect();
            obj.insert("extra_tags".into(), JsonValue::Array(tags));
        }

        // Per-entry comment (CDH `file_comment` field) — separate from
        // the archive-level EOCD comment. Used in some packaging tools
        // legitimately; abused for out-of-band config strings.
        if comment_len > 0 {
            entry_comment_count += 1;
            entry_comment_size += comment_len as u64;
            obj.insert("comment_size".into(), JsonValue::from(comment_len as u64));
        }

        members.push(JsonValue::Object(obj));
        archive_members.push(member);
    }

    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    stats.emit(values, metrics);
    metrics.insert(metric!("archive.member_count"), member_count as f64);
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

    let mut name_counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut crc_counts: BTreeMap<u32, u64> = BTreeMap::new();
    for e in raw_entries {
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
    let has = |needle: &str| names.contains(&needle);
    if has("META-INF/cose.manifest") && has("META-INF/cose.sig") {
        values.insert_key(
            value_key!("archive.signing.mozilla_extension_shape"),
            JsonValue::Bool(true),
        );
    }

    // Also report `archive.signing.jar_signed_shape` when a signature file
    // (`META-INF/*.SF`) and a signature block (`*.RSA`, `*.DSA`, `*.EC`) both
    // exist. The JDK matches both suffixes without regard to case.
    let in_meta_inf = |n: &&&str| n.starts_with("META-INF/");
    let jar_signed_shape = names
        .iter()
        .filter(in_meta_inf)
        .any(|n| ends_with_ci(n, ".SF"))
        && names.iter().filter(in_meta_inf).any(|n| {
            [".RSA", ".DSA", ".EC"]
                .iter()
                .any(|ext| ends_with_ci(n, ext))
        });
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
    if has("_metadata/verified_contents.json") {
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
    let trailing = eocd.map_or(0, |eocd| trailing_bytes(bytes, eocd));
    if trailing > 0 {
        metrics.insert(metric!("archive.trailing_bytes"), trailing as f64);
    }
}

/// Why [`read_member`] returned no bytes.
#[derive(Debug)]
pub(super) enum MemberError {
    /// The member inflates past the cap. A cut-off member would only fail
    /// to parse, so it is not returned at all.
    TooLarge { max: u64 },
    /// The `zip` crate could not open or inflate the member.
    Zip(ZipError),
}

impl fmt::Display for MemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max } => write!(f, "over the {max}-byte read cap"),
            Self::Zip(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MemberError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLarge { .. } => None,
            Self::Zip(e) => Some(e),
        }
    }
}

/// Read member `name`, refusing it when it inflates past `max` bytes.
/// `Ok(None)` when no member has that name. The cap is on what the inflater
/// actually produces: the size the central directory declares is the
/// archive's claim, and a bomb claims a small one.
pub(super) fn read_member<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
    max: u64,
) -> Result<Option<Vec<u8>>, MemberError> {
    match read_member_prefix(zip, name, max)? {
        Some(prefix) if prefix.truncated => Err(MemberError::TooLarge { max }),
        Some(prefix) => Ok(Some(prefix.bytes)),
        None => Ok(None),
    }
}

/// Read the manifest-like member `name` for a package layer. `None` when it
/// is absent (silently), inflates past `cap` (a `stage` entry in `limits`),
/// or will not read (a `ZipParse` error).
pub(super) fn read_manifest_member<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
    cap: u64,
    limits: &mut Limits,
    stage: &'static str,
    errors: &mut Errors,
) -> Option<Vec<u8>> {
    match read_member(zip, name, cap) {
        Ok(buf) => buf,
        Err(MemberError::TooLarge { max }) => {
            limits.push(stage, format!("{name} over the {max}-byte cap; not parsed"));
            None
        }
        Err(e) => {
            errors.record_malformed(Stage::ZipParse, format!("{name}: {e}"));
            None
        }
    }
}

/// The first `max` bytes of member `name`, and whether more followed, for a
/// caller that can use a prefix (a header block). `Ok(None)` when no member
/// has that name.
pub(super) fn read_member_prefix<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
    max: u64,
) -> Result<Option<MemberPrefix>, MemberError> {
    let entry = match zip.by_name(name) {
        Ok(entry) => entry,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(MemberError::Zip(e)),
    };
    inflate_capped(entry, max)
        .map(Some)
        .map_err(|e| MemberError::Zip(ZipError::Io(e)))
}

/// One central-directory entry as recovered by the raw walker: what the
/// duplicate / CRC collision / sentinel-mtime detection needs, and enough
/// to list the member when the `zip` crate cannot.
struct RawCdhEntry {
    name: String,
    crc32: u32,
    uncompressed_size: u64,
    compressed_size: u64,
    parsed_mtime: Option<i64>,
    method: u16,
    flags: u16,
    /// High byte of "version made by": the host system (3 is Unix).
    host: u8,
    external_attributes: u32,
    /// Local-header offset as recorded, relative to the archive start.
    header_offset: u64,
    /// Absolute offset of this record.
    central_header_offset: usize,
    /// Absolute range of the extra field.
    extra: (usize, usize),
    comment_len: usize,
}

impl RawCdhEntry {
    fn unix_mode(&self) -> Option<u32> {
        let mode = self.external_attributes >> 16;
        (self.host == 3 && mode != 0).then_some(mode)
    }

    fn extra<'b>(&self, bytes: &'b [u8]) -> &'b [u8] {
        bytes.get(self.extra.0..self.extra.1).unwrap_or_default()
    }
}

/// Fixed part of a central-directory file header, before the name.
const CDH_FIXED_LEN: usize = 46;

/// Fixed part of a local file header, before the name.
const LFH_FIXED_LEN: usize = 30;

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
            compressed_size: u64::from(u32_at(20)),
            parsed_mtime,
            method: u16_at(10),
            flags: u16_at(8),
            host: header[5],
            external_attributes: u32_at(38),
            header_offset: u64::from(u32_at(42)),
            central_header_offset: i,
            extra: (name_end, name_end + extra_len),
            comment_len,
        });
        i = name_end + extra_len + comment_len;
    }
    out
}

/// The central directory located from the EOCD record alone.
struct RawDirectory {
    entries: Vec<RawCdhEntry>,
    /// Absolute offset of the first record.
    start: usize,
    /// Bytes prepended to the archive (a self-extractor stub): every offset
    /// the directory records is relative to the archive, not the file.
    archive_offset: usize,
    eocd: usize,
}

impl RawDirectory {
    fn comment<'b>(&self, bytes: &'b [u8]) -> &'b [u8] {
        let len = bytes_at::u16_le(bytes, self.eocd + 20).map_or(0, usize::from);
        let start = self.eocd + 22;
        bytes
            .get(start..start.saturating_add(len))
            .unwrap_or_default()
    }
}

/// Locate and walk the central directory without the `zip` crate. `None`
/// when there is no EOCD record, it uses Zip64 sentinels this walker does
/// not follow, or no record parses where it points.
fn read_raw_directory(bytes: &[u8]) -> Option<RawDirectory> {
    let eocd = find_eocd(bytes)?;
    let cd_size = bytes_at::u32_le(bytes, eocd + 12)?;
    let cd_offset = bytes_at::u32_le(bytes, eocd + 16)?;
    if cd_size == u32::MAX || cd_offset == u32::MAX {
        return None;
    }
    // The directory ends where the EOCD begins. Where it starts according
    // to its size, minus where it says it starts, is the archive's offset
    // into the file.
    let cd_start = eocd.checked_sub(cd_size as usize)?;
    let (cd_start, archive_offset) = match cd_start.checked_sub(cd_offset as usize) {
        Some(archive_offset) => (cd_start, archive_offset),
        None => (cd_offset as usize, 0),
    };
    let entries = scan_central_directory(bytes, cd_start);
    (!entries.is_empty()).then_some(RawDirectory {
        entries,
        start: cd_start,
        archive_offset,
        eocd,
    })
}

/// Whether the local header `entry` points at starts with its signature.
fn local_header_intact(bytes: &[u8], directory: &RawDirectory, entry: &RawCdhEntry) -> bool {
    usize::try_from(entry.header_offset)
        .ok()
        .and_then(|off| off.checked_add(directory.archive_offset))
        .and_then(|at| bytes.get(at..))
        .is_some_and(|rest| rest.starts_with(b"PK\x03\x04"))
}

/// A copy of `bytes` with the signature restored on every local header the
/// central directory points at but that lacks it, and how many were
/// restored. `None` when none needed restoring — something else is wrong.
fn repair_local_headers(bytes: &[u8], directory: &RawDirectory) -> Option<(Vec<u8>, usize)> {
    let mut repaired = None::<Vec<u8>>;
    let mut count = 0;
    for entry in &directory.entries {
        if local_header_intact(bytes, directory, entry) {
            continue;
        }
        let Some(at) = usize::try_from(entry.header_offset)
            .ok()
            .and_then(|off| off.checked_add(directory.archive_offset))
            .filter(|at| {
                at.checked_add(LFH_FIXED_LEN)
                    .is_some_and(|end| end <= bytes.len())
            })
        else {
            continue;
        };
        let copy = repaired.get_or_insert_with(|| bytes.to_vec());
        if let Some(signature) = copy.get_mut(at..at + 4) {
            signature.copy_from_slice(b"PK\x03\x04");
            count += 1;
        }
    }
    repaired.map(|copy| (copy, count))
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

/// Bytes appended after the End-of-Central-Directory record at `eocd`
/// (its offset + 22 + comment length). A non-zero value means an attacker
/// (or an aggressive concatenator) stuck data on the end of the archive
/// that the canonical EOCD doesn't account for.
fn trailing_bytes(bytes: &[u8], eocd: usize) -> usize {
    // The comment length is the record's last fixed field, at +20.
    let Some(comment_len) = bytes_at::u16_le(bytes, eocd + 20) else {
        return 0;
    };
    let end = eocd + 22 + usize::from(comment_len);
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

/// The method name for a member the `zip` crate parsed. The crate keeps
/// the method's id private, so it is recovered from the crate's named
/// methods.
fn method_name(method: CompressionMethod) -> &'static str {
    use CompressionMethod as M;
    const IDS: [(CompressionMethod, u16); 20] = [
        (M::STORE, 0),
        (M::SHRINK, 1),
        (M::REDUCE_1, 2),
        (M::REDUCE_2, 3),
        (M::REDUCE_3, 4),
        (M::REDUCE_4, 5),
        (M::IMPLODE, 6),
        (M::DEFLATE, 8),
        (M::DEFLATE64, 9),
        (M::PKWARE_IMPLODE, 10),
        (M::BZIP2, 12),
        (M::LZMA, 14),
        (M::ZSTD_DEPRECATED, 20),
        (M::ZSTD, 93),
        (M::MP3, 94),
        (M::XZ, 95),
        (M::JPEG, 96),
        (M::WAVPACK, 97),
        (M::PPMD, 98),
        (M::AES, 99),
    ];
    IDS.iter()
        .find(|(m, _)| *m == method)
        .map_or("other", |&(_, id)| method_name_from_id(id))
}

/// The method name for a central-directory method id (APPNOTE 4.4.5).
fn method_name_from_id(id: u16) -> &'static str {
    match id {
        0 => "stored",
        1 => "shrink",
        2..=5 => "reduce",
        6 => "implode",
        8 => "deflate",
        9 => "deflate64",
        10 => "pkware-implode",
        12 => "bzip2",
        14 => "lzma",
        20 | 93 => "zstd",
        94 => "mp3",
        95 => "xz",
        96 => "jpeg",
        97 => "wavpack",
        98 => "ppmd",
        99 => "aes",
        _ => "other",
    }
}

#[cfg(test)]
mod tests;
