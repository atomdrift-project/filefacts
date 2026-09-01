//! Optical-disc image (`.iso`) container extractor — ISO 9660, Joliet,
//! Rock Ridge, El Torito, and the UDF descriptor layer.
//!
//! An ISO image is a *filesystem*, not a compressed archive: every file is
//! stored verbatim in a run of 2048-byte logical sectors. That single fact
//! drives the whole design here. Because member bytes are addressable
//! ranges of the image, this extractor never decompresses anything — it
//! reads the descriptors and directory records (a few sectors) and hands
//! every member out as a `(offset, length)` pair the caller can slice
//! straight from the mapped image.
//!
//! Why the detail matters: an ISO is the standard way to smuggle an
//! executable past Windows' Mark-of-the-Web, so an image is usually a
//! wrapper around exactly one payload. The interesting evidence is
//! therefore *how the wrapper was built*, not what the payload is (that
//! comes from analysing the member on its own):
//!
//! - **Two namespaces, one payload.** ISO 9660 stores 8.3-mangled names;
//!   Joliet stores the real UCS-2 name in a *separate* directory tree.
//!   Both trees are walked and the members are unioned by extent, so a
//!   file that exists in only one namespace — a classic scanner-evasion
//!   trick, since a reader that follows one tree never sees it — is still
//!   surfaced, and the divergence itself is recorded.
//! - **Builder attribution.** Mastering tools stamp their name into the
//!   PVD's application/preparer identifiers. Blank identifiers mean the
//!   image was emitted by a library or a script rather than by any of the
//!   burning tools that produce genuine media.
//! - **Space that isn't a file.** Bytes past the declared volume size,
//!   sectors inside the volume that no extent claims, and a non-zero
//!   system area are all places to park data that a file-tree walk alone
//!   would never report.
//!
//! Emitted keys (selected):
//!
//! - `iso.format` — `iso9660`, `udf`, or `iso9660+udf` (a UDF bridge disc).
//! - `iso.volume_id`, `iso.system_id`, `iso.volume_set_id`,
//!   `iso.publisher_id`, `iso.preparer_id`, `iso.application_id` — PVD
//!   identifier strings, verbatim.
//! - `iso.builder` — normalised mastering tool, resolved from those
//!   identifiers (`mkisofs`, `oscdimg`, `imgburn`, `poweriso`, `pycdlib`, …).
//! - `iso.extensions[]` — `joliet`, `rock-ridge`, `el-torito`, `udf`, `apple`.
//! - `iso.boot.*` — El Torito catalog: per-entry platform, media type,
//!   load address, and the boot image's own extent.
//! - `iso.system_area.*` — the 32 KiB before the descriptors: `empty`,
//!   `mbr` (isohybrid), `gpt`, `apm`, or `data`.
//! - `iso.files[]` + `iso.file_count` / `iso.dir_count` / `iso.max_depth` …
//! - `iso.anomalies[]` — structural findings worth a rule (`trailing-data`,
//!   `extent-beyond-volume`, `overlapping-extents`, `tree-only-file`, …).
//! - `iso.udf.*` — UDF revision, implementation identifier, volume names.
//!
//! Members are emitted into `archive_members` with `offsets.data` set to the
//! member's byte offset in the image. `offsets.data` is deliberately left
//! `None` for interleaved or non-contiguous multi-extent files, whose bytes
//! are *not* one range — a caller that slices on the offset must not be
//! handed a start it cannot trust.

use crate::metric;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::error::Error;
use crate::formats::common::bytes_at::{u16_le, u32_be, u32_le};
use crate::output::{ArchiveMember, ArchiveOffsets, ArchiveOwnership, Metrics, Values};
use crate::scan::days_from_civil;

use super::udf;

/// ISO 9660 logical sector. Fixed by the standard for optical media;
/// the PVD's `logical_block_size` field may disagree, which is itself
/// recorded as an anomaly rather than trusted.
pub(super) const SECTOR: usize = 2048;
/// The reserved area before the volume descriptors — 16 sectors.
const SYSTEM_AREA_SECTORS: usize = 16;
/// Cap on descriptors read from the volume descriptor set. A conforming
/// set is 2–5 entries; the UDF bridge recognition sequence adds a few
/// more. Anything past this is a malformed or padded set.
const MAX_VOLUME_DESCRIPTORS: usize = 64;
/// Cap on directory records walked across all trees.
const MAX_ENTRIES: usize = 65_536;
/// Cap on directory extents visited, bounding a cyclic tree.
const MAX_DIRS: usize = 16_384;
/// Cap on tree depth. ISO 9660 level 1 permits 8; Joliet and Rock Ridge
/// images routinely exceed it, so this is a loop guard, not a limit check.
const MAX_DEPTH: u32 = 64;
/// Cap on members surfaced in `iso.files[]`. `iso.file_count` carries the
/// true count.
const MAX_SURFACED_FILES: usize = 512;
/// Cap on a single directory extent read.
const MAX_DIR_EXTENT: usize = 32 << 20;
/// Cap on SUSP continuation-area hops per record.
const MAX_CE_HOPS: usize = 8;
/// Cap on El Torito catalog entries.
const MAX_BOOT_ENTRIES: usize = 64;
/// Cap on symlink component bytes reassembled from an `SL` entry.
const MAX_SYMLINK_LEN: usize = 4096;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let descriptors = scan_descriptors(bytes);
    let mut anomalies: Vec<&'static str> = Vec::new();
    if descriptors.is_empty() {
        values.insert("iso.format", JsonValue::String("unknown".into()));
        emit_system_area(bytes, values, metrics, &mut anomalies);
        anomalies.push("no-volume-descriptor");
        finish(values, metrics, &mut anomalies, &[], bytes, None);
        return Ok(());
    }
    if descriptors
        .first()
        .is_some_and(|d| d.sector != SYSTEM_AREA_SECTORS)
    {
        anomalies.push("descriptor-set-misplaced");
    }

    let mut extensions: Vec<&'static str> = Vec::new();
    // Byte ranges the image accounts for: the system area, the descriptor
    // set, the path tables, the boot catalog and images, every directory
    // extent, and every file extent. What is left over is `iso.unclaimed`.
    let mut claimed: Vec<(u64, u64)> = vec![(
        0,
        (SYSTEM_AREA_SECTORS + descriptors.len()) as u64 * SECTOR as u64,
    )];

    emit_descriptor_set(&descriptors, values, metrics);
    emit_system_area(bytes, values, metrics, &mut anomalies);

    // Primary and supplementary descriptors. A Joliet SVD is an SVD whose
    // escape sequence selects one of the three UCS-2 levels; any other SVD
    // is a plain secondary namespace and is walked as ISO 9660.
    let primary = descriptors
        .iter()
        .find(|d| d.ident == *b"CD001" && d.kind == 1)
        .and_then(|d| Pvd::parse(d.body));
    let supplementaries: Vec<(Pvd, Option<u8>)> = descriptors
        .iter()
        .filter(|d| d.ident == *b"CD001" && d.kind == 2)
        .filter_map(|d| Pvd::parse(d.body))
        .map(|p| {
            let level = joliet_level(&p.escape);
            (p, level)
        })
        .collect();

    let joliet = supplementaries.iter().find(|(_, lvl)| lvl.is_some());
    if let Some((_, Some(level))) = joliet {
        extensions.push("joliet");
        metrics.insert(metric!("iso.joliet_level"), f64::from(*level));
    }
    values.insert("iso.joliet", JsonValue::Bool(joliet.is_some()));

    let mut udf_facts = udf::extract(bytes, values, metrics);
    if udf_facts.present {
        extensions.push("udf");
    }

    // `iso.format` names the namespaces a *reader* can mount, which is what
    // decides whether a given OS sees the payload at all.
    let format = match (primary.is_some(), udf_facts.present) {
        (true, true) => "iso9660+udf",
        (true, false) => "iso9660",
        (false, true) => "udf",
        (false, false) => "unknown",
    };
    values.insert("iso.format", JsonValue::String(format.into()));

    let Some(pvd) = primary else {
        // A UDF-only image has no ISO 9660 tree, so the UDF walk is the only
        // view of its contents. An empty member list here would read as "the
        // image is empty", which is exactly the wrong conclusion.
        anomalies.push("no-iso9660-primary");
        archive_members.append(&mut udf_facts.members);
        finish(values, metrics, &mut anomalies, &extensions, bytes, None);
        return Ok(());
    };

    emit_pvd(&pvd, values, metrics, &mut anomalies);

    if let Some(boot) = descriptors
        .iter()
        .find(|d| d.ident == *b"CD001" && d.kind == 0)
    {
        if emit_boot(
            bytes,
            boot.body,
            &pvd,
            values,
            metrics,
            &mut anomalies,
            &mut claimed,
            archive_members,
        ) {
            extensions.push("el-torito");
        }
    }

    // Walk every namespace. The primary tree carries Rock Ridge (if the
    // image has it); the Joliet tree carries the names Windows shows.
    let mut walk = Walk::new();
    walk.run(bytes, pvd.root_lba, pvd.root_len, Namespace::Iso9660);
    for (svd, level) in &supplementaries {
        let ns = if level.is_some() {
            Namespace::Joliet
        } else {
            Namespace::Supplementary
        };
        walk.run(bytes, svd.root_lba, svd.root_len, ns);
    }
    if walk.rock_ridge {
        extensions.push("rock-ridge");
    }
    if walk.apple {
        extensions.push("apple");
    }
    if walk.truncated {
        anomalies.push("tree-walk-truncated");
    }

    // Path tables: every namespace has its own pair, and a Joliet SVD's pair
    // sits outside anything the primary descriptor points at.
    for desc in std::iter::once(&pvd).chain(supplementaries.iter().map(|(p, _)| p)) {
        for lba in desc.path_table_lba {
            if lba != 0 {
                let start = u64::from(lba) * SECTOR as u64;
                let span = u64::from(desc.path_table_size)
                    .div_ceil(SECTOR as u64)
                    .max(1)
                    * SECTOR as u64;
                claimed.push((start, start.saturating_add(span)));
            }
        }
    }
    for (lba, len) in &walk.visited {
        let start = u64::from(*lba) * SECTOR as u64;
        let span = u64::from(*len).div_ceil(SECTOR as u64).max(1) * SECTOR as u64;
        claimed.push((start, start.saturating_add(span)));
    }

    let files = merge_namespaces(walk.entries, &mut anomalies);
    emit_tree(&files, &pvd, bytes, values, metrics, &mut anomalies);
    emit_members(&files, archive_members);
    let unclaimed = unclaimed_regions(&files, &pvd, bytes, claimed);
    emit_unclaimed(
        &unclaimed,
        u64::from(pvd.volume_space_sectors).saturating_mul(SECTOR as u64),
        values,
        metrics,
        archive_members,
        &mut anomalies,
    );

    // On a bridge disc the same bytes are described twice. The counts are
    // expected to agree; when they don't, one namespace is showing a reader
    // something the other hides, so take the union rather than a side.
    if udf_facts.present {
        let iso_files = archive_members
            .iter()
            .filter(|m| m.entry_type.as_deref() != Some("directory"))
            .count() as u64;
        if udf_facts.file_count > iso_files {
            anomalies.push("udf-tree-has-extra-files");
            let known: Vec<String> = archive_members.iter().map(|m| m.path.clone()).collect();
            for m in udf_facts.members.drain(..) {
                if !known.contains(&m.path) {
                    archive_members.push(m);
                }
            }
        }
    }

    finish(
        values,
        metrics,
        &mut anomalies,
        &extensions,
        bytes,
        Some(&pvd),
    );
    Ok(())
}

/// Emit the facts that don't depend on a successful tree walk, so a
/// malformed or UDF-only image still reports its shape.
fn finish(
    values: &mut Values,
    metrics: &mut Metrics,
    anomalies: &mut Vec<&'static str>,
    extensions: &[&'static str],
    bytes: &[u8],
    pvd: Option<&Pvd>,
) {
    if let Some(pvd) = pvd {
        // Bytes past the volume the descriptor declares. Mastering tools
        // pad to a sector, never past the declared size, so a positive
        // value is data the filesystem does not account for.
        let declared = u64::from(pvd.volume_space_sectors) * SECTOR as u64;
        let actual = bytes.len() as u64;
        metrics.insert(metric!("iso.declared_bytes"), declared as f64);
        if actual > declared {
            let trailing = actual - declared;
            metrics.insert(metric!("iso.trailing_bytes"), trailing as f64);
            anomalies.push("trailing-data");
        } else if actual < declared {
            metrics.insert(metric!("iso.missing_bytes"), (declared - actual) as f64);
            anomalies.push("truncated-image");
        }
    }

    let mut exts: Vec<&'static str> = extensions.to_vec();
    exts.sort_unstable();
    exts.dedup();
    values.insert(
        "iso.extensions",
        JsonValue::Array(exts.iter().map(|e| json!(e)).collect()),
    );

    anomalies.sort_unstable();
    anomalies.dedup();
    metrics.insert(metric!("iso.anomaly_count"), anomalies.len() as f64);
    values.insert(
        "iso.anomalies",
        JsonValue::Array(anomalies.iter().map(|a| json!(a)).collect()),
    );
}

// ---------------------------------------------------------------------------
// Volume descriptor set
// ---------------------------------------------------------------------------

struct Descriptor<'a> {
    sector: usize,
    kind: u8,
    ident: [u8; 5],
    body: &'a [u8],
}

/// Read the volume descriptor set starting at sector 16.
///
/// Both recognition sequences live here: ISO 9660's `CD001` descriptors and
/// the UDF bridge's `BEA01`/`NSR0x`/`TEA01` sequence, which on a bridge disc
/// follows the ISO 9660 terminator. The walk therefore continues past a
/// terminator rather than stopping at it, and ends at the first sector
/// carrying no recognised standard identifier.
fn scan_descriptors(bytes: &[u8]) -> Vec<Descriptor<'_>> {
    let is_identifier = |ident: &[u8; 5]| {
        matches!(
            ident,
            b"CD001" | b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01" | b"BOOT2" | b"CDW02"
        )
    };
    let read = |sector: usize| -> Option<(Descriptor<'_>, [u8; 5])> {
        let body = sector_at(bytes, sector)?;
        let ident = body.get(1..6).and_then(|s| <[u8; 5]>::try_from(s).ok())?;
        let kind = *body.first()?;
        Some((
            Descriptor {
                sector,
                kind,
                ident,
                body,
            },
            ident,
        ))
    };

    // Find where the set starts. It belongs at sector 16, but the same
    // window identification searches is honoured here so a damaged leading
    // descriptor does not make the whole image unreadable.
    let Some(first) = (SYSTEM_AREA_SECTORS..=SYSTEM_AREA_SECTORS + 6)
        .find(|s| read(*s).is_some_and(|(_, id)| is_identifier(&id)))
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for sector in first..first + MAX_VOLUME_DESCRIPTORS {
        let Some((descriptor, ident)) = read(sector) else {
            break;
        };
        if !is_identifier(&ident) {
            break;
        }
        out.push(descriptor);
    }
    out
}

fn emit_descriptor_set(descriptors: &[Descriptor<'_>], values: &mut Values, metrics: &mut Metrics) {
    let mut list = Vec::with_capacity(descriptors.len());
    for d in descriptors {
        let mut obj = JsonMap::new();
        obj.insert("sector".into(), json!(d.sector));
        obj.insert(
            "standard_id".into(),
            json!(String::from_utf8_lossy(&d.ident)),
        );
        obj.insert("type".into(), json!(d.kind));
        obj.insert("kind".into(), json!(descriptor_kind(d.ident, d.kind)));
        list.push(JsonValue::Object(obj));
    }
    metrics.insert(
        metric!("iso.volume_descriptor_count"),
        descriptors.len() as f64,
    );
    values.insert("iso.volume_descriptors", JsonValue::Array(list));
}

fn descriptor_kind(ident: [u8; 5], kind: u8) -> &'static str {
    match &ident {
        b"CD001" => match kind {
            0 => "boot-record",
            1 => "primary",
            2 => "supplementary",
            3 => "partition",
            255 => "terminator",
            _ => "reserved",
        },
        b"BEA01" => "udf-begin",
        b"NSR02" | b"NSR03" => "udf-structure",
        b"TEA01" => "udf-end",
        b"BOOT2" => "udf-boot",
        _ => "unknown",
    }
}

#[inline]
fn sector_at(bytes: &[u8], sector: usize) -> Option<&[u8]> {
    let start = sector.checked_mul(SECTOR)?;
    bytes.get(start..start.checked_add(SECTOR)?)
}

// ---------------------------------------------------------------------------
// Primary / supplementary volume descriptor
// ---------------------------------------------------------------------------

struct Pvd {
    system_id: Vec<u8>,
    volume_id: Vec<u8>,
    volume_set_id: Vec<u8>,
    publisher_id: Vec<u8>,
    preparer_id: Vec<u8>,
    application_id: Vec<u8>,
    copyright_file: Vec<u8>,
    abstract_file: Vec<u8>,
    bibliographic_file: Vec<u8>,
    escape: Vec<u8>,
    volume_space_sectors: u32,
    volume_set_size: u16,
    volume_sequence_number: u16,
    logical_block_size: u16,
    path_table_size: u32,
    /// Both path table copies (little- and big-endian), by sector. Needed to
    /// mark their sectors as metadata when accounting for unclaimed space.
    path_table_lba: [u32; 2],
    file_structure_version: u8,
    root_lba: u32,
    root_len: u32,
    created: Option<IsoTime>,
    modified: Option<IsoTime>,
    expires: Option<IsoTime>,
    effective: Option<IsoTime>,
    application_use_nonzero: usize,
}

impl Pvd {
    fn parse(body: &[u8]) -> Option<Self> {
        // Every offset below is from ECMA-119 §8.4. A descriptor is a full
        // sector, so a short read means a truncated image.
        if body.len() < SECTOR {
            return None;
        }
        let root = body.get(156..190)?;
        Some(Self {
            system_id: field(body, 8, 32),
            volume_id: field(body, 40, 32),
            volume_set_id: field(body, 190, 128),
            publisher_id: field(body, 318, 128),
            preparer_id: field(body, 446, 128),
            application_id: field(body, 574, 128),
            copyright_file: field(body, 702, 37),
            abstract_file: field(body, 739, 37),
            bibliographic_file: field(body, 776, 37),
            escape: field(body, 88, 32),
            volume_space_sectors: u32_le(body, 80).unwrap_or(0),
            volume_set_size: u16_le(body, 120).unwrap_or(0),
            volume_sequence_number: u16_le(body, 124).unwrap_or(0),
            logical_block_size: u16_le(body, 128).unwrap_or(0),
            path_table_size: u32_le(body, 132).unwrap_or(0),
            path_table_lba: [
                u32_le(body, 140).unwrap_or(0),
                u32_be(body, 148).unwrap_or(0),
            ],
            file_structure_version: body.get(881).copied().unwrap_or(0),
            root_lba: u32_le(root, 2).unwrap_or(0),
            root_len: u32_le(root, 10).unwrap_or(0),
            created: IsoTime::parse_dec(body.get(813..830)),
            modified: IsoTime::parse_dec(body.get(830..847)),
            expires: IsoTime::parse_dec(body.get(847..864)),
            effective: IsoTime::parse_dec(body.get(864..881)),
            application_use_nonzero: body
                .get(883..1395)
                .map_or(0, |s| s.iter().filter(|b| **b != 0).count()),
        })
    }
}

/// A descriptor identifier field: fixed-width, space-padded ASCII (or, in a
/// Joliet SVD, space-padded UCS-2BE). Trailing padding and NULs are stripped
/// here; decoding is deferred so the caller can pick the right charset.
fn field(body: &[u8], off: usize, len: usize) -> Vec<u8> {
    let Some(raw) = body.get(off..off.saturating_add(len)) else {
        return Vec::new();
    };
    let end = raw
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .map_or(0, |p| p + 1);
    raw.get(..end).unwrap_or_default().to_vec()
}

/// Decode an identifier field. Joliet descriptors store them as UCS-2BE;
/// the primary descriptor stores a-characters. Both land as UTF-8 here.
fn decode_field(raw: &[u8], ucs2: bool) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if ucs2 {
        decode_ucs2be(raw)
    } else {
        raw.iter().map(|b| char::from(*b)).collect()
    }
}

fn decode_ucs2be(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches(['\u{0}', ' '])
        .to_string()
}

/// Joliet escape sequences select a UCS-2 collection level (ECMA-119
/// Annex A / Microsoft's Joliet spec): `%/@` = level 1, `%/C` = 2, `%/E` = 3.
fn joliet_level(escape: &[u8]) -> Option<u8> {
    // The field is a sequence of escapes; the Joliet one may not be first.
    escape.windows(3).find_map(|w| match w {
        b"%/@" => Some(1),
        b"%/C" => Some(2),
        b"%/E" => Some(3),
        _ => None,
    })
}

fn emit_pvd(
    pvd: &Pvd,
    values: &mut Values,
    metrics: &mut Metrics,
    anomalies: &mut Vec<&'static str>,
) {
    let idents = [
        ("iso.system_id", &pvd.system_id),
        ("iso.volume_id", &pvd.volume_id),
        ("iso.volume_set_id", &pvd.volume_set_id),
        ("iso.publisher_id", &pvd.publisher_id),
        ("iso.preparer_id", &pvd.preparer_id),
        ("iso.application_id", &pvd.application_id),
        ("iso.copyright_file", &pvd.copyright_file),
        ("iso.abstract_file", &pvd.abstract_file),
        ("iso.bibliographic_file", &pvd.bibliographic_file),
    ];
    for (key, raw) in idents {
        let text = decode_field(raw, false);
        if !text.is_empty() {
            values.insert(key, JsonValue::String(text));
        }
    }

    metrics.insert(
        metric!("iso.volume_space_sectors"),
        f64::from(pvd.volume_space_sectors),
    );
    metrics.insert(
        metric!("iso.volume_set_size"),
        f64::from(pvd.volume_set_size),
    );
    metrics.insert(
        metric!("iso.volume_sequence_number"),
        f64::from(pvd.volume_sequence_number),
    );
    metrics.insert(
        metric!("iso.logical_block_size"),
        f64::from(pvd.logical_block_size),
    );
    metrics.insert(
        metric!("iso.path_table_bytes"),
        f64::from(pvd.path_table_size),
    );
    metrics.insert(
        metric!("iso.file_structure_version"),
        f64::from(pvd.file_structure_version),
    );
    metrics.insert(
        metric!("iso.application_use_nonzero_bytes"),
        pvd.application_use_nonzero as f64,
    );

    for (unix, gmt_offset, time) in [
        (
            metric!("iso.created_unix"),
            metric!("iso.created_gmt_offset_minutes"),
            &pvd.created,
        ),
        (
            metric!("iso.modified_unix"),
            metric!("iso.modified_gmt_offset_minutes"),
            &pvd.modified,
        ),
        (
            metric!("iso.expires_unix"),
            metric!("iso.expires_gmt_offset_minutes"),
            &pvd.expires,
        ),
        (
            metric!("iso.effective_unix"),
            metric!("iso.effective_gmt_offset_minutes"),
            &pvd.effective,
        ),
    ] {
        if let Some(t) = time {
            metrics.insert(unix, t.unix as f64);
            metrics.insert(gmt_offset, f64::from(t.gmt_offset_minutes));
        }
    }

    // The mastering tool. Every burner stamps itself into one of these
    // fields; a library or ad-hoc script leaves them blank. `iso.builder`
    // is the normalised name, `iso.builder_source` says which field it
    // came from so a rule can tell a real stamp from an imitation.
    if let Some((tool, source)) = detect_builder(pvd) {
        values.insert("iso.builder", JsonValue::String(tool.into()));
        values.insert("iso.builder_source", JsonValue::String(source.into()));
    }
    let blank = [
        &pvd.system_id,
        &pvd.volume_set_id,
        &pvd.publisher_id,
        &pvd.preparer_id,
        &pvd.application_id,
    ]
    .iter()
    .filter(|f| f.is_empty())
    .count();
    metrics.insert(metric!("iso.blank_identifier_fields"), blank as f64);

    if pvd.logical_block_size != SECTOR as u16 {
        anomalies.push("nonstandard-block-size");
    }
    if pvd.file_structure_version != 1 {
        anomalies.push("nonstandard-structure-version");
    }
    if pvd.application_use_nonzero > 0 {
        anomalies.push("application-use-populated");
    }
}

/// Mastering-tool signatures, matched case-insensitively as substrings of
/// the PVD identifier fields. Ordered most specific first: `genisoimage`
/// and `xorriso` both carry the mkisofs banner text for compatibility, so
/// they must be tested before it.
const BUILDERS: &[(&str, &str)] = &[
    ("XORRISO", "xorriso"),
    ("GENISOIMAGE", "genisoimage"),
    ("CDRKIT", "genisoimage"),
    ("MKISOFS", "mkisofs"),
    ("IMGBURN", "imgburn"),
    ("CDIMAGE", "oscdimg"),
    ("OSCDIMG", "oscdimg"),
    ("POWERISO", "poweriso"),
    ("ULTRAISO", "ultraiso"),
    ("MAGICISO", "magiciso"),
    ("WINISO", "winiso"),
    ("ANYBURN", "anyburn"),
    ("ANYTOISO", "anytoiso"),
    ("NERO", "nero"),
    ("CDBURNERXP", "cdburnerxp"),
    ("INFRARECORDER", "infrarecorder"),
    ("BRASERO", "brasero"),
    ("K3B", "k3b"),
    ("PYCDLIB", "pycdlib"),
    ("FOLDER2ISO", "folder2iso"),
    ("WINARCHIVER", "winarchiver"),
    ("DAEMON TOOLS", "daemon-tools"),
    ("ALCOHOL", "alcohol"),
    ("ROXIO", "roxio"),
    ("APPLE COMPUTER", "hdiutil"),
    ("HDIUTIL", "hdiutil"),
];

fn detect_builder(pvd: &Pvd) -> Option<(&'static str, &'static str)> {
    let fields = [
        ("application_id", &pvd.application_id),
        ("preparer_id", &pvd.preparer_id),
        ("system_id", &pvd.system_id),
        ("publisher_id", &pvd.publisher_id),
    ];
    for (source, raw) in fields {
        let upper = decode_field(raw, false).to_ascii_uppercase();
        if upper.is_empty() {
            continue;
        }
        for (needle, tool) in BUILDERS {
            if upper.contains(needle) {
                return Some((tool, source));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

struct IsoTime {
    unix: i64,
    gmt_offset_minutes: i16,
}

impl IsoTime {
    /// ECMA-119 §8.4.26.1 "digits" form: 16 ASCII digits plus a signed
    /// quarter-hour GMT offset. An all-zero (or all-`'0'`) field is the
    /// standard's "not specified" sentinel, not a 1st-of-January date.
    fn parse_dec(raw: Option<&[u8]>) -> Option<Self> {
        let raw = raw?;
        let digits = raw.get(..16)?;
        if digits.iter().all(|b| *b == b'0' || *b == 0) {
            return None;
        }
        let num = |off: usize, len: usize| -> Option<i64> {
            let s = digits.get(off..off + len)?;
            let mut v: i64 = 0;
            for b in s {
                v = v * 10 + i64::from(b.checked_sub(b'0').filter(|d| *d < 10)?);
            }
            Some(v)
        };
        let year = num(0, 4)?;
        let month = num(4, 2)?;
        let day = num(6, 2)?;
        let hour = num(8, 2)?;
        let minute = num(10, 2)?;
        let second = num(12, 2)?;
        let offset = raw.get(16).map_or(0, |b| i16::from(*b as i8));
        Self::assemble(year, month, day, hour, minute, second, offset)
    }

    /// ECMA-119 §9.1.5 "binary" form used by directory records: years since
    /// 1900 and a quarter-hour GMT offset, seven bytes total.
    fn parse_bin(raw: Option<&[u8]>) -> Option<Self> {
        let raw = raw?;
        let b = raw.get(..7)?;
        if b.iter().all(|x| *x == 0) {
            return None;
        }
        Self::assemble(
            1900 + i64::from(b[0]),
            i64::from(b[1]),
            i64::from(b[2]),
            i64::from(b[3]),
            i64::from(b[4]),
            i64::from(b[5]),
            i16::from(b[6] as i8),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        second: i64,
        quarter_hours: i16,
    ) -> Option<Self> {
        // Writers that don't fill the optional expiration/effective fields
        // leave them as 1900-01-01 rather than as the standard's all-`'0'`
        // sentinel. Neither is a date; both would otherwise surface as a
        // large negative Unix timestamp.
        if !(1970..=2999).contains(&year) || !(0..24).contains(&hour) {
            return None;
        }
        let y = i32::try_from(year).ok()?;
        let days = days_from_civil(y, u32::try_from(month).ok()?, u32::try_from(day).ok()?)?;
        // The recorded time is local to the recording machine; the offset
        // converts it to UTC. The offset itself is kept — a mismatch
        // between an image's offset and its claimed origin is evidence.
        let gmt_offset_minutes = quarter_hours.saturating_mul(15);
        let local = days * 86_400 + hour * 3600 + minute * 60 + second;
        Some(Self {
            unix: local - i64::from(gmt_offset_minutes) * 60,
            gmt_offset_minutes,
        })
    }
}

// ---------------------------------------------------------------------------
// System area (isohybrid / hidden pre-descriptor data)
// ---------------------------------------------------------------------------

fn emit_system_area(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    anomalies: &mut Vec<&'static str>,
) {
    let area = bytes
        .get(..SYSTEM_AREA_SECTORS * SECTOR)
        .unwrap_or_default();
    let nonzero = area.iter().filter(|b| **b != 0).count();
    metrics.insert(metric!("iso.system_area.nonzero_bytes"), nonzero as f64);

    // A conforming image leaves this reserved. Real content means the
    // image is also bootable as a raw disk (isohybrid), or that someone
    // parked bytes where no filesystem walk will look.
    let kind = if nonzero == 0 {
        "empty"
    } else if area.get(510..512) == Some(&[0x55, 0xAA]) {
        if area
            .get(SECTOR..SECTOR + 8)
            .is_some_and(|s| s == b"EFI PART")
        {
            "gpt"
        } else {
            "mbr"
        }
    } else if area.get(..2) == Some(b"ER") {
        "apm"
    } else {
        "data"
    };
    values.insert("iso.system_area.kind", JsonValue::String(kind.into()));

    if kind == "mbr" || kind == "gpt" {
        let mut parts = Vec::new();
        for i in 0..4 {
            let off = 446 + i * 16;
            let Some(e) = area.get(off..off + 16) else {
                break;
            };
            let ptype = e.get(4).copied().unwrap_or(0);
            let start = u32_le(e, 8).unwrap_or(0);
            let count = u32_le(e, 12).unwrap_or(0);
            if ptype == 0 && start == 0 && count == 0 {
                continue;
            }
            parts.push(json!({
                "bootable": e.first().copied().unwrap_or(0) == 0x80,
                "type": ptype,
                "start_lba": start,
                "sectors": count,
            }));
        }
        if !parts.is_empty() {
            values.insert("iso.system_area.partitions", JsonValue::Array(parts));
        }
    } else if kind == "data" {
        anomalies.push("nonzero-system-area");
    }
}

// ---------------------------------------------------------------------------
// El Torito boot catalog
// ---------------------------------------------------------------------------

/// Returns true when a well-formed El Torito catalog was found.
fn emit_boot(
    bytes: &[u8],
    body: &[u8],
    pvd: &Pvd,
    values: &mut Values,
    metrics: &mut Metrics,
    anomalies: &mut Vec<&'static str>,
    claimed: &mut Vec<(u64, u64)>,
    archive_members: &mut Vec<ArchiveMember>,
) -> bool {
    let boot_system = decode_field(&field(body, 7, 32), false);
    values.insert("iso.boot.system_id", JsonValue::String(boot_system.clone()));
    if !boot_system.to_ascii_uppercase().starts_with("EL TORITO") {
        // A boot record that isn't El Torito still means "this image
        // claims to boot"; record the claim without inventing a catalog.
        values.insert("iso.boot.bootable", JsonValue::Bool(true));
        return false;
    }

    let catalog_lba = u32_le(body, 71).unwrap_or(0);
    metrics.insert(metric!("iso.boot.catalog_lba"), f64::from(catalog_lba));
    if catalog_lba >= pvd.volume_space_sectors {
        anomalies.push("boot-catalog-out-of-range");
    }
    let Some(catalog) = sector_at(bytes, catalog_lba as usize) else {
        anomalies.push("boot-catalog-unreadable");
        return false;
    };
    let catalog_start = u64::from(catalog_lba) * SECTOR as u64;
    claimed.push((catalog_start, catalog_start + SECTOR as u64));

    // Validation entry: header 0x01, a platform id, and a 0x55AA key.
    let valid = catalog.first() == Some(&0x01) && catalog.get(30..32) == Some(&[0x55, 0xAA]);
    if !valid {
        anomalies.push("boot-catalog-invalid");
    }
    let manufacturer = decode_field(&field(catalog, 4, 24), false);
    if !manufacturer.is_empty() {
        values.insert("iso.boot.manufacturer", JsonValue::String(manufacturer));
    }

    let mut entries = Vec::new();
    let mut platforms: Vec<&'static str> = Vec::new();
    let mut current_platform = catalog.get(1).copied().unwrap_or(0);
    let mut bootable_count = 0_u32;
    let mut offset = 32;

    while offset + 32 <= catalog.len() && entries.len() < MAX_BOOT_ENTRIES {
        let Some(e) = catalog.get(offset..offset + 32) else {
            break;
        };
        offset += 32;
        let header = e.first().copied().unwrap_or(0);
        match header {
            // Section header: switches the platform for the entries after it.
            0x90 | 0x91 => {
                current_platform = e.get(1).copied().unwrap_or(0);
                continue;
            }
            // Extension entry — continuation of the previous section entry.
            0x44 => continue,
            // Bootable (0x88) or non-bootable (0x00) section entry. A zero
            // byte is also what padding looks like, so an all-zero record
            // ends the catalog.
            0x88 | 0x00 => {
                if e.iter().all(|b| *b == 0) {
                    break;
                }
            }
            _ => break,
        }
        let bootable = header == 0x88;
        if bootable {
            bootable_count += 1;
        }
        let platform = platform_name(current_platform);
        if !platforms.contains(&platform) {
            platforms.push(platform);
        }
        let media = e.get(1).copied().unwrap_or(0);
        let load_rba = u32_le(e, 8).unwrap_or(0);
        let sectors = u16_le(e, 6).unwrap_or(0);
        entries.push(json!({
            "bootable": bootable,
            "platform": platform,
            "platform_id": current_platform,
            "media_type": media_name(media),
            "load_segment": u16_le(e, 2).unwrap_or(0),
            "system_type": e.get(4).copied().unwrap_or(0),
            "sector_count": sectors,
            "load_rba": load_rba,
            // Boot images are addressed in 512-byte virtual sectors but
            // located by 2048-byte LBA; the byte offset is what a caller
            // needs to carve the image out.
            "offset": u64::from(load_rba) * SECTOR as u64,
        }));
        if load_rba >= pvd.volume_space_sectors {
            anomalies.push("boot-image-out-of-range");
        }
        // El Torito counts a boot image in 512-byte virtual sectors even
        // though it is placed on a 2048-byte boundary.
        let image_start = u64::from(load_rba) * SECTOR as u64;
        let image_len = u64::from(sectors).saturating_mul(512).max(SECTOR as u64);
        claimed.push((image_start, image_start.saturating_add(image_len)));
        // The boot image is executable content that no directory entry
        // names — a bootkit lives here, not in the file tree — so it is
        // surfaced as a member and analysed like any other payload.
        archive_members.push(ArchiveMember {
            path: format!(".iso-boot/{platform}-{}.img", entries.len()),
            size_bytes: image_len,
            entry_type: Some("boot-image".into()),
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership: None,
            offsets: ArchiveOffsets {
                header: None,
                data: Some(image_start),
                central_header: None,
            },
        });
    }

    metrics.insert(metric!("iso.boot.entry_count"), entries.len() as f64);
    metrics.insert(
        metric!("iso.boot.bootable_entry_count"),
        f64::from(bootable_count),
    );
    values.insert("iso.boot.bootable", JsonValue::Bool(bootable_count > 0));
    values.insert(
        "iso.boot.platforms",
        JsonValue::Array(platforms.iter().map(|p| json!(p)).collect()),
    );
    values.insert("iso.boot.efi", JsonValue::Bool(platforms.contains(&"efi")));
    values.insert("iso.boot.entries", JsonValue::Array(entries));
    true
}

fn platform_name(id: u8) -> &'static str {
    match id {
        0x00 => "x86",
        0x01 => "powerpc",
        0x02 => "mac",
        0xEF => "efi",
        _ => "unknown",
    }
}

fn media_name(id: u8) -> &'static str {
    match id & 0x0F {
        0 => "no-emulation",
        1 => "floppy-1.2m",
        2 => "floppy-1.44m",
        3 => "floppy-2.88m",
        4 => "hard-disk",
        _ => "reserved",
    }
}

// ---------------------------------------------------------------------------
// Directory tree walk
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Namespace {
    Iso9660,
    Joliet,
    Supplementary,
}

impl Namespace {
    fn label(self) -> &'static str {
        match self {
            Self::Iso9660 => "iso9660",
            Self::Joliet => "joliet",
            Self::Supplementary => "supplementary",
        }
    }
}

struct Entry {
    namespace: Namespace,
    path: String,
    /// Rock Ridge `NM` name, when the record carries one. This is the name a
    /// Linux reader shows, and it can differ from both other namespaces.
    alt_name: Option<String>,
    lba: u32,
    size: u32,
    flags: u8,
    recorded: Option<i64>,
    depth: u32,
    /// False when the file's bytes are not one contiguous range —
    /// interleaved recording or a split multi-extent file.
    contiguous: bool,
    /// Extended attribute record length, in sectors, preceding the data.
    ext_attr_sectors: u8,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    symlink: Option<String>,
}

impl Entry {
    fn is_dir(&self) -> bool {
        self.flags & 0x02 != 0
    }
    fn hidden(&self) -> bool {
        self.flags & 0x01 != 0
    }
    fn associated(&self) -> bool {
        self.flags & 0x04 != 0
    }
    /// Byte offset of the file's first data sector, past any extended
    /// attribute record.
    fn data_offset(&self) -> u64 {
        (u64::from(self.lba) + u64::from(self.ext_attr_sectors)) * SECTOR as u64
    }
}

struct Walk {
    entries: Vec<Entry>,
    visited: Vec<(u32, u32)>,
    rock_ridge: bool,
    apple: bool,
    truncated: bool,
    dirs_walked: usize,
}

impl Walk {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            visited: Vec::new(),
            rock_ridge: false,
            apple: false,
            truncated: false,
            dirs_walked: 0,
        }
    }

    fn run(&mut self, bytes: &[u8], root_lba: u32, root_len: u32, ns: Namespace) {
        // Breadth-first with an explicit queue: an ISO directory tree is
        // untrusted input and can be cyclic, so recursion is not an option
        // and `visited` is keyed on the extent, not the path.
        let mut queue = vec![(root_lba, root_len, String::new(), 0_u32)];
        let mut head = 0;
        while head < queue.len() {
            let (lba, len, prefix, depth) = queue[head].clone();
            head += 1;
            if self.dirs_walked >= MAX_DIRS || self.entries.len() >= MAX_ENTRIES {
                self.truncated = true;
                return;
            }
            if depth > MAX_DEPTH {
                self.truncated = true;
                continue;
            }
            if self.visited.contains(&(lba, len)) {
                continue;
            }
            self.visited.push((lba, len));
            self.dirs_walked += 1;

            let start = (lba as usize).saturating_mul(SECTOR);
            let want = (len as usize).min(MAX_DIR_EXTENT);
            let Some(extent) = bytes.get(start..start.saturating_add(want)) else {
                self.truncated = true;
                continue;
            };
            for e in self.parse_extent(bytes, extent, &prefix, depth, ns) {
                if e.is_dir() {
                    queue.push((e.lba, e.size, e.path.clone(), depth + 1));
                }
                self.entries.push(e);
            }
        }
    }

    fn parse_extent(
        &mut self,
        bytes: &[u8],
        extent: &[u8],
        prefix: &str,
        depth: u32,
        ns: Namespace,
    ) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut pos = 0_usize;
        while pos < extent.len() {
            let len = extent.get(pos).copied().unwrap_or(0) as usize;
            if len == 0 {
                // Records never straddle a sector; a zero length is the
                // pad to the next sector boundary.
                let next = (pos / SECTOR + 1) * SECTOR;
                if next <= pos {
                    break;
                }
                pos = next;
                continue;
            }
            if len < 33 {
                break;
            }
            let Some(rec) = extent.get(pos..pos.saturating_add(len)) else {
                break;
            };
            pos += len;

            let name_len = rec.get(32).copied().unwrap_or(0) as usize;
            let Some(raw_name) = rec.get(33..33usize.saturating_add(name_len)) else {
                continue;
            };
            // `.` and `..` are stored as single 0x00 / 0x01 bytes.
            if name_len == 1 && matches!(raw_name.first(), Some(0) | Some(1)) {
                continue;
            }
            let flags = rec.get(25).copied().unwrap_or(0);
            let name = decode_name(raw_name, ns == Namespace::Joliet);
            if name.is_empty() || name.contains('/') {
                continue;
            }

            let mut entry = Entry {
                namespace: ns,
                path: format!("{prefix}/{name}"),
                alt_name: None,
                lba: u32_le(rec, 2).unwrap_or(0),
                size: u32_le(rec, 10).unwrap_or(0),
                flags,
                recorded: IsoTime::parse_bin(rec.get(18..25)).map(|t| t.unix),
                depth,
                // A non-zero file unit size or interleave gap means the
                // extent is recorded in strides, not one run.
                contiguous: rec.get(26) == Some(&0) && rec.get(27) == Some(&0),
                ext_attr_sectors: rec.get(1).copied().unwrap_or(0),
                mode: None,
                uid: None,
                gid: None,
                symlink: None,
            };

            // System-use area: everything after the name, padded to even.
            let su_start = 33 + name_len + usize::from(name_len % 2 == 0);
            if let Some(su) = rec.get(su_start..) {
                self.parse_susp(bytes, su, &mut entry, prefix, 0);
            }
            out.push(entry);
            if self.entries.len() + out.len() >= MAX_ENTRIES {
                self.truncated = true;
                break;
            }
        }
        out
    }

    /// System Use Sharing Protocol entries — the carrier for Rock Ridge.
    /// `CE` chains into a continuation area elsewhere in the image, which
    /// is followed up to `MAX_CE_HOPS` deep.
    fn parse_susp(&mut self, bytes: &[u8], su: &[u8], entry: &mut Entry, prefix: &str, hop: usize) {
        let mut pos = 0_usize;
        while pos + 4 <= su.len() {
            let Some(head) = su.get(pos..pos + 4) else {
                break;
            };
            let len = head[2] as usize;
            if len < 4 {
                break;
            }
            let Some(rec) = su.get(pos..pos.saturating_add(len)) else {
                break;
            };
            pos += len;
            let sig = [head[0], head[1]];
            // SUSP entries have a four-byte header: two-byte signature,
            // length, and version. Record-specific payload begins at byte 4.
            // NM and SL then carry their own flags byte at payload[0]; their
            // decoders skip that byte themselves. Starting every payload at
            // byte 5 dropped the first Rock Ridge filename character and also
            // shifted PX ownership, CE continuation, and SL component fields.
            let data = rec.get(4..).unwrap_or_default();
            match &sig {
                b"SP" | b"RR" => self.rock_ridge = true,
                b"ER" => {
                    self.rock_ridge = true;
                }
                b"PX" => {
                    self.rock_ridge = true;
                    // Both-endian fields: LSB first.
                    entry.mode = u32_le(data, 0);
                    entry.uid = u32_le(data, 16).map(u64::from);
                    entry.gid = u32_le(data, 24).map(u64::from);
                }
                b"NM" => {
                    self.rock_ridge = true;
                    // Flag bit 0 = continues in the next NM entry.
                    let part = String::from_utf8_lossy(data.get(1..).unwrap_or_default());
                    match &mut entry.alt_name {
                        Some(existing) => existing.push_str(&part),
                        None => entry.alt_name = Some(part.into_owned()),
                    }
                }
                b"SL" => {
                    self.rock_ridge = true;
                    let target = entry.symlink.get_or_insert_with(String::new);
                    decode_symlink(data, target);
                }
                b"AA" | b"AB" | b"AS" => self.apple = true,
                b"CE" => {
                    if hop >= MAX_CE_HOPS {
                        continue;
                    }
                    let (Some(block), Some(off), Some(len)) =
                        (u32_le(data, 0), u32_le(data, 8), u32_le(data, 16))
                    else {
                        continue;
                    };
                    let start = (block as usize)
                        .saturating_mul(SECTOR)
                        .saturating_add(off as usize);
                    let end = start.saturating_add((len as usize).min(SECTOR * 4));
                    if let Some(cont) = bytes.get(start..end) {
                        // Copy out: `bytes` is borrowed immutably while
                        // `entry` is borrowed mutably by the recursion.
                        let cont = cont.to_vec();
                        self.parse_susp(bytes, &cont, entry, prefix, hop + 1);
                    }
                }
                b"ST" => break,
                _ => {}
            }
        }
        if let Some(alt) = entry.alt_name.as_ref()
            && !alt.is_empty()
        {
            entry.path = format!("{prefix}/{alt}");
        }
    }
}

/// Reassemble an `SL` (symlink) entry's component list. Components are
/// length-prefixed with flag bits for `.`, `..`, and `/`.
fn decode_symlink(data: &[u8], out: &mut String) {
    let mut pos = 1_usize; // skip the entry flags byte
    while pos + 2 <= data.len() && out.len() < MAX_SYMLINK_LEN {
        let flags = data[pos];
        let len = data[pos + 1] as usize;
        pos += 2;
        let component = data.get(pos..pos.saturating_add(len)).unwrap_or_default();
        pos = pos.saturating_add(len);
        if flags & 0x08 != 0 {
            out.clear();
            out.push('/');
            continue;
        }
        if !out.is_empty() && !out.ends_with('/') {
            out.push('/');
        }
        if flags & 0x02 != 0 {
            out.push('.');
        } else if flags & 0x04 != 0 {
            out.push_str("..");
        } else {
            out.push_str(&String::from_utf8_lossy(component));
        }
    }
}

/// Decode a directory record's name. ISO 9660 names are d-characters with
/// a `;<version>` suffix; Joliet names are UCS-2BE with the same suffix.
/// The version is stripped — it is an artefact of the standard, never part
/// of the name a user or a loader sees.
fn decode_name(raw: &[u8], ucs2: bool) -> String {
    let decoded = if ucs2 {
        decode_ucs2be(raw)
    } else {
        raw.iter().map(|b| char::from(*b)).collect::<String>()
    };
    let stripped = decoded
        .rsplit_once(';')
        .filter(|(_, ver)| !ver.is_empty() && ver.chars().all(|c| c.is_ascii_digit()))
        .map_or(decoded.as_str(), |(base, _)| base);
    // A name with no extension is stored with a trailing dot.
    stripped.strip_suffix('.').unwrap_or(stripped).to_string()
}

// ---------------------------------------------------------------------------
// Namespace merge
// ---------------------------------------------------------------------------

/// One logical file, with every name the image gives it.
struct File {
    path: String,
    names: Vec<(&'static str, String)>,
    lba: u32,
    size: u32,
    offset: u64,
    contiguous: bool,
    is_dir: bool,
    hidden: bool,
    associated: bool,
    recorded: Option<i64>,
    depth: u32,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    symlink: Option<String>,
    /// Namespaces this extent appears in. A file present in only one of
    /// several namespaces is invisible to readers that follow another.
    namespaces: Vec<&'static str>,
}

/// Union the per-namespace walks into one member list, keyed on the extent
/// each entry points at.
///
/// Keying on `(lba, size)` rather than on the path is what makes the
/// evasion visible: the same bytes carry a different name in each tree,
/// and a payload placed in only one tree still yields a member here.
fn merge_namespaces(entries: Vec<Entry>, anomalies: &mut Vec<&'static str>) -> Vec<File> {
    let mut files: Vec<File> = Vec::new();
    let mut index: std::collections::HashMap<(u32, u32), usize> = std::collections::HashMap::new();

    for e in entries {
        let name = e
            .path
            .rsplit_once('/')
            .map_or(e.path.as_str(), |(_, n)| n)
            .to_string();
        // A zero-length file has no extent to key on; fall back to its path
        // so distinct empty files don't collapse into one member.
        let key = (e.lba, e.size);
        let slot = if e.size == 0 {
            files.iter().position(|f| f.path == e.path && f.size == 0)
        } else {
            index.get(&key).copied()
        };

        match slot {
            Some(i) => {
                let f = &mut files[i];
                if !f.namespaces.contains(&e.namespace.label()) {
                    f.namespaces.push(e.namespace.label());
                }
                if !f.names.iter().any(|(_, n)| *n == name) {
                    f.names.push((e.namespace.label(), name));
                }
                // Prefer the name a user actually sees: Rock Ridge (Linux),
                // then Joliet (Windows), then the 8.3 fallback.
                let better = match e.namespace {
                    Namespace::Iso9660 => e.alt_name.is_some(),
                    Namespace::Joliet => true,
                    Namespace::Supplementary => false,
                };
                if better {
                    f.path.clone_from(&e.path);
                }
                if f.symlink.is_none() {
                    f.symlink.clone_from(&e.symlink);
                }
                if f.mode.is_none() {
                    f.mode = e.mode;
                    f.uid = e.uid;
                    f.gid = e.gid;
                }
            }
            None => {
                if e.size != 0 {
                    index.insert(key, files.len());
                }
                files.push(File {
                    path: e.path.clone(),
                    names: vec![(e.namespace.label(), name)],
                    lba: e.lba,
                    size: e.size,
                    offset: e.data_offset(),
                    contiguous: e.contiguous,
                    is_dir: e.is_dir(),
                    hidden: e.hidden(),
                    associated: e.associated(),
                    recorded: e.recorded,
                    depth: e.depth,
                    mode: e.mode,
                    uid: e.uid,
                    gid: e.gid,
                    symlink: e.symlink,
                    namespaces: vec![e.namespace.label()],
                });
            }
        }
    }

    // Which namespaces exist at all — a file missing from one of them is
    // only interesting when that namespace is otherwise populated.
    let mut present: Vec<&'static str> = Vec::new();
    for f in &files {
        for ns in &f.namespaces {
            if !present.contains(ns) {
                present.push(ns);
            }
        }
    }
    if present.len() > 1 && files.iter().any(|f| f.namespaces.len() < present.len()) {
        anomalies.push("tree-only-file");
    }
    files
}

// ---------------------------------------------------------------------------
// Tree facts
// ---------------------------------------------------------------------------

/// Extensions that execute (or launch something that does) on Windows —
/// the platform an ISO delivery chain targets.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msix", "appx", "bat", "cmd", "ps1", "psm1",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "msc", "cab", "sys", "ocx", "efi",
];

fn emit_tree(
    files: &[File],
    pvd: &Pvd,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    anomalies: &mut Vec<&'static str>,
) {
    let mut file_count = 0_u64;
    let mut dir_count = 0_u64;
    let mut symlink_count = 0_u64;
    let mut hidden_count = 0_u64;
    let mut associated_count = 0_u64;
    let mut setuid_count = 0_u64;
    let mut executable_count = 0_u64;
    let mut lnk_count = 0_u64;
    let mut total_bytes = 0_u64;
    let mut largest = 0_u64;
    let mut max_depth = 0_u32;
    let mut divergent = 0_u64;
    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut surfaced = Vec::new();
    let mut extensions: Vec<String> = Vec::new();

    let volume_sectors = u64::from(pvd.volume_space_sectors);

    for f in files {
        max_depth = max_depth.max(f.depth);
        if f.is_dir {
            dir_count += 1;
            continue;
        }
        if f.symlink.is_some() {
            symlink_count += 1;
        }
        file_count += 1;
        if f.hidden {
            hidden_count += 1;
        }
        if f.associated {
            associated_count += 1;
        }
        if f.mode.is_some_and(|m| m & 0o4000 != 0) {
            setuid_count += 1;
        }
        // Distinct names for one extent across namespaces: the 8.3 mangle
        // is expected, a wholly different basename is not.
        if divergent_names(&f.names) {
            divergent += 1;
        }
        let size = u64::from(f.size);
        total_bytes = total_bytes.saturating_add(size);
        largest = largest.max(size);

        let ext = extension_of(&f.path);
        if EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
            executable_count += 1;
        }
        if ext == "lnk" {
            lnk_count += 1;
        }
        // The distinct extensions present, so a rule can ask about any file
        // kind without this module having to anticipate which ones matter.
        if !ext.is_empty() && !extensions.iter().any(|e| *e == ext) && extensions.len() < 128 {
            extensions.push(ext);
        }

        let end_sector = u64::from(f.lba) + size.div_ceil(SECTOR as u64);
        if size > 0 {
            if end_sector > volume_sectors {
                anomalies.push("extent-beyond-volume");
            }
            if f.offset.saturating_add(size) > bytes.len() as u64 {
                anomalies.push("extent-past-eof");
            }
            extents.push((u64::from(f.lba), end_sector));
        }
        if !f.contiguous {
            anomalies.push("non-contiguous-extent");
        }
        if let Some(target) = &f.symlink
            && (target.starts_with('/') || target.split('/').any(|c| c == ".."))
        {
            anomalies.push("symlink-escapes-image");
        }

        if surfaced.len() < MAX_SURFACED_FILES {
            surfaced.push(file_json(f));
        }
    }

    metrics.insert(metric!("iso.file_count"), file_count as f64);
    metrics.insert(metric!("iso.dir_count"), dir_count as f64);
    metrics.insert(metric!("iso.symlink_count"), symlink_count as f64);
    metrics.insert(metric!("iso.hidden_file_count"), hidden_count as f64);
    metrics.insert(
        metric!("iso.associated_file_count"),
        associated_count as f64,
    );
    metrics.insert(metric!("iso.setuid_file_count"), setuid_count as f64);
    metrics.insert(
        metric!("iso.executable_file_count"),
        executable_count as f64,
    );
    metrics.insert(metric!("iso.lnk_file_count"), lnk_count as f64);
    metrics.insert(metric!("iso.divergent_name_count"), divergent as f64);
    metrics.insert(metric!("iso.max_depth"), f64::from(max_depth));
    metrics.insert(metric!("iso.total_file_bytes"), total_bytes as f64);
    metrics.insert(metric!("iso.largest_file_bytes"), largest as f64);
    metrics.insert(metric!("iso.surfaced_file_count"), surfaced.len() as f64);

    // One file holding nearly the whole image is the shape of a delivery
    // wrapper rather than of distribution media.
    let declared = volume_sectors.saturating_mul(SECTOR as u64);
    if declared > 0 {
        metrics.insert(
            metric!("iso.largest_file_ratio"),
            largest as f64 / declared as f64,
        );
    }
    if divergent > 0 {
        anomalies.push("namespace-name-divergence");
    }

    // Overlapping extents mean two names resolve to the same bytes with
    // different declared lengths — a reader-dependent view of the payload.
    extents.sort_unstable();
    if extents.windows(2).any(|w| w[1].0 < w[0].1) {
        anomalies.push("overlapping-extents");
    }

    extensions.sort_unstable();
    values.insert(
        "iso.file_extensions",
        JsonValue::Array(extensions.into_iter().map(JsonValue::String).collect()),
    );
    values.insert("iso.files", JsonValue::Array(surfaced));
}

/// Cap on unclaimed regions reported. A fragmented image must not turn into
/// thousands of pseudo-members.
const MAX_UNCLAIMED_REGIONS: usize = 8;
/// Smallest unclaimed run worth reporting. Below a couple of sectors a gap
/// is ordinary alignment padding.
const MIN_UNCLAIMED_BYTES: u64 = 4096;

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
fn unclaimed_regions(
    files: &[File],
    pvd: &Pvd,
    bytes: &[u8],
    mut claimed: Vec<(u64, u64)>,
) -> Vec<(&'static str, u64, u64)> {
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
            out.push(("slack", cursor, start - cursor));
        }
        cursor = cursor.max(end);
    }
    if declared > cursor && declared - cursor >= MIN_UNCLAIMED_BYTES {
        out.push(("slack", cursor, declared - cursor));
    }
    // Bytes past the volume the descriptors declare. No mastering tool
    // writes here; an appended payload does. Reported whatever its size —
    // unlike interior padding, any trailing byte is unaccounted for.
    let actual = bytes.len() as u64;
    if actual > declared {
        out.push(("trailing", declared, actual - declared));
    }

    out.retain(|(kind, off, len)| {
        // Trailing data is reported even when zeroed: nothing should be
        // there at all. Interior padding is normally zeroed and says
        // nothing, so only a populated run counts.
        *kind == "trailing"
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

fn emit_unclaimed(
    regions: &[(&'static str, u64, u64)],
    declared: u64,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    anomalies: &mut Vec<&'static str>,
) {
    let total: u64 = regions
        .iter()
        .filter(|(kind, _, _)| *kind == "slack")
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
        list.push(json!({ "kind": kind, "offset": offset, "size_bytes": len }));
        archive_members.push(ArchiveMember {
            path: match *kind {
                "trailing" => ".iso-unclaimed/trailing.bin".to_string(),
                _ => format!(".iso-unclaimed/slack-{offset:#x}.bin"),
            },
            size_bytes: *len,
            // A distinct entry type, not `regular`: these are byte ranges the
            // filesystem does not name, and a consumer must be able to tell
            // them apart from files the image actually declares.
            entry_type: Some((*kind).to_string()),
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership: None,
            offsets: ArchiveOffsets {
                header: None,
                data: Some(*offset),
                central_header: None,
            },
        });
    }
    if !list.is_empty() {
        values.insert("iso.unclaimed", JsonValue::Array(list));
    }
}

fn file_json(f: &File) -> JsonValue {
    let mut obj = JsonMap::new();
    obj.insert("path".into(), json!(f.path));
    obj.insert("size_bytes".into(), json!(f.size));
    obj.insert("lba".into(), json!(f.lba));
    obj.insert("offset".into(), json!(f.offset));
    obj.insert("namespaces".into(), json!(f.namespaces));
    if f.names.len() > 1 {
        obj.insert(
            "names".into(),
            JsonValue::Array(
                f.names
                    .iter()
                    .map(|(ns, n)| json!({ "namespace": ns, "name": n }))
                    .collect(),
            ),
        );
    }
    if f.hidden {
        obj.insert("hidden".into(), json!(true));
    }
    if f.associated {
        obj.insert("associated".into(), json!(true));
    }
    if !f.contiguous {
        obj.insert("contiguous".into(), json!(false));
    }
    if let Some(t) = f.recorded {
        obj.insert("recorded_unix".into(), json!(t));
    }
    if let Some(m) = f.mode {
        obj.insert("mode_octal".into(), json!(m));
    }
    if let Some(t) = &f.symlink {
        obj.insert("symlink_target".into(), json!(t));
    }
    JsonValue::Object(obj)
}

/// True when the names an extent carries across namespaces differ by more
/// than the 8.3 mangle. `INSTALL0` vs `Installer_v1836_x64.exe` is expected;
/// `readme` vs `invoice.exe` is not.
fn divergent_names(names: &[(&'static str, String)]) -> bool {
    let mut stems = names.iter().map(|(_, n)| {
        let lower = n.to_ascii_lowercase();
        let stem = lower
            .split_once('.')
            .map_or(lower.clone(), |(s, _)| s.to_string());
        // The 8.3 form is a truncation of the long name, optionally with a
        // generated tail digit; compare on the shared prefix.
        stem
    });
    let Some(first) = stems.next() else {
        return false;
    };
    stems.any(|s| {
        let n = first.len().min(s.len()).min(6);
        n == 0 || first.get(..n) != s.get(..n)
    })
}

fn extension_of(path: &str) -> String {
    path.rsplit_once('/')
        .map_or(path, |(_, n)| n)
        .rsplit_once('.')
        .map_or(String::new(), |(_, e)| e.to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

fn emit_members(files: &[File], archive_members: &mut Vec<ArchiveMember>) {
    for f in files {
        let entry_type = if f.is_dir {
            "directory"
        } else if f.symlink.is_some() {
            "symlink"
        } else {
            "regular"
        };
        let ownership = (f.mode.is_some() || f.uid.is_some()).then_some(ArchiveOwnership {
            mode_octal: f.mode,
            uid: f.uid,
            gid: f.gid,
            uname: None,
            gname: None,
        });
        archive_members.push(ArchiveMember {
            path: f.path.trim_start_matches('/').to_string(),
            size_bytes: u64::from(f.size),
            entry_type: Some(entry_type.into()),
            mtime_unix: f.recorded,
            linkname: f.symlink.clone(),
            host_os: None,
            crc32: None,
            encrypted: false,
            // ISO 9660 stores file data verbatim; there is no per-member
            // codec to report, and the "compressed" size is the real size.
            compression: None,
            ownership,
            offsets: ArchiveOffsets {
                header: None,
                // Only hand out an offset a caller can slice. An interleaved
                // or split file's bytes are not one range, so no offset is
                // better than a wrong one.
                data: (!f.is_dir && f.contiguous && f.size > 0).then_some(f.offset),
                central_header: None,
            },
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn joliet_levels_recognised() {
        assert_eq!(joliet_level(b"%/@"), Some(1));
        assert_eq!(joliet_level(b"%/C"), Some(2));
        assert_eq!(joliet_level(b"%/E"), Some(3));
        assert_eq!(joliet_level(b""), None);
        assert_eq!(joliet_level(b"%/X"), None);
    }

    #[test]
    fn version_suffix_stripped_from_names() {
        assert_eq!(decode_name(b"SETUP.EXE;1", false), "SETUP.EXE");
        assert_eq!(decode_name(b"README.;1", false), "README");
        // A semicolon that isn't a version marker stays put.
        assert_eq!(decode_name(b"a;b", false), "a;b");
    }

    #[test]
    fn joliet_names_decode_from_ucs2be() {
        let name: Vec<u8> = "hi.exe".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(decode_name(&name, true), "hi.exe");
    }

    #[test]
    fn dec_datetime_sentinel_is_not_a_date() {
        assert!(IsoTime::parse_dec(Some(b"0000000000000000\x00")).is_none());
        let t = IsoTime::parse_dec(Some(b"2026032317321065\x08")).unwrap();
        // 2026-03-23 17:32:10 at +02:00 == 15:32:10 UTC.
        assert_eq!(t.gmt_offset_minutes, 120);
        assert_eq!(t.unix, 1_774_279_930);
    }

    #[test]
    fn binary_datetime_rebases_from_1900() {
        let t = IsoTime::parse_bin(Some(&[126, 3, 23, 17, 30, 20, 8])).unwrap();
        assert_eq!(t.gmt_offset_minutes, 120);
        assert_eq!(t.unix, 1_774_279_820);
    }

    #[test]
    fn builder_matched_before_the_banner_it_embeds() {
        let mut pvd = empty_pvd();
        // genisoimage carries the mkisofs banner for compatibility.
        pvd.application_id =
            b"GENISOIMAGE ISO 9660/HFS FILESYSTEM CREATOR (C) 1993 E.YOUNGDALE".to_vec();
        assert_eq!(
            detect_builder(&pvd),
            Some(("genisoimage", "application_id"))
        );
        pvd.application_id = b"MKISOFS ISO 9660/HFS FILESYSTEM BUILDER".to_vec();
        assert_eq!(detect_builder(&pvd), Some(("mkisofs", "application_id")));
        pvd.application_id = Vec::new();
        assert_eq!(detect_builder(&pvd), None);
    }

    #[test]
    fn mangled_short_name_is_not_divergence() {
        let same = [
            ("iso9660", "INSTALL0".to_string()),
            ("joliet", "Installer_v1836_x64.exe".to_string()),
        ];
        assert!(!divergent_names(&same));
        let different = [
            ("iso9660", "README".to_string()),
            ("joliet", "invoice.exe".to_string()),
        ];
        assert!(divergent_names(&different));
    }

    #[test]
    fn symlink_components_reassemble() {
        // flags=0, len=3, "etc"; flags=0, len=6, "passwd"
        let mut out = String::new();
        decode_symlink(b"\x00\x00\x03etc\x00\x06passwd", &mut out);
        assert_eq!(out, "etc/passwd");
        let mut root = String::new();
        decode_symlink(b"\x00\x08\x00\x00\x03etc", &mut root);
        assert_eq!(root, "/etc");
    }

    fn susp_record(signature: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(4 + payload.len());
        record.extend_from_slice(&signature);
        record.push((4 + payload.len()) as u8);
        record.push(1); // SUSP entry version
        record.extend_from_slice(payload);
        record
    }

    fn both32(value: u32) -> Vec<u8> {
        let mut encoded = value.to_le_bytes().to_vec();
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn test_entry() -> Entry {
        Entry {
            namespace: Namespace::Iso9660,
            path: "/LIBSYS.SO;1".into(),
            alt_name: None,
            lba: 0,
            size: 0,
            flags: 0,
            recorded: None,
            depth: 0,
            contiguous: true,
            ext_attr_sectors: 0,
            mode: None,
            uid: None,
            gid: None,
            symlink: None,
        }
    }

    #[test]
    fn susp_payload_starts_after_four_byte_header() {
        let mut system_use = susp_record(*b"NM", b"\0libsys.so.7");

        let mut px = both32(0o100755);
        px.extend(both32(1)); // link count
        px.extend(both32(1000)); // uid
        px.extend(both32(100)); // gid
        system_use.extend(susp_record(*b"PX", &px));

        // SL entry flags, followed by the `usr` and `lib` components.
        system_use.extend(susp_record(*b"SL", b"\0\0\x03usr\0\x03lib"));

        let mut walk = Walk::new();
        let mut entry = test_entry();
        walk.parse_susp(&[], &system_use, &mut entry, "/lib", 0);

        assert_eq!(entry.path, "/lib/libsys.so.7");
        assert_eq!(entry.alt_name.as_deref(), Some("libsys.so.7"));
        assert_eq!(entry.mode, Some(0o100755));
        assert_eq!(entry.uid, Some(1000));
        assert_eq!(entry.gid, Some(100));
        assert_eq!(entry.symlink.as_deref(), Some("usr/lib"));
    }

    #[test]
    fn susp_ce_continuation_uses_unshifted_payload() {
        let continuation = susp_record(*b"NM", b"\0continued-name");
        let mut image = vec![0_u8; SECTOR + continuation.len()];
        image[SECTOR..].copy_from_slice(&continuation);

        let mut ce = both32(1); // continuation block
        ce.extend(both32(0)); // offset within block
        ce.extend(both32(continuation.len() as u32));

        let mut walk = Walk::new();
        let mut entry = test_entry();
        walk.parse_susp(&image, &susp_record(*b"CE", &ce), &mut entry, "", 0);

        assert_eq!(entry.path, "/continued-name");
    }

    fn empty_pvd() -> Pvd {
        Pvd {
            system_id: Vec::new(),
            volume_id: Vec::new(),
            volume_set_id: Vec::new(),
            publisher_id: Vec::new(),
            preparer_id: Vec::new(),
            application_id: Vec::new(),
            copyright_file: Vec::new(),
            abstract_file: Vec::new(),
            bibliographic_file: Vec::new(),
            escape: Vec::new(),
            volume_space_sectors: 0,
            volume_set_size: 0,
            volume_sequence_number: 0,
            logical_block_size: 2048,
            path_table_size: 0,
            path_table_lba: [0, 0],
            file_structure_version: 1,
            root_lba: 0,
            root_len: 0,
            created: None,
            modified: None,
            expires: None,
            effective: None,
            application_use_nonzero: 0,
        }
    }
}
