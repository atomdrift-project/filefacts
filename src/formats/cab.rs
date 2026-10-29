//! Microsoft Cabinet (MS-CAB) header extractor.
//!
//! Reports a cabinet's member table (`archive.members`) and its header facts
//! (`cab.*`): version, set id/index, spanning names, reserve areas, and any
//! Authenticode signature appended past `cbCabinet`. Cabinets are a routine
//! Windows malware carrier and, as `.msu`, a routine update-package disguise.
//!
//! The CFHEADER is parsed here rather than taken from the `cab` crate, which
//! reads the interesting fields and then discards them: `cbCabinet`, the
//! version pair, the flags, the reserve sizes, and both cabinet/disk name
//! pairs are all bound to `_`-prefixed locals with no accessor. Those are the
//! forensic fields -- the name pairs are attacker-controlled strings, and
//! `cbCabinet` compared against the real file length is how an appended
//! payload shows up.
//!
//! Reading the header directly also means a cabinet the crate rejects still
//! yields facts. It refuses any file whose CFFILE folder index is out of range,
//! which is exactly how the spec encodes a member continued from or into
//! another cabinet (0xFFFD/0xFFFE/0xFFFF), so every spanned set failed whole.
//! The header walk stands alone and the member table is layered on when it can
//! be read; what could not be read is reported in `cab.limits`.
//!
//! No data block is ever decompressed.

use std::io::Cursor;

use serde_json::Value as JsonValue;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, member_value};
use super::bounded::Limits;
use crate::bytes;
use crate::error::Error;
use crate::metric;
use crate::output::{ArchiveCompression, ArchiveMember, EntryType, Metrics, Values};
use crate::value_key;

/// The shared aggregates a cabinet reports. Every CFFILE is a file (paths
/// carry their folders inline), and a hidden member is one with the DOS
/// hidden attribute. CFFILE records no per-member compressed size, so
/// `archive.compression.ratio` is taken against the declared cabinet size
/// instead, below.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::DirectoryCount,
    Agg::UncompressedSize(Scope::All),
    Agg::Executables,
    Agg::Scripts,
    Agg::NestedArchives,
    Agg::PathTraversal(Scope::All),
    Agg::HiddenFiles,
    Agg::NameTricks,
    Agg::MisplacedExecutables,
    Agg::NoiseFiles,
    Agg::MaxFilenameLength,
    Agg::DuplicateMembers,
    // An undated CFFILE is the same observation zip records as a sentinel
    // mtime.
    Agg::SentinelMtimes,
];

const FLAG_PREV_CABINET: u16 = 0x1;
const FLAG_NEXT_CABINET: u16 = 0x2;
const FLAG_RESERVE_PRESENT: u16 = 0x4;

/// Fixed part of the CFHEADER, before any reserve or cabinet-name fields.
const CFHEADER_FIXED_LEN: usize = 36;

struct Header {
    declared_total_size: u32,
    first_file_offset: u32,
    version_major: u8,
    version_minor: u8,
    declared_folder_count: u16,
    declared_file_count: u16,
    flags: u16,
    set_id: u16,
    set_index: u16,
    header_reserve: Vec<u8>,
    folder_reserve_size: u8,
    data_reserve_size: u8,
    prev_cabinet: Option<(String, String)>,
    next_cabinet: Option<(String, String)>,
    /// The three `reserved` words the spec requires to be zero.
    nonzero_reserved: u8,
}

/// Read a NUL-terminated string, returning it and the offset just past it.
fn cstr_at(bytes: &[u8], off: usize) -> Option<(String, usize)> {
    let field = bytes.get(off..)?;
    // The spec caps these at 255 bytes including the terminator.
    let len = field.iter().take(256).position(|&b| b == 0)?;
    let text = String::from_utf8_lossy(field.get(..len)?).into_owned();
    Some((text, off + len + 1))
}

fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    let Some(fixed) = bytes
        .first_chunk::<CFHEADER_FIXED_LEN>()
        .filter(|f| f.starts_with(b"MSCF"))
    else {
        return Err(Error::malformed(
            "cab",
            "not a cabinet (bad CFHEADER magic)",
        ));
    };
    // Every fixed field below is read out of `fixed`, so none of the reads
    // can come up short and the `unwrap_or(0)` defaults never apply.
    //
    // reserved1/2/3 are defined as zero. A writer that puts bytes there is
    // either a non-conforming builder worth fingerprinting or using the field
    // to carry data past readers that skip it.
    let nonzero_reserved = u8::from(bytes::u32_le(fixed, 0x04).unwrap_or(0) != 0)
        + u8::from(bytes::u32_le(fixed, 0x0c).unwrap_or(0) != 0)
        + u8::from(bytes::u32_le(fixed, 0x14).unwrap_or(0) != 0);

    let flags = bytes::u16_le(fixed, 0x1e).unwrap_or(0);
    let mut pos = CFHEADER_FIXED_LEN;
    let mut header_reserve = Vec::new();
    let mut folder_reserve_size = 0u8;
    let mut data_reserve_size = 0u8;
    if flags & FLAG_RESERVE_PRESENT != 0
        && let Some(&[size_lo, size_hi, folder_size, data_size]) =
            bytes.get(pos..).and_then(|rest| rest.first_chunk::<4>())
    {
        let header_reserve_size = usize::from(u16::from_le_bytes([size_lo, size_hi]));
        folder_reserve_size = folder_size;
        data_reserve_size = data_size;
        pos += 4;
        let end = pos.saturating_add(header_reserve_size).min(bytes.len());
        header_reserve = bytes.get(pos..end).unwrap_or_default().to_vec();
        pos = end;
    }
    let prev_cabinet = if flags & FLAG_PREV_CABINET != 0 {
        cstr_at(bytes, pos).and_then(|(cab, next)| {
            cstr_at(bytes, next).map(|(disk, after)| {
                pos = after;
                (cab, disk)
            })
        })
    } else {
        None
    };
    let next_cabinet = if flags & FLAG_NEXT_CABINET != 0 {
        cstr_at(bytes, pos)
            .and_then(|(cab, next)| cstr_at(bytes, next).map(|(disk, _)| (cab, disk)))
    } else {
        None
    };

    Ok(Header {
        declared_total_size: bytes::u32_le(fixed, 0x08).unwrap_or(0),
        first_file_offset: bytes::u32_le(fixed, 0x10).unwrap_or(0),
        version_minor: fixed[0x18],
        version_major: fixed[0x19],
        declared_folder_count: bytes::u16_le(fixed, 0x1a).unwrap_or(0),
        declared_file_count: bytes::u16_le(fixed, 0x1c).unwrap_or(0),
        flags,
        set_id: bytes::u16_le(fixed, 0x20).unwrap_or(0),
        set_index: bytes::u16_le(fixed, 0x22).unwrap_or(0),
        header_reserve,
        folder_reserve_size,
        data_reserve_size,
        prev_cabinet,
        next_cabinet,
        nonzero_reserved,
    })
}

/// Whether a DER blob is a PKCS#7 ContentInfo wrapping SignedData -- the
/// Authenticode shape. Checked before handing bytes to the CMS parser so an
/// ordinary appended payload is not run through an ASN.1 decoder.
fn is_pkcs7_signed_data(der: &[u8]) -> bool {
    // SEQUENCE, then OID 1.2.840.113549.1.7.2 (signedData) within the first
    // few bytes of the ContentInfo.
    const SIGNED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    der.first() == Some(&0x30)
        && der.len() > 16
        && der.get(..16).is_some_and(|head| {
            head.windows(SIGNED_DATA_OID.len())
                .any(|w| w == SIGNED_DATA_OID)
        })
}

/// Name the compression scheme including its parameters. `Debug` alone would
/// collapse `Lzx(KB512)` and `Quantum(7, 21)` detail an analyst wants: window
/// size and level are builder fingerprints, and LZX/Quantum in a cabinet that
/// arrived by mail is unusual on its own -- mainstream tooling emits MSZIP.
fn compression_label(ctype: cab::CompressionType) -> String {
    match ctype {
        cab::CompressionType::None => "none".into(),
        cab::CompressionType::MsZip => "mszip".into(),
        cab::CompressionType::Quantum(level, memory) => {
            format!("quantum:level={level},memory={memory}")
        }
        cab::CompressionType::Lzx(window) => format!("lzx:window={window:?}"),
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let header = parse_header(bytes)?;
    let mut limits = Limits::default();

    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("cab".into()),
    );
    values.insert_key(
        value_key!("cab.version"),
        JsonValue::String(format!("{}.{}", header.version_major, header.version_minor)),
    );
    values.insert_key(
        value_key!("cab.set_id"),
        JsonValue::Number(header.set_id.into()),
    );
    values.insert_key(
        value_key!("cab.set_index"),
        JsonValue::Number(header.set_index.into()),
    );

    // Spanning names are operator-chosen and travel with the campaign, so they
    // identify a set the way a PDB path identifies a build.
    if let Some((cabinet, disk)) = &header.prev_cabinet {
        values.insert_key(
            value_key!("cab.prev_cabinet"),
            JsonValue::String(cabinet.clone()),
        );
        values.insert_key(value_key!("cab.prev_disk"), JsonValue::String(disk.clone()));
    }
    if let Some((cabinet, disk)) = &header.next_cabinet {
        values.insert_key(
            value_key!("cab.next_cabinet"),
            JsonValue::String(cabinet.clone()),
        );
        values.insert_key(value_key!("cab.next_disk"), JsonValue::String(disk.clone()));
    }
    if !header.header_reserve.is_empty() {
        // abReserve is a spec-sanctioned opaque region every extractor skips,
        // which makes it a natural carrier. Report its shape, not its bytes.
        let printable = header
            .header_reserve
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .count();
        values.insert_key(
            value_key!("cab.header_reserve"),
            serde_json::json!({
                "size": header.header_reserve.len(),
                "all_zero": header.header_reserve.iter().all(|b| *b == 0),
                "printable_ratio":
                    printable as f64 / header.header_reserve.len() as f64,
            }),
        );
    }

    metrics.insert(
        metric!("cab.declared_total_size"),
        f64::from(header.declared_total_size),
    );
    // `coffFiles` is where the header and folder tables stop and the payload
    // begins -- the same thing `archive.header_size` means elsewhere, so it is
    // reported under that name rather than a cab-only spelling.
    metrics.insert(
        metric!("archive.header_size"),
        f64::from(header.first_file_offset),
    );
    metrics.insert(
        metric!("cab.header_reserve_size"),
        header.header_reserve.len() as f64,
    );
    metrics.insert(
        metric!("cab.folder_reserve_size"),
        f64::from(header.folder_reserve_size),
    );
    metrics.insert(
        metric!("cab.data_reserve_size"),
        f64::from(header.data_reserve_size),
    );
    metrics.insert(
        metric!("cab.nonzero_reserved_count"),
        f64::from(header.nonzero_reserved),
    );
    metrics.insert(
        metric!("cab.has_prev_cabinet"),
        f64::from(u8::from(header.flags & FLAG_PREV_CABINET != 0)),
    );
    metrics.insert(
        metric!("cab.has_next_cabinet"),
        f64::from(u8::from(header.flags & FLAG_NEXT_CABINET != 0)),
    );
    // Bytes past the cabinet's own declared end. The container says where it
    // stops; anything after it was appended by something else, which is the
    // shape of a CAB polyglot or a payload stapled to a benign cabinet.
    // Same concept zip already reports under this name -- an author hunting
    // appended payloads should not have to know a per-format spelling.
    let trailing_at = header.declared_total_size as usize;
    let trailing = (bytes.len() as u64).saturating_sub(u64::from(header.declared_total_size));
    metrics.insert(metric!("archive.trailing_bytes"), trailing as f64);

    // Authenticode for a cabinet is a PKCS#7 SignedData blob appended past
    // `cbCabinet`, so the trailing region is not automatically suspicious --
    // on a Microsoft-signed cabinet it *is* the signature. Parsing it is what
    // separates a real signed cabinet from an attacker's, and without it every
    // signed cabinet reported `trust: unsigned`, indistinguishable from one
    // that was never signed at all.
    //
    // The blob is the same structure PE and Mach-O carry, so it goes through
    // the same parser and is published under a `signatures[0]` key of the same
    // shape, which lets the identity layer reuse the PE mapping unchanged. The
    // signature commits to a digest of the cabinet that nothing here
    // recomputes, so a sound one reads `verified: null`, not true.
    if trailing > 0
        && let Some(tail) = bytes.get(trailing_at..)
        && is_pkcs7_signed_data(tail)
    {
        // The DER element alone: a signed cabinet is not obliged to end at
        // its signature, and the decoder rejects whatever follows.
        let signature = super::cms::der_element(tail)
            .and_then(|blob| Some((blob.len(), super::cms::parse_unbound_cms_blob(blob)?)));
        match signature {
            Some((der_len, sig)) => {
                values.insert_key(
                    value_key!("cab.signatures"),
                    JsonValue::Array(vec![sig.to_json()]),
                );
                metrics.insert(metric!("cab.signature_bytes"), der_len as f64);
                // Whatever sits past the signature is genuinely unaccounted
                // for: the cabinet ended at `cbCabinet` and the signature
                // ended here.
                metrics.insert(
                    metric!("cab.post_signature_bytes"),
                    crate::bytes::sat_usize(trailing).saturating_sub(der_len) as f64,
                );
            }
            None => tracing::debug!(
                target: "filefacts::cab",
                format = "cab",
                stage = "signature",
                offset = trailing_at,
                len = tail.len(),
                "appended SignedData did not parse"
            ),
        }
    }

    let mut members = Vec::new();
    let mut stats = ArchiveStats::new(AGGS);
    let mut system_count = 0u64;
    let mut exec_attr_count = 0u64;
    let mut readonly_count = 0u64;
    let mut utf8_name_count = 0u64;
    let mut folder_count = 0u64;
    let mut data_block_count = 0u64;
    let mut compressions: Vec<String> = Vec::new();

    match cab::Cabinet::new(Cursor::new(bytes)) {
        Ok(cabinet) => {
            for folder in cabinet.folder_entries() {
                folder_count += 1;
                data_block_count += u64::from(folder.num_data_blocks());
                let method = compression_label(folder.compression_type());
                if !compressions.contains(&method) {
                    compressions.push(method.clone());
                }

                for file in folder.file_entries() {
                    let member = ArchiveMember {
                        // The crate returns None for a DOS date/time that does
                        // not describe a real instant -- a builder artifact or
                        // a deliberate scrub.
                        mtime_unix: file.datetime().map(|dt| dt.assume_utc().unix_timestamp()),
                        compression: ArchiveCompression::new(None, Some(method.clone())),
                        // CFFILE stores a backslash-separated path; normalize
                        // so member rules written against `a/b/c` match a
                        // cabinet the same way they match a zip.
                        ..ArchiveMember::new(
                            file.name().replace('\\', "/"),
                            u64::from(file.uncompressed_size()),
                            EntryType::Regular,
                        )
                    };
                    // The DOS attribute bits are the cabinet's own claim about
                    // the member, independent of its name -- a payload can be
                    // marked hidden/system while carrying an innocuous
                    // extension.
                    let mut reading = Reading::of(&member);
                    reading.hidden = file.is_hidden();
                    stats.observe(&member, &reading);
                    system_count += u64::from(file.is_system());
                    exec_attr_count += u64::from(file.is_exec());
                    readonly_count += u64::from(file.is_read_only());
                    utf8_name_count += u64::from(file.is_name_utf());

                    let mut obj = member_value(&member);
                    for (key, set) in [
                        ("hidden", file.is_hidden()),
                        ("system", file.is_system()),
                        ("executable", file.is_exec()),
                        ("read_only", file.is_read_only()),
                        ("name_utf8", file.is_name_utf()),
                        ("archive_attr", file.is_archive()),
                    ] {
                        if set {
                            obj.insert(key.into(), JsonValue::Bool(true));
                        }
                    }
                    members.push(JsonValue::Object(obj));
                    archive_members.push(member);
                }
            }
        }
        Err(err) => {
            // Header facts above still stand. This is the spanned-cabinet case
            // most of the time: the reader rejects the continuation folder
            // indices the spec defines, so refusing to report anything would
            // lose a whole multi-part set.
            tracing::debug!(
                target: "filefacts::cab",
                format = "cab",
                stage = "member-table",
                error = %err,
                "member table unreadable; header facts only"
            );
            limits.push("member-table", err.to_string());
        }
    }

    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    values.insert_key(
        value_key!("cab.compression"),
        JsonValue::Array(
            compressions
                .into_iter()
                .map(JsonValue::String)
                .collect::<Vec<_>>(),
        ),
    );
    limits.emit(values, value_key!("cab.limits"));

    stats.emit(values, metrics);
    // Expansion against the cabinet's own declared size: the ratio a CAB bomb
    // shows up in, and the only compression figure CAB affords, since CFFILE
    // records no per-member compressed size.
    if header.declared_total_size > 0 {
        metrics.insert(
            metric!("archive.compression.ratio"),
            stats.uncompressed_size() as f64 / f64::from(header.declared_total_size),
        );
    }
    metrics.insert(metric!("cab.folder_count"), folder_count as f64);
    metrics.insert(metric!("cab.data_block_count"), data_block_count as f64);
    metrics.insert(metric!("cab.system_file_count"), system_count as f64);
    metrics.insert(metric!("cab.exec_attribute_count"), exec_attr_count as f64);
    metrics.insert(metric!("cab.readonly_file_count"), readonly_count as f64);
    metrics.insert(metric!("cab.utf8_name_count"), utf8_name_count as f64);
    // The header says how many folders and files to expect. A table that does
    // not match it has been edited after the fact, or is being hidden from
    // readers that trust the count instead of walking.
    metrics.insert(
        metric!("cab.declared_folder_count"),
        f64::from(header.declared_folder_count),
    );
    metrics.insert(
        metric!("cab.declared_file_count"),
        f64::from(header.declared_file_count),
    );
    metrics.insert(
        metric!("cab.file_count_mismatch"),
        f64::from(u8::from(
            u64::from(header.declared_file_count) != stats.member_count(),
        )),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
