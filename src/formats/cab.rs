//! Microsoft Cabinet (MS-CAB) header extractor.
//!
//! CAB was identified by magic and classified as an archive container, but had
//! no arm in the extractor dispatch, so `archive.members` came back empty for
//! every cabinet. Every rule reading `archive.members[*]` was therefore inert
//! against a format that is a routine Windows malware carrier -- and, as
//! `.msu`, a routine update-package disguise.
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

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::error::Error;
use crate::metric;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};

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

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Read a NUL-terminated string, returning it and the offset just past it.
fn cstr_at(bytes: &[u8], off: usize) -> Option<(String, usize)> {
    // The spec caps these at 255 bytes including the terminator.
    let end = bytes.iter().skip(off).take(256).position(|&b| b == 0)? + off;
    let text = String::from_utf8_lossy(&bytes[off..end]).into_owned();
    Some((text, end + 1))
}

fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    if bytes.len() < CFHEADER_FIXED_LEN || &bytes[..4] != b"MSCF" {
        return Err(Error::malformed(
            "cab",
            "not a cabinet (bad CFHEADER magic)",
        ));
    }
    // reserved1/2/3 are defined as zero. A writer that puts bytes there is
    // either a non-conforming builder worth fingerprinting or using the field
    // to carry data past readers that skip it.
    let nonzero_reserved = u8::from(u32_at(bytes, 0x04) != 0)
        + u8::from(u32_at(bytes, 0x0c) != 0)
        + u8::from(u32_at(bytes, 0x14) != 0);

    let flags = u16_at(bytes, 0x1e);
    let mut pos = CFHEADER_FIXED_LEN;
    let mut header_reserve = Vec::new();
    let mut folder_reserve_size = 0u8;
    let mut data_reserve_size = 0u8;
    if flags & FLAG_RESERVE_PRESENT != 0 && bytes.len() >= pos + 4 {
        let header_reserve_size = u16_at(bytes, pos) as usize;
        folder_reserve_size = bytes[pos + 2];
        data_reserve_size = bytes[pos + 3];
        pos += 4;
        let end = pos.saturating_add(header_reserve_size).min(bytes.len());
        header_reserve = bytes[pos..end].to_vec();
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
        declared_total_size: u32_at(bytes, 0x08),
        first_file_offset: u32_at(bytes, 0x10),
        version_minor: bytes[0x18],
        version_major: bytes[0x19],
        declared_folder_count: u16_at(bytes, 0x1a),
        declared_file_count: u16_at(bytes, 0x1c),
        flags,
        set_id: u16_at(bytes, 0x20),
        set_index: u16_at(bytes, 0x22),
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
/// Total encoded length of a DER TLV at the start of `der`, header included.
/// The CMS decoder rejects any bytes past the structure it is handed, and a
/// signed cabinet is not obliged to end at its signature -- the samples here
/// carry ~95KB more after it -- so the blob has to be cut to length first.
fn der_total_len(der: &[u8]) -> Option<usize> {
    let len_byte = *der.get(1)? as usize;
    if len_byte < 0x80 {
        return Some(2 + len_byte);
    }
    let count = len_byte & 0x7f;
    if count == 0 || count > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..count {
        len = (len << 8) | *der.get(2 + i)? as usize;
    }
    Some(2 + count + len)
}

fn is_pkcs7_signed_data(der: &[u8]) -> bool {
    // SEQUENCE, then OID 1.2.840.113549.1.7.2 (signedData) within the first
    // few bytes of the ContentInfo.
    const SIGNED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    der.first() == Some(&0x30)
        && der.len() > 16
        && der[..16]
            .windows(SIGNED_DATA_OID.len())
            .any(|w| w == SIGNED_DATA_OID)
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
    let mut limits: Vec<JsonValue> = Vec::new();

    values.insert("archive.format.kind", JsonValue::String("cab".into()));
    values.insert(
        "cab.version",
        JsonValue::String(format!("{}.{}", header.version_major, header.version_minor)),
    );
    values.insert("cab.set_id", JsonValue::Number(header.set_id.into()));
    values.insert("cab.set_index", JsonValue::Number(header.set_index.into()));

    // Spanning names are operator-chosen and travel with the campaign, so they
    // identify a set the way a PDB path identifies a build.
    if let Some((cabinet, disk)) = &header.prev_cabinet {
        values.insert("cab.prev_cabinet", JsonValue::String(cabinet.clone()));
        values.insert("cab.prev_disk", JsonValue::String(disk.clone()));
    }
    if let Some((cabinet, disk)) = &header.next_cabinet {
        values.insert("cab.next_cabinet", JsonValue::String(cabinet.clone()));
        values.insert("cab.next_disk", JsonValue::String(disk.clone()));
    }
    if !header.header_reserve.is_empty() {
        // abReserve is a spec-sanctioned opaque region every extractor skips,
        // which makes it a natural carrier. Report its shape, not its bytes.
        let printable = header
            .header_reserve
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .count();
        values.insert(
            "cab.header_reserve",
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
    // shape, which lets the identity layer reuse the PE mapping unchanged.
    if trailing > 0
        && let Some(tail) = bytes.get(trailing_at..)
        && is_pkcs7_signed_data(tail)
        && let Some(der_len) = der_total_len(tail)
        && let Some(blob) = tail.get(..der_len.min(tail.len()))
        && let Some(sig) = super::pe_authenticode::parse_cms_blob(blob)
    {
        values.insert("cab.signatures", JsonValue::Array(vec![sig]));
        metrics.insert(metric!("cab.signature_bytes"), der_len as f64);
        // Whatever sits past the signature is genuinely unaccounted for: the
        // cabinet ended at `cbCabinet` and the signature ended here.
        metrics.insert(
            metric!("cab.post_signature_bytes"),
            (trailing as usize).saturating_sub(der_len) as f64,
        );
    }

    let mut members = Vec::new();
    let mut total_size = 0u64;
    let mut file_count = 0u64;
    let mut executable_count = 0u64;
    let mut script_count = 0u64;
    let mut nested_archive_count = 0u64;
    let mut traversal_count = 0u64;
    let mut hidden_count = 0u64;
    let mut system_count = 0u64;
    let mut exec_attr_count = 0u64;
    let mut readonly_count = 0u64;
    let mut utf8_name_count = 0u64;
    let mut undated_count = 0u64;
    let mut folder_count = 0u64;
    let mut data_block_count = 0u64;
    let mut unicode_count = 0u64;
    let mut homoglyph_count = 0u64;
    let mut rtlo_count = 0u64;
    let mut double_extension_count = 0u64;
    let mut misplaced_executable_count = 0u64;
    let mut noise_count = 0u64;
    let mut max_filename_length = 0u64;
    let mut seen_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut duplicate_count = 0u64;
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
                    // CFFILE stores a backslash-separated path; normalize so
                    // member rules written against `a/b/c` match a cabinet the
                    // same way they match a zip.
                    let path = file.name().replace('\\', "/");
                    let size = u64::from(file.uncompressed_size());
                    let mtime_unix = file.datetime().map(|dt| dt.assume_utc().unix_timestamp());
                    if mtime_unix.is_none() {
                        // The crate returns None for a DOS date/time that does
                        // not describe a real instant -- a builder artifact or
                        // a deliberate scrub.
                        undated_count += 1;
                    }

                    let class = super::zip::classify_filename(&path);
                    file_count += 1;
                    total_size = total_size.saturating_add(size);
                    executable_count += u64::from(class.is_executable);
                    script_count += u64::from(class.is_script);
                    nested_archive_count += u64::from(class.is_nested_archive);
                    traversal_count += u64::from(class.has_path_traversal);
                    // The DOS attribute bits are the cabinet's own claim about
                    // the member, independent of its name -- a payload can be
                    // marked hidden/system while carrying an innocuous
                    // extension.
                    unicode_count += u64::from(class.is_unicode);
                    homoglyph_count += u64::from(class.has_homoglyph);
                    rtlo_count += u64::from(class.has_rtlo);
                    double_extension_count += u64::from(class.has_double_extension);
                    misplaced_executable_count += u64::from(class.is_misplaced_executable);
                    noise_count += u64::from(super::zip::is_noise_filename(&path));
                    max_filename_length = max_filename_length.max(path.len() as u64);
                    // Two members under one name: which one a reader gets
                    // depends on whether it keeps the first or the last.
                    if !seen_names.insert(path.clone()) {
                        duplicate_count += 1;
                    }
                    hidden_count += u64::from(file.is_hidden());
                    system_count += u64::from(file.is_system());
                    exec_attr_count += u64::from(file.is_exec());
                    readonly_count += u64::from(file.is_read_only());
                    utf8_name_count += u64::from(file.is_name_utf());

                    let mut member = JsonMap::new();
                    member.insert("path".into(), JsonValue::String(path.clone()));
                    member.insert("size_bytes".into(), JsonValue::Number(size.into()));
                    member.insert("entry_type".into(), JsonValue::String("regular".into()));
                    member.insert(
                        "compression_method".into(),
                        JsonValue::String(method.clone()),
                    );
                    if let Some(mtime) = mtime_unix {
                        member.insert("mtime_unix".into(), JsonValue::Number(mtime.into()));
                    }
                    for (key, set) in [
                        ("hidden", file.is_hidden()),
                        ("system", file.is_system()),
                        ("executable", file.is_exec()),
                        ("read_only", file.is_read_only()),
                        ("name_utf8", file.is_name_utf()),
                        ("archive_attr", file.is_archive()),
                    ] {
                        if set {
                            member.insert(key.into(), JsonValue::Bool(true));
                        }
                    }
                    members.push(JsonValue::Object(member));

                    archive_members.push(ArchiveMember {
                        path,
                        size_bytes: size,
                        entry_type: Some("regular".into()),
                        mtime_unix,
                        linkname: None,
                        host_os: None,
                        crc32: None,
                        encrypted: false,
                        compression: Some(ArchiveCompression {
                            compressed_size: None,
                            method: Some(method.clone()),
                        }),
                        ownership: None,
                        offsets: ArchiveOffsets::default(),
                    });
                }
            }
        }
        Err(err) => {
            // Header facts above still stand. This is the spanned-cabinet case
            // most of the time: the reader rejects the continuation folder
            // indices the spec defines, so refusing to report anything would
            // lose a whole multi-part set.
            limits.push(serde_json::json!({
                "stage": "member-table",
                "reason": err.to_string(),
            }));
        }
    }

    values.insert("archive.members", JsonValue::Array(members));
    values.insert(
        "cab.compression",
        JsonValue::Array(
            compressions
                .into_iter()
                .map(JsonValue::String)
                .collect::<Vec<_>>(),
        ),
    );
    if !limits.is_empty() {
        values.insert("cab.limits", JsonValue::Array(limits));
    }

    metrics.insert(metric!("archive.member_count"), file_count as f64);
    metrics.insert(metric!("archive.file_count"), file_count as f64);
    // CAB has no directory entries: paths carry their folders inline.
    metrics.insert(metric!("archive.directory_count"), 0.0);
    metrics.insert(metric!("archive.uncompressed_size"), total_size as f64);
    metrics.insert(metric!("archive.executable_count"), executable_count as f64);
    metrics.insert(metric!("archive.script_count"), script_count as f64);
    metrics.insert(
        metric!("archive.nested_archive_count"),
        nested_archive_count as f64,
    );
    metrics.insert(
        metric!("archive.path_traversal_count"),
        traversal_count as f64,
    );
    metrics.insert(metric!("archive.hidden_file_count"), hidden_count as f64);
    metrics.insert(
        metric!("archive.unicode_filename_count"),
        unicode_count as f64,
    );
    metrics.insert(
        metric!("archive.homoglyph_filename_count"),
        homoglyph_count as f64,
    );
    metrics.insert(metric!("archive.rtlo_filename_count"), rtlo_count as f64);
    metrics.insert(
        metric!("archive.double_extension_count"),
        double_extension_count as f64,
    );
    metrics.insert(
        metric!("archive.misplaced_executable_count"),
        misplaced_executable_count as f64,
    );
    metrics.insert(metric!("archive.noise_file_count"), noise_count as f64);
    metrics.insert(
        metric!("archive.max_filename_length"),
        max_filename_length as f64,
    );
    metrics.insert(
        metric!("archive.duplicate_member_count"),
        duplicate_count as f64,
    );
    // Expansion against the cabinet's own declared size: the ratio a CAB bomb
    // shows up in, and the only compression figure CAB affords, since CFFILE
    // records no per-member compressed size.
    if header.declared_total_size > 0 {
        metrics.insert(
            metric!("archive.compression.ratio"),
            total_size as f64 / f64::from(header.declared_total_size),
        );
    }
    metrics.insert(metric!("cab.folder_count"), folder_count as f64);
    metrics.insert(metric!("cab.data_block_count"), data_block_count as f64);
    metrics.insert(metric!("cab.system_file_count"), system_count as f64);
    metrics.insert(metric!("cab.exec_attribute_count"), exec_attr_count as f64);
    metrics.insert(metric!("cab.readonly_file_count"), readonly_count as f64);
    metrics.insert(metric!("cab.utf8_name_count"), utf8_name_count as f64);
    // A DOS date/time that does not describe a real instant is the same
    // observation zip records as a sentinel mtime.
    metrics.insert(
        metric!("archive.timing.sentinel_mtime_count"),
        undated_count as f64,
    );
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
            u64::from(header.declared_file_count) != file_count,
        )),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-file cabinet in memory and read it back through the same
    /// path a scan takes.
    fn cabinet_with(name: &str, body: &[u8]) -> Vec<u8> {
        let mut builder = cab::CabinetBuilder::new();
        builder
            .add_folder(cab::CompressionType::None)
            .add_file(name.to_string());
        let mut writer = builder.build(Cursor::new(Vec::new())).unwrap();
        while let Some(mut w) = writer.next_file().unwrap() {
            std::io::Write::write_all(&mut w, body).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn run(bytes: &[u8]) -> (Values, Metrics, Vec<ArchiveMember>) {
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed = Vec::new();
        extract(bytes, &mut values, &mut metrics, &mut typed).unwrap();
        (values, metrics, typed)
    }

    #[test]
    fn header_walk_emits_members_and_counts_executables() {
        let bytes = cabinet_with("payload\\setup.exe", b"not an executable");
        let (values, metrics, typed) = run(&bytes);

        let members = values.get("archive.members").unwrap().as_array().unwrap();
        assert_eq!(members.len(), 1);
        // Backslashes are normalized so member rules match a cabinet the same
        // way they match a zip.
        assert_eq!(members[0]["path"].as_str(), Some("payload/setup.exe"));
        assert_eq!(members[0]["size_bytes"].as_u64(), Some(17));
        assert_eq!(metrics.get("archive.file_count"), Some(1.0));
        assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
        assert_eq!(metrics.get("cab.folder_count"), Some(1.0));
        assert_eq!(metrics.get("cab.file_count_mismatch"), Some(0.0));
        assert_eq!(typed.len(), 1);
        assert_eq!(
            values
                .get("archive.format.kind")
                .and_then(serde_json::Value::as_str),
            Some("cab")
        );
        assert_eq!(
            values.get("cab.version").and_then(JsonValue::as_str),
            Some("1.3")
        );
    }

    #[test]
    fn appended_bytes_are_reported_as_trailing() {
        let mut bytes = cabinet_with("a.txt", b"hi");
        let clean = run(&bytes).1.get("archive.trailing_bytes");
        assert_eq!(clean, Some(0.0));

        bytes.extend_from_slice(&[0x41; 512]);
        let (_, metrics, _) = run(&bytes);
        // The cabinet still parses; the appended block is what gets reported.
        assert_eq!(metrics.get("archive.trailing_bytes"), Some(512.0));
    }

    #[test]
    fn header_facts_survive_an_unreadable_member_table() {
        // Truncate past the fixed header so the member table cannot be walked
        // but the CFHEADER is intact.
        let bytes = cabinet_with("a.txt", b"hi");
        let cut = &bytes[..CFHEADER_FIXED_LEN + 2];
        let (values, metrics, typed) = run(cut);

        assert!(typed.is_empty());
        assert!(values.get("cab.limits").is_some(), "limitation recorded");
        // The identifying header fields are still reported.
        assert_eq!(
            values.get("cab.version").and_then(JsonValue::as_str),
            Some("1.3")
        );
        assert!(metrics.get("cab.declared_total_size").unwrap() > 0.0);
    }

    #[test]
    fn der_length_is_read_in_short_and_long_form() {
        assert_eq!(der_total_len(&[0x30, 0x05, 0, 0, 0, 0, 0]), Some(7));
        // 0x82 => two length bytes; 0x3d4b is the length seen on a real
        // Microsoft-signed cabinet.
        assert_eq!(der_total_len(&[0x30, 0x82, 0x3d, 0x4b]), Some(0x3d4b + 4));
        assert_eq!(der_total_len(&[0x30, 0x85, 1, 1, 1, 1, 1]), None);
    }

    #[test]
    fn signature_guard_requires_the_signed_data_oid() {
        let signed_data = [
            0x30, 0x82, 0x3d, 0x4b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
            0x02, 0xa0, 0x00,
        ];
        assert!(is_pkcs7_signed_data(&signed_data));
        // A DER sequence that is not SignedData, and plain appended bytes,
        // must not be handed to the ASN.1 decoder.
        let other = [
            0x30, 0x82, 0x3d, 0x4b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
            0x01, 0xa0, 0x00,
        ];
        assert!(!is_pkcs7_signed_data(&other));
        assert!(!is_pkcs7_signed_data(&[0x41; 64]));
    }

    #[test]
    fn appended_payload_is_not_mistaken_for_a_signature() {
        let mut bytes = cabinet_with("a.txt", b"hi");
        bytes.extend_from_slice(&[0x41; 512]);
        let (values, metrics, _) = run(&bytes);
        assert_eq!(metrics.get("archive.trailing_bytes"), Some(512.0));
        assert!(values.get("cab.signatures").is_none());
        assert!(metrics.get("cab.signature_bytes").is_none());
    }

    #[test]
    fn non_cabinet_bytes_are_rejected() {
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed = Vec::new();
        assert!(extract(b"not a cab at all", &mut values, &mut metrics, &mut typed).is_err());
    }
}
