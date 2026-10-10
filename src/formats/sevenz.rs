//! 7z archive-header extractor.
//!
//! The 7z format keeps its member table in the next-header section. Reading it
//! gives consumers paths, sizes, timestamps, compression chains, and payload
//! encryption without touching member contents. Header-encrypted archives
//! cannot disclose a member table without a password and return a normal
//! malformed-format error, just as an unreadable ZIP central directory does.
//!
//! `sevenz_rust` sizes the next header, the decoded header and each table it
//! declares straight from the file, before reading any of it, and a failed
//! allocation aborts the process rather than unwinding. So [`check_header`]
//! walks the same structures first with every size and count bounded, and
//! only a header that passes is handed to the crate.

use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;
use sevenz_rust::SevenZMethod as Method;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use super::bounded::{MAX_ARCHIVE_MEMBERS, push_limit};
use crate::error::Error;
use crate::formats::common::bytes_at::u64_le;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};
use crate::value_key;

/// The shared aggregates a 7z reports. Path traversal is counted on files
/// only.
///
/// 7z carries its encryption in the coder chain rather than a per-entry
/// flag, so `archive.security.encrypted_count` had no ZIP-shaped
/// counterpart and was once never emitted: every rule gated on it was
/// unreachable for 7z, including the password-protected sideload bundles
/// that are the format's most common malicious shape. It is reported even
/// when zero, so absence is never mistaken for "not encrypted".
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::DirectoryCount,
    Agg::UncompressedSize(Scope::All),
    Agg::CompressedSize,
    Agg::Executables,
    Agg::Scripts,
    Agg::NestedArchives,
    Agg::PathTraversal(Scope::Files),
    Agg::EncryptedCount,
];

const SIGNATURE: &[u8] = b"7z\xBC\xAF\x27\x1C";
/// Signature, version, start-header CRC, then the next header's offset
/// (relative to the end of this block), size and CRC.
const SIGNATURE_HEADER_LEN: usize = 32;
/// Largest next header, raw or decoded, handed to the crate. Real headers run
/// from a few hundred bytes to a few MiB for archives with very many members.
const MAX_HEADER_BYTES: u64 = 32 << 20;
/// Most files (and non-empty streams) a header may declare. The crate builds
/// a full entry for each before reading any of their properties. Of those,
/// only the first [`MAX_ARCHIVE_MEMBERS`] are listed: a few bytes of
/// LZMA-packed header can declare a million names.
const MAX_FILES: usize = 1 << 20;
/// Per-folder coder and coder-stream limits, the same ones 7-Zip's own reader
/// enforces.
const MAX_FOLDER_CODERS: u64 = 64;
const MAX_FOLDER_STREAMS: u64 = 64;

// Property IDs, from 7-Zip's `7zFormat.txt`.
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUB_STREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_ENCODED_HEADER: u8 = 0x17;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    check_header(bytes)?;
    let password = sevenz_rust::Password::empty();
    let archive = sevenz_rust::Archive::read(
        &mut Cursor::new(bytes),
        bytes.len() as u64,
        password.as_ref(),
    )
    .map_err(|err| Error::malformed_caused_by("7z", err))?;

    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("7z".into()),
    );

    let folder_methods: Vec<Vec<&'static str>> = archive
        .folders
        .iter()
        .map(|folder| {
            folder
                .coders
                .iter()
                .map(|coder| method_name(coder.decompression_method_id()))
                .collect()
        })
        .collect();

    let listed = archive.files.len().min(MAX_ARCHIVE_MEMBERS);
    let mut members = Vec::with_capacity(listed);
    let mut stats = ArchiveStats::new(AGGS);

    for (index, entry) in archive.files.iter().enumerate().take(listed) {
        let folder_index = archive
            .stream_map
            .file_folder_index
            .get(index)
            .copied()
            .flatten();
        let methods = folder_index
            .and_then(|folder| folder_methods.get(folder))
            .cloned()
            .unwrap_or_default();
        let compressed_size = entry.has_stream().then_some(entry.compressed_size);
        let method = (!methods.is_empty()).then(|| methods.join("+"));
        let entry_type = if entry.is_directory() {
            "directory"
        } else if entry.is_anti_item() {
            "anti-item"
        } else {
            "regular"
        };
        let member = ArchiveMember {
            path: entry.name().replace('\\', "/"),
            size_bytes: entry.size,
            entry_type: Some(entry_type.into()),
            mtime_unix: entry
                .has_last_modified_date
                .then(|| entry.last_modified_date().to_unix_time()),
            linkname: None,
            host_os: None,
            // The crate widens the stored CRC-32 to u64; it never exceeds u32.
            crc32: entry
                .has_crc
                .then(|| u32::try_from(entry.crc).ok())
                .flatten(),
            encrypted: methods.contains(&"aes256sha256"),
            compression: (compressed_size.is_some() || method.is_some()).then_some(
                ArchiveCompression {
                    compressed_size,
                    method,
                },
            ),
            ownership: None,
            offsets: ArchiveOffsets::default(),
        };
        stats.observe(&member, &Reading::of(&member));
        members.push(JsonValue::Object(member_value(&member, Shape::FULL)));
        archive_members.push(member);
    }

    if archive.files.len() > listed {
        push_limit(
            values,
            value_key!("7z.limits"),
            "member-cap",
            format!("listed {listed} of {} members", archive.files.len()),
        );
    }

    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    stats.emit(values, metrics);
    Ok(())
}

fn invalid(why: &str) -> Error {
    Error::malformed("7z", why)
}

/// Walk the headers `sevenz_rust` will parse, rejecting any size or count it
/// would allocate from that the file cannot back. The walk mirrors the
/// crate's reads, so each check lands on the same field the crate reads next.
fn check_header(bytes: &[u8]) -> Result<(), Error> {
    let start = bytes
        .first_chunk::<SIGNATURE_HEADER_LEN>()
        .ok_or_else(|| invalid("signature header truncated"))?;
    if !start.starts_with(SIGNATURE) {
        return Err(invalid("bad signature"));
    }
    // A zeroed start header sends the crate scanning the file tail and
    // parsing every header-shaped candidate it finds. None of those can be
    // checked up front, so that recovery is not attempted.
    if start[8..].iter().all(|&b| b == 0) {
        return Err(invalid("start header is zeroed"));
    }
    let offset = u64_le(start, 12).unwrap_or(u64::MAX);
    let size = u64_le(start, 20).unwrap_or(u64::MAX);
    if size > MAX_HEADER_BYTES {
        return Err(invalid("next header larger than cap"));
    }
    let header = (SIGNATURE_HEADER_LEN as u64)
        .checked_add(offset)
        .and_then(|from| file_range(bytes, from, size))
        .ok_or_else(|| invalid("next header overruns file"))?;

    let mut r = HeaderReader { buf: header };
    match r.u8()? {
        K_HEADER => plain_header(&mut r),
        K_ENCODED_HEADER => {
            if let Some(decoded) = decode_header(bytes, &mut r)? {
                let mut r = HeaderReader { buf: &decoded };
                if r.u8()? != K_HEADER {
                    return Err(invalid("decoded header is not a Header"));
                }
                plain_header(&mut r)?;
            }
            Ok(())
        }
        _ => Err(invalid("next header is neither Header nor EncodedHeader")),
    }
}

/// `len` bytes at absolute offset `from`, if the file holds them.
fn file_range(bytes: &[u8], from: u64, len: u64) -> Option<&[u8]> {
    let from = usize::try_from(from).ok()?;
    let to = from.checked_add(usize::try_from(len).ok()?)?;
    bytes.get(from..to)
}

/// Decode an encoded header the way the crate will (first folder, first pack
/// stream) so the header inside can be walked too. `Ok(None)` is an encrypted
/// header: with no password the crate stops at the AES coder, before
/// decoding anything.
fn decode_header(bytes: &[u8], r: &mut HeaderReader<'_>) -> Result<Option<Vec<u8>>, Error> {
    let info = streams_info(r)?;
    let folder = info
        .folders
        .first()
        .ok_or_else(|| invalid("encoded header has no folder"))?;
    // The crate sizes its decode buffer from these before decoding.
    if folder.unpack_sizes.iter().any(|&s| s > MAX_HEADER_BYTES) {
        return Err(invalid("decoded header larger than cap"));
    }
    if folder
        .coders
        .iter()
        .any(|(id, _)| *id == Method::ID_AES256SHA256)
    {
        return Ok(None);
    }
    let pack_size = *info
        .pack_sizes
        .first()
        .ok_or_else(|| invalid("encoded header has no packed stream"))?;
    let packed = (SIGNATURE_HEADER_LEN as u64)
        .checked_add(info.pack_pos)
        .and_then(|from| file_range(bytes, from, pack_size))
        .ok_or_else(|| invalid("encoded header overruns file"))?;
    // One coder, so its one output is the header.
    let unpack_size = folder.unpack_sizes.first().copied().unwrap_or(0);
    let mut out = Vec::new();
    match folder.coders.as_slice() {
        [(id, _)] if *id == Method::ID_COPY => {
            out.extend_from_slice(
                packed
                    .get(..crate::bytes::sat_usize(unpack_size))
                    .unwrap_or(packed),
            );
        }
        [(id, props)] if *id == Method::ID_LZMA => {
            let Some(&[lc_lp_pb, d0, d1, d2, d3]) = props.get(..5) else {
                return Err(invalid("LZMA header coder properties truncated"));
            };
            let dict_size = u32::from_le_bytes([d0, d1, d2, d3]);
            sevenz_rust::lzma::LZMAReader::new_with_props(
                packed,
                unpack_size,
                lc_lp_pb,
                dict_size,
                None,
            )
            .and_then(|lzma| lzma.take(unpack_size).read_to_end(&mut out))
            .map_err(|e| Error::malformed_with_source("7z", "encoded header", e))?;
        }
        // 7-Zip and the crate's own writer use LZMA; anything else cannot be
        // checked here.
        _ => return Err(invalid("unsupported encoded-header coder chain")),
    }
    if out.len() as u64 != unpack_size {
        return Err(invalid("encoded header shorter than declared"));
    }
    Ok(Some(out))
}

/// Bounds-checked reader over a 7z header.
struct HeaderReader<'a> {
    buf: &'a [u8],
}

impl<'a> HeaderReader<'a> {
    fn u8(&mut self) -> Result<u8, Error> {
        let (&b, rest) = self
            .buf
            .split_first()
            .ok_or_else(|| invalid("header truncated"))?;
        self.buf = rest;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.buf.len() {
            return Err(invalid("header field overruns header"));
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    fn skip(&mut self, n: u64) -> Result<(), Error> {
        let n = usize::try_from(n).map_err(|_| invalid("header field overruns header"))?;
        self.take(n).map(|_| ())
    }

    /// 7z `NUMBER`: the leading one bits of the first byte count the
    /// little-endian bytes that follow it.
    fn number(&mut self) -> Result<u64, Error> {
        let first = self.u8()?;
        let mut value = 0u64;
        for i in 0..8 {
            let mask = 0x80u8 >> i;
            if first & mask == 0 {
                return Ok(value | (u64::from(first & (mask - 1)) << (8 * i)));
            }
            value |= u64::from(self.u8()?) << (8 * i);
        }
        Ok(value)
    }

    /// A declared element count. The crate allocates for a count before
    /// reading its elements, so one is accepted only when the rest of the
    /// header could hold a byte per element.
    fn count(&mut self) -> Result<usize, Error> {
        let n = self.number()?;
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= self.buf.len())
            .ok_or_else(|| invalid("declared count exceeds header size"))
    }

    /// An all-defined flag byte, else one bit per item, most significant
    /// first.
    fn defined(&mut self, n: usize) -> Result<Vec<bool>, Error> {
        if self.u8()? != 0 {
            return Ok(vec![true; n]);
        }
        let bits = self.take(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| bits.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0))
            .collect())
    }

    /// The CRC32 of each defined item.
    fn skip_crcs(&mut self, defined: &[bool]) -> Result<(), Error> {
        let n = defined.iter().filter(|&&d| d).count() as u64;
        self.skip(n * 4)
    }
}

/// What the encoded-header check needs from one folder.
#[derive(Default)]
struct Folder<'a> {
    /// Method ID and properties of each coder.
    coders: Vec<(&'a [u8], &'a [u8])>,
    out_streams: u64,
    unpack_sizes: Vec<u64>,
    has_crc: bool,
}

#[derive(Default)]
struct StreamsInfo<'a> {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder<'a>>,
}

fn plain_header(r: &mut HeaderReader<'_>) -> Result<(), Error> {
    let mut nid = r.u8()?;
    if nid == K_ARCHIVE_PROPERTIES {
        while r.u8()? != K_END {
            let size = r.number()?;
            r.skip(size)?;
        }
        nid = r.u8()?;
    }
    if nid == K_MAIN_STREAMS_INFO {
        streams_info(r)?;
        nid = r.u8()?;
    }
    if nid == K_FILES_INFO {
        if r.count()? > MAX_FILES {
            return Err(invalid("file count over cap"));
        }
        // Every per-file table is sized by the count just checked, so the
        // properties themselves only need to fit.
        while r.u8()? != K_END {
            let size = r.number()?;
            r.skip(size)?;
        }
        nid = r.u8()?;
    }
    if nid != K_END {
        return Err(invalid("bad Header terminator"));
    }
    Ok(())
}

fn streams_info<'a>(r: &mut HeaderReader<'a>) -> Result<StreamsInfo<'a>, Error> {
    let mut info = StreamsInfo::default();
    let mut nid = r.u8()?;
    if nid == K_PACK_INFO {
        info.pack_pos = r.number()?;
        let n = r.count()?;
        nid = r.u8()?;
        if nid == K_SIZE {
            for _ in 0..n {
                info.pack_sizes.push(r.number()?);
            }
            nid = r.u8()?;
        }
        if nid == K_CRC {
            let defined = r.defined(n)?;
            r.skip_crcs(&defined)?;
            nid = r.u8()?;
        }
        if nid != K_END {
            return Err(invalid("bad PackInfo terminator"));
        }
        nid = r.u8()?;
    }
    if nid == K_UNPACK_INFO {
        if r.u8()? != K_FOLDER {
            return Err(invalid("UnpackInfo without Folder"));
        }
        let n = r.count()?;
        if r.u8()? != 0 {
            return Err(invalid("external folders"));
        }
        for _ in 0..n {
            info.folders.push(folder(r)?);
        }
        if r.u8()? != K_CODERS_UNPACK_SIZE {
            return Err(invalid("UnpackInfo without CodersUnpackSize"));
        }
        for f in &mut info.folders {
            for _ in 0..f.out_streams {
                f.unpack_sizes.push(r.number()?);
            }
        }
        nid = r.u8()?;
        if nid == K_CRC {
            let defined = r.defined(n)?;
            for (f, &has_crc) in info.folders.iter_mut().zip(&defined) {
                f.has_crc = has_crc;
            }
            r.skip_crcs(&defined)?;
            nid = r.u8()?;
        }
        if nid != K_END {
            return Err(invalid("bad UnpackInfo terminator"));
        }
        nid = r.u8()?;
    }
    if nid == K_SUB_STREAMS_INFO {
        sub_streams_info(r, &info.folders)?;
        nid = r.u8()?;
    }
    if nid != K_END {
        return Err(invalid("bad StreamsInfo terminator"));
    }
    Ok(info)
}

fn folder<'a>(r: &mut HeaderReader<'a>) -> Result<Folder<'a>, Error> {
    let num_coders = r.number()?;
    if num_coders == 0 || num_coders > MAX_FOLDER_CODERS {
        return Err(invalid("implausible coder count"));
    }
    let mut f = Folder::default();
    let mut in_streams = 0u64;
    for _ in 0..num_coders {
        let flags = r.u8()?;
        if flags & 0x80 != 0 {
            return Err(invalid("alternative coder methods"));
        }
        let id = r.take(usize::from(flags & 0x0f))?;
        if flags & 0x10 == 0 {
            in_streams += 1;
            f.out_streams += 1;
        } else {
            in_streams = in_streams.saturating_add(r.number()?);
            f.out_streams = f.out_streams.saturating_add(r.number()?);
        }
        let props: &[u8] = if flags & 0x20 != 0 {
            let len = r.count()?;
            r.take(len)?
        } else {
            &[]
        };
        f.coders.push((id, props));
    }
    if f.out_streams == 0 || in_streams > MAX_FOLDER_STREAMS || f.out_streams > MAX_FOLDER_STREAMS {
        return Err(invalid("implausible coder stream count"));
    }
    let bind_pairs = f.out_streams - 1;
    for _ in 0..bind_pairs {
        r.number()?;
        r.number()?;
    }
    let packed = in_streams
        .checked_sub(bind_pairs)
        .ok_or_else(|| invalid("more bind pairs than input streams"))?;
    if packed > 1 {
        for _ in 0..packed {
            r.number()?;
        }
    }
    Ok(f)
}

fn sub_streams_info(r: &mut HeaderReader<'_>, folders: &[Folder<'_>]) -> Result<(), Error> {
    let mut per_folder = vec![1usize; folders.len()];
    let mut nid = r.u8()?;
    if nid == K_NUM_UNPACK_STREAM {
        let mut total = 0usize;
        for n in &mut per_folder {
            *n = r.count()?;
            total = total.saturating_add(*n);
        }
        if total > MAX_FILES {
            return Err(invalid("stream count over cap"));
        }
        nid = r.u8()?;
    }
    if nid == K_SIZE {
        for &n in &per_folder {
            for _ in 1..n {
                r.number()?;
            }
        }
        nid = r.u8()?;
    }
    if nid == K_CRC {
        let digests = per_folder
            .iter()
            .zip(folders)
            .filter(|&(&n, f)| !(n == 1 && f.has_crc))
            .map(|(&n, _)| n)
            .sum();
        let defined = r.defined(digests)?;
        r.skip_crcs(&defined)?;
        nid = r.u8()?;
    }
    if nid != K_END {
        return Err(invalid("bad SubStreamsInfo terminator"));
    }
    Ok(())
}

fn method_name(id: &[u8]) -> &'static str {
    match id {
        Method::ID_COPY => "stored",
        Method::ID_LZMA => "lzma",
        Method::ID_LZMA2 => "lzma2",
        Method::ID_ZSTD => "zstd",
        Method::ID_DEFLATE => "deflated",
        Method::ID_DEFLATE64 => "deflate64",
        Method::ID_BZIP2 => "bzip2",
        Method::ID_AES256SHA256 => "aes256sha256",
        Method::ID_BCJ_X86 => "bcj-x86",
        Method::ID_BCJ_PPC => "bcj-ppc",
        Method::ID_BCJ_IA64 => "bcj-ia64",
        Method::ID_BCJ_ARM => "bcj-arm",
        Method::ID_BCJ_ARM_THUMB => "bcj-arm-thumb",
        Method::ID_BCJ_SPARC => "bcj-sparc",
        Method::ID_DELTA => "delta",
        Method::ID_BCJ2 => "bcj2",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// A 7z NUMBER in its longest form: an all-ones lead byte, then eight
    /// little-endian bytes.
    fn number(n: u64) -> Vec<u8> {
        let mut out = vec![0xFF];
        out.extend_from_slice(&n.to_le_bytes());
        out
    }

    /// Signature header pointing at `next_header`, which follows it directly,
    /// with every CRC valid so only the sizes are under test.
    fn archive_with(next_header: &[u8], declared_size: u64) -> Vec<u8> {
        let mut start = Vec::new();
        start.extend_from_slice(&0u64.to_le_bytes());
        start.extend_from_slice(&declared_size.to_le_bytes());
        start.extend_from_slice(&crc32fast::hash(next_header).to_le_bytes());
        let mut out = SIGNATURE.to_vec();
        out.extend_from_slice(&[0, 4]);
        out.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
        out.extend_from_slice(&start);
        out.extend_from_slice(next_header);
        out
    }

    fn run(bytes: &[u8]) -> Result<(), Error> {
        extract(
            bytes,
            &mut Values::new(),
            &mut Metrics::new(),
            &mut Vec::new(),
        )
    }

    fn rejected_because(bytes: &[u8], why: &str) {
        let err = run(bytes).expect_err("hostile header must be refused");
        assert!(err.to_string().contains(why), "{err}");
    }

    /// The crate allocates the next header at its declared size before
    /// reading it; a size the file cannot back never reaches it.
    #[test]
    fn next_header_size_past_the_file_is_refused() {
        let header = [K_HEADER, K_END];
        rejected_because(
            &archive_with(&header, 1 << 40),
            "next header larger than cap",
        );
        rejected_because(&archive_with(&header, 1 << 20), "next header overruns file");
    }

    /// An encoded header's folder declares the decoded size, which the crate
    /// allocates before decoding a byte.
    #[test]
    fn encoded_header_unpack_size_over_cap_is_refused() {
        let mut header = vec![K_ENCODED_HEADER, K_PACK_INFO, 0, 1, K_SIZE, 1, K_END];
        // One folder, one simple COPY coder.
        header.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER, 1, 0, 1, 0x01, 0x00]);
        header.push(K_CODERS_UNPACK_SIZE);
        header.extend(number(1 << 40));
        header.extend_from_slice(&[K_END, K_END]);
        let len = header.len() as u64;
        rejected_because(
            &archive_with(&header, len),
            "decoded header larger than cap",
        );
    }

    /// Per-file tables are sized by the declared file count up front.
    #[test]
    fn file_count_the_header_cannot_hold_is_refused() {
        let mut header = vec![K_HEADER, K_FILES_INFO];
        header.extend(number(1 << 40));
        header.extend_from_slice(&[K_END, K_END]);
        let len = header.len() as u64;
        rejected_because(
            &archive_with(&header, len),
            "declared count exceeds header size",
        );
    }

    /// A zeroed start header sends the crate guessing at header positions,
    /// none of which can be checked first.
    #[test]
    fn zeroed_start_header_is_refused() {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0, 4]);
        bytes.extend_from_slice(&[0; 24]);
        bytes.extend_from_slice(&[K_HEADER, K_END]);
        rejected_because(&bytes, "start header is zeroed");
    }

    #[test]
    fn header_walk_emits_members_without_reading_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("drop");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Setup.exe"), b"not an executable").unwrap();
        let archive_path = temp.path().join("payload.7z");

        let mut writer = sevenz_rust::SevenZWriter::create(&archive_path).unwrap();
        writer.push_source_path(&source, |_| true).unwrap();
        writer.finish().unwrap();

        let bytes = fs::read(archive_path).unwrap();
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed_members = Vec::new();
        extract(&bytes, &mut values, &mut metrics, &mut typed_members).unwrap();

        let members = values.get("archive.members").unwrap().as_array().unwrap();
        let setup = members
            .iter()
            .find(|member| {
                member["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("Setup.exe"))
            })
            .unwrap();
        assert_eq!(setup["size_bytes"].as_u64(), Some(17));
        assert_eq!(setup["entry_type"].as_str(), Some("regular"));
        assert_eq!(
            values
                .get("archive.format.kind")
                .and_then(serde_json::Value::as_str),
            Some("7z")
        );
        assert_eq!(metrics.get("archive.file_count"), Some(1.0));
        // Emitted even when nothing is encrypted: a rule gated on `min: 1`
        // and the ML feature both need absence to be a reported zero rather
        // than a missing key.
        assert_eq!(metrics.get("archive.security.encrypted_count"), Some(0.0));
        assert_eq!(typed_members.len(), members.len());
    }

    /// Past the shared member cap, files are counted in the limit, not
    /// listed.
    #[test]
    fn members_past_the_cap_are_not_listed() {
        let total = MAX_ARCHIVE_MEMBERS + 3;
        let mut writer = sevenz_rust::SevenZWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        for i in 0..total {
            let mut entry = sevenz_rust::SevenZArchiveEntry::new();
            entry.name = format!("f{i}");
            writer.push_archive_entry::<&[u8]>(entry, None).unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();

        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed_members = Vec::new();
        extract(&bytes, &mut values, &mut metrics, &mut typed_members).unwrap();
        assert_eq!(typed_members.len(), MAX_ARCHIVE_MEMBERS);
        let limits = values
            .get("7z.limits")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(limits[0]["stage"].as_str(), Some("member-cap"));
        assert_eq!(
            limits[0]["reason"].as_str(),
            Some(format!("listed {MAX_ARCHIVE_MEMBERS} of {total} members").as_str())
        );
    }

    /// The shape the malicious bundles use: AES-encrypted payload streams with
    /// the header left in the clear, so the member table still reads without a
    /// password. 7z expresses that through the folder's coder chain rather than
    /// a per-entry flag, which is why it needs its own count.
    #[test]
    fn aes_payload_streams_are_counted_as_encrypted() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("drop");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Setup.exe"), b"not an executable").unwrap();
        let archive_path = temp.path().join("payload.7z");

        let mut writer = sevenz_rust::SevenZWriter::create(&archive_path).unwrap();
        writer.set_content_methods(vec![
            sevenz_rust::AesEncoderOptions::new(sevenz_rust::Password::from("hunter2")).into(),
            sevenz_rust::SevenZMethod::LZMA2.into(),
        ]);
        writer.push_source_path(&source, |_| true).unwrap();
        writer.finish().unwrap();

        let bytes = fs::read(archive_path).unwrap();
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed_members = Vec::new();
        extract(&bytes, &mut values, &mut metrics, &mut typed_members).unwrap();

        assert_eq!(metrics.get("archive.security.encrypted_count"), Some(1.0));
        assert!(typed_members.iter().all(|member| member.encrypted));
    }
}
