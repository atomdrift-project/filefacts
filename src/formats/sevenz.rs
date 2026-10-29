//! 7z archive-header extractor.
//!
//! The 7z format keeps its member table in the next-header section. Reading it
//! gives consumers paths, sizes, timestamps, compression chains, and payload
//! encryption without touching member contents. Header-encrypted archives
//! cannot disclose a member table without a password and return a normal
//! malformed-format error, just as an unreadable ZIP central directory does.
//!
//! The header is read here, with every size and count bounded by the bytes
//! that back it before anything is allocated for it. Layout reference:
//! 7-Zip's `DOC/7zFormat.txt`. An encoded (LZMA-packed) header is inflated
//! to at most [`MAX_HEADER_BYTES`]; member payloads are never decoded.

use serde_json::Value as JsonValue;

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, member_value};
use super::bounded::{Limits, MAX_ARCHIVE_MEMBERS, inflate_capped};
use crate::error::Error;
use crate::formats::common::bytes_at::{u32_le, u64_le};
use crate::output::{ArchiveCompression, ArchiveMember, EntryType, Metrics, Values};
use crate::value_key;

/// The shared aggregates a 7z reports. Path traversal is counted on files
/// only.
///
/// 7z carries its encryption in the coder chain rather than a per-entry
/// flag, so `archive.security.encrypted_count` comes from the chain. It is
/// reported even when zero, so absence is never mistaken for "not
/// encrypted": a password-protected payload with a clear header is the
/// format's most common malicious shape.
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
/// Largest next header, raw or decoded. Real headers run from a few hundred
/// bytes to a few MiB for archives with very many members.
const MAX_HEADER_BYTES: u64 = 32 << 20;
/// Most files (and non-empty streams) a header may declare. Of those, only
/// the first [`MAX_ARCHIVE_MEMBERS`] are listed: a few bytes of LZMA-packed
/// header can declare a million names.
const MAX_FILES: usize = 1 << 20;
/// Per-folder coder and coder-stream limits, the same ones 7-Zip's own reader
/// enforces.
const MAX_FOLDER_CODERS: u64 = 64;
const MAX_FOLDER_STREAMS: u64 = 64;
/// Seconds between the FILETIME epoch (1601) and the Unix epoch.
const FILETIME_UNIX_DIFF_SECS: i64 = 11_644_473_600;

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
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_ANTI: u8 = 0x10;
const K_NAME: u8 = 0x11;
const K_MTIME: u8 = 0x14;
const K_ENCODED_HEADER: u8 = 0x17;

// Coder method IDs, from 7-Zip's `Methods.txt`.
const ID_COPY: &[u8] = &[0x00];
const ID_LZMA: &[u8] = &[0x03, 0x01, 0x01];
const ID_AES256SHA256: &[u8] = &[0x06, 0xf1, 0x07, 0x01];

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let header = read_header(bytes)?;

    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("7z".into()),
    );

    let folder_methods: Vec<String> = header
        .folders
        .iter()
        .map(|folder| {
            folder
                .coders
                .iter()
                .map(|(id, _)| method_name(id))
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    let encrypted_folders: Vec<bool> = header
        .folders
        .iter()
        .map(|f| f.coders.iter().any(|(id, _)| *id == ID_AES256SHA256))
        .collect();

    let listed = header.files.len().min(MAX_ARCHIVE_MEMBERS);
    let mut members = Vec::with_capacity(listed);
    let mut stats = ArchiveStats::new(AGGS);
    let mut next_stream = 0usize;
    for file in header.files.iter().take(listed) {
        let mut member = if file.has_stream {
            let stream = header.streams.get(next_stream);
            next_stream += 1;
            let folder = stream.map(|s| s.folder);
            let mut member = ArchiveMember::new(
                file.name.clone(),
                stream.map_or(0, |s| s.size),
                EntryType::Regular,
            );
            member.crc32 = stream.and_then(|s| s.crc);
            member.encrypted = folder
                .and_then(|f| encrypted_folders.get(f))
                .copied()
                .unwrap_or(false);
            member.compression = ArchiveCompression::new(
                stream.and_then(|s| s.packed_size),
                folder
                    .and_then(|f| folder_methods.get(f))
                    .filter(|m| !m.is_empty())
                    .cloned(),
            );
            member
        } else {
            let entry_type = if file.anti {
                EntryType::AntiItem
            } else if file.empty_file {
                EntryType::Regular
            } else {
                EntryType::Directory
            };
            ArchiveMember::new(file.name.clone(), 0, entry_type)
        };
        member.mtime_unix = file.mtime_unix;
        stats.observe(&member, &Reading::of(&member));
        members.push(JsonValue::Object(member_value(&member)));
        archive_members.push(member);
    }

    if header.files.len() > listed {
        let mut limits = Limits::default();
        limits.push(
            "member-cap",
            format!("listed {listed} of {} members", header.files.len()),
        );
        limits.emit(values, value_key!("7z.limits"));
    }

    values.insert_key(value_key!("archive.members"), JsonValue::Array(members));
    stats.emit(values, metrics);
    Ok(())
}

fn invalid(why: &str) -> Error {
    Error::malformed("7z", why)
}

/// What the member listing needs from a 7z header.
#[derive(Default)]
struct Header {
    folders: Vec<Folder>,
    /// Every unpacked stream, in the order files with data consume them.
    streams: Vec<Stream>,
    files: Vec<File>,
}

/// One `FilesInfo` entry.
#[derive(Default)]
struct File {
    name: String,
    /// The file has a data stream; otherwise it is a directory, an empty
    /// file or an anti-item.
    has_stream: bool,
    empty_file: bool,
    anti: bool,
    mtime_unix: Option<i64>,
}

/// One folder: a coder chain over one or more packed streams.
#[derive(Default)]
struct Folder {
    /// Method ID and properties of each coder.
    coders: Vec<(Vec<u8>, Vec<u8>)>,
    out_streams: u64,
    /// `(in_index, out_index)` pairs wiring one coder's output into another.
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: u64,
    /// Unpacked size of each coder output stream.
    unpack_sizes: Vec<u64>,
    crc: Option<u32>,
}

impl Folder {
    /// The folder's final output: the one coder output no bind pair consumes.
    fn unpack_size(&self) -> u64 {
        (0..self.out_streams)
            .find(|out| !self.bind_pairs.iter().any(|(_, o)| o == out))
            .and_then(|out| usize::try_from(out).ok())
            .and_then(|out| self.unpack_sizes.get(out).copied())
            .unwrap_or(0)
    }
}

#[derive(Default)]
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    /// From `SubStreamsInfo`: how many files each folder unpacks into, and
    /// the size and CRC of each. `None` means one stream per folder.
    sub_streams: Option<SubStreams>,
}

#[derive(Default)]
struct SubStreams {
    per_folder: Vec<usize>,
    sizes: Vec<u64>,
    crcs: Vec<Option<u32>>,
}

/// One unpacked stream, in archive order: what a file with a stream reads.
struct Stream {
    folder: usize,
    size: u64,
    crc: Option<u32>,
    /// The folder's first packed stream, charged to the folder's first file.
    packed_size: Option<u64>,
}

impl StreamsInfo {
    fn unpacked_streams(&self) -> Vec<Stream> {
        let mut out = Vec::new();
        let mut pack_index = 0usize;
        let mut sub = 0usize;
        for (index, folder) in self.folders.iter().enumerate() {
            let first_pack = self.pack_sizes.get(pack_index).copied();
            pack_index =
                pack_index.saturating_add(usize::try_from(folder.packed_streams).unwrap_or(0));
            let count = match &self.sub_streams {
                Some(s) => s.per_folder.get(index).copied().unwrap_or(0),
                None => 1,
            };
            for n in 0..count {
                let (size, crc) = match &self.sub_streams {
                    Some(s) => (
                        s.sizes.get(sub).copied().unwrap_or(0),
                        s.crcs.get(sub).copied().flatten(),
                    ),
                    None => (folder.unpack_size(), folder.crc),
                };
                sub += 1;
                out.push(Stream {
                    folder: index,
                    size,
                    crc,
                    packed_size: if n == 0 { first_pack } else { None },
                });
            }
        }
        out
    }
}

/// Read the header the signature block points at, decoding it first when it
/// is an `EncodedHeader`.
fn read_header(bytes: &[u8]) -> Result<Header, Error> {
    let start = bytes
        .first_chunk::<SIGNATURE_HEADER_LEN>()
        .ok_or_else(|| invalid("signature header truncated"))?;
    if !start.starts_with(SIGNATURE) {
        return Err(invalid("bad signature"));
    }
    // A zeroed start header is what an interrupted writer leaves; 7-Zip then
    // scans the file tail for a header-shaped candidate. That guess is not
    // made here.
    if start[8..].iter().all(|&b| b == 0) {
        return Err(invalid("start header is zeroed"));
    }
    let offset = u64_le(start, 12).unwrap_or(u64::MAX);
    let size = u64_le(start, 20).unwrap_or(u64::MAX);
    if size > MAX_HEADER_BYTES {
        return Err(invalid("next header larger than cap"));
    }
    let raw = (SIGNATURE_HEADER_LEN as u64)
        .checked_add(offset)
        .and_then(|from| file_range(bytes, from, size))
        .ok_or_else(|| invalid("next header overruns file"))?;

    let mut r = HeaderReader { buf: raw };
    match r.u8()? {
        K_HEADER => plain_header(&mut r),
        K_ENCODED_HEADER => {
            let decoded = decode_header(bytes, &mut r)?;
            let mut r = HeaderReader { buf: &decoded };
            if r.u8()? != K_HEADER {
                return Err(invalid("decoded header is not a Header"));
            }
            plain_header(&mut r)
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

/// Decode an encoded header: its streams info names one folder over one
/// packed stream, and that folder's output is the real header.
fn decode_header(bytes: &[u8], r: &mut HeaderReader<'_>) -> Result<Vec<u8>, Error> {
    let info = streams_info(r)?;
    let folder = info
        .folders
        .first()
        .ok_or_else(|| invalid("encoded header has no folder"))?;
    let unpack_size = folder.unpack_size();
    if unpack_size > MAX_HEADER_BYTES {
        return Err(invalid("decoded header larger than cap"));
    }
    if folder.coders.iter().any(|(id, _)| *id == ID_AES256SHA256) {
        return Err(invalid("header is encrypted"));
    }
    let pack_size = *info
        .pack_sizes
        .first()
        .ok_or_else(|| invalid("encoded header has no packed stream"))?;
    let packed = (SIGNATURE_HEADER_LEN as u64)
        .checked_add(info.pack_pos)
        .and_then(|from| file_range(bytes, from, pack_size))
        .ok_or_else(|| invalid("encoded header overruns file"))?;
    let out = match folder.coders.as_slice() {
        [(id, _)] if *id == ID_COPY => packed
            .get(..crate::bytes::sat_usize(unpack_size))
            .unwrap_or(packed)
            .to_vec(),
        [(id, props)] if *id == ID_LZMA => {
            let Some(&[lc_lp_pb, d0, d1, d2, d3]) = props.get(..5) else {
                return Err(invalid("LZMA header coder properties truncated"));
            };
            // The dictionary never needs to exceed what it decodes, and the
            // header's own claim is not a bound.
            let dict_size = u32::from_le_bytes([d0, d1, d2, d3])
                .min(crate::bytes::sat_u32(crate::bytes::sat_usize(unpack_size)));
            lzma_rust2::LzmaReader::new_with_props(packed, unpack_size, lc_lp_pb, dict_size, None)
                .and_then(|lzma| inflate_capped(lzma, unpack_size))
                .map_err(|e| Error::malformed_with_source("7z", "encoded header", e))?
                .bytes
        }
        // 7-Zip writes its headers with LZMA; anything else is not decoded.
        _ => return Err(invalid("unsupported encoded-header coder chain")),
    };
    if out.len() as u64 != unpack_size {
        return Err(invalid("encoded header shorter than declared"));
    }
    Ok(out)
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

    /// The next `n` bytes, as a reader of their own.
    fn sub(&mut self, n: u64) -> Result<HeaderReader<'a>, Error> {
        let n = usize::try_from(n).map_err(|_| invalid("header field overruns header"))?;
        Ok(HeaderReader { buf: self.take(n)? })
    }

    fn skip(&mut self, n: u64) -> Result<(), Error> {
        self.sub(n).map(drop)
    }

    fn u32_le(&mut self) -> Result<u32, Error> {
        u32_le(self.take(4)?, 0).ok_or_else(|| invalid("header truncated"))
    }

    fn u64_le(&mut self) -> Result<u64, Error> {
        u64_le(self.take(8)?, 0).ok_or_else(|| invalid("header truncated"))
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

    /// A declared element count, accepted only when the rest of the header
    /// could hold a byte per element, so nothing is allocated for elements
    /// the file cannot back.
    fn count(&mut self) -> Result<usize, Error> {
        let n = self.number()?;
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= self.buf.len())
            .ok_or_else(|| invalid("declared count exceeds header size"))
    }

    /// `n` bits, most significant first.
    fn bits(&mut self, n: usize) -> Result<Vec<bool>, Error> {
        let bits = self.take(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| bits.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0))
            .collect())
    }

    /// An all-defined flag byte, else one bit per item.
    fn defined(&mut self, n: usize) -> Result<Vec<bool>, Error> {
        if self.u8()? != 0 {
            return Ok(vec![true; n]);
        }
        self.bits(n)
    }

    /// The CRC-32 of each defined item.
    fn crcs(&mut self, n: usize) -> Result<Vec<Option<u32>>, Error> {
        self.defined(n)?
            .into_iter()
            .map(|d| if d { self.u32_le().map(Some) } else { Ok(None) })
            .collect()
    }
}

fn plain_header(r: &mut HeaderReader<'_>) -> Result<Header, Error> {
    let mut header = Header::default();
    let mut nid = r.u8()?;
    if nid == K_ARCHIVE_PROPERTIES {
        while r.u8()? != K_END {
            let size = r.number()?;
            r.skip(size)?;
        }
        nid = r.u8()?;
    }
    if nid == K_MAIN_STREAMS_INFO {
        let info = streams_info(r)?;
        header.streams = info.unpacked_streams();
        header.folders = info.folders;
        nid = r.u8()?;
    }
    if nid == K_FILES_INFO {
        header.files = files_info(r)?;
        nid = r.u8()?;
    }
    if nid != K_END {
        return Err(invalid("bad Header terminator"));
    }
    let with_stream = header.files.iter().filter(|f| f.has_stream).count();
    if with_stream > header.streams.len() {
        return Err(invalid("more files with data than unpacked streams"));
    }
    Ok(header)
}

fn files_info(r: &mut HeaderReader<'_>) -> Result<Vec<File>, Error> {
    let n = r.count()?;
    if n > MAX_FILES {
        return Err(invalid("file count over cap"));
    }
    let mut files: Vec<File> = (0..n)
        .map(|_| File {
            has_stream: true,
            ..File::default()
        })
        .collect();
    let mut empty_stream: Vec<bool> = Vec::new();
    loop {
        let id = r.u8()?;
        if id == K_END {
            break;
        }
        let size = r.number()?;
        let mut p = r.sub(size)?;
        match id {
            K_EMPTY_STREAM => {
                empty_stream = p.bits(n)?;
                for (file, &empty) in files.iter_mut().zip(&empty_stream) {
                    file.has_stream = !empty;
                }
            }
            K_EMPTY_FILE | K_ANTI => {
                let empties = empty_stream.iter().filter(|&&e| e).count();
                let flags = p.bits(empties)?;
                let empty_files = files.iter_mut().filter(|f| !f.has_stream);
                for (file, set) in empty_files.zip(flags) {
                    if id == K_EMPTY_FILE {
                        file.empty_file = set;
                    } else {
                        file.anti = set;
                    }
                }
            }
            K_NAME => {
                if p.u8()? != 0 {
                    return Err(invalid("external file names"));
                }
                let units: Vec<u16> = p
                    .buf
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .collect();
                let mut names = units.split(|&u| u == 0);
                for file in &mut files {
                    let name = names.next().ok_or_else(|| invalid("too few file names"))?;
                    file.name = String::from_utf16_lossy(name).replace('\\', "/");
                }
            }
            K_MTIME => {
                let defined = p.defined(n)?;
                if p.u8()? != 0 {
                    return Err(invalid("external file times"));
                }
                for (file, d) in files.iter_mut().zip(defined) {
                    if d {
                        file.mtime_unix = filetime_to_unix(p.u64_le()?);
                    }
                }
            }
            // Creation and access times, attributes, comments, padding: not
            // needed for the listing, and bounded by their declared size.
            _ => {}
        }
    }
    Ok(files)
}

/// A Windows FILETIME (100 ns ticks since 1601) as Unix seconds.
fn filetime_to_unix(ticks: u64) -> Option<i64> {
    i64::try_from(ticks / 10_000_000)
        .ok()?
        .checked_sub(FILETIME_UNIX_DIFF_SECS)
}

fn streams_info(r: &mut HeaderReader<'_>) -> Result<StreamsInfo, Error> {
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
            r.crcs(n)?;
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
            for (f, crc) in info.folders.iter_mut().zip(r.crcs(n)?) {
                f.crc = crc;
            }
            nid = r.u8()?;
        }
        if nid != K_END {
            return Err(invalid("bad UnpackInfo terminator"));
        }
        nid = r.u8()?;
    }
    if nid == K_SUB_STREAMS_INFO {
        info.sub_streams = Some(sub_streams_info(r, &info.folders)?);
        nid = r.u8()?;
    }
    if nid != K_END {
        return Err(invalid("bad StreamsInfo terminator"));
    }
    Ok(info)
}

fn folder(r: &mut HeaderReader<'_>) -> Result<Folder, Error> {
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
        let id = r.take(usize::from(flags & 0x0f))?.to_vec();
        if flags & 0x10 == 0 {
            in_streams += 1;
            f.out_streams += 1;
        } else {
            in_streams = in_streams.saturating_add(r.number()?);
            f.out_streams = f.out_streams.saturating_add(r.number()?);
        }
        let props = if flags & 0x20 != 0 {
            let len = r.count()?;
            r.take(len)?.to_vec()
        } else {
            Vec::new()
        };
        f.coders.push((id, props));
    }
    if f.out_streams == 0 || in_streams > MAX_FOLDER_STREAMS || f.out_streams > MAX_FOLDER_STREAMS {
        return Err(invalid("implausible coder stream count"));
    }
    for _ in 0..f.out_streams - 1 {
        let pair = (r.number()?, r.number()?);
        f.bind_pairs.push(pair);
    }
    f.packed_streams = in_streams
        .checked_sub(f.out_streams - 1)
        .ok_or_else(|| invalid("more bind pairs than input streams"))?;
    if f.packed_streams > 1 {
        for _ in 0..f.packed_streams {
            r.number()?;
        }
    }
    Ok(f)
}

fn sub_streams_info(r: &mut HeaderReader<'_>, folders: &[Folder]) -> Result<SubStreams, Error> {
    let mut sub = SubStreams {
        per_folder: vec![1; folders.len()],
        ..SubStreams::default()
    };
    let mut nid = r.u8()?;
    if nid == K_NUM_UNPACK_STREAM {
        let mut total = 0usize;
        for n in &mut sub.per_folder {
            *n = r.count()?;
            total = total.saturating_add(*n);
        }
        if total > MAX_FILES {
            return Err(invalid("stream count over cap"));
        }
        nid = r.u8()?;
    }
    // Each folder with streams lists all but its last size; the last is
    // what remains of the folder's output.
    let explicit = nid == K_SIZE;
    for (folder, &n) in folders.iter().zip(&sub.per_folder) {
        if n == 0 {
            continue;
        }
        let mut sum = 0u64;
        if explicit {
            for _ in 1..n {
                let size = r.number()?;
                sum = sum.saturating_add(size);
                sub.sizes.push(size);
            }
        }
        sub.sizes.push(folder.unpack_size().saturating_sub(sum));
    }
    if explicit {
        nid = r.u8()?;
    }
    // A folder unpacking to one stream with a folder CRC already has it;
    // every other stream's CRC is listed here.
    let inherits = |f: &Folder, n: usize| n == 1 && f.crc.is_some();
    let mut listed = Vec::new().into_iter();
    if nid == K_CRC {
        let count = folders
            .iter()
            .zip(&sub.per_folder)
            .filter(|&(f, &n)| !inherits(f, n))
            .map(|(_, &n)| n)
            .sum();
        listed = r.crcs(count)?.into_iter();
        nid = r.u8()?;
    }
    for (folder, &n) in folders.iter().zip(&sub.per_folder) {
        if inherits(folder, n) {
            sub.crcs.push(folder.crc);
        } else {
            for _ in 0..n {
                sub.crcs.push(listed.next().flatten());
            }
        }
    }
    if nid != K_END {
        return Err(invalid("bad SubStreamsInfo terminator"));
    }
    Ok(sub)
}

/// The name of one coder in filefacts' stable method vocabulary.
fn method_name(id: &[u8]) -> &'static str {
    match id {
        [0x00] => "stored",
        [0x03, 0x01, 0x01] => "lzma",
        [0x21] => "lzma2",
        [0x04, 0xf7, 0x11, 0x01] => "zstd",
        [0x04, 0x01, 0x08] => "deflated",
        [0x04, 0x01, 0x09] => "deflate64",
        [0x04, 0x02, 0x02] => "bzip2",
        [0x06, 0xf1, 0x07, 0x01] => "aes256sha256",
        [0x03, 0x03, 0x01, 0x03] => "bcj-x86",
        [0x03, 0x03, 0x02, 0x05] => "bcj-ppc",
        [0x03, 0x03, 0x04, 0x01] => "bcj-ia64",
        [0x03, 0x03, 0x05, 0x01] => "bcj-arm",
        [0x03, 0x03, 0x07, 0x01] => "bcj-arm-thumb",
        [0x03, 0x03, 0x08, 0x05] => "bcj-sparc",
        [0x03] => "delta",
        [0x03, 0x03, 0x01, 0x1b] => "bcj2",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests;
