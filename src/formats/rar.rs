//! RAR 4.x / 5.0 archive-header extractor.
//!
//! RAR was identified by magic and classified as an archive, but had no arm
//! in the extractor dispatch, so `archive.members` came back empty for every
//! volume. Every rule reading `archive.members[*]` was therefore inert
//! against a format that is a routine encrypted-payload carrier.
//!
//! The member table lives in the headers, not the payload. This walk reads
//! those headers and never decompresses: encrypted files still disclose
//! names, sizes, times, host OS, method, and the encryption extras; an
//! archive whose *headers* are encrypted stops after the crypt block and
//! reports that fact. Trailing bytes past the end marker, SFX prefixes,
//! NTFS streams, comments, the original archive name, and the odd flags
//! (solid, locked, volume, recovery, split) are the same class of field
//! CAB already publishes — who built it, when, on what, and what they
//! packed.
//!
//! Quick-open cache is recorded, not trusted: the format document warns
//! that displaying names from QO and extracting from the real headers
//! can be made to disagree. We only walk the real headers.

use std::collections::BTreeSet;

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::archive_stats::{Agg, ArchiveStats, Dominance, Reading, Scope, Shape, member_value};
use crate::bytes::Reader;
use crate::error::Error;
use crate::formats::common::hex_encode;
use crate::metric;
use crate::output::{
    ArchiveCompression, ArchiveMember, ArchiveOffsets, ArchiveOwnership, Metrics, Values,
};
use crate::value_key;

const MAX_SFX: usize = 1024 * 1024;
const MAX_HEADER: usize = 2 * 1024 * 1024;
const MAX_NAME: usize = 65_536;
const MAX_MEMBERS: usize = 100_000;
const MAX_BLOCKS: usize = 200_000;
const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

const SIG4: &[u8] = b"Rar!\x1a\x07\x00";
const SIG5: &[u8] = b"Rar!\x1a\x07\x01\x00";

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HFL_SKIP_UNKNOWN: u64 = 0x0004;
const HFL_SPLIT_BEFORE: u64 = 0x0008;
const HFL_SPLIT_AFTER: u64 = 0x0010;
const HFL_CHILD: u64 = 0x0020;

const MHD_VOLUME: u64 = 0x0001;
const MHD_VOLNUM: u64 = 0x0002;
const MHD_SOLID: u64 = 0x0004;
const MHD_RECOVERY: u64 = 0x0008;
const MHD_LOCKED: u64 = 0x0010;

const LHFL_DIRECTORY: u64 = 0x0001;
const LHFL_UTIME: u64 = 0x0002;
const LHFL_CRC32: u64 = 0x0004;
const LHFL_UNPUNKNOWN: u64 = 0x0008;

const HEAD5_MAIN: u64 = 1;
const HEAD5_FILE: u64 = 2;
const HEAD5_SERVICE: u64 = 3;
const HEAD5_CRYPT: u64 = 4;
const HEAD5_END: u64 = 5;

const ATTR_READONLY: u32 = 0x1;
const ATTR_HIDDEN: u32 = 0x2;
const ATTR_SYSTEM: u32 = 0x4;
const ATTR_DIR: u32 = 0x10;

const R4_LONG_BLOCK: u16 = 0x8000;
const R4_SKIP_UNKNOWN: u16 = 0x4000;
const R4_MAIN: u8 = 0x73;
const R4_FILE: u8 = 0x74;
const R4_NEWSUB: u8 = 0x7a;
const R4_END: u8 = 0x7b;
const R4_MHD_VOLUME: u16 = 0x0001;
const R4_MHD_COMMENT: u16 = 0x0002;
const R4_MHD_LOCK: u16 = 0x0004;
const R4_MHD_SOLID: u16 = 0x0008;
const R4_MHD_NEWNUMBERING: u16 = 0x0010;
const R4_MHD_AV: u16 = 0x0020;
const R4_MHD_PROTECT: u16 = 0x0040;
const R4_MHD_PASSWORD: u16 = 0x0080;
const R4_MHD_FIRSTVOLUME: u16 = 0x0100;
const R4_MHD_ENCRYPTVER: u16 = 0x0200;
const R4_LHD_SPLIT_BEFORE: u16 = 0x0001;
const R4_LHD_SPLIT_AFTER: u16 = 0x0002;
const R4_LHD_PASSWORD: u16 = 0x0004;
const R4_LHD_SOLID: u16 = 0x0010;
const R4_LHD_WINDOWDIR: u16 = 0x00e0;
const R4_LHD_LARGE: u16 = 0x0100;
const R4_LHD_UNICODE: u16 = 0x0200;
const R4_LHD_SALT: u16 = 0x0400;
const R4_LHD_VERSION: u16 = 0x0800;
const R4_LHD_EXTTIME: u16 = 0x1000;

/// RAR5's variable-length integer: seven bits per byte, low group first,
/// with the high bit set on every byte but the last.
trait ReadVint {
    /// Read one vint. One that runs off the end, or past ten bytes, fails
    /// having consumed the bytes it read.
    fn vint(&mut self) -> Option<u64>;
}

impl ReadVint for Reader<'_> {
    fn vint(&mut self) -> Option<u64> {
        let mut n = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let b = self.u8()?;
            n = n.saturating_add(u64::from(b & 0x7f).checked_shl(shift)?);
            if b & 0x80 == 0 {
                return Some(n);
            }
            shift = shift.saturating_add(7);
        }
        None
    }
}

#[derive(Default)]
struct Extra {
    encrypted: bool,
    kdf_count: Option<u8>,
    tweaked_checksums: bool,
    blake2: Option<String>,
    mtime: Option<i64>,
    ctime: Option<i64>,
    atime: Option<i64>,
    file_version: Option<u64>,
    redir_type: Option<&'static str>,
    link_is_dir: bool,
    linkname: Option<String>,
    uname: Option<String>,
    gname: Option<String>,
    uid: Option<u64>,
    gid: Option<u64>,
    service_data: Option<Vec<u8>>,
    types: Vec<u64>,
    unknown: u64,
    bytes: u64,
}

struct Member {
    path: String,
    size_bytes: u64,
    packed: Option<u64>,
    entry_type: &'static str,
    mtime: Option<i64>,
    ctime: Option<i64>,
    atime: Option<i64>,
    encrypted: bool,
    method: Option<String>,
    dict_size: Option<u64>,
    host_os: Option<String>,
    crc32: Option<u32>,
    blake2: Option<String>,
    split_before: bool,
    split_after: bool,
    solid: bool,
    hidden: bool,
    system: bool,
    read_only: bool,
    linkname: Option<String>,
    redir_type: Option<&'static str>,
    file_version: Option<u64>,
    extra_types: Vec<u64>,
    header_off: u64,
    data_off: Option<u64>,
    mode_octal: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    uname: Option<String>,
    gname: Option<String>,
    windows_attrs: Option<u32>,
    kdf_count: Option<u8>,
    tweaked_checksums: bool,
    unpack_version: Option<u64>,
    size_unknown: bool,
}

#[derive(Default)]
struct Archive {
    version: u8,
    prefix: u64,
    volume: bool,
    volume_number: Option<u64>,
    solid: bool,
    recovery: bool,
    locked: bool,
    first_volume: bool,
    new_numbering: bool,
    authenticity: bool,
    headers_encrypted: bool,
    kdf_count: Option<u8>,
    crypt_version: Option<u64>,
    original_name: Option<String>,
    created_unix: Option<i64>,
    comment: Option<String>,
    comment_packed: bool,
    locator_qo: Option<u64>,
    locator_rr: Option<u64>,
    members: Vec<Member>,
    services: Vec<String>,
    streams: Vec<JsonValue>,
    extra_types: BTreeSet<u64>,
    limits: Vec<JsonValue>,
    end_present: bool,
    not_last_volume: bool,
    header_crc_mismatch: u64,
    unknown_header: u64,
    unknown_extra: u64,
    blake2: u64,
    acl: u64,
    file_version: u64,
    split: u64,
    child: u64,
    mapped_unix: u64,
    v1_comp: u64,
    unpack_min: Option<u64>,
    unpack_max: Option<u64>,
    quick_open: bool,
    quick_open_size: u64,
    recovery_size: u64,
    extra_field_size: u64,
    end_offset: u64,
    last_file: Option<String>,
    r4_encrypt_ver: Option<u8>,
}

fn limit(ar: &mut Archive, stage: &str, reason: impl Into<String>) {
    ar.limits.push(serde_json::json!({
        "stage": stage,
        "reason": reason.into(),
    }));
}

/// Step over a block's packed data. Data running past the end of the file is
/// a truncated archive or a lying size: stop at the end and record it, rather
/// than resume the header walk inside the payload.
fn skip_data(inp: &mut Reader<'_>, ar: &mut Archive, size: u64) {
    let remaining = inp.remaining() as u64;
    if size > remaining {
        limit(
            ar,
            "data",
            format!(
                "packed data runs {} bytes past end of file",
                size - remaining
            ),
        );
    }
    // Clamped to what is left, so the skip cannot fail.
    let _ = inp.skip(size.min(remaining) as usize);
}

fn find_signature(bytes: &[u8]) -> Option<(usize, u8)> {
    let search = bytes.len().min(MAX_SFX.saturating_add(SIG5.len()));
    let hay = bytes.get(..search)?;
    (0..hay.len().saturating_sub(SIG4.len() - 1)).find_map(|i| {
        let rest = hay.get(i..)?;
        if rest.starts_with(SIG5) {
            Some((i, 5))
        } else if rest.starts_with(SIG4) {
            Some((i, 4))
        } else {
            None
        }
    })
}

fn utf8_name(bytes: &[u8]) -> String {
    let name = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
    String::from_utf8_lossy(name).replace('\\', "/")
}

fn host5(n: u64) -> String {
    match n {
        0 => "windows".into(),
        1 => "unix".into(),
        _ => format!("os-{n}"),
    }
}

fn host4(n: u8) -> String {
    match n {
        0 => "msdos".into(),
        1 => "os2".into(),
        2 => "windows".into(),
        3 => "unix".into(),
        4 => "macos".into(),
        5 => "beos".into(),
        _ => format!("os-{n}"),
    }
}

fn method5(n: u64) -> String {
    match n {
        0 => "stored".into(),
        1 => "rar-fastest".into(),
        2 => "rar-fast".into(),
        3 => "rar-normal".into(),
        4 => "rar-good".into(),
        5 => "rar-best".into(),
        _ => format!("rar-m{n}"),
    }
}

fn redir_name(n: u64) -> &'static str {
    match n {
        1 => "unix-symlink",
        2 => "windows-symlink",
        3 => "windows-junction",
        4 => "hard-link",
        5 => "file-copy",
        _ => "unknown",
    }
}

fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft < FILETIME_UNIX_DIFF {
        return None;
    }
    i64::try_from((ft - FILETIME_UNIX_DIFF) / 10_000_000).ok()
}

fn dos_to_unix(ft: u32) -> Option<i64> {
    let date = (ft >> 16) as u16;
    let time = ft as u16;
    let year = i32::from((date >> 9) & 0x7f) + 1980;
    let month = u32::from((date >> 5) & 0xf);
    let day = u32::from(date & 0x1f);
    let hour = i64::from((time >> 11) & 0x1f);
    let min = i64::from((time >> 5) & 0x3f);
    let sec = i64::from(time & 0x1f) * 2;
    let days = crate::scan::days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

fn unix_time(flags: u64, inp: &mut Reader<'_>) -> Option<i64> {
    if flags & 0x0001 != 0 {
        Some(i64::from(inp.u32_le()?))
    } else {
        filetime_to_unix(inp.u64_le()?)
    }
}

fn parse_extra(bytes: &[u8], extra: &mut Extra) {
    extra.bytes = extra.bytes.saturating_add(bytes.len() as u64);
    let mut inp = Reader::new(bytes);
    while inp.remaining() > 0 {
        let Some(size) = inp.vint() else { break };
        let start = inp.pos();
        let Some(end) = start.checked_add(size as usize) else {
            break;
        };
        if end > bytes.len() {
            extra.unknown += 1;
            break;
        }
        let Some(typ) = inp.vint() else { break };
        extra.types.push(typ);
        let Some(data) = bytes.get(inp.pos()..end) else {
            extra.unknown += 1;
            break;
        };
        inp = Reader::at(bytes, end);
        let mut d = Reader::new(data);
        match typ {
            0x01 => {
                extra.encrypted = true;
                let _ver = d.vint();
                let flags = d.vint().unwrap_or(0);
                extra.kdf_count = d.u8();
                extra.tweaked_checksums = flags & 0x0002 != 0;
                let _ = d.skip(16);
                let _ = d.skip(16);
            }
            0x02 => {
                if d.vint() == Some(0) && d.remaining() >= 32 {
                    if let Some(h) = d.bytes(32) {
                        extra.blake2 = Some(hex_encode(h));
                    }
                }
            }
            0x03 => {
                let flags = d.vint().unwrap_or(0);
                if flags & 0x0002 != 0 {
                    extra.mtime = unix_time(flags, &mut d);
                }
                if flags & 0x0004 != 0 {
                    extra.ctime = unix_time(flags, &mut d);
                }
                if flags & 0x0008 != 0 {
                    extra.atime = unix_time(flags, &mut d);
                }
                // Sub-second refinements trail all three base timestamps,
                // in the same mtime/ctime/atime order, as plain 4-byte
                // nanosecond counts — not folded into a wider mtime field.
                // They don't change our whole-second values; read them
                // only to keep the cursor aligned for any record after.
                if flags & (0x0001 | 0x0010) == (0x0001 | 0x0010) {
                    if flags & 0x0002 != 0 {
                        let _ = d.u32_le();
                    }
                    if flags & 0x0004 != 0 {
                        let _ = d.u32_le();
                    }
                    if flags & 0x0008 != 0 {
                        let _ = d.u32_le();
                    }
                }
            }
            0x04 => {
                let _ = d.vint();
                extra.file_version = d.vint();
            }
            0x05 => {
                let kind = d.vint().unwrap_or(0);
                extra.redir_type = Some(redir_name(kind));
                let flags = d.vint().unwrap_or(0);
                extra.link_is_dir = flags & 0x0001 != 0;
                if let Some(nlen) = d.vint() {
                    let n = nlen.min(MAX_NAME as u64) as usize;
                    if let Some(name) = d.bytes(n) {
                        extra.linkname = Some(utf8_name(name));
                    }
                }
            }
            0x06 => {
                let flags = d.vint().unwrap_or(0);
                if flags & 0x0001 != 0 {
                    extra.uname = read_counted_str(&mut d);
                }
                if flags & 0x0002 != 0 {
                    extra.gname = read_counted_str(&mut d);
                }
                if flags & 0x0004 != 0 {
                    extra.uid = d.vint();
                }
                if flags & 0x0008 != 0 {
                    extra.gid = d.vint();
                }
            }
            0x07 => extra.service_data = Some(data.to_vec()),
            _ => extra.unknown += 1,
        }
    }
}

fn read_counted_str(inp: &mut Reader<'_>) -> Option<String> {
    let n = inp.vint()? as usize;
    if n > MAX_NAME {
        return None;
    }
    inp.bytes(n).map(utf8_name)
}

fn parse_main_extra(bytes: &[u8], ar: &mut Archive) {
    let mut inp = Reader::new(bytes);
    while inp.remaining() > 0 {
        let Some(size) = inp.vint() else { break };
        let start = inp.pos();
        let Some(end) = start.checked_add(size as usize) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        let Some(typ) = inp.vint() else { break };
        let data = bytes.get(inp.pos().min(end)..end).unwrap_or_default();
        inp = Reader::at(bytes, end);
        ar.extra_field_size = ar.extra_field_size.saturating_add(size);
        ar.extra_types.insert(typ);
        let mut d = Reader::new(data);
        match typ {
            0x01 => {
                let flags = d.vint().unwrap_or(0);
                if flags & 0x0001 != 0 {
                    ar.locator_qo = d.vint();
                }
                if flags & 0x0002 != 0 {
                    ar.locator_rr = d.vint();
                }
            }
            0x02 => {
                let flags = d.vint().unwrap_or(0);
                if flags & 0x0001 != 0 {
                    if let Some(nlen) = d.vint() {
                        let n = nlen.min(MAX_NAME as u64) as usize;
                        if let Some(name) = d.bytes(n) {
                            if name.first() != Some(&0) {
                                ar.original_name = Some(utf8_name(name));
                            }
                        }
                    }
                }
                if flags & 0x0002 != 0 {
                    // Unlike the File-time extra record (type 0x03), the
                    // Metadata record's own format flag is 0x0004, not
                    // 0x0001 (0x0001 here means "name is present"); the
                    // shared `unix_time` helper assumes the 0x03 layout and
                    // would misread this field, so decode it directly.
                    ar.created_unix = if flags & 0x0004 != 0 {
                        d.u32_le().map(i64::from)
                    } else {
                        d.u64_le().and_then(filetime_to_unix)
                    };
                }
            }
            _ => ar.unknown_extra += 1,
        }
    }
}

fn dict_size(comp: u64) -> u64 {
    // Bits 11-15 of CompInfo, numbered from 1; the mask in the spec is 0x7c00.
    let n = (comp >> 10) & 0x1f;
    let mut size = (128u64 * 1024).saturating_mul(1u64.checked_shl(n as u32).unwrap_or(1));
    if (comp & 0x3f) >= 1 {
        let frac = (comp >> 15) & 0x1f;
        size = size.saturating_add(size / 32 * frac);
    }
    size
}

fn apply_attrs(member: &mut Member, attrs: u32, unix: bool) {
    if unix {
        member.mode_octal = Some(attrs);
    } else {
        member.windows_attrs = Some(attrs);
        member.read_only = attrs & ATTR_READONLY != 0;
        member.hidden = attrs & ATTR_HIDDEN != 0;
        member.system = attrs & ATTR_SYSTEM != 0;
        if attrs & ATTR_DIR != 0 {
            member.entry_type = "directory";
        }
    }
}

fn finish_file(ar: &mut Archive, mut member: Member, extra: Extra, service: bool, name: &str) {
    ar.unknown_extra = ar.unknown_extra.saturating_add(extra.unknown);
    ar.extra_field_size = ar.extra_field_size.saturating_add(extra.bytes);
    for t in &extra.types {
        ar.extra_types.insert(*t);
    }
    if extra.encrypted {
        member.encrypted = true;
        member.kdf_count = extra.kdf_count;
        member.tweaked_checksums = extra.tweaked_checksums;
    }
    if extra.mtime.is_some() {
        member.mtime = extra.mtime;
    }
    member.ctime = extra.ctime;
    member.atime = extra.atime;
    member.blake2.clone_from(&extra.blake2);
    if extra.blake2.is_some() {
        ar.blake2 += 1;
    }
    if let Some(v) = extra.file_version {
        member.file_version = Some(v);
        ar.file_version += 1;
    }
    if extra.linkname.is_some() {
        member.linkname.clone_from(&extra.linkname);
        member.redir_type = extra.redir_type;
        if extra
            .redir_type
            .is_some_and(|t| t.contains("symlink") || t == "hard-link")
        {
            member.entry_type = if extra.link_is_dir {
                "directory"
            } else {
                "symlink"
            };
        }
    }
    member.uname = extra.uname;
    member.gname = extra.gname;
    member.uid = extra.uid;
    member.gid = extra.gid;
    member.extra_types = extra.types;

    if service {
        ar.services.push(name.to_string());
        match name {
            "CMT" => {
                ar.comment_packed = member.method.as_deref() != Some("stored");
            }
            "QO" => {
                ar.quick_open = true;
                ar.quick_open_size = member.packed.unwrap_or(member.size_bytes);
            }
            "RR" => {
                ar.recovery = true;
                ar.recovery_size = member.packed.unwrap_or(member.size_bytes);
            }
            "ACL" => ar.acl += 1,
            "STM" => {
                let stream = extra
                    .service_data
                    .as_deref()
                    .map(utf8_name)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "$DATA".into());
                let stream = stream.trim_start_matches(':');
                let host = ar.last_file.clone().unwrap_or_default();
                let path = if host.is_empty() {
                    format!(":{stream}")
                } else {
                    format!("{host}:{stream}")
                };
                ar.streams.push(serde_json::json!({
                    "host": host,
                    "stream": stream,
                    "size_bytes": member.size_bytes,
                    "encrypted": member.encrypted,
                }));
                member.path = path;
                member.entry_type = "ntfs-stream";
                push_member(ar, member);
            }
            _ => {}
        }
        return;
    }

    if member.path.chars().any(|c| c == '\u{FFFE}') {
        ar.mapped_unix += 1;
    }
    ar.last_file = Some(member.path.clone());
    push_member(ar, member);
}

fn push_member(ar: &mut Archive, member: Member) {
    if ar.members.len() >= MAX_MEMBERS {
        if ar.limits.is_empty() || ar.limits.last().is_some_and(|l| l["stage"] != "member-cap") {
            limit(
                ar,
                "member-cap",
                format!("stopped at {MAX_MEMBERS} members"),
            );
        }
        return;
    }
    if member.split_before || member.split_after {
        ar.split += 1;
    }
    ar.members.push(member);
}

fn walk_rar5(bytes: &[u8], start: usize, ar: &mut Archive) {
    let mut inp = Reader::at(bytes, start);
    for _ in 0..MAX_BLOCKS {
        if inp.remaining() == 0 {
            break;
        }
        let header_off = inp.pos() as u64;
        let Some(stored_crc) = inp.u32_le() else {
            limit(ar, "header", "truncated CRC");
            break;
        };
        let size_at = inp.pos();
        let Some(header_size) = inp.vint() else {
            limit(ar, "header", "truncated header size");
            break;
        };
        if header_size == 0 || header_size as usize > MAX_HEADER {
            limit(ar, "header", "header size out of range");
            break;
        }
        let type_at = inp.pos();
        let Some(rest_end) = type_at.checked_add(header_size as usize) else {
            limit(ar, "header", "header size overflow");
            break;
        };
        let Some(crc_slice) = bytes.get(size_at..rest_end) else {
            limit(ar, "header", "header overruns file");
            break;
        };
        if crc32fast::hash(crc_slice) != stored_crc {
            ar.header_crc_mismatch += 1;
        }
        let Some(htype) = inp.vint() else { break };
        let Some(hflags) = inp.vint() else { break };
        let extra_size = if hflags & HFL_EXTRA != 0 {
            inp.vint().unwrap_or(0)
        } else {
            0
        };
        let data_size = if hflags & HFL_DATA != 0 {
            inp.vint()
        } else {
            None
        };
        if hflags & HFL_CHILD != 0 {
            ar.child += 1;
        }

        match htype {
            HEAD5_CRYPT => {
                ar.headers_encrypted = true;
                ar.crypt_version = inp.vint();
                let _flags = inp.vint();
                ar.kdf_count = inp.u8();
                limit(ar, "headers-encrypted", "remaining headers are AES-256");
                ar.end_offset = rest_end as u64;
                return;
            }
            HEAD5_MAIN => {
                let aflags = inp.vint().unwrap_or(0);
                ar.volume = aflags & MHD_VOLUME != 0;
                ar.solid = aflags & MHD_SOLID != 0;
                ar.recovery = aflags & MHD_RECOVERY != 0;
                ar.locked = aflags & MHD_LOCKED != 0;
                if aflags & MHD_VOLNUM != 0 {
                    ar.volume_number = inp.vint();
                }
                if extra_size > 0 {
                    let extra_at = rest_end.saturating_sub(extra_size as usize);
                    if extra_at >= inp.pos()
                        && let Some(extra) = bytes.get(extra_at..rest_end.min(bytes.len()))
                    {
                        parse_main_extra(extra, ar);
                    }
                }
            }
            HEAD5_FILE | HEAD5_SERVICE => {
                let service = htype == HEAD5_SERVICE;
                let file_flags = inp.vint().unwrap_or(0);
                let unpacked = inp.vint().unwrap_or(0);
                let attrs = inp.vint().unwrap_or(0) as u32;
                let mut mtime = None;
                if file_flags & LHFL_UTIME != 0 {
                    mtime = inp.u32_le().map(i64::from);
                }
                let crc = if file_flags & LHFL_CRC32 != 0 {
                    inp.u32_le()
                } else {
                    None
                };
                let comp = inp.vint().unwrap_or(0);
                let host = inp.vint().unwrap_or(0);
                let nlen = inp.vint().unwrap_or(0) as usize;
                if nlen > MAX_NAME {
                    limit(ar, "name", "name longer than cap");
                    inp = Reader::at(bytes, rest_end);
                    if let Some(ds) = data_size {
                        skip_data(&mut inp, ar, ds);
                    }
                    continue;
                }
                let name_bytes = inp.bytes(nlen).unwrap_or(&[]);
                let name = utf8_name(name_bytes);
                let mut extra = Extra::default();
                if extra_size > 0 {
                    let extra_at = rest_end.saturating_sub(extra_size as usize);
                    if extra_at < rest_end
                        && let Some(record) = bytes.get(extra_at..rest_end.min(bytes.len()))
                    {
                        parse_extra(record, &mut extra);
                    }
                }
                let unpack_ver = comp & 0x3f;
                if unpack_ver >= 1 {
                    ar.v1_comp += 1;
                }
                ar.unpack_min = Some(ar.unpack_min.map_or(unpack_ver, |m| m.min(unpack_ver)));
                ar.unpack_max = Some(ar.unpack_max.map_or(unpack_ver, |m| m.max(unpack_ver)));
                let method = method5((comp >> 7) & 7);
                let solid = comp & 0x40 != 0;
                let mut member = Member {
                    path: name.clone(),
                    size_bytes: if file_flags & LHFL_UNPUNKNOWN != 0 {
                        0
                    } else {
                        unpacked
                    },
                    packed: data_size,
                    entry_type: if file_flags & LHFL_DIRECTORY != 0 {
                        "directory"
                    } else {
                        "regular"
                    },
                    mtime,
                    ctime: None,
                    atime: None,
                    encrypted: false,
                    method: Some(method),
                    dict_size: Some(dict_size(comp)),
                    host_os: Some(host5(host)),
                    crc32: crc,
                    blake2: None,
                    split_before: hflags & HFL_SPLIT_BEFORE != 0,
                    split_after: hflags & HFL_SPLIT_AFTER != 0,
                    solid,
                    hidden: false,
                    system: false,
                    read_only: false,
                    linkname: None,
                    redir_type: None,
                    file_version: None,
                    extra_types: Vec::new(),
                    header_off,
                    data_off: data_size.map(|_| rest_end as u64),
                    mode_octal: None,
                    uid: None,
                    gid: None,
                    uname: None,
                    gname: None,
                    windows_attrs: None,
                    kdf_count: None,
                    tweaked_checksums: false,
                    unpack_version: Some(unpack_ver),
                    size_unknown: file_flags & LHFL_UNPUNKNOWN != 0,
                };
                apply_attrs(&mut member, attrs, host == 1);
                inp = Reader::at(bytes, rest_end);
                if let Some(ds) = data_size {
                    if name == "CMT"
                        && member.method.as_deref() == Some("stored")
                        && let Some(body) = inp.bytes(ds as usize)
                    {
                        ar.comment = Some(utf8_name(body));
                    } else {
                        skip_data(&mut inp, ar, ds);
                    }
                }
                finish_file(ar, member, extra, service, &name);
                continue;
            }
            HEAD5_END => {
                ar.end_present = true;
                let eflags = inp.vint().unwrap_or(0);
                ar.not_last_volume = eflags & 0x0001 != 0;
                ar.end_offset = rest_end as u64;
                inp = Reader::at(bytes, rest_end);
                if let Some(ds) = data_size {
                    let _ = inp.skip(ds as usize);
                    ar.end_offset = inp.pos() as u64;
                }
                return;
            }
            _ => {
                ar.unknown_header += 1;
                if hflags & HFL_SKIP_UNKNOWN == 0 && extra_size == 0 && data_size.is_none() {
                    limit(ar, "unknown-header", format!("type {htype}"));
                    ar.end_offset = rest_end as u64;
                    return;
                }
            }
        }
        inp = Reader::at(bytes, rest_end);
        if let Some(ds) = data_size {
            skip_data(&mut inp, ar, ds);
        }
        ar.end_offset = inp.pos() as u64;
    }
}

fn decode_rar4_unicode(ascii: &[u8], enc: &[u8]) -> Option<String> {
    if enc.is_empty() {
        return None;
    }
    let mut enc_pos = 0usize;
    let high = *enc.get(enc_pos)? as u16;
    enc_pos += 1;
    let mut flags = 0u8;
    let mut flag_bits = 0i32;
    let mut out: Vec<u16> = Vec::new();
    while enc_pos < enc.len() && out.len() < MAX_NAME {
        if flag_bits == 0 {
            flags = *enc.get(enc_pos)?;
            enc_pos += 1;
            flag_bits = 8;
        }
        match flags >> 6 {
            0 => {
                out.push(u16::from(*enc.get(enc_pos)?));
                enc_pos += 1;
            }
            1 => {
                out.push(u16::from(*enc.get(enc_pos)?) + (high << 8));
                enc_pos += 1;
            }
            2 => {
                let lo = *enc.get(enc_pos)? as u16;
                let hi = *enc.get(enc_pos + 1)? as u16;
                out.push(lo + (hi << 8));
                enc_pos += 2;
            }
            _ => {
                let b = *enc.get(enc_pos)?;
                enc_pos += 1;
                let length = usize::from(b & 0x7f) + 2;
                if b & 0x80 != 0 {
                    for _ in 0..length {
                        let add = *enc.get(enc_pos)? as u16;
                        enc_pos += 1;
                        let src = ascii.get(out.len()).copied().unwrap_or(0) as u16;
                        out.push(((src + high) << 8) + add);
                    }
                } else {
                    for _ in 0..length {
                        let src = ascii.get(out.len()).copied().unwrap_or(0);
                        out.push(u16::from(src));
                    }
                }
            }
        }
        flags <<= 2;
        flag_bits -= 2;
    }
    if out.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&out).replace('\\', "/"))
}

fn rar4_name(raw: &[u8], unicode: bool) -> String {
    if unicode {
        // An ASCII name, a NUL, then the encoded Unicode form.
        let mut parts = raw.splitn(2, |&b| b == 0);
        if let (Some(ascii), Some(enc)) = (parts.next(), parts.next()) {
            if let Some(decoded) = decode_rar4_unicode(ascii, enc) {
                if !decoded.is_empty() {
                    return decoded;
                }
            }
            return utf8_name(ascii);
        }
    }
    utf8_name(raw)
}

fn walk_rar4(bytes: &[u8], start: usize, ar: &mut Archive) {
    let mut inp = Reader::at(bytes, start);
    for _ in 0..MAX_BLOCKS {
        if inp.remaining() < 7 {
            break;
        }
        let header_off = inp.pos() as u64;
        let Some(stored_crc) = inp.u16_le() else {
            break;
        };
        let Some(htype) = inp.u8() else { break };
        let Some(hflags) = inp.u16_le() else { break };
        let Some(head_size) = inp.u16_le() else { break };
        if head_size < 7 {
            limit(ar, "header", "RAR4 header smaller than 7");
            break;
        }
        let block_start = header_off as usize;
        let Some(header_end) = block_start.checked_add(head_size as usize) else {
            break;
        };
        // The CRC covers the header after its own two bytes.
        let Some(crc_of) = bytes.get(block_start + 2..header_end) else {
            limit(ar, "header", "RAR4 header overruns file");
            break;
        };
        if (crc32fast::hash(crc_of) as u16) != stored_crc {
            ar.header_crc_mismatch += 1;
        }
        inp = Reader::at(bytes, block_start + 7);
        match htype {
            R4_MAIN => {
                let _hi_posav = inp.u16_le();
                let _posav = inp.u32_le();
                ar.volume = hflags & R4_MHD_VOLUME != 0;
                ar.locked = hflags & R4_MHD_LOCK != 0;
                ar.solid = hflags & R4_MHD_SOLID != 0;
                ar.new_numbering = hflags & R4_MHD_NEWNUMBERING != 0;
                ar.authenticity = hflags & R4_MHD_AV != 0;
                ar.recovery = hflags & R4_MHD_PROTECT != 0;
                ar.headers_encrypted = hflags & R4_MHD_PASSWORD != 0;
                ar.first_volume = hflags & R4_MHD_FIRSTVOLUME != 0;
                if hflags & R4_MHD_ENCRYPTVER != 0 {
                    ar.r4_encrypt_ver = inp.u8();
                }
                if hflags & R4_MHD_COMMENT != 0 {
                    ar.comment_packed = true;
                }
                if ar.headers_encrypted {
                    limit(ar, "headers-encrypted", "RAR4 header password");
                    ar.end_offset = header_end as u64;
                    return;
                }
            }
            R4_FILE | R4_NEWSUB => {
                let service = htype == R4_NEWSUB;
                let Some(pack_lo) = inp.u32_le() else { break };
                let Some(unp_lo) = inp.u32_le() else { break };
                let host = inp.u8().unwrap_or(0);
                let crc = inp.u32_le();
                let ftime = inp.u32_le();
                let unp_ver = inp.u8().unwrap_or(0);
                let method = inp.u8().unwrap_or(0x30);
                let name_size = inp.u16_le().unwrap_or(0) as usize;
                let attrs = inp.u32_le().unwrap_or(0);
                let mut pack = u64::from(pack_lo);
                let mut unp = u64::from(unp_lo);
                if hflags & R4_LHD_LARGE != 0 {
                    pack |= u64::from(inp.u32_le().unwrap_or(0)) << 32;
                    unp |= u64::from(inp.u32_le().unwrap_or(0)) << 32;
                }
                if name_size > MAX_NAME {
                    limit(ar, "name", "RAR4 name longer than cap");
                    inp = Reader::at(bytes, header_end);
                    skip_data(&mut inp, ar, pack);
                    continue;
                }
                let name_end = (inp.pos() + name_size).min(header_end);
                let raw_name = bytes.get(inp.pos()..name_end).unwrap_or(&[]);
                inp = Reader::at(bytes, name_end);
                let name = rar4_name(raw_name, hflags & R4_LHD_UNICODE != 0);
                if hflags & R4_LHD_SALT != 0 {
                    let _ = inp.skip(8);
                }
                if hflags & R4_LHD_EXTTIME != 0 && inp.pos() + 2 <= header_end {
                    skip_rar4_exttime(&mut inp, header_end);
                }
                ar.unpack_min = Some(
                    ar.unpack_min
                        .map_or(u64::from(unp_ver), |m| m.min(u64::from(unp_ver))),
                );
                ar.unpack_max = Some(
                    ar.unpack_max
                        .map_or(u64::from(unp_ver), |m| m.max(u64::from(unp_ver))),
                );
                let mut member = Member {
                    path: name.clone(),
                    size_bytes: unp,
                    packed: Some(pack),
                    entry_type: if hflags & R4_LHD_WINDOWDIR == R4_LHD_WINDOWDIR {
                        "directory"
                    } else {
                        "regular"
                    },
                    mtime: ftime.and_then(dos_to_unix),
                    ctime: None,
                    atime: None,
                    encrypted: hflags & R4_LHD_PASSWORD != 0,
                    // RAR4 stores the method as 0x30 ("0") + the RAR5-style
                    // method number, so shift it back before the shared lookup.
                    method: Some(method5(u64::from(method.saturating_sub(0x30)))),
                    dict_size: None,
                    host_os: Some(host4(host)),
                    crc32: crc,
                    blake2: None,
                    split_before: hflags & R4_LHD_SPLIT_BEFORE != 0,
                    split_after: hflags & R4_LHD_SPLIT_AFTER != 0,
                    solid: hflags & R4_LHD_SOLID != 0,
                    hidden: false,
                    system: false,
                    read_only: false,
                    linkname: None,
                    redir_type: None,
                    file_version: if hflags & R4_LHD_VERSION != 0 {
                        Some(0)
                    } else {
                        None
                    },
                    extra_types: Vec::new(),
                    header_off,
                    data_off: Some(header_end as u64),
                    mode_octal: None,
                    uid: None,
                    gid: None,
                    uname: None,
                    gname: None,
                    windows_attrs: None,
                    kdf_count: None,
                    tweaked_checksums: false,
                    unpack_version: Some(u64::from(unp_ver)),
                    size_unknown: false,
                };
                apply_attrs(&mut member, attrs, host == 3);
                inp = Reader::at(bytes, header_end);
                if service && name == "CMT" && method == 0x30 {
                    if let Some(body) = inp.bytes(pack.min(inp.remaining() as u64) as usize) {
                        ar.comment = Some(utf8_name(body));
                    }
                } else {
                    skip_data(&mut inp, ar, pack);
                }
                finish_file(ar, member, Extra::default(), service, &name);
                continue;
            }
            R4_END => {
                ar.end_present = true;
                ar.not_last_volume = hflags & 0x0001 != 0;
                ar.end_offset = header_end as u64;
                return;
            }
            _ => {
                ar.unknown_header += 1;
                if hflags & R4_SKIP_UNKNOWN == 0 && hflags & R4_LONG_BLOCK == 0 {
                    limit(ar, "unknown-header", format!("RAR4 type 0x{htype:02x}"));
                    ar.end_offset = header_end as u64;
                    return;
                }
            }
        }
        inp = Reader::at(bytes, header_end);
        if hflags & R4_LONG_BLOCK != 0 {
            // ADD_SIZE was already consumed as part of HEAD_SIZE for MAIN;
            // file headers skip packed data in their own arm.
        }
        ar.end_offset = inp.pos() as u64;
    }
}

fn skip_rar4_exttime(inp: &mut Reader<'_>, header_end: usize) {
    let Some(flags) = inp.u16_le() else { return };
    for i in 0..4 {
        let rmode = flags >> ((3 - i) * 4);
        if rmode & 8 == 0 {
            continue;
        }
        if i != 0 && inp.pos() + 4 <= header_end {
            let _ = inp.u32_le();
        }
        let count = usize::from(rmode & 3);
        for _ in 0..count {
            if inp.pos() < header_end {
                let _ = inp.u8();
            }
        }
    }
}

fn insert_num(map: &mut JsonMap<String, JsonValue>, key: &str, n: u64) {
    map.insert(key.into(), JsonValue::Number(n.into()));
}

/// Split a walked member into its typed form and the RAR-only keys its
/// published `archive.members[]` value carries beyond the typed fields.
fn split_member(m: Member) -> (ArchiveMember, JsonMap<String, JsonValue>) {
    let mut rar_keys = JsonMap::new();
    for (key, time) in [("ctime_unix", m.ctime), ("atime_unix", m.atime)] {
        if let Some(t) = time {
            rar_keys.insert(key.into(), JsonValue::Number(t.into()));
        }
    }
    if let Some(h) = m.blake2 {
        rar_keys.insert("blake2sp".into(), JsonValue::String(h));
    }
    if let Some(d) = m.dict_size {
        insert_num(&mut rar_keys, "dictionary_size", d);
    }
    for (key, set) in [
        ("solid", m.solid),
        ("split_before", m.split_before),
        ("split_after", m.split_after),
        ("hidden", m.hidden),
        ("system", m.system),
        ("read_only", m.read_only),
        ("tweaked_checksums", m.tweaked_checksums),
        ("size_unknown", m.size_unknown),
    ] {
        if set {
            rar_keys.insert(key.into(), JsonValue::Bool(true));
        }
    }
    if let Some(t) = m.redir_type {
        rar_keys.insert("redir_type".into(), JsonValue::String(t.into()));
    }
    if let Some(v) = m.file_version {
        insert_num(&mut rar_keys, "file_version", v);
    }
    if !m.extra_types.is_empty() {
        let types = m.extra_types.iter().map(|t| JsonValue::from(*t)).collect();
        rar_keys.insert("extra_types".into(), JsonValue::Array(types));
    }
    if let Some(a) = m.windows_attrs {
        insert_num(&mut rar_keys, "windows_attrs", u64::from(a));
    }
    if let Some(k) = m.kdf_count {
        insert_num(&mut rar_keys, "kdf_count", u64::from(k));
    }
    if let Some(v) = m.unpack_version {
        insert_num(&mut rar_keys, "unpack_version", v);
    }

    let ownership = (m.mode_octal.is_some()
        || m.uid.is_some()
        || m.gid.is_some()
        || m.uname.is_some()
        || m.gname.is_some())
    .then_some(ArchiveOwnership {
        mode_octal: m.mode_octal,
        uid: m.uid,
        gid: m.gid,
        uname: m.uname,
        gname: m.gname,
    });
    let member = ArchiveMember {
        path: m.path,
        size_bytes: m.size_bytes,
        entry_type: Some(m.entry_type.into()),
        mtime_unix: m.mtime,
        linkname: m.linkname,
        host_os: m.host_os,
        crc32: m.crc32,
        encrypted: m.encrypted,
        compression: (m.packed.is_some() || m.method.is_some()).then_some(ArchiveCompression {
            compressed_size: m.packed,
            method: m.method,
        }),
        ownership,
        offsets: ArchiveOffsets {
            header: Some(m.header_off),
            data: m.data_off,
            central_header: None,
        },
    };
    (member, rar_keys)
}

/// The shared aggregates a RAR reports. Symlinks and NTFS streams count as
/// files, and a hidden member is one with the Windows hidden attribute.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::DirectoryCount,
    Agg::UncompressedSize(Scope::All),
    Agg::CompressedSize,
    Agg::CompressionRatio,
    Agg::ZipBombRatio(Scope::All),
    Agg::Methods { always: false },
    Agg::EncryptedCount,
    Agg::SymlinkCount,
    Agg::ModeBits,
    Agg::Executables,
    Agg::Scripts,
    Agg::NestedArchives,
    Agg::PathTraversal(Scope::All),
    Agg::NameTricks,
    Agg::MisplacedExecutables,
    Agg::NoiseFiles,
    Agg::HiddenFiles,
    Agg::MaxFilenameLength,
    Agg::DuplicateMembers,
    Agg::SentinelMtimes,
    Agg::MtimeRange,
    Agg::MtimeAnomalies(Dominance::TimedOnly),
];

fn emit(
    mut ar: Archive,
    bytes_len: u64,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) {
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("rar".into()),
    );
    values.insert_key(
        value_key!("rar.version"),
        JsonValue::String(ar.version.to_string()),
    );
    values.insert_key(value_key!("rar.solid"), JsonValue::Bool(ar.solid));
    values.insert_key(value_key!("rar.volume"), JsonValue::Bool(ar.volume));
    values.insert_key(value_key!("rar.locked"), JsonValue::Bool(ar.locked));
    values.insert_key(value_key!("rar.recovery"), JsonValue::Bool(ar.recovery));
    values.insert_key(
        value_key!("rar.headers_encrypted"),
        JsonValue::Bool(ar.headers_encrypted),
    );
    values.insert_key(
        value_key!("rar.end_present"),
        JsonValue::Bool(ar.end_present),
    );
    values.insert_key(value_key!("rar.quick_open"), JsonValue::Bool(ar.quick_open));
    if ar.new_numbering {
        values.insert_key(value_key!("rar.new_numbering"), JsonValue::Bool(true));
    }
    if ar.authenticity {
        values.insert_key(value_key!("rar.authenticity_info"), JsonValue::Bool(true));
    }
    if ar.first_volume {
        values.insert_key(value_key!("rar.first_volume"), JsonValue::Bool(true));
    }
    if ar.not_last_volume {
        values.insert_key(value_key!("rar.not_last_volume"), JsonValue::Bool(true));
    }
    if let Some(n) = ar.volume_number {
        values.insert_key(value_key!("rar.volume_number"), JsonValue::Number(n.into()));
    }
    if let Some(ref name) = ar.original_name {
        values.insert_key(
            value_key!("rar.original_name"),
            JsonValue::String(name.clone()),
        );
    }
    if let Some(t) = ar.created_unix {
        values.insert_key(value_key!("rar.created_unix"), JsonValue::Number(t.into()));
    }
    if let Some(ref c) = ar.comment {
        values.insert_key(value_key!("rar.comment"), JsonValue::String(c.clone()));
        metrics.insert(metric!("archive.has_comment"), 1.0);
        metrics.insert(metric!("archive.comment_size"), c.len() as f64);
    } else if ar.comment_packed {
        values.insert_key(value_key!("rar.comment_packed"), JsonValue::Bool(true));
        metrics.insert(metric!("archive.has_comment"), 1.0);
    }
    if let Some(v) = ar.crypt_version {
        values.insert_key(
            value_key!("rar.encryption.version"),
            JsonValue::Number(v.into()),
        );
    }
    if let Some(k) = ar.kdf_count {
        values.insert_key(
            value_key!("rar.encryption.kdf_count"),
            JsonValue::Number(u64::from(k).into()),
        );
        metrics.insert(metric!("rar.kdf_count"), f64::from(k));
    }
    if let Some(v) = ar.r4_encrypt_ver {
        values.insert_key(
            value_key!("rar.encryption.rar4_version"),
            JsonValue::Number(u64::from(v).into()),
        );
    }
    if ar.locator_qo.is_some() || ar.locator_rr.is_some() {
        let mut loc = JsonMap::new();
        if let Some(q) = ar.locator_qo {
            loc.insert("quick_open_offset".into(), JsonValue::Number(q.into()));
        }
        if let Some(r) = ar.locator_rr {
            loc.insert("recovery_offset".into(), JsonValue::Number(r.into()));
        }
        values.insert_key(value_key!("rar.locator"), JsonValue::Object(loc));
    }
    if !ar.services.is_empty() {
        values.insert_key(
            value_key!("rar.services"),
            JsonValue::Array(
                ar.services
                    .iter()
                    .map(|s| JsonValue::String(s.clone()))
                    .collect(),
            ),
        );
    }
    if !ar.streams.is_empty() {
        values.insert_key(
            value_key!("rar.ntfs_streams"),
            JsonValue::Array(ar.streams.clone()),
        );
    }
    if !ar.extra_types.is_empty() {
        values.insert_key(
            value_key!("rar.extra_record_types"),
            JsonValue::Array(
                ar.extra_types
                    .iter()
                    .map(|t| JsonValue::Number((*t).into()))
                    .collect(),
            ),
        );
    }
    if !ar.limits.is_empty() {
        values.insert_key(
            value_key!("rar.limits"),
            JsonValue::Array(ar.limits.clone()),
        );
    }
    if let (Some(min), Some(max)) = (ar.unpack_min, ar.unpack_max) {
        values.insert_key(
            value_key!("rar.unpack_version.min"),
            JsonValue::Number(min.into()),
        );
        values.insert_key(
            value_key!("rar.unpack_version.max"),
            JsonValue::Number(max.into()),
        );
    }

    let mut stats = ArchiveStats::new(AGGS);
    let mut members_json = Vec::with_capacity(ar.members.len());
    for m in std::mem::take(&mut ar.members) {
        let hidden = m.hidden;
        let (member, rar_keys) = split_member(m);
        let mut reading = Reading::of(&member);
        reading.hidden = hidden;
        stats.observe(&member, &reading);
        let mut obj = member_value(&member, Shape::FULL);
        obj.extend(rar_keys);
        members_json.push(JsonValue::Object(obj));
        archive_members.push(member);
    }
    values.insert_key(
        value_key!("rar.members"),
        JsonValue::Array(members_json.clone()),
    );
    values.insert_key(
        value_key!("archive.members"),
        JsonValue::Array(members_json),
    );
    stats.emit(values, metrics);

    metrics.insert(
        metric!("archive.extra_field_size"),
        ar.extra_field_size as f64,
    );
    metrics.insert(metric!("archive.leading_bytes"), ar.prefix as f64);
    let trailing = bytes_len.saturating_sub(ar.end_offset.max(ar.prefix));
    metrics.insert(metric!("archive.trailing_bytes"), trailing as f64);
    if ar.prefix > 0 {
        metrics.insert(metric!("rar.sfx_bytes"), ar.prefix as f64);
    }
    metrics.insert(
        metric!("rar.headers_encrypted"),
        f64::from(u8::from(ar.headers_encrypted)),
    );
    metrics.insert(metric!("rar.solid"), f64::from(u8::from(ar.solid)));
    metrics.insert(metric!("rar.volume"), f64::from(u8::from(ar.volume)));
    metrics.insert(metric!("rar.locked"), f64::from(u8::from(ar.locked)));
    metrics.insert(metric!("rar.recovery"), f64::from(u8::from(ar.recovery)));
    metrics.insert(
        metric!("rar.end_present"),
        f64::from(u8::from(ar.end_present)),
    );
    metrics.insert(
        metric!("rar.quick_open"),
        f64::from(u8::from(ar.quick_open)),
    );
    metrics.insert(
        metric!("rar.header_crc_mismatch_count"),
        ar.header_crc_mismatch as f64,
    );
    metrics.insert(
        metric!("rar.unknown_header_count"),
        ar.unknown_header as f64,
    );
    metrics.insert(metric!("rar.unknown_extra_count"), ar.unknown_extra as f64);
    metrics.insert(metric!("rar.blake2_count"), ar.blake2 as f64);
    metrics.insert(metric!("rar.acl_count"), ar.acl as f64);
    metrics.insert(metric!("rar.ntfs_stream_count"), ar.streams.len() as f64);
    metrics.insert(metric!("rar.file_version_count"), ar.file_version as f64);
    metrics.insert(metric!("rar.split_count"), ar.split as f64);
    metrics.insert(metric!("rar.child_header_count"), ar.child as f64);
    metrics.insert(metric!("rar.mapped_unix_name_count"), ar.mapped_unix as f64);
    metrics.insert(metric!("rar.v1_compression_count"), ar.v1_comp as f64);
    metrics.insert(
        metric!("rar.service_header_count"),
        ar.services.len() as f64,
    );
    if ar.quick_open_size > 0 {
        metrics.insert(metric!("rar.quick_open_size"), ar.quick_open_size as f64);
    }
    if ar.recovery_size > 0 {
        metrics.insert(metric!("rar.recovery_size"), ar.recovery_size as f64);
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let Some((sig_at, version)) = find_signature(bytes) else {
        return Err(Error::malformed("rar", "missing RAR signature"));
    };
    let mut ar = Archive {
        version,
        prefix: sig_at as u64,
        end_offset: sig_at as u64,
        ..Archive::default()
    };
    let after_sig = sig_at + if version == 5 { 8 } else { 7 };
    if version == 5 {
        walk_rar5(bytes, after_sig, &mut ar);
    } else {
        walk_rar4(bytes, after_sig, &mut ar);
    }
    if ar.end_offset < after_sig as u64 {
        ar.end_offset = after_sig as u64;
    }
    emit(ar, bytes.len() as u64, values, metrics, archive_members);
    Ok(())
}

#[cfg(test)]
mod tests;
