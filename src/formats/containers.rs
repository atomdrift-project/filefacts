//! Structure walkers for the media containers that carry payloads.
//!
//! Each walker answers one question — *which bytes does this format's own
//! structure account for* — and hands the answer to
//! [`crate::formats::carrier`], which turns it into the shared `media.*`
//! facts. None of them decodes samples, pixels or frames; a walk is a linear
//! pass over a chunk, box or directory table.
//!
//! Covered here: RIFF (`.wav`, `.webp`, `.avi`), IFF (`.aiff`, `.aifc`),
//! Windows icons and cursors (`.ico`, `.cur`), GIF, BMP, MP3 (ID3 + frames)
//! and ISO base media (`.mp4`, `.m4a`, `.mov`).
//!
//! These formats were chosen because they are the assets a package copies
//! verbatim and nobody opens: a favicon, a notification sound, a spritesheet.
//! Before they had walkers they had no file type at all, so every one of them
//! was skipped outright — an appended executable in a `.ico` produced no
//! findings of any kind.

use crate::formats::carrier::Coverage;

/// Chunk counts and box depths are bounded so a hostile header cannot turn a
/// linear walk into a long one.
const MAX_REGIONS: usize = 4096;

/// RIFF: `RIFF` + u32 little-endian payload length + a 4-byte form type,
/// then `id`/`size` chunks. Used by `.wav`, `.webp` and `.avi`. `RIFX` is
/// the same layout with every size big-endian.
pub(crate) fn riff(bytes: &[u8]) -> Coverage {
    let Some(head) = bytes.first_chunk::<12>() else {
        return header_truncated();
    };
    let read_size: fn([u8; 4]) -> u32 = match &head[..4] {
        b"RIFF" => u32::from_le_bytes,
        b"RIFX" => u32::from_be_bytes,
        _ => return Coverage::unrecognized(),
    };
    let form = match &head[8..12] {
        b"WAVE" => "wav",
        b"WEBP" => "webp",
        b"AVI " => "avi",
        _ => "riff",
    };
    // `LIST`/`INFO` metadata and WebP's `XMP `/`EXIF` hold author text.
    walk_chunks(
        bytes,
        head,
        form,
        read_size,
        &[b"LIST", b"INFO", b"XMP ", b"EXIF", b"ID3 "],
    )
}

/// IFF: `FORM` + u32 big-endian length + form type, then `id`/`size` chunks.
/// Used by `.aiff` and `.aifc`.
pub(crate) fn iff(bytes: &[u8]) -> Coverage {
    let Some(head) = bytes.first_chunk::<12>() else {
        return header_truncated();
    };
    if &head[..4] != b"FORM" {
        return Coverage::unrecognized();
    }
    let form = match &head[8..12] {
        b"AIFF" => "aiff",
        b"AIFC" => "aifc",
        _ => "iff",
    };
    // `NAME`/`AUTH`/`ANNO`/`(c) ` are AIFF's free-text chunks.
    walk_chunks(
        bytes,
        head,
        form,
        u32::from_be_bytes,
        &[b"NAME", b"AUTH", b"ANNO", b"(c) "],
    )
}

fn header_truncated() -> Coverage {
    let mut c = Coverage::unrecognized();
    c.problem("header truncated");
    c
}

/// The chunk walk RIFF and IFF share: a 12-byte header whose bytes 4..8 give
/// the length of everything after the first 8, then `id`/`size` chunks padded
/// to an even length. The two differ only in the byte order of the size
/// fields (`read_size`) and in which chunk ids hold free text (`freeform`).
fn walk_chunks(
    bytes: &[u8],
    head: &[u8; 12],
    form: &'static str,
    read_size: fn([u8; 4]) -> u32,
    freeform: &[&[u8; 4]],
) -> Coverage {
    let mut cov = Coverage::new(form, 12);
    // The declared length covers everything after the 8-byte header.
    let declared = u64::from(read_size([head[4], head[5], head[6], head[7]]));
    cov.declared_len = Some(declared.saturating_add(8));
    if declared.saturating_add(8) > bytes.len() as u64 {
        cov.problem("declared size exceeds file");
    }

    // A reader stops at the declared length, so the walk must too: bytes past
    // it are not chunks no matter what they look like. Without this clamp an
    // appended executable was parsed as a chunk and vanished from the
    // unaccounted-for region it belongs in.
    let limit = usize::try_from(declared.saturating_add(8))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let mut at = 12usize;
    let mut seen = 0usize;
    while let Some(&[i0, i1, i2, i3, s0, s1, s2, s3]) =
        bytes.get(at..limit).and_then(<[u8]>::first_chunk::<8>)
        && seen < MAX_REGIONS
    {
        let id = [i0, i1, i2, i3];
        let size = read_size([s0, s1, s2, s3]) as usize;
        let body = at + 8;
        let Some(end) = body.checked_add(size) else {
            cov.problem("chunk size overflows");
            break;
        };
        if end > limit {
            cov.problem("chunk extends past declared end");
            break;
        }
        if freeform.contains(&&id) {
            cov.claim_freeform(at as u64, end as u64);
        } else {
            cov.claim(at as u64, end as u64);
        }
        // Chunks are word-aligned: an odd size is followed by one pad byte.
        at = end + (size & 1);
        seen += 1;
    }
    if seen == 0 {
        cov.problem("no chunks declared");
    }
    cov
}

/// Windows icon / cursor: a 6-byte header, then one 16-byte directory entry
/// per image, each naming an offset and size. The directory is the whole of
/// the format's structure, so any byte it does not point at is unread.
pub(crate) fn ico(bytes: &[u8]) -> Coverage {
    let Some(&[r0, r1, k0, k1, c0, c1]) = bytes.first_chunk::<6>() else {
        return Coverage::unrecognized();
    };
    // reserved must be 0; type is 1 (icon) or 2 (cursor).
    let kind = u16::from_le_bytes([k0, k1]);
    if r0 != 0 || r1 != 0 || !matches!(kind, 1 | 2) {
        return Coverage::unrecognized();
    }
    let count = u16::from_le_bytes([c0, c1]) as usize;
    if count == 0 || count > 512 {
        return Coverage::unrecognized();
    }
    let dir_end = 6 + count * 16;
    let Some(dir) = bytes.get(6..dir_end) else {
        let mut c = Coverage::new(if kind == 1 { "ico" } else { "cur" }, 6);
        c.problem("icon directory truncated");
        return c;
    };
    let mut cov = Coverage::new(if kind == 1 { "ico" } else { "cur" }, dir_end as u64);
    for entry in dir.as_chunks::<16>().0 {
        let [.., z0, z1, z2, z3, o0, o1, o2, o3] = *entry;
        let size = u64::from(u32::from_le_bytes([z0, z1, z2, z3]));
        let off = u64::from(u32::from_le_bytes([o0, o1, o2, o3]));
        let Some(end) = off.checked_add(size) else {
            cov.problem("image extent overflows");
            continue;
        };
        if end > bytes.len() as u64 {
            cov.problem("image extends past end of file");
            continue;
        }
        cov.claim(off, end);
    }
    cov
}

/// GIF: header + logical screen descriptor (+ optional global colour table),
/// then a stream of blocks terminated by `0x3B`. Everything after the
/// trailer is unread by every decoder.
pub(crate) fn gif(bytes: &[u8]) -> Coverage {
    let Some(header) = bytes
        .first_chunk::<13>()
        .filter(|h| h.starts_with(b"GIF87a") || h.starts_with(b"GIF89a"))
    else {
        return Coverage::unrecognized();
    };
    let mut at = 13usize;
    let flags = header[10];
    if flags & 0x80 != 0 {
        // Global colour table: 3 * 2^(N+1) bytes.
        at += 3 * (1usize << ((flags & 0x07) + 1));
    }
    if at > bytes.len() {
        let mut c = Coverage::new("gif", 13);
        c.problem("colour table truncated");
        return c;
    }
    let mut cov = Coverage::new("gif", at as u64);
    let start = at;
    let mut seen = 0usize;
    let mut terminated = false;
    while let Some(&marker) = bytes.get(at)
        && seen < MAX_REGIONS
    {
        match marker {
            0x3B => {
                at += 1;
                terminated = true;
                break;
            }
            0x21 => {
                // Extension: label byte, then sub-blocks.
                at += 2;
                let Some(next) = skip_subblocks(bytes, at) else {
                    cov.problem("extension block truncated");
                    break;
                };
                at = next;
            }
            0x2C => {
                // Image descriptor: 9 bytes, optional local colour table,
                // an LZW code-size byte, then sub-blocks.
                let Some(&[.., local]) = bytes.get(at..).and_then(<[u8]>::first_chunk::<10>) else {
                    cov.problem("image descriptor truncated");
                    break;
                };
                at += 10;
                if local & 0x80 != 0 {
                    at += 3 * (1usize << ((local & 0x07) + 1));
                }
                at += 1; // LZW minimum code size
                let Some(next) = skip_subblocks(bytes, at) else {
                    cov.problem("image data truncated");
                    break;
                };
                at = next;
            }
            _ => {
                cov.problem("unknown block marker");
                break;
            }
        }
        seen += 1;
    }
    cov.claim(start as u64, at as u64);
    if !terminated {
        cov.problem("missing GIF trailer");
    }
    cov
}

/// Advance past a GIF sub-block chain (length-prefixed runs ended by a zero
/// length). Returns the offset just past the terminator.
fn skip_subblocks(bytes: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *bytes.get(at)? as usize;
        at += 1;
        if len == 0 {
            return Some(at);
        }
        at = at.checked_add(len)?;
        if at > bytes.len() {
            return None;
        }
    }
}

/// BMP: `BM`, then a u32 declared file size and the offset of pixel data.
/// The declared size is what every reader trusts.
pub(crate) fn bmp(bytes: &[u8]) -> Coverage {
    let Some(head) = bytes.first_chunk::<14>() else {
        return Coverage::unrecognized();
    };
    if &head[..2] != b"BM" {
        return Coverage::unrecognized();
    }
    let declared = u64::from(u32::from_le_bytes([head[2], head[3], head[4], head[5]]));
    let mut cov = Coverage::new("bmp", 14);
    cov.declared_len = Some(declared);
    if declared > bytes.len() as u64 {
        cov.problem("declared size exceeds file");
    } else if declared >= 14 {
        cov.claim(14, declared);
    }
    cov
}

/// MP3: an optional ID3v2 header (whose size field is syncsafe), the MPEG
/// frame stream, and an optional 128-byte ID3v1 trailer. Frames are not
/// walked individually — the stream is contiguous by definition, so the
/// structural question is whether anything sits outside the tags and frames.
pub(crate) fn mp3(bytes: &[u8]) -> Coverage {
    let has_id3 = bytes.starts_with(b"ID3");
    let framed = matches!(bytes, [0xFF, second, ..] if second & 0xE0 == 0xE0);
    if !has_id3 && !framed {
        return Coverage::unrecognized();
    }
    let mut start = 0u64;
    let mut cov = Coverage::new("mp3", 0);
    if has_id3 {
        let Some(head) = bytes.first_chunk::<10>() else {
            cov.problem("ID3 header truncated");
            return cov;
        };
        // Syncsafe: seven bits per byte.
        let size = u64::from(head[6] & 0x7f) << 21
            | u64::from(head[7] & 0x7f) << 14
            | u64::from(head[8] & 0x7f) << 7
            | u64::from(head[9] & 0x7f);
        let end = 10 + size;
        if end > bytes.len() as u64 {
            cov.problem("ID3 tag extends past end of file");
            return cov;
        }
        // ID3 frames carry titles, comments and cover art: author content.
        cov.claim_freeform(0, end);
        start = end;
    }
    let mut end = bytes.len() as u64;
    if bytes
        .last_chunk::<128>()
        .is_some_and(|trailer| trailer.starts_with(b"TAG"))
    {
        let tag = end - 128;
        cov.claim_freeform(tag, end);
        end = tag;
    }
    if end > start {
        cov.claim(start, end);
    }
    cov
}

/// ISO base media (`.mp4`, `.m4a`, `.mov`): a flat sequence of boxes, each a
/// u32 big-endian size and a 4-byte type. Only the top level is walked; a
/// payload hidden inside a `mdat` is indistinguishable from sample data, but
/// one appended past the last box is not.
pub(crate) fn iso_bmff(bytes: &[u8]) -> Coverage {
    // A `ftyp` box at the start is the reliable marker.
    let Some(head) = bytes.first_chunk::<8>() else {
        return Coverage::unrecognized();
    };
    if &head[4..8] != b"ftyp" {
        return Coverage::unrecognized();
    }
    let mut cov = Coverage::new("iso-bmff", 0);
    let mut at = 0usize;
    let mut seen = 0usize;
    while let Some(&[s0, s1, s2, s3, t0, t1, t2, t3]) =
        bytes.get(at..).and_then(<[u8]>::first_chunk::<8>)
        && seen < MAX_REGIONS
    {
        let size32 = u64::from(u32::from_be_bytes([s0, s1, s2, s3]));
        let btype = [t0, t1, t2, t3];
        let size = match size32 {
            // 0 means "extends to end of file".
            0 => bytes.len() as u64 - at as u64,
            // 1 means a 64-bit size follows the type.
            1 => {
                let Some(ext) = bytes.get(at + 8..).and_then(<[u8]>::first_chunk::<8>) else {
                    cov.problem("64-bit box size truncated");
                    break;
                };
                u64::from_be_bytes(*ext)
            }
            n => n,
        };
        if size < 8 {
            cov.problem("box size below header size");
            break;
        }
        let Some(end) = (at as u64).checked_add(size) else {
            cov.problem("box extent overflows");
            break;
        };
        if end > bytes.len() as u64 {
            cov.problem("box extends past end of file");
            break;
        }
        // `udta`/`meta`/`free`/`skip` hold author metadata or explicit filler.
        if matches!(&btype, b"udta" | b"meta" | b"free" | b"skip") {
            cov.claim_freeform(at as u64, end);
        } else {
            cov.claim(at as u64, end);
        }
        at = crate::bytes::sat_usize(end);
        seen += 1;
    }
    if seen == 0 {
        cov.problem("no boxes declared");
    }
    cov
}

/// SVG: XML text whose document ends at the last `</svg>`. Anything after the
/// closing tag is never parsed by a renderer or a browser, which makes the
/// tail of an SVG the same carrier the tail of a PNG is. The document itself
/// is text, so only what follows it is examined.
pub(crate) fn svg(bytes: &[u8]) -> Coverage {
    let mut cov = Coverage::new("svg", 0);
    // Case-insensitive search for the final closing tag, walking back over
    // each `<` rather than lowercasing a copy of the whole file.
    let close = memchr::memrchr_iter(b'<', bytes).find(|&at| {
        bytes
            .get(at..at + 6)
            .is_some_and(|tag| tag.eq_ignore_ascii_case(b"</svg>"))
    });
    match close {
        Some(at) => cov.claim(0, (at + 6) as u64),
        None => {
            // No closing tag: an SVG fragment, or a file that is not really
            // SVG. Either way the boundary is unknown, so claim everything
            // rather than reporting the remainder as concealed.
            cov.claim(0, bytes.len() as u64);
        }
    }
    cov
}

#[cfg(test)]
mod tests;
